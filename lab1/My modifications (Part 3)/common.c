/*
 * common.c - C code for kernel entry and exit
 * Copyright (c) 2015 Andrew Lutomirski
 * GPL v2
 *
 * Based on asm and ptrace code by many authors.  The code here originated
 * in ptrace.c and signal.c.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/tracehook.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/signal.h>
#include <linux/export.h>
#include <linux/context_tracking.h>
#include <linux/user-return-notifier.h>
#include <linux/nospec.h>
#include <linux/uprobes.h>

#include <asm/desc.h>
#include <asm/traps.h>
#include <asm/vdso.h>
#include <asm/uaccess.h>
#include <asm/cpufeature.h>
#include <asm/nospec-branch.h>

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

#ifdef CONFIG_CONTEXT_TRACKING
/* Called on entry from user mode with IRQs off. */
__visible inline void enter_from_user_mode(void)
{
	CT_WARN_ON(ct_state() != CONTEXT_USER);
	user_exit_irqoff();
}
#else
static inline void enter_from_user_mode(void) {}
#endif

static void do_audit_syscall_entry(struct pt_regs *regs, u32 arch)
{
#ifdef CONFIG_X86_64
	if (arch == AUDIT_ARCH_X86_64) {
		audit_syscall_entry(regs->orig_ax, regs->di,
				    regs->si, regs->dx, regs->r10);
	} else
#endif
	{
		audit_syscall_entry(regs->orig_ax, regs->bx,
				    regs->cx, regs->dx, regs->si);
	}
}

/*
 * Returns the syscall nr to run (which should match regs->orig_ax) or -1
 * to skip the syscall.
 */
static long syscall_trace_enter(struct pt_regs *regs)
{
	u32 arch = in_ia32_syscall() ? AUDIT_ARCH_I386 : AUDIT_ARCH_X86_64;

	struct thread_info *ti = current_thread_info();
	unsigned long ret = 0;
	bool emulated = false;
	u32 work;

	if (IS_ENABLED(CONFIG_DEBUG_ENTRY))
		BUG_ON(regs != task_pt_regs(current));

	work = ACCESS_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY;

	if (unlikely(work & _TIF_SYSCALL_EMU))
		emulated = true;

	if ((emulated || (work & _TIF_SYSCALL_TRACE)) &&
	    tracehook_report_syscall_entry(regs))
		return -1L;

	if (emulated)
		return -1L;

#ifdef CONFIG_SECCOMP
	/*
	 * Do seccomp after ptrace, to catch any tracer changes.
	 */
	if (work & _TIF_SECCOMP) {
		struct seccomp_data sd;

		sd.arch = arch;
		sd.nr = regs->orig_ax;
		sd.instruction_pointer = regs->ip;
#ifdef CONFIG_X86_64
		if (arch == AUDIT_ARCH_X86_64) {
			sd.args[0] = regs->di;
			sd.args[1] = regs->si;
			sd.args[2] = regs->dx;
			sd.args[3] = regs->r10;
			sd.args[4] = regs->r8;
			sd.args[5] = regs->r9;
		} else
#endif
		{
			sd.args[0] = regs->bx;
			sd.args[1] = regs->cx;
			sd.args[2] = regs->dx;
			sd.args[3] = regs->si;
			sd.args[4] = regs->di;
			sd.args[5] = regs->bp;
		}

		ret = __secure_computing(&sd);
		if (ret == -1)
			return ret;
	}
#endif

	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_enter(regs, regs->orig_ax);

	do_audit_syscall_entry(regs, arch);

	return ret ?: regs->orig_ax;
}

#define EXIT_TO_USERMODE_LOOP_FLAGS				\
	(_TIF_SIGPENDING | _TIF_NOTIFY_RESUME | _TIF_UPROBE |	\
	 _TIF_NEED_RESCHED | _TIF_USER_RETURN_NOTIFY)

static void exit_to_usermode_loop(struct pt_regs *regs, u32 cached_flags)
{
	/*
	 * In order to return to user mode, we need to have IRQs off with
	 * none of _TIF_SIGPENDING, _TIF_NOTIFY_RESUME, _TIF_USER_RETURN_NOTIFY,
	 * _TIF_UPROBE, or _TIF_NEED_RESCHED set.  Several of these flags
	 * can be set at any time on preemptable kernels if we have IRQs on,
	 * so we need to loop.  Disabling preemption wouldn't help: doing the
	 * work to clear some of the flags can sleep.
	 */
	while (true) {
		/* We have work to do. */
		local_irq_enable();

		if (cached_flags & _TIF_NEED_RESCHED)
			schedule();

		if (cached_flags & _TIF_UPROBE)
			uprobe_notify_resume(regs);

		/* deal with pending signal delivery */
		if (cached_flags & _TIF_SIGPENDING)
			do_signal(regs);

		if (cached_flags & _TIF_NOTIFY_RESUME) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			tracehook_notify_resume(regs);
		}

		if (cached_flags & _TIF_USER_RETURN_NOTIFY)
			fire_user_return_notifiers();

		/* Disable IRQs and retry */
		local_irq_disable();

		cached_flags = READ_ONCE(current_thread_info()->flags);

		if (!(cached_flags & EXIT_TO_USERMODE_LOOP_FLAGS))
			break;
	}
}

/* Called with IRQs disabled. */
__visible inline void prepare_exit_to_usermode(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	u32 cached_flags;

	if (IS_ENABLED(CONFIG_PROVE_LOCKING) && WARN_ON(!irqs_disabled()))
		local_irq_disable();

	lockdep_sys_exit();

	cached_flags = READ_ONCE(ti->flags);

	if (unlikely(cached_flags & EXIT_TO_USERMODE_LOOP_FLAGS))
		exit_to_usermode_loop(regs, cached_flags);

#ifdef CONFIG_COMPAT
	/*
	 * Compat syscalls set TS_COMPAT.  Make sure we clear it before
	 * returning to user mode.  We need to clear it *after* signal
	 * handling, because syscall restart has a fixup for compat
	 * syscalls.  The fixup is exercised by the ptrace_syscall_32
	 * selftest.
	 *
	 * We also need to clear TS_REGS_POKED_I386: the 32-bit tracer
	 * special case only applies after poking regs and before the
	 * very next return to user mode.
	 */
	ti->status &= ~(TS_COMPAT|TS_I386_REGS_POKED);
#endif

	user_enter_irqoff();

	mds_user_clear_cpu_buffers();
}

#define SYSCALL_EXIT_WORK_FLAGS				\
	(_TIF_SYSCALL_TRACE | _TIF_SYSCALL_AUDIT |	\
	 _TIF_SINGLESTEP | _TIF_SYSCALL_TRACEPOINT)

static void syscall_slow_exit_work(struct pt_regs *regs, u32 cached_flags)
{
	bool step;

	audit_syscall_exit(regs);

	if (cached_flags & _TIF_SYSCALL_TRACEPOINT)
		trace_sys_exit(regs, regs->ax);

	/*
	 * If TIF_SYSCALL_EMU is set, we only get here because of
	 * TIF_SINGLESTEP (i.e. this is PTRACE_SYSEMU_SINGLESTEP).
	 * We already reported this syscall instruction in
	 * syscall_trace_enter().
	 */
	step = unlikely(
		(cached_flags & (_TIF_SINGLESTEP | _TIF_SYSCALL_EMU))
		== _TIF_SINGLESTEP);
	if (step || cached_flags & _TIF_SYSCALL_TRACE)
		tracehook_report_syscall_exit(regs, step);
}

/*
 * Called with IRQs on and fully valid regs.  Returns with IRQs off in a
 * state such that we can immediately switch to user mode.
 */
__visible inline void syscall_return_slowpath(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	u32 cached_flags = READ_ONCE(ti->flags);

	CT_WARN_ON(ct_state() != CONTEXT_KERNEL);

	if (IS_ENABLED(CONFIG_PROVE_LOCKING) &&
	    WARN(irqs_disabled(), "syscall %ld left IRQs disabled", regs->orig_ax))
		local_irq_enable();

	/* MY SYSTEM CALL */
	struct task_struct* task = current;
	char *syscall_name = "unknown";
	int i;
	if (task->trace_enabled) {   
        for (i = 0; i < task->trace_count; i++) {
            if (task->trace_syscalls[i] == regs->orig_ax) {
				syscall_name = "unknown";
				switch (task->trace_syscalls[i]) {
					case 0:   syscall_name = "read"; break;
					case 1:   syscall_name = "write"; break;
					case 2:   syscall_name = "open"; break;
					case 3:   syscall_name = "close"; break;
					case 4:   syscall_name = "stat"; break;
					case 5:   syscall_name = "fstat"; break;
					case 6:   syscall_name = "lstat"; break;
					case 7:   syscall_name = "poll"; break;
					case 8:   syscall_name = "lseek"; break;
					case 9:   syscall_name = "mmap"; break;
					case 10:  syscall_name = "mprotect"; break;
					case 11:  syscall_name = "munmap"; break;
					case 12:  syscall_name = "brk"; break;
					case 13:  syscall_name = "rt_sigaction"; break;
					case 14:  syscall_name = "rt_sigprocmask"; break;
					case 15:  syscall_name = "rt_sigreturn"; break;
					case 16:  syscall_name = "ioctl"; break;
					case 17:  syscall_name = "pread64"; break;
					case 18:  syscall_name = "pwrite64"; break;
					case 19:  syscall_name = "readv"; break;
					case 20:  syscall_name = "writev"; break;
					case 21:  syscall_name = "access"; break;
					case 22:  syscall_name = "pipe"; break;
					case 23:  syscall_name = "select"; break;
					case 24:  syscall_name = "sched_yield"; break;
					case 25:  syscall_name = "mremap"; break;
					case 26:  syscall_name = "msync"; break;
					case 27:  syscall_name = "mincore"; break;
					case 28:  syscall_name = "madvise"; break;
					case 29:  syscall_name = "shmget"; break;
					case 30:  syscall_name = "shmat"; break;
					case 31:  syscall_name = "shmctl"; break;
					case 32:  syscall_name = "dup"; break;
					case 33:  syscall_name = "dup2"; break;
					case 34:  syscall_name = "pause"; break;
					case 35:  syscall_name = "nanosleep"; break;
					case 36:  syscall_name = "getitimer"; break;
					case 37:  syscall_name = "alarm"; break;
					case 38:  syscall_name = "setitimer"; break;
					case 39:  syscall_name = "getpid"; break;
					case 40:  syscall_name = "sendfile"; break;
					case 41:  syscall_name = "socket"; break;
					case 42:  syscall_name = "connect"; break;
					case 43:  syscall_name = "accept"; break;
					case 44:  syscall_name = "sendto"; break;
					case 45:  syscall_name = "recvfrom"; break;
					case 46:  syscall_name = "sendmsg"; break;
					case 47:  syscall_name = "recvmsg"; break;
					case 48:  syscall_name = "shutdown"; break;
					case 49:  syscall_name = "bind"; break;
					case 50:  syscall_name = "listen"; break;
					case 51:  syscall_name = "getsockname"; break;
					case 52:  syscall_name = "getpeername"; break;
					case 53:  syscall_name = "socketpair"; break;
					case 54:  syscall_name = "setsockopt"; break;
					case 55:  syscall_name = "getsockopt"; break;
					case 56:  syscall_name = "clone"; break;
					case 57:  syscall_name = "fork"; break;
					case 58:  syscall_name = "vfork"; break;
					case 59:  syscall_name = "execve"; break;
					case 60:  syscall_name = "exit"; break;
					case 61:  syscall_name = "wait4"; break;
					case 62:  syscall_name = "kill"; break;
					case 63:  syscall_name = "uname"; break;
					case 64:  syscall_name = "semget"; break;
					case 65:  syscall_name = "semop"; break;
					case 66:  syscall_name = "semctl"; break;
					case 67:  syscall_name = "shmdt"; break;
					case 68:  syscall_name = "msgget"; break;
					case 69:  syscall_name = "msgsnd"; break;
					case 70:  syscall_name = "msgrcv"; break;
					case 71:  syscall_name = "msgctl"; break;
					case 72:  syscall_name = "fcntl"; break;
					case 73:  syscall_name = "flock"; break;
					case 74:  syscall_name = "fsync"; break;
					case 75:  syscall_name = "fdatasync"; break;
					case 76:  syscall_name = "truncate"; break;
					case 77:  syscall_name = "ftruncate"; break;
					case 78:  syscall_name = "getdents"; break;
					case 79:  syscall_name = "getcwd"; break;
					case 80:  syscall_name = "chdir"; break;
					case 81:  syscall_name = "fchdir"; break;
					case 82:  syscall_name = "rename"; break;
					case 83:  syscall_name = "mkdir"; break;
					case 84:  syscall_name = "rmdir"; break;
					case 85:  syscall_name = "creat"; break;
					case 86:  syscall_name = "link"; break;
					case 87:  syscall_name = "unlink"; break;
					case 88:  syscall_name = "symlink"; break;
					case 89:  syscall_name = "readlink"; break;
					case 90:  syscall_name = "chmod"; break;
					case 91:  syscall_name = "fchmod"; break;
					case 92:  syscall_name = "chown"; break;
					case 93:  syscall_name = "fchown"; break;
					case 94:  syscall_name = "lchown"; break;
					case 95:  syscall_name = "umask"; break;
					case 96:  syscall_name = "gettimeofday"; break;
					case 97:  syscall_name = "getrlimit"; break;
					case 98:  syscall_name = "getrusage"; break;
					case 99:  syscall_name = "sysinfo"; break;
					case 100: syscall_name = "times"; break;
					case 101: syscall_name = "ptrace"; break;
					case 102: syscall_name = "getuid"; break;
					case 103: syscall_name = "syslog"; break;
					case 104: syscall_name = "getgid"; break;
					case 105: syscall_name = "setuid"; break;
					case 106: syscall_name = "setgid"; break;
					case 107: syscall_name = "geteuid"; break;
					case 108: syscall_name = "getegid"; break;
					case 109: syscall_name = "setpgid"; break;
					case 110: syscall_name = "getppid"; break;
					case 111: syscall_name = "getpgrp"; break;
					case 112: syscall_name = "setsid"; break;
					case 113: syscall_name = "setreuid"; break;
					case 114: syscall_name = "setregid"; break;
					case 115: syscall_name = "getgroups"; break;
					case 116: syscall_name = "setgroups"; break;
					case 117: syscall_name = "setresuid"; break;
					case 118: syscall_name = "getresuid"; break;
					case 119: syscall_name = "setresgid"; break;
					case 120: syscall_name = "getresgid"; break;
					case 121: syscall_name = "getpgid"; break;
					case 122: syscall_name = "setfsuid"; break;
					case 123: syscall_name = "setfsgid"; break;
					case 124: syscall_name = "getsid"; break;
					case 125: syscall_name = "capget"; break;
					case 126: syscall_name = "capset"; break;
					case 127: syscall_name = "rt_sigpending"; break;
					case 128: syscall_name = "rt_sigtimedwait"; break;
					case 129: syscall_name = "rt_sigqueueinfo"; break;
					case 130: syscall_name = "rt_sigsuspend"; break;
					case 131: syscall_name = "sigaltstack"; break;
					case 132: syscall_name = "utime"; break;
					case 133: syscall_name = "mknod"; break;
					case 134: syscall_name = "uselib"; break;
					case 135: syscall_name = "personality"; break;
					case 136: syscall_name = "ustat"; break;
					case 137: syscall_name = "statfs"; break;
					case 138: syscall_name = "fstatfs"; break;
					case 139: syscall_name = "sysfs"; break;
					case 140: syscall_name = "getpriority"; break;
					case 141: syscall_name = "setpriority"; break;
					case 142: syscall_name = "sched_setparam"; break;
					case 143: syscall_name = "sched_getparam"; break;
					case 144: syscall_name = "sched_setscheduler"; break;
					case 145: syscall_name = "sched_getscheduler"; break;
					case 146: syscall_name = "sched_get_priority_max"; break;
					case 147: syscall_name = "sched_get_priority_min"; break;
					case 148: syscall_name = "sched_rr_get_interval"; break;
					case 149: syscall_name = "mlock"; break;
					case 150: syscall_name = "munlock"; break;
					case 151: syscall_name = "mlockall"; break;
					case 152: syscall_name = "munlockall"; break;
					case 153: syscall_name = "vhangup"; break;
					case 154: syscall_name = "modify_ldt"; break;
					case 155: syscall_name = "pivot_root"; break;
					case 156: syscall_name = "_sysctl"; break;
					case 157: syscall_name = "prctl"; break;
					case 158: syscall_name = "arch_prctl"; break;
					case 159: syscall_name = "adjtimex"; break;
					case 160: syscall_name = "setrlimit"; break;
					case 161: syscall_name = "chroot"; break;
					case 162: syscall_name = "sync"; break;
					case 163: syscall_name = "acct"; break;
					case 164: syscall_name = "settimeofday"; break;
					case 165: syscall_name = "mount"; break;
					case 166: syscall_name = "umount2"; break;
					case 167: syscall_name = "swapon"; break;
					case 168: syscall_name = "swapoff"; break;
					case 169: syscall_name = "reboot"; break;
					case 170: syscall_name = "sethostname"; break;
					case 171: syscall_name = "setdomainname"; break;
					case 172: syscall_name = "iopl"; break;
					case 173: syscall_name = "ioperm"; break;
					case 174: syscall_name = "create_module"; break;
					case 175: syscall_name = "init_module"; break;
					case 176: syscall_name = "delete_module"; break;
					case 177: syscall_name = "get_kernel_syms"; break;
					case 178: syscall_name = "query_module"; break;
					case 179: syscall_name = "quotactl"; break;
					case 180: syscall_name = "nfsservctl"; break;
					case 181: syscall_name = "getpmsg"; break;
					case 182: syscall_name = "putpmsg"; break;
					case 183: syscall_name = "afs_syscall"; break;
					case 184: syscall_name = "tuxcall"; break;
					case 185: syscall_name = "security"; break;
					case 186: syscall_name = "gettid"; break;
					case 187: syscall_name = "readahead"; break;
					case 188: syscall_name = "setxattr"; break;
					case 189: syscall_name = "lsetxattr"; break;
					case 190: syscall_name = "fsetxattr"; break;
					case 191: syscall_name = "getxattr"; break;
					case 192: syscall_name = "lgetxattr"; break;
					case 193: syscall_name = "fgetxattr"; break;
					case 194: syscall_name = "listxattr"; break;
					case 195: syscall_name = "llistxattr"; break;
					case 196: syscall_name = "flistxattr"; break;
					case 197: syscall_name = "removexattr"; break;
					case 198: syscall_name = "lremovexattr"; break;
					case 199: syscall_name = "fremovexattr"; break;
					case 200: syscall_name = "tkill"; break;
					case 201: syscall_name = "time"; break;
					case 202: syscall_name = "futex"; break;
					case 203: syscall_name = "sched_setaffinity"; break;
					case 204: syscall_name = "sched_getaffinity"; break;
					case 205: syscall_name = "set_thread_area"; break;
					case 206: syscall_name = "io_setup"; break;
					case 207: syscall_name = "io_destroy"; break;
					case 208: syscall_name = "io_getevents"; break;
					case 209: syscall_name = "io_submit"; break;
					case 210: syscall_name = "io_cancel"; break;
					case 211: syscall_name = "get_thread_area"; break;
					case 212: syscall_name = "lookup_dcookie"; break;
					case 213: syscall_name = "epoll_create"; break;
					case 214: syscall_name = "epoll_ctl_old"; break;
					case 215: syscall_name = "epoll_wait_old"; break;
					case 216: syscall_name = "remap_file_pages"; break;
					case 217: syscall_name = "getdents64"; break;
					case 218: syscall_name = "set_tid_address"; break;
					case 219: syscall_name = "restart_syscall"; break;
					case 220: syscall_name = "semtimedop"; break;
					case 221: syscall_name = "fadvise64"; break;
					case 222: syscall_name = "timer_create"; break;
					case 223: syscall_name = "timer_settime"; break;
					case 224: syscall_name = "timer_gettime"; break;
					case 225: syscall_name = "timer_getoverrun"; break;
					case 226: syscall_name = "timer_delete"; break;
					case 227: syscall_name = "clock_settime"; break;
					case 228: syscall_name = "clock_gettime"; break;
					case 229: syscall_name = "clock_getres"; break;
					case 230: syscall_name = "clock_nanosleep"; break;
					case 231: syscall_name = "exit_group"; break;
					case 232: syscall_name = "epoll_wait"; break;
					case 233: syscall_name = "epoll_ctl"; break;
					case 234: syscall_name = "tgkill"; break;
					case 235: syscall_name = "utimes"; break;
					case 236: syscall_name = "vserver"; break;
					case 237: syscall_name = "mbind"; break;
					case 238: syscall_name = "set_mempolicy"; break;
					case 239: syscall_name = "get_mempolicy"; break;
					case 240: syscall_name = "mq_open"; break;
					case 241: syscall_name = "mq_unlink"; break;
					case 242: syscall_name = "mq_timedsend"; break;
					case 243: syscall_name = "mq_timedreceive"; break;
					case 244: syscall_name = "mq_notify"; break;
					case 245: syscall_name = "mq_getsetattr"; break;
					case 246: syscall_name = "kexec_load"; break;
					case 247: syscall_name = "waitid"; break;
					case 248: syscall_name = "add_key"; break;
					case 249: syscall_name = "request_key"; break;
					case 250: syscall_name = "keyctl"; break;
					case 251: syscall_name = "ioprio_set"; break;
					case 252: syscall_name = "ioprio_get"; break;
					case 253: syscall_name = "inotify_init"; break;
					case 254: syscall_name = "inotify_add_watch"; break;
					case 255: syscall_name = "inotify_rm_watch"; break;
					case 256: syscall_name = "migrate_pages"; break;
					case 257: syscall_name = "openat"; break;
					case 258: syscall_name = "mkdirat"; break;
					case 259: syscall_name = "mknodat"; break;
					case 260: syscall_name = "fchownat"; break;
					case 261: syscall_name = "futimesat"; break;
					case 262: syscall_name = "newfstatat"; break;
					case 263: syscall_name = "unlinkat"; break;
					case 264: syscall_name = "renameat"; break;
					case 265: syscall_name = "linkat"; break;
					case 266: syscall_name = "symlinkat"; break;
					case 267: syscall_name = "readlinkat"; break;
					case 268: syscall_name = "fchmodat"; break;
					case 269: syscall_name = "faccessat"; break;
					case 270: syscall_name = "pselect6"; break;
					case 271: syscall_name = "ppoll"; break;
					case 272: syscall_name = "unshare"; break;
					case 273: syscall_name = "set_robust_list"; break;
					case 274: syscall_name = "get_robust_list"; break;
					case 275: syscall_name = "splice"; break;
					case 276: syscall_name = "tee"; break;
					case 277: syscall_name = "sync_file_range"; break;
					case 278: syscall_name = "vmsplice"; break;
					case 279: syscall_name = "move_pages"; break;
					case 280: syscall_name = "utimensat"; break;
					case 281: syscall_name = "epoll_pwait"; break;
					case 282: syscall_name = "signalfd"; break;
					case 283: syscall_name = "timerfd_create"; break;
					case 284: syscall_name = "eventfd"; break;
					case 285: syscall_name = "fallocate"; break;
					case 286: syscall_name = "timerfd_settime"; break;
					case 287: syscall_name = "timerfd_gettime"; break;
					case 288: syscall_name = "accept4"; break;
					case 289: syscall_name = "signalfd4"; break;
					case 290: syscall_name = "eventfd2"; break;
					case 291: syscall_name = "epoll_create1"; break;
					case 292: syscall_name = "dup3"; break;
					case 293: syscall_name = "pipe2"; break;
					case 294: syscall_name = "inotify_init1"; break;
					case 295: syscall_name = "preadv"; break;
					case 296: syscall_name = "pwritev"; break;
					case 297: syscall_name = "rt_tgsigqueueinfo"; break;
					case 298: syscall_name = "perf_event_open"; break;
					case 299: syscall_name = "recvmmsg"; break;
					case 300: syscall_name = "fanotify_init"; break;
					case 301: syscall_name = "fanotify_mark"; break;
					case 302: syscall_name = "prlimit64"; break;
					case 303: syscall_name = "name_to_handle_at"; break;
					case 304: syscall_name = "open_by_handle_at"; break;
					case 305: syscall_name = "clock_adjtime"; break;
					case 306: syscall_name = "syncfs"; break;
					case 307: syscall_name = "sendmmsg"; break;
					case 308: syscall_name = "setns"; break;
					case 309: syscall_name = "getcpu"; break;
					case 310: syscall_name = "process_vm_readv"; break;
					case 311: syscall_name = "process_vm_writev"; break;
					case 312: syscall_name = "kcmp"; break;
					case 313: syscall_name = "finit_module"; break;
					case 314: syscall_name = "sched_setattr"; break;
					case 315: syscall_name = "sched_getattr"; break;
					case 316: syscall_name = "renameat2"; break;
					case 317: syscall_name = "seccomp"; break;
					case 318: syscall_name = "getrandom"; break;
					case 319: syscall_name = "memfd_create"; break;
					case 320: syscall_name = "kexec_file_load"; break;
					case 321: syscall_name = "bpf"; break;
					case 322: syscall_name = "execveat"; break;
					case 323: syscall_name = "userfaultfd"; break;
					case 324: syscall_name = "membarrier"; break;
					case 325: syscall_name = "mlock2"; break;
					case 326: syscall_name = "copy_file_range"; break;
					case 327: syscall_name = "preadv2"; break;
					case 328: syscall_name = "pwritev2"; break;
					case 329: syscall_name = "pkey_mprotect"; break;
					case 330: syscall_name = "pkey_alloc"; break;
					case 331: syscall_name = "pkey_free"; break;
				}
				printk("%d: syscall %s(%d) -> %ld\n", task->pid, syscall_name, task->trace_syscalls[i], regs->ax);
                break;
            }
        }
    }

	/*
	 * First do one-time work.  If these work items are enabled, we
	 * want to run them exactly once per syscall exit with IRQs on.
	 */
	if (unlikely(cached_flags & SYSCALL_EXIT_WORK_FLAGS))
		syscall_slow_exit_work(regs, cached_flags);

	local_irq_disable();
	prepare_exit_to_usermode(regs);
}

#ifdef CONFIG_X86_64
__visible void do_syscall_64(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	unsigned long nr = regs->orig_ax;

	enter_from_user_mode();
	local_irq_enable();

	if (READ_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY)
		nr = syscall_trace_enter(regs);

	/*
	 * NB: Native and x32 syscalls are dispatched from the same
	 * table.  The only functional difference is the x32 bit in
	 * regs->orig_ax, which changes the behavior of some syscalls.
	 */
	if (likely((nr & __SYSCALL_MASK) < NR_syscalls)) {
		nr = array_index_nospec(nr & __SYSCALL_MASK, NR_syscalls);
		regs->ax = sys_call_table[nr](
			regs->di, regs->si, regs->dx,
			regs->r10, regs->r8, regs->r9);
	}

	syscall_return_slowpath(regs);
}
#endif

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
/*
 * Does a 32-bit syscall.  Called with IRQs on in CONTEXT_KERNEL.  Does
 * all entry and exit work and returns with IRQs off.  This function is
 * extremely hot in workloads that use it, and it's usually called from
 * do_fast_syscall_32, so forcibly inline it to improve performance.
 */
static __always_inline void do_syscall_32_irqs_on(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	unsigned int nr = (unsigned int)regs->orig_ax;

#ifdef CONFIG_IA32_EMULATION
	ti->status |= TS_COMPAT;
#endif

	if (READ_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY) {
		/*
		 * Subtlety here: if ptrace pokes something larger than
		 * 2^32-1 into orig_ax, this truncates it.  This may or
		 * may not be necessary, but it matches the old asm
		 * behavior.
		 */
		nr = syscall_trace_enter(regs);
	}

	if (likely(nr < IA32_NR_syscalls)) {
		nr = array_index_nospec(nr, IA32_NR_syscalls);
		/*
		 * It's possible that a 32-bit syscall implementation
		 * takes a 64-bit parameter but nonetheless assumes that
		 * the high bits are zero.  Make sure we zero-extend all
		 * of the args.
		 */
		regs->ax = ia32_sys_call_table[nr](
			(unsigned int)regs->bx, (unsigned int)regs->cx,
			(unsigned int)regs->dx, (unsigned int)regs->si,
			(unsigned int)regs->di, (unsigned int)regs->bp);
	}

	syscall_return_slowpath(regs);
}

/* Handles int $0x80 */
__visible void do_int80_syscall_32(struct pt_regs *regs)
{
	enter_from_user_mode();
	local_irq_enable();
	do_syscall_32_irqs_on(regs);
}

/* Returns 0 to return using IRET or 1 to return using SYSEXIT/SYSRETL. */
__visible long do_fast_syscall_32(struct pt_regs *regs)
{
	/*
	 * Called using the internal vDSO SYSENTER/SYSCALL32 calling
	 * convention.  Adjust regs so it looks like we entered using int80.
	 */

	unsigned long landing_pad = (unsigned long)current->mm->context.vdso +
		vdso_image_32.sym_int80_landing_pad;

	/*
	 * SYSENTER loses EIP, and even SYSCALL32 needs us to skip forward
	 * so that 'regs->ip -= 2' lands back on an int $0x80 instruction.
	 * Fix it up.
	 */
	regs->ip = landing_pad;

	enter_from_user_mode();

	local_irq_enable();

	/* Fetch EBP from where the vDSO stashed it. */
	if (
#ifdef CONFIG_X86_64
		/*
		 * Micro-optimization: the pointer we're following is explicitly
		 * 32 bits, so it can't be out of range.
		 */
		__get_user(*(u32 *)&regs->bp,
			    (u32 __user __force *)(unsigned long)(u32)regs->sp)
#else
		get_user(*(u32 *)&regs->bp,
			 (u32 __user __force *)(unsigned long)(u32)regs->sp)
#endif
		) {

		/* User code screwed up. */
		local_irq_disable();
		regs->ax = -EFAULT;
		prepare_exit_to_usermode(regs);
		return 0;	/* Keep it simple: use IRET. */
	}

	/* Now this is just like a normal syscall. */
	do_syscall_32_irqs_on(regs);

#ifdef CONFIG_X86_64
	/*
	 * Opportunistic SYSRETL: if possible, try to return using SYSRETL.
	 * SYSRETL is available on all 64-bit CPUs, so we don't need to
	 * bother with SYSEXIT.
	 *
	 * Unlike 64-bit opportunistic SYSRET, we can't check that CX == IP,
	 * because the ECX fixup above will ensure that this is essentially
	 * never the case.
	 */
	return regs->cs == __USER32_CS && regs->ss == __USER_DS &&
		regs->ip == landing_pad &&
		(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF)) == 0;
#else
	/*
	 * Opportunistic SYSEXIT: if possible, try to return using SYSEXIT.
	 *
	 * Unlike 64-bit opportunistic SYSRET, we can't check that CX == IP,
	 * because the ECX fixup above will ensure that this is essentially
	 * never the case.
	 *
	 * We don't allow syscalls at all from VM86 mode, but we still
	 * need to check VM, because we might be returning from sys_vm86.
	 */
	return static_cpu_has(X86_FEATURE_SEP) &&
		regs->cs == __USER_CS && regs->ss == __USER_DS &&
		regs->ip == landing_pad &&
		(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF | X86_EFLAGS_VM)) == 0;
#endif
}
#endif
