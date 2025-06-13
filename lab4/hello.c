/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/*
 * 使用 FUSE3 API 实现文件系统的最小示例代码
 * 使用以下命令编译：
 *     gcc -Wall hello.c -lfuse3 -o hello
 */

#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

/**
 * @brief 打印日志，用法和 printf 完全相同，但在输出前会自动加上当前时间。
 */
void print_log(const char *fmt, ...) {
	// 获取当前时间戳
	time_t now = time(NULL);
	struct tm *tm_now = localtime(&now);
	printf("[%02d:%02d:%02d] ", tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);

	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

/**
 * 下面两个函数定义了我们文件系统中唯一一个文件的名字和内容。
 * 我们在 hello_ 系列函数中会用到这两个变量，然后向 fuse 返回相应的结果。
 */
const char filename[] = "hello";
const char contents[] = "Hello, World!\n";
const char my_filename[] = "PB23000020";
const char my_contents[] = "PB23000020\n";

/**
 * @brief 在文件系统初始化（被挂载）时会被调用，目前我们的文件系统很简单，不需要干任何事
 */
static void *hello_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
	print_log("hello_init()\n");	// 调试输出
	return NULL;
}

/**
 * @brief 获取 path 所对应的文件或目录的属性，包括权限、类型、创建/修改/读取时间等。
 *        这里我们只展示如何设置文件的类型和权限。
 * 
 * @param path 	被获取属性的文件的路径。（路径格式请参考文档。）
 * @param stbuf 属性结构体，结果存放在此处
 * @param fi 	可无视
 * @return int 	成功返回0，失败返回负数（POSIX错误代码的负值）
 */
static int hello_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
	print_log("getattr(path=%s)\n", path);		// 调试输出

	// 清空结果（stbuf）结构体
	memset(stbuf, 0, sizeof(struct stat));

	// 我们的文件系统暂时只有一个文件，但 getattr 也可能对目录使用，所以我们要考虑（文件系统）根目录和hello两种情况。
	// 注意下面 if ... else if 是怎么判断路径的

	// 结果在 stbuf 中保存，需要设置的字段有：
	// stbuf->st_mode: 一个整数，代表文件类型和权限，低 9 位表示权限（3位八进制数），前面的位表示文件文件类型。
	//                 Linux 中已经定义好了 S_IFDIR 和 S_IFREG 两个宏，分别表示目录和普通文件。
	//                 使用位运算可以方便的设置文件类型和权限，参考下面的例子。
	// stbuf->st_size: 代表文件大小，单位是字节。目录的文件大小设置为 0 即可。

	// 1. 如果 path 是根目录（/），则设置其属性为 S_IFDIR，权限为 0755 （八进制），即 rwxr-xr-x。（Linux下，目录必须有执行权限才能被读取）
	// 2. 如果 path 是 /hello，则设置其属性为 S_IFREG，权限为 0444 （八进制），即 r--r--r--，因为我们文件系统暂时没办法修改文件内容。
	//    对于文件，我们还需要设置文件大小（st->size），有些程序会根据文件大小来读取文件内容，因此大小必须设置正确。
	// 3. 其它情况返回错误 -ENOENT（表示没有这个文件或目录）。

	// TODO: 0.1 在下面添加代码，返回你学号所代表的文件的正确属性。

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755; 	// 文件类型是目录，权限是 0755 （八进制）
	} else if (strcmp(path+1, filename) == 0) {
		stbuf->st_mode = S_IFREG | 0444; 	// 普通文件，权限是 0444 （八进制）
		stbuf->st_size = strlen(contents); 	// 文件大小为 contents 的长度
	}
	// ================== Your code here =================
	else if (strcmp(path+1, my_filename) == 0) {
		stbuf->st_mode = S_IFREG | 0444; 	// 普通文件，权限是 0444 （八进制）
		stbuf->st_size = strlen(my_contents); 	// 文件大小为 contents 的长度
	}
	// ===================================================
	else {
		return -ENOENT;	// 其它情况，找不到错误
	}


	return 0;	// 成功返回0
}

/**
 * @brief 获取 path 对应的目录里的文件（子目录）列表，结果使用 filler 函数填充到 buf 中。
 *        其它参数可以忽略。
 * 
 * @param path		要读取的目录路径 
 * @param buf 		结果缓冲区（通过 filler 函数使用）
 * @param filler 	用于填充结果的函数，使用方法：filler(buf, "apple", NULL, 0, 0)，意为目录下有名为 apple 的文件。
 * @return int 		成功返回0，失败返回负数（POSIX错误代码的负值）
 */
static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
	print_log("readdir(path=%s)\n", path);	// 调试输出

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0, 0);	// "." 表示当前目录
	filler(buf, "..", NULL, 0, 0);	// ".." 表示上级目录
	filler(buf, filename, NULL, 0, 0);	// 表示目录下有个名为 filename 的文件

	// TODO: 0.1 添加文件名为你的学号的文件。（提示：参照上面格式，就一行。）
	// ================== Your code here =================
	filler(buf, my_filename, NULL, 0, 0);	// 表示目录下有个名为 filename 的文件
	// ===================================================
	return 0;
}

/**
 * @brief 读取从path对应的文件从 offset 开始的 size 字节的数据到 buf 中。
 * 
 * @param path 		要读取的文件路径
 * @param buf 		结果缓冲区
 * @param size 		要读取的字节数
 * @param offset 	要读取的偏移量
 * @return int		成功读取的字节数，一个字节都没读取成功返回0，出现错误返回负值。
 * 					注意，如果读取的字节数大于文件的实际大小，应该只读取到文件末尾。但不应该返回负值。
 * 					即使 offset 超出了文件的实际大小，也应该返回0，而不是负数。
 * 					负数仅在出现错误时返回，例如文件不存在。
 */
static int hello_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	print_log("read(path=%s, size=%zu, offset=%lld)\n", path, size, (long long)offset);	// 调试输出

	const char* file_data = NULL;	// 用于存放文件内容
	size_t file_size = 0;			// 用于存放文件大小

	if (strcmp(path+1, filename) == 0) {
		file_data = contents;	// 文件内容
		file_size = strlen(contents);	// 文件大小
	}
	
	// TODO: 0.1 添加学号正确的内容，使名字为你的学号的文件可以被读取。文件内容也应该是你的学号（可以加个换行符）。
	// ================== Your code here =================
	if (strcmp(path+1, my_filename) == 0) {
		file_data = my_contents;	// 文件内容
		file_size = strlen(my_contents);	// 文件大小
	}
	// ===================================================

	if (file_data == NULL) {
		return -ENOENT;	// 文件不存在
	}

	// 计算要读取的字节数
	size_t max_size = file_size - offset;	// 文件剩余的字节数
	size_t real_size = size > max_size ? max_size : size;	// 实际要读取的字节数
	if (real_size <= 0) {
		return 0;	// 没有要读取的字节数
	}
	// 读取文件内容到 buf 中
	memcpy(buf, file_data + offset, real_size);	// 从 offset 开始读取 real_size 字节的数据到 buf 中
	return real_size;	// 返回实际读取的字节数
}

static const struct fuse_operations hello_oper = {
	.init       = hello_init,
	.getattr	= hello_getattr,
	.readdir	= hello_readdir,
	.read		= hello_read,
};

int main(int argc, char *argv[])
{
	// 将命令行参数转化为 fuse 能处理的 fuse_args 结构体格式
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	// fuse_main() 是 FUSE 的主函数，内部会初始化各项设置，解析命令行参数，并将文件系统挂载到相应目录。
	// 然后，函数调用 fuse_operations 的 init 函数（在本程序中是 hello_init），用于初始化文件系统。
	// 初始化完毕后，函数会进入循环，等待用户对挂载的目录使用文件系统相关系统调用（如 open, read, write），
	// 每当用户使用这些系统调用，fuse会将其转换为对 fuse_operations 中对应的函数的调用。
	// fuse_main() 的循环会在文件系统被卸载 (umount) 时结束。
	int ret = fuse_main(args.argc, args.argv, &hello_oper, NULL);

	// 释放 fuse_args 结构体
	fuse_opt_free_args(&args);
	return ret;
}
