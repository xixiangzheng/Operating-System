/*
 * memlib.c - a module that simulates the memory system.  Needed because it 
 *            allows us to interleave calls from the student's malloc package 
 *            with the system's malloc package in libc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "memlib.h"
#include "config.h"

/* private variables */
static char *mem_start_brk;  /* points to first byte of heap */
static char *mem_brk;        /* points to last byte of heap */
static char *mem_max_addr;   /* largest legal heap address */ 

/* 
 * mem_init - initialize the memory system model
 */
void mem_init(void)
{
    /*
        TODO: 
        调用 sbrk, 初始化 mem_start_brk、mem_brk、以及 mem_max_addr
        此处增长堆空间大小为 MAX_HEAP
    */
    mem_start_brk = (char*)sbrk(MAX_HEAP);
    if (mem_start_brk == NULL) {
        fprintf(stderr, "mem_init: sbrk failed\n");
        exit(1);
    }

    mem_max_addr = mem_start_brk + MAX_HEAP;    // 设置正确的结束地址
    mem_brk = mem_start_brk;                    // 开始未使用任何空间
}

/* 
 * mem_deinit - free the storage used by the memory system model
 */
void mem_deinit(void)
{
    free(mem_start_brk);
}

/*
 * mem_reset_brk - reset the simulated brk pointer to make an empty heap
 */
void mem_reset_brk()
{
    mem_brk = mem_start_brk;
}

/* 
 * mem_sbrk - simple model of the sbrk function. Extends the heap 
 *    by incr bytes and returns the start address of the new area. In
 *    this model, the heap cannot be shrunk.
 */
void *mem_sbrk(int incr) 
{
    char *old_brk = mem_brk;
    
    /*
        TODO:
            模拟堆增长
            incr: 申请 mem_brk 的增长量
            返回值: 旧 mem_brk 值
        HINTS:
        1. 若 mem_brk + incr 没有超过实际的 mem_max_addr 值，直接推进 mem_brk 值即可
        2. 若 mem_brk + incr 超过实际的 mem_max_addr 值，需要调用 sbrk 为内存分配器掌管的内存扩容
        3. 每次调用 sbrk 时， mem_max_addr 增量以 MAXHEAP对齐
    */
    
    long rest_size = mem_max_addr - mem_brk; // TODO: 修改该行，计算当前剩余的堆空间大小

    if (rest_size < incr) {
        // 如果剩余空间不够，需要使用 sbrk 拓展
        long need_size = incr - rest_size;  // 缺少的空间
        long need_size_aligned = (need_size + MAX_HEAP - 1) / MAX_HEAP * MAX_HEAP;  // 上取整到 MAX_HEAP 的倍数

        // TODO: 使用 sbrk 拓展堆 need_size_aligned 字节的空间，并更新 mem_max_addr
        mem_max_addr = (char*)sbrk(need_size_aligned) + need_size_aligned;
    }

    // TODO: 修改下面的代码，分配 size 字节的内存空间，并更新 mem_brk，然后返回分配的内存空间的起始地址
    mem_brk = mem_brk + incr;
    
    return (void *)old_brk;
}

/*
 * mem_heap_lo - return address of the first heap byte
 */
void *mem_heap_lo()
{
    return (void *)mem_start_brk;
}

/* 
 * mem_heap_hi - return address of last heap byte
 */
void *mem_heap_hi()
{
    return (void *)(mem_brk - 1);
}

/*
 * mem_heapsize() - returns the heap size in bytes
 */
size_t mem_heapsize() 
{
    return (size_t)(mem_brk - mem_start_brk);
}

/*
 * mem_pagesize() - returns the page size of the system
 */
size_t mem_pagesize()
{
   /*return (size_t)getpagesize();*/
   return 4096;
}
