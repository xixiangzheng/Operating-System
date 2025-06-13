/*
 * mm.c - malloc package with explicit free list and first fit/best fit search
 * 
 * NOTE_TO_STUDENTS: Highly recommend you read the experiment tutorial
 * and get a clear view about the memory structure of free and allocated
 * block before you start coding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"


/* Word takes 8 bytes and double word takes 16 bytes */
#define WSIZE 8
#define DSIZE 16
#define CHUNKSIZE (1 << 12)
#define MAX(x, y) ((x) > (y) ? (x) : (y))

/*
    Each head or foot is WSIZE-sized and organized as below:
    |---------size (62bits)----------|--prev_alloc (1 bit)--|---alloc (1 bit)---|

    Value of size is a multiple of 8, so the 2 lowest bits can be used by prev_alloc and alloc.
*/
/* Pack each argument in the order in brackets */
#define PACK(size, prev_alloc, alloc) (((size) & ~0x7) | ((prev_alloc << 1) & ~0x1) | (alloc)) // In fact, we enforce SIZE to be multiple of 8 :)
#define PACK_PREV_ALLOC(val, prev_alloc) ((val & ~(1<<1)) | (prev_alloc << 1))
#define PACK_ALLOC(val, alloc) ((val) | (alloc))

/* Read and write a word at address p */
#define GET(p) (*(unsigned long *)(p))
#define PUT(p, val) (*(unsigned long *)(p) = (val))

/* Use mask to get different fields at address p */
#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)
#define GET_PREV_ALLOC(p) ((GET(p) & 0x2) >> 1)

/* Get head, foot, previous and next block of block bp.
   NOTE: bp is the beginning address of the block, not the addressof head */
#define HDRP(bp) ((char *)(bp)-WSIZE)
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) /*only for free blk*/
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp)-WSIZE)))
#define PREV_BLKP(bp) ((char *)(bp)-GET_SIZE(((char *)(bp)-DSIZE))) /*only when prev_block is free, which can usd*/

#define GET_PRED(bp) (GET(bp))
#define SET_PRED(bp, val) (PUT(bp, val))

#define GET_SUCC(bp) (GET(bp + WSIZE))
#define SET_SUCC(bp, val) (PUT(bp + WSIZE, val))

#define MIN_BLK_SIZE (2 * DSIZE)
/*explicit free list end*/

/* single word (8) or double word (16) alignment */
#define ALIGNMENT WSIZE

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

static char *heap_listp;
static char *free_listp;

#if FIRST_FIT
static void *find_fit_first(size_t asize);
#else
static void *find_fit_best(size_t asize);
#endif

static void *extend_heap(size_t words);
static void *coalesce(void *bp);
// static void *find_fit(size_t asize);
static void place(void *bp, size_t asize);
static void add_to_free_list(void *bp);
static void delete_from_free_list(void *bp);
double get_utilization();
void mm_check(const char * function, char* bp);

/*
    TODO:
        完成一个简单的分配器内存使用率统计
        user_malloc_size: 用户申请内存量
        heap_size: 分配器占用内存量
    HINTS:
        1. 在适当的地方修改上述两个变量，细节参考实验文档
        2. 在 get_utilization() 中计算使用率并返回
*/
size_t user_malloc_size = 0;
size_t heap_size = 0;
double get_utilization() {
    return (double) ((user_malloc_size * 1.0) / heap_size); 
}
/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    mem_init();     // 请添加该行。
    free_listp = NULL;

    if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *)-1)
        return -1;

    PUT(heap_listp, 0);
    PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1, 1));
    PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1, 1));
    PUT(heap_listp + (3 * WSIZE), PACK(0, 1, 1));
    heap_size += 4 * WSIZE;
    heap_listp += (2 * WSIZE);

    if (extend_heap(CHUNKSIZE / WSIZE) == NULL)
        return -1;

    user_malloc_size = 0;
    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    size_t newsize;         /* Adjusted block size */
    size_t extend_size;     /* Amount to extend head if not fit */
    char *bp;

    /* Ignore spurious requesets */
    if (size == 0)
        return NULL;
    /* Adjust block size to include overhead and alignment reqs. */
    newsize = MAX(MIN_BLK_SIZE, ALIGN((size + WSIZE))); 

    /* Search the free list for a fit */
    #if FIRST_FIT
    if ((bp = find_fit_first(newsize)) != NULL)
    {
        // mm_check(__FUNCTION__, bp);
        place(bp, newsize);
        user_malloc_size += GET_SIZE(HDRP(bp));
        return bp;
    }
    #else
    if ((bp = find_fit_best(newsize)) != NULL)
    {
        // mm_check(__FUNCTION__, bp);
        place(bp, newsize);
        user_malloc_size += GET_SIZE(HDRP(bp));
        return bp;
    }
    #endif
    /*no fit found.*/
    extend_size = MAX(newsize, CHUNKSIZE);
    if ((bp = extend_heap(extend_size / WSIZE)) == NULL)
    {
        return NULL;
    }
    place(bp, newsize);
    user_malloc_size += GET_SIZE(HDRP(bp));
    return bp;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *bp)
{
    size_t size = GET_SIZE(HDRP(bp));
    size_t prev_alloc = GET_PREV_ALLOC(HDRP(bp));
    void *head_next_bp = NULL;

    PUT(HDRP(bp), PACK(size, prev_alloc, 0));
    PUT(FTRP(bp), PACK(size, prev_alloc, 0));
    // mm_check(__FUNCTION__, bp);

     /*notify next_block, i am free*/
    head_next_bp = HDRP(NEXT_BLKP(bp));
    PUT(head_next_bp, PACK_PREV_ALLOC(GET(head_next_bp), 0));

    user_malloc_size -= GET_SIZE(HDRP(bp));
    coalesce(bp);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;

    newptr = mm_malloc(size);
    if (newptr == NULL)
        return NULL;
    copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    if (size < copySize)
        copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}

static void *extend_heap(size_t words)
{
    /*get heap_brk*/
    char *old_heap_brk = mem_sbrk(0);
    size_t prev_alloc = GET_PREV_ALLOC(HDRP(old_heap_brk));

    /*printf("\nin extend_heap prev_alloc=%u\n", prev_alloc);*/
    char *bp;
    size_t size;
    size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;

    if ((long)(bp = mem_sbrk(size)) == -1)
        return NULL;
    
    PUT(HDRP(bp), PACK(size, prev_alloc, 0)); /*last free block*/
    PUT(FTRP(bp), PACK(size, prev_alloc, 0));

    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 0, 1)); /*break block*/
    heap_size += GET_SIZE(HDRP(bp));
    return coalesce(bp);
}

static void *coalesce(void *bp)
{
    size_t prev_alloc = GET_PREV_ALLOC(HDRP(bp));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size = GET_SIZE(HDRP(bp));
    /*
        TODO:
            将 bp 指向的空闲块 与 相邻块合并
            结合前一块及后一块的分配情况，共有 4 种可能性
            分别完成相应case下的 数据结构维护逻辑
    */
    if (prev_alloc && next_alloc) /* 前后都是已分配的块 */
    {
    }
    else if (prev_alloc && !next_alloc) /*前块已分配，后块空闲*/
    {   
        char* next_bp = NEXT_BLKP(bp);
        delete_from_free_list(next_bp);
        size_t size_next = GET_SIZE(HDRP(next_bp));

        PUT(HDRP(bp), PACK(size + size_next, 1, 0));
        PUT(FTRP(next_bp), PACK(size + size_next, 1, 0));
    }
    else if (!prev_alloc && next_alloc) /*前块空闲，后块已分配*/
    {
        char* prev_bp = PREV_BLKP(bp);
        delete_from_free_list(PREV_BLKP(bp));
        size_t size_prev = GET_SIZE(HDRP(prev_bp));
        size_t prev_alloc = GET_PREV_ALLOC(HDRP(prev_bp));

        PUT(HDRP(prev_bp), PACK(size + size_prev, prev_alloc, 0));
        PUT(FTRP(bp), PACK(size + size_prev, prev_alloc, 0));
        bp = prev_bp;
    }
    else /*前后都是空闲块*/
    {
        char* prev_bp = PREV_BLKP(bp);
        char* next_bp = NEXT_BLKP(bp);
        delete_from_free_list(prev_bp);
        delete_from_free_list(next_bp);

        size_t size_prev = GET_SIZE(HDRP(prev_bp));
        size_t size_next = GET_SIZE(HDRP(next_bp));
        size_t prev_alloc = GET_PREV_ALLOC(HDRP(prev_bp));

        PUT(HDRP(prev_bp), PACK(size + size_prev + size_next, prev_alloc, 0));
        PUT(FTRP(next_bp), PACK(size + size_prev + size_next, prev_alloc, 0));
        bp = PREV_BLKP(bp);
    }
    add_to_free_list(bp);
    // mm_check(__FUNCTION__, bp);
    return bp;
}

#if FIRST_FIT
static void *find_fit_first(size_t asize)
{
    /* 
        首次匹配算法
        TODO:
            遍历 freelist， 找到第一个合适的空闲块后返回
        
        HINT: asize 已经计算了块头部的大小
    */
    char *ptr = free_listp;
    while(ptr) {
        if(GET_SIZE(HDRP(ptr)) > asize) return ptr;
        ptr = (void *) GET_SUCC(ptr);
    }
    return NULL; // 换成实际返回值
}

#else
static void* find_fit_best(size_t asize) {
    /* 
        最佳配算法
        TODO:
            遍历 freelist， 找到最合适的空闲块，返回
        
        HINT: asize 已经计算了块头部的大小
    */
    char *ptr = free_listp;
    char *fit_best = NULL;
    while(ptr) {
        if(GET_SIZE(HDRP(ptr)) > asize){
            if (fit_best == NULL){
                fit_best = ptr;
            }
            else if (GET_SIZE(HDRP(ptr)) < GET_SIZE(HDRP(fit_best))) {
                fit_best = ptr;
            }
        }
        ptr = (void *) GET_SUCC(ptr);
    }
    return fit_best; // 换成实际返回值
}
#endif

static void place(void *bp, size_t asize)
{
    /* 
        TODO:
        将一个空闲块转变为已分配的块

        HINTS:
            1. 若空闲块在分离出一个 asize 大小的使用块后，剩余空间不足空闲块的最小大小，
                则原先整个空闲块应该都分配出去
            2. 若剩余空间仍可作为一个空闲块，则原空闲块被分割为一个已分配块+一个新的空闲块
            3. 空闲块的最小大小已经 #define，或者根据自己的理解计算该值
    */
    
    size_t prev_alloc = GET_PREV_ALLOC(HDRP(bp));
    size_t prev_size = GET_SIZE(HDRP(bp));

    delete_from_free_list(bp);

    if(prev_size - asize > MIN_BLK_SIZE) {

        PUT(HDRP(bp), PACK(asize, prev_alloc, 1));
        char* next_bp = NEXT_BLKP(bp);
        PUT(HDRP(next_bp), PACK(prev_size - asize, 1, 0));
        PUT(FTRP(next_bp), PACK(prev_size - asize, 1, 0));

        add_to_free_list(next_bp);
    } 
    else {
        PUT(HDRP(bp), PACK(prev_size, prev_alloc, 1));
        char* next_bp = NEXT_BLKP(bp);

        size_t size_next = GET_SIZE(HDRP(next_bp));
        size_t next_alloc = GET_ALLOC(HDRP(next_bp));

        PUT(HDRP(next_bp), PACK(size_next, 1, next_alloc));
        if(!next_alloc) PUT(FTRP(next_bp), PACK(size_next, 1, next_alloc));
    }
}

static void add_to_free_list(void *bp)
{
    /*set pred & succ*/
    if (free_listp == NULL) /*free_list empty*/
    {
        SET_PRED(bp, 0);
        SET_SUCC(bp, 0);
        free_listp = bp;
    }
    else
    {
        SET_PRED(bp, 0);
        SET_SUCC(bp, (size_t)free_listp); /*size_t ???*/
        SET_PRED(free_listp, (size_t)bp);
        free_listp = bp;
    }
}

static void delete_from_free_list(void *bp)
{
    size_t prev_free_bp=0;
    size_t next_free_bp=0;
    if (free_listp == NULL)
        return;
    prev_free_bp = GET_PRED(bp);
    next_free_bp = GET_SUCC(bp);

    if (prev_free_bp == next_free_bp && prev_free_bp != 0)
    {

    }
    if (prev_free_bp && next_free_bp) /*11*/
    {
        SET_SUCC(prev_free_bp, GET_SUCC(bp));
        SET_PRED(next_free_bp, GET_PRED(bp));
    }
    else if (prev_free_bp && !next_free_bp) /*10*/
    {
        SET_SUCC(prev_free_bp, 0);
    }
    else if (!prev_free_bp && next_free_bp) /*01*/
    {
        SET_PRED(next_free_bp, 0);
        free_listp = (void *)next_free_bp;
    }
    else /*00*/
    {
        free_listp = NULL;
    }
}


/*
    mm_check - print the information of the free block beginning with **bp**.
    Please read the experiment tutorial before you use this function.
*/
void mm_check(const char *function, char* bp)
{
    #ifdef DEBUG
    printf("\n---cur func: %s :\n", function);
    printf("addr_start: 0x%lx, addr_end: 0x%lx, size_head: %lu, size_foot: %lu, PRED=0x%lx, SUCC=0x%lx \n", (size_t)bp - WSIZE,
        (size_t)FTRP(bp), GET_SIZE(HDRP(bp)), GET_SIZE(FTRP(bp)), GET_PRED(bp), GET_SUCC(bp));
    #endif
}
