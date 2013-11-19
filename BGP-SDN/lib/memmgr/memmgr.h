/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */
#ifndef _MEMMGR_H
#define _MEMMGR_H

#define MEMMGR_RUNTIME_CHECK

#define BYTES_PER_MB    1024 * 1024

/* We use 0 as infinite memory allowed per PM */
#define PM_MEM_SIZE_INF 0

#ifndef CPU  /* not vxWorks or OSE */
/*
 *  For each enabled protocol module, the memory manager pre-allocates 5 MB
 *  of memory at the start-up. When any given free bucket memory is used up,
 *  the mem manager obtains requested memory from system heap. At no point,
 *  any of the allocated memory is returned to the system pool.
 *
 *  Note that the memory manager gets more than 5 MB of memory to accommodate
 *  the overhead involved in maintaining the memory.
 *
 *  If the pre allocated memory size varies from pm to pm, then the following
 *  table is replicated for each such module with appropriate predefined
 *  memory blocks.   
 */

#define MIN_PM_MEM_SIZE   5 * BYTES_PER_MB
#define MAX_PM_MEM_SIZE   PM_MEM_SIZE_INF 

/* pre-defined memory block count - a total of 5 MB user buffer space */
#define SIZE_32_COUNT   16384       /*  512k 256k 544k 1312k */
#define SIZE_64_COUNT   16384       /* 1024k 256k 544k 1824k */
#define SIZE_128_COUNT  8192        /* 1024k 128k 272k 1424k */
#define SIZE_256_COUNT  1024        /*  256k  16k  34k  306k */
#define SIZE_512_COUNT  1024        /*  512k  16k  34k  562k */
#define SIZE_1K_COUNT   256         /*  256k */
#define SIZE_2K_COUNT   128         /*  256k */
#define SIZE_4K_COUNT   64          /*  256k */
#define SIZE_8K_COUNT   32          /*  256k */
#define SIZE_16K_COUNT  16          /*  256k */
#define SIZE_32K_COUNT  8           /*  256k */
#define SIZE_64K_COUNT  4           /*  256k */
#define SIZE_128K_COUNT 2           /*  256k */

#else

#define MIN_PM_MEM_SIZE  10 * BYTES_PER_MB
#define MAX_PM_MEM_SIZE  PM_MEM_SIZE_INF 

/*
 *  In case of VxWorks (ipnet), all protocol modules are linked in the same
 *  binary. The total pre-allocated memory should be 5 MB * number of PM's.
 *  A total of 10 MB is allocated by default.
 */
#define SIZE_32_COUNT   32768       /* 1024k */
#define SIZE_64_COUNT   16384       /* 1024k */
#define SIZE_128_COUNT  8192        /* 1024k */
#define SIZE_256_COUNT  4096        /* 1024k */
#define SIZE_512_COUNT  2048        /* 1024k */
#define SIZE_1K_COUNT   1024        /* 1024k */
#define SIZE_2K_COUNT   512         /* 1024k */
#define SIZE_4K_COUNT   256         /* 1024k */
#define SIZE_8K_COUNT   128         /* 1024k */
#define SIZE_16K_COUNT  16          /*  256k */
#define SIZE_32K_COUNT  8           /*  256k */
#define SIZE_64K_COUNT  4           /*  256k */
#define SIZE_128K_COUNT 2           /*  256k */

#endif

#define MAX_FILE_SZ     14

/* memory corruption check areas */
#define PRE_GUARD_AREA  8         
#define POST_GUARD_AREA 8
#define MAX_GUARD_AREA  16           

/*  memory magic cookie */
#define MAGIC_COOKIE    0xA5A5

/* block sizes */
#define BLK_32    32
#define BLK_64    64
#define BLK_128   128
#define BLK_256   256
#define BLK_512   512 
#define BLK_1K    1024
#define BLK_2K    2048
#define BLK_4K    4096
#define BLK_8K    8192
#define BLK_16K   16384
#define BLK_32K   32768
#define BLK_64K   65536
#define BLK_128K  131072

/* encoded block size */
#define SIZE0   0      /* decoded value of SIZE0 is BLK_32 */
#define SIZE1   1
#define SIZE2   2
#define SIZE3   3
#define SIZE4   4
#define SIZE5   5
#define SIZE6   6
#define SIZE7   7
#define SIZE8   8
#define SIZE9   9
#define SIZE10  10
#define SIZE11  11
#define SIZE12  12

/* bucket array indices */
#define BUKT0   0
#define BUKT1   1
#define BUKT2   2
#define BUKT3   3
#define BUKT4   4
#define BUKT5   5
#define BUKT6   6
#define BUKT7   7
#define BUKT8   8
#define BUKT9   9
#define BUKT10  10
#define BUKT11  11
#define BUKT12  12


#define BUKT_COUNT      13

/* Header bit fields */
#define MEM_BLK_PALLOC   1   /* pre-allocated memory at the startup */
#define MEM_BLK_MALLOC   2   /* memory obtained from system pool */
#define MEM_BLK_FREE     4   /* in free pool */
#define MEM_BLK_ALLOC    8   /* in allocated pool */

/* Global memory manager structure */
struct ipi_mem_global
{
  unsigned int max_mem_size;
  struct lib_globals *lg;
};

/*
 *  Overall stats of total pre-allocated memory and its overhead + any memory
 *  obtained after exhausting preallocated memory & its associated overhead.
 *  Also, contains a list of preallocated memory pointers to be used for
 *  releasing the meory back to system pool.
 */
struct ipi_mem_info
     {
        unsigned int  pa_mem_size;
        unsigned int  pa_mem_blocks;
        unsigned int  pa_mem_overhead;
        unsigned int  rt_mem_size;
        unsigned int  rt_mem_blocks;
        unsigned int  rt_mem_overhead;
        void          *pool_ptr[BUKT_COUNT];
     };

/*
 *  Memory manager table for holding stats for each mtype.
 *   - allocated table is based on mtype
 *   - free tbale is based on buckets having fixed size blocks.
 */
struct ipi_mem_table 
     {
        void            *list;      /* points to mtype memory list */
        unsigned int    size;       /* total size of memory allocated or free */
        unsigned int    req_size;   /* total user requested size */
        unsigned int    count;      /* number of blocks allocated or free */
     };

/*
 *  This header precedes each user buffer.  This header size must be multiple of
 *  16 bytes to avoid alignment exceptions.
 */
struct ipi_memblock_header
     {
        struct ipi_memblock_header *next;   /* linked list pointer */
        struct ipi_memblock_header *prev;
        unsigned char     size;             /* size of allocated bucket size */
        unsigned char     flags;            /* memory flags */
        unsigned short    cookie;           /* validate as authentic memory */
        unsigned short    req_size;         /* user requested size */
        unsigned short    mid;              /* mtype id */
#ifdef MEMMGR_RUNTIME_CHECK
        unsigned char     guard[PRE_GUARD_AREA];
#endif
     };

/*
 *  Mtype memory debug information for tracing back each memory allocation
 *  or freeing to a filename and line number at which it is initiated. This
 *  information is appended at the end of each memblock. This feature is
 *  used only for internal builds.
 */
struct ipi_memblock_trailer
     {
        unsigned char  guard[POST_GUARD_AREA];
        unsigned char  filename[MAX_FILE_SZ];  
        unsigned short line_number;
     };

/*
 *  Mutex semaphore support functions for any RTOS
 */
#ifdef CPU  
#define MEMMGR_MUTEX_START      memmgr_sem_take()
#define MEMMGR_MUTEX_END        memmgr_sem_give()
#else
#define MEMMGR_MUTEX_START
#define MEMMGR_MUTEX_END
#endif
int         memmgr_sem_create (void);
int         memmgr_sem_take (void);
int         memmgr_sem_give (void);
int         memmgr_sem_delete (void);


/*
 * Function prototypes
 */
int          memmgr_init_memtable ();
int          memmgr_free_memtable ();
void         memmgr_set_lg (void *);
void         memmgr_unset_lg (void *);
void *       memmgr_malloc (int, int, char *, int);
void *       memmgr_calloc (int, int, char *, int);
void *       memmgr_realloc (void *, int, int, char *, int);
void         memmgr_free (int, void *, char *, int);
char *       memmgr_strdup (const char *, int, char *, int);

unsigned int memmgr_get_mtype_size (int);
int          memmgr_get_mtype_count (int);
unsigned int memmgr_get_total_mtype_size ();
int          memmgr_get_total_mtype_count ();
unsigned int memmgr_get_total_mtype_req_size ();
unsigned int memmgr_get_bucket_size (int);
int          memmgr_get_bucket_block_size (int);
int          memmgr_get_bucket_count (int);

unsigned int memmgr_get_pa_mem_size ();
unsigned int memmgr_get_pa_mem_overhead ();
unsigned int memmgr_get_pa_mem_blocks ();

unsigned int memmgr_get_rt_mem_size ();
unsigned int memmgr_get_rt_mem_overhead ();
unsigned int memmgr_get_rt_mem_blocks ();

#endif /* _MEMMGR_H */
