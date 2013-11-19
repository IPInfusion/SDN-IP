/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */
#include "pal.h"
#include "lib.h"

#include "log.h"
#include "cli.h"
#include "memory.h"
#include "memmgr.h"
#include "memmgr_config.h"

/*
 *  Global declaration
 */
static struct ipi_mem_table  mtype_table[MTYPE_MAX];
static struct ipi_mem_table  free_table[BUKT_COUNT];
static struct ipi_mem_info   mem_stats;
static struct ipi_mem_global mem_global;

#define MEMMGR_LG mem_global.lg

#ifdef HAVE_ISO_MACRO_VARARGS
#define MEMMGR_LOG_INFO(...)                                \
do {                                                             \
  if (MEMMGR_LG)                                                 \
    zlog_info (MEMMGR_LG, __VA_ARGS__);                     \
} while (0)

#define MEMMGR_LOG_WARN(...)                                \
do {                                                             \
  if (MEMMGR_LG)                                                 \
    zlog_warn (MEMMGR_LG, __VA_ARGS__);                     \
} while (0)

#define MEMMGR_LOG_ERR(...)                                 \
do {                                                             \
  if (MEMMGR_LG)                                                 \
    zlog_err (MEMMGR_LG, __VA_ARGS__);                      \
} while (0)
#else
#define MEMMGR_LOG_INFO(ARGS...)                            \
do {                                                             \
  if (MEMMGR_LG)                                                 \
    zlog_info (MEMMGR_LG, ARGS);                            \
} while (0)

#define MEMMGR_LOG_WARN(ARGS...)                            \
do {                                                             \
  if (MEMMGR_LG)                                                 \
    zlog_warn (MEMMGR_LG, ARGS);                            \
} while (0)

#define MEMMGR_LOG_ERR(ARGS...)                             \
do {                                                             \
  if (MEMMGR_LG)                                                 \
    zlog_err (MEMMGR_LG, ARGS);                             \
} while (0)
#endif /* HAVE_ISO_MACRO_VARARGS */


/*
 * forward function prototypes
 */
int    memmgr_create_free_table();
void   memmgr_partition_memory (int, int, struct ipi_mem_table *);
char   *memmgr_get_user_membuf (int, int, char *, int);
int    memmgr_decode_header_size (int);
int    memmgr_encode_header_size (int);
void   memmgr_buffer_check (void *);
void   memmgr_add_to_mtype_table (int, struct ipi_memblock_header *, int);
void   memmgr_remove_from_mtype_table (int, void *);
void   memmgr_add_to_free_table (void *);
struct ipi_memblock_header * memmgr_get_from_free_table (int);
struct ipi_memblock_header * memmgr_get_from_system_heap (int);
int    memmgr_get_ipi_overhead_size ();
int    memmgr_get_ipi_header_size ();
struct ipi_memblock_trailer * memmgr_get_ipi_trailer_offset ();
int    memmgr_get_bucket_index (int);
int    memmgr_get_bucket_count (int);
void   memmgr_set_pa_stats (int, int, void *);
void   memmgr_set_rt_stats (int);

/****************************************************************
 * The following are the API's to access memory manager data    *
 ****************************************************************/

/*
 * Set the lib globals for memory manager
 */
void
memmgr_set_lg (void *lg)
{
  if (MEMMGR_LG == NULL)
    MEMMGR_LG = (struct lib_globals *)lg;
  return;
}

/*
 * Unset the lib globals for memory manager
 */
void
memmgr_unset_lg (void *lg)
{
  if (MEMMGR_LG == (struct lib_globals *)lg)
    MEMMGR_LG = NULL;
  return;
}
/*
 *  Initialize the mtype and free memory tables
 */
int
memmgr_init_memtable (void)
{
    int  i;
    int  sts;

    MEMMGR_MUTEX_START;

    /* init memory table */
    pal_mem_set (mtype_table,  0,  sizeof (struct ipi_mem_table) * MTYPE_MAX);
    pal_mem_set (free_table,   0,  sizeof (struct ipi_mem_table) * BUKT_COUNT);

    mem_stats.pa_mem_size      = 0;
    mem_stats.pa_mem_blocks    = 0;
    mem_stats.pa_mem_overhead  = 0;
    mem_stats.rt_mem_size      = 0;
    mem_stats.rt_mem_blocks    = 0;
    mem_stats.rt_mem_overhead  = 0;

    pal_mem_set (&mem_global,   0,  sizeof (struct ipi_mem_global));
    mem_global.max_mem_size     = MAX_PM_MEM_SIZE;

    for (i = 0; i < BUKT_COUNT; i++)
      mem_stats.pool_ptr[i] = 0;

    for (i = 0; i < MTYPE_MAX; i++)
      {
        mtype_table[i].list  = NULL;
        mtype_table[i].count = 0;
        mtype_table[i].size  = 0;
        mtype_table[i].req_size = 0;
      }

    for (i = 0; i < BUKT_COUNT; i++)
      {
        free_table[i].list  = NULL;
        free_table[i].size  = 0;
        free_table[i].count = 0;
        free_table[i].req_size = 0;
      }

    /* populate free_table with pre-defined memory size */
    sts = memmgr_create_free_table ();

    if (sts < 0)
      {
        MEMMGR_LOG_ERR ("Failed to create pre-defined free memory list\n");
        MEMMGR_MUTEX_END;
        return sts;
      }

    /*
     *  now that we have memory, partition each bucket memory into pre-defined
     *  fixed memory size blocks
     */
    memmgr_partition_memory (SIZE_32_COUNT,   BLK_32,  &free_table[BUKT0]);
    memmgr_partition_memory (SIZE_64_COUNT,   BLK_64,  &free_table[BUKT1]);
    memmgr_partition_memory (SIZE_128_COUNT,  BLK_128, &free_table[BUKT2]);
    memmgr_partition_memory (SIZE_256_COUNT,  BLK_256, &free_table[BUKT3]);
    memmgr_partition_memory (SIZE_512_COUNT,  BLK_512, &free_table[BUKT4]);
    memmgr_partition_memory (SIZE_1K_COUNT,   BLK_1K,  &free_table[BUKT5]);
    memmgr_partition_memory (SIZE_2K_COUNT,   BLK_2K,  &free_table[BUKT6]);
    memmgr_partition_memory (SIZE_4K_COUNT,   BLK_4K,  &free_table[BUKT7]);
    memmgr_partition_memory (SIZE_8K_COUNT,   BLK_8K,  &free_table[BUKT8]);
    memmgr_partition_memory (SIZE_16K_COUNT,  BLK_16K, &free_table[BUKT9]);
    memmgr_partition_memory (SIZE_32K_COUNT,  BLK_32K, &free_table[BUKT10]);
    memmgr_partition_memory (SIZE_64K_COUNT,  BLK_64K, &free_table[BUKT11]);
    memmgr_partition_memory (SIZE_128K_COUNT, BLK_128K,&free_table[BUKT12]);

    MEMMGR_MUTEX_END;

    return sts;
}


/*
 *  memmgr_free_memtable ()
 *
 *   Return all process allocated memory back to system heap at the exit time
 */
result_t
memmgr_free_memtable ()
{
    int    index;
    int    count;
    int    rt_count;
    struct ipi_memblock_trailer *p;
    struct ipi_memblock_header  *hdr;
    struct ipi_memblock_header  *temp;

    MEMMGR_MUTEX_START;

    rt_count = 0;

    /* free memory blocks from free_table */
    for (index = 0; index < BUKT_COUNT; index++)
      {
        hdr = (struct ipi_memblock_header *) free_table[index].list;
        count = free_table[index].count;
        while (count > 0 && hdr != NULL)
          {
            temp = hdr;
            hdr = hdr->next;
            if (CHECK_FLAG (temp->flags, MEM_BLK_MALLOC))
              {
                rt_count++;
                free (temp);
              }
            count--;
          }
      }

    /* Count should match sum of individual blocks in a pool */
    if (count != 0)
      MEMMGR_LOG_ERR ("Mismatch of count and # of elements in free list\n");

    /* free memory blocks from mtype_table */
    for (index = 0; index < MTYPE_MAX; index++)
      {
        hdr = (struct ipi_memblock_header *) mtype_table[index].list;
        count = mtype_table[index].count;

        while (count > 0 && hdr != NULL)
          {
            temp = hdr;
            p =  memmgr_get_ipi_trailer_offset (hdr);
            hdr = hdr->next;
            if (CHECK_FLAG (temp->flags, MEM_BLK_MALLOC))
              {
                rt_count++;
                free (temp);
              }
            count--;
          }
      }

    if (count != 0)
      MEMMGR_LOG_ERR ("Mismatch of count and # of elements in mtype list\n");

    MEMMGR_LOG_INFO ("  %d vs %d \n", rt_count, mem_stats.rt_mem_blocks);

    /* free any preallocated memory first */
    for (index = 0; index < BUKT_COUNT; index++)
      {
        if (mem_stats.pool_ptr[index])
          {
            MEMMGR_LOG_INFO ("POOL FREE: %p \n", mem_stats.pool_ptr[index]);
            free (mem_stats.pool_ptr[index]);
          }
      }

    MEMMGR_LOG_INFO ("Memory release OK\n");

    MEMMGR_MUTEX_END;

    return 0;
}

/*
 *   memmgr_malloc()
 *
 *   Return a memory buffer pointer - NULL if the call fails
 */
void *
memmgr_malloc (int size, int mtype, char *filename, int line)
{
    char *bufptr;

    /* do parameter check */
    if (size == 0)
      return NULL;

    if (mtype < 0 || mtype >= MTYPE_MAX)
      {
        MEMMGR_LOG_ERR ("Unknown memory type specified\n");
        return NULL;
      }

     if (memmgr_map_mtype_index (mtype) < 0)
       {
         MEMMGR_LOG_ERR ("Mismatch of mtype in configuration table\n");
         return NULL;
       }

     MEMMGR_MUTEX_START;

     bufptr = memmgr_get_user_membuf (size, mtype, filename, line);

     MEMMGR_MUTEX_END;

     return (void *) bufptr;
}


/*
 *   memmgr_calloc()
 *
 *   Allocate, initialize, and return memory pointer.
 */
void *
memmgr_calloc (int size,  int mtype,  char *filename,  int line)
{
    unsigned char *bptr;

    bptr = memmgr_malloc (size, mtype, filename, line);

    if (bptr == NULL)
      return NULL;

    pal_mem_set (bptr, 0, size);

    return (void *) bptr;
}

/*
 *  memmgr_realloc()
 *
 *  Reallocate memory, if necessary, and copy the contents of original buffer.
 */
void *
memmgr_realloc (void *ptr,  int new_size, int mtype, char *filename, int line)
{
    struct ipi_memblock_header *mhdr;
    void   *buf;
    int    old_size;

    if (ptr != NULL)
      {
        mhdr = (struct ipi_memblock_header *)
               ((char *) ptr - memmgr_get_ipi_header_size ());

        /* have enough memory to cover requested size */
        if ((old_size = memmgr_decode_header_size (mhdr->size)) >= new_size)
          return ptr;

        buf = memmgr_malloc (new_size, mtype, filename, line);

        /* copy memory contents to this new buffer */
        if (buf != NULL)
          pal_mem_cpy (buf, ptr, old_size);

        memmgr_free (mtype, ptr, filename, line);
      }
    else
      {
        buf = memmgr_malloc (new_size, mtype, filename, line);
      }

     return buf;
}


/*
 *   memmgr_free()
 *
 *   remove a memory block from mtype table and add it to free table for
 *   subsequent use. In this implementation none of the allocated memory is ever
 *   returned to the system heap
 */
void
memmgr_free (int mtype, void *ptr, char *file, int line)
{
     if (ptr == NULL)
       return;

     MEMMGR_MUTEX_START;

#ifdef MEMMGR_RUNTIME_CHECK
     memmgr_buffer_check (ptr);
#endif

     memmgr_remove_from_mtype_table (mtype, ptr);

     memmgr_add_to_free_table (ptr);

     MEMMGR_MUTEX_END;
}


/*
 *   memmgr_strdup ()
 *
 *   Allocate large enough memory to make a copy of the original string.
 */
char *
memmgr_strdup (const char *str1, int mtype, char *file, int line)
{
    char *str2;
    int  len = 0;

    if (str1)
      len = pal_strlen (str1);

    str2 = memmgr_malloc (len+1, mtype, file, line);

    if (str2 == NULL)
      return NULL;

    pal_strcpy (str2, str1);

    return str2;
}


/*************************************************
 * Following are the local support functions     *
 *************************************************/
/*
 *   memmgr_buffer_check ()
 *
 *   Do buffer bound check for any possible memory corruption
 */
void
memmgr_buffer_check (void *ptr)
{
    struct ipi_memblock_header  *mhdr;
    struct ipi_memblock_trailer *mtlr;
    int    i;

    mhdr = (struct ipi_memblock_header *)
           ((char *) ptr - memmgr_get_ipi_header_size ());

    /* check for MAGIC COOKIE before freeing memory */
    if (mhdr->cookie != MAGIC_COOKIE)
      MEMMGR_LOG_ERR ("Cookie check failed - hdr %p - mtype %d\n", mhdr, mhdr->mid);

    /* see if any of the pre guard area is corrupted */
    for (i = 0; i < PRE_GUARD_AREA; i++)
      {
        if (mhdr->guard[i] != 0xee)
          MEMMGR_LOG_ERR ("Pre guard check failed - hdr %p - mtype %d\n", mhdr, mhdr->mid);
      }

    /* get user buffer size */
    mtlr = memmgr_get_ipi_trailer_offset (mhdr);
    for (i = 0; i < POST_GUARD_AREA; i++)
      {
        if (mhdr->guard[i] != 0xee)
          MEMMGR_LOG_ERR ("Post guard check failed - hdr %p - mtype %d\n", mhdr, mhdr->mid);
      }
}


/*
 *  memmgr_get_memory ()
 *
 *  Given a block size and count of blocks, compute the total memory
 *  size to be pre-allocated for a given bucket. The block size represents
 *  the usable buffer space by any process. The overhead associated with
 *  each block (such as ipi header & guard area) is added on top of this size.
 */
void *
memmgr_get_memory (int count, int block_size, struct ipi_mem_table *tbl)
{
    unsigned int total_size;

    if (count == 0)
      return NULL;

    total_size = 0;
    total_size = count * block_size;
    total_size += count * memmgr_get_ipi_overhead_size ();

    /* track total size and number of blocks for each bucket */
    tbl->list = (void *) malloc (total_size);

    tbl->size = total_size;
    tbl->count = count;

    return tbl->list;
}


/*
 *  memmgr_create_free_table()
 *
 *   Obtain memory from system heap to populate free memory table at the startup.
 *   The free_table consist of several bucket sizes and each bucket holds pre-defined
 *   set of memory blocks of a specified size. This size doesn't include the
 *   header size or debug overhead.
 */
int
memmgr_create_free_table ()
{
    void *ptr;

    /* allocate memory per bucket */
    if ((ptr = memmgr_get_memory (SIZE_32_COUNT,  BLK_32,  &free_table[BUKT0])))
      memmgr_set_pa_stats (SIZE_32_COUNT, BLK_32, ptr);
    if (SIZE_32_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_64_COUNT,  BLK_64,  &free_table[BUKT1])))
      memmgr_set_pa_stats (SIZE_64_COUNT, BLK_64, ptr);
    if (SIZE_64_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_128_COUNT, BLK_128, &free_table[BUKT2])))
      memmgr_set_pa_stats (SIZE_128_COUNT, BLK_128, ptr);
    if (SIZE_128_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_256_COUNT, BLK_256, &free_table[BUKT3])))
      memmgr_set_pa_stats (SIZE_256_COUNT, BLK_256, ptr);
    if (SIZE_256_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_512_COUNT, BLK_512, &free_table[BUKT4])))
      memmgr_set_pa_stats (SIZE_512_COUNT, BLK_512, ptr);
    if (SIZE_512_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_1K_COUNT,  BLK_1K,  &free_table[BUKT5])))
      memmgr_set_pa_stats (SIZE_1K_COUNT, BLK_1K, ptr);
    if (SIZE_1K_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_2K_COUNT,  BLK_2K,  &free_table[BUKT6])))
      memmgr_set_pa_stats (SIZE_2K_COUNT, BLK_2K, ptr);
    if (SIZE_2K_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_4K_COUNT,  BLK_4K,  &free_table[BUKT7])))
      memmgr_set_pa_stats (SIZE_4K_COUNT, BLK_4K, ptr);
    if (SIZE_4K_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_8K_COUNT,  BLK_8K,  &free_table[BUKT8])))
      memmgr_set_pa_stats (SIZE_8K_COUNT, BLK_8K, ptr);
    if (SIZE_8K_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_16K_COUNT, BLK_16K, &free_table[BUKT9])))
      memmgr_set_pa_stats (SIZE_16K_COUNT, BLK_16K, ptr);
    if (SIZE_16K_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_32K_COUNT, BLK_32K, &free_table[BUKT10])))
      memmgr_set_pa_stats (SIZE_32K_COUNT, BLK_32K, ptr);
    if (SIZE_32K_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_64K_COUNT, BLK_64K, &free_table[BUKT11])))
      memmgr_set_pa_stats (SIZE_64K_COUNT, BLK_64K, ptr);
    if (SIZE_64K_COUNT && ptr == NULL) return -1;

    if ((ptr = memmgr_get_memory (SIZE_128K_COUNT, BLK_128K, &free_table[BUKT12])))
      memmgr_set_pa_stats (SIZE_128K_COUNT, BLK_128K, ptr);
    if (SIZE_128K_COUNT && ptr == NULL) return -1;

    return 0;
}


/*
 *   memmgr_partition_bucket_memory()
 *
 *   For a given bucket, partition the total memory into a list of same size
 *   memory blocks.
 */
void
memmgr_partition_memory (int count,  int block_size, struct ipi_mem_table *tbl)
{
     int    ipi_size;
     int    hdr_size;
     int    i;
     char   *ptr;
     struct ipi_memblock_header *mhdr;      /* 1st memory header in the list */
     struct ipi_memblock_header *nmhdr;     /* next memory header */

     if (count == 0)
       return;

     ipi_size = block_size +  memmgr_get_ipi_overhead_size ();
     hdr_size = memmgr_get_ipi_header_size ();

     ptr  = (char *) tbl->list;
     mhdr = (struct ipi_memblock_header *) ptr;
     pal_mem_set (mhdr, 0, hdr_size);

     mhdr->prev  = mhdr;
     mhdr->next  = mhdr;
     mhdr->size  = memmgr_encode_header_size (block_size);
     SET_FLAG (mhdr->flags, MEM_BLK_PALLOC);
     SET_FLAG (mhdr->flags, MEM_BLK_FREE);

     /* create double-linked list of memory blocks */
     for (i = 1; i < count; i++)
       {
         ptr += ipi_size;

         nmhdr = (struct ipi_memblock_header *) ptr;
         pal_mem_set (nmhdr, 0, hdr_size);

         nmhdr->prev  = mhdr->prev;
         nmhdr->next  = mhdr;
         nmhdr->size  = memmgr_encode_header_size (block_size);
         SET_FLAG (nmhdr->flags, MEM_BLK_PALLOC);
         SET_FLAG (nmhdr->flags, MEM_BLK_FREE);

         nmhdr->next->prev = nmhdr;
         nmhdr->prev->next = nmhdr;
      }
}

/*
 *   memmgr_add_to_mtype_table ()
 *
 *   Add a memory block to an appropriate mtype table slot.
 *
 */
void
memmgr_add_to_mtype_table (int mtype, struct ipi_memblock_header *nmhdr, int req_size)
{
    struct ipi_memblock_header *mhdr;

    if (nmhdr->cookie != 0)
        MEMMGR_LOG_WARN ("Mem block already exists in allocated table\n");

    if (mtype_table[mtype].list == NULL)
      {
        mtype_table[mtype].list = (void *) nmhdr;
      }
    else
      {
        mhdr = (struct ipi_memblock_header *) mtype_table[mtype].list;

        /* add to the list */
        nmhdr->prev = mhdr->prev;
        nmhdr->next = mhdr;
      }

    /* update memory header fields */
    nmhdr->cookie = MAGIC_COOKIE;
    SET_FLAG (nmhdr->flags, MEM_BLK_ALLOC);
    UNSET_FLAG (nmhdr->flags, MEM_BLK_FREE);
    nmhdr->req_size = req_size;
    nmhdr->mid = mtype;

    /* update linked list pointers */
    nmhdr->next->prev = nmhdr;
    nmhdr->prev->next = nmhdr;

    /* update mtype stats */
    mtype_table[mtype].size += memmgr_decode_header_size (nmhdr->size) +
                               memmgr_get_ipi_overhead_size ();

    mtype_table[mtype].req_size += req_size;
    mtype_table[mtype].count++;
}


/*
 *   memmgr_remove_from_mtype_table ()
 *
 *   Remove memory block of a given mtype from alloc table.
 *
 */
void
memmgr_remove_from_mtype_table (int mtype, void *ptr)
{
    struct ipi_memblock_header *mhdr;
    int    index;
    int    size;

    if (mtype_table[mtype].list == NULL)
      {
        MEMMGR_LOG_ERR ("Can't delete - mtype list is empty. mtype(%d, %s)\n",
                        mtype, memmgr_get_mtype_str (mtype));
        return;
      }

    /* get to the beginning of header */
    mhdr = (struct ipi_memblock_header *)
           ((char *) ptr - memmgr_get_ipi_header_size ());

    /* double free (?) - mem block don't exist in mtype list */
    if (mhdr->cookie != MAGIC_COOKIE)
      {
        MEMMGR_LOG_ERR ("Possible double free - cookie check failed\n");
        return;
      }

    /* block exists in both lists */
    if (CHECK_FLAG (mhdr->flags, MEM_BLK_FREE) &&
        CHECK_FLAG (mhdr->flags, MEM_BLK_ALLOC))
      {
        MEMMGR_LOG_ERR ("Mem block exists in mtype and free list\n");
        return;
      }

    /* make sure mtype matches before removing it from this list */
    if (mtype != mhdr->mid)
      {
        MEMMGR_LOG_ERR ("Mtype id mismatch - can't delete from mtype list\n");;
        return;
      }

    /* decode header size */
    size = memmgr_decode_header_size (mhdr->size);
    index = memmgr_get_bucket_index (size);

    /* in case of list having only one memory block */
    if (mhdr->next == mhdr && mhdr->prev == mhdr)
      mtype_table[mtype].list = NULL;
    /* memory block happens to be the first element in the list */
    else if (mhdr == (struct ipi_memblock_header *) mtype_table[mtype].list)
      mtype_table[mtype].list = mhdr->next;

    /* remove block from mtype list and update pointers */
    mhdr->prev->next = mhdr->next;
    mhdr->next->prev = mhdr->prev;

    /* update mtype stats */
    mtype_table[mtype].size -= memmgr_decode_header_size (mhdr->size) +
                               memmgr_get_ipi_overhead_size ();
    mtype_table[mtype].req_size -= mhdr->req_size;
    mtype_table[mtype].count--;
}


/*
 *   memmgr_add_to_free_table ()
 *
 *   Add a block of memory to free table.
 *
 */
void
memmgr_add_to_free_table (void *ptr)
{
    struct ipi_memblock_header *mhdr;
    struct ipi_memblock_header *hdr;
    int    index;

    hdr = (struct ipi_memblock_header *)
          ((char *) ptr - memmgr_get_ipi_header_size ());

    /* obtain bucket index and add to its list */
    index = memmgr_get_bucket_index (memmgr_decode_header_size (hdr->size));

    hdr->prev  = hdr;
    hdr->next  = hdr;

    hdr->cookie = 0;
    hdr->req_size = 0;
    hdr->mid = 0;

    /* move it from mtype table to free table */
    UNSET_FLAG (hdr->flags, MEM_BLK_ALLOC);
    SET_FLAG (hdr->flags, MEM_BLK_FREE);

    /* update free table stats */
    free_table[index].size += memmgr_decode_header_size (hdr->size) +
                              memmgr_get_ipi_overhead_size ();
    free_table[index].count++;

    if (free_table[index].list == NULL)
      {
        free_table[index].list = (void *) hdr;
        return;
      }

    mhdr = (struct ipi_memblock_header *) free_table[index].list;
    hdr->prev  = mhdr->prev;
    hdr->next  = mhdr;
    hdr->next->prev = hdr;
    hdr->prev->next = hdr;
}

/*
 *   memmgr_get_from_free_table ()
 *
 *   Return a memory block, if available, from  a given bucket.
 */
struct ipi_memblock_header *
memmgr_get_from_free_table (int index)
{
    struct ipi_memblock_header *mhdr;
    int    ipi_size;

    /* an empty list found */
    if (free_table[index].list == NULL)
      {
        /* pool list is empty, but count says otherwise */
        if (free_table[index].count != 0)
          MEMMGR_LOG_ERR ("List is empty but the count is non-zero\n");
        return NULL;
      }

    /* get bucket block size + overhead size*/
    ipi_size = memmgr_get_bucket_block_size (index) + memmgr_get_ipi_overhead_size ();

    mhdr = (struct ipi_memblock_header *) free_table[index].list;

    /* in case of list having only one memory block */
    if (mhdr->next == mhdr && mhdr->prev == mhdr)
      free_table[index].list = NULL;
    else
      free_table[index].list = mhdr->next;

    /* detach the first free block in the list and update
     * linked list pointers accordingly
     */
    mhdr->prev->next = mhdr->next;
    mhdr->next->prev = mhdr->prev;

    /* update bucket stats */
    free_table[index].count--;
    free_table[index].size -= ipi_size;

    /* init link pointers */
    mhdr->prev = mhdr;
    mhdr->next = mhdr;

    return mhdr;
}


/*
 *   memmgr_get_from_system_heap ()
 *
 *   get memory from system heap and initialize header fields.
 */
struct ipi_memblock_header *
memmgr_get_from_system_heap (int req_size)
{
     struct ipi_memblock_header *mhdr;
     int    ipi_size;
     int    block_size;
     int    index;

     /* map the req size to a best fit bucket size */
     index = memmgr_get_bucket_index (req_size);

     block_size = memmgr_get_bucket_block_size (index);

     /* get bucket fixed size in bytes & add the overhead */
     ipi_size = block_size + memmgr_get_ipi_overhead_size ();

     mhdr = (struct ipi_memblock_header *) malloc (ipi_size);
     if (mhdr == NULL)
       return mhdr;

     /* update rt stats */
     memmgr_set_rt_stats (block_size);

     pal_mem_set (mhdr, 0, sizeof (struct ipi_memblock_header));

     SET_FLAG (mhdr->flags, MEM_BLK_MALLOC);
     mhdr->prev = mhdr;
     mhdr->next = mhdr;
     mhdr->size = memmgr_encode_header_size (block_size);

     return mhdr;
}


/*
 *   memmgr_set_memblock_trailer()
 *
 *   Copy the buffer with approriate information to enable some
 *   run-time checks.
 */
void
memmgr_set_memblock_trailer (struct ipi_memblock_header *hdr, int index,
                             char *filename, int line)
{
    struct ipi_memblock_trailer mtlr;
    char   *ptr;
    int    len;
    int    i;

#ifdef MEMMGR_RUNTIME_CHECK
  pal_mem_set (&mtlr, 0, sizeof (struct ipi_memblock_trailer));
    /* get filename and its length */
    if (filename != NULL)
      {
        len = pal_strlen (filename);

        /* truncate filename if it exceeds MAX file size */
        if (len >= MAX_FILE_SZ)
          {
            len = len - MAX_FILE_SZ;
            filename = &filename[len];
          }

        pal_strcpy (mtlr.filename, filename);
        mtlr.line_number = (unsigned short) line;
      }

    /* set up pre guard area */
    for (i = 0; i < PRE_GUARD_AREA; i++)
      hdr->guard[i] = 0xee;

    /* set up post guard area */
    for (i = 0; i < POST_GUARD_AREA; i++)
      mtlr.guard[i] = 0xee;

    ptr = (char *) hdr;
    ptr += memmgr_get_ipi_header_size () + memmgr_get_bucket_block_size (index);

    pal_mem_cpy (ptr, &mtlr, sizeof (struct ipi_memblock_trailer));

#endif
}


/*
 *   memmgr_get_user_membuf ()
 *
 *   Based on the request size, allocate an appropriate memory block (best fit)
 *   from one of the buckets in free memory table.
 *   For now, return an error if the requested block size is more than 64k
 */
char *
memmgr_get_user_membuf (int req_size, int mtype, char *filename, int line)
{
    char      *ptr;
    struct    ipi_memblock_header  *mhdr;
    int       index;
    unsigned  int allocated_size;

    /* get bucket index */
    index = memmgr_get_bucket_index (req_size);

    if (index < 0)
      {
        MEMMGR_LOG_ERR ("Too large: memory size of more than 64k \n");
        return NULL;
      }

    /* if no free blocks, allocate memory from system */
    mhdr = memmgr_get_from_free_table (index);

    if (mhdr == NULL)
      {
        /* check here if we have exceeded max process memory before accessing
         * system heap. If so, return an error
         */
        allocated_size = memmgr_get_total_mtype_req_size () + req_size;
        /* Check for maximum allowed memory only if it is not set to
         * infinite
         */
        if ((mem_global.max_mem_size != PM_MEM_SIZE_INF) &&
            (allocated_size > mem_global.max_mem_size))
          {
            MEMMGR_LOG_WARN ("Maximum memory threshold %u KB reached\n",
                (mem_global.max_mem_size / 1000));
            return NULL;
          }

        if ((mhdr = memmgr_get_from_system_heap (req_size)) == NULL)
          {
            /* see if the requested memory could be allocated from the next
             * higher free pool
             */
            for (index = index+1; index < BUKT_COUNT; index++)
              {
                mhdr = memmgr_get_from_free_table (index);
                if (mhdr != NULL) break;
              }
            if (index == BUKT_COUNT)
              return NULL;
          }
      }

    /* init gaurd area and copy file and line information */
    memmgr_set_memblock_trailer (mhdr, index, filename, line);

    ptr = (char *) mhdr + memmgr_get_ipi_header_size ();

    /* add this block to mtype table */
    memmgr_add_to_mtype_table (mtype, mhdr, req_size);

    return ptr;
}


/*
 *  memmgr_get_bucket_index ()
 *
 *  Map memory block size to a bucket and return its index
 */
int
memmgr_get_bucket_index (int block_size)
{
    if (block_size <= (int) BLK_32)
      return BUKT0;
    else if (block_size <= (int) BLK_64)
      return BUKT1;
    else if (block_size <= (int) BLK_128)
      return BUKT2;
    else if (block_size <= (int) BLK_256)
      return BUKT3;
    else if (block_size <= (int) BLK_512)
      return BUKT4;
    else if (block_size <= (int) BLK_1K)
      return BUKT5;
    else if (block_size <= (int) BLK_2K)
      return BUKT6;
    else if (block_size <= (int) BLK_4K)
      return BUKT7;
    else if (block_size <= (int) BLK_8K)
      return BUKT8;
    else if (block_size <= (int) BLK_16K)
      return BUKT9;
    else if (block_size <= (int) BLK_32K)
      return BUKT10;
    else if (block_size <= (int) BLK_64K)
      return BUKT11;
    else if (block_size <= (int) BLK_128K)
      return BUKT12;
    else
      return -1;
}

/*
 *  memmgr_get_bucket_block_size ()
 *
 *  Map the index to a bucket and return its memory block size
 */
int
memmgr_get_bucket_block_size (int index)
{
    switch (index)
      {
        case BUKT0:
             return BLK_32;
        case BUKT1:
             return BLK_64;
        case BUKT2:
             return BLK_128;
        case BUKT3:
             return BLK_256;
        case BUKT4:
             return BLK_512;
        case BUKT5:
             return BLK_1K;
        case BUKT6:
             return BLK_2K;
        case BUKT7:
             return BLK_4K;
        case BUKT8:
             return BLK_8K;
        case BUKT9:
             return BLK_16K;
        case BUKT10:
             return BLK_32K;
        case BUKT11:
             return BLK_64K;
        case BUKT12:
             return BLK_128K;
        default:
             MEMMGR_LOG_ERR ("Bucket index out of bounds %d \n", index);
             return -1;
      }
}

/*
 *  memmgr_encode_header_size ()
 *
 *  Since we allow only 1 byte in the header for representing the memory block
 *  size, this field is encoded.
 */
int
memmgr_encode_header_size (int block_size)
{
     switch (block_size)
       {
         case BLK_32:
              return SIZE0;
         case BLK_64:
              return SIZE1;
         case BLK_128:
              return SIZE2;
         case BLK_256:
              return SIZE3;
         case BLK_512:
              return SIZE4;
         case BLK_1K:
              return SIZE5;
         case BLK_2K:
              return SIZE6;
         case BLK_4K:
              return SIZE7;
         case BLK_8K:
              return SIZE8;
         case BLK_16K:
              return SIZE9;
         case BLK_32K:
              return SIZE10;
         case BLK_64K:
              return SIZE11;
         case BLK_128K:
              return SIZE12;
         default:
             MEMMGR_LOG_ERR ("Unrecognized memory block size %d \n", block_size);
             break;
       }

    return -1;
}


/*
 *  memmgr_decode_header_size ()
 *
 *  Decode memory header size field to represent the size of user buffer.
 */
int
memmgr_decode_header_size (int hdr_size)
{
     switch (hdr_size)
       {
         case SIZE0:
              return BLK_32;
         case SIZE1:
              return BLK_64;
         case SIZE2:
              return BLK_128;
         case SIZE3:
              return BLK_256;
         case SIZE4:
              return BLK_512;
         case SIZE5:
              return BLK_1K;
         case SIZE6:
              return BLK_2K;
         case SIZE7:
              return BLK_4K;
         case SIZE8:
              return BLK_8K;
         case SIZE9:
              return BLK_16K;
         case SIZE10:
              return BLK_32K;
         case SIZE11:
              return BLK_64K;
         case SIZE12:
              return BLK_128K;
         default:
             MEMMGR_LOG_ERR ("Unrecognized memory header size %d \n", hdr_size);
             break;
       }

    return -1;
}


/*
 *  memmgr_set_pa_stats ()
 *
 *  Maintain information of the total pre-allocated memory size, the associated
 *  overhead, and the memory pointer for each pool bucket.
 */
void
memmgr_set_pa_stats (int count, int block_size, void * ptr)
{
    int  index;

    mem_stats.pa_mem_size += count * block_size;
    mem_stats.pa_mem_blocks += count;
    mem_stats.pa_mem_overhead += count * memmgr_get_ipi_overhead_size ();
    index = memmgr_get_bucket_index (block_size);
    mem_stats.pool_ptr[index] = ptr;
}

/*
 *  memmgr_set_rt_stats ()
 *
 *  Maintain information of the total memory allocated on top of pre-allocated
 *  memory size and the associated overhead.
 */
void
memmgr_set_rt_stats (int block_size)
{
    mem_stats.rt_mem_size += block_size;
    mem_stats.rt_mem_blocks += 1;
    mem_stats.rt_mem_overhead += memmgr_get_ipi_overhead_size ();
}


/*
 *  memmgr_get_pa_mem_size ()
 *
 *  Return the total memory size in pre-allocated memory blocks.
 */
unsigned int
memmgr_get_pa_mem_size ()
{
    return mem_stats.pa_mem_size;
}

/*
 *  memmgr_get_pa_mem_overhead ()
 *
 *  Return the total memory overhead associated with pre-allocated memory.
 */
unsigned int
memmgr_get_pa_mem_overhead ()
{
    return mem_stats.pa_mem_overhead;
}

/*
 *  memmgr_get_pa_mem_blocks ()
 *
 *  Return the total partitioned memory blocks in pre-allocated memory.
 */
unsigned int
memmgr_get_pa_mem_blocks ()
{
    return mem_stats.pa_mem_blocks;
}

/*
 *  memmgr_get_rt_mem_size ()
 *
 *  Return the total memory size obtained over pre-allocated memory.
 */
unsigned int
memmgr_get_rt_mem_size ()
{
    return mem_stats.rt_mem_size;
}

/*
 *  memmgr_get_rt_mem_overhead ()
 *
 *  Return the total memory overhead incurred for memory obtained over
 *  pre-allocated memory.
 */
unsigned int
memmgr_get_rt_mem_overhead ()
{
    return mem_stats.rt_mem_overhead;
}

/*
 *  memmgr_get_rt_mem_blocks ()
 *
 *  Return the total memory blocks obtained over pre-allocated memory.
 */
unsigned int
memmgr_get_rt_mem_blocks ()
{
    return mem_stats.rt_mem_blocks;
}

/*
 *  memmgr_get_ipi_overhead_size ()
 *
 *  return the number of bytes used for Ipi header & trailer.
 */
int
memmgr_get_ipi_overhead_size ()
{
    int size;

    size = sizeof (struct ipi_memblock_header);

#ifdef MEMMGR_RUNTIME_CHECK
    size += sizeof (struct ipi_memblock_trailer);
#endif

    return size;
}

/*
 *  memmgr_get_ipi_header_size ()
 *
 *  return Ipi header size.
 */
int
memmgr_get_ipi_header_size ()
{
    return sizeof (struct ipi_memblock_header);
}

/*
 *  memmgr_get_ipi_trailer_offset ()
 *
 *  return the ipi memory block trailer size.
 */
struct ipi_memblock_trailer *
memmgr_get_ipi_trailer_offset (struct ipi_memblock_header *hdr)
{
    int  size;
    char *ptr;

    size = memmgr_decode_header_size (hdr->size);

    ptr = (char *) hdr + (memmgr_get_ipi_header_size () + size);

    return (struct ipi_memblock_trailer *) ptr;
}

/*
 *   memmgr_get_mtype_size ()
 *
 *   Return the total number of bytes allocated for a given mtype
 */
unsigned int
memmgr_get_mtype_size (int mtype)
{
    return mtype_table[mtype].size;
}

/*
 *   memmgr_get_bucket_size ()
 *
 *   Return the total number of bytes available in a given bucket
 */
unsigned int
memmgr_get_bucket_size (int bucket)
{
    return free_table[bucket].size;
}

/*
 *   memmgr_get_mtype_count ()
 *
 *   Return the total number of blocks allocated for a given mtype
 */
int
memmgr_get_mtype_count (int mtype)
{
    return mtype_table[mtype].count;
}

/*
 *   memmgr_get_bucket_count ()
 *
 *   Return the total number of blocks available for a given bucket
 */
int
memmgr_get_bucket_count (int bucket)
{
    return free_table[bucket].count;
}

/*
 *   memmgr_get_total_mtype_size ()
 *
 *   Return the total number of bytes allocated for all mtypes
 */
unsigned int
memmgr_get_total_mtype_size ()
{
    unsigned int size;
    int      i;

    size = 0;

    for (i = 0; i < MTYPE_MAX; i++)
       size += mtype_table[i].size;

    return size;
}

/*
 *   memmgr_get_total_req_size ()
 *
 *   Return the total requested bytes for allocation
 */
unsigned int
memmgr_get_total_mtype_req_size ()
{
    unsigned int size;
    int          i;

    size = 0;

    for (i = 0; i < MTYPE_MAX; i++)
       size += mtype_table[i].req_size;

    return size;
}


/*
 *   memmgr_get_total_mtype_count ()
 *
 *   Return the total number of blocks allocated for all mtypes
 */
int
memmgr_get_total_mtype_count ()
{
    int  count;
    int  i;

    count = 0;

    for (i = 0; i < MTYPE_MAX; i++)
       count += mtype_table[i].count;

    return count;
}


#ifdef CPU

SEMAPHORE_OBJ_TYPE  semId;

/*
 *  memmgr_sem_create ()
 *
 *  Return 0 if creation of a mutex semaphore is succesful
 */
int
memmgr_sem_create (void)
{
    /* create mutex semaphore */
    semId = pal_sem_create (IPI_SEM_TYPE_MUTEX);

    return (semId == NULL) ? -1 : 0;
}

/*
 *   memmgr_sem_take ()
 *
 *   Obtain mutex lock
 */
int
memmgr_sem_take (void)
{
    int ret;

    ret = pal_sem_take (semId, IPI_WAIT_FOREVER);

    if (ret != 0)
      MEMMGR_LOG_ERR ("Error while taking a semaphore\n");

    return ret;
}

/*
 *   memmgr_sem_give ()
 *
 *   clear mutex lock
 */
int
memmgr_sem_give (void)
{
    int ret;

    ret = pal_sem_give (semId);

    if (ret != 0)
      MEMMGR_LOG_ERR ("Error while giving a semaphore\n");

    return ret;
}


/*
 *   memmgr_sem_take ()
 *
 *   Delete mutex semaphore
 */
int
memmgr_sem_delete (void)
{
    int ret;

    ret = pal_sem_delete (semId);

    if (ret != 0)
      MEMMGR_LOG_ERR ("Error while deleting a semaphore\n");

    return ret;
}
#endif


