/* $Id: cqueue.h,v 1.11 2012/04/25 14:29:58 santanu.kar Exp $ */
/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_CQUEUE_H
#define _BGPSDN_CQUEUE_H

#define CQUEUE_BUF_FREE_LIST_MAX_COUNT      (10)

/* Circular Queue Buffer */
struct cqueue_buffer
{
  /* Pointers for CQueue chaining */
  struct cqueue_buffer *prev;
  struct cqueue_buffer *next;

  /* Put position */
  u_int32_t putp;

  /* Get position */
  u_int32_t getp;

  /* No. bytes of Data in Queue */
  u_int32_t inqueue;

  /* Data Block size */
  u_int32_t size;

  /* Start of Data Block */
  u_int8_t data[1];
};

/* Circular Queue Buffer List Head */
struct cqueue_buf_list
{
  /* Count of CQueue Buffers */
  u_int32_t count;

  /* Max-Count of CQueue Buffers */
  u_int32_t max_count;

  /* Pointer to Head of CQueue buffers */
  struct cqueue_buffer *cqb_lhead;

  /* Pointer to Tail of CQueue buffers */
  struct cqueue_buffer *cqb_ltail;
};

/* Circular Queue Buffer Snap-shot */
struct cqueue_buf_snap_shot
{
  /* Put position */
  u_int32_t putp;

  /* Get position */
  u_int32_t getp;

  /* No. bytes of Data in Queue */
  u_int32_t inqueue;
};

/* Macro to get CQueue Buffer Free-List from Lib-Globals */
#define CQUEUE_BUF_GET_FREE_LIST(LIB_GLOB)                            \
  ((LIB_GLOB)->cqueue_buf_free_list)

/* Macro to get Head Node CQueue Buffer from CQueue List */
#define CQUEUE_BUF_GET_LIST_HEAD_NODE(CQ_LIST)                        \
  ((CQ_LIST) ? (CQ_LIST)->cqb_lhead : NULL)

/* Macro to get Tail Node CQueue Buffer from CQueue List */
#define CQUEUE_BUF_GET_LIST_TAIL_NODE(CQ_LIST)                        \
  ((CQ_LIST) ? (CQ_LIST)->cqb_ltail : NULL)

/* Macro to get writable bytes in 'CQ buffer' */
#define CQUEUE_BUF_GET_BYTES_EMPTY(CQ_BUF)                            \
  ((CQ_BUF) ? ((CQ_BUF)->size - (CQ_BUF)->inqueue) : 0)

/* Macro to get contiguous writable bytes in 'CQ buffer' */
#define CQUEUE_BUF_GET_CONTIG_BYTES_EMPTY(CQ_BUF)                     \
  ((CQ_BUF) ?                                                         \
   (((CQ_BUF)->putp > (CQ_BUF)->getp) ?                               \
    ((CQ_BUF)->size - (CQ_BUF)->putp) :                               \
    ((CQ_BUF)->putp < (CQ_BUF)->getp) ?                               \
    ((CQ_BUF)->getp - (CQ_BUF)->putp) :                               \
    ((CQ_BUF)->inqueue) ? 0 : ((CQ_BUF)->size - (CQ_BUF)->putp)) : 0)

/* Macro to get bytes to-be-read (TBR) from 'CQ Buffer' */
#define CQUEUE_BUF_GET_BYTES_TBR(CQ_BUF)                              \
  ((CQ_BUF) ? (CQ_BUF)->inqueue : 0)

/* Macro to get contiguous bytes To-Be-Read from 'CQ buffer' */
#define CQUEUE_BUF_GET_CONTIG_BYTES_TBR(CQ_BUF)                       \
  ((CQ_BUF) ?                                                         \
   (((CQ_BUF)->putp > (CQ_BUF)->getp) ?                               \
    ((CQ_BUF)->putp - (CQ_BUF)->getp) :                               \
    ((CQ_BUF)->putp < (CQ_BUF)->getp) ?                               \
    ((CQ_BUF)->size - (CQ_BUF)->getp) :                               \
    ((CQ_BUF)->inqueue) ? ((CQ_BUF)->size - (CQ_BUF)->getp) : 0) : 0)

#define CQUEUE_READ_INT8(CQ_BUF, RESULT8)                             \
  do {                                                                \
      (RESULT8) = (CQ_BUF)->data [(CQ_BUF)->getp++];                  \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue -= 1;                                         \
  } while (0)

#define CQUEUE_READ_INT16(CQ_BUF, RESULT16)                           \
  do {                                                                \
      (RESULT16) = (CQ_BUF)->data [(CQ_BUF)->getp++] << 8;            \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (RESULT16) |= (CQ_BUF)->data [(CQ_BUF)->getp++];                \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue -= 2;                                         \
  } while (0)

#define CQUEUE_READ_INT24(CQ_BUF, RESULT24)                           \
  do {                                                                \
      (RESULT24) |= (CQ_BUF)->data [(CQ_BUF)->getp++] << 16;          \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (RESULT24) |= (CQ_BUF)->data [(CQ_BUF)->getp++] << 8;           \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (RESULT24) |= (CQ_BUF)->data [(CQ_BUF)->getp++];                \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue -= 3;                                         \
  } while (0)

#define CQUEUE_READ_INT32(CQ_BUF, RESULT32)                           \
  do {                                                                \
      (RESULT32) = (CQ_BUF)->data [(CQ_BUF)->getp++] << 24;           \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (RESULT32) |= (CQ_BUF)->data [(CQ_BUF)->getp++] << 16;          \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (RESULT32) |= (CQ_BUF)->data [(CQ_BUF)->getp++] << 8;           \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (RESULT32) |= (CQ_BUF)->data [(CQ_BUF)->getp++];                \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue -= 4;                                         \
  } while (0)

#define CQUEUE_READ_1BYTE(CQ_BUF, RES_1B)                             \
  do {                                                                \
      ((u_int8_t *)(RES_1B))[0] = (CQ_BUF)->data [(CQ_BUF)->getp++];  \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue -= 1;                                         \
  } while (0)

#define CQUEUE_READ_2BYTES(CQ_BUF, RES_2B)                            \
  do {                                                                \
      ((u_int8_t *)(RES_2B))[0] = (CQ_BUF)->data [(CQ_BUF)->getp++];  \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      ((u_int8_t *)(RES_2B))[1] = (CQ_BUF)->data [(CQ_BUF)->getp++];  \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue -= 2;                                         \
  } while (0)

#define CQUEUE_READ_4BYTES(CQ_BUF, RES_4B)                            \
  do {                                                                \
      ((u_int8_t *)(RES_4B))[0] = (CQ_BUF)->data [(CQ_BUF)->getp++];  \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      ((u_int8_t *)(RES_4B))[1] = (CQ_BUF)->data [(CQ_BUF)->getp++];  \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      ((u_int8_t *)(RES_4B))[2] = (CQ_BUF)->data [(CQ_BUF)->getp++];  \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      ((u_int8_t *)(RES_4B))[3] = (CQ_BUF)->data [(CQ_BUF)->getp++];  \
      (CQ_BUF)->getp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue -= 4;                                         \
  } while (0)

#define CQUEUE_READ_NBYTES(CQ_BUF, RESULT, NBYTES)                    \
  do {                                                                \
    u_int32_t new_getp;                                               \
    u_int32_t tmp_size;                                               \
                                                                      \
    new_getp = (CQ_BUF)->getp + (NBYTES);                             \
    tmp_size = 0;                                                     \
                                                                      \
    if ((NBYTES) && (NBYTES) <= (CQ_BUF)->size)                       \
      {                                                               \
        if (new_getp <= (CQ_BUF)->putp)                               \
          {                                                           \
            pal_mem_cpy ((u_int8_t *) (RESULT),                       \
                         (CQ_BUF)->data + (CQ_BUF)->getp, (NBYTES));  \
            (CQ_BUF)->getp = new_getp;                                \
            (CQ_BUF)->inqueue -= (NBYTES);                            \
          }                                                           \
        else if ((CQ_BUF)->getp >= (CQ_BUF)->putp)                    \
          {                                                           \
            if (new_getp >= (CQ_BUF)->size)                           \
              {                                                       \
                if (new_getp % (CQ_BUF)->size <= (CQ_BUF)->putp)      \
                  {                                                   \
                    tmp_size = (CQ_BUF)->size - (CQ_BUF)->getp;       \
                    pal_mem_cpy ((u_int8_t *) (RESULT),               \
                                 (CQ_BUF)->data + (CQ_BUF)->getp,     \
                                 tmp_size);                           \
                    (CQ_BUF)->getp = new_getp % (CQ_BUF)->size;       \
                    pal_mem_cpy (((u_int8_t *) (RESULT)) + tmp_size,  \
                                 (CQ_BUF)->data, (CQ_BUF)->getp);     \
                    (CQ_BUF)->inqueue -= (NBYTES);                    \
                  }                                                   \
              }                                                       \
            else                                                      \
              {                                                       \
                pal_mem_cpy ((u_int8_t *) (RESULT),                   \
                             &(CQ_BUF)->data [(CQ_BUF)->getp],        \
                             (NBYTES));                               \
                (CQ_BUF)->getp = new_getp % (CQ_BUF)->size;           \
                (CQ_BUF)->inqueue -= (NBYTES);                        \
              }                                                       \
          }                                                           \
      }                                                               \
  } while (0)

#define CQUEUE_READ_ADVANCE_NBYTES(CQ_BUF, NBYTES)                    \
  do {                                                                \
    u_int32_t new_getp;                                               \
                                                                      \
    new_getp = (CQ_BUF)->getp + (NBYTES);                             \
                                                                      \
    if ((NBYTES) && (NBYTES) <= (CQ_BUF)->size)                       \
      {                                                               \
        if (new_getp <= (CQ_BUF)->putp)                               \
          {                                                           \
            (CQ_BUF)->getp = new_getp;                                \
            (CQ_BUF)->inqueue -= (NBYTES);                            \
          }                                                           \
        else if ((CQ_BUF)->getp >= (CQ_BUF)->putp)                    \
          {                                                           \
            if (new_getp >= (CQ_BUF)->size)                           \
              {                                                       \
                if (new_getp % (CQ_BUF)->size <= (CQ_BUF)->putp)      \
                  {                                                   \
                    (CQ_BUF)->getp = new_getp % (CQ_BUF)->size;       \
                    (CQ_BUF)->inqueue -= (NBYTES);                    \
                  }                                                   \
              }                                                       \
            else                                                      \
              {                                                       \
                (CQ_BUF)->getp = new_getp % (CQ_BUF)->size;           \
                (CQ_BUF)->inqueue -= (NBYTES);                        \
              }                                                       \
          }                                                           \
      }                                                               \
  } while (0)

#define CQUEUE_READ_REWIND_NBYTES(CQ_BUF, NBYTES)                     \
  do {                                                                \
    if ((NBYTES) > (CQ_BUF)->getp)                                    \
      (CQ_BUF)->getp = (CQ_BUF)->size - ((NBYTES) - (CQ_BUF)->getp);  \
    else                                                              \
      (CQ_BUF)->getp = (CQ_BUF)->getp - (NBYTES);                     \
    (CQ_BUF)->inqueue += (NBYTES);                                    \
  } while (0)

#define CQUEUE_WRITE_INT8(CQ_BUF, DATA8)                              \
  do {                                                                \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (u_int8_t)(DATA8);          \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue += 1;                                         \
  } while (0)

#define CQUEUE_WRITE_INT16(CQ_BUF, DATA16)                            \
  do {                                                                \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (u_int8_t)((DATA16) >> 8);  \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (u_int8_t)(DATA16);         \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue += 2;                                         \
  } while (0)

#define CQUEUE_WRITE_INT24(CQ_BUF, DATA24)                            \
  do {                                                                \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (u_int8_t)((DATA24) >> 16); \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (u_int8_t)((DATA24) >> 8);  \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (u_int8_t)(DATA24);         \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue += 3;                                         \
  } while (0)

#define CQUEUE_WRITE_INT32(CQ_BUF, DATA32)                            \
  do {                                                                \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (u_int8_t)((DATA32) >> 24); \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (u_int8_t)((DATA32) >> 16); \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (u_int8_t)((DATA32) >> 8);  \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (u_int8_t)(DATA32);         \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue += 4;                                         \
  } while (0)

#define CQUEUE_WRITE_1BYTE(CQ_BUF, DATA_1B)                           \
  do {                                                                \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = (DATA_1B);                  \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue += 1;                                         \
  } while (0)

#define CQUEUE_WRITE_2BYTES(CQ_BUF, DATA_2B)                          \
  do {                                                                \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = ((u_int8_t *)(DATA_2B))[0]; \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = ((u_int8_t *)(DATA_2B))[1]; \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue += 2;                                         \
  } while (0)

#define CQUEUE_WRITE_4BYTES(CQ_BUF, DATA_4B)                          \
  do {                                                                \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = ((u_int8_t *)(DATA_4B))[0]; \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = ((u_int8_t *)(DATA_4B))[1]; \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = ((u_int8_t *)(DATA_4B))[2]; \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->data [(CQ_BUF)->putp++] = ((u_int8_t *)(DATA_4B))[3]; \
      (CQ_BUF)->putp %= (CQ_BUF)->size;                               \
      (CQ_BUF)->inqueue += 4;                                         \
  } while (0)

#define CQUEUE_WRITE_NBYTES(CQ_BUF, DATA_N, NBYTES)                   \
  do {                                                                \
    u_int32_t new_putp;                                               \
    u_int32_t tmp_size;                                               \
                                                                      \
    new_putp = (CQ_BUF)->putp + (NBYTES);                             \
    tmp_size = 0;                                                     \
                                                                      \
    if ((NBYTES) && (NBYTES) <= (CQ_BUF)->size)                       \
      {                                                               \
        if (new_putp <= (CQ_BUF)->getp)                               \
          {                                                           \
            pal_mem_cpy (&(CQ_BUF)->data [(CQ_BUF)->putp],            \
                         (u_int8_t *)(DATA_N), (NBYTES));             \
            (CQ_BUF)->putp = new_putp;                                \
            (CQ_BUF)->inqueue += (NBYTES);                            \
          }                                                           \
        else if ((CQ_BUF)->putp >= (CQ_BUF)->getp)                    \
          {                                                           \
            if (new_putp >= (CQ_BUF)->size)                           \
              {                                                       \
                if (new_putp % (CQ_BUF)->size <= (CQ_BUF)->getp)      \
                  {                                                   \
                    tmp_size = (CQ_BUF)->size - (CQ_BUF)->putp;       \
                    pal_mem_cpy (&(CQ_BUF)->data [(CQ_BUF)->putp],    \
                                 (u_int8_t *) (DATA_N), tmp_size);    \
                    (CQ_BUF)->putp = new_putp % (CQ_BUF)->size;       \
                    pal_mem_cpy (&(CQ_BUF)->data [0],                 \
                                 ((u_int8_t *) (DATA_N)) + tmp_size,  \
                                 (CQ_BUF)->putp);                     \
                    (CQ_BUF)->inqueue += (NBYTES);                    \
                  }                                                   \
              }                                                       \
            else                                                      \
              {                                                       \
                pal_mem_cpy (&(CQ_BUF)->data [(CQ_BUF)->putp],        \
                             (u_int8_t *) (DATA_N), (NBYTES));        \
                (CQ_BUF)->putp = new_putp % (CQ_BUF)->size;           \
                (CQ_BUF)->inqueue += (NBYTES);                        \
              }                                                       \
          }                                                           \
      }                                                               \
  } while (0)

#define CQUEUE_WRITE_ADVANCE_NBYTES(CQ_BUF, NBYTES)                   \
  do {                                                                \
    u_int32_t new_putp;                                               \
                                                                      \
    new_putp = (CQ_BUF)->putp + (NBYTES);                             \
                                                                      \
    if ((NBYTES) && (NBYTES) <= (CQ_BUF)->size)                       \
      {                                                               \
        if (new_putp <= (CQ_BUF)->getp)                               \
          {                                                           \
            (CQ_BUF)->putp = new_putp;                                \
            (CQ_BUF)->inqueue += (NBYTES);                            \
          }                                                           \
        else if ((CQ_BUF)->putp >= (CQ_BUF)->getp)                    \
          {                                                           \
            if (new_putp >= (CQ_BUF)->size)                           \
              {                                                       \
                if (new_putp % (CQ_BUF)->size <= (CQ_BUF)->getp)      \
                  {                                                   \
                    (CQ_BUF)->putp = new_putp % (CQ_BUF)->size;       \
                    (CQ_BUF)->inqueue += (NBYTES);                    \
                  }                                                   \
              }                                                       \
            else                                                      \
              {                                                       \
                (CQ_BUF)->putp = new_putp % (CQ_BUF)->size;           \
                (CQ_BUF)->inqueue += (NBYTES);                        \
              }                                                       \
          }                                                           \
      }                                                               \
  } while (0)

#define CQUEUE_WRITE_REWIND_NBYTES(CQ_BUF, NBYTES)                    \
  do {                                                                \
    if ((NBYTES) > (CQ_BUF)->putp)                                    \
      (CQ_BUF)->putp = (CQ_BUF)->size - ((NBYTES) - (CQ_BUF)->putp);  \
    else                                                              \
      (CQ_BUF)->putp = (CQ_BUF)->putp - (NBYTES);                     \
    (CQ_BUF)->inqueue -= (NBYTES);                                    \
  } while (0)

#define CQUEUE_BUF_TAKE_SNAPSHOT(CQ_BUF, SNAPSHOT)                    \
  do {                                                                \
    (SNAPSHOT)->getp = (CQ_BUF)->getp;                                \
    (SNAPSHOT)->putp = (CQ_BUF)->putp;                                \
    (SNAPSHOT)->inqueue = (CQ_BUF)->inqueue;                          \
  } while (0)

#define CQUEUE_BUF_ENLIVEN_SNAPSHOT(CQ_BUF, SNAPSHOT)                 \
  do {                                                                \
    (CQ_BUF)->getp = (SNAPSHOT)->getp;                                \
    (CQ_BUF)->putp = (SNAPSHOT)->putp;                                \
    (CQ_BUF)->inqueue = (SNAPSHOT)->inqueue;                          \
  } while (0)

#define CQUEUE_BUF_RESET(CQ_BUF)                                      \
  do {                                                                \
    (CQ_BUF)->getp = 0;                                               \
    (CQ_BUF)->putp = 0;                                               \
    (CQ_BUF)->inqueue = 0;                                            \
  } while (0)

#define CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF(SNAP2, SNAP1)                \
  ((SNAP2)->inqueue - (SNAP1)->inqueue)

/*
 * Function Prototype declarations
 */
s_int32_t
cqueue_buf_free_list_alloc (struct lib_globals *);
s_int32_t
cqueue_buf_free_list_free (struct lib_globals *);
s_int32_t
cqueue_buf_list_alloc (struct cqueue_buf_list **, u_int32_t,
                       struct lib_globals *);
void
cqueue_buf_list_free (struct cqueue_buf_list *,
                      struct lib_globals *);
s_int32_t
cqueue_buf_listnode_add (struct cqueue_buf_list *,
                         struct cqueue_buffer *,
                         struct lib_globals *);
s_int32_t
cqueue_buf_listnode_remove (struct cqueue_buf_list *,
                            struct cqueue_buffer *,
                            struct lib_globals *);
struct cqueue_buffer *
cqueue_buf_get (u_int32_t, struct lib_globals *);
void
cqueue_buf_release (struct cqueue_buffer *, struct lib_globals *);

#endif /* _BGPSDN_CQUEUE_H */
