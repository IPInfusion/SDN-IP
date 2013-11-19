/* $Id: cqueue.c,v 1.8 2012/02/23 00:25:24 bob.macgill Exp $ */
/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "sockunion.h"
#include "cqueue.h"
#include "sock_cb.h"

s_int32_t
cqueue_buf_free_list_alloc (struct lib_globals *zlg)
{
  s_int32_t ret;

  ret = 0;

  /* Sanity check */
  if (! zlg || CQUEUE_BUF_GET_FREE_LIST (zlg))
    {
      ret = -1;
      goto EXIT;
    }

  ret = cqueue_buf_list_alloc (&CQUEUE_BUF_GET_FREE_LIST (zlg),
                               CQUEUE_BUF_FREE_LIST_MAX_COUNT, zlg);
  if (ret)
    goto EXIT;

EXIT:

  return ret;
}

s_int32_t
cqueue_buf_free_list_free (struct lib_globals *zlg)
{
  struct cqueue_buffer *cq_buf_nxt;
  struct cqueue_buf_list *cq_list;
  struct cqueue_buffer *cq_buf;
  s_int32_t ret;

  ret = 0;

  if (! zlg)
    {
      ret = -1;
      goto EXIT;
    }

  cq_list = CQUEUE_BUF_GET_FREE_LIST (zlg);

  /* Sanity check */
  if (! cq_list)
    {
      ret = -1;
      goto EXIT;
    }

  for (cq_buf = cq_list->cqb_lhead; cq_buf; cq_buf = cq_buf_nxt)
    {
      cq_buf_nxt = cq_buf->next;
      XFREE (MTYPE_CQUEUE_BUF, cq_buf);
      cq_list->count -= 1;
    }
  pal_assert (cq_list->count == 0);

  XFREE (MTYPE_LINK_LIST, cq_list);

  CQUEUE_BUF_GET_FREE_LIST (zlg) = NULL;

EXIT:

  return ret;
}

s_int32_t
cqueue_buf_list_alloc (struct cqueue_buf_list **cq_list,
                       u_int32_t max_count,
                       struct lib_globals *zlg)
{
  s_int32_t ret;

  ret = 0;

  /* Sanity check */
  if (! cq_list || (*cq_list) || ! zlg || ! max_count)
    {
      ret = -1;
      goto EXIT;
    }

  (*cq_list) = XCALLOC (MTYPE_LINK_LIST,
                        sizeof (struct cqueue_buf_list));
  if (! (*cq_list))
    {
      ret = -1;
      goto EXIT;
    }

  (*cq_list)->count = 0;
  (*cq_list)->max_count = max_count;

EXIT:

  return ret;
}

void
cqueue_buf_list_free (struct cqueue_buf_list *cq_list,
                      struct lib_globals *zlg)
{
  struct cqueue_buffer *cq_buf_nxt;
  struct cqueue_buffer *cq_buf;

  if (cq_list)
    {
      for (cq_buf = cq_list->cqb_lhead; cq_buf; cq_buf = cq_buf_nxt)
        {
          cq_buf_nxt = cq_buf->next;
          cqueue_buf_release (cq_buf, zlg);
          cq_list->count -= 1;
        }

      pal_assert (cq_list->count == 0);
    }

  XFREE (MTYPE_LINK_LIST, cq_list);

  return;
}

s_int32_t
cqueue_buf_listnode_add (struct cqueue_buf_list *cq_list,
                         struct cqueue_buffer *cq_buf,
                         struct lib_globals *zlg)
{
  s_int32_t ret;

  ret = 0;

  /* Sanity check */
  if (! cq_list || ! cq_buf || ! zlg)
    {
      ret = -1;
      goto EXIT;
    }

  cq_buf->prev = cq_list->cqb_ltail;
  if (cq_list->cqb_lhead == NULL)
    cq_list->cqb_lhead = cq_buf;
  else
    cq_list->cqb_ltail->next = cq_buf;
  cq_list->cqb_ltail = cq_buf;

  cq_list->count += 1;

EXIT:

  return ret;
}

s_int32_t
cqueue_buf_listnode_remove (struct cqueue_buf_list *cq_list,
                            struct cqueue_buffer *cq_buf,
                            struct lib_globals *zlg)
{
  s_int32_t ret;

  ret = 0;

  /* Sanity check */
  if (! cq_list || ! cq_buf || ! zlg)
    {
      ret = -1;
      goto EXIT;
    }

  if (cq_buf->next)
    cq_buf->next->prev = cq_buf->prev;
  if (cq_buf->prev)
    cq_buf->prev->next = cq_buf->next;
  if (cq_list->cqb_lhead == cq_buf)
    cq_list->cqb_lhead = cq_buf->next;
  if (cq_list->cqb_ltail == cq_buf)
    cq_list->cqb_ltail = cq_buf->prev;
  cq_list->count -= 1;

EXIT:

  return ret;
}

struct cqueue_buffer *
cqueue_buf_get (u_int32_t dblk_size,
                struct lib_globals *zlg)
{
  struct cqueue_buf_list *cq_free_list;
  struct cqueue_buffer *cq_buf;

  cq_buf = NULL;
  cq_free_list = CQUEUE_BUF_GET_FREE_LIST (zlg);

  if (cq_free_list && cq_free_list->count > 0)
    {
      cq_buf = cq_free_list->cqb_lhead;
      cq_free_list->cqb_lhead = cq_buf->next;
      if (cq_free_list->cqb_lhead)
        cq_free_list->cqb_lhead->prev = NULL;
      if (cq_free_list->cqb_ltail == cq_buf)
        cq_free_list->cqb_ltail = NULL;
      cq_free_list->count -= 1;
      cq_buf->next = NULL;
      CQUEUE_BUF_RESET (cq_buf);
    }
  else
    {
      cq_buf = XCALLOC (MTYPE_CQUEUE_BUF,
                        sizeof (struct cqueue_buffer) - 1 + dblk_size);
      if (cq_buf)
        {
          cq_buf->prev = NULL;
          cq_buf->next = NULL;
          cq_buf->size = dblk_size;
          CQUEUE_BUF_RESET (cq_buf);
        }
    }

  return cq_buf;
}

void
cqueue_buf_release (struct cqueue_buffer *cq_buf,
                    struct lib_globals *zlg)
{
  struct cqueue_buf_list *cq_free_list;

  cq_free_list = CQUEUE_BUF_GET_FREE_LIST (zlg);

  if (cq_free_list
      && cq_free_list->count < cq_free_list->max_count)
    {
      cq_buf->next = cq_free_list->cqb_lhead;
      cq_buf->prev = NULL;
      cq_free_list->count += 1;
      CQUEUE_BUF_RESET (cq_buf);
      if (cq_free_list->cqb_lhead)
        {
          cq_free_list->cqb_lhead->prev = cq_buf;
          cq_free_list->cqb_lhead = cq_buf;
        }
      else
        {
          cq_free_list->cqb_lhead = cq_buf;
          cq_free_list->cqb_ltail = cq_buf;
        }
    }
  else if (cq_buf)
    XFREE (MTYPE_CQUEUE_BUF, cq_buf);

  return;
}

