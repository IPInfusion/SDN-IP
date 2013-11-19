/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BUFFER_H
#define _BGPSDN_BUFFER_H

/* Buffer master. */
struct buffer
{
  /* Data list. */
  struct buffer_bucket *head;
  struct buffer_bucket *tail;

  /* Current allocated data. */
  u_int32_t alloc;

  /* Total length of buffer. */
  u_int32_t size;

  /* For allocation. */
  struct buffer_bucket *unused_head;
  struct buffer_bucket *unused_tail;

  /* Current total length of this buffer. */
  u_int32_t length;
};

/* Data container. */
struct buffer_bucket
{
  struct buffer *parent;
  struct buffer_bucket *next;
  struct buffer_bucket *prev;

  /* Acctual data stream. */
  u_char *data;

  /* Current pointer. */
  u_int32_t cp;

  /* Start pointer. */
  u_int32_t sp;
};

/* Buffer prototypes. */
struct buffer *buffer_new (u_int32_t);
u_int32_t buffer_write (struct buffer *, const char *, u_int32_t);
void buffer_free (struct buffer *);
u_int32_t buffer_putc (struct buffer *, char);
void buffer_reset (struct buffer *);
result_t buffer_flush_all (struct buffer *, pal_sock_handle_t);
result_t buffer_flush_window (struct vty *, struct buffer *, pal_sock_handle_t,
                              int, int, int, int);
result_t buffer_empty (struct buffer *);

#endif /* _BGPSDN_BUFFER_H */
