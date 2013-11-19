/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_STREAM_H
#define _BGPSDN_STREAM_H

#include "pal.h"

#include "prefix.h"

/* Stream buffer. */
struct stream
{
  struct stream *next;

  u_char *data;

  /* Put pointer. */
  u_int32_t putp;

  /* Get pointer. */
  u_int32_t getp;

  /* End of pointer. */
  u_int32_t endp;

  /* Data size. */
  u_int32_t size;
};

/* First in first out queue structure. */
struct stream_fifo
{
  u_int32_t count;

  struct stream *head;
  struct stream *tail;
};

/* Utility macros. */
#define STREAM_PNT(S)           ((S)->data + (S)->getp)
#define STREAM_PUT_PNT(S)       ((S)->data + (S)->putp)
#define STREAM_SIZE(S)          ((S)->size)
#define STREAM_REMAIN(S)        ((S)->size - (S)->putp)
#define STREAM_DATA(S)          ((S)->data)
#define STREAM_DATA_REMAIN(S)   ((S)->endp - (S)->getp)
#define STREAM_GET_GETP(S)      ((S)->getp)
#define STREAM_GET_PUTP(S)      ((S)->putp)
#define STREAM_GET_ENDP(S)      ((S)->endp)
#define STREAM_FORWARD_GETP(S, POS)                                   \
  do {                                                                \
    ((S)->getp += (POS));                                             \
  } while (0)
#define STREAM_FORWARD_PUTP(S, POS)                                   \
  do {                                                                \
    ((S)->putp += (POS));                                             \
  } while (0)
#define STREAM_FORWARD_ENDP(S, POS)                                   \
  do {                                                                \
    ((S)->endp += (POS));                                             \
  } while (0)
#define STREAM_REWIND_GETP(S, POS)                                    \
  do {                                                                \
    ((S)->getp -= (POS));                                             \
  } while (0)
#define STREAM_REWIND_PUTP(S, POS)                                    \
  do {                                                                \
    ((S)->putp -= (POS));                                             \
  } while (0)
#define STREAM_REWIND_ENDP(S, POS)                                    \
  do {                                                                \
    ((S)->endp -= (POS));                                             \
  } while (0)

/*
  A macro to check pointers in order to not
  go behind the allocated mem block
  S -- stream reference
  Z -- size of data to be written
*/
#define CHECK_SIZE(S, Z)                                              \
  do {                                                                \
    if (((S)->putp + (Z)) > (S)->size)                                \
      (Z) = (S)->size - (S)->putp;                                    \
  } while (0)

/* Stream prototypes. */
struct stream *stream_new (size_t);
void stream_free (struct stream *);

u_int32_t stream_get_getp (struct stream *);
u_int32_t stream_get_putp (struct stream *);
u_int32_t stream_get_endp (struct stream *);
u_int32_t stream_get_size (struct stream *);
void stream_set_size (struct stream *s, u_int32_t size);

u_int8_t *stream_get_data (struct stream *);

void stream_set_getp (struct stream *, u_int32_t);
void stream_set_putp (struct stream *, u_int32_t);
void stream_set_endp (struct stream *, u_int32_t);

void stream_forward (struct stream *, int);

void stream_put (struct stream *, void *, size_t);
int stream_putc (struct stream *, u_int8_t);
int stream_putc_at (struct stream *, u_int32_t, u_int8_t);
int stream_putw (struct stream *, u_int16_t);
int stream_putw_at (struct stream *, u_int32_t, u_int16_t);
int stream_putl (struct stream *, u_int32_t);
int stream_putl_at (struct stream *, u_int32_t, u_int32_t);
int stream_putf (struct stream *, float32_t);
int stream_putf_at (struct stream *, u_int32_t, float32_t);
int stream_put_ipv4 (struct stream *, u_int32_t);
int stream_put_prefix (struct stream *s, struct prefix *p);
int stream_put_in_addr (struct stream *, struct pal_in4_addr *);
#ifdef HAVE_IPV6
int stream_put_in6_addr (struct stream *, struct pal_in6_addr *);
#endif

void stream_get (void *, struct stream *, size_t);
void stream_peek (void *dst, struct stream *s, size_t size);
void stream_get_only (void *, struct stream *, size_t);
u_int8_t stream_getc (struct stream *);
u_int8_t stream_getc_from (struct stream *, u_int32_t);
u_int16_t stream_getw (struct stream *);
u_int16_t stream_getw_from (struct stream *, u_int32_t);
u_int32_t stream_getl (struct stream *);
float32_t stream_getf (struct stream *);
float32_t stream_getf_from (struct stream *, u_int32_t);
u_int32_t stream_get_ipv4 (struct stream *);
#ifdef HAVE_IPV6
struct pal_in6_addr stream_get_ipv6 (struct stream *);
#endif

#undef stream_read
#undef stream_write
int stream_read (struct stream *, int, size_t);
int stream_write (struct stream *, u_int8_t *, size_t);

u_char *stream_pnt (struct stream *);
u_char *stream_put_pnt (struct stream *);
void stream_reset (struct stream *);
int stream_flush (struct stream *, int);
int stream_empty (struct stream *);

/* Stream fifo. */
struct stream_fifo *stream_fifo_new ();
void stream_fifo_push (struct stream_fifo *fifo, struct stream *s);
struct stream *stream_fifo_pop (struct stream_fifo *fifo);
struct stream *stream_fifo_head (struct stream_fifo *fifo);
void stream_fifo_clean (struct stream_fifo *fifo);
void stream_fifo_free (struct stream_fifo *fifo);
void stream_copy (struct stream *dst, struct stream *src);
struct stream *stream_realloc (struct stream *, size_t);
#endif /* _BGPSDN_STREAM_H */
