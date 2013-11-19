/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#include "stream.h"
#include "prefix.h"
#include "network.h"

/* Stream is fixed length buffer for network output/input. */

/* Make stream buffer. */
struct stream *
stream_new (size_t size)
{
  struct stream *s;

  s = XCALLOC (MTYPE_STREAM, sizeof (struct stream));
  if (! s)
    return NULL;

  s->data = XCALLOC (MTYPE_STREAM_DATA, size);
  if (! s->data)
    {
      XFREE (MTYPE_STREAM, s);
      return NULL;
    }

  s->size = size;

  return s;
}

/* Free it now. */
void
stream_free (struct stream *s)
{
  XFREE (MTYPE_STREAM_DATA,s->data);
  XFREE (MTYPE_STREAM,s);
}

u_int32_t
stream_get_getp (struct stream *s)
{
  return s->getp;
}

u_int32_t
stream_get_putp (struct stream *s)
{
  return s->putp;
}

u_int32_t
stream_get_endp (struct stream *s)
{
  return s->endp;
}

u_int32_t
stream_get_size (struct stream *s)
{
  return s->size;
}

void
stream_set_size (struct stream *s, u_int32_t size)
{
  s->size = size;
}

/* Stream structre' stream pointer related functions.  */
void
stream_set_getp (struct stream *s, u_int32_t pos)
{
  s->getp = pos;
}

void
stream_set_putp (struct stream *s, u_int32_t pos)
{
  s->putp = pos;
}

void
stream_set_endp (struct stream *s, u_int32_t pos)
{
  s->endp = pos;
}

/* Forward pointer. */
void
stream_forward (struct stream *s, int size)
{
  s->getp += size;
}

void
stream_copy (struct stream *dst, struct stream *src)
{
   if (dst == NULL
       || src == NULL)
     return;

   if (dst->size < src->size)
     return;

   pal_mem_cpy (dst->data, src->data, dst->size);

   dst->size = src->size;
   dst->getp = src->getp;
   dst->putp = src->putp;
   dst->endp = src->endp;
}


/* Copy from stream to destination. */
void
stream_get (void *dst, struct stream *s, size_t size)
{
  pal_mem_cpy (dst, s->data + s->getp, size);
  s->getp += size;
}

/* Copy from stream to destination, but don't update s->getp. */
void
stream_peek (void *dst, struct stream *s, size_t size)
{
  pal_mem_cpy (dst, s->data + s->getp, size);
}

/* Copy from stream to destination, but don't update s->getp. */
void
stream_get_only (void *dst, struct stream *s, size_t size)
{
  stream_peek (dst, s, size);
}

/* Get next character from the stream. */
u_int8_t
stream_getc (struct stream *s)
{
  u_int8_t c;

  c = s->data[s->getp];
  s->getp++;
  return c;
}

/* Get next character from the stream. */
u_int8_t
stream_getc_from (struct stream *s, u_int32_t from)
{
  u_int8_t c;

  c = s->data[from];
  return c;
}

/* Get next word from the stream. */
u_int16_t
stream_getw (struct stream *s)
{
  u_int16_t w;

  w = s->data[s->getp++] << 8;
  w |= s->data[s->getp++];
  return w;
}

/* Get next word from the stream. */
u_int16_t
stream_getw_from (struct stream *s, u_int32_t from)
{
  u_int16_t w;

  w = s->data[from++] << 8;
  w |= s->data[from];
  return w;
}

/* Get next long word from the stream. */
u_int32_t
stream_getl (struct stream *s)
{
  u_int32_t l;

  l  = s->data[s->getp++] << 24;
  l |= s->data[s->getp++] << 16;
  l |= s->data[s->getp++] << 8;
  l |= s->data[s->getp++];
  return l;
}

/* Get next 32 bit float from the stream. */
float32_t
stream_getf (struct stream *s)
{
  union
  {
    u_int32_t l;
    float32_t f;
  } u;

  u.l  = s->data[s->getp++] << 24;
  u.l |= s->data[s->getp++] << 16;
  u.l |= s->data[s->getp++] << 8;
  u.l |= s->data[s->getp++];
  return u.f;
}

float32_t
stream_getf_from (struct stream *s, u_int32_t from)
{
  union
  {
    u_int32_t l;
    float32_t f;
  } u;

  u.l  = s->data[from++] << 24;
  u.l |= s->data[from++] << 16;
  u.l |= s->data[from++] << 8;
  u.l |= s->data[from];
  return u.f;
}

/* Get next long word from the stream. */
u_int32_t
stream_get_ipv4 (struct stream *s)
{
  u_int32_t l;

  pal_mem_cpy (&l, s->data + s->getp, 4);
  s->getp += 4;

  return l;
}

#ifdef HAVE_IPV6
struct pal_in6_addr
stream_get_ipv6 (struct stream *s)
{
  struct pal_in6_addr addr;

  pal_mem_cpy (&addr, s->data + s->getp, sizeof (struct pal_in6_addr));
  s->getp += 16;

  return addr;
}
#endif /* HAVE_IPV6 */


/* Copy to source to stream. */
void
stream_put (struct stream *s, void *src, size_t size)
{

  CHECK_SIZE (s, size);

  if (src)
    pal_mem_cpy (s->data + s->putp, src, size);
  else
    pal_mem_set (s->data + s->putp, 0, size);

  s->putp += size;
  if (s->putp > s->endp)
    s->endp = s->putp;
}

/* Put character to the stream. */
int
stream_putc (struct stream *s, u_int8_t c)
{
  if (s->putp >= s->size)
    return 0;

  s->data[s->putp] = c;
  s->putp++;
  if (s->putp > s->endp)
    s->endp = s->putp;
  return 1;
}

/* Put word to the stream. */
int
stream_putw (struct stream *s, u_int16_t w)
{
  if ((s->size - s->putp) < 2)
    return 0;

  s->data[s->putp++] = (u_int8_t)(w >>  8);
  s->data[s->putp++] = (u_int8_t) w;

  if (s->putp > s->endp)
    s->endp = s->putp;
  return 2;
}

/* Put long word to the stream. */
int
stream_putl (struct stream *s, u_int32_t l)
{
  if ((s->size - s->putp) < 4)
    return 0;

  s->data[s->putp++] = (u_int8_t)(l >> 24);
  s->data[s->putp++] = (u_int8_t)(l >> 16);
  s->data[s->putp++] = (u_int8_t)(l >>  8);
  s->data[s->putp++] = (u_int8_t)l;

  if (s->putp > s->endp)
    s->endp = s->putp;
  return 4;
}

/* Put 32 bit float to the stream. */
int
stream_putf (struct stream *s, float32_t f)
{
  u_int32_t *l;

  if ((s->size - s->putp) < 4)
    return 0;

  l = (u_int32_t *) &f;
  s->data[s->putp++] = (u_int8_t)(*l >> 24);
  s->data[s->putp++] = (u_int8_t)(*l >> 16);
  s->data[s->putp++] = (u_int8_t)(*l >> 8);
  s->data[s->putp++] = (u_int8_t)(*l);

  if (s->putp > s->endp)
    s->endp = s->putp;
  return 4;
}

int
stream_putc_at (struct stream *s, u_int32_t putp, u_int8_t c)
{
  if ((s->size - putp) < 1)
    return 0;

  s->data[putp] = c;
  return 1;
}

int
stream_putw_at (struct stream *s, u_int32_t putp, u_int16_t w)
{
  if ((s->size - putp) < 2)
    return 0;

  s->data[putp] = (u_int8_t)(w >>  8);
  s->data[putp + 1] = (u_int8_t) w;
  return 2;
}

int
stream_putl_at (struct stream *s, u_int32_t putp, u_int32_t l)
{
  if ((s->size - putp) < 4)
    return 0;

  s->data[putp] = (u_int8_t)(l >> 24);
  s->data[putp + 1] = (u_int8_t)(l >> 16);
  s->data[putp + 2] = (u_int8_t)(l >>  8);
  s->data[putp + 3] = (u_int8_t)l;
  return 4;
}

int
stream_putf_at (struct stream *s, u_int32_t putp, float32_t f)
{
  u_int32_t *l;

  if ((s->size - putp) < 4)
    return 0;

  l = (u_int32_t *) &f;
  s->data[putp] = (u_int8_t)(*l >> 24);
  s->data[putp + 1] = (u_int8_t)(*l >> 16);
  s->data[putp + 2] = (u_int8_t)(*l >> 8);
  s->data[putp + 3] = (u_int8_t)(*l);
  return 4;
}

/* Put long word to the stream. */
int
stream_put_ipv4 (struct stream *s, u_int32_t l)
{
  if ((s->size - s->putp) < 4)
    return 0;

  pal_mem_cpy (s->data + s->putp, &l, 4);
  s->putp += 4;

  if (s->putp > s->endp)
    s->endp = s->putp;
  return 4;
}

/* Put long word to the stream. */
int
stream_put_in_addr (struct stream *s, struct pal_in4_addr *addr)
{
  if ((s->size - s->putp) < 4)
    return 0;

  pal_mem_cpy (s->data + s->putp, addr, 4);
  s->putp += 4;

  if (s->putp > s->endp)
    s->endp = s->putp;
  return 4;
}

#ifdef HAVE_IPV6
int
stream_put_in6_addr (struct stream *s, struct pal_in6_addr *addr)
{
  if ((s->size - s->putp) < 16)
    return 0;

  pal_mem_cpy (s->data + s->putp, addr, 16);
  s->putp += 16;

  if (s->putp > s->endp)
    s->endp = s->putp;
  return 16;
}
#endif /* HAVE_IPV6 */

/* Put prefix by nlri type format. */
int
stream_put_prefix (struct stream *s, struct prefix *p)
{
  u_int8_t psize;

  psize = PSIZE (p->prefixlen);

  if (STREAM_REMAIN (s) < psize + 1)
    return 0;

  stream_putc (s, p->prefixlen);
  pal_mem_cpy (s->data + s->putp, &p->u.prefix, psize);
  s->putp += psize;
  
  if (s->putp > s->endp)
    s->endp = s->putp;

  return psize;
}


/* Read size from fd. */
int
stream_read (struct stream *s, int fd, size_t size)
{
  s_int32_t nbytes;
  s_int32_t nleft;

  CHECK_SIZE (s, size);

  nleft = size;

  while (nleft > 0)
    {
      nbytes = pal_sock_read (fd, s->data + s->putp, nleft);

      if (nbytes < 0)
        {
          /* Socket read was interrupted */
          if (errno == EINTR)
            continue;

          /* Kernel had locked the Socket Resource */
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            continue;

          return nbytes;
        }
      else if (nbytes == 0)
        return nbytes;

      s->putp += nbytes;
      s->endp += nbytes;
      nleft -= nbytes;
    }

  return size;
}

/* Write data to buffer. */
int
stream_write (struct stream *s, u_int8_t *ptr, size_t size)
{

  CHECK_SIZE(s, size);

  pal_mem_cpy (s->data + s->putp, ptr, size);
  s->putp += size;
  if (s->putp > s->endp)
    s->endp = s->putp;
  return size;
}

/* Return current read pointer. */
u_char *
stream_pnt (struct stream *s)
{
  return s->data + s->getp;
}

/* Return current write pointer. */
u_char *
stream_put_pnt (struct stream *s)
{
  return s->data + s->putp;
}

/* Check does this stream empty? */
int
stream_empty (struct stream *s)
{
  if (s->putp == 0 && s->endp == 0 && s->getp == 0)
    return 1;
  else
    return 0;
}

/* Reset stream. */
void
stream_reset (struct stream *s)
{
  s->putp = 0;
  s->endp = 0;
  s->getp = 0;
}

/* Write stream contens to the file descriptor. */
int
stream_flush (struct stream *s, int fd)
{
  int nbytes;

 again:
  nbytes = pal_sock_write(fd, s->data + s->getp, s->endp - s->getp);

  if (nbytes < 0) 
    {
      /* Signal happened before we could write */
      if (errno == EINTR)
        goto again;

      /* System said try it again.  */
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        goto again;
    }

  return nbytes;
}

/* Stream first in first out queue. */

struct stream_fifo *
stream_fifo_new ()
{
  struct stream_fifo *new;
 
  new = XCALLOC (MTYPE_STREAM_FIFO, sizeof (struct stream_fifo));
  return new;
}

/* Add new stream to fifo. */
void
stream_fifo_push (struct stream_fifo *fifo, struct stream *s)
{
  if (fifo->tail)
    fifo->tail->next = s;
  else
    fifo->head = s;
     
  fifo->tail = s;

  fifo->count++;
}

/* Delete first stream from fifo. */
struct stream *
stream_fifo_pop (struct stream_fifo *fifo)
{
  struct stream *s;
  
  s = fifo->head; 

  if (s)
    { 
      fifo->head = s->next;

      if (fifo->head == NULL)
        fifo->tail = NULL;
    }

  fifo->count--;

  return s; 
}

/* Return first fifo entry. */
struct stream *
stream_fifo_head (struct stream_fifo *fifo)
{
  return fifo->head;
}

void
stream_fifo_clean (struct stream_fifo *fifo)
{
  struct stream *s;
  struct stream *next;

  for (s = fifo->head; s; s = next)
    {
      next = s->next;
      stream_free (s);
    }
  fifo->head = fifo->tail = NULL;
  fifo->count = 0;
}

void
stream_fifo_free (struct stream_fifo *fifo)
{
  stream_fifo_clean (fifo);
  XFREE(MTYPE_STREAM_FIFO,fifo);
}

/* Realloc stream data */
struct stream *
stream_realloc (struct stream *s, size_t size)
{
  if (! s || ! s->data)
    return NULL;

  s->data = XREALLOC (MTYPE_STREAM_DATA, s->data, size);
  if (! s->data)
    {
      XFREE (MTYPE_STREAM, s);
      return NULL;
    }

  s->size = size;

  return s;
}

