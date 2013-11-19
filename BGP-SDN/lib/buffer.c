/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <pal.h>

#include "buffer.h"
#include "vty.h"

#undef IOV_MAX
#define IOV_MAX 1


/* Buffer library is utility for VTY output.  */

/* Allocate internal bucket.  */
static struct buffer_bucket *
buffer_bucket_new (u_int32_t size)
{
  struct buffer_bucket *d;

  d = XCALLOC (MTYPE_BUFFER_BUCKET, sizeof (struct buffer_bucket));
  if (d)
    d->data = XCALLOC (MTYPE_BUFFER_DATA, size);

  return d;
}

/* Free internal bucket.  */
static void
buffer_bucket_free (struct buffer_bucket *d)
{
  if (!d)
    return;
  
  if (d->data)
    XFREE (MTYPE_BUFFER_DATA, d->data);
  XFREE (MTYPE_BUFFER_BUCKET, d);
}

/* Make a new buffer. */
struct buffer *
buffer_new (u_int32_t size)
{
  struct buffer *b;

  b = XCALLOC (MTYPE_BUFFER, sizeof (struct buffer));
  if (b)
    b->size = size;

  return b;
}

/* Free the buffer. */
void
buffer_free (struct buffer *b)
{
  struct buffer_bucket *d;
  struct buffer_bucket *next;

  d = b->head;
  while (d)
    {
      next = d->next;
      buffer_bucket_free (d);
      d = next;
    }

  d = b->unused_head;
  while (d)
    {
      next = d->next;
      buffer_bucket_free (d);
      d = next;
    }
  
  XFREE (MTYPE_BUFFER, b);
}

/* Return 1 if buffer is empty. */
int
buffer_empty (struct buffer *b)
{
  if (b == NULL || b->tail == NULL || b->tail->cp == b->tail->sp)
    return 1;
  else
    return 0;
}

/* Clear and free all allocated data. */
void
buffer_reset (struct buffer *b)
{
  struct buffer_bucket *data;
  struct buffer_bucket *next;
  
  for (data = b->head; data; data = next)
    {
      next = data->next;
      buffer_bucket_free (data);
    }
  b->head = b->tail = NULL;
  b->alloc = 0;
  b->length = 0;
}

/* Add buffer_bucket to the end of buffer. */
struct buffer_bucket *
buffer_add (struct buffer *b)
{
  struct buffer_bucket *d = NULL;

  if (b)
    {
      d = buffer_bucket_new (b->size);
      if (d)
        {
          if (b->tail == NULL)
            {
              d->prev = NULL;
              d->next = NULL;
              b->head = d;
              b->tail = d;
            }
          else
            {
              d->prev = b->tail;
              d->next = NULL;

              b->tail->next = d;
              b->tail = d;
            }
          b->alloc++;
        }
    }
  return d;
}

/* Write data to buffer. */
u_int32_t
buffer_write (struct buffer *b, const char *ptr, u_int32_t size)
{
  struct buffer_bucket *data;
  u_int32_t actual = 0;
  u_int32_t work;

  if (b && ptr && size)
    {
      data = b->tail;

      /* We use even last one byte of data buffer. */
      while (size)    
        {
          /* If there is no data buffer add it. */
          if (data == NULL || data->cp == b->size)
            {
              data = buffer_add (b);
              if (! data)
                break;          /* Abort the while loop */
            }

          /* Last data. */
          if (size <= (b->size - data->cp))
            {
              pal_mem_cpy ((data->data + data->cp), ptr, size);

              data->cp += size;
              actual += size;
              size = 0;
            }
          else
            {
              work = b->size - data->cp;
              pal_mem_cpy ((data->data + data->cp), ptr, work);

              size -= work;
              actual += work;
              ptr += work;

              data->cp = b->size;
            }
        }
      b->length += actual;
    }
  return actual;
}

/* Insert character into the buffer. */
u_int32_t
buffer_putc (struct buffer *b, char c)
{
  return buffer_write (b, &c, 1);
}

/* Flush all buffer to the fd. */
int
buffer_flush_all (struct buffer *b, pal_sock_handle_t fd)
{
  int ret = 0;
  struct buffer_bucket *d;
  int iov_index;
  struct pal_iovec *iovec = NULL;

  if (! buffer_empty (b))
    {
      iovec = XCALLOC (MTYPE_BUFFER_IOV,
                       (sizeof (struct pal_iovec) * b->alloc));
      if (!iovec)
        return -1;
      
      iov_index = 0;

      for (d = b->head; d; d = d->next)
        {
          iovec[iov_index].iov_base = (void *)(d->data + d->sp);
          iovec[iov_index].iov_len = d->cp - d->sp;
          iov_index++;
        }
      if (fd >= 0)
        ret = pal_sock_writevec (fd, iovec, iov_index);

      XFREE (MTYPE_BUFFER_IOV, iovec);

      buffer_reset (b);
    }
  return ret;
}

/* Utility function to output buffer to the vty. */
int
buffer_flush_vty (struct buffer *b, pal_sock_handle_t fd, int size, 
                  int erase_flag, int no_more_flag, int force_more)
{
  int nbytes;
  int iov_index;
  struct pal_iovec *iov;
  struct pal_iovec small_iov[3];
  u_char more[] = " --More-- ";
  u_char erase[] = 
    { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
      ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
      0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08};
  struct buffer_bucket *data;
  struct buffer_bucket *out;
  struct buffer_bucket *next;
  u_int32_t alloc = 0;

#ifdef  IOV_MAX
  int iov_size;
  int total_size;
  struct pal_iovec *c_iov;
  int c_nbytes;
#endif /* IOV_MAX */

  /* For erase and more data add two to b's buffer_bucket count.*/
  if (b->alloc == 1)
    iov = small_iov;
  else
    {
      alloc = sizeof (struct pal_iovec) * (b->alloc + 2);
      iov = XCALLOC (MTYPE_BUFFER_IOV, alloc);
    }

  data = b->head;
  iov_index = 0;

  /* Previously print out is performed. */
  if (erase_flag)
    {
      iov[iov_index].iov_base = (void *)erase;
      iov[iov_index].iov_len = sizeof erase;
      iov_index++;
    }

  /* Output data. */
  for (data = b->head; data; data = data->next)
    {
      iov[iov_index].iov_base = (char *)(data->data + data->sp);

      if (size <= (data->cp - data->sp))
        {
          iov[iov_index++].iov_len = size;
          data->sp += size;
          if (data->sp == data->cp)
            data = data->next;
          break;
        }
      else
        {
          iov[iov_index++].iov_len = data->cp - data->sp;
          size -= (data->cp - data->sp);
          data->sp = data->cp;
        }
    }

  /* In case of `more' display need. */
  if (force_more || (! buffer_empty (b) && ! no_more_flag))
    {
      iov[iov_index].iov_base = (void *)more;
      iov[iov_index].iov_len = sizeof more;
      iov_index++;
    }

  /* We use write or writev*/

#ifdef IOV_MAX
  /* IOV_MAX are normally defined in <sys/uio.h> , Posix.1g.
     example: Solaris2.6 are defined IOV_MAX size at 16.     */
  c_iov = iov;
  total_size = iov_index;
  nbytes = 0;

  while( total_size > 0 )
    {
      /* initialize write vector size at once */
      iov_size = ( total_size > IOV_MAX ) ? IOV_MAX : total_size;

      c_nbytes = pal_sock_writevec (fd, c_iov, iov_size );

      if( c_nbytes < 0 )
        {
          if(errno == EINTR)
            ;
          if(errno == EWOULDBLOCK)
            ;
          nbytes = c_nbytes;
          break;
        }

      nbytes += c_nbytes;

      /* move pointer io-vector */
      c_iov += iov_size;
      total_size -= iov_size;
    }
#else  /* IOV_MAX */
  nbytes = pal_sock_writevec (fd, iov, iov_index);

  /* Error treatment. */
  if (nbytes < 0)
    {
      if (errno == EINTR)
        ;
      if (errno == EWOULDBLOCK)
        ;
    }
#endif /* IOV_MAX */

  /* Free printed buffer data. */
  for (out = b->head; out && out != data; out = next)
    {
      next = out->next;
      if (next)
        next->prev = out->prev;
      else
        b->tail = next;
      b->head = next;

      buffer_bucket_free (out);
      if (b->alloc) b->alloc--;
    }

  if (iov != small_iov)
    XFREE (MTYPE_BUFFER_IOV, iov);

  return force_more;
}

/* Calculate size of outputs then flush buffer to the file
   descriptor. */
int
buffer_flush_window (struct vty *vty, struct buffer *b, pal_sock_handle_t fd,
                     int width, int height, int erase, int no_more)
{
  u_int32_t cp;
  u_int32_t size;
  int lp;
  int lineno;
  struct buffer_bucket *data;
  int force_more = 0;

  if (height >= 2)
    height--;

  /* We have to calculate how many bytes should be written. */
  if (vty->cli.status == CLI_CONTINUE)
    {
      lp = vty->lp;
      lineno = vty->lineno;
    }
  else
    {
      lp = vty->lp = 0;
      lineno = vty->lineno = 0;
    }

  size = 0;
  
  for (data = b->head; data; data = data->next)
    {
      cp = data->sp;

      while (cp < data->cp)
        {
          if (data->data[cp] == '\n' || lp == width)
            {
              lineno++;
              if (lineno == height)
                {
                  cp++;
                  size++;
                  lp = 0;
                  lineno = 0;
                  force_more = 1;
                  vty->lp = lp;
                  vty->lineno = lineno;

                  return buffer_flush_vty (b, fd, size, erase, no_more, force_more);
                }
              lp = 0;
            }
          cp++;
          lp++;
          size++;
        }
    }

  /* Write data to the file descriptor. */
  vty->lp = lp;
  vty->lineno = lineno;

  return buffer_flush_vty (b, fd, size, erase, no_more, force_more);
}
