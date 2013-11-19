/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

/* Read nbytes from fd and store into ptr. */
s_int32_t
readn (pal_sock_handle_t fd, u_char *ptr, s_int32_t nbytes)
{
  s_int32_t nleft;
  s_int32_t nread;

  nleft = nbytes;

  while (nleft > 0) 
    {
      nread = pal_sock_read (fd, ptr, nleft);

      if (nread < 0)
        {
          switch (errno)
            {
            case EINTR:
            case EAGAIN:
            case EINPROGRESS:
#if (EWOULDBLOCK != EAGAIN)
            case EWOULDBLOCK:
#endif /* (EWOULDBLOCK != EAGAIN) */
              pal_delay (0);
              continue;
            }

          return (nread);
        }
      else
        if (nread == 0) 
          break;

      nleft -= nread;
      ptr += nread;
    }

  return nbytes - nleft;
}  

/* Write nbytes from ptr to fd. */
s_int32_t
writen (pal_sock_handle_t fd, u_char *ptr, s_int32_t nbytes)
{
  s_int32_t nleft;
  s_int32_t nwritten;

  nleft = nbytes;

  while (nleft > 0) 
    {
      nwritten = pal_sock_write (fd, ptr, nleft);
      
      if (nwritten <= 0) 
        {
          /* Signal happened before we could write */
          switch (errno)
            {
            case EINTR:
            case EAGAIN:
            case EINPROGRESS:
#if (EWOULDBLOCK != EAGAIN)
            case EWOULDBLOCK:
#endif /* (EWOULDBLOCK != EAGAIN) */
              pal_delay (0);
              continue;
            }
          
          return (nwritten);
        }
      nleft -= nwritten;
      ptr += nwritten;
    }

  return nbytes - nleft;
}
