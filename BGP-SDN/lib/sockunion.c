/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#include "lib.h"
#include "sockunion.h"
#include "log.h"

char *
inet_sutop (union sockunion *su, char *str)
{
  switch (su->sa.sa_family)
  {
  case AF_INET:
    pal_inet_ntop (AF_INET, &su->sin.sin_addr, str, INET_ADDRSTRLEN);
    break;
#ifdef HAVE_IPV6
  case AF_INET6:
    pal_inet_ntop (AF_INET6, &su->sin6.sin6_addr, str, INET6_ADDRSTRLEN);
    break;
#endif /* HAVE_IPV6 */
  }
  return str;
}


s_int32_t
str2sockunion (char *str, union sockunion *su)
{
  result_t ret;

  pal_mem_set (su, 0, sizeof (union sockunion));

  ret = pal_inet_pton (AF_INET, str, &su->sin.sin_addr);
  if (ret > 0)                  /* Valid IPv4 address format. */
    {
      su->sin.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
      su->sin.sin_len = sizeof(struct pal_sockaddr_in4);
#endif /* HAVE_SIN_LEN */
      return 0;
    }
#ifdef HAVE_IPV6
  ret = pal_inet_pton (AF_INET6, str, &su->sin6.sin6_addr);
  if (ret > 0)                  /* Valid IPv6 address format. */
    {
      su->sin6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
      su->sin6.sin6_len = sizeof(struct pal_sockaddr_in6);
#endif /* SIN6_LEN */
      return 0;
    }
#endif /* HAVE_IPV6 */
  return -1;
}

const char *
sockunion2str (union sockunion *su, char *buf, size_t len)
{
  const char *ret=NULL;

  if (su->sa.sa_family == AF_INET) {
    ret = pal_inet_ntop (AF_INET, &su->sin.sin_addr, buf, len);
#ifdef HAVE_IPV6
  } else if (su->sa.sa_family == AF_INET6) {
    ret = pal_inet_ntop (AF_INET6, &su->sin6.sin6_addr, buf, len);
#endif /* HAVE_IPV6 */
  }
  return ((NULL!=ret)?buf:NULL);
}

union sockunion *
sockunion_str2su (char *str)
{
  result_t ret;
  union sockunion *su;

  su = XCALLOC(MTYPE_SOCKUNION, sizeof (union sockunion));

  ret = pal_inet_pton (AF_INET, str, &su->sin.sin_addr);
  if (ret > 0)                  /* Valid IPv4 address format. */
    {
      su->sin.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
      su->sin.sin_len = sizeof(struct pal_sockaddr_in4);
#endif /* HAVE_SIN_LEN */
      return su;
    }
#ifdef HAVE_IPV6
  ret = pal_inet_pton (AF_INET6, str, &su->sin6.sin6_addr);
  if (ret > 0)                  /* Valid IPv6 address format. */
    {
      su->sin6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
      su->sin6.sin6_len = sizeof(struct pal_sockaddr_in6);
#endif /* SIN6_LEN */
      return su;
    }
#endif /* HAVE_IPV6 */

  XFREE (MTYPE_SOCKUNION, su);
  return NULL;
}

char *
sockunion_su2str (union sockunion *su)
{
  char str[INET6_ADDRSTRLEN];

  pal_mem_set (str, 0, (sizeof (char) * INET6_ADDRSTRLEN));
  switch (su->sa.sa_family)
    {
    case AF_INET:
      pal_inet_ntop (AF_INET, &su->sin.sin_addr, str, sizeof (str));
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      pal_inet_ntop (AF_INET6, &su->sin6.sin6_addr, str, sizeof (str));
      break;
#endif /* HAVE_IPV6 */
    }
  return XSTRDUP (MTYPE_TMP,str);
}

/* Return socket of sockunion. */
pal_sock_handle_t sockunion_socket (struct lib_globals *zg,
                                    union sockunion *su) 
{
  pal_sock_handle_t sock;

  sock = pal_sock (zg, su->sa.sa_family, SOCK_STREAM, 0);
  if (sock < 0) {
    zlog_warn (zg, "Can't make socket : %s", pal_strerror (errno));
    return -1;
  }
  return sock;
}

/* Return accepted new socket file descriptor. */
pal_sock_handle_t sockunion_accept (struct lib_globals *zg,
                                    pal_sock_handle_t sock, 
                                    union sockunion *su)
{
  int len;
  pal_sock_handle_t client_sock;
#ifdef HAVE_IPV6
  struct pal_sockaddr_in4 sin;
#endif /* def HAVE_IPV6 */

  len = sizeof (union sockunion);
  client_sock = pal_sock_accept (zg, sock, (struct pal_sockaddr *) su, &len);
  /* Convert IPv4 compatible IPv6 address to IPv4 address. */
#ifdef HAVE_IPV6
  if (su->sa.sa_family == AF_INET6) {
    if (IN6_IS_ADDR_V4MAPPED (&su->sin6.sin6_addr)) {
      pal_mem_set (&sin, 0, sizeof (struct pal_sockaddr_in4));
      sin.sin_family = AF_INET;
      pal_mem_cpy (&sin.sin_addr, ((char *)&su->sin6.sin6_addr) + 12, 4);
      pal_mem_cpy (su, &sin, sizeof (struct pal_sockaddr_in4));
    }
  }
#endif /* HAVE_IPV6 */
  return client_sock;
}

/**/
s_int32_t
sockunion_sizeof (union sockunion *su)
{
  result_t ret;

  ret = 0;
  switch (su->sa.sa_family)
    {
    case AF_INET:
      ret = sizeof (struct pal_sockaddr_in4);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      ret = sizeof (struct pal_sockaddr_in6);
      break;
#endif /* AF_INET6 */
    }
  return ret;
}

/* return sockunion structure : this function should be revised. */
pal_sock_handle_t sockunion_log (union sockunion *su, char *buf, size_t len) 
{
#ifdef AF_LINK
  struct sockaddr_dl *sdl;
#endif

  switch (su->sa.sa_family) {
  case AF_INET:
    pal_inet_ntop(AF_INET,&(su->sin.sin_addr), buf, len);
    break;
#ifdef HAVE_IPV6
  case AF_INET6:
    pal_inet_ntop(AF_INET6,&(su->sin6.sin6_addr), buf, len);
    break;
#endif /* HAVE_IPV6 */

#ifdef AF_LINK
  case AF_LINK:
    sdl = (struct sockaddr_dl *)&(su->sa);
    pal_snprintf (buf, len,"link#%d ", sdl->sdl_index);
    break;
#endif /* AF_LINK */
  default:
    pal_snprintf (buf, len,"af_unknown %d ", su->sa.sa_family);
    break;
  }
  return 0;
}

/*
** sockunion_connect returns
** -1 : error occured
**  0 : connect success
**  1 : connect is in progress
*/
su_connect_result_t sockunion_connect (struct lib_globals *zg, 
                                       pal_sock_handle_t fd, 
                                       union sockunion *peersu, 
                                       u_int16_t port, 
                                       u_int32_t ifindex) 
{
  result_t ret;
  s_int32_t val;
  union sockunion su;
  char buf[BUFSIZ];

  pal_mem_cpy (&su, peersu, sizeof (union sockunion));
  switch (su.sa.sa_family) {
  case AF_INET:
    su.sin.sin_port = port;
    break;
#ifdef HAVE_IPV6
  case AF_INET6:
    su.sin6.sin6_port  = port;
#ifdef KAME
    if (IN6_IS_ADDR_LINKLOCAL(&su.sin6.sin6_addr) && ifindex)
      {
#ifdef HAVE_SIN6_SCOPE_ID
        /* su.sin6.sin6_scope_id = ifindex; */
#endif /* HAVE_SIN6_SCOPE_ID */
        SET_IN6_LINKLOCAL_IFINDEX (su.sin6.sin6_addr, ifindex);
      }
#elif defined(HAVE_SIN6_SCOPE_ID)
    if (IN6_IS_ADDR_LINKLOCAL(&su.sin6.sin6_addr) && ifindex)
      {
        su.sin6.sin6_scope_id = ifindex;
        SET_IN6_LINKLOCAL_IFINDEX (su.sin6.sin6_addr, ifindex);
      }
#endif /* HAVE_SIN6_SCOPE_ID */
    break;
#endif /* HAVE_IPV6 */
  }
  /* Set socket nonblocking */
  pal_sock_get_nonblocking(fd,&val);
  pal_sock_set_nonblocking(fd,PAL_TRUE);
  /* Call connect function. */
  ret = pal_sock_connect(fd,(struct pal_sockaddr*)&su,sockunion_sizeof(&su));
  /* Immediate success */
  if (ret == 0) {
    pal_sock_set_nonblocking(fd,val);
    return connect_success;
  } else if (ret < 0) {
    if (EINPROGRESS != errno) {
      sockunion_log (&su, buf, BUFSIZ);
      zlog_info(zg, "can't connect to %s fd %d : %s",
                buf, fd, pal_strerror (errno));
      return connect_error;
    }
  }
  pal_sock_set_nonblocking(fd,val);
  return connect_in_progress;
}

/* Make socket from sockunion union. */
pal_sock_handle_t
sockunion_stream_socket (struct lib_globals *zg, union sockunion *su)
{
  pal_sock_handle_t sock;

  if (su->sa.sa_family == 0)
    su->sa.sa_family = AF_INET_UNION;

  sock = pal_sock(zg, su->sa.sa_family, SOCK_STREAM, 0);

  if (sock < 0)
    zlog_warn(zg, "can't make socket sockunion_stream_socket");

  return sock;
}

/* Bind socket to specified address. */
result_t
sockunion_bind (struct lib_globals *zg,
                pal_sock_handle_t sock,
                union sockunion *su,
                u_int16_t port,
                union sockunion *su_addr)
{
  union sockunion su_bind;
  s_int32_t size = 0;
  result_t ret;

  su_bind.sa.sa_family = su->sa.sa_family;

  if (su->sa.sa_family == AF_INET)
    {
      size = sizeof (struct pal_sockaddr_in4);
      su->sin.sin_port = pal_hton16 (port);
      su_bind.sin.sin_port = su->sin.sin_port;
#ifdef HAVE_SIN_LEN
      su->sin.sin_len = size;
      su_bind.sin.sin_len = su->sin.sin_len;
#endif /* HAVE_SIN_LEN */

      if (su_addr == NULL)
        su_bind.sin.sin_addr.s_addr = pal_hton32 (INADDR_ANY);
      else
        su_bind.sin.sin_addr.s_addr = su_addr->sin.sin_addr.s_addr;
    }
#ifdef HAVE_IPV6
  else if (su->sa.sa_family == AF_INET6)
    {
      size = sizeof (struct pal_sockaddr_in6);
      su->sin6.sin6_port = pal_hton16 (port);
      su_bind.sin6.sin6_port = su->sin6.sin6_port;
#ifdef SIN6_LEN
      su->sin6.sin6_len = size;
      su_bind.sin6.sin6_len = su->sin6.sin6_len;
#endif /* SIN6_LEN */

      if (su_addr == NULL)
        pal_mem_set (&su_bind.sin6.sin6_addr, 0,
                     sizeof (struct pal_in6_addr));
      else
        pal_mem_cpy (&su_bind.sin6.sin6_addr, &su_addr->sin6.sin6_addr,
                     sizeof (struct pal_in6_addr));
    }
#endif /* HAVE_IPV6 */

  ret = pal_sock_bind (sock, (struct pal_sockaddr *)&su_bind, size);
  if (ret < 0)
    zlog_warn(zg, "can't bind socket : %s", pal_strerror (errno));

  return ret;
}

/* If same family and same prefix return 1. */
s_int32_t
sockunion_same (union sockunion *su1, union sockunion *su2)
{
  result_t ret = 0;

  if (su1->sa.sa_family != su2->sa.sa_family)
    return 0;

  switch (su1->sa.sa_family)
    {
    case AF_INET:
      ret = pal_mem_cmp (&su1->sin.sin_addr, &su2->sin.sin_addr,
                         sizeof (struct pal_in4_addr));
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      ret = pal_mem_cmp (&su1->sin6.sin6_addr, &su2->sin6.sin6_addr,
                         sizeof (struct pal_in6_addr));
      break;
#endif /* HAVE_IPV6 */
    }
  if (ret == 0)
    return 1;
  else
    return 0;
}

/* After TCP connection is established.  Get local address and port. */
union sockunion *
sockunion_getsockname (struct lib_globals *zg, pal_sock_handle_t fd)
{
  result_t ret;
  int len;
  union
  {
    struct pal_sockaddr sa;
    struct pal_sockaddr_in4 sin;
#ifdef HAVE_IPV6
    struct pal_sockaddr_in6 sin6;
#endif /* HAVE_IPV6 */
    char tmp_buffer[128];
  } name;
  union sockunion *su;

  pal_mem_set (&name, 0, sizeof name);
  len = sizeof name;

  ret = pal_sock_getname(fd, (struct pal_sockaddr *)&name, &len);
  if (ret < 0)
    {
      zlog_warn(zg, "Can't get local address and port by pal_sock_getname: %s",
                pal_strerror (errno));
      return NULL;
    }

  if (name.sa.sa_family == AF_INET)
    {
      su = XMALLOC (MTYPE_SOCKUNION, sizeof (union sockunion));
      pal_mem_cpy (su, &name, sizeof (struct pal_sockaddr_in4));
      return su;
    }
#ifdef HAVE_IPV6
  if (name.sa.sa_family == AF_INET6)
    {
      su = XMALLOC (MTYPE_SOCKUNION, sizeof (union sockunion));
      pal_mem_cpy (su, &name, sizeof (struct pal_sockaddr_in6));

      if (IN6_IS_ADDR_V4MAPPED (&su->sin6.sin6_addr))
        {
          struct pal_sockaddr_in4 sin;
          
          pal_mem_set (&sin, 0, sizeof (struct pal_sockaddr_in4));
          sin.sin_family = AF_INET;
          pal_mem_cpy (&sin.sin_addr, ((char *)&su->sin6.sin6_addr) + 12, 4);
          sin.sin_port = su->sin6.sin6_port;
          pal_mem_cpy (su, &sin, sizeof (struct pal_sockaddr_in4));
        }
      return su;
    }
#endif /* HAVE_IPV6 */
  return NULL;
}

/* After TCP connection is established.  Get remote address and port. */
union sockunion *
sockunion_getpeername (struct lib_globals *zg, pal_sock_handle_t fd)
{
  result_t ret;
  int len;
  union
  {
    struct pal_sockaddr sa;
    struct pal_sockaddr_in4 sin;
#ifdef HAVE_IPV6
    struct pal_sockaddr_in6 sin6;
#endif /* HAVE_IPV6 */
    char tmp_buffer[128];
  } name;
  union sockunion *su;

  pal_mem_set (&name, 0, sizeof name);
  len = sizeof name;
  ret = pal_sock_getpeer (fd, (struct pal_sockaddr *)&name, &len);
  if (ret < 0)
    {
      zlog_warn(zg, "Can't get remote address and port: %s",
                pal_strerror (errno));
      return NULL;
    }

  if (name.sa.sa_family == AF_INET)
    {
      su = XMALLOC (MTYPE_SOCKUNION, sizeof (union sockunion));
      pal_mem_cpy (su, &name, sizeof (struct pal_sockaddr_in4));
      return su;
    }
#ifdef HAVE_IPV6
  if (name.sa.sa_family == AF_INET6)
    {
      su = XMALLOC (MTYPE_SOCKUNION, sizeof (union sockunion));
      pal_mem_cpy (su, &name, sizeof (struct pal_sockaddr_in6));

      if (IN6_IS_ADDR_V4MAPPED (&su->sin6.sin6_addr))
        {
          struct pal_sockaddr_in4 sin;

          pal_mem_set (&sin, 0, sizeof (struct pal_sockaddr_in4));
          sin.sin_family = AF_INET;
          pal_mem_cpy (&sin.sin_addr, ((u_int8_t *)&su->sin6.sin6_addr) + 12, 4);
          sin.sin_port = su->sin6.sin6_port;
          pal_mem_cpy (su, &sin, sizeof (struct pal_sockaddr_in4));
        }
      return su;
    }
#endif /* HAVE_IPV6 */
  return NULL;
}

#ifdef HAVE_IPV6
result_t
in6addr_cmp (struct pal_in6_addr *addr1, struct pal_in6_addr *addr2)
{
  s_int32_t i;
  u_int8_t *p1, *p2;

  p1 = (u_int8_t *)addr1;
  p2 = (u_int8_t *)addr2;

  for (i = 0; i < sizeof (struct pal_in6_addr); i++)
    {
      if (p1[i] > p2[i])
        return 1;
      else if (p1[i] < p2[i])
        return -1;
    }
  return 0;
}
#endif /* HAVE_IPV6 */

s_int32_t
sockunion_cmp (union sockunion *su1, union sockunion *su2)
{
  if (!(su1 && su2)) {
    return 0;
  }

  if (su1->sa.sa_family > su2->sa.sa_family)
    return 1;
  if (su1->sa.sa_family < su2->sa.sa_family)
    return -1;

  if (su1->sa.sa_family == AF_INET)
    {
      if (pal_ntoh32 (su1->sin.sin_addr.s_addr) == pal_ntoh32 (su2->sin.sin_addr.s_addr))
        return 0;
      if (pal_ntoh32 (su1->sin.sin_addr.s_addr) > pal_ntoh32 (su2->sin.sin_addr.s_addr))
        return 1;
      else
        return -1;
    }
#ifdef HAVE_IPV6
  if (su1->sa.sa_family == AF_INET6)
    return in6addr_cmp (&su1->sin6.sin6_addr, &su2->sin6.sin6_addr);
#endif /* HAVE_IPV6 */
  return 0;
}

/* Duplicate sockunion. */
union sockunion *
sockunion_dup (union sockunion *su)
{
  union sockunion *dup = XMALLOC (MTYPE_SOCKUNION, sizeof (union sockunion));
  pal_mem_cpy (dup, su, sizeof (union sockunion));
  return dup;
}

void
sockunion_free (union sockunion *su)
{
  XFREE (MTYPE_SOCKUNION, su);
}
