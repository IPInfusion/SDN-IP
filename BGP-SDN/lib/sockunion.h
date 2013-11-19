/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_SOCKUNION_H
#define _BGPSDN_SOCKUNION_H

#include "lib.h"

typedef enum su_connect_result {
  connect_error = -1, 
  connect_success = 0,
  connect_in_progress = 1
} su_connect_result_t;

union sockunion 
{
  struct pal_sockaddr sa;
  struct pal_sockaddr_in4 sin;
#ifdef HAVE_IPV6
  struct pal_sockaddr_in6 sin6;
#endif /* HAVE_IPV6 */
};

/* Default address family. */
#ifdef HAVE_IPV6
#define AF_INET_UNION AF_INET6
#else
#define AF_INET_UNION AF_INET
#endif

/* Sockunion address string length.  Same as INET6_ADDRSTRLEN. */
#define SU_ADDRSTRLEN                   (46)

/* Macro to set link local index to the IPv6 address.  For KAME IPv6
   stack. */
#ifdef KAME
#define IN6_LINKLOCAL_IFINDEX(a)  ((a).s6_addr[2] << 8 | (a).s6_addr[3])
#define SET_IN6_LINKLOCAL_IFINDEX(a, i) \
  do { \
    (a).s6_addr[2] = ((i) >> 8) & 0xff; \
    (a).s6_addr[3] = (i) & 0xff; \
  } while (0)
#else
#define IN6_LINKLOCAL_IFINDEX(a)  ((a).s6_addr[2] << 8 | (a).s6_addr[3])
#define SET_IN6_LINKLOCAL_IFINDEX(a, i)
#endif /* KAME */

/* shortcut macro to specify address field of struct sockaddr */
#define sock2ip(X)   (((struct sockaddr_in *)(X))->sin_addr.s_addr)
#ifdef HAVE_IPV6
#define sock2ip6(X)  (((struct sockaddr_in6 *)(X))->sin6_addr.s6_addr)
#endif /* HAVE_IPV6 */

#define sockunion_family(X)  (X)->sa.sa_family

/* Prototypes. */
s_int32_t str2sockunion (char *, union sockunion *);
const char *sockunion2str (union sockunion *, char *, size_t);
s_int32_t sockunion_cmp (union sockunion *, union sockunion *);
s_int32_t sockunion_same (union sockunion *, union sockunion *);

char *sockunion_su2str (union sockunion *su);
union sockunion *sockunion_str2su (char *str);
struct in_addr sockunion_get_in_addr (union sockunion *su);
pal_sock_handle_t sockunion_accept (struct lib_globals *, pal_sock_handle_t sock, union sockunion *);
pal_sock_handle_t sockunion_stream_socket (struct lib_globals *, union sockunion *);
pal_sock_handle_t sockunion_bind (struct lib_globals *, pal_sock_handle_t sock, union sockunion *, u_int16_t, union sockunion *);

pal_sock_handle_t sockunion_socket (struct lib_globals *zg, union sockunion *su);
char *inet_sutop (union sockunion *su, char *str);
pal_sock_handle_t sockunion_log (union sockunion *su, char *, size_t);
su_connect_result_t sockunion_connect (struct lib_globals *, pal_sock_handle_t fd, union sockunion *su, u_int16_t port, u_int32_t);
union sockunion *sockunion_getsockname (struct lib_globals *, pal_sock_handle_t);
union sockunion *sockunion_getpeername (struct lib_globals *, pal_sock_handle_t);
union sockunion *sockunion_dup (union sockunion *);
void sockunion_free (union sockunion *);

#endif /* _BGPSDN_SOCKUNION_H */
