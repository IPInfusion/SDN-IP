/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

/*
  pal_socket.c -- BGP-SDN PAL socket and associated operations definitions
  for Linux
*/

/*
  Include files
*/
#include "pal.h"
#include <asm/errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#define _LINUX_IN_H
#include <linux/mroute.h>

#include "lib.h"

#include "pal_socket.h"
#include "pal_memory.h"
#include "pal_string.h"

/*
**  Constants and enumerations
*/
#ifdef HAVE_PBR_FIB
#include "port_forward.h"
#endif /* HAVE_PBR_FIB */

/*
**  Constants and enumerations
*/
#ifdef HAVE_PBR_FIB
#ifndef SO_MARK
#define SO_MARK 36
#endif /* SO_MARK */
#endif /* HAVE_PBR_FIB */
/*
**  Types
*/

/*
**  Functions
*/

/*!
**  Initialise the socket support.
**  
**  Parameters:
**  none
**  
**  Results:
**  A nonzero handle for success
**  NULL for failure
*/
pal_handle_t
pal_sock_start (struct lib_globals *lib_node)
{
  return (pal_handle_t) 1;
}

/*!
** Shut down the socket support.
**
** Parameters
**   none
**
** Results
**   RESULT_OK if success, else the error
*/
result_t
pal_sock_stop (struct lib_globals * lib_node)
{
  return RESULT_OK;
}

/* Check if path is socket and we have permissions to access the socket.
                                                                                
Parameters:
IN path to Unix domain socket
OUT 0 success
-1 failure (not a socket or permission failure.
*/
result_t 
pal_sock_check (char *path)
{
  uid_t euid;
  /* gid_t egid; */
  struct stat s_stat;
  int ret;
                                                                                
  /* Get uid and gid.  */
  euid = geteuid();
  /* egid = getegid(); */
                                                                                
  /* Get status of the IMI socket.  */
  ret = stat (path, &s_stat);
  if (ret < 0 && errno != ENOENT)
    return -1;
                                                                                
  /* When we get status information, we make it sure the file is
     socket and we have proper rights to read/write to the socket.  */
  if (ret >= 0)
    {
      if (! S_ISSOCK (s_stat.st_mode))
        return -1;
     
#ifndef HAVE_LICENSE_MGR 
      if (euid != s_stat.st_uid
          || ! (s_stat.st_mode & S_IWUSR) || ! (s_stat.st_mode & S_IRUSR))
        return -1;
#endif /* HAVE_LICENSE_MGR */
    }
  return 0;
}

/*
** Set socket in non-blocking mode
*/
result_t
pal_sock_set_nonblocking (pal_sock_handle_t sock, s_int32_t state)
{
#ifndef HAVE_IPNET
  int val;
  int ret;

  val = fcntl (sock, F_GETFL, 0);
  if (PAL_SOCK_ERROR != val)
    {
      ret = fcntl (sock, F_SETFL, (state ? val | O_NONBLOCK : val & (~O_NONBLOCK)));
      if (ret < 0)
        return RESULT_ERROR;
      return RESULT_OK;
    }
  else
    {
      return errno;
    }
#else
  int ret;
  int on;

  if (state == PAL_TRUE)
    on = 1;
  else
    on = 0;

  ret = ioctl (sock, IP_FIONBIO, (void *) &on);
  if (ret < 0)
    return RESULT_ERROR;

  return RESULT_OK;
#endif /* HAVE_IPNET */
}

#ifdef HAVE_PBR_FIB

int
pal_nat_port_forward_rule_add (u_int8_t * ifname,
                              u_int32_t ifindex,
                              unsigned int ip_ver,
			      unsigned int proto, 
			      unsigned int src_port, 
			      unsigned int dst_port)
{
  struct pfw_setsockopt_arg optarg;
  int sockfd, len, ret;

  if (! ifname)
    return -1;

  if (strlen (ifname) >= IFNAMSIZ)
    return -1;

  strcpy ((char *)&optarg.ifname,(const char *)ifname);
  optarg.ifindex = ifindex;
  optarg.proto = proto;
  optarg.dst_port = src_port;
  optarg.target_port = dst_port;
  optarg.ip_ver = ip_ver;

#ifdef HAVE_IPV6
  sockfd = socket(AF_INET6, SOCK_RAW, PAL_IPPROTO_RAW);
#else 
  sockfd = socket(AF_INET, SOCK_RAW, PAL_IPPROTO_RAW);
#endif

  if (sockfd < 0)
    {
      return -1;
    }
	
  len = sizeof (optarg);
#ifdef HAVE_IPV6
  ret = setsockopt(sockfd, PAL_IPPROTO_IPV6, PFW_SO_SET_RULE, &optarg, len);
#else
  ret = setsockopt(sockfd, PAL_IPPROTO_IP, PFW_SO_SET_RULE, &optarg, len);
#endif

  close (sockfd);	
 
  return ret;
}

int 
pal_nat_port_forward_rule_del (u_int8_t * ifname,
                              u_int32_t ifindex,
                              unsigned int ip_ver,
                              unsigned int proto, 
			      unsigned int src_port, 
			      unsigned int dst_port)
{
  struct pfw_setsockopt_arg optarg;
  int sockfd, len, ret;

  if (! ifname)
    return -1;

  if (strlen (ifname) >= IFNAMSIZ)
    return -1;

  strcpy ((char *)&optarg.ifname,(const char *)ifname);
  optarg.ifindex = ifindex;
  optarg.proto = proto;
  optarg.dst_port = src_port;
  optarg.target_port = dst_port;
  optarg.ip_ver = ip_ver;
  
#ifdef HAVE_IPV6
  sockfd = socket(AF_INET6, SOCK_RAW, PAL_IPPROTO_RAW);
#else 
  sockfd = socket(AF_INET, SOCK_RAW, PAL_IPPROTO_RAW);
#endif

  if (sockfd < 0)
      return -1;
  
  len = sizeof (optarg);
	
#ifdef HAVE_IPV6
  ret = setsockopt(sockfd, PAL_IPPROTO_IPV6, PFW_SO_UNSET_RULE, &optarg, len);
#else
  ret = setsockopt(sockfd, PAL_IPPROTO_IP, PFW_SO_UNSET_RULE, &optarg, len);
#endif
  close (sockfd);
  return ret;
}

int 
pal_nat_port_forward_rules_remove (unsigned int port)
{
  int sockfd;
  struct pfw_get_info info;
  struct pfw_get_entries *entries;
//  struct pfw_setsockopt_arg * entry;
  int len_entries, i;
  int ret = PAL_PFW_RULE_REMOVE_OK;
  int len =  sizeof(info);
  int len_entry =  sizeof(struct pfw_setsockopt_arg);
	
  sockfd = socket(AF_INET, SOCK_RAW, PAL_IPPROTO_RAW);
  if (sockfd < 0)
    {
      ret = PAL_PFW_FAIL_TO_CREATE_SOCK;
      goto exit;
    }

  info.num_entries = 0;
  info.size = 0;

  ret = getsockopt(sockfd, IPPROTO_IP, PFW_SO_GET_INFO, &info, &len);
  if (ret < 0)
    {
      ret = PAL_PFW_FAIL_TO_GET_INFO;
      goto exit;
    }

  if (info.size != len_entry)
    {
      ret = PAL_PFW_ARG_SIZE_MISMATCH;
      goto exit;
    }

  if (info.num_entries == 0)
    {
      goto exit;
    }	

  len_entries = sizeof(struct pfw_get_entries) + info.size * info.num_entries;	
    
  entries = (struct pfw_get_entries *)XCALLOC (MTYPE_TMP, len_entries);
  if (!entries)
    {
      ret = PAL_PFW_FAIL_TO_ALLOC_MEM;
      goto exit;
    }
  memset(entries, 0, len_entries);
  ret = getsockopt(sockfd, IPPROTO_IP, PFW_SO_GET_ENTRIES, entries, &len_entries);
  if (ret < 0)
    {
      ret = PAL_PFW_FAIL_TO_GET_ENTRIES;
      goto cleanup;
    }

  for (i=0; i<entries->size;i++)
    {
      if (ntohs (entries->entrytable[i].dst_port) == port)
        {
          pal_nat_port_forward_rule_del (entries->entrytable[i].ifname,
                                         entries->entrytable[i].ifindex,
                                         entries->entrytable[i].ip_ver,
                                         entries->entrytable[i].proto,
                                         ntohs (entries->entrytable[i].dst_port),
                                         ntohs (entries->entrytable[i].target_port));
        }
    }

cleanup:	
  XFREE(MTYPE_TMP, entries);
	
exit:	
  close (sockfd);
  return ret;
}


#endif /* HAVE_PBR_FIB */

#ifdef HAVE_IPNET
int
pal_sock_bind (pal_sock_handle_t sock,
               struct pal_sockaddr *addr,
               pal_size_t addrlen)
{
  return bind (sock, (struct sockaddr *) addr, addrlen);
}

int
pal_sock_connect (pal_sock_handle_t sock,
                  struct pal_sockaddr *addr,
                  pal_size_t addrlen)
{
  return connect (sock, (struct sockaddr *) addr, addrlen);
}

int
pal_sock_sendto (pal_sock_handle_t sock,
                 const void *msg,
                 pal_size_t count,
                 pal_sock_flags_t flags,
                 const struct pal_sockaddr *addr,
                 pal_size_t addrlen)
{
  return sendto (sock, msg, count, flags, (struct sockaddr *) addr, addrlen);
}

int
pal_sock_recvfrom (pal_sock_handle_t sock,
                   void *buf,
                   pal_size_t len,
                   pal_sock_flags_t flags,
                   struct pal_sockaddr *addr,
                   pal_size_t *addrlen)
{
  return recvfrom (sock, buf, len, flags, (struct sockaddr *) addr, addrlen);
}

int
pal_sock_select (int n,
                 pal_sock_set_t *readset,
                 pal_sock_set_t *writeset,
                 pal_sock_set_t *exceptset,
                 struct pal_timeval *timeout)
{
  return select (n, (fd_set *) readset, (fd_set *) writeset,
                 (fd_set *) exceptset, timeout);
}

/* Convert sockaddr to Ip_sockaddr */
int
pal_sock_ip_sockaddr_to_sockaddr (struct Ip_sockaddr *from, struct sockaddr **to)
{
  struct Ip_sockaddr_in *ip_sin;
  struct sockaddr_in *sin;
#ifdef HAVE_IPV6
  struct Ip_sockaddr_in6 *ip_sin6;
  struct sockaddr_in6 *sin6;
#endif /* HAVE_IPV6 */

  switch (from->sa_family)
    {
      case AF_INET:
        *to = (struct sockaddr *)XCALLOC (MTYPE_TMP, sizeof (struct sockaddr_in));
        if (*to == NULL)
          return -1;
        sin = (struct sockaddr_in *)*to;
        ip_sin = (struct Ip_sockaddr_in *)from;

        sin->sin_family = ip_sin->sin_family;
        sin->sin_port = ip_sin->sin_port;
        pal_mem_cpy (&sin->sin_addr, &ip_sin->sin_addr, sizeof (ip_sin->sin_addr));
        break;

#ifdef HAVE_IPV6
      case AF_INET6:
        *to = (struct sockaddr *)XCALLOC (MTYPE_TMP, sizeof (struct sockaddr_in6));
        if (*to == NULL)
          return -1;
        sin6 = (struct sockaddr_in6 *)*to;
        ip_sin6 = (struct Ip_sockaddr_in6 *)from;

        sin6->sin6_family = ip_sin6->sin6_family;
        sin6->sin6_port = ip_sin6->sin6_port;
        sin6->sin6_flowinfo = ip_sin6->sin6_flowinfo;
        pal_mem_cpy (&sin6->sin6_addr, &ip_sin6->sin6_addr, sizeof (ip_sin6->sin6_addr));
        sin6->sin6_scope_id = ip_sin6->sin6_scope_id;
        break;

#endif /* HAVE_IPV6 */
    }

  return 0;
}


/* Convert addrinfo to Ip_addrinfo */
int
pal_sock_ip_addrinfo_to_addrinfo (struct Ip_addrinfo *from, struct addrinfo *to)
{
  int ret;

  to->ai_flags = from->ai_flags;
  to->ai_family = from->ai_family;
  to->ai_socktype = from->ai_socktype;
  to->ai_protocol = from->ai_protocol;
  to->ai_addrlen = (Ip_size_t)from->ai_addrlen;

  if (from->ai_canonname != NULL)
    {
      to->ai_canonname = XSTRDUP (MTYPE_TMP, from->ai_canonname);
      if (to->ai_canonname == NULL)
        return -1;
    }
  else
    to->ai_canonname = NULL;

  if (from->ai_addr != NULL)
    {
      ret = pal_sock_ip_sockaddr_to_sockaddr (from->ai_addr, &to->ai_addr);
      if (ret < 0)
        {
          if (to->ai_canonname)
            XFREE (MTYPE_TMP, to->ai_canonname);
          return ret;
        }
    }
  else
    to->ai_addr = NULL;

  return 0;
}

/* Convert sockaddr to Ip_sockaddr */
int
pal_sock_sockaddr_to_ip_sockaddr (struct sockaddr *from, struct Ip_sockaddr **to)
{
  struct Ip_sockaddr_in *ip_sin;
  struct sockaddr_in *sin;
#ifdef HAVE_IPV6
  struct Ip_sockaddr_in6 *ip_sin6;
  struct sockaddr_in6 *sin6;
#endif /* HAVE_IPV6 */

  switch (from->sa_family)
    {
      case AF_INET:
        *to = (struct Ip_sockaddr *)XCALLOC (MTYPE_TMP, sizeof (struct Ip_sockaddr_in));
        if (*to == NULL)
          return -1;
        ip_sin = (struct Ip_sockaddr_in *)*to;
        sin = (struct sockaddr_in *)from;


#ifdef IPI_USE_SA_LEN
        ip_sin->sin_len = sizeof (struct Ip_sockaddr_in);
#endif /* IPI_USE_SA_LEN */
        ip_sin->sin_family = sin->sin_family;
        ip_sin->sin_port = sin->sin_port;
        pal_mem_cpy (&ip_sin->sin_addr, &sin->sin_addr, sizeof (sin->sin_addr));
        break;

#ifdef HAVE_IPV6
      case AF_INET6:
        *to = (struct Ip_sockaddr *)XCALLOC (MTYPE_TMP, sizeof (struct Ip_sockaddr_in6));
        if (*to == NULL)
          return -1;
        ip_sin6 = (struct Ip_sockaddr_in6 *)*to;
        sin6 = (struct sockaddr_in6 *)from;

#ifdef IPI_USE_SA_LEN
        ip_sin6->sin6_len = sizeof (struct Ip_sockaddr_in6);
#endif /* IPI_USE_SA_LEN */
        ip_sin6->sin6_family = sin6->sin6_family;
        ip_sin6->sin6_port = sin6->sin6_port;
        ip_sin6->sin6_flowinfo = sin6->sin6_flowinfo;
        pal_mem_cpy (&ip_sin6->sin6_addr, &sin6->sin6_addr, sizeof (sin6->sin6_addr));
        ip_sin6->sin6_scope_id = sin6->sin6_scope_id;
        break;

#endif /* HAVE_IPV6 */
    }

  return 0;
}


/* Convert addrinfo to Ip_addrinfo */
int
pal_sock_addrinfo_to_ip_addrinfo (struct addrinfo *from, struct Ip_addrinfo *to)
{
  int ret;

  to->ai_flags = from->ai_flags;
  to->ai_family = from->ai_family;
  to->ai_socktype = from->ai_socktype;
  to->ai_protocol = from->ai_protocol;
  to->ai_addrlen = (Ip_size_t)from->ai_addrlen;

  if (from->ai_canonname != NULL)
    {
      to->ai_canonname = XSTRDUP (MTYPE_TMP, from->ai_canonname);
      if (to->ai_canonname == NULL)
        return -1;
    }
  else
    to->ai_canonname = NULL;

  if (from->ai_addr != NULL)
    {
      ret = pal_sock_sockaddr_to_ip_sockaddr (from->ai_addr, &to->ai_addr);
      if (ret < 0)
        {
          if (to->ai_canonname)
            XFREE (MTYPE_TMP, to->ai_canonname);
          return ret;
        }
    }
  else
    to->ai_addr = NULL;

  return 0;
}

int
pal_sock_getaddrinfo (const char *name,
                      const char *service,
                      const struct pal_addrinfo *req,
                      struct pal_addrinfo **pai)
{
  struct addrinfo *a_pai, *tmp, ai_req;
  struct Ip_addrinfo *ip_pai, *ip_tmp;
  int ret;
  int count = 0;

  ret = pal_sock_ip_addrinfo_to_addrinfo ((struct Ip_addrinfo *)req, &ai_req);
  if (ret < 0)
    return ret;

  ret = getaddrinfo (name, service, &ai_req, &a_pai);
  if (ret < 0)
    return ret;

  /* Free the memory allocated for request */
  if (ai_req.ai_canonname)
    XFREE (MTYPE_TMP, ai_req.ai_canonname);

  if (ai_req.ai_addr)
    XFREE (MTYPE_TMP, ai_req.ai_addr);

  /* Conver addrinfo to Ip_addrinfo */
  tmp = a_pai;
  while (tmp)
    {
      ++count; 
      tmp = tmp->ai_next;
    }

  if (count == 0)
    {
      *pai = NULL;
      return 0;
    }

  /* Allocate buffer for the Ip_addrinfo structure */
  ip_pai = (struct Ip_addrinfo *) XCALLOC (MTYPE_TMP, count * sizeof (struct Ip_addrinfo));
  if (ip_pai == NULL)
    {
      freeaddrinfo (a_pai);
      return -1;
    }

  /* Convert addrinfo to Ip_addrinfo */
  tmp = a_pai;
  ip_tmp = ip_pai;
  while (tmp)
    {
      ret = pal_sock_addrinfo_to_ip_addrinfo (tmp, ip_tmp);
      if (ret < 0)
        {
          freeaddrinfo (a_pai);

          /* Call pal_sock_freeaddrinfo() so
           * that the complete list is freed 
           */
          pal_sock_freeaddrinfo (ip_pai);
          return ret;
        }

      if (tmp->ai_next)
        {
          ip_tmp->ai_next = ip_tmp + 1;
          ip_tmp = ip_tmp + 1;
        }

      tmp = tmp->ai_next;
    }
  ip_tmp->ai_next = NULL;

  /* Free the returned addrinfo */
  freeaddrinfo (a_pai);

  /* Set the pointer to be returned */
  *pai = ip_pai;

  return 0;
}

void
pal_sock_freeaddrinfo (struct pal_addrinfo *ai)
{
  struct Ip_addrinfo *tmp;

  tmp = ai;
  while (tmp)
    {
      if (tmp->ai_canonname)
        XFREE (MTYPE_TMP, tmp->ai_canonname);
 
      if (tmp->ai_addr)
        XFREE (MTYPE_TMP, tmp->ai_addr);

      tmp = tmp->ai_next;
    }

  XFREE (MTYPE_TMP, ai);
}

pal_sock_handle_t
pal_sock_accept (struct lib_globals *lib_node,
                 pal_sock_handle_t sock,
                 struct pal_sockaddr *addr,
                 size_t *addrlen)
{
  union sockaddr_union
  {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
#ifdef HAVE_IPV6
    struct sockaddr_in6 sin6;
#endif /* HAVE_IPV6 */
  } taddr;
#ifndef IPI_USE_SA_LEN
  u_int32_t sa_len;
#endif /* IPI_USE_SA_LEN */

  int ret;

  ret = -1;

  if ((lib_node == NULL) || (addr == NULL) || (addrlen == NULL))
    return ret;

  memset (&taddr, 0, sizeof (union sockaddr_union));

  ret = accept (sock, (struct sockaddr *) &taddr, addrlen);
  if (ret < 0)
    return ret;

  /* Adjust sa_len, sa_family. */
  addr->sa_family = taddr.sa.sa_family;

#ifdef IPI_USE_SA_LEN
  if (addr->sa_family == AF_INET)
    addr->sa_len = sizeof (struct Ip_sockaddr_in);
#ifdef HAVE_IPV6
  else if (addr->sa_family == AF_INET6)
    addr->sa_len = sizeof (struct Ip_sockaddr_in6);
#endif /* HAVE_IPV6 */
  else
    addr->sa_len = sizeof (struct Ip_sockaddr);

  /* Copy sa_data. */
  memcpy (addr->sa_data, taddr.sa.sa_data, addr->sa_len - (sizeof (addr->sa_family) + sizeof (addr->sa_len)));

#else /* ! IPI_USE_SA_LEN */

  if (addr->sa_family == AF_INET)
    sa_len = sizeof (struct Ip_sockaddr_in);
#ifdef HAVE_IPV6
  else if (addr->sa_family == AF_INET6)
    sa_len = sizeof (struct Ip_sockaddr_in6);
#endif /* HAVE_IPV6 */
  else
    sa_len = sizeof (struct Ip_sockaddr);

  /* Copy sa_data. */
  memcpy (addr->sa_data, taddr.sa.sa_data, sa_len - sizeof (addr->sa_family));

#endif /* IPI_USE_SA_LEN */

  return ret;
}

pal_sock_handle_t
pal_sock_getname (pal_sock_handle_t sock,
                  struct pal_sockaddr *addr,
                  size_t *addrlen)
{
  union sockaddr_union
  {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
#ifdef HAVE_IPV6
    struct sockaddr_in6 sin6;
#endif /* HAVE_IPV6 */
    /* The following buffer is required as the size of the buffer expected by 
       calling function may be higher than this union wthout tmp_buffer
    */
    char tmp_buffer[128];
  } taddr;
#ifndef IPI_USE_SA_LEN
  u_int32_t sa_len;
#endif /* IPI_USE_SA_LEN */

  int ret;

  ret = -1;

  if ((addr == NULL) || (addrlen == NULL))
    return ret;

  memset (&taddr, 0, sizeof (union sockaddr_union));

  ret = getsockname (sock, (struct sockaddr *) &taddr, addrlen);
  if (ret < 0)
    return ret;

  /* Adjust sa_len, sa_family. */
  addr->sa_family = taddr.sa.sa_family;

#ifdef IPI_USE_SA_LEN
  if (addr->sa_family == AF_INET)
    addr->sa_len = sizeof (struct Ip_sockaddr_in);
#ifdef HAVE_IPV6
  else if (addr->sa_family == AF_INET6)
    addr->sa_len = sizeof (struct Ip_sockaddr_in6);
#endif /* HAVE_IPV6 */
  else
    addr->sa_len = sizeof (struct Ip_sockaddr);

  /* Copy sa_data. */
  memcpy (addr->sa_data, taddr.sa.sa_data, addr->sa_len - (sizeof (addr->sa_family) + sizeof (addr->sa_len)));

#else /* ! IPI_USE_SA_LEN */

  if (addr->sa_family == AF_INET)
    sa_len = sizeof (struct Ip_sockaddr_in);
#ifdef HAVE_IPV6
  else if (addr->sa_family == AF_INET6)
    sa_len = sizeof (struct Ip_sockaddr_in6);
#endif /* HAVE_IPV6 */
  else
    sa_len = sizeof (struct Ip_sockaddr);

  /* Copy sa_data. */
  memcpy (addr->sa_data, taddr.sa.sa_data, sa_len - sizeof (addr->sa_family));

#endif /* IPI_USE_SA_LEN */

  return ret;
}

pal_sock_handle_t
pal_sock_getpeer (pal_sock_handle_t sock,
                  struct pal_sockaddr *addr,
                  size_t *addrlen)
{
  union sockaddr_union
  {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
#ifdef HAVE_IPV6
    struct sockaddr_in6 sin6;
#endif /* HAVE_IPV6 */
  } taddr;
#ifndef IPI_USE_SA_LEN
  u_int32_t sa_len;
#endif /* IPI_USE_SA_LEN */

  int ret;

  ret = -1;

  if ((addr == NULL) || (addrlen == NULL))
    return ret;

  memset (&taddr, 0, sizeof (union sockaddr_union));

  ret = getpeername (sock, (struct sockaddr *) &taddr, addrlen);
  if (ret < 0)
    return ret;

  /* Adjust sa_len, sa_family. */
  addr->sa_family = taddr.sa.sa_family;

#ifdef IPI_USE_SA_LEN
  if (addr->sa_family == AF_INET)
    addr->sa_len = sizeof (struct Ip_sockaddr_in);
#ifdef HAVE_IPV6
  else if (addr->sa_family == AF_INET6)
    addr->sa_len = sizeof (struct Ip_sockaddr_in6);
#endif /* HAVE_IPV6 */
  else
    addr->sa_len = sizeof (struct Ip_sockaddr);

  /* Copy sa_data. */
  memcpy (addr->sa_data, taddr.sa.sa_data, addr->sa_len - (sizeof (addr->sa_family) + sizeof (addr->sa_len)));

#else /* ! IPI_USE_SA_LEN */

  if (addr->sa_family == AF_INET)
    sa_len = sizeof (struct Ip_sockaddr_in);
#ifdef HAVE_IPV6
  else if (addr->sa_family == AF_INET6)
    sa_len = sizeof (struct Ip_sockaddr_in6);
#endif /* HAVE_IPV6 */
  else
    sa_len = sizeof (struct Ip_sockaddr);

  /* Copy sa_data. */
  memcpy (addr->sa_data, taddr.sa.sa_data, sa_len - sizeof (addr->sa_family));

#endif /* IPI_USE_SA_LEN */

  return ret;
}
#endif /* HAVE_IPNET */

/*
** Get whether a socket's operations are non-blocking
*/
result_t
pal_sock_get_nonblocking (pal_sock_handle_t sock, s_int32_t * state)
{
  int val;

  val = fcntl (sock, F_GETFL, 0);
  if (PAL_SOCK_ERROR != val)
    {
      *state = (0 != (val & O_NONBLOCK));
      return RESULT_OK;
    }
  else
    {
      return errno;
    }
}

/* Set options for L2 sockets */
result_t
pal_sock_set_l2_igmp_filter (pal_sock_handle_t sock, s_int32_t enable)
{
  result_t ret;

  ret = 0;

#ifdef HAVE_IGMP_SNOOP
  ret = setsockopt (sock, AF_IGMP_SNOOP, SNOOPING_ENABLE,
                    &enable, sizeof (enable));
#endif /* HAVE_IGMP_SNOOP */

  return ret;
}

result_t
pal_sock_set_l2_mld_filter (pal_sock_handle_t sock, s_int32_t enable)
{
  result_t ret;

  ret = 0;

#ifdef HAVE_MLD_SNOOP
  ret = setsockopt (sock, AF_IGMP_SNOOP, SNOOPING_ENABLE,
                    &enable, sizeof (enable));
#endif /* HAVE_MLD_SNOOP */

  return ret;
}

/* Create join, read and write sockets for IGMP join-group functionality */

pal_sock_handle_t
pal_sock_igmp_join_group (struct lib_globals *lib_node)
{
  pal_sock_handle_t sock;

  /* Create a socket for joining the multicast group */
  sock = pal_sock (lib_node, AF_INET,
                  SOCK_RAW, IPPROTO_IGMP);

  return sock;
}

pal_sock_handle_t
pal_sock_igmp_join_read (struct lib_globals *lib_node)
{
  pal_sock_handle_t sock;

  /* Create a socket for reading ICMP packets */
  sock = pal_sock (lib_node, PF_PACKET,
                  SOCK_RAW, htons(ETH_P_IP));

  return sock;
}

pal_sock_handle_t
pal_sock_igmp_join_write (struct lib_globals *lib_node)
{
  pal_sock_handle_t sock;

  /* Create a socket for sending ICMP replies */
  sock = pal_sock (lib_node, PF_PACKET, SOCK_PACKET, 0);

  return sock;
}

/*
** Set IPv4 multicast leave
*/
result_t
pal_sock_set_ipv4_multicast_leave (pal_sock_handle_t sock,
                                   struct pal_in4_addr mc_addr,
                                   struct pal_in4_addr if_addr,
                                   u_int32_t ifindex)
{
  struct pal_ip_mreqn mr;

  pal_mem_set (&mr, 0, sizeof (mr));
  mr.imr_multiaddr = mc_addr;
  if (ifindex)
    mr.imr_ifindex = ifindex;
  else
    {
#ifdef HAVE_IPNET
      mr.imr_address = if_addr;
#else
      mr.imr_address = if_addr;
#endif /* ! HAVE_IPNET */
    }

  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_DROP_MEMBERSHIP, &mr, sizeof (mr));
}

/*
** Set IPv4 multicast join
*/
result_t
pal_sock_set_ipv4_multicast_join (pal_sock_handle_t sock,
                                  struct pal_in4_addr mc_addr,
                                  struct pal_in4_addr if_addr,
                                  u_int32_t ifindex)
{
  struct pal_ip_mreqn mr;
  int ret;

  pal_mem_set (&mr, 0, sizeof (mr));
  mr.imr_multiaddr = mc_addr;
  if (ifindex)
    mr.imr_ifindex = ifindex;
  else
    {
#ifdef HAVE_IPNET
      mr.imr_address = if_addr;
#else
      mr.imr_address = if_addr;
#endif /* ! HAVE_IPNET */
    }
  
  ret = setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_ADD_MEMBERSHIP, &mr, sizeof (mr));

  if (ret < 0 && (errno == EADDRINUSE))
    ret = RESULT_OK;

  return ret;
}

/*
** Set IP TOS option
*/
result_t
pal_sock_set_ipv4_tos_prec (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_TOS, &state, sizeof (state));
}

/*
** Get IP TOS option
*/
result_t
pal_sock_get_ipv4_tos_prec (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, PAL_IPPROTO_IP, PAL_IP_TOS, state, &len);
}

/*
** Set TCP nodelay option
*/
result_t
pal_sock_set_tcp_nodelay (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, SOL_TCP, TCP_NODELAY, &state, sizeof (state));
}

/*
** Get TCP nodelay option
*/
result_t
pal_sock_get_tcp_nodelay (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, SOL_TCP, TCP_NODELAY, state, &len);
}

/*
** Set the socket so it's bound to a particular interface
*/
result_t
pal_sock_set_bindtodevice (pal_sock_handle_t sock, const char * ifname)
{
#ifdef SO_BINDTODEVICE
  return setsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname) + 1);
#else /* def SO_BINDTODEVICE */
  errno = EINVAL;
  return PAL_SOCK_ERROR;
#endif /* def SO_BINDTODEVICE */
}

/*
** Get the socket's bound interface
*/
result_t
pal_sock_get_bindtodevice (pal_sock_handle_t sock, char * ifname)
{
#ifdef SO_BINDTODEVICE
  int ret;
  struct ifreq ifr;
  socklen_t len = sizeof (ifr);

  ret = getsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, &len);
  pal_strncpy (ifname, (char *) & ifr.ifr_name, sizeof (ifr.ifr_name));
  return ret;
#else /* def SO_BINDTODEVICE */
  errno = EINVAL;
  return PAL_SOCK_ERROR;
#endif /* def SO_BINDTODEVICE */
}

/*
** Set broadcast packet control option
*/
result_t
pal_sock_set_broadcast (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, SOL_SOCKET, SO_BROADCAST, &state, sizeof (state));
}

/*
** Get broadcast packet control option
*/
result_t
pal_sock_get_broadcast (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, SOL_SOCKET, SO_BROADCAST, state, &len);
}

/*
** Set option for getting information about ingress interface
*/
result_t
pal_sock_set_ip_recvif (pal_sock_handle_t sock, s_int32_t state)
{
#if defined (IP_PKTINFO)
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_PKTINFO, &state, sizeof (state));
#elif defined (IP_RECVIF)
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_RECVIF, &state, sizeof (state));
#else 
  errno = ENOPROTOOPT;
  return PAL_SOCK_ERROR;
#endif
}

/*
** Set option for getting information about ingress IPv6 interface
*/
#ifdef HAVE_IPV6
result_t
pal_sock_set_ipv6_recvif (pal_sock_handle_t sock, s_int32_t state)
{
#if defined (IPV6_PKTINFO)
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_PKTINFO, &state, sizeof (state));
#elif defined (IPV6_RECVIF)
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IPV6_RECVIF, &state, sizeof (state));
#else
  errno = ENOPROTOOPT;
  return PAL_SOCK_ERROR;
#endif
}
#endif

/*
** Set option for getting information about ingress interface
*/
result_t
pal_sock_get_ip_recvif (pal_sock_handle_t sock, s_int32_t *state)
{
  socklen_t len = sizeof (s_int32_t);

#if defined (IP_PKTINFO)
  return getsockopt (sock, PAL_IPPROTO_IP, PAL_IP_PKTINFO, state, &len);
#elif defined (IP_RECVIF)
  return getsockopt (sock, PAL_IPPROTO_IP, PAL_IP_RECVIF, state, &len);
#else 
  errno = ENOPROTOOPT;
  return PAL_SOCK_ERROR;
#endif
}

/*
** Set IPv4 header include option
*/
result_t
pal_sock_set_ip_hdr_incl (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_HDRINCL, &state, sizeof (state));
}

/*
** Get IPv4 header include option
*/
result_t
pal_sock_get_ip_hdr_incl (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, PAL_IPPROTO_IP, PAL_IP_HDRINCL, state, &len);
}

/*
** Set IPv4 unicast hops
*/
result_t
pal_sock_set_ipv4_unicast_hops (pal_sock_handle_t sock, s_int32_t ttl)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_TTL, &ttl, sizeof (ttl));
}

/*
** Get IPv4 unicast hops
*/
result_t
pal_sock_get_ipv4_unicast_hops (pal_sock_handle_t sock, s_int32_t * ttl)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, PAL_IPPROTO_IP, PAL_IP_TTL, ttl, &len);
}

/*
** Set IPv4 multicast loop
*/
result_t
pal_sock_set_ipv4_multicast_loop (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_MULTICAST_LOOP, &state,
                     sizeof (state));
}

/*
** Get IPv4 multicast loop
*/
result_t
pal_sock_get_ipv4_multicast_loop (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, PAL_IPPROTO_IP, PAL_IP_MULTICAST_LOOP, state, &len);
}

/*
** Set IPv4 multcast interface
*/
result_t
pal_sock_set_ipv4_multicast_if (pal_sock_handle_t sock,
                                struct pal_in4_addr addr, u_int32_t ifindex)
{
  struct pal_ip_mreqn mr;

  pal_mem_set (&mr, 0, sizeof (mr));
  if (ifindex)
    mr.imr_ifindex = ifindex;
  else
    {
#ifdef HAVE_IPNET
      mr.imr_address = addr;
#else
      mr.imr_address = addr;
#endif /* ! HAVE_IPNET */
    }

  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_MULTICAST_IF, &mr, sizeof (mr));
}

/*
** Set IPv4 multicast hops
*/
result_t
pal_sock_set_ipv4_multicast_hops (pal_sock_handle_t sock, s_int32_t ttl)
{
#ifdef HAVE_IPNET
  u_int8_t ttl_val = ttl;

  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_MULTICAST_TTL, &ttl_val,
                     sizeof (ttl_val));
#else
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_MULTICAST_TTL, &ttl, sizeof (ttl));
#endif /* !HAVE_IPNET */
}

/*
** Get IPv4 multicast hops
*/
result_t
pal_sock_get_ipv4_multicast_hops (pal_sock_handle_t sock, s_int32_t * ttl)
{
#ifdef HAVE_IPNET
  u_int8_t ttl_val = 0;
  u_int32_t len = sizeof (ttl_val);

  getsockopt (sock, PAL_IPPROTO_IP, PAL_IP_MULTICAST_TTL, &ttl_val, &len);

  if (*ttl)
    *ttl = ttl_val;

  return 0;
#else
  socklen_t len = sizeof (int);
  return getsockopt (sock, PAL_IPPROTO_IP, PAL_IP_MULTICAST_TTL, ttl, &len);
#endif /* !HAVE_IPNET */
}

/*
** Set multicast forwarding on 
*/
result_t 
pal_sock_set_ipv4_mrt_init (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_MRT_INIT, &state, sizeof (state));
}

/*
** Set multicast forwarding off 
*/
result_t 
pal_sock_set_ipv4_mrt_done (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_MRT_DONE, &state, sizeof (state));
}

/*
** Set kernel IGMP on 
*/
result_t 
pal_sock_set_ipv4_mrt_igmp_init (pal_sock_handle_t sock, s_int32_t state)
{
  return RESULT_ERROR;
}

/*
** Set kernel IGMP off 
*/
result_t 
pal_sock_set_ipv4_mrt_igmp_done (pal_sock_handle_t sock, s_int32_t state)
{
  return RESULT_ERROR;
}

/*
** Set MRT assert option 
*/
result_t 
pal_sock_set_ipv4_mrt_assert (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_MRT_ASSERT, &state, sizeof (state));
}


/*
** Set PIM multicast forwarding on 
*/
result_t 
pal_sock_set_ipv4_pim (pal_sock_handle_t sock, s_int32_t state)
{
#ifdef HAVE_IPNET
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_MRT_ASSERT, &state, sizeof (state));
#else
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_MRT_PIM, &state, sizeof (state));
#endif /* HAVE_IPNET */
}

/*
** Get PIM multicast forwarding state 
*/
result_t 
pal_sock_get_ipv4_pim (pal_sock_handle_t sock, s_int32_t *state)
{
  return RESULT_OK;
}


/*
** Set option for getting information about destination address
*/
result_t 
pal_sock_set_ipv4_dstaddr (pal_sock_handle_t sock, s_int32_t state)
{
#if defined (IP_RECVDSTADDR)
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_RECVDSTADDR, &state, sizeof (state));
#elif defined (IP_PKTINFO) 
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_PKTINFO, &state, sizeof (state));
#else
  errno = ENOPROTOOPT;
  return PAL_SOCK_ERROR;
#endif 
}

/*
** Get option for getting information about destination address
*/
result_t 
pal_sock_get_ipv4_dstaddr (pal_sock_handle_t sock, s_int32_t *state)
{
  socklen_t len = sizeof (s_int32_t);

#if defined (IP_RECVDSTADDR)
  return getsockopt (sock, PAL_IPPROTO_IP, PAL_IP_RECVDSTADDR, &state, &len);
#elif defined (IP_PKTINFO)
  return getsockopt (sock, PAL_IPPROTO_IP, PAL_IP_PKTINFO, &state, &len);
#else
  errno = ENOPROTOOPT;
  return PAL_SOCK_ERROR;
#endif 
}

result_t 
pal_sock_set_ipv4_mrt_add_mfc (pal_sock_handle_t sock, void *mfc, size_t len)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_MRT_ADD_MFC, mfc, len);
}

result_t 
pal_sock_set_ipv4_mrt_del_mfc (pal_sock_handle_t sock, void *mfc, size_t len)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_MRT_DEL_MFC, mfc, len);
}

result_t 
pal_sock_set_ipv4_mrt_spt_bit (pal_sock_handle_t sock, void *mfc, size_t len)
{
  return RESULT_OK;
}


result_t 
pal_sock_set_ipv4_mrt_add_vif (pal_sock_handle_t sock, void *vif, size_t len)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_MRT_ADD_VIF, vif, len);
}

result_t 
pal_sock_set_ipv4_mrt_del_vif (pal_sock_handle_t sock, void *vif, size_t len)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_MRT_DEL_VIF, vif, len);
}


/*
** Set socket receive buffer depth
*/
result_t
pal_sock_set_recvbuf (pal_sock_handle_t sock, s_int32_t size)
{
  return setsockopt (sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof (size));
}

/*
** Get socket receive buffer depth
*/
result_t
pal_sock_get_recvbuf (pal_sock_handle_t sock, s_int32_t * size)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, SOL_SOCKET, SO_RCVBUF, size, &len);
}

/*
** Set socket send buffer depth
*/
result_t
pal_sock_set_sendbuf (pal_sock_handle_t sock, s_int32_t size)
{
  return setsockopt (sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof (size));
}

/*
** Get socket send buffer depth
*/
result_t
pal_sock_get_sendbuf (pal_sock_handle_t sock, s_int32_t * size)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, SOL_SOCKET, SO_SNDBUF, size, &len);
}

/*
** Set reuse address option
*/
result_t
pal_sock_set_reuseaddr (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &state, sizeof (state));
}

/*
** Get reuse address option
*/
result_t
pal_sock_get_reuseaddr (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, SOL_SOCKET, SO_REUSEADDR, state, &len);
}

/*
** Set reuse port option
*/
result_t
pal_sock_set_reuseport (pal_sock_handle_t sock, s_int32_t state)
{
#ifdef SO_REUSEPORT
  return setsockopt (sock, SOL_SOCKET, SO_REUSEPORT, &state, sizeof (state));
#else /* def SO_REUSEPORT */
  errno = EINVAL;
  return PAL_SOCK_ERROR;
#endif /* def SO_REUSEPORT */
}

/*
** Get reuse port option
*/
result_t
pal_sock_get_reuseport (pal_sock_handle_t sock, s_int32_t * state)
{
#ifdef SO_REUSEPORT
  socklen_t len = sizeof (int);
  return getsockopt (sock, SOL_SOCKET, SO_REUSEPORT, state, &len);
#else /* def SO_REUSEPORT */
  errno = EINVAL;
  return PAL_SOCK_ERROR;
#endif /* def SO_REUSEPORT */
}

/* 
** Get SO_ERROR socket option
*/
result_t
pal_sock_get_soerr (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, SOL_SOCKET, SO_ERROR, state, &len);
}

#ifdef HAVE_IPV6

/*
** Set IPv6 packet checksum option
*/
result_t
pal_sock_set_ipv6_checksum (pal_sock_handle_t sock, s_int32_t state)
{
#ifdef HAVE_IPNET
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_CHECKSUM, &state, sizeof(state));
#else
  return setsockopt (sock, PAL_IPPROTO_RAW, PAL_IPV6_CHECKSUM, &state, sizeof (state));
#endif /* HAVE_IPNET */
}

/*
** Get IPv6 packet checksum option
*/
result_t
pal_sock_get_ipv6_checksum (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
#ifdef HAVE_IPNET
  return getsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_CHECKSUM, state, &len);
#else
  return getsockopt (sock, PAL_IPPROTO_RAW, PAL_IPV6_CHECKSUM, state, &len);
#endif /* HAVE_IPNET */
}

/*
** Set IPv6 packet information option
*/
result_t
pal_sock_set_ipv6_pktinfo (pal_sock_handle_t sock, s_int32_t state)
{
#if defined(IPV6_RECVPKTINFO) || defined(HAVE_IPNET)
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_RECVPKTINFO, &state,
                     sizeof (state));
#else /* def IPV6_RECVPKTINFO */
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_PKTINFO, &state,
                     sizeof (state));
#endif /* def IPV6_RECVPKTINFO */
}

/*
** Get IPv6 packet information option
*/
result_t
pal_sock_get_ipv6_pktinfo (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
#if defined(IPV6_RECVPKTINFO) || defined(HAVE_IPNET)
  return getsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_RECVPKTINFO, state, &len);
#else /* def IPV6_RECVPKTINFO */
  return getsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_PKTINFO, state, &len);
#endif /* def IPV6_RECVPKTINFO */
}

/*
** Set IPv6 Hop-by-Hop options
*/
result_t
pal_sock_set_ipv6_hopopts (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_HOPOPTS, &state,
                     sizeof (state));
}

/*
** Get IPv6 Hop-by-Hop options
*/
result_t
pal_sock_get_ipv6_hopopts (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_HOPOPTS, state, &len);
}

/*
** Set IPv6 multicast hops
*/
result_t
pal_sock_set_ipv6_multicast_hops (pal_sock_handle_t sock, s_int32_t hops)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_MULTICAST_HOPS, &hops,
                     sizeof (hops));
}

/*
** Get IPv6 multicast hops
*/
result_t
pal_sock_get_ipv6_multicast_hops (pal_sock_handle_t sock, s_int32_t * hops)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_MULTICAST_HOPS, hops, &len);
}

/*
** Set IPv6 unicast hops
*/
result_t
pal_sock_set_ipv6_unicast_hops (pal_sock_handle_t sock, s_int32_t hops)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_UNICAST_HOPS, &hops,
                     sizeof (hops));
}

/*
** Set IPv6 unicast hops
*/
result_t
pal_sock_get_ipv6_unicast_hops (pal_sock_handle_t sock, s_int32_t * hops)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_UNICAST_HOPS, hops, &len);
}

/*
** Set IPv6 hoplimit
*/
result_t
pal_sock_set_ipv6_hoplimit (pal_sock_handle_t sock, s_int32_t hoplim)
{
#ifdef IPV6_RECVHOPLIMIT
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_RECVHOPLIMIT, &hoplim,
                     sizeof (hoplim));
#else /* def IPV6_RECVHOPLIMIT */
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_HOPLIMIT, &hoplim,
                     sizeof (hoplim));
#endif /* def IPV6_RECVHOPLIMIT */
}

/*
** Get IPv6 hoplimit
*/
result_t
pal_sock_get_ipv6_hoplimit (pal_sock_handle_t sock, s_int32_t * hoplim)
{
  socklen_t len = sizeof (int);
#ifdef IPV6_RECVHOPLIMIT
  return getsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_RECVHOPLIMIT, hoplim, &len);
#else /* def IPV6_RECVHOPLIMIT */
  return getsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_HOPLIMIT, hoplim, &len);
#endif /* def IPV6_RECVHOPLIMIT */
}

/*
** Set IPv6 multicast loop
*/
result_t
pal_sock_set_ipv6_multicast_loop (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_MULTICAST_LOOP, &state,
                     sizeof (state));
}

/*
** Get IPv6 multicast loop
*/
result_t
pal_sock_get_ipv6_multicast_loop (pal_sock_handle_t sock, s_int32_t * state)
{
  socklen_t len = sizeof (int);
  return getsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_MULTICAST_LOOP, state, &len);
}

/*
** Set IPv6 multcast interface
*/
result_t
pal_sock_set_ipv6_multicast_if (pal_sock_handle_t sock,
                                u_int32_t ifindex)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_MULTICAST_IF, &ifindex,
                     sizeof (ifindex));
}

/*
** Set IPv6 multicast join
*/
result_t
pal_sock_set_ipv6_multicast_join (pal_sock_handle_t sock,
                                  struct pal_in6_addr mc_addr,
                                  u_int32_t ifindex)
{
  struct pal_ipv6_mreq mreq;

  pal_mem_set (&mreq, 0, sizeof (struct pal_ipv6_mreq));
  mreq.ipv6mr_multiaddr = mc_addr;
  mreq.ipv6mr_interface = ifindex;
#ifdef IPV6_JOIN_GROUP
  return setsockopt (sock,
                     PAL_IPPROTO_IPV6,
                     PAL_IPV6_JOIN_GROUP,
                     (char *) &mreq, sizeof (struct pal_ipv6_mreq));
#else /* def IPV6_JOIN_GROUP */
  return setsockopt (sock,
                     PAL_IPPROTO_IPV6,
                     PAL_IPV6_ADD_MEMBERSHIP,
                     (char *) &mreq, sizeof (struct pal_ipv6_mreq));
#endif /* def IPV6_JOIN_GROUP */
}

/*
** Set IPv6 multicast leave
*/
result_t
pal_sock_set_ipv6_multicast_leave (pal_sock_handle_t sock,
                                   struct pal_in6_addr mc_addr,
                                   u_int32_t ifindex)
{
  struct pal_ipv6_mreq mreq;

  pal_mem_set (&mreq, 0, sizeof (struct pal_ipv6_mreq));
  mreq.ipv6mr_multiaddr = mc_addr;
  mreq.ipv6mr_interface = ifindex;

#ifdef IPV6_LEAVE_GROUP
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_LEAVE_GROUP, (char *) &mreq,
                     sizeof (struct pal_ipv6_mreq));
#else /* def IPV6_LEAVE_GROUP */
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_DROP_MEMBERSHIP, (char *) &mreq,
                     sizeof (struct pal_ipv6_mreq));
#endif /* IPV6_LEAVE_GROUP */
}

/*
** Set ICMPv6 filter options
*/
#if defined HAVE_RTADV || defined HAVE_MCAST_IPV6 || defined HAVE_IPV6
result_t
pal_sock_set_ipv6_icmp_filter (pal_sock_handle_t sock,
                               struct pal_icmp6_filter *filter)
{
  return setsockopt (sock, PAL_IPPROTO_ICMPV6, PAL_ICMP6_FILTER,
                     (struct icmp6_filter *) filter,
                     sizeof (struct icmp6_filter));
}
#endif /* defined HAVE_RTADV || defined HAVE_MCAST_IPV6 || defined HAVE_IPV6 */

#ifdef HAVE_MCAST_IPV6
/*
** Set multicast forwarding on
*/
result_t
pal_sock_set_ipv6_mrt6_init (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IP_MRT6_INIT, &state, sizeof (state));
}

/*
** Set multicast forwarding off
*/
result_t
pal_sock_set_ipv6_mrt6_done (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IP_MRT6_DONE, &state, sizeof (state));
}

/*
** Set PIM multicast forwarding on/off
*/
result_t
pal_sock_set_ipv6_mrt6_pim (pal_sock_handle_t sock, s_int32_t state)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IP_MRT6_PIM, &state, sizeof (state));
}

result_t
pal_sock_set_ipv6_mrt6_add_mfc (pal_sock_handle_t sock, void *mfc, size_t len)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IP_MRT6_ADD_MFC, mfc, len);
}

result_t
pal_sock_set_ipv6_mrt6_del_mfc (pal_sock_handle_t sock, void *mfc, size_t len)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IP_MRT6_DEL_MFC, mfc, len);
}

result_t
pal_sock_set_ipv6_mrt6_add_vif (pal_sock_handle_t sock, void *vif, size_t len)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IP_MRT6_ADD_MIF, vif, len);
}

result_t
pal_sock_set_ipv6_mrt6_del_vif (pal_sock_handle_t sock, void *vif, size_t len)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IP_MRT6_DEL_MIF, vif, len);
}
#endif /* HAVE_MCAST_IPV6 */
#endif /* HAVE_IPV6 */

/*
** Set socket-FIB binding.
*/
result_t
pal_sock_set_bindtofib (pal_sock_handle_t sock, fib_id_t fib)
{
#if defined(HAVE_MULTIPLE_FIB) || defined(HAVE_IPNET) || defined(HAVE_PBR_FIB)
  u_int32_t vrid = fib;
#endif /* HAVE_MULTIPLE_FIB || HAVE_IPNET || HAVE_PBR_FIB */

#ifdef HAVE_MULTIPLE_FIB
  return setsockopt (sock, SOL_SOCKET, SO_VRF, &vrid, sizeof (vrid));
#endif /* HAVE_MULTIPLE_FIB */

#ifdef HAVE_IPNET
  return setsockopt (sock, IP_SOL_SOCKET, IP_SO_X_VR, &vrid, sizeof (vrid));
#endif /* HAVE_IPNET */

#ifdef HAVE_PBR_FIB
  return setsockopt (sock, SOL_SOCKET, SO_MARK, &vrid, sizeof (vrid));
#endif /* HAVE_PBR_FIB */

  return RESULT_OK;
}

/*
** Get socket-FIB binding.
*/
result_t
pal_sock_get_bindtofib (pal_sock_handle_t sock, fib_id_t * fib)
{
#if defined(HAVE_MULTIPLE_FIB) || defined(HAVE_IPNET) || defined(HAVE_PBR_FIB)
  socklen_t len = sizeof (int);
#endif /* HAVE_MULTIPLE_FIB || HAVE_IPNET || HAVE_PBR_FIB */

#ifdef HAVE_MULTIPLE_FIB
  int ret;
  s_int32_t vrid = *fib;

  ret = getsockopt (sock, SOL_SOCKET, SO_VRF, &vrid, &len);
  *fib = (fib_id_t) vrid;

  return ret;
#endif /* HAVE_MULTIPLE_FIB */

#ifdef HAVE_IPNET
  return getsockopt (sock, IP_SOL_SOCKET, IP_SO_X_VR, fib, &len);
#endif /* HAVE_IPNET */

#ifdef HAVE_PBR_FIB
  return getsockopt (sock, SOL_SOCKET, SO_MARK, fib, &len);
#endif /* HAVE_PBR_FIB */

  return RESULT_OK;
}

/*
** Set Link-Layer multicast join
*/
result_t
pal_sock_set_ll_multicast_join (pal_sock_handle_t sock,
                                u_char * mc_addr, u_int32_t ifindex)
{
  struct packet_mreq mr;

  pal_mem_set (&mr, 0, sizeof mr);

  mr.mr_ifindex = ifindex;
  mr.mr_type = PACKET_MR_MULTICAST;
  mr.mr_alen = ETHER_ADDR_LEN;
  memcpy (mr.mr_address, mc_addr, ETHER_ADDR_LEN);
#ifdef SOL_PACKET
  return setsockopt (sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr);
#else
  return -1;
#endif /* SOL_PACKET */
}

/*
** Set Link-Layer multicast leave
*/
result_t
pal_sock_set_ll_multicast_leave (pal_sock_handle_t sock,
                                 u_char * mc_addr, u_int32_t ifindex)
{
  struct packet_mreq mr;

  pal_mem_set (&mr, 0, sizeof (mr));
  mr.mr_ifindex = ifindex;
  mr.mr_type = PACKET_MR_MULTICAST;
  mr.mr_alen = ETHER_ADDR_LEN;
  memcpy (mr.mr_address, mc_addr, ETHER_ADDR_LEN);

#ifdef SOL_PACKET
  return setsockopt (sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mr, sizeof mr);
#else
  return -1;
#endif /* SOL_PACKET */
}

/*
** Set "router alert" option.
*/
result_t
pal_sock_set_router_alert (pal_sock_handle_t sock, int state,
                           module_id_t prot_id)
{
  return setsockopt (sock, PAL_IPPROTO_IP, PAL_IP_ROUTER_ALERT, &state, sizeof(state));
}

#ifdef HAVE_IPV6
result_t
pal_sock6_set_router_alert (pal_sock_handle_t sock, int state,
                            module_id_t prot_id)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, PAL_IPV6_ROUTER_ALERT, 
                     &state, sizeof(state));
}

result_t
pal_sock_unset_ipv6_nexthop (pal_sock_handle_t sock)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, IPV6_NEXTHOP, NULL, 0);
}

result_t
pal_sock_set_ipv6_nexthop (pal_sock_handle_t sock, struct pal_in6_addr *addr)
{
  return setsockopt (sock, PAL_IPPROTO_IPV6, IPV6_NEXTHOP, addr,
                     sizeof (struct pal_in6_addr));
}

#endif

#ifdef HAVE_IPNET
char *
pal_ipnet_version ()
{
  return "IPNET";
}
#endif /* HAVE_IPNET */

result_t
pal_sock_set_timestamp(pal_sock_handle_t sock, int state)
{
  return setsockopt (sock, SOL_SOCKET, SO_TIMESTAMP, &state, sizeof(state));
}

/*
 * Set the socket receive buffer size.
 *
 * Arguments:
 * sock [in] Socket handle.
 * size [in] Receive buffer size.
 *
 * Return value:
 * 0 if successful, -1 otherwise.
 */
int
pal_sock_set_rcvbuf(pal_sock_handle_t sock, int size)
{
  return (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)));
}

/*
 * Set the socket send buffer size.
 *
 * Arguments:
 * sock [in] Socket handle.
 * size [in] Send buffer size.
 *
 * Return value:
 * 0 if successful, -1 otherwise.
 */
int
pal_sock_set_sndbuf(pal_sock_handle_t sock, int size)
{
  return (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)));
}

