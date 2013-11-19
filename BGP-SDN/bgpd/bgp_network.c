/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/*********************************************************************/
/* FILE       : bgp_network.c                                        */
/* PURPOSE    : This file contains BGP Peer Network-Interface        */
/*              (Sockets) related function definitions.              */
/* SUB-MODULE : BGP Peer Network-Interface                           */
/* NAME-TAG   : 'bpn_' (BGP Peer Network)                            */
/*********************************************************************/

in_port_t
bpn_get_port_any (int family, int socktype, struct pal_sockaddr *sa)
{
  struct pal_addrinfo hints;
  struct pal_addrinfo *res;
  void *src;
  socklen_t size;
  in_port_t port_any = 0;
  char addr_str[INET6_ADDRSTRLEN];
  const char *s;
  int ret;

  pal_mem_set (&hints, 0, sizeof(hints));
  hints.ai_flags |= (AI_NUMERICHOST | AI_NUMERICSERV);
  hints.ai_family = family;
  hints.ai_socktype = socktype;

  switch (family)
    {
    case AF_INET:
      if (sa->sa_family != AF_INET)
        {
          zlog_warn (&BLG, "[NETWORK] %s: family mismatch (AF_INET - %d)",
                     __FUNCTION__, sa->sa_family);
          goto fallback;
        }
      src = &(((struct pal_sockaddr_in4 *)sa)->sin_addr);
      size = INET_ADDRSTRLEN;
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      if (sa->sa_family != AF_INET6)
        {
          zlog_warn (&BLG, "[NETWORK] %s: family mismatch (AF_INET6 - %d)",
                     __FUNCTION__, sa->sa_family);
          goto fallback;
        }
      src = &(((struct pal_sockaddr_in6 *)sa)->sin6_addr);
      size = INET6_ADDRSTRLEN;
      break;
#endif /* HAVE_IPV6 */
    default:
      zlog_warn (&BLG, "[NETWORK] %s: wrong family param (%d)",
                 __FUNCTION__, sa->sa_family);
      goto fallback;
    }
  s = pal_inet_ntop (family, src, addr_str, size);
  if (!s)
    {
      zlog_warn (&BLG, "[NETWORK] %s: inet_ntop(%d)", __FUNCTION__, errno);
      goto fallback;
    }
  ret = pal_sock_getaddrinfo (addr_str, NULL, &hints, &res);
  if (ret < 0)
    {
      zlog_warn (&BLG, "[NETWORK] %s: getaddrinfo(%d)", __FUNCTION__, errno);
      goto fallback;
    }
  switch (res->ai_family)
    {
    case AF_INET:
      port_any = ((struct pal_sockaddr_in4 *)(res->ai_addr))->sin_port;
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      port_any = ((struct pal_sockaddr_in6 *)(res->ai_addr))->sin6_port;
      break;
#endif /* HAVE_IPV6 */
    default:
      zlog_warn (&BLG, "[NETWORK] %s: wrong family from getaddrinfo(): %d",
                 __FUNCTION__, res->ai_family);
      break;
    }
  pal_sock_freeaddrinfo (res);

 fallback:
  return port_any;
}


/*
 * LEVEL 1 Socket Status Handler function:
 * Informs BGP Peer FSM of socket error status
 */
void
bpn_sock_cb_status_hdlr (struct stream_sock_cb *ssock_cb,
                         s_int32_t sock_err,
                         struct lib_globals *blg)
{
  struct bgp_peer *peer;

  /* Sanity check */
  if (! ssock_cb || blg != &BLG)
    {
      zlog_err (&BLG, "[NETWORK] Sock Status: Invalid Sock CB (%X)",
                ssock_cb);

      goto EXIT;
    }

  /* Obtain the Socket CB's owning peer */
  peer = (struct bgp_peer *) SSOCK_CB_GET_OWNER (ssock_cb);
  if (! peer || peer->sock_cb != ssock_cb)
    {
      zlog_err (&BLG, "%s-%s [NETWORK] Sock Status: Invalid Sock CB (%X)",
                peer ? peer->host : (u_int8_t *) "?",
                peer ? BGP_PEER_DIR_STR (peer): "?", ssock_cb);

      goto EXIT;
    }

  /* Set BGP VR Context */
  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  if (BGP_DEBUG (fsm, FSM))
    zlog_info (&BLG, "%s-%s [NETWORK] FD=%u, Sock Status: %d-%s",
               peer->host, BGP_PEER_DIR_STR (peer),
               SSOCK_CB_GET_SSOCK_FD (ssock_cb),
               sock_err, pal_strerror (sock_err));

  switch (sock_err)
    {
    case RESULT_OK:
      /*
       * NOTE: Currently, in RFC 4271, there is
       * no distinction in terms of Event handling for Event 16
       * (Tcp_CR_Acked) and Event 17 (TcpConnectionConfirmed).
       * So we just generate Event 17. If different handling is
       * defined in later drafts, we will generate Event 16.
       */
      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_TCP_CONN_CFM);

      /* Set the Initial Decode Function and its Argument */
      SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_hdr);
      SSOCK_CB_SET_READ_FUNC_ARG (ssock_cb, BGP_HEADER_SIZE);
      break;

    case EFAULT:
    case EINVAL:
    case EBADF:
    case EISDIR:
    case EIO:
    case ENOTCONN:
    default:
      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_TCP_CONN_FAIL);
      break;
    }

 EXIT:

  return;
}

/* Tries to open TCP Connection to BGP Peer */
void
bpn_sock_cb_connect (struct bgp_peer *peer)
{
  pal_sock_handle_t sck_fd;
  union sockunion su;
  u_int32_t ifindex;
  s_int32_t ret;

  ifindex = 0;

  /* Obtain Socket FD */
  sck_fd = stream_sock_cb_get_fd (peer->sock_cb, &peer->su, &BLG);
  if (sck_fd < 0)
    {
      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_TCP_CONN_FAIL);

      goto EXIT;
    }

  /* Set Socket options */
  ret = bpn_sock_set_opt (peer, sck_fd, PAL_TRUE);
  if (ret < 0)
    {
      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_TCP_CONN_FAIL);

      goto EXIT;
    }

  /* Prepare the Sock-Union struct to connect */
  pal_mem_cpy (&su, &peer->su, sizeof (union sockunion));

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      if (peer->ifname)
        ifindex = if_name2index (&BGP_VR.owning_ivr->ifm,
                                 peer->ifname);
    }
#endif /* HAVE_IPV6 */

  switch (su.sa.sa_family)
    {
    case AF_INET:
      su.sin.sin_port = pal_hton16 (BGP_PORT_DEFAULT);
      break;

#ifdef HAVE_IPV6
    case AF_INET6:
      su.sin6.sin6_port  = pal_hton16 (BGP_PORT_DEFAULT);
#ifdef KAME
      if (IN6_IS_ADDR_LINKLOCAL(&su.sin6.sin6_addr) && ifindex)
        {
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

  /* Connect the Stream Socket */
  ret = stream_sock_cb_connect (peer->sock_cb, &su, &BLG);
  if (ret < 0)
    {
      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_TCP_CONN_FAIL);

      goto EXIT;
    }

 EXIT:

  return;
}

/* Closes a TCP Connection to BGP Peer */
void
bpn_sock_cb_disconnect (struct bgp_peer *peer)
{
  /* Loose the Connected Socket Identification information */
  peer->su_local = NULL;
  peer->su_remote = NULL;

  /* De-activate the Socket-CB */
  stream_sock_cb_close (peer->sock_cb, &BLG);

  return;
}

/* Resets a Socket-CB of the BGP Peer */
void
bpn_sock_cb_reset (struct bgp_peer *peer)
{
  /* De-activate the Socket-CB */
  stream_sock_cb_idle (peer->sock_cb, &BLG);

  return;
}

void
bpn_set_peer_nexthop (union sockunion *su, struct bgp_peer *peer,
		      struct bgp_nexthop *nexthop)
{
  if (! su || ! nexthop)
    return;

  if (su->sa.sa_family == AF_INET)
    {
      nexthop->v4 = su->sin.sin_addr;
    }
#ifdef HAVE_IPV6
  else if (su->sa.sa_family == AF_INET6)
    {
      if (peer->local_id.s_addr)
	nexthop->v4 = peer->local_id;

      if (! IN6_IS_ADDR_LINKLOCAL (&su->sin6.sin6_addr))
    	{
	  pal_mem_cpy (&nexthop->v6_global, &su->sin6.sin6_addr, IPV6_MAX_BYTELEN);
	}
      else
	{
	  pal_mem_cpy (&nexthop->v6_global, &su->sin6.sin6_addr, IPV6_MAX_BYTELEN);
	  pal_mem_cpy (&nexthop->v6_local, &su->sin6.sin6_addr, IPV6_MAX_BYTELEN);
	}
    }
#endif /* HAVE_IPV6 */

  return;
}

/* Obtain Socket Identification */
void
bpn_sock_cb_get_id (struct bgp_peer *peer)
{
  peer->su_local = SSOCK_CB_GET_SU_LOCAL (peer->sock_cb);
  peer->su_remote = SSOCK_CB_GET_SU_REMOTE (peer->sock_cb);

  bpn_set_peer_nexthop (peer->su_local, peer, &peer->nexthop);
  return;
}

/* BGP Peer TCP Socket bind to 'update-source' address
 *
 * Specify the TCP client's source IP address.
 * This function must be called before calling connect().
 * The source port is set to "any port"
 * (i.e., picked by the kernel) unless a user specified it.
 */
s_int32_t
bpn_sock_bind_address (struct bgp_peer *peer,
                       pal_sock_handle_t sck_fd)
{
  struct prefix *if_prefix;
  struct interface *ifp;
  union sockunion uaddr;
  s_int32_t uaddr_len;
  s_int32_t ret;

  pal_mem_set (&uaddr, 0, sizeof (union sockunion));
  uaddr_len = 0;
  ret = 0;

  /* Ifname is exist. */
  if (peer->update_if)
    {
      ifp = if_lookup_by_name (&BGP_VR.owning_ivr->ifm,
                               peer->update_if);
      if (! ifp)
        {
          ret = -1;
          goto EXIT;
        }

      if_prefix = if_get_connected_address (ifp, peer->su.sa.sa_family);
      if (! if_prefix)
        {
          ret = -1;
          goto EXIT;
        }

      uaddr.sa.sa_family = if_prefix->family;

      if (uaddr.sa.sa_family == AF_INET)
        {
          uaddr.sin.sin_family = AF_INET;

          uaddr_len = sizeof (struct pal_sockaddr_in4);
#ifdef HAVE_SIN_LEN
          uaddr.sin.sin_len = pal_hton16 (uaddr_len);
#endif /* HAVE_SIN_LEN */
          IPV4_ADDR_COPY (&uaddr.sin.sin_addr, &if_prefix->u.prefix4);

          if (peer->sock_port == BGP_PORT_DEFAULT)
            uaddr.sin.sin_port = 
              bpn_get_port_any (AF_INET, SOCK_STREAM, &uaddr.sa);
          else
            uaddr.sin.sin_port = pal_hton16 (peer->sock_port);

        }
#ifdef HAVE_IPV6
      else if (BGP_CAP_HAVE_IPV6 && uaddr.sa.sa_family == AF_INET6)
        {
          uaddr.sin6.sin6_family = AF_INET6;

          uaddr_len = sizeof (struct pal_sockaddr_in6);
#ifdef HAVE_SIN_LEN
          uaddr.sin6.sin6_len = pal_hton16 (uaddr_len);
#endif /* HAVE_SIN_LEN */
          IPV6_ADDR_COPY (&uaddr.sin6.sin6_addr, &if_prefix->u.prefix6);

          if (peer->sock_port == BGP_PORT_DEFAULT)
            uaddr.sin6.sin6_port = 
              bpn_get_port_any (AF_INET6, SOCK_STREAM, &uaddr.sa);
          else
            uaddr.sin6.sin6_port = pal_hton16 (peer->sock_port);
        }
#endif /* HAVE_IPV6 */
      else
        {
          if (BGP_DEBUG (events, EVENTS))
            zlog_err (&BLG, "%s-%s [NETWORK] bind addr: socket (%d), "
                      "unknown update-interface family (%d)", peer->host,
                      BGP_PEER_DIR_STR (peer), sck_fd, uaddr.sa.sa_family);

          ret = -1;
          goto EXIT;
        }
    }
  else if (peer->update_source)
    {
      uaddr.sa.sa_family = peer->update_source->sa.sa_family;

      if (uaddr.sa.sa_family == AF_INET)
        {
          uaddr.sin.sin_family = AF_INET;

          uaddr_len = sizeof (struct pal_sockaddr_in4);

         if (peer->sock_port == BGP_PORT_DEFAULT)
           uaddr.sin.sin_port =
             bpn_get_port_any (AF_INET, SOCK_STREAM,
                               &peer->update_source->sa);
         else
           uaddr.sin.sin_port = pal_hton16 (peer->sock_port);

#ifdef HAVE_SIN_LEN
          uaddr.sin.sin_len = pal_hton16 (uaddr_len);
#endif /* HAVE_SIN_LEN */

          IPV4_ADDR_COPY (&uaddr.sin.sin_addr,
                          &peer->update_source->sin.sin_addr);
        }
#ifdef HAVE_IPV6
      else if (BGP_CAP_HAVE_IPV6 && uaddr.sa.sa_family == AF_INET6)
        {
          uaddr.sin6.sin6_family = AF_INET6;

          uaddr_len = sizeof (struct pal_sockaddr_in6);

         if (peer->sock_port == BGP_PORT_DEFAULT)
           uaddr.sin6.sin6_port =
             bpn_get_port_any (AF_INET6, SOCK_STREAM,
                               &peer->update_source->sa);
         else
           uaddr.sin.sin_port = pal_hton16 (peer->sock_port);

#ifdef HAVE_SIN_LEN
          uaddr.sin6.sin6_len = pal_hton16 (uaddr_len);
#endif /* HAVE_SIN_LEN */

          IPV6_ADDR_COPY (&uaddr.sin6.sin6_addr,
                          &peer->update_source->sin6.sin6_addr);
        }
#endif /* HAVE_IPV6 */
      else
        {
          if (BGP_DEBUG (events, EVENTS))
            zlog_err (&BLG, "%s-%s [NETWORK] bind addr: socket (%d), "
                      "unknown update-address family (%d)", peer->host,
                      BGP_PEER_DIR_STR (peer), sck_fd, uaddr.sa.sa_family);

          ret = -1;
          goto EXIT;
        }
    }

  if (uaddr_len)
    {
      ret = pal_sock_bind (sck_fd, (struct pal_sockaddr *) &uaddr, uaddr_len);

      if (ret < 0)
        if (BGP_DEBUG (events, EVENTS))
          zlog_err (&BLG, "%s-%s [NETWORK] bind addr: socket (%d), bind"
                    " failed (%d-%s)", peer->host, BGP_PEER_DIR_STR (peer),
                    sck_fd, errno, pal_strerror (errno));
    }

 EXIT:

  return ret;
}

/* BGP Peer TCP Socket No-Delay (Push) Option Setting */
s_int32_t
bpn_sock_set_opt_nodelay (struct bgp_peer *peer)
{
  pal_sock_handle_t sck_fd;
  s_int32_t ret;

  sck_fd = stream_sock_cb_get_fd (peer->sock_cb, &peer->su, &BLG);
  if (sck_fd < 0)
    {   
      zlog_warn(&BLG, " Failure in getting sock_fd (%d)", sck_fd);
      return sck_fd;
    }

  ret = pal_sock_set_tcp_nodelay (sck_fd, PAL_TRUE);
  if (ret < 0)
    {
      zlog_warn (&BLG, "%s-%s [NETWORK] set sockopt NODELAY FAILED(%d-%s)",
                 peer->host, BGP_PEER_DIR_STR (peer), errno,
                 pal_strerror (errno));
    }

  return ret;
}

/* BGP Peer General TCP Socket Option Settings */
s_int32_t
bpn_sock_set_opt (struct bgp_peer *peer,
                  pal_sock_handle_t sck_fd,
                  bool_t do_bind)
{
  fib_id_t fib_id;
  s_int32_t ret;
  int flags = 1;


  fib_id = LIB_VRF_GET_FIB_ID (peer->bgp->owning_ivrf);
  ret = 0;

  /* set socket as ipv6 only */
  if (peer->su.sa.sa_family == AF_INET6)
    {
      ret = setsockopt(sck_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &flags, sizeof(flags));
      if (ret < 0)
        {
          zlog_err (&BLG, "%s-%s [NETWORK] Set Sock Opt: "
                    "failed to set option: Sock = %d",
                    peer->host, BGP_PEER_DIR_STR (peer), sck_fd);
        }
    }

  /* Set Socket as Non-blocking */
  pal_sock_set_nonblocking (sck_fd, PAL_TRUE);

  /* Set Socket to reuse Addr and Port */
  ret = pal_sock_set_reuseaddr (sck_fd, PAL_TRUE);
  if (ret < 0)
    {
      zlog_err (&BLG, "%s-%s [NETWORK] Set Sock Opt: "
                "failed to reuse addr: Sock %d",
                peer->host, BGP_PEER_DIR_STR (peer), sck_fd);

      return ret;
    }
  pal_sock_set_reuseport (sck_fd, PAL_TRUE);

  /* Set TTL for EBGP peers */
  if (peer_sort (peer) == BGP_PEER_EBGP)
    {
      if (peer->su.sa.sa_family == AF_INET)
        ret = (s_int32_t)pal_sock_set_ipv4_unicast_hops (sck_fd, peer->ttl);
#ifdef HAVE_IPV6
      else if (BGP_CAP_HAVE_IPV6
               && peer->su.sa.sa_family == AF_INET6)
        ret = (s_int32_t)pal_sock_set_ipv6_hoplimit (sck_fd, peer->ttl);
#endif /* HAVE_IPV6 */
      
      if (ret < 0)
        zlog_warn (&BLG, "Can't set Hop Limit: %s(%d)",    
	           pal_strerror (errno), errno);
    }

  if (PAL_TRUE == do_bind)
    {
      /* Bind socket to FIB */
      ret = pal_sock_set_bindtofib (sck_fd, fib_id);
      if (ret < 0)
        {
          zlog_err (&BLG, "%s-%s [NETWORK] Set Sock Opt: Failed to bind "
              "Sock %d to FIB with VRF-ID %d",
              peer->host, BGP_PEER_DIR_STR (peer), sck_fd, fib_id);

          return ret;
        }
    }

  /* Bind Socket to Interface */
#ifdef SO_BINDTODEVICE
  if (peer->ifname)
    {
      ret = pal_sock_set_bindtodevice (sck_fd, peer->ifname);
      if (ret < 0)
        {
          zlog_err (&BLG, "%s-%s [NETWORK] Set Sock Opt: Failed to "
                    "bind Sock %d to IF %s", peer->host,
                    BGP_PEER_DIR_STR (peer), sck_fd, peer->ifname);

          return ret;
        }
    }
#endif /* SO_BINDTODEVICE */

  /* Update-source address bind */
  if (do_bind == PAL_TRUE)
    {
      ret = bpn_sock_bind_address (peer, sck_fd);
      if (ret < 0)
        {
          zlog_err (&BLG, "%s-%s [NETWORK] Set Sock Opt: Update-source "
                    "failed on Sock %d", peer->host,
                    BGP_PEER_DIR_STR (peer), sck_fd);

          return ret;
        }
    }

  /* Set TCP MD5 authentication */
#ifdef HAVE_TCP_MD5SIG
  if (CHECK_FLAG (peer->config, PEER_CONFIG_PASSWORD))
    if (sockunion_family (&peer->su) == AF_INET)
      bgp_md5_set (sck_fd, &peer->su.sin.sin_addr, peer->password);
#endif /* TCP_MD5SIG */

  return ret;
}

/* BGP Peer Incoming Connection Accept thread handler */
s_int32_t
bpn_sock_accept (struct thread *t_accept)
{
  struct bgp_listen_sock_lnode *tmp_lnode;
  struct bgp_peer_inconn_req *peer_icr;
  u_int8_t su_buf [SU_ADDRSTRLEN];
  pal_sock_handle_t accept_sock;
  pal_sock_handle_t bgp_sock;
  struct lib_globals *blg;
  struct bgp_peer *peer;
  union sockunion su;
  struct bgp *bgp;
  s_int32_t ret;

  bgp_sock = THREAD_FD (t_accept);
  blg = THREAD_GLOB (t_accept);
  bgp = THREAD_ARG (t_accept);
  ret = 0;

  /* Sanity check thread variables */
  if (! blg || &BLG != blg)
    {
      ret = -1;
      goto EXIT;
    }

  if (! bgp)
    {
      zlog_err (&BLG, "[NETWORK] Accept Thread: Invalid Vital Vars, "
                "blg(%p) bgp(%p)", blg, bgp);

      ret = -1;
      goto EXIT;
    }

  /* Verify integrity of thread variables */
  for (tmp_lnode = bgp->listen_sock_lnode; tmp_lnode;
       tmp_lnode = tmp_lnode->next)
    {
      if (tmp_lnode->listen_sock == bgp_sock)
        break;
    }

  if (! tmp_lnode)
    {
      zlog_err (&BLG, "[NETWORK] Accept Thread: Mismatch in thread args"
                "blg(%p) bgp(%p)", blg, bgp);

      ret = -1;
      goto EXIT;
    }

  /* Set BGP VR Context */
  BGP_SET_VR_CONTEXT (&BLG, bgp->owning_bvr);

  /* Re-regiser accept thread */
  t_accept = NULL;
  BGP_READ_ON (&BLG, t_accept, bgp, bpn_sock_accept, bgp_sock);

  /* Update the Accept Thread List Node */
  tmp_lnode->t_accept = t_accept;

  /* Accept Incoming Connection (Blocking) */
  accept_sock = sockunion_accept (&BLG, bgp_sock, &su);
  if (accept_sock < 0)
    {
      zlog_err (&BLG, "[NETWORK] Accept Thread: accept() Failed for Server"
                " Sock %d, Err:%d-%s", bgp_sock, errno, pal_strerror (errno));

      ret = -1;
      goto EXIT;
    }

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "[NETWORK] Accept Thread: Incoming conn from host"
               " %s (FD=%u)", inet_sutop (&su, su_buf), accept_sock);

  /* Search for Configured Peer with same Remote IP address */
  peer = bgp_peer_search (bgp, &su);

  if (! peer)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "[NETWORK] Accept Thread: %s - No such Peer "
                   "configured", inet_sutop (&su, su_buf));

      SSOCK_FD_CLOSE (&BLG, accept_sock);

      ret = -1;
      goto EXIT;
    }

  /* Prepare an Incoming Connection Req. Info structure */
  peer_icr = XCALLOC (MTYPE_TMP, sizeof (struct bgp_peer_inconn_req));
  if (! peer_icr)
    {
      zlog_err (&BLG, "[NETWORK] Accept Thread:"
                " Cannot allocate memory (%d) @ %s:%d",
                sizeof (struct bgp_peer_inconn_req), __FILE__, __LINE__);

      SSOCK_FD_CLOSE (&BLG, accept_sock);

      ret = -1;
      goto EXIT;
    }

  /* Initialize the FIFO Node */
  FIFO_INIT (&peer_icr->icr_fifo);

  /* Store the ICR Information */
  peer_icr->icr_sock = accept_sock;
  switch (su.sa.sa_family)
    {
    case AF_INET:
      peer_icr->icr_port = su.sin.sin_port;
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      peer_icr->icr_port = su.sin6.sin6_port;
      break;
#endif /* HAVE_IPV6 */
    }

  /* Enqueue into Peer's 'bicr_fifo' */
  FIFO_ADD (&peer->bicr_fifo, &peer_icr->icr_fifo);

  /* Generate BGP Peer FSM ICR Event */
  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_TCP_CONN_VALID);

 EXIT:

  return ret;
}

#if defined(HAVE_IPV6) && !defined(NRL)
s_int32_t
bpn_sock_listen (struct bgp *bgp, u_int16_t port)
{
  struct bgp_listen_sock_lnode *tmp_lnode;
  u_int8_t port_str [SU_ADDRSTRLEN];
  struct pal_addrinfo *ainfo_save[2], *ainfo_head;
  struct pal_addrinfo *ainfo;
  struct pal_sockaddr_in4 ain4;
  struct pal_sockaddr_in6 ain6;
  struct pal_addrinfo req;
  struct thread *t_accept;
  s_int32_t bgp_sock;
  u_int8_t addr_set;
  fib_id_t fib_id;
  s_int32_t ret;	
  int i, flags = 1;

  pal_mem_set (&req, 0, sizeof (struct pal_addrinfo));
  t_accept = NULL;
  ainfo_save[0] = NULL;
  ainfo_save[1] = NULL;
  ret = 0;
  addr_set = 0;

  if (! bgp)
    {
      zlog_err (&BLG, "[NETWORK] Server Sock: Invalid 'bgp' instance");

      return -1;
    }

  fib_id = LIB_VRF_GET_FIB_ID (bgp->owning_ivrf);
  req.ai_flags = AI_PASSIVE;
  req.ai_family = AF_UNSPEC;
  req.ai_socktype = SOCK_STREAM;
  pal_snprintf (port_str, SU_ADDRSTRLEN, "%d", port);
  port_str[sizeof (port_str) - 1] = '\0';

  ret = pal_sock_getaddrinfo (NULL, port_str, &req, &ainfo);
  if (ret != 0)
    {
      zlog_err (&BLG, "[NETWORK] Server Sock: getaddrinfo() failed: %d-%s",
                errno, pal_strerror (errno));

      return ret;
    }

  ainfo_head = ainfo;
  /* IPv4 can connect to IPv6 socket, not other way around. */
  while (ainfo)
    {
      if (ainfo->ai_family == AF_INET)
        ainfo_save[1] = ainfo;
      else if (ainfo->ai_family == AF_INET6)
        ainfo_save[0] = ainfo;

      ainfo = ainfo->ai_next;
    }

  for (i = 0; i < 2; i++) {
    ainfo = ainfo_save[i];

    if (! ainfo)
      continue;

    if (ainfo->ai_family != AF_INET && ainfo->ai_family != AF_INET6)
      continue;

    bgp_sock = pal_sock (&BLG, ainfo->ai_family, ainfo->ai_socktype,
                         ainfo->ai_protocol);
    if (bgp_sock < 0)
      {
        zlog_err (&BLG, "[NETWORK] Server Sock: socket() Failed for AF"
                  "=%d, FIB-ID %d, Err:%d-%s", ainfo->ai_family,
                  fib_id, errno, pal_strerror (errno));

        continue;
      }

    /* set socket as ipv6 only */
    if (ainfo->ai_family == AF_INET6)
      {
        ret = setsockopt(bgp_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &flags, sizeof(flags));
        if (ret < 0)
          {
            zlog_err (&BLG, "[NETWORK] Server Sock: socket() failed to"
                      "set option for AF=%d, Err:%d-%s", ainfo->ai_family,
                      errno, pal_strerror (errno));
          }
      }

    ret = pal_sock_set_reuseaddr (bgp_sock, PAL_TRUE);
    pal_sock_set_reuseport (bgp_sock, PAL_TRUE);

    /* Bind socket to FIB. */
    ret = pal_sock_set_bindtofib (bgp_sock, fib_id);
    if (ret < 0)
      {
        zlog_err (&BLG, "[NETWORK] Server Sock: bindtofib() Failed for"
                  " AF=%d, Sock %d, FIB-ID %d, Err:%d-%s",
                  ainfo->ai_family, bgp_sock, fib_id, errno,
                  pal_strerror (errno));

        SSOCK_FD_CLOSE (&BLG, bgp_sock);

        ret = 0;

        continue;
      }

    /* If the ai_addr is NULL, bind it to the port. */
    if (ainfo->ai_addr == NULL)
      {
        if (ainfo->ai_family == AF_INET)
          {
            pal_mem_set (&ain4, 0, sizeof (ain4)); 

            ain4.sin_family = AF_INET;
            ain4.sin_port   = pal_hton16 (port);

            ainfo->ai_addr    = (struct pal_sockaddr *) &ain4;
            ainfo->ai_addrlen = sizeof (struct pal_sockaddr_in4);
            addr_set = 1;
          }
        else if (ainfo->ai_family == AF_INET6)
          {
            pal_mem_set (&ain6, 0, sizeof (ain6));

            ain6.sin6_family = AF_INET6;
            ain6.sin6_port   = pal_hton16 (port);

            ainfo->ai_addr    = (struct pal_sockaddr *) &ain6;
            ainfo->ai_addrlen = sizeof (struct pal_sockaddr_in6);
            addr_set = 1;
          }
        else
          {
            zlog_err (&BLG, "[NETWORK] Server Sock: getaddrinfo() returned"
                      "invalid address"
                      " AF=%d, Sock %d",
                      ainfo->ai_family, bgp_sock);
              
            SSOCK_FD_CLOSE (&BLG, bgp_sock);
              
            ret = 0;
              
            continue;
          }
      }

    ret = pal_sock_bind (bgp_sock, ainfo->ai_addr, ainfo->ai_addrlen);

    if (addr_set)
      ainfo->ai_addr = NULL;

    if (ret < 0)
      {
        zlog_err (&BLG, "[NETWORK] Server Sock: bind() Failed for AF="
                  "%d, Err: %d-%s, port[%d]", ainfo->ai_family, errno,
                  pal_strerror (errno),  port);

        SSOCK_FD_CLOSE (&BLG, bgp_sock);

        ret = 0;

        continue;
      }

#ifdef HAVE_TCP_MD5SIG
    bgp_md5_set_server (bgp, bgp_sock);
#endif /* TCP_MD5SIG */

    ret = pal_sock_listen (bgp_sock, BGP_SOCK_LISTEN_BACKLOG);
    if (ret < 0)
      {
        zlog_err (&BLG, "[NETWORK] Server Sock: listen() Failed for "
                  "AF=%d, Sock %d, FIB-ID %d, Err:%d-%s",
                  ainfo->ai_family, bgp_sock, fib_id, errno,
                  pal_strerror (errno));

        SSOCK_FD_CLOSE (&BLG, bgp_sock);

        ret = 0;

        continue;
      }

    /* Start a fresh Accept Thread */
    t_accept = NULL;
    BGP_READ_ON (&BLG, t_accept, bgp, bpn_sock_accept, bgp_sock);

    /* Add thread to Listen Thread List */
    tmp_lnode = XCALLOC (MTYPE_TMP,
                         sizeof (struct bgp_listen_sock_lnode));
    if (! tmp_lnode)
      {
        zlog_err (&BLG, "[NETWORK] Server Sock:"
                  " Cannot allocate memory (%d) @ %s:%d",
                  sizeof (struct bgp_peer_inconn_req), __FILE__, __LINE__);

        SSOCK_FD_CLOSE (&BLG, bgp_sock);
        BGP_READ_OFF (&BLG, t_accept);

        continue;
      }

    tmp_lnode->listen_sock = bgp_sock;
    tmp_lnode->t_accept = t_accept;
    if (bgp->listen_sock_lnode)
      tmp_lnode->next = bgp->listen_sock_lnode;
    bgp->listen_sock_lnode = tmp_lnode;

  } 

  pal_sock_freeaddrinfo (ainfo_head);

  return ret;
}
#else /* HAVE_IPV6 && !NRL */
s_int32_t
bpn_sock_listen (struct bgp *bgp, u_int16_t port)
{
  struct bgp_listen_sock_lnode *tmp_lnode;
  struct thread *t_accept;
  union sockunion su;
  s_int32_t bgp_sock;
  fib_id_t fib_id;
  s_int32_t ret;

  pal_mem_set (&su, 0, sizeof (union sockunion));

  t_accept = NULL;
  ret = 0;

  if (! bgp)
    {
      zlog_err (&BLG, "[NETWORK] Server Sock: Invalid 'bgp' instance");

      ret = -1;
      goto EXIT;
    }

  fib_id = LIB_VRF_GET_FIB_ID (bgp->owning_ivrf);

  /* Specify address family. */
  su.sa.sa_family = AF_INET;

  bgp_sock = pal_sock (&BLG, su.sa.sa_family, SOCK_STREAM, 0);
  if (bgp_sock < 0)
    {
      zlog_err (&BLG, "[NETWORK] Server Sock: socket() Failed, FIB-ID %d, "
                "Err:%d-%s", fib_id, errno, pal_strerror (errno));

      ret = -1;
      goto EXIT;
    }

  pal_sock_set_reuseaddr (bgp_sock, PAL_TRUE);
  pal_sock_set_reuseport (bgp_sock, PAL_TRUE);

  /* Bind socket to FIB. */
  ret = pal_sock_set_bindtofib (bgp_sock, fib_id);
  if (ret < 0)
    {
      zlog_err (&BLG, "[NETWORK] Server Sock: bindtofib() Failed, Sock %d"
                ", FIB-ID %d, Err:%d-%s", bgp_sock, fib_id, errno,
                pal_strerror (errno));

      SSOCK_FD_CLOSE (&BLG, bgp_sock);

      /* Ignore platform error */
      ret = 0;
      goto EXIT;
    }

  ret = sockunion_bind (&BLG, bgp_sock, &su, port, NULL);
  if (ret < 0)
    {
      zlog_err (&BLG, "[NETWORK] Server Sock: bind() Failed, Err: %d-%s",
                errno, pal_strerror (errno));

      SSOCK_FD_CLOSE (&BLG, bgp_sock);

      /* Ignore platform error */
      ret = 0;
      goto EXIT;
    }

#ifdef HAVE_TCP_MD5SIG
  bgp_md5_set_server (bgp, bgp_sock);
#endif /* TCP_MD5SIG */

  ret = pal_sock_listen (bgp_sock, BGP_SOCK_LISTEN_BACKLOG);
  if (ret < 0)
    {
      zlog_err (&BLG, "[NETWORK] Server Sock: listen() Failed, Sock %d, "
                "FIB-ID %d, Err:%d-%s", bgp_sock, fib_id, errno,
                pal_strerror (errno));

      SSOCK_FD_CLOSE (&BLG, bgp_sock);

      /* Ignore platform error */
      ret = 0;
      goto EXIT;
    }

  /* Start a fresh Accept Thread */
  BGP_READ_ON (&BLG, t_accept, bgp, bpn_sock_accept, bgp_sock);

  /* Add thread to Listen Thread List */
  tmp_lnode = XCALLOC (MTYPE_TMP, sizeof (struct bgp_listen_sock_lnode));
  if (! tmp_lnode)
    {
      zlog_err (&BLG, "[NETWORK] Server Sock:"
                " Cannot allocate memory (%d) @ %s:%d",
                sizeof (struct bgp_peer_inconn_req), __FILE__, __LINE__);

      SSOCK_FD_CLOSE (&BLG, bgp_sock);
      BGP_READ_OFF (&BLG, t_accept);

      ret = -1;
      goto EXIT;
    }

  tmp_lnode->listen_sock = bgp_sock;
  tmp_lnode->t_accept = t_accept;
  if (bgp->listen_sock_lnode)
    tmp_lnode->next = bgp->listen_sock_lnode;
  bgp->listen_sock_lnode = tmp_lnode;

 EXIT:

  return ret;
}
#endif /* defined(HAVE_IPV6) && !defined(NRL) */

s_int32_t
bpn_sock_listen_uninit (struct bgp *bgp)
{
  struct bgp_listen_sock_lnode *tmp_lnode_nxt;
  struct bgp_listen_sock_lnode *tmp_lnode;
  s_int32_t ret;

  ret = 0;

  if (! bgp)
    {
      ret = -1;
      goto EXIT;
    }

  /* Release all Listen Socket Threads */
  for (tmp_lnode = bgp->listen_sock_lnode;
       tmp_lnode; tmp_lnode = tmp_lnode_nxt)
    {
      tmp_lnode_nxt = tmp_lnode->next;

      SSOCK_FD_CLOSE (&BLG, tmp_lnode->listen_sock);
      BGP_READ_OFF (&BLG, tmp_lnode->t_accept);

      XFREE (MTYPE_TMP, tmp_lnode);
    }
  bgp->listen_sock_lnode = NULL;

 EXIT:

  return ret;
}
