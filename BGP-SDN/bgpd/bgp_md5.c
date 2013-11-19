/* Copyright (C) 2003-2011 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/*
 * BGP TCP MD5 Authentication:
 * 'linux/tcp_md5.h' file presence is used to detect
 * platform support TCP MD5
 */

#ifdef HAVE_TCP_MD5SIG

/* Set MD5 key to the socket.  */
int
bgp_md5_set (pal_sock_handle_t sock, struct pal_in4_addr *addr, char *md5_key)
{
  int ret;
  struct tcp_md5sig md5sig;
  struct pal_sockaddr_in4 md5sockaddr;

  memset (&md5sig, 0, sizeof (struct tcp_md5sig));
  memset (&md5sockaddr, 0, sizeof (struct pal_sockaddr_in4));

  md5sockaddr.sin_family = AF_INET;
  memcpy(&md5sockaddr.sin_addr, addr, sizeof (struct pal_in4_addr));
  memcpy (&md5sig.tcpm_addr, &md5sockaddr, sizeof (struct pal_sockaddr_in4));
 
  md5sig.tcpm_keylen = pal_strlen (md5_key);
  memcpy (md5sig.tcpm_key, md5_key, md5sig.tcpm_keylen);
 
  ret = setsockopt (sock, IPPROTO_TCP, TCP_MD5SIG, &md5sig,
                    sizeof (struct tcp_md5sig));
  if (ret < 0)
    zlog_err (&BLG, "[TCP-MD5] : Error from socket call %d errno = %d \n",
              ret, errno);

  return ret;
}

/* Unset MD5 key from the socket.  */
int
bgp_md5_unset (pal_sock_handle_t sock, struct pal_in4_addr *addr,
               char *md5_key)
{
  int ret;
  struct tcp_md5sig md5sig;
  struct pal_sockaddr_in4 md5sockaddr;

  memset (&md5sig, 0, sizeof md5sig);
  memset (&md5sockaddr, 0, sizeof (struct pal_sockaddr_in4));

  md5sockaddr.sin_family = AF_INET;
  memcpy(&md5sockaddr.sin_addr, addr, sizeof (struct pal_in4_addr));
  memcpy (&md5sig.tcpm_addr, &md5sockaddr, sizeof (struct pal_sockaddr_in4));

  ret = setsockopt (sock, IPPROTO_TCP, TCP_MD5SIG, &md5sig, sizeof md5sig);
   if (ret < 0)
    zlog_err (&BLG, "[TCP-MD5] : Error from socket call %d errno = %d \n",
              ret, errno);

  return ret;
}

/* Traverse all of peers then set MD5 key to the socket.  */
int
bgp_md5_set_server (struct bgp *bgp, pal_sock_handle_t sock)
{
  struct listnode *ln;
  struct bgp_peer *peer;

  if (! bgp)
    bgp = bgp_lookup_default ();

  if (! bgp)
    return 0;

  LIST_LOOP (bgp->peer_list, peer, ln)
    {
      if (CHECK_FLAG (peer->config, PEER_CONFIG_PASSWORD))
        if (sockunion_family (&peer->su) == AF_INET)
          bgp_md5_set (sock, &peer->su.sin.sin_addr, peer->password);
    }

  return 0;
}

/* Traverse all of peers then unset MD5 key to the socket.  */
int
bgp_md5_unset_server (struct bgp *bgp, pal_sock_handle_t sock)
{
  struct listnode *ln;
  struct bgp_peer *peer;

  if (! bgp)
    bgp = bgp_lookup_default ();

  if (! bgp)
    return 0;

  LIST_LOOP (bgp->peer_list, peer, ln)
    {
      if (CHECK_FLAG (peer->config, PEER_CONFIG_PASSWORD))
        if (sockunion_family (&peer->su) == AF_INET)
          bgp_md5_unset (sock, &peer->su.sin.sin_addr, peer->password);
    }

  return 0;
}

#endif /* TCP_MD5SIG */
