/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

/*
  pal_sock_ll.c -- BGP-SDN PAL Link Layer socket and associated operations
  definitions for Linux
*/

#include "pal.h"

#include "pal_socket.h"
#include "pal_sock_ll.h"

#include <linux/if_ether.h>
#include <netpacket/packet.h>

#define ETH_P_8021Q_CTAG 0x8100

int
pal_sock_ll_def (char *device, u_int32_t ifindex)
{
  return -1;
}

int
pal_sock_ll_ethernet (char *device, u_int32_t ifindex)
{
  struct sockaddr_ll addr;
  int sock;
  int ret = -1;

  sock = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_802_2));
  if (sock < 0)
    return ret;

  memset (&addr, 0, sizeof (struct pal_sockaddr_ll));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons (ETH_P_802_2);
  addr.sll_ifindex = ifindex;

  ret = bind (sock, (struct sockaddr *)&addr, sizeof (struct pal_sockaddr_ll));
  if (ret < 0)
    return ret;

  return sock;
}

int
pal_sock_ll_cisco_hdlc (char *device, u_int32_t ifindex)
{
  struct sockaddr_ll addr;
  int sock;
  int ret = -1;

  sock = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (sock < 0)
    return ret;

  memset (&addr, 0, sizeof (struct pal_sockaddr_ll));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons (ETH_P_ALL);
  addr.sll_ifindex = ifindex;

  ret = bind (sock, (struct sockaddr *)&addr, sizeof (struct pal_sockaddr_ll));
  if (ret < 0)
    return ret;

  return sock;
}

int
pal_sock_ll_vlan (char *device, u_int32_t ifindex)
{
  struct sockaddr_ll addr;
  int sock;
  int ret = -1;

  sock = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_802_2));
  if (sock < 0)
    return ret;

  memset (&addr, 0, sizeof (struct pal_sockaddr_ll));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons (ETH_P_8021Q_CTAG);
  addr.sll_ifindex = ifindex;

  ret = bind (sock, (struct sockaddr *)&addr, sizeof (struct pal_sockaddr_ll));
  if (ret < 0)
    return ret;

  return sock;
}

int
pal_sock_ll_def_close (int sock)
{
  return close (sock);
}

int
pal_sock_ll_def_promisc_enable (int fd, u_int32_t ifindex)
{
  return 1;
}

int
pal_sock_ll_def_promisc_disable (int fd, u_int32_t ifindex)
{
  return 1;
}

int
pal_sock_ll_def_phyaddr_get (int fd, u_int32_t ifindex, char *addr)
{
  return 1;
}

int
pal_sock_ll_def_phyaddr_set (int fd, u_int32_t ifindex,
                             char *addr, int length)
{
  return 1;
}

int
pal_sock_ll_def_recvmsg (int fd, u_int32_t ifindex,
                         u_char *hbuf, size_t hlen,
                         u_char *bbuf, size_t blen)
{
  struct iovec iov[2];
  struct msghdr msg;
  int ret;

  iov[0].iov_base = (u_char *)hbuf;
  iov[0].iov_len = hlen;
  iov[1].iov_base = (u_char *)bbuf;
  iov[1].iov_len = blen;

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  ret = recvmsg (fd, (struct msghdr *) &msg,0);

  return ret - hlen;
}

int
pal_sock_ll_def_sendmsg (int fd, u_int32_t ifindex,
                         u_char *hbuf, size_t hlen,
                         u_char *bbuf, size_t blen)
{
  struct iovec iov[2];
  struct msghdr msg;
  struct sockaddr_ll to;
  int ret;

  memset (&to, 0, sizeof(struct pal_sockaddr_ll));
  to.sll_family = AF_PACKET;
  to.sll_ifindex = ifindex; 

  iov[0].iov_base = (u_char *) hbuf;
  iov[0].iov_len = hlen;
  iov[1].iov_base = (u_char *) bbuf;
  iov[1].iov_len = blen;

  msg.msg_name = (void *)&to;
  msg.msg_namelen = sizeof (struct pal_sockaddr_ll);
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  ret = sendmsg (fd, (struct msghdr *) &msg, 0);

  return ret;
}

/* PAL socket link-layer callback functions. */
struct pal_sock_ll_callback_t PAL_SOCK_LL_CALLBACK[PAL_SOCK_LL_MAX] =
{
  /* PAL_SOCK_LL_UNSPEC. */
  {
    0,
    pal_sock_ll_def,
    pal_sock_ll_def_close,
    pal_sock_ll_def_promisc_enable,
    pal_sock_ll_def_promisc_disable,
    pal_sock_ll_def_phyaddr_get,
    pal_sock_ll_def_phyaddr_set,
    pal_sock_ll_def_recvmsg,
    pal_sock_ll_def_sendmsg,
  },
  /* PAL_SOCK_LL_ETHERNET. */
  {
    PAL_SOCK_LL_ETHERNET_HEADER_LEN + PAL_SOCK_LL_LLC_LEN,
    pal_sock_ll_ethernet,
    pal_sock_ll_def_close,
    pal_sock_ll_def_promisc_enable,
    pal_sock_ll_def_promisc_disable,
    pal_sock_ll_def_phyaddr_get,
    pal_sock_ll_def_phyaddr_set,
    pal_sock_ll_def_recvmsg,
    pal_sock_ll_def_sendmsg,
  },
  /* PAL_SOCK_LL_CISCO_HDLC. */
  {
    PAL_SOCK_LL_CISCO_HDLC_HEADER_LEN + 1,
    pal_sock_ll_cisco_hdlc,
    pal_sock_ll_def_close,
    pal_sock_ll_def_promisc_enable,
    pal_sock_ll_def_promisc_disable,
    pal_sock_ll_def_phyaddr_get,
    pal_sock_ll_def_phyaddr_set,
    pal_sock_ll_def_recvmsg,
    pal_sock_ll_def_sendmsg,
  },
  /* PAL_SOCK_LL_VLAN */
  {
    PAL_SOCK_LL_VLAN_HEADER_LEN + PAL_SOCK_LL_LLC_LEN,
    pal_sock_ll_vlan,
    pal_sock_ll_def_close,
    pal_sock_ll_def_promisc_enable,
    pal_sock_ll_def_promisc_disable,
    pal_sock_ll_def_phyaddr_get,
    pal_sock_ll_def_phyaddr_set,
    pal_sock_ll_def_recvmsg,
    pal_sock_ll_def_sendmsg,
  },
};
