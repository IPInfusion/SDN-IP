/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _PAL_SOCKET_H
#define _PAL_SOCKET_H

#define IFF_TDM         0x00100000
/* pal_socket.h -- BGP-SDN PAL socket and associated operations
   definitions.  */

struct lib_globals;

/*
  Constants and enumerations
*/

/*
  Maximum size of a hardware address (MAC address or equivalent)
*/
#define IFHWASIZ 20

/*
  This is used to indicate the socket handle is not valid.  If this is the
  value of a returned pal_sock_handle_t, there was an error.  It must be a
  type which is compatible with the pal_sock_handle_t definition below.
*/
#define PAL_SOCK_ERROR ((pal_sock_handle_t)-1)

/* The socket handle type. */
typedef int pal_sock_handle_t;

/*
  This is the type used to specify socket flags.  It must be compatible with
  the flags specified above (and it must also be an integer class so the flags
  given above can be ORed together when appropriate).
*/
typedef unsigned short int pal_sock_flags_t;

/*
  Length of things in socket structures.
*/
typedef socklen_t pal_sock_len_t;

/*
 * Socket Options.
 */

/*
 * Max socket receive and send buffer sizes.  The PAL must support
 * increasing the socket buffer sizes up to these values.
 *
 * XXX this value has been found sufficient for 256 Routed VLAN
 * interfaces, each of which has 7 global and 1 link-local addresses.
 */
#ifndef SOCKET_MAXRCVBUF
#define SOCKET_MAXRCVBUF (20 * 1024 * 1024)
#endif

#ifndef SOCKET_MAXSNDBUF
#define SOCKET_MAXSNDBUF (20 * 1024 * 1024)
#endif


/*
  IPNET specific defines.
*/
#ifndef HAVE_IPNET
/*
** The following constants should be used for the second parameter of `shutdown'
*/
#define PAL_SHUT_RD     SHUT_RD /* No more receptions.  */
#define PAL_SHUT_WR     SHUT_WR /* No more transmissions.  */
#define PAL_SHUT_RDWR   SHUT_RDWR /* No more receptions or transmissions.  */

/*
  Interface flags.  Any nonsupported ones must be set to zero.
*/
#define IFF_OACTIVE     0x00000000
#define IFF_SIMPLEX     0x00000000
#define IFF_LINK0       0x00000000
#define IFF_LINK1       0x00000000
#define IFF_LINK2       0x00000000

/*
  The socket address structure and its parts.
*/
#define pal_sockaddr sockaddr

/*
  The socket address structure for IPv4
*/
#define pal_sockaddr_in4 sockaddr_in

/*
  The socket address structure for IPv6
*/
#ifdef HAVE_IPV6
#define pal_sockaddr_in6 sockaddr_in6
#define pal_ipv6_mreq ipv6_mreq
#endif /* HAVE_IPV6 */

/*
  IP definitions
*/
#define PAL_IPPROTO_IP                  IPPROTO_IP
#define PAL_IPPROTO_RAW                 IPPROTO_RAW
#define PAL_IPPROTO_IPIP                IPPROTO_IPIP
#define PAL_IPPROTO_GRE                 IPPROTO_GRE

#ifdef HAVE_IPV6
#define PAL_IPPROTO_IPV6                IPPROTO_IPV6
#endif /* HAVE_IPV6 */

#define PAL_IP_DROP_MEMBERSHIP          IP_DROP_MEMBERSHIP
#define PAL_IP_ADD_MEMBERSHIP           IP_ADD_MEMBERSHIP
#define PAL_IP_TOS                      IP_TOS
#define PAL_IP_RECVIF                   IP_RECVIF
#define PAL_IP_PKTINFO                  IP_PKTINFO
#define PAL_IP_HDRINCL                  IP_HDRINCL
#define PAL_IP_TTL                      IP_TTL
#define PAL_IP_MULTICAST_LOOP           IP_MULTICAST_LOOP
#define PAL_IP_MULTICAST_IF             IP_MULTICAST_IF
#define PAL_IP_MULTICAST_TTL            IP_MULTICAST_TTL
#define PAL_IP_RECVDSTADDR              IP_RECVDSTADDR
#define PAL_IP_ROUTER_ALERT             IP_ROUTER_ALERT

#define PAL_MRT_INIT                    MRT_INIT
#define PAL_MRT_DONE                    MRT_DONE
#define PAL_MRT_PIM                     MRT_PIM
#define PAL_MRT_ASSERT                  MRT_ASSERT
#define PAL_MRT_ADD_MFC                 MRT_ADD_MFC
#define PAL_MRT_DEL_MFC                 MRT_DEL_MFC
#define PAL_MRT_ADD_VIF                 MRT_ADD_VIF
#define PAL_MRT_DEL_VIF                 MRT_DEL_VIF

#ifdef HAVE_IPV6
#define PAL_IPV6_CHECKSUM               IPV6_CHECKSUM
#define PAL_IPV6_PKTINFO                IPV6_PKTINFO
#define PAL_IPV6_RECVPKTINFO            IPV6_RECVPKTINFO
#define PAL_IPV6_HOPOPTS                IPV6_HOPOPTS
#define PAL_IPV6_MULTICAST_HOPS         IPV6_MULTICAST_HOPS
#define PAL_IPV6_UNICAST_HOPS           IPV6_UNICAST_HOPS
#define PAL_IPV6_RECVHOPLIMIT           IPV6_RECVHOPLIMIT
#define PAL_IPV6_HOPLIMIT               IPV6_HOPLIMIT
#define PAL_IPV6_NEXTHOP                IPV6_NEXTHOP
#define PAL_IPV6_MULTICAST_LOOP         IPV6_MULTICAST_LOOP
#define PAL_IPV6_MULTICAST_IF           IPV6_MULTICAST_IF
#define PAL_IPV6_ROUTER_ALERT           IPV6_ROUTER_ALERT
#ifdef IPV6_JOIN_GROUP
#define PAL_IPV6_JOIN_GROUP             IPV6_JOIN_GROUP
#else
#define PAL_IPV6_ADD_MEMBERSHIP         IPV6_ADD_MEMBERSHIP
#endif /* ! IPV6_JOIN_GROUP */
#ifdef IPV6_LEAVE_GROUP
#define PAL_IPV6_LEAVE_GROUP            IPV6_LEAVE_GROUP
#else
#define PAL_IPV6_DROP_MEMBERSHIP        IPV6_DROP_MEMBERSHIP
#endif /* ! IPV6_LEAVE_GROUP */

#define PAL_IP_MRT6_INIT                MRT6_INIT 
#define PAL_IP_MRT6_DONE                MRT6_DONE 
#define PAL_IP_MRT6_PIM                 MRT6_PIM 
#define PAL_IP_MRT6_ADD_MFC             MRT6_ADD_MFC 
#define PAL_IP_MRT6_DEL_MFC             MRT6_DEL_MFC 
#define PAL_IP_MRT6_ADD_MIF             MRT6_ADD_MIF 
#define PAL_IP_MRT6_DEL_MIF             MRT6_DEL_MIF 

#define PAL_IPPROTO_ICMPV6              IPPROTO_ICMPV6

#endif /* HAVE_IPV6 */

/*
  IPv4 Packet information
*/
#define pal_in4_pktinfo in_pktinfo

/*
  IPv6 Packet information
*/

#ifdef HAVE_IPV6
#define pal_in6_pktinfo in6_pktinfo
#endif /* HAVE_IPV6 */
 
#ifdef HAVE_IPV6
/* 
** ICMPv6 filter
*/
#define pal_icmp6_filter        icmp6_filter

/*
  ICMPv6 filter set options
*/
#define PAL_ICMP6_FILTER             ICMP6_FILTER
#define PAL_ICMP6_FILTER_SETBLOCKALL ICMP6_FILTER_SETBLOCKALL
#define PAL_ICMP6_FILTER_SETPASS     ICMP6_FILTER_SETPASS

#endif /* HAVE_IPV6 */

/*
  The socket address for <dl>?
*/
#define pal_sockaddr_dl sockaddr_dl

/*
  The socket address structure for a UNIX socket
*/
#define pal_sockaddr_un sockaddr_un

/*
  The link-layer socket structure
*/
#define pal_sockaddr_ll sockaddr_ll

/*
  IP Multicast request.
*/
#define pal_ip_mreqn ip_mreqn

/*
  Select structures.  This will probably vary somewhat if the system does not
  use integers as socket handles.
  
  Linux : Okay, so it cheats a little and touches stuff within the handle
  from outside the pal_socket module, but it hides the effort.
*/
#define pal_sock_set_t                  fd_set
#define PAL_SOCKSET_SIZE                FD_SETSIZE
#define PAL_SOCK_HANDLESET_ISSET(h,s)   FD_ISSET(h,s)
#define PAL_SOCK_HANDLESET_SET(h,s)     FD_SET(h,s)
#define PAL_SOCK_HANDLESET_CLR(h,s)     FD_CLR(h,s)

/*
  I/O vector for scatter/gather operations
*/
#define pal_iovec iovec

/*
  Message header structure
*/
#define pal_msghdr msghdr
#define PAL_MSG_PEEK                    MSG_PEEK
#define PAL_MSG_DONTROUTE               MSG_DONTROUTE

/* 
   POSIX 1003.1g - ancillary data object information
*/
#define pal_cmsghdr     cmsghdr

/* Addrinfo structure.  */
#define pal_addrinfo addrinfo

/* Servent structure.  */
#define pal_servent servent

/* Hostent structure.  */
#define pal_hostent hostent

#else  /* HAVE_IPNET */

/*
** The following constants should be used for the second parameter of `shutdown'
*/
#define PAL_SHUT_RD     IP_SHUT_RD /* No more receptions.  */
#define PAL_SHUT_WR     IP_SHUT_WR /* No more transmissions.  */
#define PAL_SHUT_RDWR   IP_SHUT_RDWR /* No more receptions or transmissions.  */

/*
  Interface flags.  Any nonsupported ones must be set to zero.
*/
#define IFF_OACTIVE     0x00000000
#define IFF_SIMPLEX     0x00000000
#define IFF_LINK0       0x00000000
#define IFF_LINK1       0x00000000
#define IFF_LINK2       0x00000000

/*
  The socket address structure and its parts.
*/
#define pal_sockaddr Ip_sockaddr

/*
  The socket address structure for IPv4
*/
#define pal_sockaddr_in4 Ip_sockaddr_in

/*
  The socket address structure for IPv6
*/
#ifdef HAVE_IPV6
#define pal_sockaddr_in6 Ip_sockaddr_in6
#define pal_ipv6_mreq        Ip_ipv6_mreq
#endif /* HAVE_IPV6 */

/*
  IP definitions
*/
#define PAL_IPPROTO_IP                  IP_IPPROTO_IP
#define PAL_IPPROTO_RAW                 IP_IPPROTO_RAW
#define PAL_IPPROTO_IPIP                IP_IPPROTO_IPIP
#define PAL_IPPROTO_GRE                 IP_IPPROTO_GRE
#ifdef HAVE_IPV6
#define PAL_IPPROTO_IPV6                IP_IPPROTO_IPV6
#endif /* HAVE_IPV6 */

#define PAL_IP_DROP_MEMBERSHIP          IP_IP_DROP_MEMBERSHIP
#define PAL_IP_ADD_MEMBERSHIP           IP_IP_ADD_MEMBERSHIP
#define PAL_IP_TOS                      IP_IP_TOS
#define PAL_IP_RECVIF                   IP_IP_RECVIF
#define PAL_IP_PKTINFO                  IP_IP_PKTINFO
#define PAL_IP_HDRINCL                  IP_IP_HDRINCL
#define PAL_IP_TTL                      IP_IP_TTL
#define PAL_IP_MULTICAST_LOOP           IP_IP_MULTICAST_LOOP
#define PAL_IP_MULTICAST_IF             IP_IP_MULTICAST_IF
#define PAL_IP_MULTICAST_TTL            IP_IP_MULTICAST_TTL
#define PAL_IP_RECVDSTADDR              IP_IP_RECVDSTADDR
#define PAL_IP_ROUTER_ALERT             IP_IP_ROUTER_ALERT

#define PAL_MRT_INIT                    IP_MRT_INIT
#define PAL_MRT_DONE                    IP_MRT_DONE
#define PAL_MRT_PIM                     IP_MRT_PIM
#define PAL_MRT_ASSERT                  IP_MRT_ASSERT
#define PAL_MRT_ADD_MFC                 IP_MRT_ADD_MFC
#define PAL_MRT_DEL_MFC                 IP_MRT_DEL_MFC
#define PAL_MRT_ADD_VIF                 IP_MRT_ADD_VIF
#define PAL_MRT_DEL_VIF                 IP_MRT_DEL_VIF

#ifdef HAVE_IPV6
#define PAL_IPV6_CHECKSUM               IP_IPV6_CHECKSUM
#define PAL_IPV6_PKTINFO                IP_IPV6_PKTINFO
#define PAL_IPV6_RECVPKTINFO            IP_IPV6_RECVPKTINFO
#define PAL_IPV6_HOPOPTS                IP_IPV6_HOPOPTS
#define PAL_IPV6_MULTICAST_HOPS         IP_IPV6_MULTICAST_HOPS
#define PAL_IPV6_UNICAST_HOPS           IP_IPV6_UNICAST_HOPS
#define PAL_IPV6_RECVHOPLIMIT           IP_IPV6_RECVHOPLIMIT
#define PAL_IPV6_NEXTHOP		IP_IPV6_NEXTHOP
#define PAL_IPV6_HOPLIMIT               IP_IPV6_HOPLIMIT
#define PAL_IPV6_MULTICAST_LOOP         IP_IPV6_MULTICAST_LOOP
#define PAL_IPV6_MULTICAST_IF           IP_IPV6_MULTICAST_IF
#define PAL_IPV6_ROUTER_ALERT           IP_IP6OPT_ROUTER_ALERT
#ifdef IPV6_JOIN_GROUP
#define PAL_IPV6_JOIN_GROUP             IP_IPV6_JOIN_GROUP
#else
#define PAL_IPV6_ADD_MEMBERSHIP         IP_IPV6_ADD_MEMBERSHIP
#endif /* ! IPV6_JOIN_GROUP */
#ifdef IPV6_LEAVE_GROUP
#define PAL_IPV6_LEAVE_GROUP            IP_IPV6_LEAVE_GROUP
#else
#define PAL_IPV6_DROP_MEMBERSHIP        IP_IPV6_DROP_MEMBERSHIP
#endif /* ! IPV6_LEAVE_GROUP */

#define PAL_IP_MRT6_INIT                IP_MRT6_INIT
#define PAL_IP_MRT6_DONE                IP_MRT6_DONE
#define PAL_IP_MRT6_PIM                 IP_MRT6_PIM
#define PAL_IP_MRT6_ADD_MFC             IP_MRT6_ADD_MFC
#define PAL_IP_MRT6_DEL_MFC             IP_MRT6_DEL_MFC
#define PAL_IP_MRT6_ADD_MIF             IP_MRT6_ADD_MIF
#define PAL_IP_MRT6_DEL_MIF             IP_MRT6_DEL_MIF

#define PAL_IPPROTO_ICMPV6              IP_IPPROTO_ICMPV6

#endif /* HAVE_IPV6 */

/*
  IPv4 Packet information
*/
#define pal_in4_pktinfo in_pktinfo

/*
  IPv6 Packet information
*/
#ifdef HAVE_IPV6
#define pal_in6_pktinfo Ip_in6_pktinfo
#endif /* HAVE_IPV6 */

#ifdef HAVE_IPV6
/* 
** ICMPv6 filter
*/
#define pal_icmp6_filter        Ip_icmp6_filter

/*
  ICMPv6 filter set options
*/
#define PAL_ICMP6_FILTER             IP_ICMP6_FILTER
#define PAL_ICMP6_FILTER_SETBLOCKALL(filterp)           \
  memset ((filterp), 0xFF, sizeof(struct Ip_icmp6_filter))
#define PAL_ICMP6_FILTER_SETPASS     IP_ICMP6_FILTER_SETPASS

#endif /* HAVE_IPV6 */

/*
  The socket address for <dl>?
*/
#define pal_sockaddr_dl sockaddr_dl

/*
  The socket address structure for a UNIX socket
*/
#define pal_sockaddr_un sockaddr_un

/*
  The link-layer socket structure
*/
#define pal_sockaddr_ll sockaddr_ll

/*
  IP Multicast request.
*/
#define pal_ip_mreqn Ip_ip_mreqn

/*
  Select structures.  This will probably vary somewhat if the system does not
  use integers as socket handles.
  
  Linux : Okay, so it cheats a little and touches stuff within the handle
  from outside the pal_socket module, but it hides the effort.
*/
#define pal_sock_set_t                  Ip_fd_set
#define PAL_SOCKSET_SIZE                IP_FD_SETSIZE
#define PAL_SOCK_HANDLESET_ISSET(h,s)   IP_FD_ISSET(h,s)
#define PAL_SOCK_HANDLESET_SET(h,s)     IP_FD_SET(h,s)
#define PAL_SOCK_HANDLESET_CLR(h,s)     IP_FD_CLR(h,s)

/*
  I/O vector for scatter/gather operations
*/
#define pal_iovec iovec

/*
  Message header structure
*/
#define pal_msghdr msghdr
#define PAL_MSG_PEEK                    IP_MSG_PEEK
#define PAL_MSG_DONTROUTE               IP_MSG_DONTROUTE

/* 
   POSIX 1003.1g - ancillary data object information
*/
#define pal_cmsghdr     cmsghdr

/* Addrinfo structure.  */
#define pal_addrinfo Ip_addrinfo

/* Servent structure.  */
#define pal_servent servent

/* Hostent structure.  */
#define pal_hostent hostent
#endif /* HAVE_IPNET */

#include "pal_socket.def"

/*
  Functions
*/

#undef pal_sock
#define pal_sock(w,x,y,z) socket(x,y,z)

#ifndef HAVE_IPNET
#undef pal_sock_accept
#define pal_sock_accept(w,x,y,z) accept(x,y,z)

#undef pal_sock_bind
#define pal_sock_bind bind

#undef pal_sock_sendto
#define pal_sock_sendto sendto

#undef pal_sock_recvfrom
#define pal_sock_recvfrom recvfrom

#undef pal_sock_connect
#define pal_sock_connect connect

#undef pal_sock_select
#define pal_sock_select select

#undef pal_sock_getaddrinfo
#define pal_sock_getaddrinfo getaddrinfo

#undef pal_sock_freeaddrinfo
#define pal_sock_freeaddrinfo freeaddrinfo

#endif /* ! HAVE_IPNET */

#if 0
#ifdef HAVE_IPNET

#undef pal_sock_getaddrinfo
#define pal_sock_getaddrinfo ipcom_getaddrinfo

#undef pal_sock_freeaddrinfo
#define pal_sock_freeaddrinfo ipcom_freeaddrinfo

#endif /* HAVE_IPNET */
#endif

#undef pal_sock_close
#define pal_sock_close(y,z) close(z)

#undef pal_sock_listen
#define pal_sock_listen listen

#undef pal_sock_read
#define pal_sock_read read

#undef pal_sock_readvec
#define pal_sock_readvec readv

#undef pal_sock_write
#define pal_sock_write write

#undef pal_sock_writevec
#define pal_sock_writevec writev

#undef pal_sock_send
#define pal_sock_send send

#undef pal_sock_sendmsg
#define pal_sock_sendmsg sendmsg

#undef pal_sock_recv
#define pal_sock_recv recv

#undef pal_sock_recvmsg
#define pal_sock_recvmsg recvmsg

#undef pal_sock_shutdown
#define pal_sock_shutdown shutdown

#ifndef HAVE_IPNET
#undef pal_sock_getname
#define pal_sock_getname getsockname
#endif /* ! HAVE_IPNET */

#ifndef HAVE_IPNET
#undef pal_sock_getpeer
#define pal_sock_getpeer getpeername
#endif /* ! HAVE_IPNET */

#undef pal_getservbyname
#define pal_getservbyname getservbyname

#undef pal_getservbyport
#define pal_getservbyport getservbyport

#undef pal_gethostbyname
#define pal_gethostbyname gethostbyname

#undef pal_freehostbyname
#define pal_freehostbyname(x)

#undef pal_fcntl
#define pal_fcntl fcntl

#undef pal_ntoh32
#undef pal_hton32
#undef pal_ntoh16
#undef pal_hton16
#define pal_ntoh32 ntohl
#define pal_hton32 htonl
#define pal_ntoh16 ntohs
#define pal_hton16 htons

#ifdef HAVE_PBR_FIB

int
pal_nat_port_forward_rule_del (u_int8_t * ifname,
                              u_int32_t ifindex,
                              unsigned int ip_ver,
                              unsigned int proto,
                              unsigned int src_port,
                              unsigned int dst_port);

int
pal_nat_port_forward_rule_add (u_int8_t * ifname,
                              u_int32_t ifindex,
                              unsigned int ip_ver,
                              unsigned int proto,
                              unsigned int src_port,
                              unsigned int dst_port);
int 
pal_nat_port_forward_rules_remove (unsigned int port);

#define PAL_PFW_RULE_REMOVE_OK              0
#define PAL_PFW_FAIL_TO_CREATE_SOCK        -1
#define PAL_PFW_FAIL_TO_GET_INFO           -2
#define PAL_PFW_ARG_SIZE_MISMATCH          -3
#define PAL_PFW_FAIL_TO_ALLOC_MEM          -4
#define PAL_PFW_FAIL_TO_GET_ENTRIES        -5

#endif

#endif /* _PAL_SOCKET_H */
