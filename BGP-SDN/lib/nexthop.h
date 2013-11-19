/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _NEXTHOP_H
#define _NEXTHOP_H

struct nexthop
{
  struct nexthop *next;
  struct nexthop *prev;

  u_int8_t type;
#define NEXTHOP_TYPE_IFINDEX        1 /* Directly connected. */
#define NEXTHOP_TYPE_IFNAME         2 /* Interface route. */
#define NEXTHOP_TYPE_IPV4           3 /* IPv4 nexthop. */
#define NEXTHOP_TYPE_IPV4_IFINDEX   4 /* IPv4 nexthop with ifindex. */
#define NEXTHOP_TYPE_IPV4_IFNAME    5 /* IPv4 nexthop with ifname. */
#define NEXTHOP_TYPE_IPV6           6 /* IPv6 nexthop. */
#define NEXTHOP_TYPE_IPV6_IFINDEX   7 /* IPv6 nexthop with ifindex. */
#define NEXTHOP_TYPE_IPV6_IFNAME    8 /* IPv6 nexthop with ifname. */

  u_int8_t flags;
#define NEXTHOP_FLAG_ACTIVE               (1 << 0) /* This nexthop is alive. */
#define NEXTHOP_FLAG_FIB                  (1 << 1) /* FIB nexthop. */
#define NEXTHOP_FLAG_RECURSIVE            (1 << 2) /* Recursive nexthop. */
#define NEXTHOP_FLAG_MROUTE               (1 << 3) /* Multicast route nexthop. */
#define NEXTHOP_FLAG_RECURSIVE_BLACKHOLE  (1 << 4) /* Blackhole Recursive nexthop. */

#ifdef HAVE_SNMP
  /* Route type.  */
  u_int8_t snmp_route_type;
#endif /* HAVE_SNMP */
#define ROUTE_TYPE_LOCAL        1
#define ROUTE_TYPE_REMOTE       2
#define ROUTE_TYPE_OTHER        3
#define ROUTE_TYPE_REJECT       4

  /* Recursive lookup nexthop. */
  u_int8_t rtype;
  u_int32_t rifindex;

  /* Interface index. */
  u_int32_t ifindex;

  char *ifname;

  /* Nexthop address or interface name. */
  union
  {
    struct pal_in4_addr ipv4;
#ifdef HAVE_IPV6
    struct pal_in6_addr ipv6;
#endif /* HAVE_IPV6*/
  } gate;

  union
  {
    struct pal_in4_addr ipv4;
#ifdef HAVE_IPV6
    struct pal_in6_addr ipv6;
#endif /* HAVE_IPV6 */
  } rgate;
 /* resolved rrn */
  struct nsm_ptree_node *rrn;
};
struct nexthop_addr
{
  u_char afi;
  union
  {
    u_char key;
    struct pal_in4_addr ipv4;
#ifdef HAVE_IPV6
    struct pal_in6_addr ipv6;
#endif
  } u;
};

#define VALID_MROUTE_NEXTHOP(n)                                 \
  (CHECK_FLAG ((n)->flags, NEXTHOP_FLAG_MROUTE) &&              \
   CHECK_FLAG ((n)->flags, NEXTHOP_FLAG_ACTIVE))

#endif /* _NEXTHOP_H */
