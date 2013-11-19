/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_MESSAGE_H
#define _BGPSDN_BGP_MESSAGE_H

#define BGP_CHECK_CTYPE(F,C)        (CHECK_FLAG (F, (1 << C)))
#define BGP_SET_CTYPE(F,C)          (SET_FLAG (F, (1 << C)))
#define BGP_UNSET_CTYPE(F,C)        (UNSET_FLAG (F, (1 << C)))

#define BGP_MSG_ROUTE_FLAG_ADD             (1 << 0)

#define BGP_ROUTE_CTYPE_IPV4_NEXTHOP      0

struct bgp_tlv_ipv4_nexthop
{
  u_int32_t ifindex;
  struct pal_in4_addr addr;
};

/* Default nexthop num for communication.  */
#define BGP_TLV_IPV4_NEXTHOP_NUM      64

/* IPv4 route.  */
struct bgp_msg_route_ipv4
{
  /* Ctype index.  */
  cindex_t cindex;

  /* Flags.  */
  u_int16_t flags;

  /* Route type.  */
  u_char type;

  /* Distance.  */
  u_char distance;

  /* Sub type.  */
  u_char sub_type;

  /* Metric.  */
  u_int32_t metric;

  u_char prefixlen;
  struct pal_in4_addr prefix;

  /* Next hop information.  */
  u_char nexthop_num;
  struct bgp_tlv_ipv4_nexthop nexthop[BGP_TLV_IPV4_NEXTHOP_NUM];
  struct bgp_tlv_ipv4_nexthop *nexthop_opt;

  /* Tag.  */
  u_int32_t tag;

  /* Process id.  */
  u_int32_t pid;
};

#ifdef HAVE_IPV6
#define BGP_TLV_IPV6_NEXTHOP_NUM       4

struct bgp_tlv_ipv6_nexthop
{
  u_int32_t ifindex;
  struct pal_in6_addr addr;
};

/* IPv6 route.  */
struct bgp_msg_route_ipv6
{
  /* Ctype index.  */
  cindex_t cindex;

  /* Flags.  */
  u_int16_t flags;

  /* Route type.  */
  u_char type;

  /* Distance.  */
  u_char distance;

  /* Sub type.  */
  u_char sub_type;

  /* Metric.  */
  u_int32_t metric;

  u_char prefixlen;
  struct pal_in6_addr prefix;

  /* Next hop information.  */
  u_char nexthop_num;
  struct bgp_tlv_ipv6_nexthop nexthop[BGP_TLV_IPV6_NEXTHOP_NUM];
  struct bgp_tlv_ipv6_nexthop *nexthop_opt;

  /* Tag.  */
  u_int32_t tag;

  /* Process id.  */
  u_int32_t pid;
};
#endif /* HAVE_IPV6 */
#endif /* _BGPSDN_BGP_MESSAGE_H */
