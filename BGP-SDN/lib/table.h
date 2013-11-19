/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_TABLE_H
#define _BGPSDN_TABLE_H

#include "pal.h"
#include "prefix.h"

/* Routing table top structure. */
struct route_table
{
  struct route_node *top;

  /* Table identifier. */
  u_int32_t id;
};

/* Each routing entry. */
struct route_node
{
  /* DO NOT MOVE the first 2 pointers. They are used for memory
     manager as well */
  struct route_node *link[2];
#define l_left   link[0]
#define l_right  link[1]

  /* Actual prefix of this radix. */
  struct prefix p;

  /* Tree link. */
  struct route_table *table;
  struct route_node *parent;

  /* Lock of this radix */
  u_int32_t lock;

  /* Each node of route. */
  void *info;

  /* Aggregation. */
  void *aggregate;
};

/* Prototypes. */
struct route_table *route_table_init (void);
void route_table_finish (struct route_table *);
void route_unlock_node (struct route_node *node);
void route_node_delete (struct route_node *node);
struct route_node *route_top (struct route_table *);
struct route_node *route_next (struct route_node *);
struct route_node *route_next_until (struct route_node *, struct route_node *);
struct route_node *route_node_get (struct route_table *, struct prefix *);
struct route_node *route_node_get_ipv4 (struct route_table *,
                                        struct pal_in4_addr *);
#ifdef HAVE_IPV6
struct route_node *route_node_get_ipv6 (struct route_table *,
                                        struct pal_in6_addr *);
#endif /* HAVE_IPV6 */
struct route_node *route_node_lookup (struct route_table *, struct prefix *);
struct route_node *route_node_lookup_ipv4 (struct route_table *,
                                           struct pal_in4_addr *);
#ifdef HAVE_IPV6
struct route_node *route_node_lookup_ipv6 (struct route_table *,
                                           struct pal_in6_addr *);
#endif /* HAVE_IPV6 */
struct route_node *route_lock_node (struct route_node *node);
struct route_node *route_node_match (struct route_table *, struct prefix *);
struct route_node *route_node_match_exclude (struct route_table *,
                                             struct prefix *,
                                             struct prefix *);
struct route_node *route_node_match_ipv4 (struct route_table *,
                                          struct pal_in4_addr *);
void route_node_free (struct route_node *node);
u_char route_table_has_info (struct route_table *);
void route_table_id_set (struct route_table *, u_int32_t);
#ifdef HAVE_IPV6
struct route_node *route_node_match_ipv6 (struct route_table *,
                                          struct pal_in6_addr *);
#endif /* HAVE_IPV6 */

#endif /* _BGPSDN_TABLE_H */
