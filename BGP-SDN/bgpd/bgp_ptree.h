/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_PTREE_H
#define _BGPSDN_BGP_PTREE_H
#include "prefix.h"

/* Patricia tree top structure. */
struct bgp_ptree
{
  /* Top node. */
  struct bgp_node *top;

  /* AFI family information */
   u_int16_t family;

  /* Maximum key size allowed (in bits). */
  u_int16_t max_key_len;
};

/* Patricia tree node structure. */
struct bgp_node
{
  struct bgp_node *link[2];
#define  p_left      link[0]
#define  p_right     link[1]

  /* Tree link. */
  struct bgp_ptree *tree;
  struct bgp_node *parent;

  /* Lock of this radix. */
  u_int32_t lock;

  /* Each node of route. */
  void *info;
  
  /* bgp specific data */

  /* Adj-RIBs-Out cache.  */
   struct bgp_adj_out *adj_out;

  /* Adj-RIB-In.  */
  struct bgp_adj_in *adj_in;

  /* Key len (in bits). */
  u_int8_t key_len;

  /* Key begins here. */
  u_int8_t key [1];
};

#define BGP_PTREE_KEY_MIN_LEN       1
#define BGP_PTREE_NODE_KEY(n)       (& (n)->key [0])
#define BGP_AFI_LENGTH_IN_BITS		8
#ifdef HAVE_IPV6
#define BGP_MAX_KEY_LEN      128 + BGP_AFI_LENGTH_IN_BITS
#else 
#define BGP_MAX_KEY_LEN      32  + BGP_AFI_LENGTH_IN_BITS 
#endif
#define bpg_table bpg_ptree
#define BGP_IPV4_ADDR_AFI	0
#define BGP_IPV6_ADDR_AFI	1
#define BGP_IPV4_IPV6_ADDR_AFI  2
#define BGP_GET_PREFIX_FROM_NODE(N)    bgp_ptree_get_prefix_from_node (N, &rnp);

/* Prototypes. */
struct bgp_ptree *bgp_ptree_init (u_int16_t max_key_len);
struct bgp_node *bgp_ptree_top (struct bgp_ptree *tree);
struct bgp_node *bgp_ptree_next (struct bgp_node *node);
struct bgp_node *bgp_ptree_next_until (struct bgp_node *node1,
				     struct bgp_node *node2);
struct bgp_node *bgp_ptree_node_get (struct bgp_ptree *tree, u_char *key,
				   u_int16_t key_len);
struct bgp_node *bgp_ptree_node_lookup (struct bgp_ptree *tree, u_char *key,
				      u_int16_t key_len);
struct bgp_node *bgp_ptree_lock_node (struct bgp_node *node);
struct bgp_node *bgp_ptree_node_match (struct bgp_ptree *tree, u_char *key,
				     u_int16_t key_len);
void   bgp_ptree_node_free (struct bgp_node *node);
void   bgp_ptree_finish (struct bgp_ptree *tree);
void   bgp_ptree_unlock_node (struct bgp_node *node);
void   bgp_ptree_node_delete (struct bgp_node *node);
void   bgp_ptree_node_delete_all (struct bgp_ptree *tree);
int    bgp_ptree_has_info (struct bgp_ptree *tree);
void   bgp_ptree_key_copy (struct bgp_node *node, u_char *key, u_int16_t key_len);
int    bgp_ptree_bit_to_octets (u_int16_t key_len);
int    bgp_ptree_key_match (u_char *np, u_int16_t n_len, u_char *pp, u_int16_t p_len);
int    bgp_ptree_check_bit (struct bgp_ptree *tree, u_char *p, u_int16_t key_len);
void   bgp_ptree_get_prefix_from_node(struct bgp_node *node, struct prefix *rnp);

struct bgp_ptree *bgp_table_init (u_int16_t afi);
void   bgp_table_finish (struct bgp_ptree *);
void   bgp_unlock_node (struct bgp_node *node);
void   bgp_node_delete (struct bgp_node *node);
struct bgp_node *bgp_table_top (struct bgp_ptree *);
struct bgp_node *bgp_route_next (struct bgp_node *);
struct bgp_node *bgp_route_next_until (struct bgp_node *, struct bgp_node *);
struct bgp_node *bgp_node_get (struct bgp_ptree *, struct prefix *);
struct bgp_node *bgp_node_lookup (struct bgp_ptree *, struct prefix *);
struct bgp_node *bgp_lock_node (struct bgp_node *node);
struct bgp_node *bgp_node_match (struct bgp_ptree *, struct prefix *);

/* End Prototypes. */
#endif /* _BGPSDN_PTREE_H */

