/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_ATTR_H
#define _BGPSDN_BGP_ATTR_H

/* Simple bit mapping. */
#define BITMAP_NBBY 8

#define SET_BITMAP(MAP, NUM) \
        SET_FLAG (MAP[(NUM) / BITMAP_NBBY], 1 << ((NUM) % BITMAP_NBBY))

#define CHECK_BITMAP(MAP, NUM) \
        CHECK_FLAG (MAP[(NUM) / BITMAP_NBBY], 1 << ((NUM) % BITMAP_NBBY))

/* BGP Attribute type range. */
#define BGP_ATTR_TYPE_RANGE     256
#define BGP_ATTR_BITMAP_SIZE    (BGP_ATTR_TYPE_RANGE / BITMAP_NBBY)

/* BGP Attribute flags. */
#define BGP_ATTR_FLAG_OPTIONAL  0x80    /* Attribute is optional. */
#define BGP_ATTR_FLAG_TRANS     0x40    /* Attribute is transitive. */
#define BGP_ATTR_FLAG_PARTIAL   0x20    /* Attribute is partial. */
#define BGP_ATTR_FLAG_EXTLEN    0x10    /* Extended length flag. */

/* BGP attribute header must be atleast 3 bytes */
#define BGP_ATTR_MIN_SIZE       (3)

/* BGP attribute header Length field size */
#define BGP_ATTR_LEN_SIZE       (1)

/* BGP attribute header Ext-Length field size */
#define BGP_ATTR_EXT_LEN_SIZE   (2)

/* BGP MP Attribute Min Sizes */
#define BGP_ATTR_MP_REACH_MIN_SIZE             (5)
#define BGP_ATTR_MP_UNREACH_MIN_SIZE           (3)

/* BGP attribute structure. */
struct attr
{
  /* Reference count of this attribute. */
  u_int32_t refcnt;

  /* Flag of attribute is set or not. */
  u_int32_t flag;

  /* Partial Flag of optional transitive attribute. */
  u_int8_t partial_flag;
#define BGP_ATTR_AGGREGATOR_PARTIAL  0x80   /* Aggregator attribute is partial. */
#define BGP_ATTR_COMMUNITY_PARTIAL   0x40   /* Community attribute is partial. */
#define BGP_ATTR_ECOMMUNITY_PARTIAL  0x20   /* Extended-Community attribute is partial. */

#define BGP_ATTR_AS4_AGGREGATOR_PARTIAL 0x10 /* AS4 Aggregator attribute is partial. */
  /* Attributes. */
  u_int8_t origin;
  u_int8_t distance;
  u_int8_t mp_nexthop_len;

  struct pal_in4_addr nexthop;
  u_int32_t nsm_metric;
  u_int32_t med;
  u_int32_t local_pref;
#ifndef HAVE_EXT_CAP_ASN
  as_t aggregator_as;
#else
  u_int16_t aggregator_as;
  as_t aggregator_as4;
#endif /* HAVE_EXT_CAP_ASN */
  u_int8_t pad2 [2];
  struct pal_in4_addr aggregator_addr;
  /* u_int32_t dpa; */
  u_int32_t weight;
  struct pal_in4_addr originator_id;
  struct cluster_list *cluster;

#ifdef HAVE_IPV6
  struct pal_in6_addr mp_nexthop_global;
  struct pal_in6_addr mp_nexthop_local;
#endif /* HAVE_IPV6 */
  struct pal_in4_addr mp_nexthop_global_in;

  /* AS Path structure */
#ifndef HAVE_EXT_CAP_ASN
  struct aspath *aspath;
#else
  struct aspath *aspath;
  struct as4path *as4path;
  struct as4path *aspath4B;
#endif /* HAVE_EXT_CAP_ASN */

  /* Community structure */
  struct community *community;

  /* Extended Communities attribute. */
  struct ecommunity *ecommunity;

  /* Unknown transitive attribute. */
  struct transit *transit;

  /* BGP RFD Config Parameter -
   * Used only as a pass-through parameter for 'route_map_apply'
   */
  struct bgp_rfd_cb_cfg_param *rfd_cb_cfg;
};

/* Router Reflector related structure. */
struct cluster_list
{
  u_int32_t refcnt;
  int length;
  struct pal_in4_addr *list;
};

/* Unknown transit attribute. */
struct transit
{
  u_int32_t refcnt;
  int length;
  u_int8_t *val;
};

#define ATTR_FLAG_BIT(X)  (1 << ((X) - 1))

/* Prototypes. */
void bgp_attr_init ();
bool_t bgp_peer_attr_check (struct bgp_peer *, struct attr *, bool_t);
struct attr *bgp_attr_intern (struct attr *attr);
void bgp_attr_unintern (struct attr *);
struct transit * transit_intern (struct transit *);
void transit_unintern (struct transit *);
struct cluster_list *cluster_parse (u_int8_t *, int);
void bgp_attr_flush (struct attr *);
struct hash *bgp_attr_hash ();

struct attr *bgp_attr_default_set (struct attr *attr, u_int8_t);
struct attr *
bgp_attr_aggregate_intern (struct bgp *,
                           u_int8_t,
                           struct aspath *,
                           struct community *,
                           u_int32_t, u_int32_t, bool_t);
#ifdef HAVE_EXT_CAP_ASN
struct attr *
bgp_attr_aggregate_4b_intern (struct bgp *,
                              u_int8_t,
                              struct aspath *,
                              struct as4path *,
                              struct as4path *,
                              struct community *,
                              u_int32_t, u_int32_t, bool_t);
#endif /* HAVE_EXT_CAP_ASN */
void bgp_dump_routes_attr (struct stream *, struct attr *);
u_int32_t attrhash_key_make (void *);
bool_t attrhash_cmp (void *, void *);
void attr_show_all (struct vty *);

/* Cluster list prototypes. */
int cluster_loop_check (struct cluster_list *, struct pal_in4_addr);
void cluster_unintern (struct cluster_list *);

/* Transit attribute prototypes. */
void transit_unintern (struct transit *);

#endif /* _BGPSDN_BGP_ATTR_H */
