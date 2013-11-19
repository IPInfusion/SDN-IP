/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_ROUTE_H
#define _BGPSDN_BGP_ROUTE_H

/* BGP "network" configuration */
struct bgp_static
{
  /* Backdoor configuration */
  bool_t bs_backdoor;

  /* BGP network redistribute route-map */
  struct bgp_rmap bs_rmap;
};

struct bgp_aggregate
{
  /* Summary-only flag. */
  u_int8_t summary_only;

  /* AS set generation. */
  u_int8_t as_set;

 /* origin of the aggargate route */
  u_int8_t origin;

  /* Suppress-count. */
  u_int32_t count;

  /* suppressed route med */
  u_int32_t med;

  /* suppressed routes nexthop */
  struct pal_in4_addr nexthop;

#ifdef HAVE_IPV6
  struct pal_in6_addr nexthop_global;
#endif /* HAVE_IPV6 */

  /* back pointer to aggregated node */
  struct bgp_node * rnagg;
};

struct bgp_distance
{
  /* Distance value for the IP source prefix. */
  u_int8_t distance;

  /* Name of the access-list to be matched. */
  u_int8_t *access_list;
};

#define DISTRIBUTE_IN_NAME(F)   ((F)->dlist[FILTER_IN].name)
#define DISTRIBUTE_IN(F)        ((F)->dlist[FILTER_IN].alist)
#define DISTRIBUTE_OUT_NAME(F)  ((F)->dlist[FILTER_OUT].name)
#define DISTRIBUTE_OUT(F)       ((F)->dlist[FILTER_OUT].alist)

#define PREFIX_LIST_IN_NAME(F)  ((F)->plist[FILTER_IN].name)
#define PREFIX_LIST_IN(F)       ((F)->plist[FILTER_IN].plist)
#define PREFIX_LIST_OUT_NAME(F) ((F)->plist[FILTER_OUT].name)
#define PREFIX_LIST_OUT(F)      ((F)->plist[FILTER_OUT].plist)

#define FILTER_LIST_IN_NAME(F)  ((F)->aslist[FILTER_IN].name)
#define FILTER_LIST_IN(F)       ((F)->aslist[FILTER_IN].aslist)
#define FILTER_LIST_OUT_NAME(F) ((F)->aslist[FILTER_OUT].name)
#define FILTER_LIST_OUT(F)      ((F)->aslist[FILTER_OUT].aslist)

#define ROUTE_MAP_IN_NAME(F)    ((F)->map[FILTER_IN].name)
#define ROUTE_MAP_IN(F)         ((F)->map[FILTER_IN].map)
#define ROUTE_MAP_OUT_NAME(F)   ((F)->map[FILTER_OUT].name)
#define ROUTE_MAP_OUT(F)        ((F)->map[FILTER_OUT].map)

#define UNSUPPRESS_MAP_NAME(F)  ((F)->usmap.name)
#define UNSUPPRESS_MAP(F)       ((F)->usmap.map)



/*
 * Function Prototype declarations
 */

struct bgp_node *
bgp_afi_node_get (struct bgp *, afi_t, safi_t,
                  struct prefix *, struct bgp_rd_node *);
struct bgp_info *
bgp_info_new ();
void
bgp_info_free (struct bgp_info *);
void
bgp_info_add (struct bgp_node *, struct bgp_info *);
void
bgp_info_delete (struct bgp_node *, struct bgp_info *);
u_int32_t
bgp_info_sort (struct bgp_node *, struct bgp_info_sort *);
u_int32_t
bgp_med_value (struct attr *, struct bgp *);
s_int32_t
bgp_info_cmp (struct bgp *, struct bgp_info *, struct bgp_info *);
enum filter_type
bgp_input_filter (struct bgp_peer *, struct prefix *,
                  struct attr *, afi_t, safi_t);
enum filter_type
bgp_output_filter (struct bgp_peer *, struct prefix *,
                   struct attr *, afi_t, safi_t);
bool_t
bgp_community_filter (struct bgp_peer *, struct attr *);
bool_t
bgp_cluster_filter (struct bgp_peer *, struct attr *);
s_int32_t
bgp_input_modifier (struct bgp_peer *, struct prefix *,
                    struct attr *, afi_t, safi_t);
s_int32_t
bgp_announce_check (struct bgp_info *, struct bgp_peer *,
                    struct prefix *, struct attr *,
                    afi_t, safi_t);

void
bgp_process (struct bgp *, struct bgp_node *,
             afi_t, safi_t, struct bgp_info *);

bool_t
bgp_peer_max_prefix_overflow (struct bgp_peer *,
                              afi_t, safi_t);

void
bgp_rib_withdraw (struct bgp_peer *, struct bgp_node *,
                  struct bgp_info *, afi_t, safi_t);

s_int32_t
bgp_update (struct bgp_peer *,
            struct prefix *,
            struct attr *,
            afi_t, safi_t,
            u_int32_t, u_int32_t,
            struct bgp_rd_node *,
	    u_int32_t);

s_int32_t
bgp_withdraw (struct bgp_peer *,
              struct prefix *,
              afi_t, safi_t,
              u_int32_t, u_int32_t,
              struct bgp_rd_node *,
              struct bgp_rd_node *);

s_int32_t
bgp_peer_default_originate (struct bgp_peer *,
                            afi_t, safi_t, bool_t);

void
bgp_peer_process_nlri (struct bgp_peer *,
                       struct attr *,
                       struct bgp_nlri *);

void
bgp_soft_reconfig_in (struct bgp_peer *, afi_t, safi_t);

void
bgp_peer_initial_announce (struct bgp_peer *);

void
bgp_announce_table (struct bgp_peer *,
                    afi_t, safi_t,
                    struct bgp_rd_node *);

void
bgp_announce_route (struct bgp_peer *, afi_t, safi_t);

void
bgp_clear_route_table (struct bgp_peer *,
                       afi_t, safi_t, struct bgp_ptree *);

void
bgp_clear_all_routes (struct bgp_peer *peer, afi_t afi, safi_t safi,
                      struct list * list);

void
bgp_clear_route (struct bgp_peer *, afi_t, safi_t);

void
bgp_peer_clear_route_all (struct bgp_peer *);

s_int32_t
bgp_static_network_update (struct bgp *,
                           struct prefix *,
                           struct bgp_static *,
                           afi_t, safi_t,
                           bool_t);

s_int32_t
bgp_static_network_set (struct bgp *, u_int8_t *,
                        afi_t, safi_t,
                        u_int32_t, u_int8_t *);

s_int32_t
bgp_static_network_unset (struct bgp *, u_int8_t *,
                          afi_t, safi_t);

void
bgp_reflected_routes_update (struct bgp *);

void
bgp_static_network_backdoor_process (struct bgp *,
                                     struct prefix *,
                                     struct bgp_node *,
                                     bool_t,
                                     afi_t, safi_t);

bool_t
bgp_aggregate_attr_same (struct attr *attr1,
                         struct attr *attr2);

s_int32_t
bgp_aggregate_del_route (struct bgp *bgp, struct prefix *aggr_p,
                         struct bgp_info *del_ri,
                         struct bgp_aggregate *aggregate,
                         afi_t afi, safi_t safi);

s_int32_t
bgp_aggregate_new_route (struct bgp *bgp, struct prefix *aggr_p,
                         struct prefix *p, struct bgp_info *rinew,
                         struct bgp_aggregate *aggregate,
                         afi_t afi, safi_t safi, bool_t new_aggregator);

s_int32_t
bgp_aggregate_process_new_aggregator (struct bgp *bgp, struct prefix *p,
                                      struct bgp_aggregate *aggregate,
                                      afi_t afi, safi_t safi);

s_int32_t
bgp_aggregate_remove_aggregator (struct bgp *bgp, struct prefix *aggr_p,
                                 struct bgp_aggregate *aggregate,
                                  afi_t afi, safi_t safi);

s_int32_t
bgp_aggregate_new_route (struct bgp *bgp, struct prefix *aggr_p,
                         struct prefix *p, struct bgp_info *rinew,
                         struct bgp_aggregate *aggregate,
                         afi_t afi, safi_t safi, bool_t new_aggregator);

s_int32_t
bgp_aggregate_process_new_aggregator (struct bgp *bgp, struct prefix *p,
                                      struct bgp_aggregate *aggregate,
                                      afi_t afi, safi_t safi);

s_int32_t
bgp_aggregate_remove_aggregator (struct bgp *bgp, struct prefix *aggr_p,
                                 struct bgp_aggregate *aggregate,
                                  afi_t afi, safi_t safi);

void
bgp_aggregate_increment (struct bgp *,
                         struct prefix *,
                         struct bgp_info *,
                         afi_t, safi_t);

void
bgp_aggregate_decrement (struct bgp *,
                         struct prefix *,
                         struct bgp_info *,
                         afi_t, safi_t);

s_int32_t
bgp_aggregate_set (struct bgp *, u_int8_t *,
                   afi_t, safi_t, u_int32_t);

s_int32_t
bgp_aggregate_unset (struct bgp *, u_int8_t *,
                     afi_t, safi_t);

s_int32_t
bgp_redistribute_add (struct bgp *, void* msg, 
                      u_int8_t, bool_t);

s_int32_t
bgp_redistribute_delete (struct bgp *,
                         struct prefix *,
                         u_int32_t, bool_t);

void
bgp_redistribute_withdraw (struct bgp *, afi_t, u_int32_t);

struct bgp_distance *bgp_distance_new (void);

void bgp_distance_free (struct bgp_distance *);

s_int32_t bgp_distance_reset (struct bgp *);

s_int32_t
bgp_distance_apply (struct bgp_peer *,
                    struct prefix *,
                    struct attr *,
                    afi_t, safi_t);

void
bgp_route_cli_init (struct cli_tree *);

u_int8_t
bgp_mpath_to_install(struct bgp_node *rnode, struct bgp *bgp,
		     struct bgp_info *selected,
		     u_int8_t installed_ibgp,
                     u_int8_t installed_ebgp);

u_int8_t
bgp_match_attr_bestpath(struct bgp *bgp, struct bgp_info *bestpath, struct bgp_info *ri);

#ifdef HAVE_SDN
void bgp_post_routerid (struct bgp *bgp);
void bgp_delete_routerid (struct bgp *bgp);
#endif

#endif /* _BGPSDN_BGP_ROUTE_H */
