/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_API_H
#define _BGPSDN_BGP_API_H

/* BGP API return codes.  */
#define BGP_API_GET_SUCCESS                               0
#define BGP_API_GET_ERROR                                -1
#define BGP_API_GET_ERR_MAX                              -2

#define BGP_API_SET_SUCCESS                               0
#define BGP_API_SET_ERROR                                -1
#define BGP_API_SET_ERR_INVALID_VALUE                    -2
#define BGP_API_SET_ERR_INVALID_FLAG                     -3
#define BGP_API_SET_ERR_INVALID_AS                       -4
#define BGP_API_SET_ERR_INVALID_BGP                      -5
#define BGP_API_SET_ERR_PEER_GROUP_MEMBER                -6
#define BGP_API_SET_ERR_MULTIPLE_INSTANCE_USED           -7
#define BGP_API_SET_ERR_PEER_GROUP_MEMBER_EXISTS         -8
#define BGP_API_SET_ERR_PEER_BELONGS_TO_GROUP            -9
#define BGP_API_SET_ERR_PEER_GROUP_AF_UNCONFIGURED      -10
#define BGP_API_SET_ERR_PEER_GROUP_NO_REMOTE_AS         -11
#define BGP_API_SET_ERR_PEER_GROUP_CANT_CHANGE          -12
#define BGP_API_SET_ERR_PEER_GROUP_MISMATCH             -13
#define BGP_API_SET_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT  -14
#define BGP_API_SET_ERR_MULTIPLE_INSTANCE_NOT_SET       -15
#define BGP_API_SET_ERR_AS_MISMATCH                     -16
#define BGP_API_SET_ERR_PEER_INACTIVE                   -17
#define BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER   -18
#define BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG         -19
#define BGP_API_SET_ERR_PEER_FLAG_CONFLICT              -20
#define BGP_API_SET_ERR_PEER_GROUP_SHUTDOWN             -21
#define BGP_API_SET_ERR_PEER_FILTER_CONFLICT            -22
#define BGP_API_SET_ERR_NOT_INTERNAL_PEER               -23
#define BGP_API_SET_ERR_REMOVE_PRIVATE_AS               -24
#define BGP_API_SET_ERR_AF_UNCONFIGURED                 -25
#define BGP_API_SET_ERR_SOFT_RECONFIG_UNCONFIGURED      -26
#define BGP_API_SET_ERR_INSTANCE_MISMATCH               -29
#define BGP_API_SET_ERR_UNKNOWN_OBJECT                  -30
#define BGP_API_SET_ERR_OBJECT_ALREADY_EXIST            -31
#define BGP_API_SET_ERR_REGEXP_COMPILE_FAIL             -32
#define BGP_API_SET_ERR_MALFORMED_ARG                   -33
#define BGP_API_SET_ERR_RMAP_NOT_EXIST                  -34
#define BGP_API_SET_ERR_RMAP_INDEX_NOT_EXIST            -35
#define BGP_API_SET_ERR_SET_VALUE_NOT_UNIQUE            -36
#define BGP_API_SET_ERR_CONFIG_CANT_CHANGED             -37
#define BGP_API_SET_ERR_OPERATION_CANT_ALLOWED          -38
#define BGP_API_SET_ERR_CLIST_DEFINE_CONFLICT           -39
#define BGP_API_SET_ERR_ROUTE_DISTINGUISHER_UNDEFINED   -40
#define BGP_API_SET_ERR_PEER_GROUP_AF_INVALID           -41
#define BGP_API_SET_ERR_REMOTE_AS_MISMATCH              -42
#define BGP_API_SET_ERR_MULT_INST_DEL_CONFIG            -43
#define BGP_API_SET_ERR_MULT_INST_CONFIGURED            -44
#define BGP_API_SET_ERR_PEER_CONFIG_IN_ANOTHER_INST     -45
#define BGP_API_SET_ERR_INVALID_NETWORK                 -46
#define BGP_API_SET_ERR_UNSUP_VPNVF_CONF                -47
#define BGP_API_SET_ERR_INVALID_AF                      -48
#define BGP_API_SET_ERR_INVALID_MASK                    -49
#define BGP_API_NO_REDIST_RMAP                          -50
#define BGP_API_IP_NOT_IN_SAME_SUBNET                   -51
#define BGP_API_INVALID_INTERFACE_NAME                  -52
#define BGP_API_SET_ERR_ALREADY_EXTASNCAP               -53
#define BGP_API_SET_ERR_NO_EXTASNCAP                    -54 
#define BGP_API_INVALID_EXTASN                          -55
#define BGP_API_SET_ERR_NONMAPPABLE                     -56
#define BGP_API_SET_ERR_INFINITE_HOLD_TIME_VALUE        -57
#define BGP_API_SET_WARN_HOLD_AND_KEEPALIVE_INVALID     -58
#define BGP_API_SET_ERR_INVALID_HOLD_TIME               -59
#define BGP_API_SET_WARN_HOLD_LESS_DEFAULT              -60
#define BGP_API_INVALID_ROUTE_NODE                      -61
#define BGP_API_SET_ERR_AUTO_SUMMARY_ENABLED            -62
#define BGP_API_SET_ERR_AUTO_SUMMARY_DISABLED           -63
#define BGP_API_SET_ERR_INVALID_REMOTEASN               -64 
#define BGP_API_SET_ERR_DEFAULTINS_FOR_SAMEPEER         -65
#define BGP_API_SET_ERR_PEER_MALFORMED_ADDRESS          -70
#define BGP_API_SET_ERR_PEER_SELF_ADDRESS               -71
#define BGP_API_SET_ERR_PEER_UNINITIALIZED              -72
#define BGP_API_SET_ERR_PEER_DUPLICATE                  -73
#define BGP_API_FEATURE_NOT_ENABLED_SET_ERR             -76
#define BGP_API_SET_ERR_ALREADY_SET                     -77
#define BGP_API_SET_ERR_ADJ_OUT_DYNAMIC                 -78
#define BGP_API_SET_ERR_NOT_SET                         -79

#define BGP_API_SET_ERR_MEM_ALLOC_FAIL                  -80
#define BGP_API_SET_ERR_TOO_MANY_PEERS_PER_GROUP        -81
#define BGP_API_SET_ERR_NO_CAP_CMD                      -83
#define BGP_API_SET_ERR_PEER_IBGP                       -86
#define BGP_API_SET_ERR_PEER_NOT_EBGP                   -91
#define BGP_API_SET_ERR_LOCAL_AS_EQUAL_TRUE_AS          -92
#define BGP_API_SET_ERR_LOCAL_AS_EQUAL_PEER_AS          -93
#define BGP_API_SET_ERR_LOCAL_AS_TO_PEER_GROUP_MEMBER   -94
#define BGP_API_SET_ERR_MAX                             -95

/* Status for bgpPeerAdminStatus. */
#define BGP_API_PEERADMIN_STOP                1
#define BGP_API_PEERADMIN_START               2

/* For bgp4PathAttrBest. */
#define BGP_API_PATHATTRBEST_FALSE            1
#define BGP_API_PATHATTRBEST_TRUE             2

/* For bgp4PathAttrAtomicAggregate. */
#define BGP_API_PATHATTR_LESS_SPEC_ROUTE_NOT_SELECTED  1
#define BGP_API_PATHATTR_LESS_SPEC_ROUTE_SELECTED      2

/* Default BGP instance id.  */
#define BGP_PROCESS_ID_ANY                    0

/* Default weight for Routes learned through another BGP peer */
#define BGP_DEFAULT_WEIGHT                    0

/* BGP API clear flag for peer_clear_soft(). */
#define BGP_CLEAR_SOFT_MIN                      1
#define BGP_CLEAR_SOFT_NONE                     1
#define BGP_CLEAR_SOFT_OUT                      2
#define BGP_CLEAR_SOFT_IN                       3
#define BGP_CLEAR_SOFT_BOTH                     4
#define BGP_CLEAR_SOFT_IN_ORF_PREFIX            5
#define BGP_CLEAR_SOFT_MAX                      5

/* BGP API clear flag for Route Flap Dampening */
#define BGP_CLEAR_RFD_MIN                       1
#define BGP_CLEAR_RFD_DAMP                      1
#define BGP_CLEAR_RFD_FLAP_STAT                 2
#define BGP_CLEAR_RFD_MAX                       2

/* BGP API filter direct. */
#define BGP_API_FILTER_DENY                     0
#define BGP_API_FILTER_PERMIT                   1

/* Definition of Ranges. */
/* Scan time. */
#define BGP_SCAN_TIME_MIN                       0
#define BGP_SCAN_TIME_MAX                       60 

#define BGP_API_CHECK_RANGE(V,C)                \
  ((V) >= BGP_ ## C ## _MIN &&                  \
  (V) <= BGP_ ## C ## _MAX)

/* BGP API functions prototypes. */
int bgp_get_version (u_int32_t, int, u_char *);
int bgp_get_local_as (u_int32_t, int, int *);
int bgp_get_identifier (u_int32_t, int, struct pal_in4_addr *);

int bgp_get_peer_identifier (u_int32_t, int, struct pal_in4_addr *,
                             struct pal_in4_addr *);
int bgp_get_peer_state (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_peer_admin_status (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_set_peer_admin_status (u_int32_t, int, struct pal_in4_addr *, s_int32_t );
int bgp_get_peer_negotiated_version (u_int32_t, int, struct pal_in4_addr *,
                                     int *);
int bgp_get_peer_local_addr (u_int32_t, int, struct pal_in4_addr *,
                             struct pal_in4_addr *);
int bgp_get_peer_local_port (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_peer_remote_addr (u_int32_t, int, struct pal_in4_addr *,
                              struct pal_in4_addr *);
int bgp_get_peer_remote_port (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_peer_remote_as (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_peer_in_updates (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_peer_out_updates (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_peer_in_total_messages (u_int32_t, int, struct pal_in4_addr *,
                                    int *);
int bgp_get_peer_out_total_messages (u_int32_t, int, struct pal_in4_addr *,
                                     int *);
int bgp_get_peer_last_error (u_int32_t, int, struct pal_in4_addr *, u_char *);
int bgp_get_peer_fsm_established_transitions (u_int32_t, int,
                                              struct pal_in4_addr *, int *);
int bgp_get_peer_fsm_established_time (u_int32_t, int, struct pal_in4_addr *,
                                       int *);
int bgp_get_peer_connect_retry_interval (u_int32_t, int, struct pal_in4_addr *,
                                         int *);
int bgp_set_peer_connect_retry_interval (u_int32_t, int, struct pal_in4_addr *, 
                                         int );
int bgp_get_peer_hold_time (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_peer_keep_alive (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_peer_hold_time_configured (u_int32_t, int, struct pal_in4_addr *,
                                       int *);
int bgp_set_peer_hold_time_configured (u_int32_t, int, struct pal_in4_addr *,
                                       int );
int bgp_get_peer_keep_alive_configured (u_int32_t, int, struct pal_in4_addr *,
                                        int *);
int bgp_set_peer_keep_alive_configured (u_int32_t, int, struct pal_in4_addr *,
                                        int);
int bgp_get_peer_min_as_origination_interval (u_int32_t, int,
                                              struct pal_in4_addr *, int *);
int bgp_set_peer_min_as_origination_interval (u_int32_t, int,
                                              struct pal_in4_addr *, int );
int bgp_get_peer_min_route_advertisement_interval (u_int32_t, int,
                                                   struct pal_in4_addr *,
                                                   int *);
int bgp_set_peer_min_route_advertisement_interval (u_int32_t, int,
                                                   struct pal_in4_addr *,
                                                   int );
int bgp_get_peer_in_update_elapsed_time (u_int32_t, int,
                                         struct pal_in4_addr *, int *);

/* Next peer fucntions */
int bgp_get_next_peer_identifier (u_int32_t, int, struct pal_in4_addr *,
                                  struct pal_in4_addr *);
int bgp_get_next_peer_state (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_next_peer_admin_status (u_int32_t, int, struct pal_in4_addr *,
                                    int *);
int bgp_set_next_peer_admin_status (u_int32_t, int, struct pal_in4_addr *,
                                    s_int32_t );
int bgp_get_next_peer_negotiated_version (u_int32_t, int, struct pal_in4_addr *,
                                          int *);
int bgp_get_next_peer_local_addr (u_int32_t, int, struct pal_in4_addr *,
                                  struct pal_in4_addr *);
int bgp_get_next_peer_local_port (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_next_peer_remote_addr (u_int32_t, int, struct pal_in4_addr *,
                                   struct pal_in4_addr *);
int bgp_get_next_peer_remote_port (u_int32_t, int, struct pal_in4_addr *,
                                   int *);
int bgp_get_next_peer_remote_as (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_next_peer_in_updates (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_next_peer_out_updates (u_int32_t, int, struct pal_in4_addr *,
                                   int *);
int bgp_get_next_peer_in_total_messages (u_int32_t, int, struct pal_in4_addr *, 
                                         int *);
int bgp_get_next_peer_out_total_messages (u_int32_t, int, struct pal_in4_addr *,
                                          int *);
int bgp_get_next_peer_last_error (u_int32_t, int, struct pal_in4_addr *,
                                  u_char *);
int bgp_get_next_peer_fsm_established_transitions (u_int32_t, int,
                                                   struct pal_in4_addr *,
                                                   int *);
int bgp_get_next_peer_fsm_established_time (u_int32_t, int,
                                            struct pal_in4_addr *, int *);
int bgp_get_next_peer_connect_retry_interval (u_int32_t, int,
                                              struct pal_in4_addr *, int *);
int bgp_set_next_peer_connect_retry_interval (u_int32_t, int,
                                              struct pal_in4_addr *, int );
int bgp_get_next_peer_hold_time (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_next_peer_keep_alive (u_int32_t, int, struct pal_in4_addr *, int *);
int bgp_get_next_peer_hold_time_configured (u_int32_t, int,
                                            struct pal_in4_addr *, int *);
int bgp_set_next_peer_hold_time_configured (u_int32_t, int,
                                            struct pal_in4_addr *, int );
int bgp_get_next_peer_keep_alive_configured (u_int32_t, int,
                                             struct pal_in4_addr *, int *);
int bgp_set_next_peer_keep_alive_configured (u_int32_t, int,
                                             struct pal_in4_addr *, int);
int bgp_get_next_peer_min_as_origination_interval (u_int32_t, int,
                                                   struct pal_in4_addr *,
                                                   int *);
int bgp_set_next_peer_min_as_origination_interval (u_int32_t, int,
                                                   struct pal_in4_addr *, int );
int bgp_get_next_peer_min_route_advertisement_interval (u_int32_t, int,
                                                        struct pal_in4_addr *,
                                                        int *);
int bgp_set_next_peer_min_route_advertisement_interval (u_int32_t, int,
                                                        struct pal_in4_addr *,
                                                        int );
int bgp_get_next_peer_in_update_elapsed_time (u_int32_t, int,
                                              struct pal_in4_addr *, int *);

/* Path Attr functions */
int bgp4_get_path_attr_peer (u_int32_t, int, struct prefix_ipv4 *, 
                             union sockunion *, struct pal_in4_addr *);
int bgp4_get_path_attr_ip_addr_prefix_len (u_int32_t, int, struct prefix_ipv4 *,                                           union sockunion *, int *);
int bgp4_get_path_attr_ip_addr_prefix (u_int32_t, int, struct prefix_ipv4 *, 
                                       union sockunion *, struct pal_in4_addr *);
int bgp4_get_path_attr_origin (u_int32_t, int, struct prefix_ipv4 *, 
                               union sockunion *, int *);
int bgp4_get_path_attr_as_path_segment (u_int32_t, int, struct prefix_ipv4 *, 
                                        union sockunion *, u_char **, size_t *);
int bgp4_get_path_attr_next_hop (u_int32_t, int, struct prefix_ipv4 *, 
                                 union sockunion *, struct pal_in4_addr *);
int bgp4_get_path_attr_multi_exit_disc (u_int32_t, int, struct prefix_ipv4 *, 
                                        union sockunion *, int *);
int bgp4_get_path_attr_local_pref (u_int32_t, int, struct prefix_ipv4 *, 
                                   union sockunion *, int *);
int bgp4_get_path_attr_atomic_aggregate (u_int32_t, int, struct prefix_ipv4 *, 
                                         union sockunion *, int *);
int bgp4_get_path_attr_aggregator_as (u_int32_t, int, struct prefix_ipv4 *, 
                                      union sockunion *, int *);
int bgp4_get_path_attr_aggregator_addr (u_int32_t, int, struct prefix_ipv4 *, 
                                        union sockunion *,
                                        struct pal_in4_addr *);
int bgp4_get_path_attr_calc_local_pref (u_int32_t, int, struct prefix_ipv4 *, 
                                        union sockunion *, int *);
int bgp4_get_path_attr_best (u_int32_t, int, struct prefix_ipv4 *, 
                             union sockunion *, int *);
int bgp4_get_path_attr_unknown (u_int32_t, int, struct prefix_ipv4 *, 
                                union sockunion *, u_char **, size_t *);

/* Path Attr Next functions */
int bgp4_get_next_path_attr_peer (u_int32_t, int, struct prefix_ipv4 *, 
                                  union sockunion *, int, struct pal_in4_addr *);
int bgp4_get_next_path_attr_ip_addr_prefix_len (u_int32_t, int,
                                                struct prefix_ipv4 *, 
                                                union sockunion *, int, int *);
int bgp4_get_next_path_attr_ip_addr_prefix (u_int32_t, int,
                                            struct prefix_ipv4 *, 
                                            union sockunion *, int,
                                            struct pal_in4_addr *);
int bgp4_get_next_path_attr_origin (u_int32_t, int, struct prefix_ipv4 *, 
                                    union sockunion *, int, int *);
int bgp4_get_next_path_attr_as_path_segment (u_int32_t, int,
                                             struct prefix_ipv4 *,
                                             union sockunion *, int, u_char **,
                                             size_t *);
int bgp4_get_next_path_attr_next_hop (u_int32_t, int, struct prefix_ipv4 *,
                                      union sockunion *, int,
                                      struct pal_in4_addr *);
int bgp4_get_next_path_attr_multi_exit_disc (u_int32_t, int,
                                             struct prefix_ipv4 *,
                                             union sockunion *, int, int *);
int bgp4_get_next_path_attr_local_pref (u_int32_t, int, struct prefix_ipv4 *,
                                        union sockunion *, int, int *);
int bgp4_get_next_path_attr_atomic_aggregate (u_int32_t, int,
                                              struct prefix_ipv4 *,
                                              union sockunion *, int, int *);
int bgp4_get_next_path_attr_aggregator_as (u_int32_t, int, struct prefix_ipv4 *,
                                           union sockunion *, int, int *);
int bgp4_get_next_path_attr_aggregator_addr (u_int32_t, int,
                                             struct prefix_ipv4 *, 
                                             union sockunion *, int,
                                             struct pal_in4_addr *);
int bgp4_get_next_path_attr_calc_local_pref (u_int32_t, int,
                                             struct prefix_ipv4 *, 
                                             union sockunion *, int, int *);
int bgp4_get_next_path_attr_best (u_int32_t, int, struct prefix_ipv4 *,
                                  union sockunion *, int, int *);
int bgp4_get_next_path_attr_unknown (u_int32_t, int, struct prefix_ipv4 *, 
                                     union sockunion *, int, u_char **, size_t *);

/* Function Prototypes from bgp_api.c */
struct bgp_peer *
bgp_peer_lookup (u_int32_t, struct pal_in4_addr *);
struct bgp_peer *
bgp_peer_lookup_next (u_int32_t, struct pal_in4_addr *);
struct bgp_info *
bgp_path_attr_lookup_addr_ipv4 (u_int32_t, struct prefix_ipv4 *,
                                union sockunion *);
struct bgp_info *
bgp_path_attr_lookup_addr_ipv4_next (u_int32_t, struct prefix_ipv4 *,
                                     union sockunion *, int);

/* BGP CLI API.  */

s_int32_t
bgp_option_set (u_int32_t);
s_int32_t
bgp_option_unset (u_int32_t);
s_int32_t
bgp_option_check (u_int32_t);

s_int32_t
bgp_get (struct bgp **, as_t *, u_int8_t *);
s_int32_t
bgp_delete (struct bgp *);
s_int32_t
bgp_free (struct bgp *);

int
bgp_router_id_set (struct bgp *, struct pal_in4_addr *);
int
bgp_router_id_unset (struct bgp *);

s_int32_t
bgp_cluster_id_validate (struct pal_in4_addr *addr);

int
bgp_cluster_id_set (struct bgp *, struct pal_in4_addr *);
int
bgp_cluster_id_digit_set (struct bgp *, u_int32_t);
int
bgp_cluster_id_unset (struct bgp *);

int
bgp_confederation_id_set (struct bgp *, as_t);
int
bgp_confederation_id_unset (struct bgp *);

int
bgp_confederation_peers_check (struct bgp *, as_t);
int
bgp_confederation_peers_add (struct bgp *, as_t);
int
bgp_confederation_peers_remove (struct bgp *, as_t);

int
bgp_timers_set (struct bgp *, u_int16_t, u_int16_t);
int
bgp_timers_unset (struct bgp *);

int
bgp_default_local_preference_set (struct bgp *, u_int32_t);
int
bgp_default_local_preference_unset (struct bgp *);

s_int32_t
bgp_auto_summary_update (struct bgp *, afi_t, safi_t, bool_t);

s_int32_t
bgp_network_sync_set (struct bgp *, afi_t, safi_t);
s_int32_t
bgp_network_sync_unset (struct bgp *, afi_t, safi_t);

s_int32_t
bgp_peer_remote_as (struct bgp *,
                    union sockunion *,
                    as_t *, afi_t, safi_t);
s_int32_t
bgp_peer_group_remote_as (struct bgp *, u_int8_t *, as_t *);

s_int32_t
bgp_peer_delete (struct bgp_peer *);
s_int32_t
bgp_peer_group_delete (struct bgp_peer_group *);
s_int32_t
bgp_peer_group_remote_as_delete (struct bgp_peer_group *);

int
peer_activate (struct bgp *, struct bgp_peer *, afi_t, safi_t);

s_int32_t
bgp_peer_group_bind (struct bgp *,
                     union sockunion *,
                     struct bgp_peer_group *,
                     afi_t, safi_t, as_t *);
s_int32_t
bgp_peer_group_unbind (struct bgp *,
                       struct bgp_peer *,
                       struct bgp_peer_group *,
                       afi_t, safi_t);

int
peer_flag_set (struct bgp_peer *, u_int32_t);
int
peer_flag_unset (struct bgp_peer *, u_int32_t);
int
peer_flag_check (struct bgp_peer *, u_int32_t);

int
peer_af_flag_set (struct bgp_peer *, afi_t, safi_t, u_int32_t);
int
peer_af_flag_unset (struct bgp_peer *, afi_t, safi_t, u_int32_t);
int
peer_af_flag_check (struct bgp_peer *peer,
                    afi_t afi, safi_t safi, u_int32_t flag);

int
peer_ebgp_multihop_set (struct bgp_peer *, u_int8_t);
int
peer_ebgp_multihop_unset (struct bgp_peer *);

int
peer_description_set (struct bgp_peer *, u_int8_t *);
int
peer_description_unset (struct bgp_peer *);

int
peer_update_source_if_set (struct bgp_peer *, u_int8_t *);
int
peer_update_source_addr_set (struct bgp_peer *, union sockunion *);
int
peer_update_source_unset (struct bgp_peer *);

int
peer_default_originate_set (struct bgp_peer *,
                            afi_t, safi_t, u_int8_t *);
int
peer_default_originate_unset (struct bgp_peer *, afi_t, safi_t, bool_t);

int
peer_port_set (struct bgp_peer *, u_int16_t);
int
peer_port_unset (struct bgp_peer *);

int
peer_remote_port_set (struct bgp_peer *, u_int16_t);
int
peer_remote_port_unset (struct bgp_peer *);

int
peer_weight_set (struct bgp_peer *, u_int16_t, afi_t, safi_t);
int
peer_weight_unset (struct bgp_peer *, afi_t, safi_t);

int
peer_timers_set (struct bgp_peer *, u_int32_t, u_int32_t);
int
peer_timers_unset (struct bgp_peer *);
int
peer_timers_connect_set (struct bgp_peer *, u_int32_t);
int
peer_timers_connect_unset (struct bgp_peer *);

int
peer_asorig_interval_set (struct bgp_peer *, u_int32_t);
int
peer_asorig_interval_unset (struct bgp_peer *);

int
peer_advertise_interval_set (struct bgp_peer *, u_int32_t, bool_t);
int
peer_advertise_interval_unset (struct bgp_peer *);

int
peer_version_set (struct bgp_peer *, u_int32_t);
int
peer_version_unset (struct bgp_peer *);

int
peer_interface_set (struct bgp_peer *, u_int8_t *, u_int8_t *);
int
peer_interface_unset (struct bgp_peer *, u_int8_t *);


int
peer_allowas_in_set (struct bgp_peer *,
                     afi_t, safi_t, u_int32_t);
int
peer_allowas_in_unset (struct bgp_peer *, afi_t, safi_t);
int
peer_distribute_set (struct bgp_peer *, afi_t, safi_t,
                     u_int32_t, u_int8_t *);
int
peer_distribute_unset (struct bgp_peer *peer,
                       afi_t, safi_t, u_int32_t);

int
peer_prefix_list_set (struct bgp_peer *,
                      afi_t, safi_t,
                      u_int32_t, u_int8_t *);
int
peer_prefix_list_unset (struct bgp_peer *,
                        afi_t, safi_t, u_int32_t);

int
peer_aslist_set (struct bgp_peer *, afi_t, safi_t,
                 u_int32_t, u_int8_t *);
int
peer_aslist_unset (struct bgp_peer *,
                   afi_t, safi_t, u_int32_t);

int
peer_route_map_set (struct bgp_peer *, afi_t, safi_t,
                    u_int32_t, u_int8_t *);
int
peer_route_map_unset (struct bgp_peer *,
                      afi_t, safi_t, u_int32_t);

int
peer_unsuppress_map_set (struct bgp_peer *,
                         afi_t, safi_t, u_int8_t *);
int
peer_unsuppress_map_unset (struct bgp_peer *, afi_t, safi_t);

int
peer_maximum_prefix_set (struct bgp_peer *,
                         afi_t, safi_t,
                         u_int32_t,
                         u_int32_t,
                         bool_t);
int
peer_maximum_prefix_unset (struct bgp_peer *, afi_t, safi_t);

int
peer_clear_soft (struct bgp_peer *, afi_t, safi_t, u_int32_t);

#ifdef HAVE_TCP_MD5SIG
int
peer_password_set (struct bgp_peer *, u_int8_t, u_int8_t *);
int
peer_password_unset (struct bgp_peer *);
#endif /* TCP_MD5SIG */

int
bgp_clear_all_set (struct bgp *, afi_t, safi_t, u_int32_t);
int
bgp_clear_peer_set (struct bgp *, afi_t, safi_t,
                    u_int32_t, u_int8_t *);
int
bgp_clear_peer_group_set (struct bgp *, afi_t, safi_t,
                          u_int32_t, u_int8_t *);
int
bgp_clear_external_set (struct bgp *, afi_t, safi_t,
                        u_int32_t);
int
bgp_clear_as_set (struct bgp *, afi_t, safi_t,
                  u_int32_t, u_int32_t);

int
bgp_community_list_set (char *, char *, int, int, int);
int
bgp_community_list_unset (char *);
int
bgp_community_list_entry_unset (char *, char *,
                                int, int, int);
int
bgp_extcommunity_list_set (char *, char *, int, int, int);
int
bgp_extcommunity_list_unset (char *);
int
bgp_extcommunity_list_entry_unset (char *, char *,
                                   int, int, int);
int
bgp_aspath_access_list_set (char *, char *, int);
int
bgp_aspath_access_list_entry_unset (char *, char *, int);
int
bgp_aspath_access_list_unset (char *);

s_int32_t
bgp_static_network_set (struct bgp *, u_int8_t *,
                        afi_t, safi_t,
                        u_int32_t, u_int8_t *);
s_int32_t
bgp_static_network_unset (struct bgp *, u_int8_t *,
                          afi_t, safi_t);

s_int32_t
bgp_aggregate_addr_set (struct bgp *,
                        u_int8_t *,
                        afi_t, safi_t,
                        u_int32_t);
s_int32_t
bgp_aggregate_addr_unset (struct bgp *,
                          u_int8_t *,
                          afi_t, safi_t);

#ifdef HAVE_SNMP
s_int32_t
bgp_snmp_notification_callback_set (u_int32_t, SNMP_TRAP_CALLBACK);
s_int32_t
bgp_snmp_notification_callback_unset (u_int32_t, SNMP_TRAP_CALLBACK);
#endif /* HAVE_SNMP */

/*
 * BGP Inline Utility Functions
 */

/* BGP Instance Config Flags Manipulation Functions */
pal_static pal_inline s_int32_t
bgp_config_set (struct bgp *bgp, u_int32_t cflag)
{
  SET_FLAG (bgp->bgp_cflags, cflag);

  return BGP_API_SET_SUCCESS;
}

pal_static pal_inline s_int32_t
bgp_config_unset (struct bgp *bgp, u_int32_t cflag)
{
  UNSET_FLAG (bgp->bgp_cflags, cflag);

  return BGP_API_SET_SUCCESS;
}

pal_static pal_inline s_int32_t
bgp_config_check (struct bgp *bgp, u_int32_t cflag)
{
  return CHECK_FLAG (bgp->bgp_cflags, cflag);
}

/* BGP Instance Status Flags Manipulation Functions */
pal_static pal_inline s_int32_t
bgp_status_set (struct bgp *bgp, u_int32_t sflag)
{
  SET_FLAG (bgp->bgp_sflags, sflag);

  return BGP_API_SET_SUCCESS;
}

pal_static pal_inline s_int32_t
bgp_status_unset (struct bgp *bgp, u_int32_t sflag)
{
  UNSET_FLAG (bgp->bgp_sflags, sflag);

  return BGP_API_SET_SUCCESS;
}

pal_static pal_inline s_int32_t
bgp_status_check (struct bgp *bgp, u_int32_t sflag)
{
  return CHECK_FLAG (bgp->bgp_sflags, sflag);
}

/* BGP Instance AF-Configuration Flags Manipulation Functions */
pal_static pal_inline s_int32_t
bgp_af_config_set (struct bgp *bgp,
                   afi_t afi, safi_t safi,
                   u_int32_t af_cflag)
{
  SET_FLAG (bgp->bgp_af_cflags [BGP_AFI2BAAI (afi)]
                               [BGP_SAFI2BSAI (safi)],
            af_cflag);

  return BGP_API_SET_SUCCESS;
}

pal_static pal_inline s_int32_t
bgp_af_config_unset (struct bgp *bgp,
                     afi_t afi, safi_t safi,
                     u_int32_t af_cflag)
{
  UNSET_FLAG (bgp->bgp_af_cflags [BGP_AFI2BAAI (afi)]
                                 [BGP_SAFI2BSAI (safi)],
              af_cflag);

  return BGP_API_SET_SUCCESS;
}

pal_static pal_inline s_int32_t
bgp_af_config_check (struct bgp *bgp,
                     afi_t afi, safi_t safi,
                     u_int32_t af_cflag)
{
  return CHECK_FLAG (bgp->bgp_af_cflags [BGP_AFI2BAAI (afi)]
                                        [BGP_SAFI2BSAI (safi)],
                     af_cflag);
}

/* BGP Instance AF-Status Flag Manipulation Functions */
pal_static pal_inline s_int32_t
bgp_af_status_set (struct bgp *bgp,
                   afi_t afi, safi_t safi,
                   u_int32_t af_sflag)
{
  SET_FLAG (bgp->bgp_af_sflags [BGP_AFI2BAAI (afi)]
                               [BGP_SAFI2BSAI (safi)],
            af_sflag);

  return BGP_API_SET_SUCCESS;
}

pal_static pal_inline s_int32_t
bgp_af_status_unset (struct bgp *bgp,
                     afi_t afi, safi_t safi,
                     u_int32_t af_sflag)
{
  UNSET_FLAG (bgp->bgp_af_sflags [BGP_AFI2BAAI (afi)]
                                 [BGP_SAFI2BSAI (safi)],
              af_sflag);

  return BGP_API_SET_SUCCESS;
}

pal_static pal_inline s_int32_t
bgp_af_status_check (struct bgp *bgp,
                     afi_t afi, safi_t safi,
                     u_int32_t af_sflag)
{
  return CHECK_FLAG (bgp->bgp_af_sflags [BGP_AFI2BAAI (afi)]
                                        [BGP_SAFI2BSAI (safi)],
                     af_sflag);
}

#endif /* _BGPSDN_BGP_API_H */
