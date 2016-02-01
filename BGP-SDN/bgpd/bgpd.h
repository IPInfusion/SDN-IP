/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGPD_H
#define _BGPSDN_BGPD_H

#ifdef HAVE_BGP_SDN
#include <curl/curl.h>
#endif /* HAVE_BGP_SDN */

/* Default configuration settings for bgpd. */
#define BGP_VTYSH_PATH                          "/tmp/.bgpd"
#define BGP_DEFAULT_CONFIG                      "bgpd.conf"

/* Loopback Address */
#define LOOPBACK_ADDR_NW                0x100007F /* 127.0.0.1 */

#ifdef HAVE_SNMP
#define BGP_SNMP_NOTIFY_ALL                     (0)
#define BGP_SNMP_NOTIFY_ID_MIN                  (1)
#define BGP_SNMP_NOTIFY_ID_MAX                  (2)
#define BGP_SNMP_NOTIFY_VEC_MIN_SIZE            (1)
#endif /* HAVE_SNMP */

/* BGP-Address-Family-Identifier-Array-Index values */
#define BAAI_IP                                 (0)
#define BAAI_IP6                                (1)
#define BAAI_MAX                                (2)

/* BGP-Sub-Address-Family-Identifier-Array-Index values  */
#define BSAI_UNICAST                            (0)
#define BSAI_MULTICAST                          (1)
#define BSAI_MAX                                (2)

/* BGP version */
#define BGP_VERSION_4                           (4)

/* BGP Default Port number */
#define BGP_PORT_DEFAULT                        (179)

/* BGP Listen Socket Listen Backlog Count */
#define BGP_SOCK_LISTEN_BACKLOG                 (5)

/* BGP Outgoing Message Cluster Max Number */
#define BGP_SEND_MSG_CLUST_MAX_COUNT            (5)

/* BGP RIB Scan Stagger Count */
#define BGP_RIB_SCAN_STAGGER_COUNT              (20000)

/* BGP message header and packet size.  */
#define BGP_MARKER_SIZE                         (16)
#define BGP_HEADER_SIZE                         (19)
#define BGP_MAX_PACKET_SIZE                     (4096)

#define BGP_NLRI_MIN_SIZE                       (1)
#define BGP_TOTAL_ATTR_LEN_FIELD_SIZE           (2)
#define BGP_WITHDRAWN_NLRI_LEN_FIELD_SIZE       (2)

/* BGP minimum message size */
#define BGP_MSG_OPEN_MIN_SIZE                   (BGP_HEADER_SIZE + 10)
#define BGP_MSG_UPDATE_MIN_SIZE                 (BGP_HEADER_SIZE + 4)
#define BGP_MSG_NOTIFY_MIN_SIZE                 (BGP_HEADER_SIZE + 2)
#define BGP_MSG_KEEPALIVE_MIN_SIZE              (BGP_HEADER_SIZE + 0)
#define BGP_MSG_ROUTE_REFRESH_MIN_SIZE          (BGP_HEADER_SIZE + 4)
#define BGP_MSG_CAPABILITY_MIN_SIZE             (BGP_HEADER_SIZE + 3)

/* BGP Maximum message sizes */
#define BGP_MSG_OPEN_MAX_SIZE                   (BGP_MSG_OPEN_MIN_SIZE + 255)
#define BGP_MSG_DYNA_CAP_MAX_SIZE               (BGP_MSG_CAPABILITY_MIN_SIZE + 255)

/* BGP OPEN Options size */
#define BGP_MSG_OPEN_OPT_MIN_SIZE               (2)
#define BGP_MSG_OPEN_OPT_LEN_FIELD_SIZE         (1)
#define BGP_MSG_OPEN_OPT_TYPE_FIELD_SIZE        (1)
#define BGP_MSG_OPEN_OPT_CAP_MIN_SIZE           (2)
#define BGP_MSG_OPEN_OPT_CAP_CODE_FIELD_SIZE    (1)
#define BGP_MSG_OPEN_OPT_CAP_ORF_MIN_SIZE       (7)
#define BGP_MSG_OPEN_OPT_CAP_ORF_AFI_SAFI_SIZE  (4)

/* BGP OPEN Options size */
#define BGP_MSG_CAP_OPT_MIN_SIZE                (7)

/* Multiprotocol Extensions capabilities. */
#define BGP_CAPABILITY_CODE_MP                  (1)
#define BGP_CAPABILITY_CODE_MP_LEN              (4)

/* Route refresh capabilities. */
#define BGP_CAPABILITY_CODE_REFRESH             (2)
#define BGP_CAPABILITY_CODE_REFRESH_OLD         (128)
#define BGP_CAPABILITY_CODE_REFRESH_LEN         (0)

/* Cooperative Route Filtering Capability.  */
#define BGP_CAPABILITY_CODE_ORF                 (3)
#define BGP_CAPABILITY_CODE_ORF_OLD             (130)

/* 4-octet AS Capability */
#define BGP_CAPABILITY_CODE_EXTASN              (65)
#define BGP_CAPABILITY_CODE_EXTASN_LEN          (4)

/* ORF Type.  */
#define BGP_ORF_TYPE_PREFIX                     (64)
#define BGP_ORF_TYPE_PREFIX_OLD                 (128)

/* ORF When-to-refresh */
#define BGP_ORF_REFRESH_IMMEDIATE               (1)
#define BGP_ORF_REFRESH_DEFER                   (2)

/* ORF Prefix Sizes */
#define BGP_ORF_PREFIX_ENTRY_MIN_SIZE           (7)

/* BGP R-Refresh ORF Common-Part Action flags */
#define BGP_ORF_COMMON_ACTION_MASK              (0xC0)
#define BGP_ORF_COMMON_ACTION_ADD               (0x00)
#define BGP_ORF_COMMON_ACTION_REMOVE            (0x40)
#define BGP_ORF_COMMON_ACTION_REMOVE_ALL        (0x80)

/* BGP R-Refresh ORF Common-Part Match flags */
#define BGP_ORF_COMMON_MATCH_MASK               (0x20)
#define BGP_ORF_COMMON_MATCH_PERMIT             (0x00)
#define BGP_ORF_COMMON_MATCH_DENY               (0x20)

/* ORF Mode.  */
#define BGP_ORF_MODE_RECEIVE                    (1)
#define BGP_ORF_MODE_SEND                       (2)
#define BGP_ORF_MODE_BOTH                       (3)

/* Dynamic capability.  */
#define BGP_CAPABILITY_CODE_DYNAMIC_OLD         (66)
#define BGP_CAPABILITY_CODE_DYNAMIC             (67)
#define BGP_CAPABILITY_CODE_DYNAMIC_LEN         (0)

/* Capability Message Action */
#define BGP_CAPABILITY_ACTION_SET               (0)
#define BGP_CAPABILITY_ACTION_UNSET             (1)

/* BGP Message Types */
#define BGP_MSG_OPEN                            (1)
#define BGP_MSG_UPDATE                          (2)
#define BGP_MSG_NOTIFY                          (3)
#define BGP_MSG_KEEPALIVE                       (4)
#define BGP_MSG_ROUTE_REFRESH_NEW               (5)
#define BGP_MSG_CAPABILITY                      (6)
#define BGP_MSG_ROUTE_REFRESH_OLD               (128)
#define BGP_MSG_CAPABILITY_EXTASN               (65)

/* BGP open optional parameter */
#define BGP_OPEN_OPT_AUTH                       (1)
#define BGP_OPEN_OPT_CAP                        (2)

/* BGP Route-Refresh ORF size */
#define BGP_MSG_RR_ORF_WHEN2RR_MIN_SIZE         (1)
#define BGP_MSG_RR_ORF_ENTRY_MIN_SIZE           (4)
#define BGP_MSG_RR_ORF_LEN_FIELD_SIZE           (2)

/* BGP4 attribute type codes. */
#define BGP_ATTR_ORIGIN                         (1)
#define BGP_ATTR_AS_PATH                        (2)
#define BGP_ATTR_NEXT_HOP                       (3)
#define BGP_ATTR_MULTI_EXIT_DISC                (4)
#define BGP_ATTR_LOCAL_PREF                     (5)
#define BGP_ATTR_ATOMIC_AGGREGATE               (6)
#define BGP_ATTR_AGGREGATOR                     (7)
#define BGP_ATTR_COMMUNITIES                    (8)
#define BGP_ATTR_ORIGINATOR_ID                  (9)
#define BGP_ATTR_CLUSTER_LIST                   (10)
#define BGP_ATTR_DPA                            (11)
#define BGP_ATTR_ADVERTISER                     (12)
#define BGP_ATTR_RCID_PATH                      (13)
#define BGP_ATTR_MP_REACH_NLRI                  (14)
#define BGP_ATTR_MP_UNREACH_NLRI                (15)
#define BGP_ATTR_EXT_COMMUNITIES                (16)

/* Attributes Types for 4-octet ASN capability  */

#define BGP_ATTR_AS4_PATH                       (17)
#define BGP_ATTR_AS4_AGGREGATOR                 (18)  

/* BGP update origin.  */
#define BGP_ORIGIN_IGP                          (0)
#define BGP_ORIGIN_EGP                          (1)
#define BGP_ORIGIN_INCOMPLETE                   (2)

/* BGP notify message codes.  */
#define BGP_NOTIFY_HEADER_ERR                   (1)
#define BGP_NOTIFY_OPEN_ERR                     (2)
#define BGP_NOTIFY_UPDATE_ERR                   (3)
#define BGP_NOTIFY_HOLD_ERR                     (4)
#define BGP_NOTIFY_FSM_ERR                      (5)
#define BGP_NOTIFY_CEASE                        (6)
#define BGP_NOTIFY_CAPABILITY_ERR               (7)
#define BGP_NOTIFY_MAX                          (8)

/* BGP_NOTIFY_HEADER_ERR sub codes.  */
#define BGP_NOTIFY_HEADER_NOT_SYNC              (1)
#define BGP_NOTIFY_HEADER_BAD_MESLEN            (2)
#define BGP_NOTIFY_HEADER_BAD_MESTYPE           (3)
#define BGP_NOTIFY_HEADER_MAX                   (4)

/* BGP_NOTIFY_OPEN_ERR sub codes. RFC 4271, RFC 3392  */
#define BGP_NOTIFY_OPEN_UNSUP_VERSION           (1)
#define BGP_NOTIFY_OPEN_BAD_PEER_AS             (2)
#define BGP_NOTIFY_OPEN_BAD_BGP_IDENT           (3)
#define BGP_NOTIFY_OPEN_UNSUP_PARAM             (4)
#define BGP_NOTIFY_OPEN_AUTH_FAILURE            (5)
#define BGP_NOTIFY_OPEN_UNACEP_HOLDTIME         (6)
#define BGP_NOTIFY_OPEN_UNSUP_CAPBL             (7)
#define BGP_NOTIFY_OPEN_MAX                     (8)

/* BGP_NOTIFY_UPDATE_ERR sub codes. RFC 4271 */
#define BGP_NOTIFY_UPDATE_MAL_ATTR              (1)
#define BGP_NOTIFY_UPDATE_UNREC_ATTR            (2)
#define BGP_NOTIFY_UPDATE_MISS_ATTR             (3)
#define BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR         (4)
#define BGP_NOTIFY_UPDATE_ATTR_LENG_ERR         (5)
#define BGP_NOTIFY_UPDATE_INVAL_ORIGIN          (6)
#define BGP_NOTIFY_UPDATE_AS_ROUTE_LOOP         (7)
#define BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP        (8)
#define BGP_NOTIFY_UPDATE_OPT_ATTR_ERR          (9)
#define BGP_NOTIFY_UPDATE_INVAL_NETWORK         (10)
#define BGP_NOTIFY_UPDATE_MAL_AS_PATH           (11)
#define BGP_NOTIFY_UPDATE_MAL_AS4_PATH          (12)
#define BGP_NOTIFY_UPDATE_MAX                   (13)

/* BGP_NOTIFY_CEASE sub codes (RFC 4486).  */
#define BGP_NOTIFY_CEASE_MAX_PREFIX             (1)
#define BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN         (2)
#define BGP_NOTIFY_CEASE_PEER_UNCONFIG          (3)
#define BGP_NOTIFY_CEASE_ADMIN_RESET            (4)
#define BGP_NOTIFY_CEASE_CONNECT_REJECT         (5)
#define BGP_NOTIFY_CEASE_CONFIG_CHANGE          (6)
#define BGP_NOTIFY_CEASE_CONN_COLLISION_RES     (7)
/* This Notify message will be used in future */
#define BGP_NOTIFY_CEASE_OUT_OF_RESOURCES       (8)
#define BGP_NOTIFY_CEASE_MAX                    (9)

/* BGP_NOTIFY_CAPABILITY_ERR sub codes (RFC 4271). */
#define BGP_NOTIFY_CAPABILITY_INVALID_ACTION    (1)
#define BGP_NOTIFY_CAPABILITY_INVALID_LENGTH    (2)
#define BGP_NOTIFY_CAPABILITY_MALFORMED_CODE    (3)
#define BGP_NOTIFY_CAPABILITY_MAX               (4)

/*
 * BGP Peer FSM State Definitions
 */
#define BPF_STATE_IDLE                          (1)
#define BPF_STATE_CONNECT                       (2)
#define BPF_STATE_ACTIVE                        (3)
#define BPF_STATE_OPEN_SENT                     (4)
#define BPF_STATE_OPEN_CFM                      (5)
#define BPF_STATE_ESTABLISHED                   (6)
#define BPF_STATE_MAX                           (7)

/*
 * BGP Peer FSM Event Definitions
 */
/* BGP Peer FSM Administrative Events */
#define BPF_EVENT_MANUAL_START                  (1)
#define BPF_EVENT_MANUAL_STOP                   (2)
#define BPF_EVENT_AUTO_START                    (3)
#define BPF_EVENT_MANUAL_START_TCP_PASSIVE      (4)
#define BPF_EVENT_AUTO_START_TCP_PASSIVE        (5)
#define BPF_EVENT_AUTO_START_POD                (6)
#define BPF_EVENT_AUTO_START_TCP_PASSIVE_POD    (7)
#define BPF_EVENT_AUTO_STOP                     (8)

/* BGP Peer FSM Timer based Events */
#define BPF_EVENT_CONN_RETRY_EXP                (9)
#define BPF_EVENT_HOLD_EXP                      (10)
#define BPF_EVENT_KEEPALIVE_EXP                 (11)
#define BPF_EVENT_DELAY_OPEN_EXP                (12)
#define BPF_EVENT_IDLE_HOLD_EXP                 (13)

/* BGP Peer FSM TCP Connection based Events */
#define BPF_EVENT_TCP_CONN_VALID                (14)
#define BPF_EVENT_TCP_CONN_INVALID              (15)
#define BPF_EVENT_TCP_CONN_ACKED                (16)
#define BPF_EVENT_TCP_CONN_CFM                  (17)
#define BPF_EVENT_TCP_CONN_FAIL                 (18)

/* BGP Peer FSM Message based Events */
#define BPF_EVENT_OPEN_VALID                    (19)
#define BPF_EVENT_OPEN_VALID_DELAY_OPEN         (20)
#define BPF_EVENT_HDR_ERR                       (21)
#define BPF_EVENT_OPEN_ERR                      (22)
#define BPF_EVENT_OPEN_COLLISION_DUMP           (23)
#define BPF_EVENT_NOTIFY_VER_ERR                (24)
#define BPF_EVENT_NOTIFY_VALID                  (25)
#define BPF_EVENT_KEEPALIVE_VALID               (26)
#define BPF_EVENT_UPDATE_VALID                  (27)
#define BPF_EVENT_UPDATE_ERR                    (28)
#define BPF_EVENT_ROUTE_REFRESH_VALID           (29)
#define BPF_EVENT_ROUTE_REFRESH_ERR             (30)
#define BPF_EVENT_DYNA_CAP_VALID                (31)
#define BPF_EVENT_DYNA_CAP_ERR                  (32)

/* BGP Peer FSM Implementation Defined Events */
#define BPF_EVENT_ASORIG_EXP                    (33)
#define BPF_EVENT_ROUTEADV_EXP                  (34)
#define BPF_EVENT_MANUAL_RESET                  (35)
#define BPF_EVENT_MAX                           (36)

/* BGP timers default value.  */
#define BGP_INITIAL_CONNECT_RETRY               (20)
#define BGP_DEFAULT_AUTO_START                  (5)
#define BGP_DEFAULT_CONNECT_RETRY               (120)
#define BGP_DEFAULT_HOLDTIME_LARGE              (240)
#define BGP_DEFAULT_HOLDTIME                    (90)
#define BGP_DEFAULT_KEEPALIVE                   (30)
#define BGP_DEFAULT_ASORIG                      (15)
#define BGP_DEFAULT_EBGP_ROUTEADV               (30)
#define BGP_DEFAULT_IBGP_ROUTEADV               (5)

/* BGP Default Weight */
#define BGP_ATTR_WEIGHT_DEF                     (32768)

/* BGP Default local preference */
#define BGP_DEFAULT_LOCAL_PREF                  (100)

/* BGP Default maximum-prefix threshold */
#define BGP_DEFAULT_MAX_PREFIX_THRESHOLD        (75)

/* Route-Distringuisher size in bytes */
#define BGP_RD_SIZE                             (8)

/* Route-Target size in bytes */
#define BGP_RT_SIZE                             (8)

/* BGP Neighbor TTL values */
#define BGP_PEER_TTL_MIN                        (1)
#define BGP_PEER_TTL_EBGP_DEF                   (1)
#define BGP_PEER_TTL_IBGP_DEF                   (255)
#define BGP_PEER_TTL_MAX                        (255)

/* BGP uptime string length.  */
#define BGP_UPTIME_LEN                          (25)

/* For log-neighbor-status neighbor's status.  */
#define PEER_LOG_STATUS_DOWN                    (0)
#define PEER_LOG_STATUS_UP                      (1)

/* AS path segment Types */
#define BGP_AS_SET                              (1)
#define BGP_AS_SEQUENCE                         (2)
#define BGP_AS_CONFED_SEQUENCE                  (3)
#define BGP_AS_CONFED_SET                       (4)

/* AS range <1-65535> */
#define BGP_AS_MIN                              (1)
#define BGP_AS_MAX                              (65535)


/* 4-octet AS Range */
#define BGP_AS4_MIN                             (1)
#define BGP_AS4_MAX                             (4294967295U) 




/* AS_TRANS for 4-octet AS compatibility */
#define BGP_AS_TRANS                            (23456) 



/* Private AS range defined in RFC2270 */
#define BGP_PRIVATE_AS_MIN                      (64512)
#define BGP_PRIVATE_AS_MAX                      (65535)

/* BGP AS Path String Default Length */
#define BGP_ASPATH_STR_DEFAULT_LEN              (32)
#define BGP_AS4PATH_STR_DEFAULT_LEN             (64)

/* BGP Aggregate Route attribute Type Flags */
#define BGP_AGGREGATE_SUMMARY_ONLY              (1 << 0)
#define BGP_AGGREGATE_AS_SET                    (1 << 1)

/* BGP RIB Scan and BGP Network Scan Timer Intervals */
#define BGP_RIB_SCAN_INTERVAL_DEFAULT           (60)
#define BGP_NETWORK_SCAN_INTERVAL_DEFAULT       (15)

/* BGP Process Global Variable Container Name */
#define BGP_LIB_GLOBAL_VAR    bgp_lib_globals

/* BGP Maximum and Minimum MED Value */
#define BGP_MED_MIN                             (0)
#define BGP_MED_MAX                             (0xFFFFFFFEUL)

/* Route recieved from OSPF of type4 LSA */
#define BGP_OSPF_VRF_ROUTE_OF_TYPE4_LSA                (4)

/* BGP VR-VRF ID Values */
#define BGP_VR_ID_DEFAULT                       (VRF_ID_MAIN)
#define BGP_VRF_ID_DEFAULT                      (VRF_ID_MAIN)

#define BGP_FALSE                       (0)
#define BGP_TRUE                        (1)
    
#define BGP_SUCCESS                     BGP_TRUE
#define BGP_ERROR                       -1

#ifdef HAVE_DEV_TEST
#define BGP_ASSERT(expr) pal_assert ((expr))
#else
#define BGP_ASSERT(expr) 
#endif /* HAVE_DEV_TEST */


/* BGP Process Global variable Container */
extern struct lib_globals *BGP_LIB_GLOBAL_VAR;

/* Declare Some BGP specific types. */
#ifndef HAVE_EXT_CAP_ASN
typedef u_int16_t as_t;
#else
typedef u_int32_t as_t;
#endif /* HAVE_EXT_CAP_ASN */


/* BGP Peer Type Enumeration */
enum bgp_peer_type
{
  BGP_PEER_IBGP,
  BGP_PEER_EBGP,
  BGP_PEER_INTERNAL,
  BGP_PEER_CONFED
};

/* BGP 'clear' Command Types Enumeration */
enum bgp_clear_type
{
  clear_all,
  clear_peer,
  clear_group,
  clear_external,
  clear_as,
  clear_rfd
};

/* BGP Peer Incoming Connection Req. Actions Enumeration */
enum bgp_peer_icr_act
{
  BGP_PEER_ICR_IGNORE,
  BGP_PEER_ICR_ACCEPT,
  BGP_PEER_ICR_TRACK
};

/* BGP Peer Config Modification Type Enumeration */
enum bgp_peer_change_type
{
  peer_change_none,
  peer_change_reset,
  peer_change_reset_in,
  peer_change_reset_out
};

/* BGP "show ip bgp" Types Enumeration */
enum bgp_show_type
{
  bgp_show_type_normal,
  bgp_show_type_regexp,
  bgp_show_type_prefix_list,
  bgp_show_type_filter_list,
  bgp_show_type_route_map,
  bgp_show_type_neighbor,
  bgp_show_type_cidr_only,
  bgp_show_type_prefix_longer,
  bgp_show_type_community_all,
  bgp_show_type_community,
  bgp_show_type_community_exact,
  bgp_show_type_community_list,
  bgp_show_type_community_list_exact,
  bgp_show_type_flap_statistics,
  bgp_show_type_dampened_paths,
  bgp_show_type_inconsistent_as
};

/* BGP route-map information type */
enum bgp_rmap_info_type
{
  BGP_RMAP_INFO_REGULAR,
  BGP_RMAP_INFO_SYNC_PREFIX
};

/* BGP route-map information structure */
struct bgp_rmap_info
{
  enum bgp_rmap_info_type brmi_type;
  struct bgp *brmi_bgp;
  struct bgp_info *brmi_bri;
};

/* BGP route-map structure */
struct bgp_rmap
{
  u_int8_t *name;
  struct route_map *map;
};

/* BGP Global for Process-wide configurations and variables */
struct bgp_global
{
  /* BGP port number */
  u_int16_t sock_port;

  /* BGP start time. */
  pal_time_t start_time;

  /* BGP License Manager Capability Variables */
  u_int8_t cap_have_ipv6;
#define bgp_cap_have_ipv6                (BGP_GLOBAL.cap_have_ipv6)

  /* BGP global configuration options  */
  u_int16_t blg_options;
#define BGP_OPT_NO_FIB                   (1 << 0)
#define BGP_OPT_MULTIPLE_INSTANCE        (1 << 1)
#define BGP_OPT_CONFIG_STANDARD          (1 << 2)
#define BGP_OPT_RFC1771_PATH_SELECT      (1 << 3)
#define BGP_OPT_RFC1771_STRICT           (1 << 4)
#define BGP_OPT_AGGREGATE_NEXTHOP_CHECK  (1 << 5)

  /* Hash Table for all BGP Attributes */
  struct hash *attrhash_tab;
#define bgp_attrhash_tab                 (BGP_GLOBAL.attrhash_tab)


/* Hash Table for 2B AS paths */

  struct hash *ashash_tab;
#define bgp_ashash_tab                   (BGP_GLOBAL.ashash_tab)

/* Hash Table for 4B AS paths (Reference: RFC 4893)
 * aspath4Bhash_tab - It is used for storing 4byte aspaths which
 *                    are used for NBGP-to-NBGP 4byte AS_PATH and for
 *                    NBGP conversion of 2byte to 4B.
 * as4hash_tab      - It is used for storing AS4_PATH (RFC 4893) information
 *                    in NBGP implementation
 */
#ifdef HAVE_EXT_CAP_ASN
  struct hash *aspath4Bhash_tab;
#define bgp_aspath4Bhash_tab                (BGP_GLOBAL.aspath4Bhash_tab)
  struct hash *as4hash_tab; 
#define bgp_as4hash_tab                  (BGP_GLOBAL.as4hash_tab)
#endif /* HAVE_EXT_CAP_ASN */

  /* Hash Table for Cluster lists */
  struct hash *clusterhash_tab;
#define bgp_clusterhash_tab              (BGP_GLOBAL.clusterhash_tab)

  /* Hash Table for Community attribute. */
  struct hash *comhash_tab;
#define bgp_comhash_tab                  (BGP_GLOBAL.comhash_tab)

  /* Hash Table for Extended-Community attribute. */
  struct hash *ecomhash_tab;
#define bgp_ecomhash_tab                 (BGP_GLOBAL.ecomhash_tab)

  /* Hash Table for Unknown transitive attribute. */
  struct hash *transithash_tab;
#define bgp_transithash_tab              (BGP_GLOBAL.transithash_tab)

  /* BGP community-list */
  struct community_list_handler *com_ecom_list;
#define bgp_clist                        (BGP_GLOBAL.com_ecom_list)

  /* BGP AS Path List master */
  struct bgp_as_list_master *aslist_master;
#define bgp_aslist_master                (BGP_GLOBAL.aslist_master)

#ifdef HAVE_BGP_DUMP
  /* BGP packet dump output buffer. */
  struct stream *dump_obuf;
#define bgp_dump_obuf                    (BGP_GLOBAL.dump_obuf)

  /* BGP dump strucuture for 'dump bgp all' */
  struct bgp_dump *dump_all;
#define bgp_dump_all                     (BGP_GLOBAL.dump_all)

  /* BGP dump structure for 'dump bgp updates' */
  struct bgp_dump *dump_updates;
#define bgp_dump_updates                 (BGP_GLOBAL.dump_updates)

  /* BGP dump structure for 'dump bgp routes' */
  struct bgp_dump *dump_routes;
#define bgp_dump_routes                  (BGP_GLOBAL.dump_routes)
#endif /* HAVE_BGP_DUMP */

  /* Debug option setting */
  u_int32_t debug_option;
#define bgp_debug_option                 (BGP_GLOBAL.debug_option)

#ifdef HAVE_BGP_SDN
  CURLM	     *curlm;
#define bgp_curlm			 (BGP_GLOBAL.curlm)

  struct list *curl_list;
#define bgp_curl_list			 (BGP_GLOBAL.curl_list)

  struct list *curl_list_pending;
#define bgp_curl_list_pending		 (BGP_GLOBAL.curl_list_pending)

  struct thread *curlm_thread;
#define bgp_curlm_thread		 (BGP_GLOBAL.curlm_thread)

  char       *rest_addr;
  char       *rest_port;
#define bgp_rest_addr			 (BGP_GLOBAL.rest_addr)
#define bgp_rest_port			 (BGP_GLOBAL.rest_port)

#define BGP_MAX_SDN_CLIENT	2
  char       *sdn_addr[BGP_MAX_SDN_CLIENT];
  u_int16_t  sdn_port[BGP_MAX_SDN_CLIENT];
#define bgp_sdn_addr			 (BGP_GLOBAL.sdn_addr)
#define bgp_sdn_port			 (BGP_GLOBAL.sdn_port)
#endif /* HAVE_BGP_SDN */

};

#ifdef HAVE_BGP_SDN
struct bgp_curl_info
{
  CURL *handle;
  char *url;
  int post;
};
#endif /* HAVE_BGP_SDN */

/* BGP Virtual-Router structure */
struct bgp_vr
{
  /* BGP VR configuration options  */
  u_int16_t bvr_options;
#define BGP_OPT_NO_FIB                     (1 << 0)
#define BGP_OPT_MULTIPLE_INSTANCE          (1 << 1)
#define BGP_OPT_CONFIG_STANDARD            (1 << 2)
#define BGP_OPT_RFC1771_PATH_SELECT        (1 << 3)
#define BGP_OPT_RFC1771_STRICT             (1 << 4)
#define BGP_OPT_AGGREGATE_NEXTHOP_CHECK    (1 << 5)
#define BGP_OPT_EXTENDED_ASN_CAP           (1 << 9)
#define BGP_OPT_MULTI_INS_ALLOW_SAME_PEER  (1 << 10)
#define BGP_OPT_DISABLE_ADJ_OUT            (1 << 12)

  /* Nexthop tracking delay time interval */
  u_int16_t nh_tracking_delay_interval;
#define  BGP_NH_TRACKING_DELAY_INTERVAL_DEFAULT    5
  
  u_int32_t conf_bgp_debug_flags;
  u_int32_t term_bgp_debug_flags;

#define BGP_DEBUG_FSM                 (1 << 0)
#define BGP_DEBUG_EVENTS              (1 << 1)
#define BGP_DEBUG_PACKET              (1 << 2)
#define BGP_DEBUG_FILTER              (1 << 3)
#define BGP_DEBUG_KEEPALIVE           (1 << 4)
#define BGP_DEBUG_UPDATE_IN           (1 << 5)
#define BGP_DEBUG_UPDATE_OUT          (1 << 6)
#define BGP_DEBUG_NORMAL              (1 << 7)
#define BGP_DEBUG_NHT                 (1 << 8)
#define BGP_DEBUG_NSM                 (1 << 9)
#define BGP_DEBUG_RFD                 (1 << 10)

#define BGP_DEBUG_PACKET_SEND         (1 << 12)
#define BGP_DEBUG_PACKET_SEND_DETAIL  (1 << 13)

#define BGP_DEBUG_PACKET_RECV         (1 << 14)
#define BGP_DEBUG_PACKET_RECV_DETAIL  (1 << 15)
#define BGP_DEBUG_BFD		      (1 << 16)                 

  /* Owning IPI VR */
  struct ipi_vr *owning_ivr;

  /* BGP Instance List */
  struct list *bgp_list;

  /* BGP Configured/Automatic Router ID */
  struct pal_in4_addr router_id;

  /* BGP start time.  */
  pal_time_t start_time;

  /* BGP Route Flap Dampening Reuse List Array */
  struct bgp_rfd_hist_info **rfd_reuse_list;

  /* BGP Route Flap Dampening Non-Reuse List Array */
  struct bgp_rfd_hist_info *rfd_non_reuse_list;

  /* BGP Route Flap Dampening Reuse List Array offset */
  u_int32_t rfd_reuse_list_offset;

  /* BGP Route Flap Dampening Reuse Timer thread */
  struct thread *t_rfd_reuse;

  /* BGP Route Flap Dampening Non-Reuse Timer thread */
  struct thread *t_rfd_non_reuse;

  /* BGP SNMP Notifications callback function */
#ifdef HAVE_SNMP
  vector snmp_notifications [BGP_SNMP_NOTIFY_ID_MAX];
#endif /* HAVE_SNMP */
};

/* BGP Listen Socket List Node */
struct bgp_listen_sock_lnode
{
  /* BGP Listen Socket Next Node */
  struct bgp_listen_sock_lnode *next;

  /* BGP Listen Socket FD */
  pal_sock_handle_t listen_sock;

  /* BGP Thread Node pointer */
  struct thread *t_accept;
};

/* BGP Instance structure */
struct bgp
{
  /* Owning BGP VR structure */
  struct bgp_vr *owning_bvr;

  /* Owning Library VRF structure */
  struct ipi_vrf *owning_ivrf;

  /* BGP Instance AS Number */
  as_t as; 
  u_int8_t pad1 [2];

  /* BGP Instance Name */
  u_int8_t *name;

  /* Self Peer */
  struct bgp_peer *peer_self;

  /* BGP Peers List */
  struct list *peer_list;

  /* BGP Peer-Group List */
  struct list *group_list;

  /* BGP router identifier.  */
  struct pal_in4_addr router_id;

  /* BGP route reflector cluster ID */
  struct pal_in4_addr cluster_id;

  /* BGP confederation information.  */
  as_t confed_id;
  u_int8_t pad2 [2];
  as_t *confed_peers;
  u_int16_t confed_peers_cnt;

  /* BGP Configuration Flags (all AFs) */
  u_int32_t bgp_cflags;
#define BGP_CFLAG_ROUTER_ID             (1 << 0)
#define BGP_CFLAG_CLUSTER_ID            (1 << 1)
#define BGP_CFLAG_CLUSTER_ID_DIGIT      (1 << 2)
#define BGP_CFLAG_CONFEDERATION         (1 << 3)
#define BGP_CFLAG_DEFAULT_LOCAL_PREF    (1 << 4)
#define BGP_CFLAG_DEFAULT_TIMER         (1 << 5)
#define BGP_CFLAG_ALWAYS_COMPARE_MED    (1 << 7)
#define BGP_CFLAG_DETERMINISTIC_MED     (1 << 8)
#define BGP_CFLAG_MED_MISSING_AS_WORST  (1 << 9)
#define BGP_CFLAG_MED_CONFED            (1 << 10)
#define BGP_CFLAG_NO_DEFAULT_IPV4       (1 << 11)
#define BGP_CFLAG_NO_CLIENT_TO_CLIENT   (1 << 12)
#define BGP_CFLAG_ENFORCE_FIRST_AS      (1 << 13)
#define BGP_CFLAG_COMPARE_ROUTER_ID     (1 << 14)
#define BGP_CFLAG_ASPATH_IGNORE         (1 << 15)
#define BGP_CFLAG_NO_FAST_EXT_FAILOVER  (1 << 16)
#define BGP_CFLAG_NO_INBOUND_RT_FILTER  (1 << 17)
#define BGP_CFLAG_LOG_NEIGHBOR_CHANGES  (1 << 18)
#define BGP_CFLAG_COMPARE_CONFED_ASPATH (1 << 19)
#define BGP_CFLAG_MED_REMOVE_RCVD       (1 << 20)
#define BGP_CFLAG_MED_REMOVE_SEND       (1 << 21)
#define BGP_CFLAG_ROUTER_DELETE_IN_PROGRESS (1 << 22)
#define BGP_CFLAG_ECMP_ENABLE		(1 << 23)
#define BGP_CFLAG_PREFER_OLD_ROUTE	(1 << 24)
#define BGP_CFLAG_DONT_COMP_ORIG_ID	(1 << 25)

  /* BGP Instance Status Flags (all AFs) - For internal events */
  u_int32_t bgp_sflags;
#define BGP_SFLAG_NSM_ROUTER_ID         (1 << 6)

  /* BGP Instance per AF Configuration Flags */
  u_int32_t bgp_af_cflags [BAAI_MAX][BSAI_MAX];
#define BGP_AF_CFLAG_SYNCHRONIZATION          (1 << 0)
#define BGP_AF_CFLAG_NETWORK_SYNC             (1 << 1)
#define BGP_AF_CFLAG_AUTO_SUMMARY             (1 << 2)

  /* BGP Instance per AF Status Flags - For internal events */
  u_int32_t bgp_af_sflags [BAAI_MAX][BSAI_MAX];
#define BGP_AF_SFLAG_TABLE_ANNOUNCED                (1 << 0)

  /* BGP Route Flap Dampening Control Block */
  struct bgp_rfd_cfg *rfd_cfg [BAAI_MAX][BSAI_MAX];

  /* Static route configuration */
  struct bgp_ptree *route [BAAI_MAX][BSAI_MAX];

  /* Aggregate address configuration */
  struct bgp_ptree *aggregate [BAAI_MAX][BSAI_MAX];

  /* BGP routing information base */
  struct bgp_ptree *rib [BAAI_MAX][BSAI_MAX];

  /* BGP redistribute configuration */
  u_int8_t redist [BAAI_MAX][IPI_ROUTE_MAX];

  /* BGP redistribute route-map */
  struct bgp_rmap rmap [BAAI_MAX][IPI_ROUTE_MAX];

  /* BGP table version */
  u_int32_t table_version [BAAI_MAX][BSAI_MAX];

  /* BGP distance configuration, and the default values are 0 */
  u_int8_t distance_ebgp [BAAI_MAX][BSAI_MAX];
  u_int8_t distance_ibgp [BAAI_MAX][BSAI_MAX];
  u_int8_t distance_local [BAAI_MAX][BSAI_MAX];

  /* BGP distance table */
  struct bgp_ptree *distance_table;

  /* BGP default local-preference */
  u_int32_t default_local_pref;

  /* BGP default timer */
  u_int16_t default_holdtime;
  u_int16_t default_keepalive;

  /* Peer Index vector */
  vector peer_index [BAAI_MAX][BSAI_MAX];

  /* BGP Server (Listen) Socket Threads List */
  struct bgp_listen_sock_lnode *listen_sock_lnode;

  /* BGP Network Scan Interval */
  u_int16_t network_scan_interval;

  /* BGP total count of selected routes per AFI */
  u_int32_t selrt_count[BAAI_MAX];

  /* AFI based Nexthop count for all BGP selected routes. */
  u_int32_t nhop_count[BAAI_MAX];

  /* BGP Network Scan Thread */
  struct thread *t_network_scan;

  /* BGP nexthop tree having nexthops of
   * selected BGP routes.
   */
  struct bgp_ptree *nh_tab[BAAI_MAX];

  /* BGP convergence */
  u_int16_t neighbors_converged;
  u_int16_t conv_complete;

#define BGP_MAXPATH_SUPPORTED	64	
#define BGP_DEFAULT_MAXPATH_ECMP 1
  /* ECMP MULTIPATH */
  u_int16_t maxpath_ebgp;
  u_int16_t maxpath_ibgp;
  u_int16_t cfg_maxpath_ebgp;
  u_int16_t cfg_maxpath_ibgp;
#define BGP_LOCAL_AS_COUNT_MAX  64
  /* as-local-count: default is 1 */
  u_int16_t aslocal_count;
};

/* BGP Peer-Group structure */
struct bgp_peer_group
{
  /* Peer-Group Name */
  u_int8_t *name;

  /* Owining BGP structure  */
  struct bgp *bgp;

  /* Peer-group client list. */
  struct list *peer_list;

  /* Peer-group config */
  struct bgp_peer *conf;

#define BGP_MAX_PEERS_PER_GRP 32
  /* Peer ID bitmap */
  u_int32_t peer_bitmap;

  /* Number of peers in this group */
  s_int16_t num;
};

/* Next hop self address. */
struct bgp_nexthop
{
  struct interface *ifp;
  struct pal_in4_addr v4;
#ifdef HAVE_IPV6
  struct pal_in6_addr v6_global;
  struct pal_in6_addr v6_local;
#endif /* HAVE_IPV6 */
};

/* BGP Router Distinguisher IP-Type */
struct bgp_rd_ip
{
  u_int16_t rd_type;
  u_int8_t rd_ipval[4];
  u_int16_t rd_ipnum;
};

/* BGP Router Distinguisher AS-Type */
struct bgp_rd_as
{
  u_int16_t rd_type;
  u_int16_t rd_asval;
  u_int32_t rd_asnum;
};

/* BGP Router Distinguisher 4-octect-AS-Type */
struct bgp_rd_as4
{
  u_int16_t rd_type;
  u_int32_t rd_asval4;
  u_int16_t rd_asnum4;
}__attribute__((__packed__));


/* BGP router distinguisher value */
struct bgp_rd
{
  union {
    u_int8_t rd_val[BGP_RD_SIZE];
    struct bgp_rd_as rd_as;
    struct bgp_rd_as4 rd_as4;
    struct bgp_rd_ip rd_ip;
  } u;
#define brd_val   u.rd_val
#define brd_type  u.rd_as.rd_type
#define brd_ip    u.rd_ip.rd_ipval
#define brd_ipnum u.rd_ip.rd_ipnum
#define brd_as    u.rd_as.rd_asval
#define brd_asnum u.rd_as.rd_asnum
#define brd_as4    u.rd_as4.rd_asval4
#define brd_asnum4 u.rd_as4.rd_asnum4
};

/* BGP VRF Route-Distinguisher Node */
struct bgp_rd_node
{
  /* Node lock count */
  u_int32_t lock;

  /* Route-Distinguisher value */
  struct bgp_rd rd;

  /* Associated VRF-ID */
  vrf_id_t vrf_id;

  /* ==> bgp->rib[BAAI_IP][BSAI_UNICAST] */
  struct bgp_ptree *rib;

  struct bgp *bgp;
};

/* BGP filter structure. */
struct bgp_filter
{
  /* Distribute-list.  */
  struct
  {
    u_int8_t *name;
    struct access_list *alist;
  } dlist[FILTER_MAX];

  /* Prefix-list.  */
  struct
  {
    u_int8_t *name;
    struct prefix_list *plist;
  } plist[FILTER_MAX];

  /* AS-list.  */
  struct
  {
    u_int8_t *name;
    struct as_list *aslist;
  } aslist[FILTER_MAX];

  /* Route-map.  */
  struct bgp_rmap map[FILTER_MAX];

  /* Unsuppress-map.  */
  struct bgp_rmap usmap;
};

/* BGP Peer Adj_RIBs_out index */
struct bgp_peer_index
{
  /* Index of the peer.  */
  u_int32_t val;

  /* Offset to use bit comparison.  */
  u_int8_t offset;

  /* Mask of this peer index.  */
  u_int8_t mask;
};

struct bgp_peer_flag_action
{
  /* Peer's flag.  */
  u_int32_t flag;

  /* This flag can not be set for peer-group member.  */
  u_char not_for_member;

  /* Action when the flag is changed.  */
  enum bgp_peer_change_type type;
};

/* BGP Peer Notification Information */
struct bgp_peer_notify_info
{
  u_int16_t not_err_code;
  u_int16_t not_err_sub_code;
  bool_t not_err_dir_sent; 
  u_int32_t not_err_dlen;
  u_int8_t not_err_data[1];
};

/* BGP node list to be used by same peer 
 * in multiple view 
*/
struct peer_bgp_node
{
  u_int8_t afc[BAAI_MAX][BSAI_MAX];

  struct bgp *bgp;
  /* Filters on a peer per view */
  struct bgp_filter filter[BAAI_MAX][BSAI_MAX];
};

/* BGP neighbor structure. */
struct bgp_peer
{
  /* BGP structure.  */
  struct bgp *bgp;
  /* master bgp is used in multi-instance allow same peer
   * this instance on which the timer are running */
  struct bgp * master_bgp;

  /* BGP peer group.  */
  struct bgp_peer_group *group;
  u_int8_t af_group [BAAI_MAX][BSAI_MAX];

  /* Peer's remote AS number. */
  as_t as; 

  /* Peer's local AS number. */
  as_t local_as; 

  /* Remote router ID. */
  struct pal_in4_addr remote_id;

  /* Local router ID. */
  struct pal_in4_addr local_id;

  /* BGP Peer Notify Data */
  struct bgp_peer_notify_info *notify_info;

  /* BGP list for Route-Server */
  struct list *peer_bgp_node_list;

  /* BGP node for Route-Server in the context of view */
  struct peer_bgp_node *pbgp_node_inctx;

  /* BGP Peer Incoming Peer Connections list */
  struct list *clones_list;

  /* BGP Peer Owning Real-Peer (valid if Clone) */
  struct bgp_peer *real_peer;

  /* BGP Peer Stream Socket CB */
  struct stream_sock_cb *sock_cb;

  /* BGP Peer TCP connection TTL */
  u_int8_t ttl;

  /* BGP Peer is on same shared network */
  u_int8_t shared_network;

  /* BGP Peer Port Number */
  u_int16_t sock_port;

  u_int16_t sock_remote_port;

  /* Peer information */
  u_int8_t *desc;               /* Description of the peer. */
  u_int8_t *host;               /* Printable address of the peer. */
  union sockunion su;           /* Sockunion address of the peer. */
  pal_time_t uptime;            /* Last Up/Down time */
  pal_time_t last_reset_time;   /* Last Reset time */

  u_int8_t *ifname;             /* bind interface name. */
  u_int8_t *update_if;
  union sockunion *update_source;
  struct zlog *log;
  u_int8_t version;             /* Peer BGP version. */

  union sockunion *su_local;    /* Sockunion of local address.  */
  union sockunion *su_remote;   /* Sockunion of remote address.  */
  struct bgp_nexthop nexthop;   /* Nexthop */

  /* BGP Peer FSM State */
  u_int32_t bpf_state;

  /* BGP Peer FSM ConnectRetryCounter */
  u_int32_t bpf_conn_retry_count;

  /* BGP peer used in multiple views */
  u_int32_t refcnt;

  /* Peer address family configuration. */
  u_int8_t afc [BAAI_MAX][BSAI_MAX];
  u_int8_t afc_nego [BAAI_MAX][BSAI_MAX];
  u_int8_t afc_adv [BAAI_MAX][BSAI_MAX];
  u_int8_t afc_recv [BAAI_MAX][BSAI_MAX];

  /* Peer index information for each address family.  */
  struct bgp_peer_index index [BAAI_MAX][BSAI_MAX];

  /* Capability Flags.*/
  u_int32_t cap;
#define PEER_CAP_REFRESH_ADV                (1 << 0) /* refresh advertised */
#define PEER_CAP_REFRESH_OLD_RCV            (1 << 1) /* refresh old received */
#define PEER_CAP_REFRESH_NEW_RCV            (1 << 2) /* refresh rfc received */
#define PEER_CAP_DYNAMIC_ADV                (1 << 3) /* dynamic advertised */
#define PEER_CAP_DYNAMIC_RCV                (1 << 4) /* dynamic received */
#define PEER_CAP_NONE_RCV                   (1 << 5) /* No capability received */
#define PEER_CAP_EXTENDED_ASN_ADV           (1 << 6) /* Extended ASN Capability advertised */
#define PEER_CAP_EXTENDED_ASN_RCV           (1 << 7) /* Extended ASN Capability received */ 
  /* Per AF Capability Flags */
  u_int16_t af_cap [BAAI_MAX][BSAI_MAX];
#define PEER_CAP_ORF_PREFIX_SM_ADV          (1 << 0) /* send-mode advertised */
#define PEER_CAP_ORF_PREFIX_RM_ADV          (1 << 1) /* receive-mode advertised */
#define PEER_CAP_ORF_PREFIX_SM_RCV          (1 << 2) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_RCV          (1 << 3) /* receive-mode received */
#define PEER_CAP_ORF_PREFIX_SM_OLD_RCV      (1 << 4) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_OLD_RCV      (1 << 5) /* receive-mode received */

u_int32_t dyn_cap_flags;
#define PEER_CAP_MP_NEW_DYN_CAP_RCV         (1 << 0) /* Multi- protocol dynamic capabilty received*/
#define PEER_CAP_REFRESH_OLD_DYN_CAP_RCV    (1 << 1) /* refresh old dynamic capability received */
#define PEER_CAP_REFRESH_NEW_DYN_CAP_RCV    (1 << 2) /* refresh rfc dynamic capability received */

  /* Peer-level (all AFs) configuration flags */
  u_int32_t flags;
#define PEER_FLAG_PASSIVE                   (1 << 0) /* passive mode */
#define PEER_FLAG_SHUTDOWN                  (1 << 1) /* shutdown */
#define PEER_FLAG_DONT_CAPABILITY           (1 << 2) /* dont-capability */
#define PEER_FLAG_OVERRIDE_CAPABILITY       (1 << 3) /* override-capability */
#define PEER_FLAG_STRICT_CAP_MATCH          (1 << 4) /* strict-match */
#define PEER_FLAG_NO_ROUTE_REFRESH_CAP      (1 << 5) /* route-refresh */
#define PEER_FLAG_DYNAMIC_CAPABILITY        (1 << 6) /* dynamic capability */
#define PEER_FLAG_ENFORCE_MULTIHOP          (1 << 7) /* enforce-multihop */
#define PEER_FLAG_COLLIDE_ESTABLISHED       (1 << 8) /* Estab state Collision Detect */
#define PEER_FLAG_NO_IF_BINDING             (1 << 9) /* No Interfaces bound to BGP Instance */
#define PEER_FLAG_IN_GROUP                  (1 << 10) /* peer-group conf */
#define PEER_FLAG_GROUP_IN_VRF              (1 << 11) /* peer-group is in VRF */
#define PEER_FLAG_6PE_ENABLED               (1 << 12) /* peer is 6pe Enabled */
#define PEER_DISALLOW_INFINITE_HOLD_TIME    (1 << 13) /* peer-disallow-infinite-hold-time */
#define PEER_FLAG_RECV_EOR_UPDATE           (1 << 14) /* EOR update recieved */
#define PEER_FLAG_LOCAL_AS                  (1 << 16) /* Local-AS override */
#define PEER_FLAG_VERSION_CHECK             (1 << 17) /* Bgp Version check */

  /* Per AF Configuration Flags */
  u_int32_t af_flags [BAAI_MAX][BSAI_MAX];
#define PEER_FLAG_SEND_COMMUNITY            (1 << 0) /* send-community */
#define PEER_FLAG_SEND_EXT_COMMUNITY        (1 << 1) /* send-community ext. */
#define PEER_FLAG_NEXTHOP_SELF              (1 << 2) /* next-hop-self */
#define PEER_FLAG_REFLECTOR_CLIENT          (1 << 3) /* reflector-client */
#define PEER_FLAG_RSERVER_CLIENT            (1 << 4) /* route-server-client */
#define PEER_FLAG_SOFT_RECONFIG             (1 << 5) /* soft-reconfiguration */
#define PEER_FLAG_AS_PATH_UNCHANGED         (1 << 6) /* transparent-as */
#define PEER_FLAG_NEXTHOP_UNCHANGED         (1 << 7) /* transparent-next-hop */
#define PEER_FLAG_MED_UNCHANGED             (1 << 8) /* transparent-med */
#define PEER_FLAG_DEFAULT_ORIGINATE         (1 << 9) /* default-originate */
#define PEER_FLAG_REMOVE_PRIVATE_AS         (1 << 10) /* remove-private-as */
#define PEER_FLAG_ALLOWAS_IN                (1 << 11) /* set allowas-in */
#define PEER_FLAG_ORF_PREFIX_SM             (1 << 12) /* orf capability send-mode */
#define PEER_FLAG_ORF_PREFIX_RM             (1 << 13) /* orf capability receive-mode */
#define PEER_FLAG_MAX_PREFIX_WARNING        (1 << 14) /* maximum prefix warning-only */
#define PEER_FLAG_AS_OVERRIDE               (1 << 15) /* AS override  */
#define PEER_FLAG_SITE_ORIGIN               (1 << 16) /* set site-origin */
#define PEER_FLAG_EBGP_VPN_ALLOW            (1 << 18) /* Allow EBGP VPN */

  /* Peer-level (all AFs) Status Flags */
  u_int32_t sflags;
#define PEER_STATUS_PREFIX_OVERFLOW         (1 << 0) /* prefix-overflow */
#define PEER_STATUS_CAPABILITY_OPEN         (1 << 1) /* capability open send */
#define PEER_STATUS_SOFT_RESET_IN           (1 << 2) /* Soft-reset In */
#define PEER_STATUS_SOFT_RESET_OUT          (1 << 3) /* Soft-reset Out */
#define PEER_STATUS_CAP_ROUTE_REFRESH       (1 << 4) /* Capability RR modification */
#define PEER_STATUS_CONV_FOR_IGP            (1 << 5) /* Conv. status for IGP */

  /* Per AF Status Flags */
  u_int16_t af_sflags [BAAI_MAX][BSAI_MAX];
#define PEER_STATUS_ORF_PREFIX_SEND         (1 << 0) /* prefix-list send peer */
#define PEER_STATUS_ORF_WAIT_REFRESH        (1 << 1) /* wait refresh received peer */
#define PEER_STATUS_ORF_NOT_WAIT_REFRESH    (1 << 2) /* not waiting refresh */
#define PEER_STATUS_AF_DEFAULT_ORIGINATE    (1 << 3) /* default-originate peer */
#define PEER_STATUS_AF_SOFT_RESET_IN        (1 << 4) /* Soft-reset In */
#define PEER_STATUS_AF_SOFT_RESET_OUT       (1 << 5) /* Soft-reset Out */
#define PEER_STATUS_AF_ROUTE_REFRESH_SEND   (1 << 7) /* Send Route-Refresh */
#define PEER_STATUS_AF_ROUTE_REFRESH_RCVD   (1 << 8) /* Received Route-Refresh */
#define PEER_STATUS_AF_ASORIG_ROUTE_ADV     (1 << 9) /* Advt. AS-Origin Routes */

  /* Default attribute value for the peer. */
  u_int32_t config;
#define PEER_CONFIG_TIMER                   (1 << 1) /* keepalive & holdtime */
#define PEER_CONFIG_CONNECT                 (1 << 2) /* connect */
#define PEER_CONFIG_ASORIG                  (1 << 3) /* route advertise */
#define PEER_CONFIG_ROUTEADV                (1 << 4) /* route advertise */
#define PEER_CONFIG_PASSWORD                (1 << 5) /* MD5 password.  */
#define PEER_CONFIG_ROUTEADV_IMMEDIATE      (1 << 9) /* route advertise
                                                        immediate. */
  u_int32_t weight [BAAI_MAX][BSAI_MAX];
  u_int32_t holdtime;
  u_int32_t keepalive;
  u_int32_t connect;
  u_int32_t asorig;
  u_int32_t routeadv;

  /* BGP Peer MD5 Auth setting */
  u_int8_t password_type;
  u_int8_t *password;

  /* BGP Peer FSM Timer values */
  u_int32_t v_auto_start;
  u_int32_t v_connect;
  u_int32_t v_holdtime;
  u_int32_t v_keepalive;
  u_int32_t v_asorig;
  u_int32_t v_routeadv;
  u_int32_t v_gshut_time;

  /* BGP Peer FSM Timer Threads */
  struct thread *t_auto_start;
  struct thread *t_connect;
  struct thread *t_holdtime;
  struct thread *t_keepalive;
  struct thread *t_asorig;
  struct thread *t_routeadv;
  struct thread *t_gshut_timer;

  /* Statistics fields */
  u_int32_t open_in;            /* Open message input count */
  u_int32_t open_out;           /* Open message output count */
  u_int32_t update_in;          /* Update message input count */
  u_int32_t update_out;         /* Update message ouput count */
  u_int32_t keepalive_in;       /* Keepalive input count */
  u_int32_t keepalive_out;      /* Keepalive output count */
  u_int32_t notify_in;          /* Notify input count */
  u_int32_t notify_out;         /* Notify output count */
  u_int32_t refresh_in;         /* Route Refresh input count */
  u_int32_t refresh_out;        /* Route Refresh output count */
  u_int32_t dynamic_cap_in;     /* Dynamic Capability input count.  */
  u_int32_t dynamic_cap_out;    /* Dynamic Capability output count.  */

  /* BGP state count */
  u_int32_t established;        /* Established */
  u_int32_t dropped;            /* Dropped */

  /* BGP peer ID in the peer group */
  s_int32_t peer_id;

  /* BGP Peer Advertisement lists for non-AS-Origin routes */
  struct bgp_peer_adv_list *adv_list [BAAI_MAX][BSAI_MAX];

  /* BGP Peer Advertisement lists for AS-Origination routes */
  struct bgp_peer_adv_list *asorig_adv_list [BAAI_MAX][BSAI_MAX];

  /* BGP Peer Advertisement lists for non-AS-Origin routes */
  struct bgp_peer_adv_list *adv_list_new [BAAI_MAX][BSAI_MAX];

  /* BGP Peer Advertisement lists for AS-Origination routes */
  struct bgp_peer_adv_list *asorig_adv_list_new [BAAI_MAX][BSAI_MAX];

  /* Current advertisement in the same attribute */
  struct bgp_advertsise *curr_adv [BAAI_MAX][BSAI_MAX];
  struct bgp_advertsise *curr_asorig [BAAI_MAX][BSAI_MAX];

  /* Update message received time */
  pal_time_t update_time;

  /* BGP Peer Previous Advertisement Time */
  pal_time_t advtime;

  /* Send prefix count. */
  u_int32_t scount [BAAI_MAX][BSAI_MAX];

  /* BGP Peer Advertisement Attribute Hash Table */
  struct hash *baa_hash [BAAI_MAX][BSAI_MAX];

  /* Filter structure. */
  struct bgp_filter filter [BAAI_MAX][BSAI_MAX];

  /* ORF Prefix-list */
  struct prefix_list *orf_plist [BAAI_MAX][BSAI_MAX];

  /* Prefix count. */
  u_int32_t pcount [BAAI_MAX][BSAI_MAX];

  /* Table version.  */
  u_int32_t table_version [BAAI_MAX][BSAI_MAX];

  /* BGP Peer Maximum Acceptable Prefix Limit */
  u_int32_t pmax [BAAI_MAX][BSAI_MAX];

  /* BGP Peer Maximum Acceptable Prefix Warning Threshold */
  u_int32_t threshold [BAAI_MAX][BSAI_MAX];

  /* allowas-in. */
  u_int8_t allowas_in [BAAI_MAX][BSAI_MAX];

  /* FIFO of Decoded UPDATE Messges Info. */
  struct fifo bdui_fifo;

  /* FIFO of Incoming Connection Requests */
  struct fifo bicr_fifo;

  /* default-originate route-map.  */
  struct bgp_rmap default_rmap [BAAI_MAX][BSAI_MAX];

  /* to check whether a default-originated route
     is already sent to this peer.
     if sent this variable will be PAL_TRUE
     else it will be PAL_FALSE.
  */
  bool_t def_orig_route_sent;
};

/* BGP RIB information */
struct bgp_info
{
  /* For doubly linked list.  */
  struct bgp_info *next;
  struct bgp_info *prev;

  /* Type of this route.  */
  u_int8_t type;

  /* Sub type for BGP routes.  */
  u_int8_t sub_type;
#define BGP_ROUTE_NORMAL          (0)
#define BGP_ROUTE_STATIC          (1)
#define BGP_ROUTE_DEFAULT         (2)
#define BGP_ROUTE_AGGREGATE       (3)

  /* Selected route flag for calculate deterministic MED.  */
  u_int8_t as_selected;

  /* BGP info status.  */
  u_int8_t flags;
#define BGP_INFO_IGP_CHANGED      (1 << 0)
#define BGP_INFO_SELECTED         (1 << 1)
#define BGP_INFO_NHOP_VALID       (1 << 2)
#define BGP_INFO_ATTR_CHANGED     (1 << 3)
#define BGP_INFO_SYNCHRONIZED     (1 << 6)
#define BGP_INFO_UNSYNCHRONIZED   (1 << 7)

  /* Pointer to peer structure.  */
  struct bgp_peer *peer;

  /* Pointer to attributes structure.  */
  struct attr *attr;

  /* Aggregate related information.  */
  u_int32_t suppress;

  /* IGP metric value for route selection.  */
  u_int32_t igpmetric;

  /* Tag */
  u_int32_t tag;

  /* BGP RtInfo Uptime (time-stamp when created) */
  pal_time_t bri_uptime;

  /* Pointer to dampening structure.  */
  struct bgp_rfd_hist_info *rfd_hinfo;

 /* back pointer to aggregated node info */
  struct bgp_aggregate* riagg;

  /* Miscellaneous flags related to route.
   * Currently using for 6PE and NHT features.
  */
  u_int8_t flags_misc;
#define BGP_INFO_MULTI_INSTALLED      (1 << 2)    /* Multipath candidate and  installed */
#define BGP_INFO_ECMP_MULTI_CANDIDATE  (1 << 3) /* ECMP multipath candidate only */
#define BGP_INFO_RMAP_NEXTHOP_APPLIED (1 << 4)

#ifdef HAVE_BGP_SDN
#define BGP_INFO_MULTI_POST	(1 << 5)
#endif

};

/* A temporary list sorted bgp_info pointers for ECMP handling */
#define BGP_MAX_MPATH 256	
struct bgp_info_sort
{
  u_int32_t mpath_count;
  struct bgp_info * sort_list[BGP_MAX_MPATH];
};
 
/* BGP NLRI List Definition */
struct bgp_nlri
{
  /* Information valid */
  bool_t ni_present;

  /* AFI */
  afi_t ni_afi;

  /* SAFI */
  safi_t ni_safi;
  u_int8_t dummy[1];

  /* Length of NLRI List */
  u_int32_t ni_length;

  /* NLRI data buffer */
  u_int8_t *ni_data;
};

/* BGP decoded UPDATE information */
struct bgp_dec_update_info
{
  /* FIFO of UPDATE Info. */
  struct fifo ui_fifo;

  /* Decoded Attribute Structure */
  struct attr *ui_attr;

  /* Decoded Withdrawn IPv4-Unicast NLRI */
  struct bgp_nlri ip_withdrawn;

  /* Decoded Advertised IPv4-Unicast NLRI */
  struct bgp_nlri ip_advertised;

  /* Decoded MP Unreach NLRI */
  struct bgp_nlri mp_unreach;

  /* Decoded MP Reach NLRI */
  struct bgp_nlri mp_reach;

  /* Decoded NLRI byte buffer */
  u_int8_t ui_nlri [1];
};

/* BGP Update NLRI Snap-shots */
struct bgp_nlri_snap_shot
{
  /* Length of Withdrawn NLRIs */
  u_int32_t withdrawn_len;

  /* CQueue Snap-shot of Withdrawn NLRIs */
  struct cqueue_buf_snap_shot withdrawn_cqbss;

  /* Length of Advertised NLRIs */
  u_int32_t advertised_len;

  /* CQueue Snap-shot of Advertised NLRIs */
  struct cqueue_buf_snap_shot advertised_cqbss;

  /* Length of MP-UnReach NLRIs */
  u_int32_t mp_unreach_len;

  /* AFI of MP-UnReach NLRIs */
  afi_t mp_unreach_afi;

  /* SAFI of MP-UnReach NLRIs */
  safi_t mp_unreach_safi;
  u_int8_t dummy1[1];

  /* CQueue Snap-shot of MP-UnReach NLRIs */
  struct cqueue_buf_snap_shot mp_unreach_cqbss;

  /* Length of MP-Reach NLRIs */
  u_int32_t mp_reach_len;

  /* AFI of MP-Reach NLRIs */
  afi_t mp_reach_afi;

  /* SAFI of MP-Reach NLRIs */
  safi_t mp_reach_safi;
  u_int8_t dummy2[1];

  /* CQueue Snap-shot of MP-Reach NLRIs */
  struct cqueue_buf_snap_shot mp_reach_cqbss;
};

/* BGP Peer Incoming Connection Request */
struct bgp_peer_inconn_req
{
  /* FIFO of Inconn Req.s */
  struct fifo icr_fifo;

  /* Incoming Connection Sock FD */
  pal_sock_handle_t icr_sock;

  /* Incoming Connection Port */
  u_int16_t icr_port;
  u_int8_t dummy[2];
};

/* ORF Choice */
struct bgp_cap_orf_choice
{
  u_int8_t orf_type;
  u_int8_t orf_mode;
};

/* ORF Capability Value-Field */
struct bgp_cap_orf
{
  u_int16_t afi;
  u_int8_t reserved;
  u_int8_t safi;
  u_int8_t num_orfs;
  struct bgp_cap_orf_choice orf_choice[1];
};

/* MP Capability Value-Field */
struct bgp_cap_mp
{
  u_int16_t afi;
  u_int8_t reserved;
  u_int8_t safi;
};

/* 4-octet ASN Capability Value-Field */
struct bgp_cap_as4ext
{
  u_int32_t as4ext;
};

/* BGP OPEN Message Optional Paramter-Capabilities */
struct bgp_capability
{
  u_int8_t cap_code;
  u_int8_t cap_len;

  union
  {
    struct bgp_cap_mp mp;
    struct bgp_cap_orf orf;
    struct bgp_cap_as4ext as4ext;
  } cap_val;
#define cap_mp cap_val.mp
#define cap_orf cap_val.orf
#define cap_as4ext cap_val.as4ext
};

struct  capbilitymessage
{
     u_int32_t seqno;
     union
    {
       u_int8_t init_ack:1;
       u_int8_t ack_request:1;
       u_int8_t reserved:5;
       u_int8_t action:1;
       u_int8_t action_header;
  } cap_header;
};



/* BGP Route-Map Community */
struct bgp_route_map_comm
{
  u_int8_t *brmc_name;
  bool_t brmc_exact;
};

/* BGP Route-Map Aggregator */
struct bgp_route_map_aggregator
{
#ifndef HAVE_EXT_CAP_ASN 
  as_t brma_as;
#else
  u_int16_t brma_as;
  as_t brma_as4;
#endif /* HAVE_EXT_CAP_ASN */
  u_int8_t pad [2];
  struct pal_in4_addr brma_address;
};

/* BGP Peer Finite State Machine Action Function Type */
typedef s_int32_t (*bpf_act_func_t) (struct bgp_peer *, u_int32_t);

/* Macros for Context-based execution */
#define BGP_LIB_GLOBAL        (BGP_LIB_GLOBAL_VAR)
#define BLG                   (*BGP_LIB_GLOBAL)
#define BGP_GLOBAL            (*((struct bgp_global *)(LIB_GLOB_GET_PROTO_GLOB (&BLG))))
#define BGP_SET_VR_CONTEXT(LIB_GLOB, BVR)                            \
  do {                                                               \
    LIB_GLOB_SET_VR_CONTEXT ((LIB_GLOB), ((BVR)->owning_ivr));       \
  } while (0)
#define BGP_GET_VR_CONTEXT(LIB_GLOB)                                 \
  ((struct bgp_vr *)(LIB_VR_GET_PROTO_VR                             \
                     (LIB_GLOB_GET_VR_CONTEXT (&BLG))))
#define BGP_VR                                                       \
  (*((struct bgp_vr *)(LIB_VR_GET_PROTO_VR                           \
                       (LIB_GLOB_GET_VR_CONTEXT (&BLG)))))

/* Macros to check BGP License Manager Variables */
#define IF_BGP_CAP(var)
#define BGP_CAP(var)                 (1)

#define BGP_CAP_HAVE_IPV6         BGP_CAP (have_ipv6)
#define IF_BGP_CAP_HAVE_IPV6      IF_BGP_CAP (have_ipv6)

/* Utility Macros */
#define BGP_MIN(A, B)         ((A) < (B) ? (A) : (B))
#define BGP_MAX(A, B)         ((A) > (B) ? (A) : (B))
#define BGP_UNREFERENCED_PARAMETER(PARAM) ((PARAM) = (PARAM))

/* Macro to convert AFI value to BGP-AFI-Array-Index value */
#define BGP_AFI2BAAI(AFI)     ((AFI) - 1)

/* Macro to convert BGP-AFI-Array-Index value to AFI value */
#define BGP_BAAI2AFI(BAAI)    ((BAAI) + 1)

/* Macro to convert SAFI value to BGP-SAFI-Array-Index value */
#define BGP_SAFI2BSAI(SAFI)   ((SAFI) - 1)

/* Macro to convert BGP-SAFI-Array-Index value to SAFI value */
#define BGP_BSAI2SAFI(BSAI)   ((BSAI) + 1)   

/* Macro to check BGP information is alive or not.  */
#define BGP_INFO_HOLDDOWN(BI)                                         \
  (! CHECK_FLAG ((BI)->flags, BGP_INFO_NHOP_VALID)                    \
   || BGP_RFD_RT_STATE_IS_HISTORY (BI)                                \
   || BGP_RFD_RT_STATE_IS_DAMPED (BI))

/* BGP Peer Direction String Macro */
#define BGP_PEER_DIR_STR(PEER) ((PEER)->real_peer ? "Incoming" : "Outgoing")

/* BGP Route-Origin Type To Short-String Macro */
#define BGP_ORIGIN_STR(ORIGIN)                                        \
  ((ORIGIN) == BGP_ORIGIN_IGP ? "i" :                                 \
   (ORIGIN) == BGP_ORIGIN_EGP ? "e" :                                 \
   (ORIGIN) == BGP_ORIGIN_INCOMPLETE ? "?" : "?")

/* BGP Route-Origin Type To Long-String Macro */
#define BGP_ORIGIN_LONG_STR(ORIGIN)                                   \
  ((ORIGIN) == BGP_ORIGIN_IGP ? "IGP" :                               \
   (ORIGIN) == BGP_ORIGIN_EGP ? "EGP" :                               \
   (ORIGIN) == BGP_ORIGIN_INCOMPLETE ? "incomplete" : "incomplete")

/* Macro to validate AFI value */
#ifdef HAVE_IPV6
#define BGP_AFI_VALID_CHECK(AFI)                                      \
  ((AFI) == AFI_IP                                                    \
   || (BGP_CAP_HAVE_IPV6 && (AFI) == AFI_IP6))
#else
#define BGP_AFI_VALID_CHECK(AFI)                                      \
  ((AFI) == AFI_IP)
#endif /* HAVE_IPV6 */

/* Macro to validate SAFI value */
#define BGP_SAFI_VALID_CHECK(SAFI)                                    \
  ((SAFI) == SAFI_UNICAST || (SAFI) == SAFI_MULTICAST) 

/* Macro to validate supported combination of AFI-SAFI */

#ifdef HAVE_IPV6
#define BGP_AFI_SAFI_SUPPORT_CHECK(AFI, SAFI)                         \
  (((AFI) == AFI_IP                                                   \
    && ((SAFI) == SAFI_UNICAST || (SAFI) == SAFI_MULTICAST))           \
   || (BGP_CAP_HAVE_IPV6 && (AFI) == AFI_IP6 && (SAFI) == SAFI_UNICAST))
#else
#define BGP_AFI_SAFI_SUPPORT_CHECK(AFI, SAFI)                         \
  ((AFI) == AFI_IP                                                    \
   && ((SAFI) == SAFI_UNICAST || (SAFI) == SAFI_MULTICAST))
#endif /* defined (HAVE_IPV6) */

/* Macro for Starting a Read Thread */
#define BGP_READ_ON(LIB_GLOB, THREAD, THREAD_ARG,                     \
                    THREAD_FUNC, SOCK_FD)                             \
do {                                                                  \
  if (! (THREAD))                                                     \
    (THREAD) = thread_add_read ((LIB_GLOB), (THREAD_FUNC),            \
                                (THREAD_ARG), (SOCK_FD));             \
} while (0)

/* Macro for Stopping a Read Thread */
#define BGP_READ_OFF(LIB_GLOB, THREAD)                                \
do {                                                                  \
  if (THREAD)                                                         \
    {                                                                 \
      thread_cancel ((THREAD));                                       \
      (THREAD) = NULL;                                                \
    }                                                                 \
} while (0)

/* Macro for timer turn on */
#define BGP_TIMER_ON(LIB_GLOB, THREAD, ARG, THREAD_FUNC, TIME_VAL)    \
do {                                                                  \
  if (!(THREAD))                                                      \
    (THREAD) = thread_add_timer ((LIB_GLOB), (THREAD_FUNC),           \
                                 (ARG), (TIME_VAL));                  \
} while (0)

/* Macro for timer turn off */
#define BGP_TIMER_OFF(THREAD)                                         \
do {                                                                  \
  if (THREAD)                                                         \
    {                                                                 \
      thread_cancel (THREAD);                                         \
      (THREAD) = NULL;                                                \
    }                                                                 \
} while (0)

/* Macro for BGP VRF Route-Distinguisher Comaprison */
#define BGP_RD_SAME(RD1, RD2)                                         \
  (! pal_mem_cmp ((RD1), (RD2), BGP_RD_SIZE))

/* Macro to check ASN is of mappable or not */
#define BGP_IS_AS4_MAPPABLE(x)                                        \
  ((x <= 65535)? 1 : 0)  

/* Macro used for auto-summary */
#define BGP_SET_PREFIX_LEN(S, P)                                      \
do {                                                                  \
  if (IN_CLASSA (S))                                                  \
    {                                                                 \
      (S) &= IN_CLASSA_NET;                                           \
      (P) = IN_CLASSA_PREFIXLEN;                                      \
    }                                                                 \
  else if (IN_CLASSB (S))                                             \
    {                                                                 \
      (S) &= IN_CLASSB_NET;                                           \
      (P) = IN_CLASSB_PREFIXLEN;                                      \
    }                                                                 \
  else if (IN_CLASSC (S))                                             \
    {                                                                 \
      (S)&= IN_CLASSC_NET;                                            \
      (P) = IN_CLASSC_PREFIXLEN;                                      \
    }                                                                 \
} while(0)

/* Macro to make IPV4 prefix */
#define BGP_ADDR_TO_PREFIXV4(P,A)                                     \
do {                                                                  \
  (P).family = AF_INET;                                               \
  (P).prefixlen = IPV4_MAX_BITLEN;                                    \
  (P).u.prefix4 = A;                                                  \
} while (0)

#ifdef HAVE_IPV6
/* Macro to make IPV6 prefix */
#define BGP_ADDR_TO_PREFIXV6(P,A)                                     \
do {                                                                  \
  (P).family = AF_INET6;                                              \
  (P).prefixlen = IPV6_MAX_BITLEN;                                    \
  (P).u.prefix6 = A;                                                  \
} while (0)
#endif /* HAVE_IPV6 */

/*
 * Function Prototype Declarations from bgp_show.c
 */
u_int32_t
bgp_config_write_redistribute (struct cli *,
                               struct bgp *,
                               afi_t,
                               safi_t,
                               u_int32_t *);
void
bgp_config_write_family_header (struct cli *,
                                afi_t, safi_t,
                                u_int32_t *);
void
bgp_config_write_network (struct cli *,
                          struct bgp *,
                          afi_t, safi_t,
                          u_int32_t *);
s_int32_t 
bgp_config_write_distance (struct cli *,
			   struct bgp *,
       			   afi_t, safi_t,
                           u_int32_t *);
void
bgp_config_write_peer (struct cli *,
                       struct bgp *,
                       struct bgp_peer *,
                       afi_t, safi_t);
void
route_vty_out_detail (struct cli *,
                      struct prefix *,
                      struct bgp_info *,
                      afi_t, safi_t);
s_int32_t
bgp_show_summary (struct cli *,
                  struct bgp *,
                  afi_t, safi_t,
                  bool_t *);
s_int32_t
bgp_show_line (struct cli *,
               struct prefix *,
               struct bgp_info *,
               u_int32_t,
               safi_t);
void
bgp_show_init (void);

/*
 * Function Prototype Declarations from bgp_cli.c
 */
afi_t
bgp_cli_mode_afi (struct cli *);
safi_t
bgp_cli_mode_safi (struct cli *);
afi_t
bgp_cli_str2afi (u_int8_t *);
safi_t
bgp_cli_str2safi (u_int8_t *);
s_int32_t
bgp_cli_str2proto (afi_t, u_int8_t *);
s_int32_t
bgp_cli_return (struct cli *, s_int32_t);
void
bgp_cli_init (void);
void
bgp_ecmp_cli_init(struct cli_tree *);

/*
 * Function Prototype Declarations from bgp_routemap.c
 */
s_int32_t
bgp_route_map_init (struct ipi_vr *);

/*
 * Function Prototype Declarations
 */

s_int32_t
bgp_option_set (u_int32_t);
s_int32_t
bgp_option_unset (u_int32_t);
s_int32_t
bgp_option_check (u_int32_t);

void
bgp_reset_all_peers (struct bgp *);
s_int32_t
bgp_router_id_validate (struct pal_in4_addr *);
s_int32_t
bgp_router_id_auto_get (struct bgp *);
s_int32_t
bgp_router_id_set (struct bgp *, struct pal_in4_addr *);
s_int32_t
bgp_router_id_unset (struct bgp *);
int
bgp_cluster_id_set (struct bgp *, struct pal_in4_addr *);
int
bgp_cluster_id_digit_set (struct bgp *, u_int32_t);
int
bgp_cluster_id_unset (struct bgp *);
int
bgp_timers_set (struct bgp *, u_int16_t, u_int16_t);
int
bgp_timers_unset (struct bgp *);
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
bgp_default_local_preference_set (struct bgp *, u_int32_t);
int
bgp_default_local_preference_unset (struct bgp *);
int
bgp_peer_cmp (struct bgp_peer *, struct bgp_peer *);
int
bgp_set_maxpath (bool_t setflag, struct bgp *bgp, int bgptype, int multipath);
int
bgp_unset_local_as_count(struct bgp *bgp, int count);
int
bgp_set_local_as_count(struct bgp *bgp, int count);
int
peer_af_flag_check (struct bgp_peer *, afi_t, safi_t, u_int32_t);
s_int8_t
peer_afc_set (struct bgp_peer *, afi_t, safi_t);
s_int8_t
peer_afc_unset (struct bgp_peer *, afi_t, safi_t);
void
peer_global_config_reset (struct bgp_peer *);
enum bgp_peer_type
peer_sort (struct bgp_peer *);
struct bgp_peer *
bgp_peer_new (bool_t);
struct bgp_peer *
bgp_peer_create (union sockunion *, struct bgp *,
                 as_t, as_t, afi_t, safi_t);
struct bgp_peer *
bgp_peer_create_clone (struct bgp_peer *);
void
bgp_peer_as_change (struct bgp_peer *, as_t);
s_int32_t
bgp_peer_activate_all (struct bgp *);
s_int32_t
bgp_peer_deactivate_all (struct bgp *);
s_int32_t
bgp_peer_fast_external_failover (struct bgp *,
                                 struct interface *, u_int32_t);
s_int32_t
bgp_peer_remote_as (struct bgp *,
                    union sockunion *,
                    as_t *, afi_t, safi_t);
s_int8_t
peer_afc_activate (struct bgp_peer *, afi_t, safi_t);
int
peer_activate (struct bgp *, struct bgp_peer *, afi_t, safi_t);
s_int8_t
peer_deactivate (struct bgp_peer *, afi_t, safi_t);
int
peer_group_af_check (struct bgp *, struct bgp_peer *,
                     afi_t, safi_t);
void
peer_group_config_reset (struct bgp_peer_group *);
bool_t
bgp_peer_orf_capability_active (struct bgp_peer *);
bool_t
bgp_peer_strict_cap_same (struct bgp_peer *);
void
bgp_peer_stop (struct bgp_peer *);
s_int32_t
bgp_peer_delete (struct bgp_peer *);
s_int32_t
bgp_peer_config_delete (struct bgp_peer *);
/* delete a peer from one view when it is 
 * present in multiple views
*/
s_int32_t
bgp_peer_del_in_multi_ins (struct bgp *,
                           struct bgp_peer *);
void
bgp_peer_lock (struct bgp_peer *);

void
bgp_peer_unlock (struct bgp_peer *);

struct peer_bgp_node *
bgp_peer_pbgp_node_inctx_get (struct bgp *, struct bgp_peer *);

s_int32_t
bgp_peer_group_cmp (struct bgp_peer_group *,
                    struct bgp_peer_group *);
int
bgp_peer_group_active (struct bgp_peer *);
struct bgp_peer_group *
bgp_peer_group_lookup (struct bgp *, u_int8_t *);
struct bgp_peer_group *
bgp_peer_group_get (struct bgp *, u_int8_t *);
s_int32_t
bgp_peer_group_remote_as (struct bgp *, u_int8_t *, as_t *);
s_int32_t
bgp_peer_group_delete (struct bgp_peer_group *);
s_int32_t
bgp_peer_group_remote_as_delete (struct bgp_peer_group *);
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
struct bgp *
bgp_create (as_t, u_int8_t *, struct ipi_vrf *);
void
bgp_distance_config_set (struct cli *, char *, char *, char *);
int
bgp_distance_config_unset(struct cli *, u_int32_t , u_int32_t, u_int32_t );
struct bgp *
bgp_lookup_default ();
struct bgp *
bgp_lookup_by_routerid (struct pal_in4_addr *);
struct bgp *
bgp_lookup_by_name (u_int8_t *);
struct bgp *
bgp_lookup_by_id (struct lib_globals *, u_int32_t);
struct bgp *
bgp_lookup_by_vrf_id (u_int32_t vr_id, vrf_id_t vrf_id);
struct bgp *
bgp_lookup (as_t, u_int8_t *);
s_int32_t
bgp_get (struct bgp **, as_t *, u_int8_t *); 
s_int32_t
bgp_delete (struct bgp *);
s_int32_t
bgp_config_delete (struct bgp *);
struct bgp_peer *
bgp_peer_search (struct bgp *, union sockunion *);
bool_t
peer_active (struct bgp_peer *peer);
bool_t
peer_active_nego (struct bgp_peer *peer);
void
peer_change_action (struct bgp_peer *, afi_t, safi_t,
                    enum bgp_peer_change_type, u_int32_t);
s_int32_t
peer_flag_action_set (struct bgp_peer_flag_action *, u_int32_t,
                      struct bgp_peer_flag_action *, u_int32_t);
void
peer_flag_modify_action (struct bgp_peer *, u_int32_t);
int
peer_flag_modify (struct bgp_peer *, u_int32_t, u_int32_t);
int
peer_flag_set (struct bgp_peer *, u_int32_t);
int
peer_flag_unset (struct bgp_peer *, u_int32_t);
int
peer_flag_check (struct bgp_peer *, u_int32_t);
int
peer_is_group_member (struct bgp_peer *, afi_t, safi_t);
int
peer_af_flag_modify (struct bgp_peer *, afi_t, safi_t,
                     u_int32_t, u_int32_t);
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
peer_disallow_hold_timer_set (struct bgp_peer *);
int
peer_disallow_hold_timer_unset (struct bgp_peer *);
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
void
peer_distribute_update (struct ipi_vr *,
                        struct access_list *,
                        struct filter_list *);
int
peer_prefix_list_set (struct bgp_peer *,
                      afi_t, safi_t,
                      u_int32_t, u_int8_t *);
int
peer_prefix_list_unset (struct bgp_peer *,
                        afi_t, safi_t, u_int32_t);
void
peer_prefix_list_update (void);
int
peer_aslist_set (struct bgp_peer *, afi_t, safi_t,
                 u_int32_t, u_int8_t *);
int
peer_aslist_unset (struct bgp_peer *,
                   afi_t, safi_t, u_int32_t);
void
peer_aslist_update (void);
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
s_int32_t
bgp_peer_clear (struct bgp_peer *);
int
peer_clear_soft (struct bgp_peer *, afi_t, safi_t, u_int32_t);
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
bgp_scan_time_set (struct bgp *, u_int32_t);
s_int32_t
bgp_scan_time_unset (struct bgp *);
s_int32_t
bgp_aggregate_addr_set (struct bgp *,
                        u_int8_t *,
                        afi_t, safi_t,
                        u_int32_t);
s_int32_t
bgp_aggregate_addr_unset (struct bgp *,
                          u_int8_t *,
                          afi_t, safi_t);

#ifdef HAVE_TCP_MD5SIG
int
peer_password_set (struct bgp_peer *, u_int8_t, u_int8_t *);
int
peer_password_unset (struct bgp_peer *);
#endif /* TCP_MD5SIG */
s_int8_t *
bgp_time_t2wdhms_str (pal_time_t, s_int8_t *, size_t);
s_int8_t *
bgp_sec2wdhms_str (pal_time_t, s_int8_t *, size_t);

s_int32_t
bgp_global_init (void);
void
bgp_global_delete (void);
void
bgp_terminate (void);
s_int32_t
bgp_vr_create (struct ipi_vr *);
s_int32_t
bgp_vr_delete (struct ipi_vr *);

#ifdef HAVE_EXT_CAP_ASN
s_int32_t
bgp_conf_ext_asn_cap (struct bgp *, u_int32_t, bool_t);
#endif /* HAVE_EXT_CAP_ASN */

/* BGP converge processing */
void bgp_check_peer_convergence (struct bgp *);


/* BGP auto-summary set/unset */
s_int32_t
bgp_auto_summary_update (struct bgp *bgp,
                         afi_t afi,
                         safi_t safi,
                         bool_t auto_summary_set);

/* BGP Local-AS set/unset */
s_int32_t
bgp_peer_set_local_as (struct bgp_peer *peer, as_t local_as);
s_int32_t
bgp_peer_unset_local_as (struct bgp_peer *peer);

s_int32_t
bgp_peer_g_shut_time_set (struct bgp_peer *, u_int32_t);
s_int32_t
bgp_peer_g_shut_time_unset (struct bgp_peer *);
s_int32_t
bgp_peer_g_shut (struct bgp_peer *, afi_t, safi_t,  bool_t);
s_int32_t
bgp_peer_g_neigh_shut (struct attr *,struct bgp_peer *);
s_int32_t
bgp_no_g_shut_cap (struct bgp *);
s_int32_t
bgp_router_g_shut (struct bgp *, safi_t);
s_int32_t
bgp_router_no_g_shut (struct bgp *);
s_int32_t
bgp_session_g_shut (struct bgp_peer *, afi_t, safi_t);
s_int32_t
bgp_session_no_g_shut (struct bgp_peer *);

#ifdef HAVE_BGP_SDN
void bgp_onion_stop (void);
int bgp_onion_init (void);
void bgp_delete_routerid (struct bgp *);
void bgp_post_routerid (struct bgp *);
s_int32_t bgp_curl_free (void *);
int bgp_send_url (struct bgp *, char *, int);
#endif /* HAVE_BGP_SDN */

#endif /* _BGPSDN_BGPD_H */
