/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */

#ifndef _MEMMGR_CONFIG_H
#define _MEMMGR_CONFIG_H


/*
 *  Represents each memory type, its description, and owner module
 */
struct mtype_info
    {
       unsigned int  id;               /* mtype id */
       unsigned int  owner;            /* owner module of this memory type */
       unsigned char *desc;            /* description memory type */
    };


/* memory type description strings */
#define  TMP_STR                "Temporary memory"
#define  HASH_STR               "Hash"
#define  HASH_INDEX_STR         "Hash index"
#define  HASH_BUCKET_STR        "Hash bucket"
#define  THREAD_MASTER_STR      "Thread master"
#define  THREAD_STR             "Thread"
#define  LINK_LIST_STR          "Link list"
#define  LIST_NODE_STR          "Link list node"
#define  BUFFER_STR             "Buffer"
#define  BUFFER_BUCKET_STR      "Buffer bucket"
#define  BUFFER_DATA_STR        "Buffer data"
#define  BUFFER_IOV_STR         "Buffer IOV"
#define  SHOW_STR               "Show"
#define  SHOW_PAGE_STR          "Show page"
#define  SHOW_SERVER_STR        "Show server"
#define  PREFIX_STR             "Prefix"
#define  PREFIX_IPV4_STR        "Prefix IPv4"
#define  PREFIX_IPV6_STR        "Prefix IPv6"
#define  ROUTE_TABLE_STR        "Route table"
#define  ROUTE_NODE_STR         "Route node"
#define  LS_TABLE_STR           "LS table"
#define  LS_NODE_STR            "LS node"
#define  LS_PREFIX_STR          "LS prefix"
#define  LS_QoS_RESOURCE_STR    "QoS resource"
#define  IF_DB_STR              "Interface database"
#define  VECTOR_STR             "Vector"
#define  VECTOR_INDEX_STR       "Vector index"

#define  SNMP_SUBTREE_STR       "SNMP subtree"
#define  SMUX_PASSWD_STR        "SMUX password"

/* Host configuration. */
#define  CONFIG_STR             "Host config"
#define  CONFIG_MOTD_STR        "Message of The Day"
#define  CONFIG_LOGIN_STR       "Host config login"
#define  CONFIG_PASSWD_STR      "Host config password"

#define  IMI_CLIENT_STR         "IMI Client"

#define  MEMORY_GLOBALS_STR     "Memory globals"

/* VTY */
#define  VTY_MASTER_STR         "VTY master"
#define  VTY_STR                "VTY"
#define  VTY_HIST_STR           "VTY history"
#define  VTY_PATH_STR           "VTY path"
#define  VTY_OUT_BUF_STR        "VTY output buffer"
#define  IF_STR                 "VTY if"
#define  CONNECTED_STR          "VTY connected"
#define  STREAM_STR             "Stream"
#define  STREAM_DATA_STR        "Stream data"
#define  STREAM_FIFO_STR        "Stream FIFO"

#define  LABEL_POOL_SERVER_STR  "Label pool server"
#define  LABEL_POOL_CLIENT_STR  "Label pool client"
#define  LABEL_POOL_GEN_LBL_STR "Label pool generic label"
#define  LABEL_POOL_LSET_STR    "Label pool label set node"

#define  SSOCK_CB_STR           "Stream sock CB"
#define  CQUEUE_BUF_STR         "Circular queue buf"

/* Access list */
#define  ACCESS_LIST_STR        "Access list"
#define  ACCESS_LIST_STR2       "Access list str"
#define  ACCESS_FILTER_STR      "Access filter"

/* Prefix list */
#define  PREFIX_LIST_STR        "Prefix list"
#define  PREFIX_LIST_STR_STR    "Prefix list str"
#define  PREFIX_LIST_ENTRY_STR  "Prefix list entry"
#define  PREFIX_LIST_DESC_STR   "Prefix list desc"

/* Route map */
#define  ROUTE_MAP_STR          "Route map"
#define  ROUTE_MAP_NAME_STR     "Route map name"
#define  ROUTE_MAP_INDEX_STR    "Route map index"
#define  ROUTE_MAP_RULE_STR     "Route map rule"
#define  ROUTE_MAP_RULE_STR_STR "Route map rule str"
#define  ROUTE_MAP_COMPILED_STR "Route map data"
#ifdef HAVE_PBR
#define PBR_NEXTHOP_STR             "Pbr nexthop"
#define PBR_STRING_STR              "Pbr string"
#define ROUTE_MAP_PBR_IF_STR        "Route map pbr interface"  
#endif /* HAVE_PBR */

/* Bit map */
#define  BITMAP_STR             "Bit map"
#define  BITMAP_BLOCK_STR       "Bit map block"
#define  BITMAP_BLOCK_ARRAY_STR "Bit map block array"
#define  STRING_BUFF_STR        "Flat string Buffer"

/* Ptree */
#define  PTREE_STR              "Patricia tree"
#define  PTREE_NODE_STR         "Patricia tree node"

/* AVL tree */
#define  AVL_TREE_STR           "Avl tree"
#define  AVL_TREE_NODE_STR      "Avl tree node"

/* Binary Heap */
#define BINARY_HEAP_STR         "Binary heap"
#define BINARY_HEAP_ARRAY_STR   "Binary heap array"

#define  VRF_NAME_STR           "VRF name"

/* Keys */
#define  KEYCHAIN_STR           "Key chain"
#define  KEYCHAIN_NAME_STR      "Key chain name"
#define  KEY_STR                "Key"
#define  KEY_STRING_STR         "Key string"

#define  RMM_STR                "RMM data block"
#define  RMM_MSG_STR            "RMM message"
#define  RMM_TMP_STR            "RMM dummy client"

#ifdef HAVE_TUNNEL
#define  TUNNEL_IF_STR          "Tunnel interface"
#endif

#ifdef HAVE_GMPLS
#define  GMPLS_IF_STR           "GMPLS interface"
#define  GMPLS_IF_DESC_STR      "GMPLS interface description"
#define  GMPLS_SRLG_STR         "GMPLS SRLG"
#define  GMPLS_DL_STR           "GMPLS Data Link"
#define  GMPLS_TEL_STR          "GMPLS TE Link"
#define  GMPLS_CC_STR           "GMPLS Control Channel"
#define  GMPLS_CADJ_STR         "GMPLS Control Adjacency"
#define  GMPLS_LINK_ID_STR      "GMPLS Link Identifier"
#define GMPLS_LINK_PROP_STR     "GMPLS Link Properties"
#define GMPLS_BIDIR_STR         "GMPLS Bidirectional LSP"

#endif

/* Messaging. */
#define  MESSAGE_ENTRY_STR      "Message entry"
#define  MESSAGE_HANDLER_STR    "Message handler"

/* NSM messaging. */
#define  NSM_MSG_NEXTHOP_IPV4_STR       "Nexthop IPv4 from NSM"
#define  NSM_MSG_NEXTHOP_IPV6_STR       "Nexthop IPv6 from NSM"
#define  NSM_CLIENT_HANDLER_STR         "NSM Client Handler"
#define  NSM_CLIENT_STR                 "NSM Client"

#define  NSM_SERVER_ENTRY_STR           "NSM server entry"
#define  NSM_SERVER_CLIENT_STR          "NSM server client"
#define  NSM_SERVER_STR                 "NSM server"
#define  NSM_PENDING_MSG_STR            "NSM pending message"
#define  NSM_MSG_LABEL_POOL_STR         "NSM service message label pool"

/* NSM Route table */
#define  NSM_PTREE_TABLE_STR            "NSM Tree table"
#define  NSM_PTREE_NODE_STR             "NSM Tree node"
#define  NSM_NEXTHOP_LOOKUP_REG_STR     "NSM nexthop lookup register"
#define  NSM_SNMP_ROUTE_ENTRY_STR       "NSM snmp route entry register"

/* NSM ARP Entry strings */
#define NSM_ARP_MASTER_STR              "NSM ARP Master"
#define NSM_ARP_STATIC_ENTRY_STR        "NSM ARP Static Entry"
#ifdef HAVE_IPV6
#define MTYPE_NSM_IPV6_STATIC_NBR_ENTRY_STR "NSM IPv6 Static Neighbor Entry"
#endif /* HAVE_IPV6 */

/* NSM redistribution */
#define  NSM_REDISTRIBUTE_STR           "NSM redistribution"

#define  RIP_STR                        "RIP structure"
#define  RIP_NAME_STR                   "RIP instance name"
#define  RIP_INFO_STR                   "RIP route info"
#define  RIP_IF_STR                     "RIP interface"
#define  RIP_IF_NAME_STR                "RIP interface name"
#define  RIP_IF_PARAMS_STR              "RIP interface params"
#define  RIP_PASSIVE_IF_STR             "RIP passive i/f"
#define  RIP_PEER_STR                   "RIP peer"
#define  RIP_OFFSET_LIST_STR            "RIP offset list"
#define  RIP_OFFSET_IF_NAME_STR         "RIP offset i/f name"
#define  RIP_OFFSET_ALIST_STR           "RIP offset alist name"
#define  RIP_DISTANCE_STR               "RIP distance"
#define  RIP_DISTANCE_ALIST_STR         "RIP distance alist name"
#define  RIP_RMAP_COMPILED_STR          "RIP route map data"
#define  RIP_RMAP_NAME_STR              "RIP route map name"
#define  RIP_AUTH_STRING_STR            "RIP auth string"
#define  RIP_KEY_CHAIN_STR              "RIP key chain"
#define  RIP_NEXTHOP_STR                "RIP next hop"

#define  RIPNG_STR                      "RIPng structure"
#define  RIPNG_NAME_STR                 "RIPng instance name"
#define  RIPNG_INFO_STR                 "RIPng route info"
#define  RIPNG_AGGREGATE_STR            "RIPng aggregate info"
#define  RIPNG_IF_STR                   "RIPng interface"
#define  RIPNG_IF_NAME_STR              "RIPng interface name"
#define  RIPNG_IF_PARAMS_STR            "RIPng interface params"
#define  RIPNG_NBR_STR                  "RIPng neighbor"
#define  RIPNG_NBR_IF_STR               "RIPng neighbor i/f name"
#define  RIPNG_PASSIVE_IF_STR           "RIPng passive i/f name"
#define  RIPNG_OFFSET_LIST_STR          "RIPng offset list"
#define  RIPNG_OFFSET_IF_NAME_STR       "RIPng offset i/f name"
#define  RIPNG_OFFSET_ALIST_STR         "RIPng offset alist name"
#define  RIPNG_RMAP_COMPILED_STR        "RIPng route map data"
#define  RIPNG_RMAP_NAME_STR            "RIPng route map name"
#define  RIPNG_DISTANCE_STR             "RIPng distance"
#define  RIPNG_DISTANCE_ALIST_STR       "RIPng distance alist name"

/* BGP */
#define  BGP_STR                        "BGP structure"
#define  BGP_VR_STR                     "BGP VR structure"
#define  BGP_GLOBAL_STR                 "BGP global structure"
#define  BGP_PEER_STR                   "BGP peer"
#define  BGP_PEER_CONF_STR              "BGP peer conf"
#define  BGP_PEER_GROUP_STR             "BGP peer group"
#define  BGP_PEER_NOTIFY_DATA_STR       "BGP peer notification data"
#define  BGP_ROUTE_STR                  "BGP RIB"
#define  BGP_STATIC_STR                 "BGP network"
#define  BGP_AGGREGATE_STR              "BGP aggregate"
#define  BGP_MPCAP_STR                  "BGP MP capability"
#define  BGP_ADJACENCY_STR              "BGP adjacency"
#define  BGP_ADVERTISE_STR              "BGP advertise"
#define  BGP_ADVERTISE_ATTR_STR         "BGP advertise attr"
#define  BGP_ADJ_IN_STR                 "BGP adj_in"
#define  ATTR_STR                       "BGP attribute"
#define  AS_PATH_STR                    "BGP aspath"
#define  AS_SEG_STR                     "BGP aspath seg"
#define  AS_STR_STR                     "BGP aspath str"
#define  COMMUNITY_STR                  "Community"
#define  COMMUNITY_VAL_STR              "Community val"
#define  COMMUNITY_STR_STR              "Community str"
#define  COMMUNITY_LIST_CONFIG_STR      "Community list config"
#define  COMMUNITY_LIST_NAME_STR        "Community list name"
#define  ECOMMUNITY_STR                 "Ext community"
#define  ECOMMUNITY_VAL_STR             "Ext community val"
#define  ECOMMUNITY_STR_STR             "Ext community str"
#define  CLUSTER_STR                    "Cluster"
#define  CLUSTER_VAL_STR                "Cluster val"
#define  TRANSIT_STR                    "BGP transit attr"
#define  TRANSIT_VAL_STR                "BGP transit val"
#define  AS_LIST_STR                    "BGP as list"
#define  AS_LIST_MASTER_STR             "BGP as list master"
#define  AS_FILTER_STR                  "BGP as filter"
#define  AS_FILTER_STR_STR              "BGP as filter str"
#define  COMMUNITY_LIST_HANDLER_STR     "Community list handler"
#define  COMMUNITY_LIST_STR             "Community list"
#define  COMMUNITY_LIST_ENTRY_STR       "Community list ent"
#define  COMMUNITY_REGEXP_STR           "Community reg exp"
#define  BGP_CONFED_LIST_STR            "Confederation list"
#define  BGP_DISTANCE_STR               "BGP distance"
#define  BGP_NEXTHOP_CACHE_STR          "BGP nexthop cache"
#define  BGP_RFD_HINFO_STR              "BGP Damp History Info"
#define  BGP_RFD_DECAY_ARRAY_STR        "BGP Damp Decay Array"
#define  BGP_RFD_REUSE_LIST_ARRAY_STR   "BGP Damp Reuse List Array"
#define  BGP_RFD_CB_STR                 "BGP Damp Control Block"
#define  BGP_RFD_CFG_STR                "BGP Damp Config Block"
#define  BGP_TABLE_STR                  "BGP table"
#define  BGP_NODE_STR                   "BGP node"
#define  BGP_WALKER_STR                 "BGP walker"
#define  PEER_UPDATE_SOURCE_STR         "BGP Peer Update Source"
#define  PEER_DESC_STR                  "BGP Peer Description"
#define  BGP_VRF_STR                    "BGP VRF list"
#define  BGP_DUMP_STR                   "BGP dump"
#define  BGP_MPLS_LABEL_REQ_STR         "BGP MPLS label req"
#ifdef HAVE_EXT_CAP_ASN
#define  AS4_PATH_STR                    "BGP as4path"
#define  AS4_SEG_STR                     "BGP as4path seg"
#define  AS4_STR_STR                     "BGP as4path str"
#endif /* HAVE_EXT_CAP_ASN */
#define  PEER_BGP_NODE_STR               "BGP peer bgp node"


#define  NSM_GLOBAL_STR                 "NSM Global"
#define  NSM_MASTER_STR                 "NSM Master"
#define  NSM_DESC_STR                   "NSM desc"
#define  NSM_RIB_STR                    "NSM RIB"
#define  NSM_VRF_STR                    "NSM VRF"
#define  NEXTHOP_STR                    "NSM Nexthop"
#define  NSM_STATIC_STR                 "NSM static"
#ifdef HAVE_BFD
#define  NSM_BFD_STATIC_STR             "NSM BFD static"
#endif /* HAVE_BFD */
#define  NSM_IF_STR                     "NSM interface"
#define  NSM_IFNAME_STR                 "NSM interface name"
#define  NSM_IF_PARAMS_STR              "NSM interface params"
#define  NSM_STAGGER_NODE_STR           "NSM stagger node"
#define  NSM_RESTART_OPTION_STR         "NSM restart option"
#define  NSM_MSG_QUEUE_STR              "NSM message queue"
#define  NSM_MSG_QUEUE_BUF_STR          "NSM message queue buffer"
#define  RTADV_STR                      "NSM Router Advertisement"
#define  RTADV_IF_STR                   "NSM Router Adv interface"
#define  RTADV_PREFIX_STR               "NSM Router Adv prefix"
#define  RTADV_HOME_AGENT_STR           "NSM Home agent"
#define  NSM_MPLS_STR                   "NSM MPLS"
#define  NSM_MPLS_IF_STR                "NSM MPLS interface"
#define  NSM_LABEL_SPACE_STR            "NSM Label space"
#define  NSM_QOS_IF_STR                 "NSM QoS interface"
#define  NSM_STATIC_DESCRIPTION         "NSM static description"

#ifdef HAVE_MPLS_VC
#define  NSM_VIRTUAL_CIRCUIT_STR        "NSM Virtual Circuit"
#define  NSM_VC_CONTAINER_STR           "NSM VC Container"
#define  NSM_VC_GROUP_STR               "NSM Virtual Circuit Group"
#define  NSM_VC_FIB_STR                 "NSM VC FIB Entry"
#define MTYPE_NSM_VC_PERF_CNTR_STR      "NSM VC Performance Counters"
#endif

#ifdef HAVE_VPLS
#define  NSM_VPLS_STR                   "NSM VPLS"
#define  NSM_VPLS_PEER_STR              "NSM VPLS Peer"
#define  NSM_VPLS_SPOKE_VC_STR          "NSM VPLS Spoke VC"
#endif

#define  NSM_LSP_DEP_CONFIRM_STR        "NSM LSP Dependency Confirm object"
#define  MTYPE_MPLS_BW_CLASS_STR        "MPLS BW Class"
#define  MPLS_CONFIRM_LIST_STR          "MPLS Confirm List object"
#define  MPLS_FTN_ENTRY_STR             "MPLS FTN Entry"
#define  MPLS_ILM_ENTRY_STR             "MPLS ILM Entry"
#define  MPLS_XC_ENTRY_STR              "MPLS XC Entry"
#define  MPLS_NHLFE_ENTRY_STR           "MPLS NHLFE Entry"
#define  MPLS_MAPPED_ROUTE_STR          "MPLS Mapped Route"
#define  MPLS_MAPPED_LSP_ENTRY_STR      "MPLS Mapped LSP Entry"
#define  NSM_MPLS_VRF_TABLE_STR         "MPLS VRF table entry"

#ifdef HAVE_BFD
#define  NSM_MPLS_BFD_CONF_STR              "MPLS BFD FEC Conf entry"
#endif /* HAVE_BFD */

#ifdef HAVE_HAL
#define  NSM_HAL_TLV_DECODE_STR         "NSM hal sub tlv decode entry"
#endif /* HAVE_HAL */

#if defined HAVE_MCAST_IPV4 || defined HAVE_IGMP_SNOOP
#define  IGMP_INST_STR                  "IGMP Instance"
#define  IGMP_SVC_REG_STR               "IGMP Service Reg"
#define  IGMP_SSM_MAP_STATIC_STR        "IGMP SSM-Map Static"
#define  IGMP_IF_STR                    "IGMP interface"
#define  IGMP_IF_IDX_STR                "IGMP interface idx"
#define  IGMP_GRP_REC_STR               "IGMP Group Record"
#define  IGMP_SRC_REC_STR               "IGMP Source Record"
#define  IGMP_SRC_LIST_STR              "IGMP Source List"
#define  IGMP_SNMP_VAR                  "IGMP SNMP Variable"
#endif /* HAVE_MCAST_IPV4 || HAVE_IGMP_SNOOP */

#ifdef HAVE_MCAST
#define  MCAST_GLOBALS_STR                 "MCAST globals"
#define  MCAST_MRIB_MSG_QUEUE_STR          "MCAST MRIB message queue"
#define  MCAST_MRIB_MSG_QUEUE_BUF_STR      "MCAST MRIB message queue buffer"
#define  MCAST_MRIB_MSG_PENDING_STR        "MCAST MRIB pending message"
#define  MCAST_MRIB_MSG_CLIENT_STR         "MCAST MRIB client"
#define  MCAST_MRIB_MSG_CLIENT_HANDLER_STR "MCAST MRIB client handler"
#define  MCAST_MRIB_MSG_SERVER_STR         "MCAST MRIB server"
#define  MCAST_MRIB_MSG_SERVER_ENTRY_STR   "MCAST MRIB server entry"
#define  MCAST_MRIB_MSG_SERVER_CLIENT_STR  "MCAST MRIB server client"
#ifdef HAVE_MCAST_IPV4
#define  MCAST4_IGMP_INST_STR           "MCAST4 IGMP Instance"
#define  MCAST4_IGMP_SVC_REG_STR        "MCAST4 IGMP Service Reg"
#define  MCAST4_IGMP_SSM_MAP_STATIC_STR "MCAST4 IGMP SSM-Map Static"
#define  MCAST4_IGMP_IF_STR             "MCAST4 IGMP interface"
#define  MCAST4_IGMP_IF_IDX_STR         "MCAST4 IGMP interface idx"
#define  MCAST4_IGMP_GRP_REC_STR        "MCAST4 IGMP Group Record"
#define  MCAST4_IGMP_SRC_REC_STR        "MCAST4 IGMP Source Record"
#define  MCAST4_IGMP_SRC_LIST_STR       "MCAST4 IGMP Source List"
#define  MCAST4_IGMP_SNMP_VAR           "MCAST4 IGMP SNMP Variable"
#ifdef HAVE_NSM
#define  NSM_MCAST_STR                  "NSM IPv4 Mcast entry"
#define  NSM_MCAST_VIF_STR              "NSM IPv4 Mcast Vif entry"
#define  NSM_MCAST_MRT_STR              "NSM IPv4 Mcast MRT entry"
#define  NSM_MCAST_MRT_OLIST_STR        "NSM IPv4 Mcast MRT olist"
#define  NSM_MCAST_ST_BLK_STR           "NSM IPv4 Mcast Stat block entry"
#define  NSM_MCAST_MRT_REG_STR          "NSM IPv4 Mcast MRT Register entry"
#define  NSM_MCAST_TUN_CONF_STR         "NSM IPv4 Mcast Tunnel configuration entry"
#define  NSM_MTRACE_STATE_STR           "NSM mtrace state entry"
#define  NSM_MTRACE_PKT_STR             "NSM mtrace pkt entry"
#endif /* HAVE_NSM */
#endif /* HAVE_MCAST_IPV4 */

#if defined HAVE_MCAST_IPV6 || defined HAVE_MLD_SNOOP
#define  MLD_INST_STR                   "MLD Instance"
#define  MLD_SVC_REG_STR                "MLD Service Reg"
#define  MLD_SSM_MAP_STATIC_STR         "MLD SSM-Map Static"
#define  MLD_IF_STR                     "MLD interface"
#define  MLD_IF_IDX_STR                 "MLD interface idx"
#define  MLD_GRP_REC_STR                "MLD Group Record"
#define  MLD_SRC_REC_STR                "MLD Source Record"
#define  MLD_SRC_LIST_STR               "MLD Source List"
#define  MLD_SNMP_VAR                   "MLD SNMP Variables"
#endif /* HAVE_MCAST_IPV6 || HAVE_MLD_SNOOP */

#ifdef HAVE_MCAST_IPV6
#define  MCAST6_MLD_INST_STR            "MCAST6 MLD Instance"
#define  MCAST6_MLD_SVC_REG_STR         "MCAST6 MLD Service Reg"
#define  MCAST6_MLD_SSM_MAP_STATIC_STR  "MCAST6 MLD SSM-Map Static"
#define  MCAST6_MLD_IF_STR              "MCAST6 MLD interface"
#define  MCAST6_MLD_IF_IDX_STR          "MCAST6 MLD interface idx"
#define  MCAST6_MLD_GRP_REC_STR         "MCAST6 MLD Group Record"
#define  MCAST6_MLD_SRC_REC_STR         "MCAST6 MLD Source Record"
#define  MCAST6_MLD_SRC_LIST_STR        "MCAST6 MLD Source List"
#define  MCAST6_MLD_SNMP_VAR            "MCAST6 MLD SNMP Variables"
#ifdef HAVE_NSM
#define  NSM_MCAST6_STR                 "NSM IPv6 Mcast entry"
#define  NSM_MCAST6_MIF_STR             "NSM IPv6 Mcast Mif entry"
#define  NSM_MCAST6_MRT_STR             "NSM IPv6 Mcast MRT entry"
#define  NSM_MCAST6_MRT_OLIST_STR       "NSM IPv6 Mcast MRT olist"
#define  NSM_MCAST6_ST_BLK_STR          "NSM IPv6 Mcast Stat block entry"
#define  NSM_MCAST6_MRT_REG_STR         "NSM IPv6 Mcast MRT Register entry"
#endif /* HAVE_NSM */
#endif /* HAVE_MCAST_IPV6 */
#endif /* HAVE_MCAST */

#define  NSM_MROUTE_CONFIG_STR          "NSM static multicast route config"
#define  NSM_MRIB_STR                   "NSM Multicast RIB"
#define  NSM_MNH_REG_STR                "NSM Multicast Nexthop Registration"
#define  NSM_MNH_REG_CL_STR             "NSM Multicast Nexthop Registration Client"

#define  STP_BRIDGE_STR                 "STP bridge"
#define  STP_BRIDGE_PORT_STR            "STP Port Instance"
#define  STP_INTERFACE_STR              "STP interface"

#define  GARP_GID_STR                   "GARP Group Id"
#define  GARP_GID_PORT_STR              "GARP Group Id Port"
#define  GARP_GID_MACHINE_STR           "GARP State Machine"
#define  GARP_GIP_STR                   "GARP GIP"
#define  NSM_L2_MCAST_STR               "NSM IPv4 Layer 2 Mcast entry"
#define  NSM_L2_MCAST_GRP_STR           "NSM IPv4 Layer 2 Mcast Group entry"
#define  NSM_L2_MCAST_SRC_STR           "NSM IPv4 Layer 2 Mcast Source entry"

#define  GMRP_STR                       "GMRP"
#define  GMRP_PORT_STR                  "GMRP Port"
#define  GMRP_PORT_INSTANCE_STR         "GMRP Port Instance"
#define  GMRP_PORT_CONFIG_STR           "GMRP Port config"
#define  GMRP_VLAN_STR                  "GMRP Vlan"
#define  GMRP_GMD_STR                   "GMRP GMD"
#define  GMRP_GMD_ENTRY_STR             "GMRP GMD Entry"

#define  GVRP_STR                       "GVRP"
#define  GVRP_PORT_STR                  "GVRP Port"
#define  GVRP_PORT_CONFIG_STR           "GVRP Port Config"
#define  GVRP_GVD_STR                   "GVRP Gvd"
#define  GVRP_GVD_ENTRY_STR             "GVRP Gvd Entry"
#define  GVRP_CONFIG_PORTS_STR          "GVRP Config Port"
#define  L2_SNMP_FDB_STR                "802.1 SNMP support"
#define  FLOW_CONTROL_ENTRY_STR         "802.3x flow control"
#define  PORT_MIRROR_ENTRY_STR          "Port mirroring"
#define  BCAST_SUPPRESS_ENTRY_STR       "Broadcast storm suppression"
#define  VLAN_DATABASE_STR              "VLAN Database"

#define  RSTP_BRIDGE_STR                "RSTP Bridge Instance"
#define  RSTP_BRIDGE_PORT_STR           "RSTP Port Instance"

#define  NSM_VLAN_CLASSIFIER_GROUP_STR  "VLAN Classifier Group"
#define  NSM_VLAN_CLASSIFIER_RULE_STR   "VLAN Classifier Rule"
#define  NSM_VLAN_CLASS_IF_GROUP_STR   "VLAN Classifier Interface Group"
#define  NSM_VLAN_CLASS_TMP_GROUP_STR   "VLAN Classifier Temporary Group"
#define  NSM_VLAN_CLASS_TMP_RULE_STR    "VLAN Classifier Temporary Rule"
#define  NSM_CVLAN_REG_TAB_STR          "C-VLAN Registration table"
#define  NSM_SVLAN_SW_CTX_STR           "S-VLAN Switching Contexts"
#define  NSM_VLAN_DBL_VID_KEY_STR       "Key with Double VIDs"
#define  NSM_VLAN_PRO_EDGE_SWCTX_STR    "Provider Edge Switching Context"
#define  NSM_VLAN_SVLAN_INFO_STR        "Provider Edge SVLAN Info"
#define  NSM_VLAN_SVLAN_PORT_INFO_STR   "Provider Edge SVLAN Port Info"
#define  NSM_VLAN_BITMAP_STR            "VLAN Bitmap"
#define  NSM_UNI_BW_PROFILE_STR         "UNI Bw profile info"
#define  NSM_INGRESS_UNI_BW_PROFILE_STR "Ingress UNI BW Profile info" 
#define  NSM_EGRESS_UNI_BW_PROFILE_STR  "Egress UNI BW Profile info"
#define  NSM_INGRESS_EVC_BW_PROFILE_STR "Ingress EVC BW Profile info"
#define  NSM_EGRESS_EVC_BW_PROFILE_STR  "Egress EVC BW Profile info"
#define  NSM_INGRESS_EVC_COS_BW_PROFILE  "Ingress COS BW Profile info"
#define  NSM_EGRESS_EVC_COS_BW_PROFILE  "Egress COS BW Profile info"
#define  NSM_UNI_EVC_BW_PROFILE_STR     "UNI EVC BW profile info"  

#define  EFM_EVLOG_STR                  "EFM Event Log Info"
#define  NSM_EFM_OAM_IF_STR             "EFM OAM Interface Info"
#define  NSM_EFM_LLDP_IF_STR            "LLDP Interface Info"
#define  NSM_L2_OAM_MASTER_STR          "NSM L2 OAM Master"

#define  GARP_GID_STR                   "GARP Group Id"
#define  GARP_GID_PORT_STR              "GARP Group Id Port"
#define  GARP_GID_MACHINE_STR           "GARP State Machine"
#define  GARP_GIP_STR                   "GARP GIP"

#define  GMRP_STR                       "GMRP"
#define  GMRP_PORT_STR                  "GMRP Port"
#define  GMRP_PORT_INSTANCE_STR         "GMRP Port Instance"
#define  GMRP_GMD_STR                   "GMRP GMD"
#define  GMRP_GMD_ENTRY_STR             "GMRP GMD Entry"

#define  GVRP_STR                       "GVRP"
#define  GVRP_PORT_STR                  "GVRP Port"
#define  GVRP_GVD_STR                   "GVRP Gvd"
#define  GVRP_GVD_ENTRY_STR             "GVRP Gvd Entry"
#define  GVRP_CONFIG_PORTS_STR          "GVRP Config Port"

#define  ONMD_GLOBALS_STR               "ONMD global structure"
#define  ONMD_MASTER_STR                "ONMD master"
#define  ONM_INTERFACE_STR              "ONM Interface"
#define  ONM_CLIENT_HANDLER_STR         "ONM Client Handler"
#define  ONM_CLIENT_STR                 "ONM Client"
#define  ONM_SERVER_ENTRY_STR           "ONM Server Entry"
#define  ONM_SERVER_CLIENT_STR          "ONM Client Server"
#define  ONM_SERVER_STR                 "ONM Server"
#define  ONM_PENDING_MSG_STR            "ONM Pending Msg"
#define  ONM_MSG_QUEUE_STR              "ONM Message Queue"
#define  ONM_MSG_QUEUE_BUF_STR          "ONM Message Queue Buf"
#define  AUTH_GLOBALS_STR               "802.1X global structure"
#define  AUTH_MASTER_STR                "802.1X master"
#define  AUTH_PORT_STR                  "802.1X port instance"
#define  AUTH_RADIUS_STR                "802.1X RADIUS server"

/*MAC-based authentication Enhancement*/
#define  MAC_AUTH_PORT_STR              "MAC authentication port instance"

#define  MSTP_VLAN_STR                  "MSTP VLAN"
#define  MSTP_BRIDGE_STR                "MSTP Bridge "
#define  MSTP_BRIDGE_NAME_STR           "MSTP Bridge Name"
#define  MSTP_BRIDGE_PORT_STR           "MSTP Port"
#define  MSTP_MSTI_INFO_STR             "MSTP MSTI info"
#define  MSTP_BPDU_INST_STR             "MSTP Instance bpdu"
#define  MSTP_BRIDGE_INSTANCE_STR       "MST Bridge Instance"
#define  MSTP_PORT_INSTANCE_STR         "MST Port Instance"
#define  L2_CLASSIFIER_STR              "VLAN Classifier"

#define  GARP_GID_STR                   "GARP Group Id"
#define  GARP_GID_PORT_STR              "GARP Group Id Port"
#define  GARP_GID_MACHINE_STR           "GARP State Machine"
#define  GARP_GIP_STR                   "GARP GIP"

#define  GMRP_STR                       "GMRP"
#define  GMRP_PORT_STR                  "GMRP Port"
#define  GMRP_PORT_INSTANCE_STR         "GMRP Port Instance"
#define  GMRP_GMD_STR                   "GMRP GMD"
#define  GMRP_GMD_ENTRY_STR             "GMRP GMD Entry"

#define  GVRP_STR                       "GVRP"
#define  GVRP_PORT_STR                  "GVRP Port"
#define  GVRP_GVD_STR                   "GVRP Gvd"
#define  GVRP_GVD_ENTRY_STR             "GVRP Gvd Entry"
#define  GVRP_CONFIG_PORTS_STR          "GVRP Config Port"

#define  LACP_LINK_STR                  "LACP Link"
#define  LACP_AGGREGATOR_STR            "LACP Aggregator"

#define  OSPF_MASTER_STR                "OSPF master"
#define  OSPF_STR                       "OSPF structure"
#define  OSPF_AREA_STR                  "OSPF area"
#define  OSPF_IF_STR                    "OSPF interface"
#define  OSPF_NEIGHBOR_STR              "OSPF neighbor"
#define  OSPF_VERTEX_STR                "OSPF SPF vertex"
#define  OSPF_NEXTHOP_STR               "OSPF Nexthop"
#define  OSPF_ROUTE_STR                 "OSPF Route"
#define  OSPF_ROUTE_CALC_STR            "OSPF Route calculation"
#define  OSPF_PATH_STR                  "OSPF Path"
#define  OSPF_LSA_STR                   "OSPF LSA"
#define  OSPF_LSA_DATA_STR              "OSPF LSA data"
#define  OSPF_ROUTER_LSA_MAP_STR        "OSPF Router-LSA Map"
#define  OSPF_SUMMARY_LSA_MAP_STR       "OSPF Summary-LSA Map"
#define  OSPF_LSDB_STR                  "OSPF LSDB"
#define  OSPF_LS_REQUEST_STR            "OSPF LS request"
#define  OSPF_PACKET_STR                "OSPF Packet"
#define  OSPF_REDIST_INFO_STR           "OSPF Redistribute Info"
#define  OSPF_REDIST_CONF_STR           "OSPF Redistribute Config"
#define  OSPF_REDIST_MAP_STR            "OSPF Redistribute Map"
#define  OSPF_DISTANCE_STR              "OSPF Distance"
#define  OSPF_NETWORK_STR               "OSPF Network"
#define  OSPF_VLINK_STR                 "OSPF Virtual-Link"
#ifdef HAVE_OSPF_MULTI_AREA
#define  OSPF_MULTI_AREA_LINK_STR       "OSPF Multi-Area-Link"
#endif /* HAVE_OSPF_MULTI_AREA */
#define  OSPF_IF_PARAMS_STR             "OSPF If-Params"
#define  OSPF_PASSIVE_IF_STR            "OSPF Passive If"
#define  OSPF_AUTH_KEY_STR              "OSPF Auth Key"
#define  OSPF_CRYPT_KEY_STR             "OSPF Crypt Key"
#define  OSPF_AREA_RANGE_STR            "OSPF Area Range"
#define  OSPF_SUMMARY_STR               "OSPF Summary Address"
#define  OSPF_NEIGHBOR_STATIC_STR       "OSPF Static Neighbor"
#define  OSPF_HOST_ENTRY_STR            "OSPF Host Entry"
#define  OSPF_OPAQUE_MAP_STR            "OSPF Opaque Map"
#define  OSPF_OPAQUE_SHOW_STR           "OSPF Opaque-LSA show"
#define  OSPF_NOTIFIER_STR              "OSPF Notifier"
#define  OSPF_VRF_STR                   "OSPF VR information"
#define  OSPF_DESC_STR                  "OSPF Description"
#define  OSPF_IGP_SHORTCUT_LSP_STR      "OSPF IGP Shortcut LSP"
#define  OSPF_IGP_SHORTCUT_ROUTE_STR    "OSPF IGP Shortcut Route"
#define  OSPF_DOMAIN_ID_STR             "OSPF_DOMAIN_ID"
#define  OSPF_RTR_ID_STR                "OSPF_ROUTER_ID"
#define  OSPF_LS_RXMT_STR               "OSPF LSA Retransmit Info"
#ifdef HAVE_GMPLS
#define  OSPF_TEL_STR                   "OSPF_TE Link"
#define  OSPF_TLINK_PARAMS_STR          "OSPF_TE Link Parameters"
#define  OSPF_SRLG_STR                  "OSPF SRLG VALUE"
#endif /* HAVE_GMPLS */
#define  OSPF_LDP_IGP_SYNC_STR           "OSPF LDP-IGP Sync parameters"

#define  OSPF6_MASTER_STR               "OSPFv3 master"
#define  OSPF6_STR                      "OSPFv3 structure"
#define  OSPF6_AREA_STR                 "OSPFv3 area"
#define  OSPF6_IF_STR                   "OSPFv3 interface"
#define  OSPF6_VLINK_STR                "OSPFv3 virtual link"
#define  OSPF6_NEIGHBOR_STR             "OSPFv3 neighbor"
#define  OSPF6_NBR_STATIC_STR           "OSPFv3 static neighbor"
#define  OSPF6_VERTEX_STR               "OSPFv3 vertex"
#define  OSPF6_ROUTE_STR                "OSPFv3 route"
#define  OSPF6_ROUTE_CALC_STR           "OSPFv3 Route calculation"
#define  OSPF6_PATH_STR                 "OSPFv3 path"
#define  OSPF6_NEXTHOP_STR              "OSPFv3 nexthop"
#define  OSPF6_LSA_STR                  "OSPFv3 LSA"
#define  OSPF6_LSA_DATA_STR             "OSPFv3 LSA data"
#define  OSPF6_LSA_MAP_STR              "OSPFv3 LSA map"
#define  OSPF6_LSDB_STR                 "OSPFv3 LSDB"
#define  OSPF6_LSDB_SLOT_STR            "OSPFv3 LSDB slot"
#define  OSPF6_PREFIX_STR               "OSPFv3 prefix"
#define  OSPF6_PREFIX_MAP_STR           "OSPFv3 prefix map"
#define  OSPF6_PACKET_STR               "OSPFv3 packet"
#define  OSPF6_FIFO_STR                 "OSPFv3 FIFO"
#define  OSPF6_REDIST_INFO_STR          "OSPFv3 redist info"
#define  OSPF6_REDIST_CONF_STR          "OSPFv3 redist config"
#define  OSPF6_REDIST_MAP_STR           "OSPFv3 redist map"
#define  OSPF6_IF_PARAMS_STR            "OSPFv3 if params"
#define  OSPF6_AREA_RANGE_STR           "OSPFv3 area range"
#define  OSPF6_SUMMARY_STR              "OSPFv3 Summary"
#define  OSPF6_RMAP_COMPILED_STR        "OSPFv3 route map data"
#define  OSPF6_DESC_STR                 "OSPFv3 description"
#define  OSPF6_VRF_STR                  "OSPFv3 VRF"
#define  OSPF6_ROUTER_ID_STR            "OSPFV3 router id"

#define  VRRP_GLOBAL_INFO_STR           "VRRP global info"
#define  VRRP_SESSION_STR               "VRRP session"
#define  VRRP_ASSO_TABLE_STR            "VRRP Asso Table"
#define  VRRP_VIP_ADDR_STR              "VRRP virtual IP"
#define  VRRP_IF_AUTH_STR                "VRRP if auth"
#define  VRRP_LINUX_DATA_STR            "VRRP Linux session"
#define  VRRP_BSD_DATA_STR              "VRRP BSD session"
#define  VRRP_ASSO_STR                  "VRRP Association"

#define  VTYSH_INTEGRATE_STR            "VTYSH integrate"
#define  VTYSH_CONFIG_STR               "VTYSH config str"
#define  VTYSH_CONFIG_LINE_STR          "VTYSH config line str"

#define  LDP_STR                        "LDP structure"
#define  LDP_IF_STR                     "LDP interface"
#define  LDP_ADJACENCY_STR              "LDP adjacency"
#define  LDP_ENTITY_STR                 "LDP entity"
#define  LDP_ID_STR                     "LDP Id"
#define  LDP_SESSION_STR                "LDP session"
#define  LDP_FEC_STR                    "LDP FEC"
#define  LDP_FEC_ELEMENT_STR            "LDP FEC element"
#define  LDP_LABEL_STR                  "LDP label"
#define  LDP_LABEL_REQUEST_STR          "LDP label request"
#define  LDP_ATTR_NODE_STR              "LDP attr info"
#define  LDP_REMOTE_ADDR_STR            "LDP remote addresses"
#define  LDP_UPSTREAM_STR               "LDP upstream"
#define  LDP_DOWNSTREAM_STR             "LDP downstream"
#define  LDP_USM_PARAM_STR              "LDP USM param"
#define  LDP_DSM_PARAM_STR              "LDP DSM param"
#define  LDP_IPV4_NEXT_HOP_STR          "LDP IPv4 nexthop"
#define  LDP_TMP_STR                    "LDP temp memory"
#define  LDP_PATH_VECTOR_STR            "LDP path vector"
#define  LDP_ATTR_STR                   "LDP attribute"
#define  LDP_CR_ATTR_STR                "LDP CR attribute"
#define  LDP_TLV_ER_HOP_STR             "LDP TLV ER hop"
#define  LDP_ER_STR                     "LDP ER"
#define  LDP_ER_HOP_STR                 "LDP ER hop"
#define  LDP_PATH_STR                   "LDP path"
#define  LDP_TRUNK_STR                  "LDP trunk"
#define  LDP_IPV6_NEXT_HOP_STR          "LPD IPv6 nethop"

#ifdef HAVE_TE
#define  LDP_TRUNK_ADMIN_GROUP_STR      "LDP trunk admin group"
#endif

#define  LDP_TARGETED_PEER_STR          "LDP targeted peer"
#define  LDP_LS_TO_ADDR_STR             "LDP labelspace to address"

#ifdef HAVE_MPLS_VC
#define  LDP_VC_STR                     "LDP Virtual Circuit"
#define  VC_LSP_CB_STR                  "LDP VC LSP Control block"
#define  SESSION_VC_LINK_STR            "LDP Session VC link"
#define  VC_EVENT_PARAM_STR             "LDP VC Event parameter"
#define  VC_EVENT_PARAM_DATA_STR        "VC Event param data"
#endif

#ifdef HAVE_VPLS
#define  LDP_VPLS_STR                   "LDP Virtual Private LAN Service"
#endif

#define  LDP_ADV_LIST_STR               "LDP Advertisement list"
#define  LDP_ADV_LIST_STR_STR           "LDP Advertisement list str"
#ifdef HAVE_LINUX_TCP_MD5_H
#define  LDP_NBR_TO_PASSWD_STR          "LDP Neighbor password structure"
#endif /* HAVE_LINUX_TCP_MD5_H */
#ifdef HAVE_RESTART
#define LDP_FEC_STALE_INFO_STR          "LDP FEC Stale INFO structure"
#endif /* HAVE_RESTART */

#define  RSVP_STR                        "RSVP structure"
#define  RSVP_IF_STR                     "RSVP interface"
#define  RSVP_WRITE_QUEUE_NODE_STR       "RSVP write queue node"
#define  RSVP_TRUNK_STR                  "RSVP trunk"
#define  RSVP_PATH_STR                   "RSVP path"
#define  RSVP_PATH_HOP_STR               "RSVP path hop"
#define  RSVP_SESSION_STR                "RSVP session"
#define  RSVP_EXPLICIT_ROUTE_VAL_STR     "RSVP explicit route object"
#define  RSVP_ROUTE_RECORD_VAL_STR       "RSVP route record object"
#define  RSVP_NEIGHBOR_STR               "RSVP neighbor"
#define  RSVP_LABEL_STR                  "RSVP label"
#define  RSVP_SESSION_ADMIN_GROUP_STR    "RSVP session admin group"
#define  RSVP_RCVD_PKT_NODE_STR          "RSVP received packet node"
#define  RSVP_NEXTHOP_STR                "RSVP nexthop"
#define  RSVP_MAPPED_ROUTE_STR           "RSVP Mapped route"
#define  RSVP_PATH_REFRESH_BUF_STR       "RSVP Path refresh buf"
#define  RSVP_RESV_REFRESH_BUF_STR       "RSVP Resc refresh buf"
#define  RSVP_MESSAGE_STR                "RSVP Message"
#define  RSVP_ACK_WAIT_NODE_STR          "RSVP Ack Wait Node"
#define  RSVP_NEIGH_ACK_BUF_STR          "RSVP Neighbor Ack Buffer"
#define  RSVP_NEIGH_BUNDLE_BUF_STR       "RSVP Neighbor Bundle Buffer"

#ifdef HAVE_MPLS_FRR
#define  RSVP_SUBOBJ_AVOID_NODE_STR      "RSVP Detour Avoid Node"
#define  RSVP_BYPASS_STR                 "RSVP Bypass"
#endif /* HAVE_MPLS_FRR */

#ifdef HAVE_GMPLS

#define  GMPLS_RSVP_IF_STR           "RSVP GMPLS Interface"
#define  RSVP_GMPLS_ATTR_STR         "RSVP GMPLS Attribute"
#define  RSVP_GMPLS_SESS_ATTR_STR    "RSVP GMPLS Session Attribute"
#define  RSVP_GMPLS_LBL_SET_STR      "RSVP GMPLS Label Set"
#define  RSVP_GMPLS_NOTIFN_T_STR     "RSVP GMPLS Notification Target Node"
#define  RSVP_GMPLS_NOTIFN_AB_STR    "RSVP GMPLS Notification Aggregate Buffer"
#define  RSVP_GMPLS_NOTIFN_AN_STR    "RSVP GMPLS Notification Aggregate Node"
#define  RSVP_GMPLS_NOTIFN_RB_STR    "RSVP GMPLS Notification Resend Buffer"
#define  RSVP_GMPLS_NOTIFN_RN_STR    "RSVP GMPLS Notification Resend Node"
#define  RSVP_GMPLS_NOTIFN_TGT_STR   "RSVP GMPLS Notification Target Entry"
#define  RSVP_GMPLS_REM_ACK_STR      "RSVP GMPLS Remote Acknowledgement Buffer"

#ifdef HAVE_PCE
#define  RSVP_PCE_ATTR_STR               "RSVP PCE Attribute"
#endif /* HAVE_PCE */
#endif /* HAVE_GMPLS */

#define  RSVP_SNMP_RESOURCE_ENTRY_STR   "SNMP RSVP Resource Node"
#define  RSVP_SNMP_HOP_ENTRY_STR        "SNMP RSVP Hop Node"
#define  RSVP_SNMP_TUNNEL_ENTRY_STR     "SNMP RSVP Tunnel Node"

#define  CSPF_STR                        "CSPF structure"
#define  CSPF_LSP_STR                    "CSPF LSP structure"
#define  CSPF_LSP_ADDR_BINDING_STR       "CSPF LSP Address-Binding structure"
#define  CSPF_ROUTE_CONSTRAINT_STR       "CSPF constraint structure"
#define  CSPF_VERTEX_STR                 "CSPF vertex"
#define  CSPF_PATH_ELEMENT_STR           "CSPF path element"
#define  CSPF_DATA_STR                   "CSPF computation data"
#define  CSPF_SESSION_STR                "CSPF session"
#define  CSPF_MSG_BUF_STR                "CSPF message buffer"
#define  CSPF_NEXTHOP_DATA_STR           "CSPF nexthop data"
#define  CSPF_UNNUMBERED_IF_DATA_STR     "CSPF unnumbered interface data"
#define  CSPF_LSP_LIST_STR               "CSPF LSP list"
#define  TE_LSA_NODE_STR                 "CSPF TED node"
#define  OSPF_TE_LSA_DATA_STR            "CSPF TE LSA structure"
#define  CSPF_CLIENT_STR                 "CSPF client"
#define  CSPF_LSP_KEY_STR                "CSPF LSP Key"
#define  CSPF_IPADDR_LIST_STR            "CSPF IP Address list"
#define CSPF_SRLG_DATA_STR               "CSPF SRLG"

#define  ISIS_MASTER_STR                 "IS-IS master"
#define  ISIS_INSTANCE_STR               "IS-IS instance"
#define  ISIS_AREA_ADDR_STR              "IS-IS area address"
#define  ISIS_RECV_AREA_ADDR_STR         "IS-IS recv area address"
#define  ISIS_IF_STR                     "IS-IS interface"
#define  ISIS_IF_NAME_STR                "IS-IS interface name"
#define  ISIS_IF_PARAMS_STR              "IS-IS interface params"
#define  ISIS_NEIGHBOR_STR               "IS-IS neighbor"
#define  ISIS_TLV_STR                    "IS-IS TLV"
#define  ISIS_TLV_DATA_STR               "IS-IS TLV data"
#define  ISIS_STLV_STR                   "IS-IS sub TLV"
#define  ISIS_STLV_DATA_STR              "IS-IS sub TLV data"
#define  ISIS_LSP_STR                    "IS-IS LSP"
#define  ISIS_LSP_HEADER_STR             "IS-IS LSP header"
#define  ISIS_PACKET_STR                 "IS-IS packet"
#define  ISIS_FIFO_STR                   "IS-IS FIFO"
#define  ISIS_IP_IFADDR_STR              "IS-IS IP interface addr"
#define  ISIS_BITMAP_STR                 "IS-IS bitmap"
#define  ISIS_BITMAP_BITS_STR            "IS-IS bitmap bits"
#define  ISIS_VERTEX_STR                 "IS-IS SPF vertex"
#define  ISIS_VERTEX_NEXTHOP_STR         "IS-IS SPF vertex nexthop"
#define  ISIS_ROUTE_STR                  "IS-IS route"
#define  ISIS_PATH_STR                   "IS-IS path"
#define  ISIS_NEXTHOP_STR                "IS-IS nexthop"
#define  ISIS_PASSWD_STR                 "IS-IS simple text password"
#define  ISIS_TAG_STR                    "IS-IS tag"
#define  ISIS_HOSTNAME_STR               "IS-IS hostname"
#define  ISIS_REDIST_INFO_STR            "IS-IS redistribution info"
#define  ISIS_REDIST_MAP_STR             "IS-IS redistribution map"
#define  ISIS_REACH_INFO_STR             "IS-IS reachability info"
#define  ISIS_REACH_MAP_STR              "IS-IS reachability map"
#define  ISIS_REACH_SOURCE_STR           "IS-IS reachability source"
#define  ISIS_IS_REACH_MAP_STR           "IS-IS IS-reachability map"
#define  ISIS_IS_REACH_INFO_STR          "IS-IS IS-reachability info"
#define  ISIS_SUMMARY_STR                "IS-IS summary prefix"
#define  ISIS_RESTART_IF_STR             "IS-IS restart interface"
#define  ISIS_DESC_STR                   "IS-IS description"
#define  ISIS_DISTANCE_STR               "IS-IS Distance"
#define  ISIS_VRF_STR                    "IS-IS VRF"
#define  ISIS_IGP_SHORTCUT_LSP_STR           "IS-IS IGP SHORTCUT LSP"
#define  ISIS_LDP_IGP_SYNC_STR           "IS-IS LDP-IGP Sync parameters"

#ifdef HAVE_MD5
#define  ISIS_KEY_CHAIN_STR              "IS-IS key chain"
#endif /* HAVE_MD5 */

#define  ISIS_CSPF_STR                   "IS-IS CSPF"
#define  ISIS_CSPF_LSP_STR               "IS-IS CSPF LSP"
#define  ISIS_CSPF_ROUTE_CONSTRAINT_STR  "IS-IS CSPF constraint route"
#define  ISIS_CSPF_VERTEX_STR            "IS-IS CSPF vertex"
#define  ISIS_CSPF_VERTEX_NEXTHOP_STR    "IS-IS CSPF vertex nexthop"

#define  MRIB_GLOBALS_STR       "MRIB globals entry"
#define  MRIB_MASTER_STR        "MRIB master entry"
#define  MRIB_VRF_VECTOR_STR    "MRIB VRF instance vector"
#define  MRIB_VRF_STR           "MRIB VRF instance"
#define  MRIB_VIF_VECTOR_STR    "MRIB VIF vector"
#define  MRIB_VIF_STR           "MRIB VIF entry"
#define  MRIB_STATS_BLOCK_STR   "MRIB stats block"
#define  MRIB_MRT_STR           "MRIB MRT entry"
#define  MRIB_MRT_OLIST_STR     "MRIB MRT olist entry"
#define  MRIB_MRT_REG_STR       "MRIB MRT register entry"
#define  MRIB_MTRACE_STATE_STR  "MRIB mtrace state entry"
#define  MRIB_MTRACE_PKT_STR    "MRIB mtrace packet entry"

#define  PIM_GLOBALS_STR        "PIM Globals"
#define  PIM_MASTER_STR         "PIM Master"
#define  PIM_VRF_VECTOR_STR     "PIM VRF instance vector"
#define  PIM_VRF_STR            "PIM VRF instance"
#define  PIM_VIF_VECTOR_STR     "PIM VIF vector"
#define  PIM_VIF_STR            "PIM VIF"
#define  PIM_VIF_MEMBER_STR     "PIM VIF Local-member entry"
#define  PIM_NEIGHBOR_STR       "PIM neighbor"
#define  PIM_MIB_NEIGHBOR_STR   "PIM MIB neighbor"
#define  PIM_SG_STR             "PIM SG"
#define  PIM_G_STR              "PIM G"
#define  PIM_SRC_STR            "PIM src"
#define  PIM_GROUP_STR          "PIM group"
#define  PIM_MRT_STR            "PIM MRT"
#define  PIM_MRT_FCR_STR        "PIM (*,G) MRT FCR"
#define  PIM_MRT_OLIST_STR      "PIM MRT OList"
#define  PIM_MRT_VIF_STATE      "PIM MRT VIF state"
#define  PIM_RP_STR             "PIM RP"
#define  PIM_RP_SET_STR         "PIM RP SET"
#define  PIM_RP_STATIC_CONF_STR "PIM Static RP configuration"
#define  PIM_RP_ANYCAST_STR     "PIM Anycast-RP"
#define  PIM_RP_ANYCAST_MEM_STR "PIM Anycast-RP member"
#define  PIM_RP_CANDIDATE_STR   "PIM Candidate-RP"
#define  PIM_RP_CANDIDATE_GRP_RNG_STR    "PIM Candidate-RP Group Range"
#define  PIM_BSR_STR            "PIM BSR"
#define  PIM_NEXTHOP_STR        "PIM nexthop"
#define  PIM_NEXTHOP_ENTRY_STR  "PIM nexthop entry"
#define  PIM_OIF_STR            "PIM OIF"
#define  PIM_REG_STR            "PIM reg"
#define  PIM_MSG_RECORD_STR     "PIM message record"

#define  PIM4_MSDP_GLOBALS_STR  "PIM MSDP Globals"
#define  PIM4_MSDP_STR          "PIM MSDP"

#define  PIM_MBR_STR            "PIM MBR"
#define  PIM_MBR_MRT_STATUS_STR "PIM MBR MRT status"

#define  DVMRP_STR              "DVMRP"
#define  DVMRP_VIF_STR          "DVMRP vif"
#define  DVMRP_BITMAP_STR       "DVMRP bitmap"
#define  DVMRP_BITMAP_BLOCK_STR "DVMRP bitmap block"
#define  DVMRP_NBR_STR          "DVMRP neighbor"
#define  DVMRP_PRUNE_STR        "DVMRP prune state"
#define  DVMRP_DSPS_STR         "DVMRP downstream prune state"
#define  DVMRP_DSPS_NBR_STR     "DVMRP downstream prune state nbr"
#define  DVMRP_FCR_STR          "DVMRP forwarding cache"
#define  DVMRP_ROUTE_STR        "DVMRP route"
#define  DVMRP_ROUTE_DS_STATE_STR "DVMRP route downstream"
#define  DVMRP_TUNNEL_CONF_STR  "DVMRP tunnel config"
#define  DVMRP_VIF_LOCAL_INFO_STR       "DVMRP Vif local info"

#ifdef HAVE_IMI
#define  IMI_STR                "IMI"
#define  IMI_MASTER_STR         "IMI master"
#define  IMI_STRING_STR         "IMI String"
#define  IMI_SERVER_STR         "IMI Server"
#define  IMI_SERVER_CLIENT_STR  "IMI Server Client"
#define  IMI_SERVER_ENTRY_STR   "IMI Server Entry"
#define  IMI_LINE_STR           "IMI Line"
#define  IMI_SERV_STR           "IMI Web Server Connection"
#define  IMI_EXTAPI_STR         "IMI Web ext CLI callback"
#define  IMI_WEB_STR            "IMI Web CLI"
#define  IMI_DNS_STR            "IMI DNS"
#define  IMI_DHCP_STR           "IMI DHCP"
#define  IMI_DHCP_POOL_STR      "IMI DHCP Pool"
#define  IMI_DHCP_RANGE_STR     "IMI DHCP Range"
#define  IMI_DHCP_CLIENT_STR    "IMI DHCP Client"
#define  IMI_PPPOE_STR          "IMI PPPoE"
#define  IMI_NAT_POOL_STR       "IMI NAT Pool"
#define  IMI_RULE_STR           "IMI NAT/filter rule"
#define  IMI_VIRTUAL_SERVER_STR "IMI Virtual Server"
#define  IMI_VIRTUAL_SERVER_DESC_STR    "IMI Virtual Server Description"
#define  IMI_NTP_MASTER_STR     "IMI NTP Master"
#define  IMI_NTP_AUTH_KEY_STR   "IMI NTP auth key"
#define  IMI_NTP_TRUSTED_KEY_STR "IMI NTP trusted key"
#define  IMI_NTP_NEIGHBOR_STR   "IMI NTP neighbor"
#define  IMI_CONFIG_STR         "IMI config"
#define  IMI_STATE_STR          "IMI state"
#define  IMI_STATE_LINE_STR     "IMI state line"
#endif /* HAVE_IMI */

#define  IMI_CFG_CMD_STR        "IMI config cmd"

/* PAL workspace */
#define  CFG_HANDLE_STR         "Config handle"
#define  LOG_HANDLE_STR         "Log handle"
#define  LOG_NAME_STR           "Log file name"
#define  SOCK_HANDLE_STR        "Socket handle"

/* sort these? */
#define  HOST_STR               "Host"
#define  COMMAND_NODE_STR       "Command node"
#define  DISTRIBUTE_STR         "Distribute"
#define  DISTSTR_STR            "Distribute str"
#define  ZLOG_STR               "Log information"
#define  IF_DESC_STR            "If descriptor"
#define  IF_RMAP_STR            "Rmap"
#define  IF_RMAP_NAME_STR       "Rmap name"

#define  SOCKUNION_STR          "Socket union"

#define  ZGLOB_STR              "Context"
#define  UNKNOWN_STR            "Unknown"

#ifdef HAVE_INTEL
#define L3_NPF_NEXTHOP_STR      "L3 NPF Nexthop"
#define L3_NPF_NHOP_ARRAY_STR   "L3 Nexthop Array"
#define L3_NPF_PREFIX_STR       "L3 NPF Prefix"
#endif /* HAVE_INTEL */

#define  CRX_MESSAGE_HANDLER_STR "CRX Message handler"
#define  CRX_PEER_STR            "CRX Peer"
#define  CRX_CONFIG_DATA_STR     "CRX Config data"
#define  CRX_IF_STR              "CRX If"
#define  CRX_INFO_STR            "CRX Info"
#define  CRX_STR                 "CRX"
#ifdef HAVE_RMOND
#define RMON_INFO_STR           "RMON info"
#endif /* HAVE_RMOND */
#ifdef HAVE_IPSEC
#define  IPSEC_CRYPTO_STR       "IPsec Crypto Map"
#define  IPSEC_TRANSFORM_STR    "IPsec Transform Set"
#define  IPSEC_STR              "Ipsec"
#define  IPSEC_ISAKMP_STR       "Ipsec Isakmp"
#define  IPSEC_SESSION_KEY_STR  "Ipsec Session Key"
#define  IPSEC_PEER_STR         "Ipsec Peer"
#define  IPSEC_MASTER_STR       "Ipsec Master"
#define  IPSEC_CRYPTO_BUNDLE_STR "Ipsec Crypto bundle"
#endif /* HAVE_IPSEC */
#ifdef HAVE_FIREWALL
#define  FIREWALL_MASTER_STR  "IpFirewall Master"
#define  FIREWALL_GROUP_STR   "Firewall Group"
#endif /* HAVE_FIREWALL */


#ifdef HAVE_HA
#define MTYPE_CAL_STR          "CAL Control"
#define MTYPE_CAL_TXN_STR      "CAL Transactions"
#define MTYPE_CAL_ACT_STR      "CAL Actions"
#define MTYPE_CAL_CDR_STR      "CAL Chkpt Data"
#define MTYPE_CAL_EVENT_STR    "CAL Events and Timers"
#define MTYPE_AM               "Availability Management"

#ifdef HAVE_ENEA_ELEMENT
#define MTYPE_ENEA_DATA_STR    "ENEA Ckpt data"
#endif

#ifdef HAVE_OSAF
#define MTYPE_OSAF_BMAP_STR    "OSAF Bitmap"
#define MTYPE_OSAF_DEL_REC_STR "OSAF Deleted record data"
#define MTYPE_OSAF_SECT_STR    "OSAF Section"
#define MTYPE_OSAF_DATA_STR    "OSAF Ckpt action data"
#define MTYPE_OSAF_LUDATA_STR  "OSAF Live update data"
#endif

#endif /* HAVE_HA */

#define MTYPE_FM_STR           "FM"
#define MTYPE_FM_LIB_STR       "FM Lib"

#define MTYPE_LIB_VREP_STR     "VREP"

#define MTYPE_COMMSG_STR       "COMMSG Control"

#define ONM_BRIDGE_STR          "ONM Bridge"
#define ONM_VLAN_BMP_STR        "ONM Vlan Bitmap"
#define ONM_VLAN_STR            "ONM Vlan"

#define LLDP_IF_STR             "LLDP Interface"
#define LLDP_MASTER_STR         "LLDP Master"
#define LLDP_MSG_BUF_STR        "LLDP Message Buffer"
#define REMOTE_LLDP_STR         "Remote LLDP"
#define REMOTE_VLAN_STR         "Remote Vlan"

#define EFM_MASTER_STR          "EFM Master"
#define EFM_IF_STR              "EFM Interface"
#define EFMOAM_STR              "EFM OAM Structure"
#define EFM_MSG_BUF_STR         "EFM Message Buffer"

#define CFM_MASTER_STR          "CFM Master"
#define CFM_PORT_STR            "CFM Port"
#define CFM_STR                 "CFM"
#define CFM_LT_STR              "CFM Link Trace"
#define CFM_LTM_REPLY_STR       "CFM LinkTrace Reply List"
#define CFM_LTM_STR             "CFM LinkTrace Message"
#define CFM_LTR_PDU_STR         "CFM LinkTrace Reply"
#define CFM_HEADER_STR          "CFM Header"
#define CFM_LTR_MSG_STR         "CFM LinkTrace Reply Message"
#define CFM_MSG_BUF_STR         "CFM Message Buffer"
#define CFM_FNG_STR             "CFM Fault Alarm"
#define CFM_MD_STR              "CFM MD"
#define CFM_MA_STR              "CFM MA"
#define CFM_MEP_STR             "CFM MEP"
#define CFM_CC_STR              "CFM CC"
#define CFM_LB_STR              "CFM LB"
#define CFM_FA_STR              "CFM FA"
#define CFM_FR_STR              "CCM frame"
#define CFM_IF_STR              "CFM Interface"
#define CFM_RMEP_STR            "CFM rmep"
#define CFM_LTQ_STR             "CFM link trace"
#define CFM_ERRCCM_STR          "CFM error ccm"
#define CFM_PROCESS_STR         "CFM process"
#define CFM_LM_DUAL_STR         "CFM LM Dual Ended"

#ifdef HAVE_CFM_Y1731
/* For memory allocations */
/* For multicast LBM, LBR information will be stored */
#define CFM_LBR_STR             "CFM LBR"
#define CFM_LM_STR              "CFM LM"
#define CFM_DUAL_LM_STR         "CFM Dual LM"
#define CFM_LM_COUNT_INST_STR   "CFM LM Counter Instance"
#define CFM_1DM_TX_STR          "CFM 1DM TX"
#define CFM_1DM_RX_STR          "CFM 1DM RX"
#define CFM_1DM_RX_FR_STR       "CFM 1DM RX FRAME"
#define CFM_DMM_STR             "CFM DMM"
#define CFM_DMM_FRAME_STR       "CFM DMM FRAME"
#define CFM_AIS_STR             "CFM AIS"
#define CFM_AIS_RMEP_INST_STR   "CFM AIS RMEP Instance"
#define CFM_AIS_DEFECT_CONDITION_STR "CFM AIS Defect Condition"
#define CFM_SERVER_MEP_STR      "CFM Server MEP"
#define CFM_SERVER_MEP_MSG_BUF_STR "CFM Server MSG BUF"
#define CFM_LCK_STR             "CFM LCK"
#define CFM_TST_STR             "CFM TST"
#define CFM_TPUT_RX_STR         "CFM Throughput measurement"
#define CFM_MCC_STR             "CFM MCC"
#define CFM_EXM_STR             "CFM EXM"
#define CFM_VSM_STR             "CFM VSM"

#endif /* HAVE_CFM_Y1731 */
#if defined HAVE_CFM && (defined HAVE_I_BEB || defined HAVE_B_BEB)
#define CFM_PBB_PORT_STR        "CFM PBB PORT INFO"
#define CFM_PBB_ISID_BVID_STR   "CFM PBB ISID TO BVID MAP"
#define CFM_PBB_ISID_ON_BRIDGE_STR   "CFM PBB ISID ON BRIDGE"
#endif /* (HAVE_CFM && (HAVE_I_BEB || HAVE_B_BEB)) */
#ifdef HAVE_G8031
#define G8031_VLAN_STR           "G8031 VLAN INFO"
#define G8031_PROTECTION_GRP_STR "G8031 PG INFO"
#endif /* HAVE_G8031 */
#define CFM_VID_INFO_STR        "CFM VID Information"
#define CFM_DEFAULT_MD_LEVEL_TBL_STR        "CFM Default MD Level Table"
#define CFM_DEFAULT_MD_LEVEL_TBL_ENTRY_STR  "CFM Default MD Level Entry"
#define CFM_VID_ACTIVE_LEVELS_STR  "CFM ACTIVE LEVELS ON VID"
#define CFM_CONFIG_ERROR_STR       "CFM CONFIG ERROR"

#define ONM_PE_PORT_STR            "ONM PE PORT ERROR"

#define  MAX_STR                "Invalid type"

/* function prototypes */
int    memmgr_get_mtype_max ();
char * memmgr_get_mtype_str (int);
int    memmgr_match_protocol_id (int, int);
int    memmgr_map_mtype_index (int);
/* mtype array quick sort functions */
void memmgr_qsort_mtype_array(void);
int memmgr_qsort_mtype_comp(const void *entry_one, const void *entry_two);
#endif /* _MEMMGR_CONFIG_H */

