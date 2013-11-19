/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */

#ifndef _BGPSDN_MEMORY_H
#define _BGPSDN_MEMORY_H

#include "modbmap.h"

/* Memory types. */
enum memory_type
{
  MTYPE_TMP = 0,        /* Must always be first and should be zero. */

  /* Hash */
  MTYPE_HASH,
  MTYPE_HASH_INDEX,
  MTYPE_HASH_BUCKET,

  /* Thread */
  MTYPE_THREAD_MASTER,
  MTYPE_THREAD,

  /* Linklist */
  MTYPE_LINK_LIST,
  MTYPE_LIST_NODE,

  /*port mode list */
  MTYPE_PORT_MODE,

  /* Buffer */
  MTYPE_BUFFER,
  MTYPE_BUFFER_BUCKET,
  MTYPE_BUFFER_DATA,
  MTYPE_BUFFER_IOV,

  /* Show */
  MTYPE_SHOW,
  MTYPE_SHOW_PAGE,
  MTYPE_SHOW_SERVER,

  /* Prefix */
  MTYPE_PREFIX,
  MTYPE_PREFIX_IPV4,
  MTYPE_PREFIX_IPV6,

  /* Route table */
  MTYPE_ROUTE_TABLE,
  MTYPE_ROUTE_NODE,

  /* Vector */
  MTYPE_VECTOR,
  MTYPE_VECTOR_INDEX,

  /* snmp : agentx/smux */
  MTYPE_SNMP_SUBTREE,
  MTYPE_SMUX_PASSWD,

  /* Host configuration. */
  MTYPE_CONFIG,
  MTYPE_CONFIG_MOTD,
  MTYPE_CONFIG_LOGIN,
  MTYPE_CONFIG_PASSWORD,

  /* IMI client.  */
  MTYPE_IMI_CLIENT,

  /* Interface database. */
  MTYPE_IF_DB,

  /* Memory globals. */
  MTYPE_MEMORY_GLOBALS,

  /* VTY */
  MTYPE_VTY_MASTER,
  MTYPE_VTY,
  MTYPE_VTY_HIST,
  MTYPE_VTY_PATH,
  MTYPE_VTY_OUT_BUF,
  MTYPE_IF,
  MTYPE_CONNECTED,
  MTYPE_STREAM,
  MTYPE_STREAM_DATA,
  MTYPE_STREAM_FIFO,

  /* Stream Socket Control Block */
  MTYPE_SSOCK_CB,
  /* Circular Queue Buffer */
  MTYPE_CQUEUE_BUF,

  /* Access list */
  MTYPE_ACCESS_LIST,
  MTYPE_ACCESS_LIST_STR,
  MTYPE_ACCESS_FILTER,

  /* Prefix list */
  MTYPE_PREFIX_LIST,
  MTYPE_PREFIX_LIST_STR,
  MTYPE_PREFIX_LIST_ENTRY,
  MTYPE_PREFIX_LIST_DESC,

  /* Route map */
  MTYPE_ROUTE_MAP,
  MTYPE_ROUTE_MAP_NAME,
  MTYPE_ROUTE_MAP_INDEX,
  MTYPE_ROUTE_MAP_RULE,
  MTYPE_ROUTE_MAP_RULE_STR,
  MTYPE_ROUTE_MAP_COMPILED,

  /* VR data */
  MTYPE_VRF_NAME,
  MTYPE_IPI_VRF,

  /* Keys */
  MTYPE_KEYCHAIN,
  MTYPE_KEYCHAIN_NAME,
  MTYPE_KEY,
  MTYPE_KEY_STRING,

  /* Bit map */
  MTYPE_BITMAP,
  MTYPE_BITMAP_BLOCK,
  MTYPE_BITMAP_BLOCK_ARRAY,
  MTYPE_STRING_BUFF,

  /* Ptree */
  MTYPE_PTREE,
  MTYPE_PTREE_NODE,

  /* Avl tree */
  MTYPE_AVL_TREE,
  MTYPE_AVL_TREE_NODE,

  /* Binary Heap */
  MTYPE_BINARY_HEAP,
  MTYPE_BINARY_HEAP_ARRAY,

  /* Message */
  MTYPE_MESSAGE_ENTRY,
  MTYPE_MESSAGE_HANDLER,

  /* BGP */
  MTYPE_BGP,
  MTYPE_BGP_VR,
  MTYPE_BGP_GLOBAL,
  MTYPE_BGP_PEER,
  MTYPE_BGP_PEER_CONF,
  MTYPE_BGP_PEER_GROUP,
  MTYPE_BGP_PEER_NOTIFY_DATA,
  MTYPE_BGP_ROUTE,
  MTYPE_BGP_STATIC,
  MTYPE_BGP_AGGREGATE,
  MTYPE_BGP_MPCAP,
  MTYPE_BGP_ADJACENCY,
  MTYPE_BGP_ADVERTISE,
  MTYPE_BGP_ADVERTISE_ATTR,
  MTYPE_BGP_ADJ_IN,
  MTYPE_ATTR,
  MTYPE_AS_PATH,
  MTYPE_AS_SEG,
  MTYPE_AS_STR,
  MTYPE_COMMUNITY,
  MTYPE_COMMUNITY_VAL,
  MTYPE_COMMUNITY_STR,
  MTYPE_COMMUNITY_LIST_CONFIG,
  MTYPE_COMMUNITY_LIST_NAME,
  MTYPE_ECOMMUNITY,
  MTYPE_ECOMMUNITY_VAL,
  MTYPE_ECOMMUNITY_STR,
  MTYPE_CLUSTER,
  MTYPE_CLUSTER_VAL,
  MTYPE_TRANSIT,
  MTYPE_TRANSIT_VAL,
  MTYPE_AS_LIST,
  MTYPE_AS_LIST_MASTER,
  MTYPE_AS_FILTER,
  MTYPE_AS_FILTER_STR,
  MTYPE_COMMUNITY_LIST_HANDLER,
  MTYPE_COMMUNITY_LIST,
  MTYPE_COMMUNITY_LIST_ENTRY,
  MTYPE_COMMUNITY_REGEXP,
  MTYPE_BGP_CONFED_LIST,
  MTYPE_BGP_DISTANCE,
  MTYPE_BGP_NEXTHOP_CACHE,
  MTYPE_BGP_RFD_HINFO,
  MTYPE_BGP_RFD_DECAY_ARRAY,
  MTYPE_BGP_RFD_REUSE_LIST_ARRAY,
  MTYPE_BGP_RFD_CB,
  MTYPE_BGP_RFD_CFG,
  MTYPE_BGP_TABLE,
  MTYPE_BGP_NODE,
  MTYPE_BGP_WALKER,
  MTYPE_PEER_UPDATE_SOURCE,
  MTYPE_PEER_DESC,
  MTYPE_BGP_VRF,
  MTYPE_BGP_DUMP,
#ifdef HAVE_EXT_CAP_ASN
  MTYPE_AS4_PATH,
  MTYPE_AS4_SEG,
  MTYPE_AS4_STR,
#endif /* HAVE_EXT_CAP_ASN */
  MTYPE_PEER_BGP_NODE,

  /* VTYSH */
  MTYPE_VTYSH_INTEGRATE,
  MTYPE_VTYSH_CONFIG,
  MTYPE_VTYSH_CONFIG_LINE,

  MTYPE_IMI_CFG_CMD,

  /* PAL workspace */
  MTYPE_CFG_HANDLE,
  MTYPE_LOG_HANDLE,
  MTYPE_LOG_NAME,
  MTYPE_SOCK_HANDLE,

  MTYPE_HOST,
  MTYPE_COMMAND_NODE,
  MTYPE_DISTRIBUTE,
  MTYPE_DISTSTR,
  MTYPE_ZLOG,
  MTYPE_IF_DESC,
  MTYPE_IF_RMAP,
  MTYPE_IF_RMAP_NAME,
  MTYPE_SOCKUNION,
  MTYPE_ZGLOB,

  /* default if something is wrong with input type */
  MTYPE_UNKNOWN,

  MTYPE_COMMSG,

  MTYPE_MAX             /* 1028 - Must be last & should be largest. */
};

/* Function prototypes. */
modbmap_t memory_active_modules (void);
int memory_init (int);
int memory_finish (void);
void memory_set_lg (void *);
void memory_unset_lg (void *);

#ifdef MEMMGR
/* Malloc Fault Handler Prototypes */
void *mfh_malloc (int, int, char *, int);
void *mfh_calloc (int, int, char *, int);
void *mfh_realloc (void *, int, int, char *, int);
char *mfh_strdup (const char *, int, char *, int);

/* Memory API mapping.  */
#define XMALLOC(type,size)      mfh_malloc (size, type, __FILE__, __LINE__)
#define XCALLOC(type,size)      mfh_calloc (size, type, __FILE__,  __LINE__)
#define XFREE(type,ptr)         memmgr_free (type, ptr,  __FILE__,  __LINE__)
#define XREALLOC(type,ptr,size) mfh_realloc (ptr, size, type,  __FILE__,  __LINE__)
#define XSTRDUP(type,str)       mfh_strdup (str, type, __FILE__,  __LINE__)
#else

struct memory_global
{
  u_int32_t max_mem_size;
  struct lib_globals *zg;
};

void memory_set_zg (void *);
void memory_unset_zg (void *);

/* Malloc Fault Handler Prototype */
void *mfh_malloc (enum memory_type, size_t);
void *mfh_calloc (enum memory_type, size_t);
void *mfh_realloc (enum memory_type, void *, size_t);
char *mfh_strdup (enum memory_type, const char *);

#define XMALLOC(type,size)      mfh_malloc (type, size)
#define XCALLOC(type,size)      mfh_calloc (type, size)
#define XFREE(type,ptr)         pal_mem_free (type, ptr)
#define XREALLOC(type,ptr,size) mfh_realloc (type, ptr, size)
#define XSTRDUP(type,str)       mfh_strdup (type, str)
#endif /* MEMMGR */

struct lib_globals;

#endif /* _BGPSDN_MEMORY_H */
