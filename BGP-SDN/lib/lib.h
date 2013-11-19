/*=============================================================================
**
** Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.
**
** lib.h -- BGP-SDN library common definitions
*/
#ifndef _LIB_H
#define _LIB_H

/*-----------------------------------------------------------------------------
**
** Include files
*/
#include "pal.h"
#include "pal_types.h"
#include "pal_socket.h"
#include "pal_log.h"
#include "pal_memory.h"

#include "memory.h"
#ifdef MEMMGR
#include "memmgr.h"
#include "memmgr_cli.h"
#endif /* MEMMGR */
#include "fifo.h"
#include "vector.h"
#include "prefix.h"
#include "vty.h"
#include "host.h"
#include "auth_md5.h"

#include "if.h"
#include "filter.h"
#include "plist.h"
#include "routemap.h"
#include "entity.h"
#include "hash.h"
#ifdef HAVE_SNMP
#include "snmp.h"
#include "snmp_misc.h"
#endif /* HAVE_SNMP */
#include "api.h"

#include "commsg.h"
#include "message.h"

#include "mod_stop.h"

#define IPI_MAX(a,b) ((a) > (b) ? (a) : (b))
#define IPI_MIN(a,b) ((a) < (b) ? (a) : (b))

/* An 'infinite' distance to the routing protocols. */
#define DISTANCE_INFINITY       255

#define LIB_MAX_PROG_NAME       15

/* Value of u_int_32 maximum value*/
#define VECTOR_MEM_ALLOC_ERROR 0xFFFFFFFF

/* Maximum VR name length
 * Required for IPNET to limit the per-VR loopback
 * interface name to the IP_IFNAMSIZ (16)
 * Max len = 16 - 1 ('\0') - 2 ("lo") - 1 (Seperator ".") = 12
 */
#define LIB_VR_MAX_NAMELEN                         12

struct ipi_vr
{
  /* Pointer to globals. */
  struct lib_globals *zg;

  /* VR name. */
  char *name;

  /* VR ID. */
  u_int32_t id;

  /* Router ID. */
  struct pal_in4_addr router_id;

  u_int8_t flags;
#define LIB_FLAG_DELETE_VR_CONFIG_FILE    (1 << 0)

  /* Interface Master. */
  struct if_vr_master ifm;

  /* VRFs. */
  vector vrf_vec;

  /* VRFs. */
  struct ipi_vrf *vrf_list;

  /* Protocol bindings. */
  u_int32_t protos;

  /* Host. */
  struct host *host;

  /* Access List. */
  struct access_master access_master_ipv4;
#ifdef HAVE_IPV6
  struct access_master access_master_ipv6;
#endif /* def HAVE_IPV6 */

  /* Prefix List. */
  struct prefix_master prefix_master_ipv4;
#ifdef HAVE_IPV6
  struct prefix_master prefix_master_ipv6;
#endif /* HAVE_IPV6 */
  struct prefix_master prefix_master_orf;

  /* Route Map. */
  vector route_match_vec;
  vector route_set_vec;
  struct route_map_list route_map_master;

  /* Key Chain. */
  struct list *keychain_list;

  /* Protocol Master. */
  void *proto;

  /* Config read event. */
  struct thread *t_config;

  /* VRF currently in context */
  struct ipi_vrf *vrf_in_cxt;

  /* If stats update threshold timer */
  struct thread *t_if_stat_threshold;

  struct entLogicalEntry *entLogical;
  struct list *mappedPhyEntList;

  /* Community string to identify current VR */
  struct snmpCommunity snmp_community;

};

/* Logical entity structure */
struct entLogicalEntry
{
  u_int32_t entLogicalIndex;
  char *entLogicalDescr;
  char *entLogicalType;
  char *entLogicalCommunity;
  char *entLogicalTAddress;
  char *entLogicalTDomain;
  char *entLogicalContextEngineId;
  char *entLogicalContextName;
};

struct ipi_vrf
{
  /* VRF Linked List Pointers, List indexed by 'name' */
  struct ipi_vrf *prev;
  struct ipi_vrf *next;

  /* Pointer to VR. */
  struct ipi_vr *vr;

  /* VRF ID. */
  vrf_id_t id;

  /* Table ID. */
  fib_id_t fib_id;

  /* VRF name. */
  char *name;

  /* Router ID. */
  struct pal_in4_addr router_id;

  /* Interface Master. */
  struct if_vrf_master ifv;

  /* Protocol data. */
  void *proto;

};

enum vr_callback_type
{
  VR_CALLBACK_ADD,
  VR_CALLBACK_DELETE,
  VR_CALLBACK_CLOSE,
  VR_CALLBACK_UNBIND,
  VR_CALLBACK_CONFIG_READ,
  VR_CALLBACK_ADD_UNCHG,
  VR_CALLBACK_MAX
};

enum vrf_callback_type
{
  VRF_CALLBACK_ADD,
  VRF_CALLBACK_DELETE,
  VRF_CALLBACK_UPDATE,
  VRF_CALLBACK_ROUTER_ID,
  VRF_CALLBACK_MAX
};

/* Library Globals
   One of these is kept per daemon, or instance of daemon, depending upon
   implementation and support for such features as virtual routing. */
struct lib_globals
{
  char progname[LIB_MAX_PROG_NAME+1];

  /* Module ID defined in pal/api/pal_modules.def.  */
  module_id_t protocol;

  /* Flags */
  u_int8_t flags;
#define LIB_FLAG_SHUTDOWN_IN_PROGRESS           (1 << 0)

  mod_stop_cause_t stop_cause;

  /* Banner configuration.  */
  char *motd;

  /* Current working directory.  */
  char *cwd;

  /* Thread master. */
  struct thread_master *master;
  struct thread *pend_read_thread;

  /* Interface Master. */
  struct if_master ifg;

  /* VR vector. */
  vector vr_vec;

  /* VRF vector for Kernel Table ID mapping. */
  vector fib2vrf;

  /* Log. */
  struct zlog *log;
  struct zlog *log_default;

#ifdef HAVE_SNMP
  /* snmp : agentx or smux */
  struct snmp_master snmp;
#endif /* HAVE_SNMP */

  /* Callback functions. */
  int (*vr_callback[VR_CALLBACK_MAX]) (struct ipi_vr *);
  int (*vrf_callback[VRF_CALLBACK_MAX]) (struct ipi_vrf *);
  int (*user_callback[USER_CALLBACK_MAX]) (struct ipi_vr *,
                                           struct host_user *);

  /* ONM client. */
  struct onm_server *os;
  struct onm_client *oc;

  /* VR. */
  u_int32_t vr_instance;

  /* PAL. */
  pal_handle_t pal_debug;
  pal_handle_t pal_kernel;
  pal_handle_t pal_log;
  pal_handle_t pal_np;
  pal_handle_t pal_socket;
  pal_handle_t pal_stdlib;
  pal_handle_t pal_string;
  pal_handle_t pal_time;

  /* Vty master structure. */
  struct vty_server *vty_master;

  /* CLI tree. */
  struct cli_tree *ctree;

  /* IMI message handler.  */
  struct message_handler *imh;

  /* Show server.  */
  struct show_server *ss;

  /* Fault Management - Fault Recording. */
  void *lib_fm;

  /* Protocol Globals. */
  void *proto;

  /* VR currently in context */
  struct ipi_vr *vr_in_cxt;

  /* Stream Socket-CB Zombies List */
  struct list *ssock_cb_zombie_list;

  /* Circular Queue Buffers Free List */
  struct cqueue_buf_list *cqueue_buf_free_list;

  /* Instance of COMMSG transport for this daemon. */
  COMMSG *commsg;

  /* Access-list add/delete notification callback. */
  filter_ntf_cb_t lib_acl_ntf_cb;

};

#define IS_LIB_IN_SHUTDOWN(LIB_GLOB)                            \
  (CHECK_FLAG ((LIB_GLOB)->flags, LIB_FLAG_SHUTDOWN_IN_PROGRESS))
#define SET_LIB_IN_SHUTDOWN(LIB_GLOB)                           \
  SET_FLAG ((LIB_GLOB)->flags, LIB_FLAG_SHUTDOWN_IN_PROGRESS)
#define UNSET_LIB_IN_SHUTDOWN(LIB_GLOB)                         \
  UNSET_FLAG ((LIB_GLOB)->flags, LIB_FLAG_SHUTDOWN_IN_PROGRESS)

#define SET_LIB_STOP_CAUSE(LIB_GLOB, cause) \
  (LIB_GLOB)->stop_cause = (cause)
#define GET_LIB_STOP_CAUSE(LIB_GLOB) (LIB_GLOB)->stop_cause

#define LIB_CALLBACK_VERIFY(LIB_GLOB, GLOB, FUNC_PTR_ARR, CALLBACK_ID)        \
  ((! IS_LIB_IN_SHUTDOWN ((LIB_GLOB))) && ((GLOB)->FUNC_PTR_ARR[(CALLBACK_ID)]))

/*
 * Utility Macros for manipulating Library Structures
 */
#define IPI_PVR_ID              0
#define IS_IPI_VR_PRIVILEGED(V) ((V) != NULL && (V)->id == IPI_PVR_ID)
#define IS_IPI_VRF_DEFAULT(V)   ((V) == NULL || (V)->name == NULL)
#define IS_IPI_VRF_PRIV_DEFAULT(V)   (IS_IPI_VRF_DEFAULT (V)     \
                                      && IS_IPI_VR_PRIVILEGED ((V)->vr))
#define IS_IPI_VRF_UP(V)        ((V) != NULL && (V)->id != VRF_ID_DISABLE)

#define LIB_GLOB_SET_PROTO_GLOB(LIB_GLOB, PROTO_GLOB)                 \
    (((LIB_GLOB)->proto) = (PROTO_GLOB))
#define LIB_GLOB_GET_PROTO_GLOB(LIB_GLOB)  ((LIB_GLOB)->proto)

#define LIB_VR_SET_PROTO_VR(LIB_VR, PROTO_VR)                         \
    (((LIB_VR)->proto) = (PROTO_VR))
#define LIB_VR_GET_PROTO_VR(LIB_VR)        ((LIB_VR)->proto)
#define LIB_VR_GET_VR_ID(LIB_VR)           ((LIB_VR)->id)
#define LIB_VR_GET_VR_NAME(LIB_VR)         ((LIB_VR)->name)
#define LIB_VR_GET_VR_NAME_STR(LIB_VR)                                \
    ((LIB_VR)->name ? (LIB_VR)->name : "Default")
#define LIB_VR_GET_IF_MASTER(LIB_VR)       (&(LIB_VR)->ifm)
#define LIB_VR_GET_IF_TABLE(LIB_VR)        ((LIB_VR)->ifm.if_table)

#define LIB_VRF_SET_PROTO_VRF(LIB_VRF, PROTO_VRF)                     \
    (((LIB_VRF)->proto) = (PROTO_VRF))
#define LIB_VRF_GET_PROTO_VRF(LIB_VRF)     ((LIB_VRF)->proto)
#define LIB_VRF_GET_VRF_ID(LIB_VRF)        ((LIB_VRF)->id)
#define LIB_VRF_GET_VRF_NAME(LIB_VRF)      ((LIB_VRF)->name)
#define LIB_VRF_GET_VR(LIB_VRF)            ((LIB_VRF)->vr)
#define LIB_VRF_GET_VRF_NAME_STR(LIB_VRF)                             \
    ((LIB_VRF)->name ? (LIB_VRF)->name : "Default")
#define LIB_VRF_GET_FIB_ID(LIB_VRF)        ((LIB_VRF)->fib_id)
#define LIB_VRF_GET_IF_MASTER(LIB_VRF)     (&(LIB_VRF)->ifv)
#define LIB_VRF_GET_IF_TABLE(LIB_VRF)      ((LIB_VRF)->ifv.if_table)
/*
 * Macros for Context-based execution
 */
#define LIB_GLOB_SET_VR_CONTEXT(LIB_GLOB, VR_CXT)                     \
  do {                                                                \
    ((LIB_GLOB)->vr_in_cxt) = (VR_CXT);                               \
  } while (0)
#define LIB_GLOB_GET_VR_CONTEXT(LIB_GLOB)  ((LIB_GLOB)->vr_in_cxt)
#define LIB_VR_SET_VRF_CONTEXT(LIB_VR, VRF_CXT)                       \
  do {                                                                \
    ((LIB_VR)->vrf_in_cxt) = (VRF_CXT);                               \
  } while (0)
#define LIB_VR_GET_VRF_CONTEXT(LIB_VR)     ((LIB_VR)->vrf_in_cxt)

#ifdef HAVE_SNMP
#define SNMP_MASTER(ZG)                              (&(ZG)->snmp)
#endif /* HAVE_SNMP. */

#define ipi_offsetof(type, mem) (pal_size_t)(&(((type *)0)->mem))

#define ARR_ELEM_TO_INDEX(TYPE,ARR,ELEM)  ((TYPE*)&(ELEM) - (TYPE*)&((ARR)[0]))

/* Macro to Stringize a variable */
#define VAR_STRINGIZE(VAR)             # VAR
#define VAR_SUPERSTR(VAR)              VAR_STRINGIZE (VAR)

/* Macro for Catenatiion a variables */
#define VAR_CATENIZE(VAR1, VAR2)       VAR1 ## VAR2
#define VAR_SUPERCAT(VAR1, VAR2)       VAR_CATENIZE (VAR1, VAR2)

/* Extern definition. */
extern char *loglevel[9];
extern char *modnames[13];
extern char *modnamel[13];

/* Prototypes. */
extern struct lib_globals *
lib_create(char *progname);

struct lib_globals *
lib_clean (struct lib_globals *zg);

extern result_t
lib_start (struct lib_globals *);

extern result_t
lib_stop (struct lib_globals *);

result_t
lib_set_context (struct lib_globals *zg,
                 struct ipi_vr *vr, struct ipi_vrf *vrf);

result_t
lib_set_context_by_ifp (struct lib_globals *zg, struct interface *ifp);

result_t
lib_set_context_by_id (struct lib_globals *zg,
                       u_int32_t vr_id, vrf_id_t vrf_id);

void ipi_vr_delete (struct ipi_vr *);
struct ipi_vr *ipi_vr_get (struct lib_globals *);
struct ipi_vr *ipi_vr_get_by_name (struct lib_globals *, char *);
struct ipi_vr *ipi_vr_get_by_id (struct lib_globals *, u_int32_t);
struct ipi_vr *ipi_vr_get_privileged (struct lib_globals *);
struct ipi_vr *ipi_vr_lookup_by_id (struct lib_globals *, u_int32_t);
struct ipi_vr *ipi_vr_lookup_by_name (struct lib_globals *, char *);
struct ipi_vr *ipi_vr_update_by_name (struct lib_globals *, char *, u_int32_t);

typedef ZRESULT (* IPI_VRS_WALK_CB)(struct ipi_vr *, intptr_t);

ZRESULT ipi_vrs_walk_and_exec(struct lib_globals *zg,
                              IPI_VRS_WALK_CB func,
                              intptr_t user_ref);
void ipi_vrf_delete (struct ipi_vrf *);
struct ipi_vrf *ipi_vrf_get_by_name (struct ipi_vr *, char *);
struct ipi_vrf *ipi_vrf_lookup_by_name (struct ipi_vr *, char *);
struct ipi_vrf *ipi_vrf_lookup_by_id (struct ipi_vr *, u_int32_t);
struct ipi_vrf *ipi_vrf_lookup_default (struct ipi_vr *);

void ipi_vr_add_callback (struct lib_globals *, enum vr_callback_type,
                          int (*func) (struct ipi_vr *));
void ipi_vrf_add_callback (struct lib_globals *, enum vrf_callback_type,
                           int (*func) (struct ipi_vrf *));

int protoid2routetype (int);

char *modname_strl (int);
char *modname_strs (int);
char *loglevel_str (int);

#endif /* _LIB_H */
