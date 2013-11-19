/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_IF_H
#define _BGPSDN_IF_H

#include "pal.h"
#include "pal_socket.h"

#include "linklist.h"

struct interface;
struct connected;

enum if_callback_type
{
  IF_CALLBACK_NEW,
  IF_CALLBACK_DELETE,
  IF_CALLBACK_UP,
  IF_CALLBACK_DOWN,
  IF_CALLBACK_UPDATE,
  IF_CALLBACK_VR_BIND,
  IF_CALLBACK_VR_UNBIND,
  IF_CALLBACK_VRF_BIND,
  IF_CALLBACK_VRF_UNBIND,
  IF_CALLBACK_PRIORITY_BW,
  IF_CALLBACK_MAX,
};

enum ifc_callback_type
{
  IFC_CALLBACK_ADDR_ADD,
  IFC_CALLBACK_ADDR_DELETE,
  IFC_CALLBACK_SESSION_CLOSE,
  IFC_CALLBACK_MAX,
};

struct if_master
{
  /* Lib Globals. */
  struct lib_globals *zg;

  /* Interface table. */
  struct route_table *if_table;

  /* Interface list. */
  struct list *if_list;

  pal_time_t ifTblLastChange;

  /* Internal hash for name lookup. */
  struct hash *if_hash;

  /* Callback functions. */
  int (*if_callback[IF_CALLBACK_MAX]) (struct interface *);
  int (*ifc_callback[IFC_CALLBACK_MAX]) (struct connected *);
};


struct if_vr_master
{
  /* Pointer to VR. */
  struct ipi_vr *vr;

  /* Interface table. */
  struct route_table *if_table;

  /* Interface list. */
  struct list *if_list;
};

struct if_vrf_master
{
  /* Pointer to VRF. */
  struct ipi_vrf *vrf;

  /* Interface table. */
  struct route_table *if_table;

  /* IPv4 address table. */
  struct route_table *ipv4_table;

#ifdef HAVE_IPV6
  /* IPv6 address table. */
  struct route_table *ipv6_table;
#endif /* HAVE_IPV6 */

};

/* For interface table key. */
struct prefix_if
{
  u_char family;
  u_char prefixlen;
  u_char pad1;
  u_char pad2;
  s_int32_t ifindex;
};

#define INTERFACE_NAMSIZ      ((IFNAMSIZ)+4)
#define INTERFACE_HWADDR_MAX  (IFHWASIZ)

/* Internal If indexes start at 0xFFFFFFFF and go down to 1 greater
   than this */

#define IFINDEX_INTERNBASE 0x80000000

/* Bandwidth-specific defines */
#define MAX_BANDWIDTH                  10000000000.0
#define MAX_BANDWIDTH_LONG             10000000000
#define LEGAL_BANDWIDTH(b)             (((b) > 0) && ((b) <= MAX_BANDWIDTH))
#define BW_CONSTANT                    1000
#define BW_BUFSIZ                      19
#define MAX_WHOLE_STR_BUFSIZ           30
#define MAX_BW_STR_SIZE                11

/* Duplex-specific defines */
#define NSM_IF_HALF_DUPLEX      0
#define NSM_IF_FULL_DUPLEX      1
#define NSM_IF_AUTO_NEGO        2
#define NSM_IF_DUPLEX_UNKNOWN   3

#define NSM_IF_AUTONEGO_DISABLE 1
#define NSM_IF_AUTONEGO_ENABLE  0

#define IF_ETHER_HEADER_LEN     14
#define IF_ETHER_CRC_LEN        4

/* Interface structure */
struct interface
{
  /* Interface name. */
  char name[INTERFACE_NAMSIZ + 1];

  /* Interface index. */
  s_int32_t ifindex;

  /* Interface attribute update flags.  */
  u_int32_t cindex;

  /* Interface flags. */
  u_int32_t flags;

  /* BGP-SDN internal interface status */
  u_int32_t status;

  /* Interface metric */
  s_int32_t metric;

  /* Interface MTU. */
  s_int32_t mtu;

  /* Interface DUPLEX status. */
  u_int32_t duplex;

  /* Interface AUTONEGO. */
  u_int32_t autonego;

  /* Interface MDIX crossover. */
  u_int32_t mdix;

  /* Interface ARP AGEING TIMEOUT. */
  u_int32_t arp_ageing_timeout;

  /* Slot Id. */
  u_int32_t slot_id;

  /* Hardware address. */
  u_int16_t hw_type;
  u_int8_t hw_addr[INTERFACE_HWADDR_MAX];

  s_int32_t hw_addr_len;

  /* interface bandwidth, bytes/s */
  float64_t bandwidth;

  /*Interface link up or link down traps */
  s_int32_t if_linktrap;

  /* Interface alias name */
  char if_alias[INTERFACE_NAMSIZ + 1];

  /* Has the bandwidth been configured/read from kernel. */
  char conf_flags;

  /* description of the interface. */
  char *desc;

  /* Connected address list. */
  struct connected *ifc_ipv4;
#ifdef HAVE_IPV6
  struct connected *ifc_ipv6;
#endif /* HAVE_IPV6 */

  /* Unnumbered interface list.  */
  struct list *unnumbered_ipv4;
#ifdef HAVE_IPV6
  struct list *unnumbered_ipv6;
#endif /* HAVE_IPV6 */

  /* Daemon specific interface data pointer. */
  void *info;

  /* Pointer to VR/VRF context. */
  struct ipi_vr *vr;
  struct ipi_vrf *vrf;

  /* Bind information.  */
  u_char bind;

  pal_time_t ifLastChange;

  /* To store the configured duplex value */
  u_char config_duplex;

 struct list *clean_pend_resp_list;

  struct list *rmap_if_match_cmd_list;

  /*Interface BW- Configured CIR/EIR sync*/
  struct nsm_band_width_profile *bw_profile;
};

/* Connected address structure. */
struct connected
{
  struct connected *next;
  struct connected *prev;

  /* Attached interface. */
  struct interface *ifp;

  /* Address family for prefix. */
  u_int8_t family;

  /* Flags for configuration. */
  u_int8_t conf;
#define NSM_IFC_REAL            (1 << 0)
#define NSM_IFC_CONFIGURED      (1 << 1)
#define NSM_IFC_ARBITER         (1 << 2)
#define NSM_IFC_ACTIVE          (1 << 3)

  /* Flags for connected address. */    /* XXX-VR */
  u_int8_t flags;
#define NSM_IFA_SECONDARY       (1 << 0)
#define NSM_IFA_ANYCAST         (1 << 1)
#define NSM_IFA_VIRTUAL         (1 << 2)

  /* Address of connected network. */
  struct prefix *address;
  struct prefix *destination;
};

/*
 * Utility Macros for manipulating Library Structures
 */
#define INTF_TYPE_L2(IFP)                  ((IFP)->type == IF_TYPE_L2)
#define INTF_TYPE_L3(IFP)                  ((IFP)->type == IF_TYPE_L3)
#define LIB_IF_SET_LIB_VR(LIB_IF, LIB_VR)                             \
    (((LIB_IF)->vr) = (LIB_VR))
#define LIB_IF_GET_LIB_VR(LIB_IF)          ((LIB_IF)->vr)

#define LIB_IF_SET_LIB_VRF(LIB_IF, LIB_VRF)                           \
    (((LIB_IF)->vrf) = (LIB_VRF))
#define LIB_IF_GET_LIB_VRF(LIB_IF)          ((LIB_IF)->vrf)

#define PREFIX_IF_SET(P,I)                              \
  do {                                                  \
    pal_mem_set ((P), 0, sizeof (struct prefix_if));    \
    (P)->family = AF_INET;                              \
    (P)->prefixlen = 32;                                \
    (P)->ifindex = pal_hton32 (I);                      \
  } while (0)

#define RN_IF_INFO_SET(R,V)                     \
  do {                                          \
    (R)->info = (V);                            \
    route_lock_node (R);                        \
  } while (0)

#define RN_IF_INFO_UNSET(R)                     \
  do {                                          \
    (R)->info = NULL;                           \
    route_unlock_node (R);                      \
  } while (0)

#define IF_MATCH_IFC_BY_IPV4_SUB(ifp, ifc, rn, p, match, best_prefixlen, addr)\
  do {                                                                  \
    for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)                     \
      if ((p = ifc->address))                                           \
        {                                                               \
          if (if_is_pointopoint (ifp))                                  \
            {                                                           \
              if ((p = ifc->destination))                               \
                if (IPV4_ADDR_SAME (&p->u.prefix4, addr))               \
                  match = ifc;                                  \
            }                                                           \
          else                                                          \
            {                                                           \
              if (prefix_match (p, &q) && p->prefixlen > best_prefixlen) \
                {                                                       \
                  best_prefixlen = p->prefixlen;                        \
                  match = ifc;                                          \
                }                                                       \
            }                                                           \
        }                                                               \
  } while (0)

/* Exported variables. */
extern struct cli_element interface_desc_cli;
extern struct cli_element no_interface_desc_cli;

/* Prototypes. */
struct connected *ifc_new (u_char);
struct connected *ifc_get_ipv4 (struct pal_in4_addr *, u_char,
                                struct interface *);
#ifdef HAVE_IPV6
struct connected *ifc_get_ipv6 (struct pal_in6_addr *, u_char,
                                struct interface *);
#endif /* HAVE_IPV6 */
void ifc_free (struct lib_globals *, struct connected *);
u_int32_t if_ifc_ipv4_count (struct interface *);
void if_add_ifc_ipv4 (struct interface *, struct connected *);
void if_delete_ifc_ipv4 (struct interface *, struct connected *);
char * if_map_lookup (struct hash *, char *);
struct connected *if_lookup_ifc_ipv4 (struct interface *,
                                      struct pal_in4_addr *);
struct connected *if_lookup_ifc_prefix (struct interface *, struct prefix *);

struct connected *if_match_ifc_ipv4_direct (struct interface *,
                                            struct prefix *);
void if_delete_ifc_by_ipv4_addr (struct interface *, struct pal_in4_addr *);
#ifdef HAVE_IPV6
u_int32_t if_ifc_ipv6_count (struct interface *);
void if_add_ifc_ipv6 (struct interface *, struct connected *);
void if_delete_ifc_ipv6 (struct interface *, struct connected *);
struct connected *if_lookup_ifc_ipv6 (struct interface *,
                                      struct pal_in6_addr *);
struct connected *if_lookup_ifc_ipv6_linklocal (struct interface *);
struct connected *if_lookup_ifc_ipv6_global (struct interface *);
void if_delete_ifc_by_ipv6_addr (struct interface *, struct pal_in6_addr *);
struct connected *if_match_ifc_ipv6_direct (struct interface *, struct prefix *);
#endif /* HAVE_IPV6 */
struct interface *if_lookup_by_name (struct if_vr_master *, char *);
struct interface *if_lookup_by_index (struct if_vr_master *, u_int32_t);
struct interface *if_lookup_by_ipv4_address (struct if_vr_master *,
                                             struct pal_in4_addr *);
struct interface *if_lookup_loopback (struct if_vr_master *);
struct interface *if_match_by_ipv4_address (struct if_vr_master *,
                                            struct pal_in4_addr *, vrf_id_t);
struct connected * if_subnet_match_by_ipv4_address (struct if_vr_master *,
                           struct pal_in4_addr *, vrf_id_t);
struct interface * if_lookup_by_hw_addr (struct if_vr_master *ifm,
                                                char *mac_addr);
struct prefix *if_get_connected_address (struct interface *, u_int8_t);
struct interface *if_match_all_by_ipv4_address (struct if_vr_master *,
                                                struct pal_in4_addr *,
                                                struct connected **);
struct interface *ifv_lookup_by_prefix (struct if_vrf_master *,
                                        struct prefix *);

#ifdef HAVE_IPV6
struct interface *if_lookup_by_ipv6_address (struct if_vr_master *,
                                             struct pal_in6_addr *);
struct interface *if_match_by_ipv6_address (struct if_vr_master *,
                                            struct pal_in6_addr *, vrf_id_t);
struct interface *if_match_all_by_ipv6_address (struct if_vr_master *,
                                                struct pal_in6_addr *);
#endif /* HAVE_IPV6 */

struct interface *if_lookup_by_prefix (struct if_vr_master *, struct prefix *);

struct interface *
if_match_by_prefix (struct if_vr_master *ifm, struct prefix *p,
                    vrf_id_t vrf_id);

char *if_index2name (struct if_vr_master *, int);
s_int32_t if_name2index (struct if_vr_master *, char *);
char *if_index2name_copy (struct if_vr_master *, int, char *);
char *if_kernel_name (struct interface *);

struct interface *if_new (struct if_master *);
void if_delete (struct if_master *, struct interface *);
void if_master_init (struct if_master *, struct lib_globals *);
void if_master_finish (struct if_master *);
int ifg_table_add (struct if_master *, int, struct interface *);
int ifg_table_delete (struct if_master *, int);
struct interface *ifg_lookup_by_index (struct if_master *, u_int32_t);
struct interface *ifg_lookup_by_prefix (struct if_master *, struct prefix *);
void ifg_list_add (struct if_master *, struct interface *);
void ifg_list_delete (struct if_master *, struct interface *);
struct interface *ifg_lookup_by_name (struct if_master *, char *);
struct interface *ifg_get_by_name (struct if_master *, char *);

void if_vr_master_init (struct if_vr_master *, struct ipi_vr *);
void if_vr_master_finish (struct if_vr_master *, struct ipi_vr *);
int if_vr_bind (struct if_vr_master *, int);
int if_vr_unbind (struct if_vr_master *, int);
int if_vr_table_add (struct if_vr_master *ifvrm, int ifindex, struct interface *ifp);
int if_vr_table_delete (struct if_vr_master *ifvrm, int ifindex);

bool_t if_vrf_master_init (struct if_vrf_master *, struct ipi_vrf *);
void if_vrf_master_finish (struct if_vrf_master *, struct ipi_vrf *);
int if_vrf_bind (struct if_vrf_master *, int);
int if_vrf_unbind (struct if_vrf_master *, int);
int if_vrf_table_add (struct if_vrf_master *ifvrm, int ifindex, struct interface *ifp);
int if_vrf_table_delete (struct if_vrf_master *ifvrm, int ifindex);
struct interface * ifv_lookup_by_name (struct if_vrf_master *, char *);
struct interface *ifv_lookup_by_index (struct if_vrf_master *, u_int32_t);
struct interface *ifv_lookup_next_by_index (struct if_vrf_master *, u_int32_t);
int if_ifindex_update (struct if_master *, struct interface *, int);

void if_add_hook (struct if_master *, enum if_callback_type,
                  int (*func) (struct interface *));
void ifc_add_hook (struct if_master *, enum ifc_callback_type,
                   int (*func) (struct connected *));

u_int16_t if_get_hw_type (struct interface *);
result_t if_is_up (const struct interface *);
result_t if_is_running (struct interface *);
result_t if_is_loopback (struct interface *);
result_t if_is_broadcast (struct interface *);
result_t if_is_pointopoint (struct interface *);

result_t bandwidth_string_to_float (char *, float32_t *);
char *bandwidth_float_to_string (char *, float64_t);

#endif /* _BGPSDN_IF_H */
