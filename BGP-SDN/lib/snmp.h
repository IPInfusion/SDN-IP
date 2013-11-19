/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_SNMP_H
#define _BGPSDN_SNMP_H

#include "pal.h"
#ifdef HAVE_SNMP

#include "asn1.h"

#include "pal_socket.h"
#include "lib.h"

#ifdef HAVE_AGENTX
#include "agentx.h"
#else
#include "smux.h"
#endif /* HAVE_AGENTX */

/* Forward declarations. */
struct variable;

/* Structures here are mostly compatible with UCD SNMP 4.1.1 */
#define MATCH_FAILED     (-1)
#define MATCH_SUCCEEDED  0

/* SYNTAX TruthValue from SNMPv2-TC. */
#define SNMP_TRUE  1
#define SNMP_FALSE 2

/* SYNTAX RowStatus from SNMPv2-TC. */
#define SNMP_VALID  1
#define SNMP_INVALID 2

/* CHOICE value for Exceptions Response in Report-PDU from RFC1905. */
#define SNMP_NOSUCHOBJECT       (ASN_CONTEXT | ASN_PRIMITIVE | 0x0)
#define SNMP_NOSUCHINSTANCE     (ASN_CONTEXT | ASN_PRIMITIVE | 0x1)
#define SNMP_ENDOFMIBVIEW       (ASN_CONTEXT | ASN_PRIMITIVE | 0x2)

/* Error status in Report-PDU from RFC1905. and SNMPv3 */
#define SNMP_ERR_NOERROR        (0)
#define SNMP_ERR_TOOBIG         (1)
#define SNMP_ERR_NOSUCHNAME     (2)
#define SNMP_ERR_BADVALUE       (3)
#define SNMP_ERR_READONLY       (4)
#define SNMP_ERR_GENERR         (5)
#define SNMP_ERR_NOACCESS       (6)
#define SNMP_ERR_WRONGTYPE      (7)
#define SNMP_ERR_WRONGLENGTH    (8)
#define SNMP_ERR_WRONGENCODING  (9)
#define SNMP_ERR_WRONGVALUE     (10)
#define SNMP_ERR_NOCREATION             (11)
#define SNMP_ERR_INCONSISTENTVALUE      (12)
#define SNMP_ERR_RESOURCEUNAVAILABLE    (13)
#define SNMP_ERR_COMMITFAILED           (14)
#define SNMP_ERR_UNDOFAILED             (15)
#define SNMP_ERR_AUTHORIZATIONERROR     (16)
#define SNMP_ERR_NOTWRITABLE            (17)
#define SNMP_ERR_INCONSISTENTNAME       (18)
                                                                                
#define MAX_SNMP_ERR            18

/* The generic-trap field in trap PDUs */
#define SNMP_TRAP_COLDSTART             (0)
#define SNMP_TRAP_WARMSTART             (1)
#define SNMP_TRAP_LINKDOWN              (2)
#define SNMP_TRAP_LINKUP                (3)
#define SNMP_TRAP_AUTHFAIL              (4)
#define SNMP_TRAP_EGPNEIGHBORLOSS       (5)
#define SNMP_TRAP_ENTERPRISESPECIFIC    (6)

/* SYNTAX RowStatus from SNMPv2-TC. */
#define SNMP_ROW_NONEXISTENT    0
#define SNMP_ROW_ACTIVE         1
#define SNMP_ROW_NOTINSERVICE   2
#define SNMP_ROW_NOTREADY       3
#define SNMP_ROW_CREATEANDGO    4
#define SNMP_ROW_CREATEANDWAIT  5
#define SNMP_ROW_DESTROY        6

#define SNMP_MAX_LEN            1500
#define SPRINT_MAX_LEN          2560


#define IN_ADDR_SIZE sizeof(struct pal_in4_addr)

#ifdef HAVE_IPV6
#define MAX_WAIT_COUNT          50
#define IN6_ADDR_SIZE sizeof(struct pal_in6_addr)
#endif /*HAVE_IPV6*/

typedef s_int32_t (WriteMethod)(s_int32_t action,
                                u_int8_t *var_val,
                                u_int8_t var_val_type,
                                size_t var_val_len,
                                u_int8_t *statP,
                                oid *name,
                                size_t length,
                                struct variable *v, 
                                u_int32_t vr_id);

typedef u_int8_t *(FindVarMethod)(struct variable *v,
                                  oid *name,
                                  size_t *length,
                                  s_int32_t exact,
                                  size_t *var_len,
                                  WriteMethod **write_method,
                                  u_int32_t vr_id);

/* SNMP variable */
struct variable
{
  /* Index of the MIB.*/
  u_int8_t magic;

  /* Type of variable. */
  char type;

  /* Access control list. */
  u_int8_t acl;

  /* Callback function. */
  FindVarMethod *findVar;

  /* Suffix of the MIB. */
  u_int8_t namelen;
  oid name[MAX_OID_LEN];

  /* Lib globals */
  struct lib_globals *lg;
};

/* SNMP tree. */
struct subtree
{
  /* Tree's oid. key value for sort. */
  oid name[MAX_OID_LEN];
  u_int8_t name_len;

  /* List of the variables. */
  struct variable *variables;

  /* Length of the variables list. */
  s_int32_t variables_num;

  /* Width of the variables list. */
  s_int32_t variables_width;

  /* Registered flag. */
  s_int32_t registered;

#ifdef HAVE_AGENTX
  /* objid of start of covered range */
  oid *start_a;
  /* number of subid's in start name */
  u_char start_len;

  /* objid of end of covered range   */
  oid *end_a;
  /* number of subid's in end name */
  u_char end_len;

  struct agentx_session *session;

  u_int8_t flags;
  u_int8_t priority;
  s_int32_t timeout;

  s_int32_t range_subid;
  oid range_ubound;
#endif /* HAVE_AGENTX */
};

struct trap_object
{
  FindVarMethod *findVar;
  u_int8_t namelen;
  oid name[MAX_OID_LEN];
};

struct trap_object2
{
  size_t namelen;
  oid name[MAX_OID_LEN];
  u_char val_type;
  size_t val_len;
  void *val;
};

/* Declare Subagent return value. */
#define SNMP_LOCAL_VARIABLES                                                  \
  static int32_t snmp_int_val;                                                \
  static struct pal_in4_addr snmp_in_addr_val;

#define SNMP_INTEGER(V)                                                       \
  (                                                                           \
    *var_len = sizeof (int32_t),                                              \
    snmp_int_val = V,                                                         \
    (u_int8_t *) &snmp_int_val                                                \
  )

#define SNMP_IPADDRESS(V)                                                     \
  (                                                                           \
    *var_len = sizeof (struct pal_in4_addr),                                  \
    snmp_in_addr_val = V,                                                     \
    (u_int8_t *) &snmp_in_addr_val                                            \
  )

/* Subagent master container. */
struct snmp_master
{
  /* Subagent socket. */
  pal_sock_handle_t sock;

  /* Subagent tree list. */
  struct list *treelist;

  /* Subagent OID. */
  oid *oid;

  /* Subagent OID Length. */
  size_t oid_len;

  /* Subagent Default OID. */
  oid *default_oid;

  /* Subagent Default OID Length. */
  size_t default_oid_len;

  /* Subagent read thread. */
  struct thread *t_read;

  /* Subagent connect thread. */
  struct thread *t_connect;

  /* Subagent ping thread. */
  struct thread *t_ping;

  /* Subagent restart/stop thread. */
  struct thread *t_restart;

  /* Subagent debug flag. */
  s_int32_t debug;
#define SUBAG_DEBUG_SEND        (1 << 0)
#define SUBAG_DEBUG_RECV        (1 << 1)
#define SUBAG_DEBUG_PROCESS     (1 << 2)
#define SUBAG_DEBUG_XDUMP       (1 << 3)
#define SUBAG_DEBUG_LIBERR      (1 << 4)
#define SUBAG_DEBUG_DETAIL      (1 << 5)
#define SUBAG_DEBUG_MASK        (0xff)

  /* Subagent counter. */
  s_int32_t fail;

#ifndef HAVE_AGENTX
  /* SMUX password. */
  char *passwd;

  /* SMUX Default password. */
  char *default_passwd;

  /* This buffer we'll use for SOUT message. We could allocate it with
     malloc and save only static pointer/length, but IMHO static
     buffer is a faster solution. */
  u_int8_t sout_save_buff[SMUXMAXPKTSIZE];
  s_int32_t sout_save_len ;

#endif /* !HAVE_AGENTX */

#ifdef HAVE_AGENTX
  /* AgentX received and saved packet */
  u_int8_t *SavedPacket;
  s_int32_t SavedPacket_len;
  s_int32_t SavedPacket_size;
  
  /* AgentX saved information in subagent */
  struct agentx_session Agx_session;
  struct agentx_set_info Agx_set_info;
  struct agentx_request_info Agx_request_info;
  struct subtree *Agx_reg_subtree;
  
  /* AgentX state in subagent */
  enum agentx_state Agx_state;

  struct pal_timeval starttime;
  
  long Reqid;

  long Transid;

#endif /* HAVE_AGENTX */
};

#define IS_SUBAG_DEBUG          zg->snmp.debug
#define IS_SUBAG_DEBUG_SEND     (zg->snmp.debug & SUBAG_DEBUG_SEND)
#define IS_SUBAG_DEBUG_RECV     (zg->snmp.debug & SUBAG_DEBUG_RECV)
#define IS_SUBAG_DEBUG_PROCESS  (zg->snmp.debug & SUBAG_DEBUG_PROCESS)
#define IS_SUBAG_DEBUG_XDUMP    (zg->snmp.debug & SUBAG_DEBUG_XDUMP)
#define IS_SUBAG_DEBUG_LIBERR   (zg->snmp.debug & SUBAG_DEBUG_LIBERR)
#define IS_SUBAG_DEBUG_DETAIL   (zg->snmp.debug & SUBAG_DEBUG_DETAIL)

#define IS_SUBAG_DEBUG_LIBERR_SHOW(V)                                         \
  {                                                                           \
    if (IS_SUBAG_DEBUG_LIBERR)                                                \
      {                                                                       \
        char msg_buf[256];                                                    \
        snmp_lib_errstring ((V), msg_buf);                                    \
        zlog_info (zg, "        %s (lib_err=%d)", msg_buf, (V));              \
      }                                                                       \
  }


struct variable;

#ifdef HAVE_AGENTX
#define UNREGISTER_MIB agentx_unregister_mib
#define REGISTER_MIB(zg, descr, var, vartype, theoid)                         \
    agentx_register_mib (zg, descr, (struct variable *)var,                   \
                       sizeof(struct vartype),                                \
                       sizeof(var) / sizeof(struct vartype),                  \
                       theoid, sizeof(theoid) / sizeof(oid),                  \
                       0, 0, 0, 0, 0)

#else /* SMUX */
#define REGISTER_MIB(zg, descr, var, vartype, theoid)                         \
    smux_register_mib (zg, descr, (struct variable *)var,                     \
                       sizeof(struct vartype),                                \
                       sizeof(var) / sizeof(struct vartype),                  \
                       theoid, sizeof(theoid) / sizeof(oid))
#endif /* HAVE_AGENTX */

#ifdef HAVE_AGENTX
#define UNREGISTER_MIB2 agentx_unregister_mib
#define REGISTER_MIB2(zg, descr, var, vartype, theoid, objnum)                \
    agentx_register_mib (zg, descr, (struct variable *)var,                   \
                       sizeof(struct vartype),                                \
                       objnum,                                                \
                       theoid, sizeof(theoid) / sizeof(oid),                  \
                       0, 0, 0, 0, 0)

#else /* SMUX */
#define REGISTER_MIB2(zg, descr, var, vartype, theoid, objnum)                \
    smux_register_mib (zg, descr, (struct variable *)var,                     \
                       sizeof(struct vartype),                                \
                       objnum,                                                \
                       theoid, sizeof(theoid) / sizeof(oid))
#endif /* HAVE_AGENTX */


result_t
oid_compare_part (oid *o1, s_int32_t o1_len, oid *o2, s_int32_t o2_len);
s_int32_t oid_compare (oid *, s_int32_t, oid *, s_int32_t);
void oid2in_addr (oid [], s_int32_t, struct pal_in4_addr *);
void *oid_copy (void *, void *, size_t);
void oid_copy_addr (oid [], struct pal_in4_addr *, s_int32_t);
#ifdef HAVE_IPV6
void oid2in6_addr (oid [], s_int32_t, struct pal_in6_addr *);
void oid_copy_in6_addr (oid [], struct pal_in6_addr *, s_int32_t);
#endif /* HAVE_IPV6 */

extern char snmp_progname[100];
void snmp_progname_set ();
s_int32_t snmp_tree_cmp (struct subtree *tree1, struct subtree *tree2);
void snmp_make_tree (struct lib_globals *);
void snmp_init (struct lib_globals *, oid [], size_t);
void snmp_start (struct lib_globals *);
void snmp_restart (struct lib_globals *);
void snmp_stop (struct lib_globals *);
void snmp_debug_set (struct lib_globals *);
void snmp_debug_init (struct lib_globals *);
void snmp_debug_cli_init (struct lib_globals *zg);

s_int32_t snmp_header_generic (struct variable *, oid [], size_t *,
                                   s_int32_t, size_t *, WriteMethod **);
/* OID Dump and Hexa Dump */
void snmp_oid_dump (struct lib_globals *zg, char *prefix,
                        oid *oid, size_t oid_len);
void snmp_xdump (struct lib_globals *zg, char *prefix,
                     u_char *ptr, size_t length);
void snmp_debug_all_off(struct cli *cli);

/* convert smux -> subagent : CMBAE temporarilly */
#define smux_init           snmp_init
#define smux_start          snmp_start
#define smux_oid_dump       snmp_oid_dump
#define smux_header_generic snmp_header_generic
#define smux_debug_init     snmp_debug_init
#define smux_debug_set      snmp_debug_set
/*
 * Functions related to AgentX
 */
#ifdef HAVE_AGENTX
/* convert smux -> agentx : CMBAE temporarilly */
#define smux_trap agentx_trap
#define smux_trap2 agentx_trap2

#define snmp_trap agentx_trap
#define snmp_trap2 agentx_trap2
void agentx_register_mib (struct lib_globals *, char *, struct variable *,
                          size_t, s_int32_t, oid [], size_t,
                          s_int32_t, s_int32_t, s_int32_t, u_int8_t, u_int8_t);
void agentx_unregister_mib (struct lib_globals *zg,
                            oid name[], size_t namelen);
s_int32_t agentx_trap (struct lib_globals *, oid *, size_t, oid, oid *, size_t,
                       oid *, size_t, struct trap_object *, size_t, u_int32_t);
s_int32_t agentx_trap2 (struct lib_globals *, oid *, size_t, oid, oid *, size_t,
                        struct trap_object2 *, size_t, u_int32_t);
/*
 * Functions related to SMUX
 */
#else /* SMUX */
#define snmp_trap smux_trap
#define snmp_trap2 smux_trap2

void smux_register_mib (struct lib_globals *, char *, struct variable *,
                        size_t, s_int32_t, oid [], size_t);
s_int32_t smux_trap (struct lib_globals *, oid *, size_t, oid, oid *, size_t,
                     oid *, size_t, struct trap_object *, size_t, u_int32_t);
s_int32_t smux_trap2 (struct lib_globals *, oid *, size_t, oid, oid *, size_t,
                      struct trap_object2 *, size_t, u_int32_t);
#endif /* HAVE_AGENTX */

#endif /* HAVE_SNMP */

#endif /* _BGPSDN_SUBAGENT_H */
