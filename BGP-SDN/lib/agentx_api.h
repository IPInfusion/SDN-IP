/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_AGENTX_API_H
#define _BGPSDN_AGENTX_API_H

#ifdef HAVE_SNMP
#ifdef HAVE_AGENTX

/*
 *  SNMP-API definitions
 */

/*
 * Error return values.
 *
 * SNMPERR_SUCCESS is the non-PDU "success" code.
 *
 */
#define SNMPERR_SUCCESS                 (0)
#define SNMPERR_GENERR                  (-1)
#define SNMPERR_BAD_LOCPORT             (-2)
#define SNMPERR_BAD_ADDRESS             (-3)
#define SNMPERR_BAD_SESSION             (-4)
#define SNMPERR_TOO_LONG                (-5)
#define SNMPERR_TOO_SHORT               (-6)
#define SNMPERR_NO_SOCKET               (-7)
#define SNMPERR_BAD_REPEATERS           (-8)
#define SNMPERR_BAD_REPETITIONS         (-9)
#define SNMPERR_BAD_BUILD               (-10)
#define SNMPERR_BAD_SENDTO              (-11)
#define SNMPERR_BAD_PARSE               (-12)
#define SNMPERR_BAD_VERSION             (-13)
#define SNMPERR_BAD_SRC_PARTY           (-14)
#define SNMPERR_BAD_DST_PARTY           (-15)
#define SNMPERR_BAD_CONTEXT             (-16)
#define SNMPERR_BAD_COMMUNITY           (-17)
#define SNMPERR_BAD_ACL                 (-18)
#define SNMPERR_BAD_PARTY               (-19)
#define SNMPERR_ABORT                   (-20)
#define SNMPERR_UNKNOWN_PDU             (-21)
#define SNMPERR_TIMEOUT                 (-22)
#define SNMPERR_BAD_RECVFROM            (-23)
#define SNMPERR_PARSE_ERR               (-24)
#define SNMPERR_INVALID_MSG             (-25)
#define SNMPERR_NOT_IN_TIME_WINDOW      (-26)
#define SNMPERR_UNKNOWN_REPORT          (-27)
#define SNMPERR_NOMIB                   (-28)
#define SNMPERR_RANGE                   (-29)
#define SNMPERR_MAX_SUBID               (-30)
#define SNMPERR_BAD_SUBID               (-31)
#define SNMPERR_LONG_OID                (-32)
#define SNMPERR_BAD_NAME                (-33)
#define SNMPERR_VALUE                   (-34)
#define SNMPERR_UNKNOWN_OBJID           (-35)
#define SNMPERR_NULL_PDU                (-36)
#define SNMPERR_NO_VARS                 (-37)
#define SNMPERR_VAR_TYPE                (-38)
#define SNMPERR_MALLOC                  (-39)

#define SNMPERR_MAX                     (-40)

/*  SNMP-API functions */
void
snmp_lib_errstring(int snmp_errnumber, char *msg_buf);
int snmp_realloc (u_char **buf, size_t *buf_len);

/*
 *  AgentX-API definitions
 */

/* This definition related to FLAG_INSTANCE_REGISTER */
#define FULLY_QUALIFIED_INSTANCE        0x1

/* This definition related to FLAG_ANY_INDEX and FLAG_NEW_INDEX */
#define ALLOCATE_THIS_INDEX             0x0
#define ALLOCATE_ANY_INDEX              0x1
#define ALLOCATE_NEW_INDEX              0x3

#define non_repeaters   errstat
#define max_repetitions errindex

/*  AgentX-API functions */
const char *agentx_errstring (int errstat);
int agentx_action_test_set ();
int agentx_handle_cleanup_set ();
int agentx_action_undo_set ();
struct agentx_pdu *
agentx_pdu_create (int command, int req_flag, struct lib_globals *);

int agentx_clone_var (struct agentx_variable_list * var, 
                      struct agentx_variable_list * newvar);
int agentx_clone_mem (void **dstPtr, void *srcPtr, unsigned len);
struct agentx_variable_list *
agentx_clone_varbind (struct agentx_variable_list * varlist);
struct agentx_pdu *
agentx_clone_pdu (struct agentx_pdu *pdu);

void agentx_free_pdu (struct agentx_pdu *pdu);
void agentx_free_varbind (struct agentx_variable_list *var);

int
agentx_set_var_objid (struct agentx_variable_list *vp,
                      const oid *objid, size_t name_length);
int
agentx_set_var_typed_value (struct agentx_variable_list *newvar, u_char type,
                            const u_char *val_str, size_t val_len);

struct agentx_variable_list *
agentx_add_null_var (struct lib_globals *zg, struct agentx_pdu *pdu,
                     const oid *name, size_t name_length);
struct agentx_variable_list *
agentx_pdu_add_variable (struct lib_globals *zg, struct agentx_pdu *pdu,
                         const oid *name, size_t name_length,
                         u_char type, const u_char *value, size_t len);
struct agentx_variable_list *
agentx_varlist_add_variable (struct lib_globals *zg,
                             struct agentx_variable_list **varlist,
                             const oid *name, size_t name_length,
                             u_char type, const u_char *value, size_t len);
int agentx_add_var (struct lib_globals *zg, struct agentx_pdu *pdu,
                    const oid *name, size_t name_length,
                    char type, const char *value);

#endif /* HAVE_AGENTX */
#endif /* HAVE_SNMP */
#endif /* _BGPSDN_AGENTX_API_H */
