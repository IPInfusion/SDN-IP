/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

/* Use it for both AgentX and SMUX subagent */

#ifndef _BGPSDN_SNMP_MISC_H
#define _BGPSDN_SNMP_MISC_H

/* Common MIBs definitions begin */

/* TruthValue from SNMPv2-TC.txt rfc2559 */
#define SNMP_AG_TRUE                    1
#define SNMP_AG_FALSE                   2

/* RowStatus from SNMPv2-TC.txt rfc2559 */
#define SNMP_AG_ROW_active              1
#define SNMP_AG_ROW_notInService        2
#define SNMP_AG_ROW_notReady            3
#define SNMP_AG_ROW_createAndGo         4
#define SNMP_AG_ROW_createAndWait       5
#define SNMP_AG_ROW_destroy             6

/* StorageType from SNMPv2-TC.txt rfc2559 */
#define SNMP_AG_STOR_other              1
#define SNMP_AG_STOR_volatile           2
#define SNMP_AG_STOR_nonVolatile        3
#define SNMP_AG_STOR_permanent          4
#define SNMP_AG_STOR_readOnly           5

/* InetAddressType INET-ADDRESS-MIB.txt rfc3291 */
#define SNMP_AG_ADDR_TYPE_unknown       0
#define SNMP_AG_ADDR_TYPE_ipv4          1
#define SNMP_AG_ADDR_TYPE_ipv6          2
#define SNMP_AG_ADDR_TYPE_ipv4z         3
#define SNMP_AG_ADDR_TYPE_ipv6z         4
#define SNMP_AG_ADDR_TYPE_dns           16

/* Common MIBs definitions end */

#define RET_ERR_WRITE(RC)       prev_action = COMMIT; return RC;
#define SNMP_SET_WRITE_METHOD(METH) *write_method = (void*) (METH);
#define SET_IND_ERR_FMT "%s: Cannot build %s index from entry"

extern long long_sub_return;
extern unsigned long unsigned_sub_return;
extern u_char return_sub_buf[];

/* Traps. */

/* Trap variable bindings structure. */
struct snmp_trap_object
{
  /* OID name length. */
  size_t namelen;

  /* OID name. */
  oid name[MAX_OID_LEN];

  /* Value type. */
  u_char val_type;

  /* Value length. */
  size_t val_len;

  /* Pointer to the value. */
  void *val;
};

/* Trap callback prototype. */
typedef void (*SNMP_TRAP_CALLBACK) (oid *, size_t, oid, u_int32_t,
                                    struct snmp_trap_object *, size_t);

/* Macros. */
#define OID_COPY(PTR,OID,LEN)                                                 \
    do {                                                                      \
      oid_copy ((PTR), (OID), (LEN));                                         \
      (PTR) += (LEN);                                                         \
    } while (0)

#define OID_SET_IP_ADDR(PTR,ADDR)                                             \
    do {                                                                      \
      oid_copy_addr ((PTR), (ADDR), sizeof (struct pal_in4_addr));            \
      (PTR) += sizeof (struct pal_in4_addr);                                  \
    } while (0)

#ifdef HAVE_IPV6
#define OID_SET_IP_ADDR6(PTR,ADDR)                                             \
    do {                                                                      \
      oid_copy_in6_addr ((PTR), (ADDR), sizeof (struct pal_in6_addr));            \
      (PTR) += sizeof (struct pal_in6_addr);                                  \
    } while (0)
#endif /* HAVE_IPV6 */

#define OID_SET_ARG1(PTR,ARG1)                                                \
    do {                                                                      \
      *(PTR)++ = (ARG1);                                                      \
    } while (0)

#define OID_SET_ARG2(PTR,ARG1,ARG2)                                           \
    do {                                                                      \
      *(PTR)++ = (ARG1);                                                      \
      *(PTR)++ = (ARG2);                                                      \
    } while (0)

#define OID_SET_ARG3(PTR,ARG1,ARG2,ARG3)                                      \
    do {                                                                      \
      *(PTR)++ = (ARG1);                                                      \
      *(PTR)++ = (ARG2);                                                      \
      *(PTR)++ = (ARG3);                                                      \
    } while (0)

#define OID_SET_ARG4(PTR,ARG1,ARG2,ARG3,ARG4)                                 \
    do {                                                                      \
      *(PTR)++ = (ARG1);                                                      \
      *(PTR)++ = (ARG2);                                                      \
      *(PTR)++ = (ARG3);                                                      \
      *(PTR)++ = (ARG4);                                                      \
    } while (0)

#define OID_SET_ARG5(PTR,ARG1,ARG2,ARG3,ARG4,ARG5)                            \
    do {                                                                      \
      *(PTR)++ = (ARG1);                                                      \
      *(PTR)++ = (ARG2);                                                      \
      *(PTR)++ = (ARG3);                                                      \
      *(PTR)++ = (ARG4);                                                      \
      *(PTR)++ = (ARG5);                                                      \
    } while (0)

#define OID_SET_ARGN(PTR,ARGC,ARGV)                                           \
    do {                                                                      \
      int _i;                                                                 \
      for (_i = 0; _i < (ARGC); _i++)                                         \
        *(PTR)++ = ARGV[_i];                                                  \
    } while (0)

#define OID_SET_VAL(OBJ,LEN,TYPE,VLEN,VAL)                                    \
    do {                                                                      \
      (OBJ).namelen = (LEN);                                                  \
      (OBJ).val_type = (TYPE);                                                \
      (OBJ).val_len = (VLEN);                                                 \
      (OBJ).val = (VAL);                                                      \
    } while (0)


/* snmp_util_xxx */

void snmp_util_tracer_init (struct lib_globals *);

int snmp_util_advance_index_name (struct variable *vp, oid *name,
                               size_t *length, int exact);

int snmp_util_get_int_value (u_char *var_val, int for_smux,
                        long min_value, long max_value,
                        long* long_tmp);

int snmp_util_get_ip_value (u_char *var_val, u_char var_val_type,
                        int var_val_len, int for_smux,
                        struct pal_in4_addr *ip_addr);

int snmp_util_check_ip_value (long *index, struct pal_in4_addr *addr);

#ifdef HAVE_IPV6
int snmp_util_get_ipv6_value (u_char *var_val, u_char var_val_type,
                        int var_val_len, int for_smux,
                        struct pal_in6_addr *ip_addr);
#endif /* HAVE_IPV6 */

int snmp_util_get_string_value (u_char *var_val, u_char  var_val_type, int var_val_len,
                             int for_smux,
                             int buffer_max_size, short should_zero_limited,
                             int *buffer_actual_size, char* buffer);

int snmp_util_get_ostring_from_index (oid *name, int name_len,
                                  int wr_meth_snux_delta,
                                  int *offset, 
                                  int olen, unsigned char *oval);
int snmp_util_get_int_from_index (oid * name, int name_len,
                              int wr_meth_snux_delta,
                              int *offset, long *int_val);

int snmp_util_set_ostring_to_index (oid *name, int *name_len,
                                    int olen, unsigned char* oval);
int snmp_util_set_int_to_index (oid *name, size_t *name_len, long int_val);

int snmp_utils_header_generic(struct variable *vp,
               oid *name,
               size_t *length,
               int exact,
               size_t *var_len,
               WriteMethod **write_method);

void ag_trace (const char *format, ...);

int
write_dummy(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len);

/*
 * debugging
 */

const char*
_dbg_get_action_name (int action);

char*
_dbg_sprint_oid (oid *name, size_t length);

#endif /* _BGPSDN_SNMP_MISC_H */


