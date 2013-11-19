/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_AGENTX_MESSAGE_H
#define _BGPSDN_AGENTX_MESSAGE_H

#ifdef HAVE_SNMP
#ifdef HAVE_AGENTX


/* AgentX versions : AGENTX_VERSION_1 (0x1) */

#define AGENTX_HEADER_LENGTH    20

/* PDU types in AgentX  */
#define AGENTX_MSG_OPEN         ((u_int8_t) 1)
#define AGENTX_MSG_CLOSE        ((u_int8_t) 2)
#define AGENTX_MSG_REGISTER     ((u_int8_t) 3)
#define AGENTX_MSG_UNREGISTER   ((u_int8_t) 4)
#define AGENTX_MSG_GET          ((u_int8_t) 5)
#define AGENTX_MSG_GETNEXT      ((u_int8_t) 6)
#define AGENTX_MSG_GETBULK      ((u_int8_t) 7)
#define AGENTX_MSG_TESTSET      ((u_int8_t) 8)
#define AGENTX_MSG_COMMITSET    ((u_int8_t) 9)
#define AGENTX_MSG_UNDOSET      ((u_int8_t) 10)
#define AGENTX_MSG_CLEANUPSET   ((u_int8_t) 11)
#define AGENTX_MSG_NOTIFY       ((u_int8_t) 12)
#define AGENTX_MSG_PING         ((u_int8_t) 13)
#define AGENTX_MSG_INDEX_ALLOCATE    ((u_int8_t) 14)
#define AGENTX_MSG_INDEX_DEALLOCATE  ((u_int8_t) 15)
#define AGENTX_MSG_ADD_AGENT_CAPS    ((u_int8_t) 16)
#define AGENTX_MSG_REMOVE_AGENT_CAPS ((u_int8_t) 17)
#define AGENTX_MSG_RESPONSE          ((u_int8_t) 18)
#define AGENTX_MSG_MAX               AGENTX_MSG_RESPONSE

/* PDU flags */
#define AGENTX_MSG_FLAGS_MASK                 0xff
#define AGENTX_MSG_FLAG_INSTANCE_REGISTER     0x01 /* bit 0 */
#define AGENTX_MSG_FLAG_NEW_INSTANCE          0x02 /* bit 1 */
#define AGENTX_MSG_FLAG_ANY_INSTANCE          0x04 /* bit 2 */
#define AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT   0x08 /* bit 3 */
#define AGENTX_MSG_FLAG_NETWORK_BYTE_ORDER    0x10 /* bit 4 */

/* Session Flags */ 
#define AGENTX_FLAGS_NETWORK_BYTE_ORDER       AGENTX_MSG_FLAG_NETWORK_BYTE_ORDER


/* Close reasons (c.reason) from RFC 2741, chap. 6.2.2. The agentx-Close-PDU */ 
#define AGENTX_CLOSE_OTHER              1
#define AGENTX_CLOSE_PARSE_ERROR        2
#define AGENTX_CLOSE_PROTOCOL_ERROR     3
#define AGENTX_CLOSE_TIMEOUTS           4
#define AGENTX_CLOSE_SHUTDOWN           5
#define AGENTX_CLOSE_BY_MANAGER         6

/* Default values from RFC 2741, chap. 6.2.3. The agentx-Register-PDU */ 
#define AGENTX_REGISTER_DEF_TIMEOUT     0
#define AGENTX_REGISTER_DEF_PRIORITY    127

/* Error status (res.error) from RFC 2741, chap. 6.2.16. The agentx-Response-PDU
   included error status in Report-PDU from RFC1905. and SNMPv3 (SNMP_ERR_) */
#define AGENTX_ERR_NOERROR              (0)
#define AGENTX_ERR_OPEN_FAILED          (256)
#define AGENTX_ERR_NOT_OPEN             (257)
#define AGENTX_ERR_INDEX_WRONG_TYPE     (258)
#define AGENTX_ERR_INDEX_ALREADY_ALLOCATED (259)
#define AGENTX_ERR_INDEX_NONE_AVAILABLE (260)
#define AGENTX_ERR_INDEX_NOT_ALLOCATED  (261)
#define AGENTX_ERR_UNSUPPORTED_CONTEXT  (262)
#define AGENTX_ERR_DUPLICATE_REGISTRATION (263)
#define AGENTX_ERR_UNKNOWN_REGISTRATION (264)
#define AGENTX_ERR_UNKNOWN_AGENTCAPS    (265)
#define AGENTX_ERR_PARSE_ERROR          (266)
#define AGENTX_ERR_REQUEST_DENIED       (267)
#define AGENTX_ERR_PROCESSING_ERROR     (268)

#define MIN_AGENTX_ERR                  (256)
#define MAX_AGENTX_ERR                  (268)

/* Message processing models */
#define AGENTX_MP_MODEL_AGENTXv1        (257)


const char *agentx_cmd (u_char code);

/*  build (set) and parse (get) functions */
int agentx_build (struct lib_globals *zg, 
                  struct agentx_session *session, struct agentx_pdu *pdu,
                  u_char **buf, size_t *buf_len, size_t *out_len);
u_char *agentx_parse_oid (struct lib_globals *zg, 
                          u_char *data, size_t *length, int *inc,
                          oid *oid_buf, size_t *oid_len,
                          u_int network_byte_order);
int agentx_parse (struct lib_globals *zg, 
                  struct agentx_session *, struct agentx_pdu *,
                  u_int8_t *, size_t);
int agentx_check_packet (struct lib_globals *zg, u_int8_t *, size_t);

/*  Utility functions */
int agentx_open_session (struct lib_globals *, struct agentx_session *);
int agentx_close_session (struct lib_globals *, struct agentx_session *, int);
int agentx_send_register (struct lib_globals *, struct agentx_session *,
                          oid *, size_t, int, int, oid, int, u_char);
int agentx_send_unregister (struct lib_globals *, struct agentx_session *,
                            oid *, size_t, int, int, oid);
int agentx_send_index_allocate (struct lib_globals *, struct agentx_session *,
                                struct agentx_variable_list *, int);
int agentx_send_index_deallocate (struct lib_globals *, struct agentx_session *,
                                  struct agentx_variable_list *);
int agentx_send_add_agentcaps (struct lib_globals *, struct agentx_session *,
                               oid *, size_t, const char *);
int agentx_send_remove_agentcaps (struct lib_globals *, struct agentx_session *,
                                  oid *, size_t);
int agentx_send_ping (struct lib_globals *, struct agentx_session *);
int agentx_send_notify (struct lib_globals *, struct agentx_session *,
                        struct agentx_variable_list *);

#endif /* HAVE_AGENTX */
#endif /* HAVE_SNMP */
#endif /* _BGPSDN_AGENTX_MESSAGE_H */
