/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_AGENTX_H
#define _BGPSDN_AGENTX_H

#ifdef HAVE_SNMP
#ifdef HAVE_AGENTX

#include "asn1.h"
#include "pal.h"

#include "pal_socket.h"
#include "lib.h"

/* Forward declaration. */
struct subtree;
struct snmp_master;

/*  Definitions for Agent Extensibility Protocol (RFC 2741) */
#define AGENTX_PORT             705
#define AGENTX_SOCKET           "/var/agentx/master"

#define AGENTXMAXPKTSIZE        65536
#define AGENTXMAXSTRLEN         256
#define AGENTX_MAX_FAILURE      40  /* 10 min */

#define MAX_PACKET_LENGTH       (0x7fffffff)

#define AGENTX_VERSION_1        1
#define IS_AGENTX_VERSION(v)    ((v) == AGENTX_VERSION_1)
#define AGENTX_DEFAULT_VERSION  AGENTX_VERSION_1
#define AGENTX_DEFAULT_RETRIES  0
#define AGENTX_DEFAULT_TIMEOUT  1000000L
#define AGENTX_DEFAULT_ERRSTAT  0
#define AGENTX_DEFAULT_ERRINDEX 0
#define AGENTX_LIMIT_RETRIES    5

/* AgentX ping interval */
#define AGENTX_PING_INTERVAL    15

/* AgentX internal set flags (mode) */
#define AGENTX_SET_RESERVE1     RESERVE1 /* 0 */
#define AGENTX_SET_RESERVE2     RESERVE1 /* 1 */
#define AGENTX_SET_ACTION       ACTION   /* 2 */
#define AGENTX_SET_COMMIT       COMMIT   /* 3 */
#define AGENTX_SET_FREE         FREE_DEL /* 4 */
#define AGENTX_SET_UNDO         UNDO     /* 5 */
#define AGENTX_SET_MAX          (6)

/* AgentX internal state */
enum agentx_state {
     AGENTX_INITIAL,
     AGENTX_OPENING,
     AGENTX_REGISTERING,
     AGENTX_OPERATIONAL
};

/* AgentX internal event */
enum agentx_event {
     AGENTX_SCHEDULE,
     AGENTX_CONNECT,
     AGENTX_READ,
     AGENTX_RESTART,
     AGENTX_PING,
     AGENTX_STOP
};

/* AgentX PDU-type in agentx_message.h */

/*
 * The AgentX library.
 */

#define AGENTX_FREE(ptr)                                                      \
    do {                                                                      \
      if (ptr)                                                                \
        {                                                                     \
           XFREE (MTYPE_TMP, (ptr));                                          \
           (ptr) = NULL;                                                      \
        }                                                                     \
    } while(0)
     
/*
 * The AgentX protocol data unit.
 */
struct agentx_variable_list;

struct agentx_pdu {
  /* agentx version */
  long version;

  /* Type of this PDU */        
  int command;

  /* Request id - note: not incremented on retries */
  long reqid;  

  /* Unique ID for incoming transactions */
  long transid;

  /* Session id for AgentX messages */
  long sessid;

  /* Error status (GetBulk : non_repeaters) */
  long errstat;

  /* Error index (GetBulk : max_repetitions) */
  long errindex;       

  /* Uptime */
  unsigned long time;   

  unsigned long flags;
  /* AGENTX_MSG_FLAG_xxx is defined as 0xff. */
#define AGENTX_FLAGS_EXPECT_RESPONSE    0x0100
#define AGENTX_FLAGS_RESPONSE_PDU       0x0200
#define AGENTX_FLAGS_FORCE_PDU_COPY     0x0400

  struct agentx_variable_list *variables;

  int priority;
  int range_subid;

  /** community for outgoing requests. */
  u_char *community;
  /** Length of community name. */
  size_t community_len;

};

/*
 * The AgentX session structure.
 */
struct agentx_session {
  /* agent version */
  long version;

  /* Number of retries before timeout. */
  int retries;

  /* Number of uS until first timeout, then exponential backoff */
  long timeout;        

  u_long flags;

  /* Domain name or dotted IP address of default peer */
  char *peername;

  /* UDP port number of peer. */
  u_short remote_port;

  /* My UDP port number, 0 for default, picked randomly */
  u_short local_port;     

  /* copy of system errno */
  int sys_errno;

  /* copy of library errno */
  int lib_errno;   

  /* Session id */
  long sessid; 
};
 
typedef int (*AGENTX_CALLBACK) (struct lib_globals *,
                                struct agentx_session *, int,
                                struct agentx_pdu *, void *);

struct agentx_request_info {
  long request_id;     /* request id */
  AGENTX_CALLBACK callback; /* user callback per request (NULL if unused) */
  void *cb_data;       /* user callback data per request (NULL if unused) */
  int retries;         /* Number of retries */
  u_long timeout;      /* length to wait for timeout */
  struct pal_timeval time;   /* Time this request was made */
  struct pal_timeval expire; /* time this request is due to expire */
  struct agentx_session *session;
  struct agentx_pdu *pdu;    /* The pdu for this request
                              * (saved so it can be retransmitted */
};

typedef union {
  long *integer;
  u_char *string;
  oid *objid;
  u_char *bitstring;
  struct counter64 *counter64;
} agentx_vardata;

/*
 * The AgentX variable list binding structure, it's typedef'd to
 * agentx_variable_list.
 */
struct agentx_variable_list {
  /* NULL for last variable */
  struct agentx_variable_list *next_variable;    

  /* Object identifier of variable */
  oid *name;   

  /* number of subid's in name */
  size_t name_length;    

  /* ASN type of variable */
  u_char type;   

  /* value of variable */
  agentx_vardata val;

  /* the length of the value to be copied into buf */
  size_t val_len;

  /* 128 (90 percentile < 24) */
  oid name_loc[MAX_OID_LEN];  
  /* MAX_VAR_VALUE : 128 (90 percentile < 40) */
  u_char buf[128];

  /* (Opaque) hook for additional data */
  void  *data;
  /* callback to free above */
  void (*dataFreeHook)(void *);    

  int index;
};

struct agentx_magic {
  int original_command;
  struct agentx_session *session;
  struct agentx_variable_list *ovars;
};

struct agentx_set_info {
  struct agentx_session *session;
  int transid;
  int mode;
  int errstat;
  time_t uptime;
  struct agentx_variable_list *var_list;
};

extern struct agentx_session Agx_session;
extern struct pal_timeval starttime;
extern enum agentx_state Agx_state;
const char *agentx_statestr (int state);


int agentx_handle_open_response (struct lib_globals *zg, 
                                 struct agentx_session *sess, int reqid,
                                 struct agentx_pdu *pdu, void *magic);
int agentx_handle_reg_response (struct lib_globals *zg, 
                                struct agentx_session *sess, int reqid,
                                struct agentx_pdu *pdu, void *magic);
int agentx_handle_ping_response (struct lib_globals *zg, 
                                 struct agentx_session *sess, int reqid,
                                 struct agentx_pdu *pdu, void *magic);
int agentx_send (struct lib_globals *zg,
                 struct agentx_session *sess, struct agentx_pdu *pdu,
                 AGENTX_CALLBACK callback, void *cb_data);

void agentx_event (struct lib_globals *, enum agentx_event, s_int32_t);
void agentx_stop (struct lib_globals *zg);
s_int32_t agentx_tree_cmp(struct subtree *, struct subtree *);
int agentx_initialize (struct snmp_master *snmpm);
#ifdef HAVE_IPV6
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
#endif /*HAVE_IPV6*/
#endif /* HAVE_AGENTX */
#endif /* HAVE_SNMP */
#endif /* _BGPSDN_AGENTX_H */
