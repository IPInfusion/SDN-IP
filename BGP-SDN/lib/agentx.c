/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#ifdef HAVE_SNMP
#ifdef HAVE_AGENTX

#include "snmp.h"
#include "agentx.h"
#include "agentx_api.h"
#include "agentx_message.h"
#include "thread.h"
#include "log.h"
#include "snprintf.h"
#include "linklist.h"
#include "bgpsdn_version.h"
#include "sockunion.h"
#include "asn1.h"
#include "errno.h"

const char *Agx_state_str[] = {
    "Initial",
    "Opening",
    "Registering",
    "Operational",
    "Unknown"
};

oid nullOid[] = { 0, 0 };
int nullOidLen = sizeof(nullOid);

/*--------------------------------------------------------*
 *   AGENTX-PARSE&BUILD : agentx_message.c/h              *
 *--------------------------------------------------------*/

/*--------------------------------------------------------*
 *   AGENTX-API : agentx_api.c/h                          *
 *--------------------------------------------------------*/

/*--------------------------------------------------------*
 *   AGENTX-PROCESS : agentx.c/h                          *
 *--------------------------------------------------------*/

const char *
agentx_statestr (int state)
{
  if (state >= AGENTX_INITIAL && state <= AGENTX_OPERATIONAL) {
    return Agx_state_str[state];
  } else {
    return "Unknown";
  }
}

/* AgentX Tips */
int
calculate_time_diff (struct pal_timeval *now, struct pal_timeval *then)
{
  struct pal_timeval  tmp, diff;

  pal_mem_cpy (&tmp, now, sizeof(struct pal_timeval));
  tmp.tv_sec--;
  tmp.tv_usec += 1000000L;
  diff.tv_sec = tmp.tv_sec - then->tv_sec;
  diff.tv_usec = tmp.tv_usec - then->tv_usec;
  if (diff.tv_usec > 1000000L) {
    diff.tv_usec -= 1000000L;
    diff.tv_sec++;
  }
  return ((diff.tv_sec * 100) + (diff.tv_usec / 10000));
}

/* Synchronise sysUpTime with the master agent */
void
agentx_synchronise_sysuptime (struct lib_globals *zg, struct agentx_pdu *pdu)
{
  struct pal_timeval now, diff;
  struct snmp_master *snmpm = SNMP_MASTER (zg);

  pal_time_tzcurrent (&now, NULL);
  now.tv_sec--;
  now.tv_usec += 1000000L;
  diff.tv_sec = pdu->time / 100;  /* Response-PDU sysUpTime is TimeTicks */
  diff.tv_usec = (pdu->time - (diff.tv_sec * 100)) * 10000;
  snmpm->starttime.tv_sec = now.tv_sec - diff.tv_sec;
  snmpm->starttime.tv_usec = now.tv_usec - diff.tv_usec;
  if (snmpm->starttime.tv_usec > 1000000L) {
    snmpm->starttime.tv_usec -= 1000000L;
    snmpm->starttime.tv_sec++;
  }

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: response, start_time: %d sec, %d usec", 
               snmpm->starttime.tv_sec, snmpm->starttime.tv_usec);
  return;
}

/* AgentX Socket & Session */

pal_sock_handle_t
agentx_socket_ipv4 (struct lib_globals *zg)
{
  struct pal_sockaddr_in4 serv;
  struct pal_servent *sp;
  pal_sock_handle_t sock = -1;
  s_int32_t ret;

  sock = pal_sock (zg, AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      if (IS_SUBAG_DEBUG)
        zlog_warn (zg, "Can't make socket for SNMP");
      return -1;
    }

  pal_mem_set (&serv, 0, sizeof (struct pal_sockaddr_in4));
  serv.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
  serv.sin_len = sizeof (struct pal_sockaddr_in4);
#endif /* HAVE_SIN_LEN */

  sp = (struct pal_servent *) pal_getservbyname ("agentx", "tcp");
  if (sp != NULL) 
    serv.sin_port = sp->s_port;
  else
    serv.sin_port = pal_hton16 (AGENTX_PORT);

  serv.sin_addr.s_addr = pal_hton32 (INADDR_LOOPBACK);
  pal_sock_set_reuseaddr (sock, PAL_TRUE);
  pal_sock_set_reuseport (sock, PAL_TRUE);

  ret = pal_sock_connect (sock, (struct pal_sockaddr *) &serv,
                          sizeof (struct pal_sockaddr_in4));
  if (ret < 0)
    {
      pal_sock_close (zg, sock);
      zg->snmp.sock = -1;
      return -1;
    }

  /* Set socket to non-blocking. */
  pal_sock_set_nonblocking (sock, 1);

  return sock;
}

#ifdef HAVE_AGENTX_UNIX_DOMAIN

/* AgentX Socket for unix domain */

pal_sock_handle_t
agentx_socket_unix_domain (struct lib_globals *zg)
{
  struct pal_sockaddr_un addr;
  pal_sock_handle_t sock = -1;
  int len;
  s_int32_t ret;

  sock = pal_sock (zg, AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      if (IS_SUBAG_DEBUG)
        zlog_warn (zg, "Can't make socket for SNMP");
      return -1;
    }

  pal_mem_set (&addr, 0, sizeof (struct pal_sockaddr_un));
  addr.sun_family = AF_UNIX;
  pal_strncpy (addr.sun_path, AGENTX_SOCKET, pal_strlen (AGENTX_SOCKET));
#ifdef HAVE_SUN_LEN
  len = addr.sun_len = SUN_LEN (&addr);
#else
  len = sizeof (addr.sun_family) + pal_strlen (addr.sun_path);
#endif /* HAVE_SUN_LEN */

  ret = pal_sock_connect (sock, (struct pal_sockaddr *) &addr, len);
  if (ret < 0)
    {
      if (IS_SUBAG_DEBUG)
        zlog_warn (zg, "AgentX: Connect Error @ %s:%d", __FILE__, __LINE__);
      pal_sock_close (zg, sock);
      zg->snmp.sock = -1;
      return -1;
    }

  /* Set socket to non-blocking. */
  pal_sock_set_nonblocking (sock, 1);

  return sock;
}

#endif /* HAVE_AGENTX_UNIX_DOMAIN */

int
agentx_initialize (struct snmp_master *snmpm)
{
  snmpm->SavedPacket = NULL;
  snmpm->SavedPacket_len = 0;
  snmpm->SavedPacket_size = 0;

  snmpm->Reqid = 0;
  snmpm->Transid = 0;

  pal_mem_set (&snmpm->Agx_session, 0, sizeof (struct agentx_session));
  pal_mem_set (&snmpm->Agx_set_info, 0, sizeof (struct agentx_set_info));
  pal_mem_set (&snmpm->Agx_request_info, 0, sizeof (struct agentx_request_info));

  snmpm->Agx_reg_subtree = NULL;
  
  return 0;
}

#ifdef HAVE_IPV6
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) 
     {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
            break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
     }

    return s;
}

pal_sock_handle_t
agentx_socket_hybrid (struct lib_globals *zg)
{
  struct pal_addrinfo hints, *ai_res, *ai;
  char servbuf[NI_MAXSERV];
  pal_sock_handle_t sock = -1;
  s_int32_t ret;
  static s_int32_t timeout_fail_v6=0 ,timeout_fail_v4=0;
  bool_t flag_cnct4;
  bool_t flag_cnct6;
  char s[NI_MAXSERV];

  pal_mem_set (&hints, 0, sizeof hints);
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  ret = pal_sock_getaddrinfo (NULL, "agentx", &hints, &ai_res);
  if (ret == EAI_SERVICE)
    {
      zsnprintf (servbuf, sizeof servbuf, "%d", AGENTX_PORT);
      ret = pal_sock_getaddrinfo (NULL, servbuf, &hints, &ai_res);
    }

  if (ret != 0)
    {
      if (IS_SUBAG_DEBUG)
        zlog_warn (zg, "Cannot locate loopback service agentx");
      return -1;
    }

  for (ai = ai_res; ai; ai = ai->ai_next)
    if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6)
     {
        sock = pal_sock (zg, ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock >= 0)
          {
            /*
              Defect BGP-SDN00072541 FIX :
              
              PROBLEM   : IMISH hangs , when NSM is killed and restarted

              ANALYSIS  : The Agentx client connect mechanism is a background 
                          operation conducted by all the Protocol modules
                          (NSM included) which have SNMP support.
                          NSM tries to connect to AgentX periodically every
                          10sec for 40 times.So when the connect call is made 
                          for IPV6 , it blocks the calling function(for 6m40sec)
                          and returns ETIMEDOUT error.This is why the hang happens.
                       
             RESOLUTION : When the sock_connect() fails with the error ETIMEDOUT.
                          Do not try to connect for the next MAX_WAIT_TIME times.
                          Since each attempt will block the call.
             ---------------------------------------------------------------------
             NOTE       : The localhost ::1 ipv6 connection timeout, leading to
                          the IMI hang issue, is a kernel issue.This issue has already
                          been reported in bugzilla.kernel.org
                          Bug 48741 - ipv6 localhost connection times out since 
                                      linux 3.6.0.
                          (https://bugzilla.kernel.org/show_bug.cgi?id=48741)

                          Find more details of this issue @
                          http://comments.gmane.org/gmane.linux.network/245905  
             ---------------------------------------------------------------------
            */
            pal_sock_set_reuseaddr (sock, PAL_TRUE);
            pal_sock_set_reuseport (sock, PAL_TRUE);
            
            if (IS_SUBAG_DEBUG_PROCESS)
            zlog_info(" addr family = %d, addr = %s\n",
                       ai->ai_family,get_ip_str(ai->ai_addr,s,256) );  

            flag_cnct4 = PAL_TRUE;
            flag_cnct6 = PAL_TRUE;
          
            /*Disable the respective flags for ipv4/ipv6 if the soc_connect() 
              fails because of 'ETIMEDOUT'*/
            if(timeout_fail_v4) 
              {
                flag_cnct4 = PAL_FALSE; 
              }
            if(timeout_fail_v6)
              {
                flag_cnct6 = PAL_FALSE;
              }
         
            if((flag_cnct4 && (ai->ai_family == AF_INET)) ||
                (flag_cnct6 && (ai->ai_family == AF_INET6)))
              {
                ret = pal_sock_connect (sock, ai->ai_addr, ai->ai_addrlen);
    
                if (ret >= 0)
                  break;
                else
                 {
                   /*increment the counters(ipv4/ipv6) if soc_connect()
                      fails due to 'ETIMEDOUT' error for the first time*/
                   if(errno == ETIMEDOUT) 
                     { 
                       if(ai->ai_family == AF_INET)
                         {
                           timeout_fail_v4 ++;
                         }
                       else
                         {
                           timeout_fail_v6 ++;
                         }
                       if (IS_SUBAG_DEBUG_PROCESS)
                       zlog_info("addr family = %d, error return = %s\n", 
                                                 ai->ai_family,strerror(errno));
                     }
                 }
              }
            else 
              {
                /* Continue incrementing the counters after the 'ETIMEDOUT' 
                    error has occured till MAX_WAIT_COUNT*/
                if(ai->ai_family == AF_INET) 
                  {
                    timeout_fail_v4++; 
                  }
                else
                  {
                    timeout_fail_v6 ++;
                  }
                /* Reset the counters to 0 when the 
                   MAX_WAIT_COUNT is reached */
                if(timeout_fail_v4 >= MAX_WAIT_COUNT)
                  {
                    timeout_fail_v4 = 0;
                  }
                if(timeout_fail_v6 >= MAX_WAIT_COUNT)
                  {
                    timeout_fail_v6 = 0;
                  }
              }

            pal_sock_close (zg, sock);
            sock = -1;
          }
      } 
	    
  /* Set socket to non-blocking. */
  pal_sock_set_nonblocking (sock, 1);

  pal_sock_freeaddrinfo (ai_res);

  return sock;
}

#endif /* HAVE_IPV6 */

pal_sock_handle_t
agentx_socket (struct lib_globals *zg)
{

  pal_sock_handle_t ret;

#ifdef HAVE_AGENTX_UNIX_DOMAIN
  ret = agentx_socket_unix_domain (zg);
#elif defined(HAVE_IPV6)
  ret = agentx_socket_hybrid (zg);
#else /* HAVE_IPV6 */
  ret = agentx_socket_ipv4 (zg);
#endif /* HAVE_IPV6 */

  return ret;

}

void agentx_restart_session (struct lib_globals *zg, int restart)
{
  struct agentx_session *sess;
  struct agentx_set_info *setptr;
  struct agentx_request_info *rq;
  struct snmp_master *snmpm = SNMP_MASTER(zg);

  /* Session. */
  sess = &snmpm->Agx_session;
  setptr = &snmpm->Agx_set_info;
  rq = &snmpm->Agx_request_info;

  /*
   * Frees global variables.
   */

  /* Frees SavedPacket */
  AGENTX_FREE (snmpm->SavedPacket);
  snmpm->SavedPacket_len = 0;
  snmpm->SavedPacket_size = 0;

  /* Frees session */
  pal_mem_set (sess, 0 , sizeof (struct agentx_session));

  /* Frees Set information */
  agentx_free_varbind (setptr->var_list);
  pal_mem_set (setptr, 0 , sizeof (struct agentx_set_info));

  /* Frees Request information */
  agentx_free_pdu (rq->pdu);
  pal_mem_set (rq, 0 , sizeof (struct agentx_request_info));

  /* Closes and re-connects socket */
  if (zg->snmp.sock >= 0)
    pal_sock_close (zg, zg->snmp.sock);
  zg->snmp.sock = -1;

  /* Initializes a state of agentx */
  zg->snmp.Agx_state = AGENTX_INITIAL;

  /* Initializes a registered oid of agentx */
  zg->snmp.Agx_reg_subtree = NULL;

  if (restart)
    agentx_event (zg, AGENTX_CONNECT, 0);

  return;
}

/* AgentX Sending packet (PDU). */
int
agentx_send (struct lib_globals *zg,
             struct agentx_session *sess, struct agentx_pdu *pdu,
             AGENTX_CALLBACK callback, void *cb_data)
{
  u_char *pktbuf = NULL, *packet = NULL;
  size_t pktbuf_len = 0, offset = 0, length = 0;
  int result;
  long reqid;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);

  if (sess == NULL)
    {
      if (IS_SUBAG_DEBUG_SEND)
        zlog_err (zg, "AgentX: send fail: closing session...");
      return 0;
    }

  if (pdu == NULL)
    {
      if (IS_SUBAG_DEBUG_SEND)
        zlog_err (zg, "AgentX: send fail: closing session...");
      sess->lib_errno = SNMPERR_NULL_PDU;
      return 0;
    }

  if ((pktbuf = XMALLOC (MTYPE_TMP, 2048)) == NULL)
    {
      if (IS_SUBAG_DEBUG_SEND)
        zlog_err (zg, "AgentX: send, couldn't malloc initial packet buffer");
      sess->lib_errno = SNMPERR_MALLOC;
      return 0;
    }
  else
    {
      pktbuf_len = 2048;
    }

  sess->lib_errno = 0;
  sess->sys_errno = 0;

  pdu->flags |= AGENTX_FLAGS_EXPECT_RESPONSE;

  /* Check/setup the version. */ 
  if (pdu->version != sess->version)
    {
      if (IS_SUBAG_DEBUG_SEND)
        zlog_err (zg, "AgentX: send, bad version");
      sess->lib_errno = SNMPERR_BAD_VERSION;
      AGENTX_FREE (pktbuf);
      return 0;
    }

  /* Build the message to send. */ 
  result = agentx_build (zg, sess, pdu, &pktbuf, &pktbuf_len, &offset);

  packet = pktbuf;
  length = offset;

  if (result < 0)
    {
      if (IS_SUBAG_DEBUG_SEND)
        zlog_err (zg, "AgentX: send, encoding failure");
      /* already session's lib_errno is set by realloc_build function */
      AGENTX_FREE (pktbuf);
      return 0;
    }
  
  /* Check that the underlying transport is capable of sending a packet as
   * large as length. */ 
  if (length > MAX_PACKET_LENGTH)
    {
    /*If the size of the Response-PDU would be too large to transport, rebuild toobig packet*/
    if (pdu->command == AGENTX_MSG_RESPONSE)
      {
        if (IS_SUBAG_DEBUG_SEND)
          zlog_err (zg, "AgentX: send, length of Response-PDU (%lu) exceeds transport maximum (%lu)",
               length, MAX_PACKET_LENGTH);
        pdu->errstat = SNMP_ERR_TOOBIG;
        pdu->errindex = 0;
        memset (pktbuf, 0, pktbuf_len);
        offset = 0;

        result = agentx_build (zg, sess, pdu, &pktbuf, &pktbuf_len, &offset);
    
        packet = pktbuf;
        length = offset;
  
        if (result < 0)
          {
            if (IS_SUBAG_DEBUG_SEND)
              zlog_err (zg, "AgentX: send, encoding failure");
            /* already session's lib_errno is set by realloc_build function */
            AGENTX_FREE (pktbuf);
            return 0;
          }

      if (length > MAX_PACKET_LENGTH)
        {
          if (IS_SUBAG_DEBUG_SEND)
            zlog_err (zg, "AgentX: send, length of TOOBIG packet (%lu) exceeds transport maximum (%lu)",
                      length, MAX_PACKET_LENGTH);
          sess->lib_errno = SNMPERR_TOO_LONG;
          AGENTX_FREE (pktbuf);
          return 0;
        }
      }
    else
      {
        if (IS_SUBAG_DEBUG_SEND)
          zlog_err (zg, "AgentX: send, length of packet (%lu) exceeds transport maximum (%lu)",
                    length, MAX_PACKET_LENGTH);
        sess->lib_errno = SNMPERR_TOO_LONG;
        AGENTX_FREE (pktbuf);
        return 0;
      }
    }

  if (IS_SUBAG_DEBUG_XDUMP)
    snmp_xdump (zg, "AgentX: sending PDU", packet, length);

  /* Send the message. */ 
  result = pal_sock_send (zg->snmp.sock, packet, length, 0);

  AGENTX_FREE (pktbuf);

  if (result < 0)
    {
      sess->lib_errno = SNMPERR_BAD_SENDTO;
      sess->sys_errno = errno;
      if (IS_SUBAG_DEBUG_SEND)
        zlog_err (zg, "AgentX: send, BAD_SEND, lib_errno: %d, sys_errno: %d",
                  sess->lib_errno, sess->sys_errno);
      return 0;
    }

  reqid = pdu->reqid;

  /* Add to request info if we expect a response. */ 
  if (pdu->flags & AGENTX_FLAGS_EXPECT_RESPONSE) {
    struct agentx_request_info *rq;
    struct agentx_pdu *req_pdu;
    struct pal_timeval  tv;

    rq = &snmpm->Agx_request_info;

    if (rq == NULL) {
      sess->lib_errno = SNMPERR_GENERR;
      if (IS_SUBAG_DEBUG_SEND)
        zlog_err (zg, "AgentX: send, error in a request information");
      return 0;
    }

    if (rq->pdu) {
      agentx_free_pdu (rq->pdu);
      pal_mem_set (rq, 0 , sizeof (struct agentx_request_info));
    }

    if (rq->callback) {
      rq->callback = NULL;
      if (rq->cb_data)
        AGENTX_FREE (rq->cb_data);
    }

    req_pdu = agentx_clone_pdu (pdu);
    pal_time_tzcurrent (&tv, NULL);
    rq->pdu = req_pdu;
    rq->request_id = req_pdu->reqid;
    rq->callback = callback;
    rq->cb_data = cb_data;
    rq->retries = 0;
    rq->timeout = sess->timeout;
    rq->time = tv;
    tv.tv_usec += rq->timeout;
    tv.tv_sec += tv.tv_usec / 1000000L;
    tv.tv_usec %= 1000000L;
    rq->expire = tv;

  } else {
    /* No response expected... */ 
  }

  return reqid;
}


/*
 * AgentX Tips : Set operations
 */

struct agentx_set_info *
save_set_vars (struct lib_globals *zg, struct agentx_session *sess, struct agentx_pdu *pdu)
{
  struct agentx_set_info *ptr;
  struct pal_timeval  now;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);
  ptr = &snmpm->Agx_set_info;

  if (ptr == NULL)
    return NULL;

  /* Save the important information. */
  ptr->session = sess;
  ptr->transid = pdu->transid;
  ptr->mode = AGENTX_SET_RESERVE1;
  pal_time_tzcurrent (&now, NULL);
  ptr->uptime = calculate_time_diff(&now, &snmpm->starttime);

  ptr->var_list = agentx_clone_varbind (pdu->variables);
  if (ptr->var_list == NULL) {
    pal_mem_set (ptr, 0 , sizeof (struct agentx_set_info));
    return NULL;
  }
  return ptr;
}

struct agentx_set_info *
restore_set_vars (struct lib_globals *zg, struct agentx_pdu *pdu)
{
  struct agentx_set_info *ptr;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);
  ptr = &snmpm->Agx_set_info;

  if (ptr == NULL || ptr->var_list == NULL)
    return NULL;

  if (ptr->transid != pdu->transid)
    return NULL;

  pdu->variables = agentx_clone_varbind (ptr->var_list);
  if (pdu->variables == NULL)
    return NULL;

  return ptr;
}

void
free_set_vars (struct lib_globals *zg, struct agentx_session *sess, struct agentx_pdu *pdu)
{
  struct agentx_set_info *ptr;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);
  ptr = &snmpm->Agx_set_info;

  if (ptr->transid == pdu->transid) {
    agentx_free_varbind (ptr->var_list);
    pal_mem_set (ptr, 0 , sizeof (struct agentx_set_info));
    return;
  }
}

/*
 * AgentX Handling packet (PDU)
 */

/*
 RFC 2741, chap. 7.2.4.1. Subagent Processing of the agentx-TestSet-PDU
 * If each VarBind is successful, the subagent has a further
 * responsibility to ensure the availability of all resources (memory,
 * write access, etc.) required for successfully carrying out a
 * subsequent agentx-CommitSet operation.  If this cannot be guaranteed,
 * the subagent should set res.error to `resourceUnavailable'.  As a
 * result of this validation step, an agentx-Response-PDU is sent in
 * reply whose res.error field is set to one of the following SNMPv2 PDU
 * error-status values (see section 3, "Definitions", in RFC 1905):
 * 
 *          noError                    (0),
 *          genErr                     (5),
 *          noAccess                   (6),
 *          wrongType                  (7),
 *          wrongLength                (8),
 *          wrongEncoding              (9),
 *          wrongValue                (10),
 *          noCreation                (11),
 *          inconsistentValue         (12),
 *          resourceUnavailable       (13),
 *          notWritable               (17),
 *          inconsistentName          (18)
 */
s_int32_t
agentx_set (struct lib_globals *zg,
            oid *reqoid, size_t *reqoid_len,
            u_int8_t val_type, void *val, size_t val_len,
            s_int32_t action, u_int32_t vr_id)
{
  s_int32_t j;
  struct subtree *subtree;
  struct variable *v;
  s_int32_t subresult;
  oid *suffix;
  size_t suffix_len;
  s_int32_t result;
  u_int8_t *statP = NULL;
  WriteMethod *write_method = NULL;
  struct listnode *node;
  bool_t match_found;

  match_found = PAL_FALSE;

  /* Check */
  for (node = zg->snmp.treelist->head; node; node = node->next)
    {
      subtree = node->data;
      subresult = oid_compare_part (reqoid, *reqoid_len,
                                    subtree->name, subtree->name_len);

      /* Subtree matched. */
      if (subresult == 0)
        {
          /* Prepare suffix. */
          suffix = reqoid + subtree->name_len;
          suffix_len = *reqoid_len - subtree->name_len;
          result = subresult;

          /* Check variables. */
          for (j = 0; j < subtree->variables_num; j++)
            {
              v = &subtree->variables[j];

              /* Always check suffix */
              result = oid_compare_part (suffix, suffix_len,
                                         v->name, v->namelen);

               if (result == 0)
                 {
                   if (IS_SUBAG_DEBUG_PROCESS)
                     zlog_info (zg, "AgentX function call index is %d",
                                v->magic);

                   if (v->acl == NOACCESS)
                     return SNMP_ERR_NOACCESS;
 
                   statP = (*v->findVar) (v, suffix, &suffix_len, 1,
                                          &val_len, &write_method, vr_id);
 
                   if (v->acl == RONLY)
                     return SNMP_ERR_READONLY;
 
                   if (write_method)
                     return (*write_method)(action, val, val_type, val_len,
                                            statP, suffix, suffix_len, v,
                                            vr_id);
                   else
                     {
                       match_found = PAL_TRUE;
                       break;
                     }
                 }

                 /* If above execution is failed or oid is small (so
                    there is no further match). */
                 if (result < 0)
                   return SNMP_ERR_NOSUCHNAME;
             }
         }
     }

  if (match_found)
    return SNMP_ERR_NOACCESS;
 
  return SNMP_ERR_NOSUCHNAME;
}

s_int32_t
agentx_get (struct lib_globals *zg,
            oid *reqoid, size_t *reqoid_len,  s_int32_t exact,
            u_int8_t *val_type,void **val, size_t *val_len, u_int32_t vr_id)
{
  s_int32_t j;
  struct subtree *subtree;
  struct variable *v;
  s_int32_t subresult;
  oid *suffix;
  size_t suffix_len;
  s_int32_t result;
  WriteMethod *write_method=NULL;
  struct listnode *node;
  bool_t match_found;

  match_found = PAL_FALSE;

  /* Check */
  for (node = zg->snmp.treelist->head; node; node = node->next)
    {
      subtree = node->data;
      subresult = oid_compare_part (reqoid, *reqoid_len,
                                    subtree->name, subtree->name_len);

      /* Subtree matched. */
      if (subresult == 0)
        {
          /* Prepare suffix. */
          suffix = reqoid + subtree->name_len;
          suffix_len = *reqoid_len - subtree->name_len;
          result = subresult;

          /* Check variables. */
          for (j = 0; j < subtree->variables_num; j++)
            {
              v = &subtree->variables[j];

              /* Always check suffix */
              result = oid_compare_part (suffix, suffix_len,
                                         v->name, v->namelen);

              /* This is exact match so result must be zero. */
              if (result == 0)
                {
                  if (IS_SUBAG_DEBUG_PROCESS)
                    zlog_info (zg, "AgentX function call index is %d",
                               v->magic);

                  if (v->acl == NOACCESS)
                    return SNMP_ERR_NOACCESS;
 
                  *val = (*v->findVar) (v, suffix, &suffix_len, exact,
                                        val_len, &write_method, vr_id);

                  if (*val)
                    {
                      /* Call is suceed. */
                      *val_type = v->type;
                      return 0;
                    }
                  else
                    {
                      match_found = PAL_TRUE;
                      break;
                    }
                }

              /* If above execution is failed or oid is small (so
                 there is no further match). */
              if (result < 0)
                return SNMP_NOSUCHOBJECT;
            }
        }
    }
  if (match_found)
    return SNMP_NOSUCHINSTANCE;

  return SNMP_NOSUCHOBJECT;
}

s_int32_t
agentx_getnext (struct lib_globals *zg,
                oid *reqoid, size_t *reqoid_len, s_int32_t exact,
                u_int8_t *val_type,void **val, size_t *val_len,
                u_int32_t vr_id)
{
  s_int32_t j;
  oid save[MAX_OID_LEN];
  s_int32_t savelen = 0;
  struct subtree *subtree;
  struct variable *v;
  s_int32_t subresult;
  oid *suffix;
  oid retoid[MAX_OID_LEN];
  size_t suffix_len;
  size_t retoidlen;
  s_int32_t result;
  WriteMethod *write_method=NULL;
  struct listnode *node;
  void *retval = NULL;
  s_int32_t resultval;
  u_int8_t *retval_type = NULL;
  size_t retval_len = 0;

  retoidlen = 0;

  /* Save incoming request. */
  oid_copy (save, reqoid, *reqoid_len);
  savelen = *reqoid_len;

  /* Check */
  for (node = zg->snmp.treelist->head; node; node = node->next)
    {
      subtree = node->data;
      subresult = oid_compare_part (reqoid, *reqoid_len,
                                    subtree->name, subtree->name_len);

      /* If request is in the tree. The agent has to make sure we
         only receive requests we have registered for.
         Unfortunately, that's not true. In fact, a AgentX subagent has to
         behave as if it manages the whole SNMP MIB tree itself. It's the
         duty of the master agent to collect the best answer and return it
         to the manager. See RFC 1227 chapter 3.1.6 for the glory details
         :-).*/

      if (subresult <= 0)
        {
          /* Prepare suffix.  */
          suffix = reqoid + subtree->name_len;
          suffix_len = *reqoid_len - subtree->name_len;

          if (subresult < 0) {
            oid_copy (reqoid, subtree->name, subtree->name_len);
          *reqoid_len = subtree->name_len;
          }
          for (j = 0; j < subtree->variables_num; j++)
            {
              result = subresult;
              v = &subtree->variables[j];

              /* Next then check result >= 0. */
              if (result == 0)
                result = oid_compare_part (suffix, suffix_len,
                                           v->name, v->namelen);
              if (result <= 0) {
                if (IS_SUBAG_DEBUG_PROCESS)
                  zlog_info (zg, "AgentX function call index is %d", v->magic);
                if (result < 0) {
                  oid_copy(suffix, v->name, v->namelen);
                  suffix_len = v->namelen;
                }

                /* After fetching the correct value from the subtree node
                 * if  next subtree node registrations has OID with longer
                 * length, and makes oid_compart_part to return negative,  
                 * return the value to the manager
                 */
                if ((*val) && (retval) && (result < 0))
                  {
                    *val = retval;
                    val_type = retval_type;
                    *val_len = retval_len;
                    oid_copy (reqoid, retoid, retoidlen);
                    *reqoid_len = retoidlen;
                    return 0;
                  }

                if (v->acl == NOACCESS)
                  continue;
 
                *val = (*v->findVar) (v, suffix, &suffix_len, exact,
                                      val_len, &write_method, vr_id);
                *reqoid_len = suffix_len + subtree->name_len;

                 /* Multiple Registrations for the same OID */
                 if (*val)
                   {
                     if (! retval)
                       {
                         oid_copy (retoid, reqoid, *reqoid_len);
                         retoidlen = *reqoid_len;
                         retval = *val;
                         *val_type = v->type;
                         retval_type = val_type;
                         retval_len = *val_len;
                         oid_copy (reqoid, save, savelen);
                         *reqoid_len = savelen;
                         break;
                       }
                     else
                       {
                         if (result < 0)
                           break;
                         resultval = oid_compare (reqoid, *reqoid_len, retoid,
                                                  retoidlen);
                         if (resultval < 0)
                           {
                             oid_copy (retoid, reqoid, *reqoid_len);
                             retoidlen = *reqoid_len;
                             retval = *val;
                             *val_type = v->type;
                             retval_type = val_type;
                             retval_len = *val_len;
                             oid_copy (reqoid, save, savelen);
                             *reqoid_len = savelen;
                             break;
                           }

                       } 
                   }
              }
            }
        }
      oid_copy (reqoid, save, *reqoid_len);
      *reqoid_len = savelen;
    }

  if (retval)
    {
      *val = retval;
      val_type = retval_type;
      *val_len = retval_len;
      oid_copy (reqoid, retoid, retoidlen);
      *reqoid_len = retoidlen;
      return 0;
    }

  oid_copy (reqoid, save, savelen);
  *reqoid_len = savelen;

  return SNMP_ENDOFMIBVIEW;
}

int
agentx_handle_set (struct lib_globals *zg, 
                   struct agentx_session *sess, s_int32_t action,
                   struct agentx_pdu *pdu, void *magic, u_int32_t vr_id)
{
  struct agentx_variable_list *v = NULL;
  u_int8_t index = 0;
  int ret = 0;

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: handling Set message (%s)",
               (AGENTX_SET_RESERVE1 == action) ? "RESERVE1" 
               : ((AGENTX_SET_ACTION == action) ? "ACTION"
                 : ((AGENTX_SET_UNDO == action) ? "UNDO"
                   : ((AGENTX_SET_FREE == action) ? "FREE"
                     : "COMMIT"))));

  for (v = pdu->variables; v != NULL; v = v->next_variable)
    {
      index++;

      ret = agentx_set (zg, v->name, &v->name_length,
                        v->type, v->val.string, v->val_len, action, vr_id);
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: handle_set, errstat %d", ret);

      /* Return result. */
      if (ret != 0) {
        if (AGENTX_SET_RESERVE1 == action) {
          pdu->errstat = ret;
        } else if (AGENTX_SET_ACTION == action) {
          /* Returns the actual SNMP error */
          pdu->errstat = ret;
        } else if (AGENTX_SET_UNDO == action) {
          pdu->errstat = SNMP_ERR_UNDOFAILED;
        } else {
          pdu->errstat = SNMP_ERR_GENERR;
        }
        pdu->errindex = index;
        return pdu->errstat;
      }
    }
  return SNMP_ERR_NOERROR;
}

int
agentx_handle_get (struct lib_globals *zg, 
                   struct agentx_session *sess, s_int32_t exact,
                   struct agentx_pdu *pdu, void *magic, u_int32_t vr_id)
{
  struct agentx_variable_list *v = NULL;
  u_int8_t index = 0;
  u_int8_t val_type;
  void *val;
  size_t val_len;
  int ret = 0;

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: handling Get message");
  
  for (v = pdu->variables; v != NULL; v = v->next_variable)
    {
      index++;

      ret = agentx_get (zg, v->name, &v->name_length, exact,
                        &val_type, &val, &val_len, vr_id);
      if (ret != 0) {
        /*
         RFC 2741, chap. 7.2.3.1. Subagent Processing of the agentx-Get-PDU
         * (3)  Otherwise, if the starting OID does not match the object
         *      identifier prefix of any variable instantiated within the
         *      indicated context and session, the VarBind is set to
         *      `noSuchObject'.
         * (4)  Otherwise, the VarBind is set to `noSuchInstance'.
         */
        if ((ret == SNMP_NOSUCHOBJECT)
            || (ret == SNMP_NOSUCHINSTANCE)) {
          if (IS_SUBAG_DEBUG_PROCESS) {
            snmp_oid_dump (zg, "AgentX: can't handle OID",
                               v->name, v->name_length);
            zlog_info (zg, "AgentX: get, no such object/instance: result %d",
                       ret);
          }
          agentx_set_var_typed_value (v, ret, 0, 0);
        } else {
          if (ret == SNMP_ERR_NOACCESS)
            {
              pdu->errstat = ret;
              pdu->errindex = index;
              return pdu->errstat;
            }
          /*
           RFC 2741, p.65. chapter 7.2.3.
           * If processing should fail for any reason not described below,
           * res.error is set to `genErr',
           * res.index to the index of the failed SearchRange,
           * the VarBindList is reset to null,
           * and this agentx-Response-PDU is returned to the master agent.
           */
          pdu->errstat = SNMP_ERR_GENERR;
          pdu->errindex = index;
          agentx_free_varbind (pdu->variables);
          return pdu->errstat;
        }
      } else {
        /* save the variable bindings separately */
        agentx_set_var_typed_value (v, val_type, val, val_len);
      }
    }

  return SNMP_ERR_NOERROR;
}

int
agentx_handle_getnext (struct lib_globals *zg, 
                       struct agentx_session *sess, s_int32_t exact,
                       struct agentx_pdu *pdu, void *magic, u_int32_t vr_id)
{
  struct agentx_magic *smagic = (struct agentx_magic *) magic;
  struct agentx_variable_list *u = NULL, *v = NULL;
  u_int8_t index = 0;
  u_int8_t val_type;
  void *val = NULL;
  size_t val_len;
  int ret = 0;

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: handling GetNext message");
  
  for (u = smagic->ovars, v = pdu->variables; u != NULL && v != NULL;
       u = u->next_variable, v = v->next_variable)
    {
      index++;

      /*
         It need to handle this based on include flag (v->type)
         (ASN_PRIV_INCL_RANGE or ASN_PRIV_EXCL_RANGE)
         Currently, it seems to be operated as ASN_PRIV_INCL_RANGE
       */
      val_type = v->type;
      ret = agentx_getnext (zg, v->name, &v->name_length, exact,
                            &val_type, &val, &val_len, vr_id);
      if (ret != 0) {
        /*
         RFC 2741, chap. 7.2.3.2. Subagent Processing of the agentx-GetNext-PDU
         * (2)  If the subagent cannot locate an appropriate variable,
         *      v.name is set to the starting OID, 
         *      and the VarBind is set to `endOfMibView'.
         */
        if (ret == SNMP_ENDOFMIBVIEW) {
          if (IS_SUBAG_DEBUG_PROCESS) {
            snmp_oid_dump (zg, "AgentX: cannot handle OID",
                               v->name, v->name_length);
            zlog_info (zg, "AgentX: cannot locate an appropriate variable"
                           " -- endOfMibView (%d)", ret);
          }
          agentx_set_var_objid (v, u->name, u->name_length);
          agentx_set_var_typed_value (v, ret, 0, 0);
        } else {
          /*
           RFC 2741, p.65. chapter 7.2.3.
           * If processing should fail for any reason not described below,
           * res.error is set to `genErr',
           * res.index to the index of the failed SearchRange,
           * the VarBindList is reset to null,
           * and this agentx-Response-PDU is returned to the master agent.
           */
          pdu->errstat = SNMP_ERR_GENERR;
          pdu->errindex = index;
          agentx_free_varbind (pdu->variables);
          return pdu->errstat;
        }
      } else {
        /* save the variable bindings separately */
        agentx_set_var_typed_value (v, val_type, val, val_len);
      }

      /*
       * scope check
       */
      if (oid_compare
          (u->val.objid, u->val_len / sizeof(oid), nullOid,
           nullOidLen) != 0)
        {
          /* The master agent requested scoping for this variable. */ 
          ret = oid_compare (v->name, v->name_length,
                             u->val.objid,
                             u->val_len / sizeof(oid));
          if (IS_SUBAG_DEBUG_PROCESS) {
            snmp_oid_dump (zg, "AgentX: OID", v->name, v->name_length);
            snmp_oid_dump (zg, "AgentX: scope to", 
                               u->val.objid, u->val_len / sizeof(oid));
            zlog_info (zg, "AgentX: result %s\n",
                       (ret < 0)? "OK": "Out of scope");
          }

          if (ret >= 0) {
            /* The varbind is out of scope.  From RFC2741, p. 66: "If
             * the subagent cannot locate an appropriate variable,
             * v.name is set to the starting OID, and the VarBind is
             * set to `endOfMibView'". */ 
            agentx_set_var_objid (v, u->name, u->name_length);
            agentx_set_var_typed_value (v, SNMP_ENDOFMIBVIEW, 0, 0);
            if (IS_SUBAG_DEBUG_PROCESS)
              zlog_info (zg, "AgentX: scope violation -- return endOfMibView");
          }
        }
      else {
        if (IS_SUBAG_DEBUG_PROCESS)
          zlog_info (zg, "AgentX: handle_getnext, unscoped var in SearchRange");
      }
    }

  return SNMP_ERR_NOERROR;
}

int
agentx_handle_getbulk (struct lib_globals *zg, 
                       struct agentx_session *sess, s_int32_t exact,
                       struct agentx_pdu *pdu, void *magic, u_int32_t vr_id)
{
  struct agentx_magic *smagic = (struct agentx_magic *) magic;
  struct agentx_variable_list *u = NULL, *v = NULL;
  struct variable tvar;
  u_int32_t non_repeaters = pdu->errstat; /* non_repeaters in GetBulk */
  u_int32_t max_repetitions = pdu->errindex; /* max_repetitions in GetBulk */
  u_int32_t i = 0; /* for each iteration */
  u_int8_t index = 0;
  u_int8_t val_type;
  void *val = NULL;
  size_t val_len;
  int ret = 0;

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: handling GetBulk message");
  
  /* Initializes variable bind list of pdu for adding a result */
  agentx_free_varbind (pdu->variables);

  for (u = smagic->ovars; u != NULL; u = u->next_variable) {
    index++;
    if (u->name)
      pal_mem_cpy (&tvar.name, u->name, u->name_length);
    tvar.namelen = u->name_length;

    /*
     RFC 2741, chap. 7.2.3.3. Subagent Processing of the agentx-GetBulk-PDU
     * The first N SearchRanges are processed exactly as for the agentx-
     * GetNext-PDU.
     */
    if (index <= non_repeaters || max_repetitions == 0) {
      /*
         It need to handle this based on include flag (v->type)
         (ASN_PRIV_INCL_RANGE or ASN_PRIV_EXCL_RANGE)
         Currently, it seems to be operated as ASN_PRIV_INCL_RANGE
       */
      ret = agentx_getnext (zg, tvar.name, (size_t *)&tvar.namelen, exact,
                            &val_type, &val, &val_len, vr_id);
      if (ret != 0) {
        /*
         RFC 2741, chap. 7.2.3.3. Subagent Processing of the agentx-GetBulk-PDU
         */
        if (ret == SNMP_ENDOFMIBVIEW) {
          if (IS_SUBAG_DEBUG_PROCESS) {
            snmp_oid_dump (zg, "AgentX: cannot handle OID",
                               v->name, v->name_length);
            zlog_info (zg, "AgentX: cannot locate an appropriate variable"
                           " -- endOfMibView (%d)", ret);
          }
          v = agentx_pdu_add_variable (zg, pdu, u->name, u->name_length,
                                       ret, 0, 0);
        } else {
          /*
           RFC 2741, p.65. chapter 7.2.3.
           * If processing should fail for any reason not described below,
           * res.error is set to `genErr',
           * res.index to the index of the failed SearchRange,
           * the VarBindList is reset to null,
           * and this agentx-Response-PDU is returned to the master agent.
           */
          pdu->errstat = SNMP_ERR_GENERR;
          pdu->errindex = index;
          agentx_free_varbind (pdu->variables);
          return pdu->errstat;
        }
      } else {
        /* save the variable bindings separately */
        v = agentx_pdu_add_variable (zg, pdu, tvar.name, tvar.namelen,
                                     val_type, val, val_len);
      }

      /*
       * scope check
       */
      if (oid_compare
          (u->val.objid, u->val_len / sizeof(oid), nullOid,
           nullOidLen) != 0)
        {
          /* The master agent requested scoping for this variable. */ 
          ret = oid_compare (v->name, v->name_length,
                             u->val.objid,
                             u->val_len / sizeof(oid));
          if (IS_SUBAG_DEBUG_PROCESS) {
            snmp_oid_dump (zg, "AgentX: OID", v->name, v->name_length);
            snmp_oid_dump (zg, "AgentX: scope to", 
                               u->val.objid, u->val_len / sizeof(oid));
            zlog_info (zg, "AgentX: result %s\n",
                       (ret < 0)? "OK": "Out of scope");
          }

          if (ret >= 0) {
            /* The varbind is out of scope.  From RFC2741, p. 66: "If
             * the subagent cannot locate an appropriate variable,
             * v.name is set to the starting OID, and the VarBind is
             * set to `endOfMibView'". */ 
            agentx_set_var_objid (v, u->name, u->name_length);
            agentx_set_var_typed_value (v, SNMP_ENDOFMIBVIEW, 0, 0);
            if (IS_SUBAG_DEBUG_PROCESS)
              zlog_info (zg, "AgentX: scope violation -- return endOfMibView");
          }
        }
      else {
        if (IS_SUBAG_DEBUG_PROCESS)
          zlog_info (zg, "AgentX: handle_getbulk, unscoped var in SearchRange");
      }

    /*
     RFC 2741, chap. 7.2.3.3. Subagent Processing of the agentx-GetBulk-PDU
     * If M and R are both non-zero, the remaining R SearchRanges are
     * processed iteratively to produce potentially many VarBinds.  For each
     * iteration i, such that i is greater than zero and less than or equal
     * to M, and for each repeated SearchRange s, such that s is greater
     * than zero and less than or equal to R, the (N+((i-1)*R)+s)-th VarBind
     * is added to the agentx-Response-PDU
     */
    /* handling iteration */
    } else {
      for (i = 0; i < max_repetitions; i++) {
        /*
           It need to handle this based on include flag (v->type)
           (ASN_PRIV_INCL_RANGE or ASN_PRIV_EXCL_RANGE)
           Currently, it seems to be operated as ASN_PRIV_INCL_RANGE
         */
        ret = agentx_getnext (zg, tvar.name, (size_t *)&tvar.namelen, exact,
                              &val_type, &val, &val_len, vr_id);
        if (ret != 0) {
          /*
           RFC 2741, chap.7.2.3.3. Subagent Processing of the agentx-GetBulk-PDU
           */
          if (ret == SNMP_ENDOFMIBVIEW) {
            if (IS_SUBAG_DEBUG_PROCESS) {
              snmp_oid_dump (zg, "AgentX: cannot handle OID",
                                 v->name, v->name_length);
              zlog_info (zg, "AgentX: cannot locate an appropriate variable"
                             " -- endOfMibView (%d)", ret);
            }
            v = agentx_pdu_add_variable (zg, pdu, tvar.name, tvar.namelen,
                                         ret, 0, 0);
            break;
          } else {
            /* 
             RFC 2741, p.65. chapter 7.2.3.
             */
            pdu->errstat = SNMP_ERR_GENERR;
            pdu->errindex = index;
            agentx_free_varbind (pdu->variables);
            return pdu->errstat;
          }
        } else {
          /* save the variable bindings separately */
          v = agentx_pdu_add_variable (zg, pdu, tvar.name, tvar.namelen,
                                       val_type, val, val_len);
        }
  
        /*
         * scope check
         */
        if (oid_compare
            (u->val.objid, u->val_len / sizeof(oid), nullOid,
             nullOidLen) != 0)
          {
            /* The master agent requested scoping for this variable. */ 
            ret = oid_compare (v->name, v->name_length,
                               u->val.objid,
                               u->val_len / sizeof(oid));
            if (IS_SUBAG_DEBUG_PROCESS) {
              snmp_oid_dump (zg, "AgentX: OID", v->name, v->name_length);
              snmp_oid_dump (zg, "AgentX: scope to", 
                                 u->val.objid, u->val_len / sizeof(oid));
              zlog_info (zg, "AgentX: result %s\n",
                         (ret < 0)? "OK": "Out of scope");
            }
  
            if (ret >= 0) {
            /*
             RFC 2741, 7.2.3.3. Subagent Processing of the agentx-GetBulk-PDU
             * 2) If no such variable exists, the VarBind is set to '
             *    endOfMibView' as described in section 5.4, "Value
             *    Representation".  v.name is set to v.name of the (N+((i-
             *    2)xR)+s)-th VarBind unless i is currently 1, in which case it
             *    is set to the value of the starting OID in the (N+s)-th
             *    SearchRange.
             */
              /* The varbind is out of scope. */
              agentx_set_var_objid (v, tvar.name, tvar.namelen);
              agentx_set_var_typed_value (v, SNMP_ENDOFMIBVIEW, 0, 0);
              if (IS_SUBAG_DEBUG_PROCESS)
                zlog_info (zg, "AgentX: scope violation -- return endOfMibView");
              break;
            }
          }
        else {
          if (IS_SUBAG_DEBUG_PROCESS)
            zlog_info (zg, "AgentX: handle_getbulk, unscoped var in SearchRange");
        }
      }
    }
  }

  return SNMP_ERR_NOERROR;
}

int
agentx_handle_response (struct lib_globals *zg, 
                        struct agentx_session *sess, int reqid,
                        struct agentx_pdu *pdu, void *magic)
{
  struct agentx_magic *smagic = (struct agentx_magic *) magic;

  if (magic == NULL) {
    return 1;
  }

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: handling response (cmd 0x%02x orig_cmd 0x%02x)",
               pdu->command, smagic->original_command);

  if (pdu->command == AGENTX_SET_UNDO ||
      pdu->command == AGENTX_SET_FREE ||
      pdu->command == AGENTX_SET_COMMIT) {
    free_set_vars (zg, smagic->session, pdu);
  }

  if (smagic->ovars != NULL) {
    agentx_free_varbind (smagic->ovars);
  }

  pdu->command = AGENTX_MSG_RESPONSE;
  pdu->version = smagic->session->version;

  if (!agentx_send (zg, smagic->session, pdu, NULL, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (smagic->session->lib_errno);
    if (IS_SUBAG_DEBUG_PROCESS)
      zlog_info (zg, "AgentX: handle_response failed!");
    AGENTX_FREE (smagic);
    return 0;
  }
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: FINISHED handle_response");
  AGENTX_FREE (smagic);
  return 1;
}

int
agentx_handle_set_response (struct lib_globals *zg,
                            struct agentx_session *sess, int reqid,
                            struct agentx_pdu *pdu, void *magic)
{
  struct agentx_session *retsess;
  struct agentx_set_info *asi;

  if (magic == NULL) {
    return 1;
  }

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: handling subagent set response (mode=%d,req=0x%x,trans=0x%x,sess=0x%x)",
               pdu->command, pdu->reqid,pdu->transid, pdu->sessid);

  asi = (struct agentx_set_info *) magic;
  retsess = asi->session;
  asi->errstat = pdu->errstat;

  if (asi->mode == AGENTX_SET_RESERVE1) {
    /* move to RESERVE2 mode, an internal only agent mode */
    /* check exception statuses of reserve1 first */
    if (!pdu->errstat) {
      asi->mode = pdu->command = AGENTX_SET_RESERVE2;
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: going from RESERVE1 -> RESERVE2");
    } else {
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: an error happens in RESERVE1", pdu->errstat);
    }
  } else {
    if (asi->mode == AGENTX_SET_FREE ||
        asi->mode == AGENTX_SET_UNDO ||
        asi->mode == AGENTX_SET_COMMIT) {
      free_set_vars (zg, retsess, pdu);
    }
  }
  agentx_free_varbind (pdu->variables);
  pdu->variables = NULL;  /* the variables were added by us */

  /*
   RFC 2741, chap. 7.2.4.4.  Subagent Processing of the agentx-CleanupSet-PDU
   * The agentx-CleanupSet-PDU signals the end of processing of the
   * management operation requested in the previous TestSet-PDU.  This is
   * an indication to the subagent that it may now release any resources
   * it may have reserved in order to carry out the management request.
   * No response is sent by the subagent.
   */
  /* When it receied CleanupSet-PDU,
     mode is AGENTX_SET_COMMIT or AGENTX_SET_FREE. */
  if (asi->mode == AGENTX_SET_RESERVE1 ||
      asi->mode == AGENTX_SET_RESERVE2 ||
      asi->mode == AGENTX_SET_ACTION ||
      asi->mode == AGENTX_SET_UNDO)
    {
      pdu->command = AGENTX_MSG_RESPONSE;
      pdu->version = retsess->version;

      if (!agentx_send (zg, retsess, pdu, NULL, NULL)) {
        IS_SUBAG_DEBUG_LIBERR_SHOW (retsess->lib_errno);
        if (IS_SUBAG_DEBUG_PROCESS)
          zlog_info (zg, "AgentX: handle_set_response failed!");
        return 0;
      }
    }
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: FINISHED handle_set_response");
  return 1;
}

int
agentx_handle_packet (struct lib_globals *zg, 
                      struct agentx_session *sess, int reqid,
                      struct agentx_pdu *pdu, void *magic)
{
  struct agentx_set_info *asi = NULL;
  AGENTX_CALLBACK mycallback;
  void *retmagic = NULL;
  struct agentx_magic *smagic = NULL;
  s_int32_t result;
  u_int32_t vr_id = 0;

  if (IS_SUBAG_DEBUG_PROCESS) {
    zlog_info (zg, "AgentX: agentx_handle_packet");
    zlog_info (zg, "        handling request (req=0x%x,trans=0x%x,sess=0x%x)",
               pdu->reqid,pdu->transid, pdu->sessid);
  }
  pdu->version = AGENTX_VERSION_1;

  if (pdu->command == AGENTX_MSG_GET
      || pdu->command == AGENTX_MSG_GETNEXT
      || pdu->command == AGENTX_MSG_GETBULK) {
    smagic = (struct agentx_magic *) XCALLOC (MTYPE_TMP,
                                              sizeof (struct agentx_magic));
    if (smagic == NULL) {
      zlog_err (zg, "agentx: couldn't malloc() smagic");
      return 1;
    }
    smagic->original_command = pdu->command;
    smagic->session = sess;
    smagic->ovars = NULL;
    retmagic = (void *) smagic;
  }

  /* Currently, community string is not available in pdu */
/*  if (pdu->community)
    str = pdu->community + pal_strlen ("public");
    vr_id = pal_strtou32 (str, &ptr, 10); */

  vr_id = 0;
  
  switch (pdu->command) {
    case AGENTX_MSG_GET:
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: -> Get");
      mycallback = agentx_handle_response;
      result = agentx_handle_get (zg, sess, 1, pdu, retmagic, vr_id);
      break;

    case AGENTX_MSG_GETNEXT:
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: -> GetNext");

      /* We have to save a copy of the original variable list here because
       * if the master agent has requested scoping for some of the varbinds
       * that information is stored there. */ 

      smagic->ovars = agentx_clone_varbind (pdu->variables);
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "        saved variables");
      mycallback = agentx_handle_response;
      result = agentx_handle_getnext (zg, sess, 0, pdu, retmagic, vr_id);
      break;

    case AGENTX_MSG_GETBULK:
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: -> GetBulk");

      /* We have to save a copy of the original variable list here because
       * if the master agent has requested scoping for some of the varbinds
       * that information is stored there. */ 

      smagic->ovars = agentx_clone_varbind (pdu->variables);
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "        saved variables at %p", smagic->ovars);
      mycallback = agentx_handle_response;
      result = agentx_handle_getbulk (zg, sess, 0, pdu, retmagic, vr_id);
      break;

    case AGENTX_MSG_RESPONSE:
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: -> Response");
      return 1;

    case AGENTX_MSG_TESTSET:
      /* we must map this twice to both RESERVE1 and RESERVE2 */
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: -> TestSet");
      asi = save_set_vars (zg, sess, pdu);
      if (asi == NULL) {
        zlog_err (zg, "agentx: save_set_vars() failed");
        return 1;
      }
      asi->mode = pdu->command = AGENTX_SET_RESERVE1;
      mycallback = agentx_handle_set_response;
      retmagic = asi;
      result = agentx_action_test_set ();
      break;

    case AGENTX_MSG_COMMITSET:
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: -> CommitSet");
      asi = restore_set_vars (zg, pdu);
      if (asi == NULL) {
        zlog_err (zg, "agentx: restore_set_vars() failed");
        return 1;
      }
      if (asi->mode != AGENTX_SET_RESERVE2) {
        zlog_warn (zg, "agentx: dropping bad AgentX request (wrong mode %d)",
                   asi->mode);
        return 1;
      }
      asi->mode = pdu->command = AGENTX_SET_ACTION;
      mycallback = agentx_handle_set_response;
      retmagic = asi;
      result = agentx_handle_set (zg, sess, asi->mode, pdu, retmagic, vr_id);
      break;

    case AGENTX_MSG_CLEANUPSET:
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: -> CleanupSet");
      asi = restore_set_vars (zg, pdu);
      if (asi == NULL) {
        zlog_err (zg, "agentx: restore_set_vars() failed");
        return 1;
      }
      if (asi->mode == AGENTX_SET_RESERVE1 ||
          asi->mode == AGENTX_SET_RESERVE2) {
          asi->mode = pdu->command = AGENTX_SET_FREE;
      } else if (asi->mode == AGENTX_SET_ACTION) {
          asi->mode = pdu->command = AGENTX_SET_COMMIT;
      } else {
        zlog_warn (zg, "agentx: dropping bad AgentX request (wrong mode %d)",
                   asi->mode);
        return 1;
      }
      mycallback = agentx_handle_set_response;
      retmagic = asi;
      result = agentx_handle_cleanup_set ();
      break;

    case AGENTX_MSG_UNDOSET:
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: -> UndoSet");
      asi = restore_set_vars (zg, pdu);
      if (asi == NULL) {
        zlog_err (zg, "agentx: restore_set_vars() failed");
        return 1;
      }
      asi->mode = pdu->command = AGENTX_SET_UNDO;
      mycallback = agentx_handle_set_response;
      retmagic = asi;
      result = agentx_action_undo_set ();
      break;

    default:
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: -> unknown command %d (%02x)",
                   pdu->command, pdu->command);
      return 0;
  }

  /* handle response callback */
  if (mycallback != NULL)
    mycallback (zg, sess, pdu->reqid, pdu, retmagic);

  return 1;
}

/*
 * AgentX Processing packet (PDU). 
 * This function processes a complete (according to agentx_check_packet) 
 * packet, parsing it into a PDU and calling the relevant functions.
 * On entry, packetptr points at the packet in the session's buffer and
 * length is the length of the packet.
 */ 
int
agentx_process_packet (struct lib_globals *zg, 
                       struct agentx_session *sess,
                       u_char *packetptr, int length,
                       u_int32_t vr_id)
{
  struct agentx_pdu *pdu;
  struct agentx_request_info *rq;
  int ret = 0, handled = 0;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);
  rq = &snmpm->Agx_request_info;
  
  if (IS_SUBAG_DEBUG_PROCESS && IS_SUBAG_DEBUG_DETAIL)
    zlog_info (zg, "AgentX: process_packet, %s state, fd %d, pkt %p, length %d",
               Agx_state_str[snmpm->Agx_state], zg->snmp.sock, packetptr, length);

  if (IS_SUBAG_DEBUG_XDUMP)
    snmp_xdump (zg, "AgentX: received PDU", packetptr, length);

  /* No transport-level filtering (e.g. IP-address based allow/deny). */

  pdu = agentx_pdu_create (AGENTX_MSG_RESPONSE, 0, zg);
  if (pdu == NULL) {
    zlog_err (zg, "AgentX: process_packet, pdu failed to be created\n");
    return -1;
  }

  /* Parsing function */
  ret = agentx_parse (zg, sess, pdu, packetptr, length);

  if (ret != SNMP_ERR_NOERROR) {
    zlog_err (zg, "AgentX: process_packet, parse fail");

    /*
    RFC 2741, chap. 7.2.2. Subagent Processing
     * 2) If the received PDU cannot be parsed, res.error is set to
     *    `parseError'.
     * 3) Otherwise, if h.sessionID does not correspond to a currently
     *    established session, res.error is set to `notOpen'.
     * 4) At this point, if res.error is not `noError', the received PDU is
     *    not processed further.  If the received PDU's header was
     *    successfully parsed, the AgentX-Response-PDU is sent in reply.  If
     *    the received PDU's header was not successfully parsed or for some
     *    other reason the subagent cannot send a reply, processing is
     *    complete.
     */
    if (ret > SNMP_ERR_NOERROR) {
      pdu->command = AGENTX_MSG_RESPONSE;
      pdu->version = sess->version;
      pdu->errstat = ret;

      if (!agentx_send (zg, sess, pdu, NULL, NULL)) {
        IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
        if (IS_SUBAG_DEBUG_PROCESS)
          zlog_info (zg, "AgentX: process_packet, failed to send response-pdu");
      }
    }
    agentx_free_pdu (pdu);
    return 0;
  }

  /* Handling function: Response-PDU */
  if (pdu->flags & AGENTX_FLAGS_RESPONSE_PDU) {
    /* A requested packet is only one. */
    if (rq && rq->request_id == pdu->reqid) {
      AGENTX_CALLBACK callback;
      void *magic = NULL;
      long rq_request_id = rq->request_id;

      /* in case of the response of agentx-admin request */
      if (rq->callback) {
        callback = rq->callback;
        if (rq->cb_data)
          magic = rq->cb_data;
        else
          magic = rq->pdu;
      } else {
        callback = agentx_handle_packet;
        magic = NULL;
      }
      handled = 1;

      if (callback != NULL)
        callback (zg, sess, pdu->reqid, pdu, magic);

      /* If this request_id is different, this (rq) already was freed. */
      if (rq_request_id == rq->request_id) {
        agentx_free_pdu (rq->pdu);
        /* As occasion demands, it frees rq->cb_data */
        pal_mem_set (rq, 0 , sizeof (struct agentx_request_info));
      }
    }
    else if (rq) {
    /* If reqid(packetID) of a received pkt is different from a saved reqid,
       it does not any action. */ 
      zlog_warn (zg, "AgentX: process_packet (%s state), Response-PDU, %d:%d", 
                      Agx_state_str[snmpm->Agx_state], rq->request_id, pdu->reqid);
      if (rq->pdu && rq->pdu->command)
      zlog_warn (zg, "AgentX: requested pdu : %d", 
                      rq && rq->pdu && rq->pdu->command);
    }
  }
  /* Handling function: Except Response-PDU */
  else {
    handled = 1;
    agentx_handle_packet (zg, sess, pdu->reqid, pdu, NULL);
  }

  if (!handled) {
    zlog_warn (zg, "AgentX: process_packet, unhandled PDU, %s state", 
                    Agx_state_str[snmpm->Agx_state]);
  }

  agentx_free_pdu (pdu);
  return 0;
}

int
agentx_handle_open_response (struct lib_globals *zg, 
                             struct agentx_session *sess, int reqid,
                             struct agentx_pdu *pdu, void *magic)
{
  struct agentx_pdu *rq_pdu = (struct agentx_pdu *) magic;
  struct subtree *subtree;
  struct listnode *node;
  s_int32_t index = 0;
  s_int32_t result;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);

  /* Check Response-PDU of Open-PDU */
  if (rq_pdu->command != AGENTX_MSG_OPEN) {
    /* Maybe the requested packet is overwrited by somw packet */
    zlog_warn (zg, "(Warning) AgentX: sent command (%s) is not Open-PDU",
               agentx_cmd((u_char)rq_pdu->command)); 
  }

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: open_response, %s state", 
                    Agx_state_str[snmpm->Agx_state]);

  /* Synchronise sysUpTime with the master agent */
  agentx_synchronise_sysuptime (zg, pdu);

  for (node = zg->snmp.treelist->head; node; node = node->next)
    {
      subtree = node->data;
      if (subtree) {
        result = agentx_send_register (zg, sess,
                                       subtree->name, subtree->name_len,
                                       subtree->priority,
                                       subtree->range_subid,
                                       subtree->range_ubound,
                                       subtree->timeout, subtree->flags);
        if (result == 0) {
          snmpm->Agx_reg_subtree = (struct subtree *) subtree;
          index++;
          break;
        }
      }
    }

  if (index == 0) {
    zlog_warn (zg, "(Warning) AgentX: can't support SNMP services (none MIB)"); 
    /* For preventing endless loop (Open<->Response),
       no called agentx_event (zg, AGENTX_RESTART, 0) */
    return -1;
  }

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: open_response, %s -> %s state", 
                    Agx_state_str[snmpm->Agx_state],
                    Agx_state_str[AGENTX_REGISTERING]);

  /* The state of subagent changes to OPENING. */
  snmpm->Agx_state = AGENTX_REGISTERING;

  return 0;
}

int
agentx_handle_reg_response (struct lib_globals *zg, 
                            struct agentx_session *sess, int reqid,
                            struct agentx_pdu *pdu, void *magic)
{
  struct agentx_pdu *rq_pdu = (struct agentx_pdu *) magic;
  struct agentx_set_info *setptr;
  struct subtree *regtree;
  struct subtree *subtree = NULL;
  struct listnode *node;
  s_int32_t op_flag = 0;
  s_int32_t index = 0;
  s_int32_t result;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);
  setptr = &snmpm->Agx_set_info;
  regtree = snmpm->Agx_reg_subtree;

  /* check Register-PDU of Register-PDU */
  if (rq_pdu->command != AGENTX_MSG_REGISTER) {
    /* Maybe the requested packet is overwrited by somw packet */
    zlog_warn (zg, "(Warning) AgentX: sent command (%s) is not Register-PDU",
               agentx_cmd((u_char)rq_pdu->command)); 
  }

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: register_response, %s state", 
                    Agx_state_str[snmpm->Agx_state]);

  /* Synchronise sysUpTime with the master agent */
  agentx_synchronise_sysuptime (zg, pdu);

  for (node = zg->snmp.treelist->head; node; node = node->next)
    {
      subtree = node->data;
      if (subtree && regtree == subtree) {
        /* Because that regtree is the lastest registered subtree,
           it executes from here. */
        op_flag = 1;
        continue;
      }

      if (subtree && op_flag) {
        /* Already subtree is the next registered subtree.
           There is no use this routine, but it does for guarantee. */
        result = oid_compare_part (regtree->name, regtree->name_len, 
                                   subtree->name, subtree->name_len);

        /* Subtree greater than the registered subtree. */
        if (result < 0) {
          result = agentx_send_register (zg, sess,
                                         subtree->name, subtree->name_len,
                                         subtree->priority,
                                         subtree->range_subid,
                                         subtree->range_ubound,
                                         subtree->timeout, subtree->flags);
          if (result == 0) {
            snmpm->Agx_reg_subtree = (struct subtree *) subtree;
            index++;
            break;
          }
        }
      }
    }

  if (index != 0) {
    if (subtree && IS_SUBAG_DEBUG_PROCESS)
      snmp_oid_dump (zg, "AgentX: registring...",
                         subtree->name, subtree->name_len);
    return 0;
  }

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: register_response, %s -> %s state", 
                    Agx_state_str[snmpm->Agx_state],
                    Agx_state_str[AGENTX_OPERATIONAL]);

  /* Frees Set information */
  agentx_free_varbind (setptr->var_list);
  pal_mem_set (setptr, 0 , sizeof (struct agentx_set_info));

  /* Initializes the registered subtree */
  regtree = NULL;

  /* The state of subagent changes to OPENING. */
  snmpm->Agx_state = AGENTX_OPERATIONAL;

  return 0;
}

int
agentx_handle_ping_response (struct lib_globals *zg, 
                             struct agentx_session *sess, int reqid,
                             struct agentx_pdu *pdu, void *magic)
{
  struct agentx_pdu *rq_pdu = (struct agentx_pdu *) magic;
  struct snmp_master *snmpm = SNMP_MASTER (zg);

  /* Check Response-PDU of Open-PDU */
  if (rq_pdu->command != AGENTX_MSG_PING) {
    /* Maybe the requested packet is overwrited by somw packet */
    zlog_warn (zg, "(Warning) AgentX: sent command (%s) is not Ping-PDU",
               agentx_cmd((u_char)rq_pdu->command)); 
  }

  if (IS_SUBAG_DEBUG_PROCESS && IS_SUBAG_DEBUG_DETAIL)
    zlog_info (zg, "AgentX: ping_response, %s state", 
                    Agx_state_str[snmpm->Agx_state]);

  /* Synchronise sysUpTime with the master agent */
  agentx_synchronise_sysuptime (zg, pdu);

  /* Initializes session's retries number */
  sess->retries = 0;

  return 0;
}

/*--------------------------------------------------------*
 *   AGENTX-THREAD : agentx.c/h                           *
 *--------------------------------------------------------*/

/* AgentX message read function. */
s_int32_t
agentx_read (struct thread *t)
{
  struct agentx_session *sess;
  pal_sock_handle_t sock;
  s_int32_t pdulen = 0, rxbuf_len = AGENTXMAXPKTSIZE;
  u_int8_t *rxbuf = NULL;
  s_int32_t length = 0;
  u_int8_t *pptr = NULL;
  s_int32_t ret;
  u_int32_t vr_id = 0;
  struct lib_globals *zg;
  struct snmp_master *snmpm;

  zg = THREAD_GLOB (t);
  snmpm = SNMP_MASTER (zg);
  sess = &snmpm->Agx_session;

  /* Clear thread. */
  sock = THREAD_FD (t);
  zg->snmp.t_read = NULL;

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: read start");

  if (snmpm->SavedPacket == NULL) {
    /* We have no saved packet. Allocate one. */
    if ((snmpm->SavedPacket = (u_char *) XMALLOC (MTYPE_TMP, rxbuf_len)) == NULL) {
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: read, can't malloc %d bytes for rxbuf",
                   rxbuf_len);
      /* Regiser read thread. */
      agentx_event (zg, AGENTX_READ, sock);
      return 0;
    } else {
      rxbuf = snmpm->SavedPacket;
      snmpm->SavedPacket_size = rxbuf_len;
      snmpm->SavedPacket_len = 0;
    }
  } else {
    /* We have saved a partial packet from last time.  Extend that, if
     * necessary, and receive new data after the old data. */ 
    u_char         *newbuf;

    if (snmpm->SavedPacket_size < snmpm->SavedPacket_len + rxbuf_len) {
      newbuf = (u_char *) XREALLOC (MTYPE_TMP, snmpm->SavedPacket, snmpm->SavedPacket_len + rxbuf_len);
      if (newbuf == NULL) {
        if (IS_SUBAG_DEBUG_PROCESS)
          zlog_info (zg, "AgentX: read, can't allocate %d more memory for rxbuf (total %d)",
                     rxbuf_len, snmpm->SavedPacket_len + rxbuf_len);
        /* Regiser read thread. */
        agentx_event (zg, AGENTX_READ, sock);
        return 0;
      } else {
        snmpm->SavedPacket = newbuf;
        snmpm->SavedPacket_size = snmpm->SavedPacket_len + rxbuf_len;
        rxbuf = snmpm->SavedPacket + snmpm->SavedPacket_len;
      }
    } else {
      rxbuf = snmpm->SavedPacket + snmpm->SavedPacket_len;
      rxbuf_len = snmpm->SavedPacket_size - snmpm->SavedPacket_len;
    }
  }

  /* Read message from AgentX socket. */
  length = pal_sock_recv (sock, rxbuf, rxbuf_len, 0);

  if (length < 0) {
    zlog_warn (zg, "Can't read AgentX packet: %s, connection closed: %d",
               pal_strerror (errno), sock);
    agentx_event (zg, AGENTX_RESTART, 0);
    return -1;
  }

  if (length == 0) {
    zlog_warn (zg, "AgentX: read, connection (sock %d) closed: length is zero",
               sock);
    agentx_event (zg, AGENTX_RESTART, 0);
    return -1;
  }

  pptr = snmpm->SavedPacket;
  snmpm->SavedPacket_len += length;

  if (IS_SUBAG_DEBUG_PROCESS && IS_SUBAG_DEBUG_DETAIL)
    zlog_info (zg, "AgentX: read length: %d, saved packet_len: %d",
               length, snmpm->SavedPacket_len);

  while (snmpm->SavedPacket_len > 0) {
    /* Get the total data length we're expecting (and need to wait for). */
    pdulen = agentx_check_packet(zg, pptr, snmpm->SavedPacket_len);

    if (IS_SUBAG_DEBUG_PROCESS && IS_SUBAG_DEBUG_DETAIL)
      zlog_info (zg, "AgentX: read, saved packet_len %d, PDU length %d",
                 snmpm->SavedPacket_len, pdulen);

    if (pdulen > MAX_PACKET_LENGTH) {
      /* Illegal length, drop the connection. */ 
      zlog_err(zg, "AgentX: read, Maximum packet size exceeded in a request.");
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: read, disconnected the connection %d",
                   sock);
      agentx_event (zg, AGENTX_RESTART, 0);
      return -1;
    }

    if (pdulen > snmpm->SavedPacket_len) {
      /* We don't have a complete packet yet.  Return, and wait for
       * more data to arrive. */
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: read, pkt not complete (need %d got %d so far)",
                   pdulen, snmpm->SavedPacket_len);
      /* If we get here, then there is a partial packet of length
       * SavedPacket_len bytes starting at pptr left over. 
       * Move that to the start of the buffer,
       * and then reallocate the buffer down to size to reduce the memory. */
      break;
    }

    /* We have at least one complete packet in the buffer now. */
    ret = agentx_process_packet (zg, sess, pptr, pdulen, vr_id);

    /* Step past the packet we've just dealt with. */
    pptr += pdulen;
    snmpm->SavedPacket_len -= pdulen;
  }

  if (snmpm->SavedPacket_len >= MAX_PACKET_LENGTH) {
    /* Obviously this should never happen! */ 
    zlog_err (zg, "AgentX: read, too large packet_len = %d, dropping connection %d",
              snmpm->SavedPacket_len, sock);
    agentx_event (zg, AGENTX_RESTART, 0);
    return -1;
  } else if (snmpm->SavedPacket_len == 0) {
    /* It means the packet buffer contained an integral number of PDUs,
     * so we don't have to save any data for next time. */
    AGENTX_FREE (snmpm->SavedPacket);
    snmpm->SavedPacket_size = snmpm->SavedPacket_len = 0;
  } else {
    /* If we get here, then there is a partial packet of length
     * SavedPacket_len bytes starting at pptr left over. 
     * Move that to the start of the buffer,
     * and then reallocate the buffer down to size to reduce the memory. */
    if (snmpm->SavedPacket != pptr) {
      pal_mem_move (snmpm->SavedPacket, pptr, snmpm->SavedPacket_len);
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_info (zg, "AgentX: read, end: memmove(%p, %p, %d); realloc(%p, %d)",
                   snmpm->SavedPacket, pptr, snmpm->SavedPacket_len, 
                   snmpm->SavedPacket, snmpm->SavedPacket_len);

      if ((rxbuf = XREALLOC (MTYPE_TMP, snmpm->SavedPacket, snmpm->SavedPacket_len)) == NULL) {
        /* I don't see why this should ever fail, but it's not a big deal. */
        if (IS_SUBAG_DEBUG_PROCESS)
          zlog_info (zg, "AgentX: read, failed to reallocate memory");
      } else {
        if (IS_SUBAG_DEBUG_PROCESS)
          zlog_info (zg, "AgentX: read, okay to reallocate memory, old buffer %p, new %p",
                     snmpm->SavedPacket, rxbuf);
        snmpm->SavedPacket = rxbuf;
        snmpm->SavedPacket_size = snmpm->SavedPacket_len;
      }
    }
  }

  /* Regiser read thread. */
  agentx_event (zg, AGENTX_READ, sock);

  return 0;
}


/* Try to connect to master agent. */
s_int32_t
agentx_connect (struct thread *t)
{
  struct agentx_session *sess;
  struct lib_globals *zg = THREAD_GLOB (t);
  s_int32_t ret;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);
  sess = &snmpm->Agx_session;

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: connect try %d", zg->snmp.fail + 1);

  /* Clear thread poner of myself. */
  zg->snmp.t_connect = NULL;

  /* Make socket.  Try to connect. */
  zg->snmp.sock = agentx_socket (zg);
  if (zg->snmp.sock < 0)
    {
      if (++zg->snmp.fail < AGENTX_MAX_FAILURE)
        {
          agentx_event (zg, AGENTX_CONNECT, 0);
        }
      
      if (IS_SUBAG_DEBUG_PROCESS)
        zlog_warn (zg, "AgentX: sock %d, %s state, fail %d (limit %d), errno: %s", 
                   zg->snmp.sock, Agx_state_str[snmpm->Agx_state], 
                   zg->snmp.fail, AGENTX_MAX_FAILURE,
                   pal_strerror (errno));
      return 0;
    }

  /* Initialize and set a session information (&Agx_session) */
  pal_mem_set (sess, 0 , sizeof (struct agentx_session));
  sess->version = AGENTX_VERSION_1;
  sess->retries = AGENTX_DEFAULT_RETRIES;
  sess->timeout = AGENTX_DEFAULT_TIMEOUT;
  sess->peername = pal_strdup (MTYPE_TMP, AGENTX_SOCKET);
  sess->local_port = 0; /* client */
  sess->remote_port = AGENTX_PORT; /* 705 : master agent */

  /* Send OPEN-PDU. */
  ret = agentx_open_session (zg, sess);
  if (ret < 0)
    {
      zlog_err (zg, "AgentX: failed to send open message: %s",
                 pal_strerror (errno));
      agentx_event (zg, AGENTX_RESTART, 0);
      return -1;
    }

  /* The state of subagent changes to OPENING. */
  snmpm->Agx_state = AGENTX_OPENING;

  /* Everything goes fine. */
  agentx_event (zg, AGENTX_READ, zg->snmp.sock);
  agentx_event (zg, AGENTX_PING, zg->snmp.sock); /* for monitoring */

  /* trap funtion uses this opened session */
  return 0;
}

/* AgentX Ping */
s_int32_t
agentx_ping (struct thread *t)
{
  struct agentx_session *sess;
  pal_sock_handle_t sock;
  s_int32_t ret;
  struct lib_globals *zg;
  struct snmp_master *snmpm;

  zg = THREAD_GLOB (t);
  snmpm = SNMP_MASTER (zg);
  sess = &snmpm->Agx_session;

  /* Clear thread. */
  sock = THREAD_FD (t);
  zg->snmp.t_ping = NULL;

  if (IS_SUBAG_DEBUG_PROCESS && IS_SUBAG_DEBUG_DETAIL)
    zlog_info (zg, "AgentX: ping, %s state, fail %d",
               Agx_state_str[snmpm->Agx_state], zg->snmp.fail);

  if (sess->retries > AGENTX_LIMIT_RETRIES) {
    zlog_warn (zg, "(Warning) AgentX: ping retries's no.(%d) exceeds the limit (%d)", 
               sess->retries, AGENTX_LIMIT_RETRIES);
    agentx_event (zg, AGENTX_RESTART, 0);
    return -1;
  }
  sess->retries++;  /* After received Response-PDU of Ping-PDU, reset it */

  switch (snmpm->Agx_state) {
    case AGENTX_OPENING:
      /* check that subagent received Response-PDU of Open-PDU. */
      zg->snmp.fail++;
      if (IS_SUBAG_DEBUG_PROCESS && IS_SUBAG_DEBUG_DETAIL)
        zlog_info (zg, "AgentX: ping retries's no. (%d) in Opening state", 
                   sess->retries);
      break;

    case AGENTX_REGISTERING:
      /* check that subagent received Response-PDU of Register-PDU. */
      zg->snmp.fail++;
      if (IS_SUBAG_DEBUG_PROCESS && IS_SUBAG_DEBUG_DETAIL)
        zlog_info (zg, "AgentX: ping retries's no. (%d) in Registering state", 
                   sess->retries);
      break;

    case AGENTX_OPERATIONAL:
      zg->snmp.fail = 0;

      /* Send Ping-PDU. */
      ret = agentx_send_ping (zg, sess);
      if (ret < 0) {
        /* Accumulated session's retries */
        agentx_event (zg, AGENTX_PING, sock);
        return -1;
      }
      break;

    case AGENTX_INITIAL:
    default:
      zlog_warn (zg, "AgentX: monitoring session, %s state, connection closed: %d", 
                 Agx_state_str[snmpm->Agx_state], sock);
      agentx_event (zg, AGENTX_RESTART, 0);
      return -1;
  }

  /* Check that SentPing is on and RecvPing is off. *
   * SentPing is off -> check retry-ping limit and send_ping again. */

  /* Regiser ping thread. */
  agentx_event (zg, AGENTX_PING, sock);

  return 0;
};

/* AgentX Restart */
s_int32_t
agentx_restart (struct thread *t)
{
  pal_sock_handle_t restart_flag;
  struct snmp_master *snmpm;

  struct lib_globals *zg;
  zg = THREAD_GLOB (t);
  snmpm = SNMP_MASTER (zg);

  restart_flag = THREAD_FD (t);

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: restart (%s), %s state, sock %d, fail %d",
               (restart_flag) ? "re-connect" : "stop",
               Agx_state_str[snmpm->Agx_state],
               zg->snmp.sock, zg->snmp.fail);

  /* Clear thread. */
  zg->snmp.t_restart = NULL;
  if (zg->snmp.t_read)
    THREAD_OFF (zg->snmp.t_read);
  if (zg->snmp.t_connect)
    THREAD_OFF (zg->snmp.t_connect);
  if (zg->snmp.t_ping)
    THREAD_OFF (zg->snmp.t_ping);

  agentx_restart_session (zg, restart_flag);
  return 0;
}

/* Clear all AGENTX related resources. */
void
agentx_stop (struct lib_globals *zg)
{
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: stop");
  agentx_event (zg, AGENTX_STOP, 0);
}

void
agentx_event (struct lib_globals *zg, enum agentx_event event,
              pal_sock_handle_t sock)
{
  switch (event)
    {
    case AGENTX_SCHEDULE:
      if (zg->snmp.t_connect == NULL)
        zg->snmp.t_connect = thread_add_event (zg, agentx_connect, NULL, 0);
      break;
    case AGENTX_CONNECT:
      /* CONNECT_DELAY : 10 */
      if (zg->snmp.t_connect == NULL)
        zg->snmp.t_connect = thread_add_timer (zg, agentx_connect, NULL, 10);
      break;
    case AGENTX_READ:
      if (zg->snmp.t_read == NULL)
        zg->snmp.t_read = thread_add_read (zg, agentx_read, NULL, sock);
      break;
    case AGENTX_RESTART:
      if (zg->snmp.t_restart == NULL)
        zg->snmp.t_restart = thread_add_event (zg, agentx_restart, NULL, 1);
      break;
    case AGENTX_PING:
      /* PING_INTERVAL : 15 */
      if (zg->snmp.t_ping == NULL)
        zg->snmp.t_ping = thread_add_timer (zg, agentx_ping, NULL,
                                            AGENTX_PING_INTERVAL);
      break;
    case AGENTX_STOP:
      if (zg->snmp.t_restart == NULL)
        zg->snmp.t_restart = thread_add_event (zg, agentx_restart, NULL, 0);
      break;
    default:
      break;
    }
}

/*
 * Trap functions.
 */

s_int32_t
agentx_trap (struct lib_globals *zg,
             oid *trap_oid, size_t trap_oid_len, oid spec_trap_val,
             oid *name, size_t namelen, oid *iname, size_t inamelen,
             struct trap_object *trapobj, size_t trapobjlen, 
             u_int32_t tick)
{
  struct agentx_session *sess;
  struct agentx_variable_list *varbind = NULL;
  oid snmptrap_oid[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
  size_t snmptrap_oid_len = 11;
  s_int32_t i;
  oid t_oid[MAX_OID_LEN];
  size_t t_oid_len;
  void *val1 = NULL;
  size_t val_len = 0;
  u_int8_t val_type = ASN_NULL;
  s_int32_t ret;
  oid ptr[MAX_OID_LEN];  
  oid *trap_oid_ptr;
  struct snmp_master *snmpm;
  u_int32_t vr_id = 0;

  snmpm = SNMP_MASTER (zg);
  sess = &snmpm->Agx_session;

  /*
   RFC 2741, chap. 6.2.10. The agentx-Notify-PDU
   *  n.vb
   *        A VarBindList whose contents define the actual PDU to be
   *        sent.  This memo places the following restrictions on its
   *        contents:
   *           -  If the subagent supplies sysUpTime.0, it must be
   *              present as the first varbind.
   *           -  snmpTrapOID.0 must be present, as the second varbind
   *              if sysUpTime.0 was supplied, as the first if it was
   *              not.
   */

  /*
   RFC 1907, Management Information Base for Version 2 of the 
   *         Simple Network Management Protocol (SNMPv2)
   * .iso(1).org(3).dod(6).internet(1).mgmt(2).mib-2(1).system(1).sysUpTime(3)
   */

  /* Timeticks timestamp (sysUpTime.0). - optional varbind. */
  if (tick) {
    oid sysuptimeoid[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    size_t sysuptimelen = 9;
    u_int32_t tickv = 0; /* ignores tick value */

    (void) agentx_varlist_add_variable (zg, &varbind, sysuptimeoid, sysuptimelen,
                                     ASN_TIMETICKS,
                                     (u_char *) &tickv, sizeof(tickv));
  }

  /*
   RFC 2089, Mapping SNMPv2 onto SNMPv1 within a bi-lingual SNMP agent
   RFC 1907, Management Information Base for SNMPv2
   * .iso(1).org(3).dod(6).internet(1).snmpV2(6).snmpModules(3).-------
   * ----snmpMIB(1).snmpMIBObjects(1).snmpTrap(4).snmpTrapOID(1)
   *                       |              +------.snmpTrapEnterprise(3)
   *                       +---------.snmpTraps(5)
   */

  /* snmpTrapOID.0 - mandatory varbind. */
  if (!trap_oid || !trap_oid_len) {
    zlog_err (zg, "AgentX: trap error, null trap OID or zero length");
    return -1;
  }

  trap_oid_ptr = ptr;
  oid_copy (ptr, trap_oid, trap_oid_len);
  oid_copy (ptr + trap_oid_len, &spec_trap_val, sizeof(spec_trap_val));

  (void) agentx_varlist_add_variable (zg, &varbind, snmptrap_oid, snmptrap_oid_len,
                                   ASN_OBJECT_ID, (u_char *) trap_oid_ptr,
                                   trap_oid_len * sizeof(oid) + sizeof (oid));

  /* Iteration for each objects. */
  for (i = 0; i < trapobjlen; i++)
    {
      /* Make OID.
       * OID : MIB name (subtree) + object ID (variables) + index name */
      oid_copy (t_oid, name, namelen);
      oid_copy (t_oid + namelen, trapobj[i].name, trapobj[i].namelen);
      oid_copy (t_oid + namelen + trapobj[i].namelen, iname, inamelen);
      t_oid_len = namelen + trapobj[i].namelen + inamelen;

      if (IS_SUBAG_DEBUG_PROCESS)
        snmp_oid_dump (zg, "AgentX: Trap", t_oid, t_oid_len);

      ret = agentx_get (zg, t_oid, &t_oid_len, 1, &val_type, &val1, 
                        &val_len, vr_id);
      if (ret != 0) {
        zlog_warn (zg, "(Warning) AgentX: trap_get, result %d", ret);
        return -1;
      }
      (void) agentx_varlist_add_variable (zg, &varbind, t_oid, t_oid_len,
                                       val_type, val1, val_len);
    }

  return agentx_send_notify (zg, sess, varbind);
}

s_int32_t
agentx_trap2 (struct lib_globals *zg,
              oid *trap_oid, size_t trap_oid_len, oid spec_trap_val,
              oid *name, size_t namelen,
              struct trap_object2 *trapobj, size_t trapobjlen,
              u_int32_t tick)
{
  struct agentx_session *sess;
  struct agentx_variable_list *varbind = NULL;
  oid snmptrap_oid[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
  size_t snmptrap_oid_len = 11;
  s_int32_t i;
  oid ptr[MAX_OID_LEN];  
  oid *trap_oid_ptr;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);
  sess = &snmpm->Agx_session;
 
  /*
   RFC 2741, chap. 6.2.10. The agentx-Notify-PDU
   *  n.vb
   *        A VarBindList whose contents define the actual PDU to be
   *        sent.  This memo places the following restrictions on its
   *        contents:
   *           -  If the subagent supplies sysUpTime.0, it must be
   *              present as the first varbind.
   *           -  snmpTrapOID.0 must be present, as the second varbind
   *              if sysUpTime.0 was supplied, as the first if it was
   *              not.
   */

  /* Timeticks timestamp (sysUpTime.0). - optional varbind.
   RFC 1907, Management Information Base for Version 2 of the 
   *         Simple Network Management Protocol (SNMPv2)
   * .iso(1).org(3).dod(6).internet(1).mgmt(2).mib-2(1).system(1).sysUpTime(3)
   */
  if (tick) {
    oid sysUpTimeOid[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    size_t sysUpTimeLen = 9;
    u_int32_t tickv = tick; /* tick value */

    (void) agentx_varlist_add_variable (zg, &varbind, sysUpTimeOid, sysUpTimeLen,
                                     ASN_TIMETICKS,
                                     (u_char *) &tickv, sizeof(tickv));
  }

  /* snmpTrapOID.0 - mandatory varbind.
   RFC 2089, Mapping SNMPv2 onto SNMPv1 within a bi-lingual SNMP agent
   RFC 1907, Management Information Base for SNMPv2
   * .iso(1).org(3).dod(6).internet(1).snmpV2(6).snmpModules(3).-------
   * ----snmpMIB(1).snmpMIBObjects(1).snmpTrap(4).snmpTrapOID(1)
   *                       |              +------.snmpTrapEnterprise(3)
   *                       +---------.snmpTraps(5)
   */
  if (!trap_oid || !trap_oid_len) {
    zlog_err (zg, "AgentX: trap error, null trap OID or zero length");
    agentx_free_varbind (varbind);
    return -1;
  }
 
  trap_oid_ptr = ptr;
  oid_copy (ptr, trap_oid, trap_oid_len);
  oid_copy (ptr + trap_oid_len, &spec_trap_val, sizeof(spec_trap_val));
  (void) agentx_varlist_add_variable (zg, &varbind, snmptrap_oid, snmptrap_oid_len,
                                   ASN_OBJECT_ID, (u_char *) trap_oid_ptr,
                                   trap_oid_len * sizeof(oid) + sizeof(oid));
  /* Iteration for each objects. */
  for (i = 0; i < trapobjlen; i++)
    {
      /* Make OID.
       * OID : already made it as MIB name + object ID + index name */

      if (IS_SUBAG_DEBUG_PROCESS)
        snmp_oid_dump (zg, "AgentX: Trap2",
                           trapobj[i].name, trapobj[i].namelen);

      (void) agentx_varlist_add_variable (zg, &varbind,
                                       trapobj[i].name, trapobj[i].namelen,
                                       trapobj[i].val_type, trapobj[i].val,
                                       trapobj[i].val_len);
    }

  return agentx_send_notify (zg, sess, varbind);
}


/* Register subtree to subagent master tree. */
void
agentx_register_mib (struct lib_globals *zg,
                     char *descr, struct variable *var, size_t width,
                     s_int32_t num, oid name[], size_t namelen,
                     s_int32_t range_subid, s_int32_t range_ubound,
                     s_int32_t timeout, u_int8_t priority, u_int8_t flags)
{
  struct agentx_session *sess;
  struct subtree *tree;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);
  sess = &snmpm->Agx_session;

  tree = XMALLOC (MTYPE_SNMP_SUBTREE, sizeof(struct subtree));
  oid_copy (tree->name, name, namelen);
  tree->name_len = namelen;
  tree->variables = var;
  tree->variables_num = num;
  tree->variables_width = width;
  tree->registered = 0;

  /* Objects related to AgentX */
  tree->start_a = NULL;
  tree->start_len = 0;
  tree->end_a = NULL;
  tree->end_len = 0;
  tree->session = sess;
  tree->flags = flags;
  if (priority)
    tree->priority = priority;
  else 
    tree->priority = AGENTX_REGISTER_DEF_PRIORITY;
  if (timeout)
    tree->timeout = timeout;
  else
    tree->timeout = AGENTX_REGISTER_DEF_TIMEOUT;
  tree->range_subid = range_subid;
  tree->range_ubound = range_ubound;

  listnode_add_sort (zg->snmp.treelist, tree);
}

/* Unregister subtree to subagent master tree. */
void
agentx_unregister_mib (struct lib_globals *zg,
                       oid name[], size_t namelen)
{
  struct agentx_session *sess;
  struct subtree *tree = NULL;
  struct listnode *node;
  u_int32_t find = 0;
  s_int32_t result;
  struct snmp_master *snmpm;

  snmpm = SNMP_MASTER (zg);
  sess = &snmpm->Agx_session;

  for (node = zg->snmp.treelist->head; node; node = node->next)
    {
      tree = node->data;
      if (tree) {
        result = oid_compare_part (name, namelen, 
                                   tree->name, tree->name_len);

        /* Subtree is same the registered subtree. */
        if (result == 0) {
          find = 1;
          break;
        }
      }
    }

  if (find && tree) {
    result = agentx_send_unregister (zg, sess,
                                     tree->name, tree->name_len,
                                     tree->priority,
                                     tree->range_subid, tree->range_ubound);
    listnode_delete (zg->snmp.treelist, tree);
    AGENTX_FREE (tree);
  }
}

#endif  /* HAVE_AGENTX */
#endif  /* HAVE_SNMP */
