/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#ifdef HAVE_SNMP
#ifndef HAVE_AGENTX

#include "snmp.h"
#include "smux.h"
#include "thread.h"
#include "log.h"
#include "snprintf.h"
#include "linklist.h"
#include "bgpsdn_version.h"
#include "sockunion.h"
#include "asn1.h"
#include "errno.h"


/* Set Object ID and value.

   Parameters
     IN     u_char *data          Pointer to the output buffer.
     IN     oid    *var_name      Object id of variable.
     IN     int    *var_name_len  Length of object id.
     IN     u_char  var_val_type  Type of variable.
     IN     int     var_val_len   Length of variable.
     IN     u_char *var_val       Value of variable.
     IN/OUT int    *datalen       Number of valid bytes left in output buffer.

   Results
*/
u_char *
smux_build_var_op (u_char *data, oid *var_name, size_t *var_name_len,
                   u_char var_val_type, size_t var_val_len,
                   u_char *var_val, size_t *datalen)
{
  u_char *ptr = data;
  size_t len;
  size_t hlen;

  if (*datalen < 4)
    return NULL;

  /* Proceed pointer to set sequence later. */
  ptr += 4;

  hlen = (ptr - data);
  *datalen -= hlen;

  ptr =
    asn1_set_object_id (ptr, datalen,
                        (u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OBJECT_ID),
                        var_name, *var_name_len);
  if (ptr == NULL)
    return NULL;

  switch (var_val_type)
    {
    case ASN_INTEGER:
      ptr = asn1_set_int (ptr, datalen, var_val_type,
                          (long *)var_val, var_val_len);
      break;
    case ASN_GAUGE:
    case ASN_COUNTER:
    case ASN_TIMETICKS:
    case ASN_UINTEGER:
      ptr = asn1_set_unsigned_int (ptr, datalen, var_val_type,
                                   (unsigned long *)var_val, var_val_len);
      break;
    case ASN_COUNTER64:
      ptr = asn1_set_unsigned_int64 (ptr, datalen, var_val_type,
                                     (struct counter64 *)var_val,
                                     var_val_len);
      break;
    case ASN_OCTET_STR:
    case ASN_IPADDRESS:
    case ASN_OPAQUE:
    case ASN_NSAP:
      ptr = asn1_set_string (ptr, datalen, var_val_type,
                             var_val, var_val_len);
      break;
    case ASN_OBJECT_ID:
      ptr = asn1_set_object_id (ptr, datalen, var_val_type,
                                (oid *)var_val, var_val_len / sizeof (oid));
      break;
    case ASN_NULL:
      ptr = asn1_set_null (ptr, datalen, var_val_type);
      break;
    case ASN_BIT_STR:
      ptr = asn1_set_bitstring (ptr, datalen, var_val_type,
                                var_val, var_val_len);
      break;
    case SNMP_NOSUCHOBJECT:
    case SNMP_NOSUCHINSTANCE:
    case SNMP_ENDOFMIBVIEW:
      ptr = asn1_set_null (ptr, datalen, var_val_type);
      break;
    default:
      return NULL;
    }

  if (ptr == NULL)
    return NULL;

  len = (ptr - data) - hlen;

  asn1_set_sequence (data, &len, (u_char)(ASN_SEQUENCE|ASN_CONSTRUCTOR), len);

  return ptr;
}

/* Get Object ID and value.

   Parameters
     IN         u_char *data            Pointer to the start of object.
     OUT        oid    *var_name        Object id of variable.
     IN/OUT     int    *var_name_len    Length of variable name.
     OUT        u_char *var_val_type    Type of variable.
     OUT        int    *var_val_len     Length of variable.
     OUT        u_char**var_val         Pointer to ASN1 encoded
                                        value of variable.
     IN/OUT     int    *datalen         Number of valid bytes left
                                        in var_op_list. */

u_char *
smux_parse_var_op (u_char *data, oid *var_name, size_t *var_name_len,
                   u_char *var_val_type, size_t *var_val_len,
                   u_char **var_val, size_t *datalen)
{
  u_char var_op_type;
  size_t var_op_len = *datalen;
  u_char *var_op_start = data;

  data = asn1_get_header (data, &var_op_len, &var_op_type);
  if (data == NULL)
    return NULL;

  if (var_op_type != (ASN_SEQUENCE | ASN_CONSTRUCTOR))
    return NULL;

  data = asn1_get_object_id (data, &var_op_len, &var_op_type,
                             var_name, var_name_len);
  if (data == NULL)
    return NULL;

  if (var_op_type != (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID))
    return NULL;
  *var_val = data;

  data = asn1_get_header (data, &var_op_len, var_val_type);
  if (data == NULL)
    return NULL;

  *var_val_len = var_op_len;
  data += var_op_len;
  *datalen -= (int)(data - var_op_start);

  return data;
}


pal_sock_handle_t
smux_socket_ipv4 (struct lib_globals *zg)
{
  struct pal_sockaddr_in4 serv;
  struct pal_servent *sp;
  pal_sock_handle_t sock = -1;
  s_int32_t ret;

  sock = pal_sock (zg, AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      zlog_warn (zg, "Can't make socket for SNMP");
      return -1;
    }

  pal_mem_set (&serv, 0, sizeof (struct pal_sockaddr_in4));
  serv.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
  serv.sin_len = sizeof (struct pal_sockaddr_in4);
#endif /* HAVE_SIN_LEN */

  sp = pal_getservbyname ("smux", "tcp");
  if (sp != NULL) 
    serv.sin_port = sp->s_port;
  else
    serv.sin_port = pal_hton16 (SMUX_PORT_DEFAULT);

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

  return sock;
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
smux_socket_hybrid (struct lib_globals *zg)
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
  ret = pal_sock_getaddrinfo (NULL, "smux", &hints, &ai_res);
  if (ret == EAI_SERVICE)
    {
      zsnprintf (servbuf, sizeof servbuf, "%d", SMUX_PORT_DEFAULT);
      ret = pal_sock_getaddrinfo (NULL, servbuf, &hints, &ai_res);
    }

  if (ret != 0)
    {
      zlog_warn (zg, "Cannot locate loopback service smux");
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
                          for IPV6 , it blocks the calling function(for 6min40sec)
                          and returns ETIMEDOUT error.This is why the hang happens.
                       
             RESOLUTION : When the sock_connect() fails with the error ETIMEDOUT.
                          Do not try to connect for the next MAX_WAIT_TIME times.
                          Since each attempt will block the call.
             ---------------------------------------------------------------------
            NOTE        : The localhost ::1 ipv6 connection timeout, leading to
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
 
            if (IS_SUBAG_DEBUG)
            zlog_info(zg, " addr family = %d, addr = %s\n",
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
                       if (IS_SUBAG_DEBUG)
                       zlog_info(zg, "addr family = %d, error return = %s\n", 
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
smux_socket (struct lib_globals *zg)
{
#ifdef HAVE_IPV6
  return smux_socket_hybrid (zg);
#else /* HAVE_IPV6 */
  return smux_socket_ipv4 (zg);
#endif /* HAVE_IPV6 */
}

void
smux_getresp_send (struct lib_globals *zg, long reqid, long errstat,
                   long errindex, struct list *varlist)
{
  u_int8_t buf[BUFSIZ];
  u_int8_t *ptr, *h1, *h1e, *h2, *h2e;
  size_t len, length;
  struct listnode *node;
  struct trap_object2 *varbind;

  ptr = buf;
  len = BUFSIZ;
  length = len;

  if (IS_SUBAG_DEBUG)
    {
      zlog_info (zg, "SMUX GETRSP send");
      zlog_info (zg, "SMUX GETRSP reqid: %d", reqid);
    }

  h1 = ptr;
  /* Place holder h1 for complete sequence */
  ptr = asn_build_sequence (ptr, &len, (u_int8_t) SMUX_GETRSP, 0);
  h1e = ptr;
 
  ptr = asn_build_int (ptr, &len,
                       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                       &reqid, sizeof (reqid));

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX GETRSP errstat: %d", errstat);

  ptr = asn_build_int (ptr, &len,
                       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                       &errstat, sizeof (errstat));
  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX GETRSP errindex: %d", errindex);

  ptr = asn_build_int (ptr, &len,
                       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                       &errindex, sizeof (errindex));

  h2 = ptr;
  /* Place holder h2 for one variable */
  ptr = asn_build_sequence (ptr, &len, 
                            (u_int8_t)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                            0);
  h2e = ptr;

  LIST_LOOP (varlist, varbind, node)
    {
      ptr = smux_build_var_op (ptr, varbind->name, &varbind->namelen, 
                           varbind->val_type, varbind->val_len, 
                           (u_char *)varbind->val, &len);
    }
  /* Now variable size is known, fill in size */
  asn_build_sequence (h2, &length,
                      (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), ptr - h2e);

  /* Fill in size of whole sequence */
  asn_build_sequence (h1, &length, (u_char)SMUX_GETRSP, ptr - h1e);

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX getresp send: %d", ptr - buf);
  
  (void) pal_sock_send (zg->snmp.sock, buf, (ptr - buf), 0);
}

char *
smux_var (struct lib_globals *zg, char *ptr, size_t *len, oid objid[],
          size_t *objid_len, size_t *var_val_len, u_int8_t *var_val_type,
          void **var_value)
{
  u_int8_t val_type;
  size_t val_len;
  u_int8_t *val;

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX var parse: len %d", *len);

  /* Parse var option. */
  *objid_len = MAX_OID_LEN;
  ptr = smux_parse_var_op(ptr, objid, objid_len, &val_type, 
                          &val_len, &val, len);
  if (ptr == NULL)
    return NULL;

  if (var_val_len)
    *var_val_len = val_len;

  if (var_value)
    *var_value = (void*) val;

  if (var_val_type)
    *var_val_type = val_type;

  /* Requested object id length is objid_len. */
  if (IS_SUBAG_DEBUG)
    snmp_oid_dump (zg, "Request OID", objid, *objid_len);

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX val_type: %d", val_type);

  /* Wrong Length is returned in SNMP in the write_method even before
     the corresponding SET API is called. This error is obtained because
     the length that SMUX returns is the actual number of bytes occupied
     by the value, whereas the check in SNMP for length is against the
     maximum, that is, sizeof (long).  This error will be got only for
     entries that are newly created via SNMP, since, for existing entries,
     the length that SMUX returns is overwritten with sizeof (long) in
     the RETURN macro present in the GET callback. Hence, even before
     the write_method is called, the length is overwritten with
     sizeof (long) for all integers.  */

  switch (val_type)
    {
    case ASN_INTEGER:
      *var_val_len = sizeof (long);
      break;
    default:
      break;
    }

  /* Check request value type. */
  if (IS_SUBAG_DEBUG)
  switch (val_type)
    {
    case ASN_NULL:
      /* In case of SMUX_GET or SMUX_GET_NEXT val_type is set to
         ASN_NULL. */
      zlog_info (zg, "ASN_NULL");
      break;

    case ASN_INTEGER:
      zlog_info (zg, "ASN_INTEGER");
      break;
    case ASN_COUNTER:
    case ASN_GAUGE:
    case ASN_TIMETICKS:
    case ASN_UINTEGER:
      zlog_info (zg, "ASN_COUNTER");
      break;
    case ASN_COUNTER64:
      zlog_info (zg, "ASN_COUNTER64");
      break;
    case ASN_IPADDRESS:
      zlog_info (zg, "ASN_IPADDRESS");
      break;
    case ASN_OCTET_STR:
      zlog_info (zg, "ASN_OCTET_STR");
      break;
    case ASN_OPAQUE:
    case ASN_NSAP:
    case ASN_OBJECT_ID:
      zlog_info (zg, "ASN_OPAQUE");
      break;
    case SNMP_NOSUCHOBJECT:
      zlog_info (zg, "SNMP_NOSUCHOBJECT");
      break;
    case SNMP_NOSUCHINSTANCE:
      zlog_info (zg, "SNMP_NOSUCHINSTANCE");
      break;
    case SNMP_ENDOFMIBVIEW:
      zlog_info (zg, "SNMP_ENDOFMIBVIEW");
      break;
    case ASN_BIT_STR:
      zlog_info (zg, "ASN_BIT_STR");
      break;
    default:
      zlog_info (zg, "Unknown type");
      break;
    }
  return ptr;
}

int
smux_parse_val (u_char *var_val, u_char *var_val_type, size_t *var_val_len)
{

  long intval;
  struct pal_in4_addr inaddrval;
  size_t bigsize = SNMP_MAX_LEN;
  u_char *val_string = NULL;

  switch (*var_val_type)
    {
    case ASN_INTEGER:
      asn_parse_int (var_val, &bigsize, var_val_type, &intval, sizeof(long));
      pal_mem_cpy (var_val, &intval,4);
      break;

    case ASN_IPADDRESS:
      pal_mem_cpy (&inaddrval.s_addr, var_val + 2, 4);
      pal_mem_cpy (var_val,&inaddrval.s_addr,4);
      break;

    case ASN_OCTET_STR:
      val_string = asn_parse_char (var_val, &bigsize, var_val_type,
                                   var_val_len,255);
      if (val_string) 
        {
          pal_mem_cpy (var_val, val_string,*var_val_len);      
          var_val[*var_val_len] ='\0';
        }
      break;

    default:
      break;
    }
  return 0;
}

/* NOTE: all 3 functions (smux_set, smux_get & smux_getnext) are based on
   ucd-snmp smux and as such suppose, that the peer receives in the message
   only one variable. Fortunately, IBM seems to do the same in AIX. */

s_int32_t
smux_set (struct lib_globals *zg, oid *reqid, size_t *reqid_len,
          u_int8_t val_type, void *val, size_t val_len, s_int32_t action)
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
  u_int32_t vr_id = 0;
  bool_t match_found;

  match_found = PAL_FALSE;

  /* Check */
  for (node = zg->snmp.treelist->head; node; node = node->next)
    {
      subtree = node->data;
      subresult = oid_compare_part (reqid, *reqid_len,
                                    subtree->name, subtree->name_len);

      /* Subtree matched. */
      if (subresult == 0)
        {
          /* Prepare suffix. */
          suffix = reqid + subtree->name_len;
          suffix_len = *reqid_len - subtree->name_len;
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
                  if (IS_SUBAG_DEBUG)
                    zlog_info (zg, "SMUX function call index is %d", v->magic);

                  statP = (*v->findVar) (v, suffix, &suffix_len, 1,
                                         &val_len, &write_method, vr_id);

                  if (write_method)
                    {
                      smux_parse_val (val, &val_type, &val_len);
                      return (*write_method)(action, val, val_type, val_len,
                                             statP, suffix, suffix_len, v, 
                                             vr_id);
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
                return SNMP_ERR_NOSUCHNAME;
            }
        }
    }
  if (match_found)
    return SNMP_ERR_NOACCESS;

  return SNMP_ERR_NOSUCHNAME;
}

s_int32_t
smux_get (struct lib_globals *zg, oid *reqid, size_t *reqid_len,
          s_int32_t exact, u_int8_t *val_type,void **val, size_t *val_len)
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
  u_int32_t vr_id = 0;
  bool_t match_found;

  match_found = PAL_FALSE;


  /* Check */
  for (node = zg->snmp.treelist->head; node; node = node->next)
    {
      subtree = node->data;
      subresult = oid_compare_part (reqid, *reqid_len, 
                                    subtree->name, subtree->name_len);

      /* Subtree matched. */
      if (subresult == 0)
        {
          /* Prepare suffix. */
          suffix = reqid + subtree->name_len;
          suffix_len = *reqid_len - subtree->name_len;
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
                  if (IS_SUBAG_DEBUG)
                    zlog_info (zg, "SMUX function call index is %d", v->magic);

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
                  return SNMP_ERR_NOSUCHNAME;
            }
        }
    }
  if (match_found)
    return SNMP_NOSUCHINSTANCE;

  return SNMP_NOSUCHOBJECT;
}

s_int32_t
smux_getnext (struct lib_globals *zg, oid *reqid, size_t *reqid_len,
              s_int32_t exact, u_int8_t *val_type,void **val, size_t *val_len)
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
  u_int32_t vr_id = 0;

  retoidlen = 0;

  /* Save incoming request. */
  oid_copy (save, reqid, *reqid_len);
  savelen = *reqid_len;

  /* Check */
  for (node = zg->snmp.treelist->head; node; node = node->next)
    {
      subtree = node->data;
      subresult = oid_compare_part (reqid, *reqid_len,
                                    subtree->name, subtree->name_len);

      /* If request is in the tree. The agent has to make sure we
         only receive requests we have registered for. */
      /* Unfortunately, that's not true. In fact, a SMUX subagent has to
         behave as if it manages the whole SNMP MIB tree itself. It's the
         duty of the master agent to collect the best answer and return it
         to the manager. See RFC 1227 chapter 3.1.6 for the glory details
         :-). ucd-snmp really behaves bad here as it actually might ask
         multiple times for the same GETNEXT request as it throws away the
         answer when it expects it in a different subtree and might come
         back later with the very same request. --jochen */

      if (subresult <= 0)
        {
          /* Prepare suffix. */
          suffix = reqid + subtree->name_len;
          suffix_len = *reqid_len - subtree->name_len;
          if (subresult < 0)
            {
              oid_copy(reqid, subtree->name, subtree->name_len);
              *reqid_len = subtree->name_len;
            }
          for (j = 0; j < subtree->variables_num; j++)
            {
              result = subresult;
              v = &subtree->variables[j];

              /* Next then check result >= 0. */
              if (result == 0)
                result = oid_compare_part (suffix, suffix_len,
                                           v->name, v->namelen);

              if (result <= 0)
                {
                  if (IS_SUBAG_DEBUG)
                    zlog_info (zg, "SMUX function call index is %d", v->magic);
                  if(result < 0)
                    {
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
                      oid_copy (reqid, retoid, retoidlen);
                      *reqid_len = retoidlen;
                      return 0;
                    }

                  *val = (*v->findVar) (v, suffix, &suffix_len, exact,
                                        val_len, &write_method, vr_id);
                  *reqid_len = suffix_len + subtree->name_len;

                 /* Multiple Registrations for the same OID */
                  if (*val)
                    {
                      if (! retval)
                        {
                          oid_copy (retoid, reqid, *reqid_len);
                          retoidlen = *reqid_len;
                          retval = *val;
                          *val_type = v->type;
                          retval_type = val_type;
                          retval_len = *val_len;
                          oid_copy (reqid, save, savelen);
                          *reqid_len = savelen;
                          break;
                        }
                      else
                        {
                         if (result < 0)
                           break;
                          resultval =  oid_compare (reqid, *reqid_len, retoid,
                                                    retoidlen);
                          if (resultval < 0)
                            {
                              oid_copy (retoid, reqid, *reqid_len);
                              retoidlen = *reqid_len;
                              retval = *val;
                              *val_type = v->type;
                              retval_type = val_type;
                              retval_len = *val_len;
                              oid_copy (reqid, save, savelen);
                              *reqid_len = savelen;
                            }
                        }
                    }
               }
            }
         }
      oid_copy (reqid, save, *reqid_len);
      *reqid_len = savelen;
    }

  if (retval)
    {
      *val = retval;
      val_type = retval_type;
      *val_len = retval_len;
      oid_copy (reqid, retoid, retoidlen);
      *reqid_len = retoidlen;
      return 0;
    }

  oid_copy (reqid, save, savelen);
  *reqid_len = savelen;

  return SNMP_ERR_NOSUCHNAME;
}

/* GET message header. */
char *
smux_parse_get_header (struct lib_globals *zg, char *ptr, size_t *len,
                       long *reqid)
{
  u_int8_t type;
  long errstat;
  long errindex;

  /* Request ID. */
  ptr = asn_parse_int (ptr, len, &type, reqid, sizeof (*reqid));

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX GET reqid: %d len: %d", (s_int32_t) *reqid,
               (s_int32_t) *len);

  /* Error status. */
  ptr = asn_parse_int (ptr, len, &type, &errstat, sizeof (errstat));

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX GET errstat %d len: %d", errstat, *len);

  /* Error index. */
  ptr = asn_parse_int (ptr, len, &type, &errindex, sizeof (errindex));

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX GET errindex %d len: %d", errindex, *len);

  return ptr;
}

s_int32_t
smux_varbind_del (void *val)
{
  struct trap_object2 *var = (struct trap_object2 *)val;
  if (var == NULL)
    return 0;

  if (var->val != NULL)
    {
      XFREE (MTYPE_TMP, (u_char *)var->val);
      var->val = NULL;
    }
  XFREE (MTYPE_TMP, var);
  var = NULL;

  return 0;
}

s_int32_t
smux_parse_set (struct lib_globals *zg, char *ptr,
                size_t len, s_int32_t action)
{
  long reqid;
  oid oid[MAX_OID_LEN];
  size_t oid_len;
  u_int8_t type;
  u_int8_t val_type;
  void *val;
  size_t val_len;
  struct list *varlist;
  struct trap_object2 *varbind;
  s_int32_t ret;

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX SET(%s) message parse: len %d",
               (RESERVE1 == action) ? "RESERVE1" 
               : ((FREE_DEL == action) ? "FREE" : "COMMIT"),
               len);

  /* Parse SET message header. */
  ptr = smux_parse_get_header (zg, ptr, &len, &reqid);

  /* Parse smux variable binding header. */
  ptr = asn_parse_header (ptr, &len, &type);
  
  if (IS_SUBAG_DEBUG)
    {
      zlog_info (zg, "SMUX var parse: type %d len %d", type, len);
      zlog_info (zg, "SMUX var parse: type must be %d", 
                 (ASN_SEQUENCE | ASN_CONSTRUCTOR));
    }

  /* Parse SET message object ID. */
  ptr = smux_var (zg, ptr, &len, oid, &oid_len, &val_len, &val_type, &val);
  if (ptr == NULL)
    return -1;

  ret = smux_set (zg, oid, &oid_len, val_type, val, val_len, action);
  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX SET ret %d", ret);

  /* Return result. */
  if (RESERVE1 == action)
    {
      varlist = list_new();
      varlist->del = smux_varbind_del;
      varbind = XMALLOC (MTYPE_TMP, sizeof (struct trap_object2));
      oid_copy (varbind->name, oid, oid_len);
      varbind->namelen = oid_len;
      varbind->val_type = ASN_NULL;
      varbind->val_len = 0;
      varbind->val = NULL;
      listnode_add(varlist, varbind);
      smux_getresp_send (zg, reqid, ret, 3, varlist);
      list_delete (varlist);
    }

    return 0;
}

void
smux_parse_get (struct lib_globals *zg, char *ptr, size_t len,
                s_int32_t exact)
{
  long reqid;
  u_int8_t type;
  u_int8_t index = 0;
  u_int8_t errindex = 0;
  u_int8_t val_type;
  void *val;
  size_t val_len;
  struct list *varlist;
  struct trap_object2 *varbind;
  s_int32_t ret;

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX GET message parse: len %d", len);
  
  /* Parse GET message header. */
  ptr = smux_parse_get_header (zg, ptr, &len, &reqid);
  
  /* Parse smux variable binding header. */
  ptr = asn_parse_header (ptr, &len, &type);
  
  if (IS_SUBAG_DEBUG)
    {
      zlog_info (zg, "SMUX var parse: type %d len %d", type, len);
      zlog_info (zg, "SMUX var parse: type must be %d", 
                 (ASN_SEQUENCE | ASN_CONSTRUCTOR));
    }

  /* Parse GET message object ID. There may have multiple object ID */
  varlist = list_new();
  varlist->del = smux_varbind_del;

  /* Initialize the return value as wrongLength. */
  ret = SNMP_ERR_WRONGLENGTH;

  while (len > 0)
    {
      index++;
      varbind = XMALLOC (MTYPE_TMP, sizeof (struct trap_object2));
      ptr = smux_var (zg, ptr, &len, varbind->name, &varbind->namelen, NULL, NULL, NULL);

      /* Traditional getstatptr. */
      if (exact)
        ret = smux_get (zg, varbind->name, &varbind->namelen, exact, &val_type, &val, &val_len);
      else
        ret = smux_getnext (zg, varbind->name, &varbind->namelen, exact, &val_type, &val, &val_len);
      if (ret != 0)
        {
          varbind->val_type = ASN_NULL;
          varbind->val = NULL;
          varbind->val_len = 0;
          errindex = index;
          list_delete_all_node (varlist);
          listnode_add (varlist, varbind);
          break;
        }         
      else
        {
          /* save the variable bindings separately */
          varbind->val_type = val_type;
          varbind->val_len = val_len;
          if (val_len == 0)
            varbind->val = NULL;
          else
            {
              varbind->val = XMALLOC (MTYPE_TMP, val_len);
              pal_mem_cpy (varbind->val, val, val_len);
            }
          listnode_add (varlist, varbind);
        }
    }

  /* Return result. */
  /* we shall return ASN_NULL only when one variable binding get 
   * failure, we shall not return combination of result */
  smux_getresp_send (zg, reqid, ret, errindex, varlist);
  list_delete(varlist);
}

/* Parse SMUX_CLOSE message. */
void
smux_parse_close (struct lib_globals *zg, char *ptr, s_int32_t len)
{
  long reason = 0;

  while (len--)
    {
      reason = (reason << 8) | (long) *ptr;
      ptr++;
    }
  zlog_info (zg, "SMUX_CLOSE with reason: %d", reason);
}

/* SMUX_RRSP message. */
void
smux_parse_rrsp (struct lib_globals *zg, char *ptr, size_t len)
{
  char val;
  long errstat;
  
  ptr = asn_parse_int (ptr, &len, &val, &errstat, sizeof (errstat));

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX_RRSP value: %d errstat: %d", val, errstat);
}

/* Parse SMUX message. */
s_int32_t
smux_parse (struct lib_globals *zg, char *ptr, size_t len)
{
  s_int32_t len_income = len; /* see note below: YYY */
  u_int8_t type;
  u_int8_t rollback;
  s_int32_t ret = 0;

  rollback = ptr[2]; /* important only for SMUX_SOUT */

process_rest: /* see note below: YYY */

  /* Parse SMUX message type and subsequent length. */
  ptr = asn_parse_header (ptr, &len, &type);
  if (ptr == NULL)
    return -1;

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX message received type: %d rest len: %d", type, len);

  switch (type)
    {
    case SMUX_OPEN:
      /* Open must not be sent from SNMP agent. */
      zlog_warn (zg, "SMUX_OPEN received: resetting connection.");
      return -1;
      break;
    case SMUX_RREQ:
      /* SMUX_RREQ message is invalid for us. */
      zlog_warn (zg, "SMUX_RREQ received: resetting connection.");
      return -1;
      break;
    case SMUX_SOUT:
      /* SMUX_SOUT message is now valid for us. */
      if (IS_SUBAG_DEBUG)
        zlog_info (zg, "SMUX_SOUT(%s)", rollback ? "rollback" : "commit");

      if (zg->snmp.sout_save_len > 0)
        {
          ret = smux_parse_set (zg, zg->snmp.sout_save_buff, zg->snmp.sout_save_len,
                          rollback ? FREE_DEL : COMMIT);
          if (ret < 0)
            {
              zlog_err(zg, "SMUX_SOUT smux_parse_set: Error returning !");
              return ret;
            }

          zg->snmp.sout_save_len = 0;
        }
      else
        zlog_warn (zg, "SMUX_SOUT sout_save_len=%d - invalid",
                   (s_int32_t) zg->snmp.sout_save_len);

      if (len_income > 3) 
        {
          /* YYY: this strange code has to solve the "slow peer"
             problem: When agent sends SMUX_SOUT message it doesn't
             wait for any response and may send some next message to
             subagent. Then the peer in 'smux_read()' will receive
             from socket the 'concatenated' buffer, contaning both
             SMUX_SOUT message and the next one
             (SMUX_GET/SMUX_GETNEXT/SMUX_GET). So we should check: if
             the buffer is longer than 3 ( length of SMUX_SOUT ), we
             must process the rest of it.  This effect may be observed
             if 'zg->snmp.debug' is set to '1' */
          ptr++;
          len = len_income - 3;
          goto process_rest;
        }
      break;
    case SMUX_GETRSP:
      /* SMUX_GETRSP message is invalid for us. */
      zlog_warn (zg, "SMUX_GETRSP received: resetting connection.");
      return -1;
      break;
    case SMUX_CLOSE:
      /* Close SMUX connection. */
      if (IS_SUBAG_DEBUG)
        zlog_info (zg, "SMUX_CLOSE");
      smux_parse_close (zg, ptr, len);
      return -1;
      break;
    case SMUX_RRSP:
      /* This is response for register message. */
      if (IS_SUBAG_DEBUG)
        zlog_info (zg, "SMUX_RRSP");
      smux_parse_rrsp (zg, ptr, len);
      break;
    case SMUX_GET:
      /* Exact request for object id. */
      if (IS_SUBAG_DEBUG)
        zlog_info (zg, "SMUX_GET");
      smux_parse_get (zg, ptr, len, 1);
      break;
    case SMUX_GETNEXT:
      /* Next request for object id. */
      if (IS_SUBAG_DEBUG)
        zlog_info (zg, "SMUX_GETNEXT");
      smux_parse_get (zg, ptr, len, 0);
      break;
    case SMUX_SET:
      /* SMUX_SET is supported with some limitations. */
      if (IS_SUBAG_DEBUG)
        zlog_info (zg, "SMUX_SET");

      /* save the data for future SMUX_SOUT */
      pal_mem_cpy (zg->snmp.sout_save_buff, ptr, len);
      zg->snmp.sout_save_len = len;
      ret = smux_parse_set (zg, ptr, len, RESERVE1);
      if (ret < 0)
        {
          zlog_err(zg, "SMUX_SOUT smux_parse_set: Error returning !");
          return ret;
        }
      break;
    default:
      zlog_info (zg, "Unknown type: %d", type);
      break;
    }
  return ret;
}

/* SMUX message read function. */
s_int32_t
smux_read (struct thread *t)
{
  pal_sock_handle_t sock;
  s_int32_t len;
  u_int8_t buf[SMUXMAXPKTSIZE];
  s_int32_t ret;

  struct lib_globals *zg;
  zg = THREAD_GLOB (t);

  /* Clear thread. */
  sock = THREAD_FD (t);
  zg->snmp.t_read = NULL;

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX read start");

  /* Read message from SMUX socket. */
  len = pal_sock_recv (sock, buf, SMUXMAXPKTSIZE, 0);

  if (len < 0)
    {
      zlog_warn (zg, "Can't read all SMUX packet: %s", pal_strerror (errno));
      pal_sock_close (zg, sock);
      zg->snmp.sock = -1;
      smux_event (zg, SMUX_CONNECT, 0);
      return -1;
    }

  if (len == 0)
    {
      zlog_warn (zg, "SMUX connection closed: %d", sock);
      pal_sock_close (zg, sock);
      zg->snmp.sock = -1;
      smux_event (zg, SMUX_CONNECT, 0);

      return -1;
    }

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX read len: %d", len);

  /* Parse the message. */
  ret = smux_parse (zg, buf, len);

  if (ret < 0)
    {
      pal_sock_close (zg, sock);
      zg->snmp.sock = -1;
      smux_event (zg, SMUX_CONNECT, 0);

      return -1;
    }

  /* Regiser read thread. */
  smux_event (zg, SMUX_READ, sock);


  return 0;
}

s_int32_t
smux_open (struct lib_globals *zg, pal_sock_handle_t sock)
{
  u_int8_t buf[BUFSIZ];
  u_int8_t *ptr;
  size_t len;
  unsigned long version;

  if (IS_SUBAG_DEBUG)
    {
      snmp_oid_dump (zg, "SMUX open oid", zg->snmp.oid, zg->snmp.oid_len);
      zlog_info (zg, "SMUX open progname: %s", snmp_progname);
      zlog_info (zg, "SMUX open password: %s", zg->snmp.passwd);
    }

  ptr = buf;
  len = BUFSIZ;

  /* SMUX Header.  As placeholder. */
  ptr = asn_build_header (ptr, &len, (u_int8_t) SMUX_OPEN, 0);

  /* SMUX Open. */
  version = 0;
  ptr = asn_build_int (ptr, &len, 
                       (u_int8_t)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                       &version, sizeof (unsigned long));

  /* SMUX connection oid. */
  ptr = asn_build_objid (ptr, &len,
                         (u_int8_t) 
                         (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
                         zg->snmp.oid, zg->snmp.oid_len);

  /* SMUX connection description. */
  ptr = asn_build_string (ptr, &len, 
                          (u_int8_t)
                          (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
                          snmp_progname, pal_strlen (snmp_progname));

  /* SMUX connection password. */
  ptr = asn_build_string (ptr, &len, 
                          (u_int8_t)
                          (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
                          zg->snmp.passwd, pal_strlen (zg->snmp.passwd));

  /* Fill in real SMUX header.  We exclude ASN header size (2). */
  len = BUFSIZ;
  asn_build_header (buf, &len, (u_int8_t) SMUX_OPEN, (ptr - buf) - 2);

  return pal_sock_send (sock, buf, (ptr - buf), 0);
}

s_int32_t
smux_trap (struct lib_globals *zg,
           oid *trap_oid, size_t trap_oid_len,  
           oid spec_trap_val,
           oid *name, size_t namelen,
           oid *iname, size_t inamelen,
           struct trap_object *trapobj, size_t trapobjlen,
           u_int32_t tick)
{
  s_int32_t i;
  u_int8_t buf[BUFSIZ];
  u_int8_t *ptr;
  size_t len, length;
  struct pal_in4_addr addr;
  unsigned long val;
  u_int8_t *h1, *h1e;
  s_int32_t ret;
  oid oid[MAX_OID_LEN];
  size_t oid_len;
  void *val1;
  size_t val_len;
  size_t packet_len;
  u_int8_t val_type;

  ptr = buf;
  len = BUFSIZ;
  length = len;

  /* When SMUX connection is not established. */
  if (zg->snmp.sock < 0)
    return 0;

  /* SMUX header. */
  ptr = asn_build_header (ptr, &len, (u_int8_t) SMUX_TRAP, 0);

  /* Subagent enterprise oid. */
  ptr = asn_build_objid (ptr, &len,
                         (u_int8_t) 
                         (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
                         trap_oid, trap_oid_len);

  /* IP address. */
  addr.s_addr = 0;
  ptr = asn_build_string (ptr, &len, 
                          (u_int8_t)
                          (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_IPADDRESS),
                          (u_int8_t *)&addr, sizeof (struct pal_in4_addr));

  /* Generic trap integer. */
  val = SNMP_TRAP_ENTERPRISESPECIFIC;
  ptr = asn_build_int (ptr, &len, 
                       (u_int8_t)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                       &val, sizeof (s_int32_t));

  /* Specific trap integer. */
  val = spec_trap_val;
  ptr = asn_build_int (ptr, &len, 
                       (u_int8_t)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                       &val, sizeof (s_int32_t));

  /* Timeticks timestamp. */
  val = 0;
  ptr = asn_build_unsigned_int (ptr, &len, 
                                (u_int8_t)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_TIMETICKS),
                                &val, sizeof (u_int32_t));
  
  /* Variables. */
  h1 = ptr;
  ptr = asn_build_sequence (ptr, &len, 
                            (u_int8_t) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                            0);


  /* Iteration for each objects. */
  h1e = ptr;
  for (i = 0; i < trapobjlen; i++)
    {

      /* Make OID. */
      oid_copy (oid, name, namelen);
      oid_copy (oid + namelen, trapobj[i].name, trapobj[i].namelen);
      oid_copy (oid + namelen + trapobj[i].namelen, iname, inamelen);
      oid_len = namelen + trapobj[i].namelen + inamelen;

      if (IS_SUBAG_DEBUG)
        snmp_oid_dump (zg, "Trap", oid, oid_len);

      ret = smux_get (zg, oid, &oid_len, 1, &val_type, &val1, &val_len);

      if (IS_SUBAG_DEBUG)
        zlog_info (zg, "smux_get result %d", ret);

      if (ret == 0)
        ptr = smux_build_var_op (ptr, oid, &oid_len,
                                 val_type, val_len, val1, &len);
    }

  /* Now variable size is known, fill in size */
  asn_build_sequence(h1, &length,
                     (u_int8_t) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                     ptr - h1e);

  /* Fill in size of whole sequence */
  len = BUFSIZ;
  packet_len = ptr - buf;
  val_len = packet_len - 2;
  if (val_len >= 0x80 && val_len <= 0xFF)
    {
      pal_mem_move (buf + 2, buf + 1, packet_len - 1);
      packet_len++;
    }
  else if (val_len > 0xFF)
    {
      pal_mem_move (buf + 3, buf + 1, packet_len - 1);
      packet_len += 2;
    }

  asn_build_header (buf, &len, (u_int8_t) SMUX_TRAP, val_len);

  return pal_sock_send (zg->snmp.sock, buf, packet_len, 0);
}

s_int32_t
smux_trap2 (struct lib_globals *zg,
          oid *trap_oid, size_t trap_oid_len, oid spec_trap_val,
          oid *name, size_t namelen,
          struct trap_object2 *trapobj, size_t trapobjlen,
          u_int32_t tick)
{
  s_int32_t i;
  u_char buf[BUFSIZ];
  u_char *ptr;
  size_t len, length;
  struct pal_in4_addr addr;
  unsigned long val;
  u_char *h1, *h1e;
  size_t val_len;
  size_t packet_len;

  ptr = buf;
  len = BUFSIZ;
  length = len;

  /* When SMUX connection is not established. */
  if (zg->snmp.sock < 0)
    return 0;

  /* SMUX header. */
  ptr = asn_build_header (ptr, &len, (u_char) SMUX_TRAP, 0);

  /* Subagent enterprise oid. */
  ptr = asn_build_objid (ptr, &len,
                       (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
                       trap_oid, trap_oid_len);
  /* IP address. */
  addr.s_addr = 0;
  ptr = asn_build_string (ptr, &len,
                        (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_IPADDRESS),
                        (u_char *)&addr, sizeof (struct pal_in4_addr));

  /* Generic trap integer. */
  val = SNMP_TRAP_ENTERPRISESPECIFIC;
  ptr = asn_build_int (ptr, &len,
                     (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                     &val, sizeof (s_int32_t));

  /* Specific trap integer. */
  val = spec_trap_val;
  ptr = asn_build_int (ptr, &len,
                     (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                     &val, sizeof (s_int32_t));

  /* Timeticks timestamp. */
  val = 0;
  ptr =
    asn_build_unsigned_int (ptr, &len,
                          (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_TIMETICKS),
                          &val, sizeof (u_int32_t));
  
  /* Variables. */
  h1 = ptr;
  ptr = asn_build_sequence (ptr, &len, 
                          (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);

  /* Iteration for each objects. */
  h1e = ptr;
  for (i = 0; i < trapobjlen; i++)
    {
      if (IS_SUBAG_DEBUG)
      snmp_oid_dump (zg, "Trap", trapobj[i].name, trapobj[i].namelen);

      ptr = smux_build_var_op (ptr, trapobj[i].name, &trapobj[i].namelen,
                             trapobj[i].val_type, trapobj[i].val_len,
                             trapobj[i].val, &len);
    }

  /* Now variable size is known, fill in size. */
  asn_build_sequence(h1, &length,
                   (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR), ptr - h1e);

  /* Fill in size of whole sequence. */
  len = BUFSIZ;
  packet_len = ptr - buf;
  val_len = packet_len - 2;
  if (val_len >= 0x80 && val_len <= 0xFF)
    {
      pal_mem_move (buf + 2, buf + 1, packet_len - 1);
      packet_len++;
    }
  else if (val_len > 0xFF)
    {
      pal_mem_move (buf + 3, buf + 1, packet_len - 1);
      packet_len += 2;
    }

  asn_build_header (buf, &len, (u_char) SMUX_TRAP, val_len);

  return pal_sock_send (zg->snmp.sock, buf, packet_len, 0);
}



s_int32_t
smux_register (struct lib_globals *zg, pal_sock_handle_t sock)
{
  u_int8_t buf[BUFSIZ];
  u_int8_t *ptr;
  size_t len;
  s_int32_t ret;
  long priority;
  long operation;
  struct subtree *subtree;
  struct listnode *node;

  ret = 0;

  for (node = zg->snmp.treelist->head; node; node = node->next)
    {
      ptr = buf;
      len = BUFSIZ;

      subtree = node->data;

      /* SMUX RReq Header. */
      ptr = asn_build_header (ptr, &len, (u_int8_t) SMUX_RREQ, 0);

      /* Register MIB tree. */
      ptr = asn_build_objid (ptr, &len,
                             (u_int8_t)
                             (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
                             subtree->name, subtree->name_len);

      /* Priority. */
      priority = -1;
      ptr = asn_build_int (ptr, &len, 
                           (u_int8_t)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                           &priority, sizeof (u_int32_t));

      /* Operation. */
      operation = 2; /* Register R/W */
      ptr = asn_build_int (ptr, &len, 
                           (u_int8_t)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                           &operation, sizeof (u_int32_t));

      if (IS_SUBAG_DEBUG)
        {
          snmp_oid_dump (zg, "SMUX register oid", subtree->name, subtree->name_len);
          zlog_info (zg, "SMUX register priority: %d", priority);
          zlog_info (zg, "SMUX register operation: %d", operation);
        }

      len = BUFSIZ;
      asn_build_header (buf, &len, (u_int8_t) SMUX_RREQ, (ptr - buf) - 2);
      ret = pal_sock_send (sock, buf, (ptr - buf), 0);
      if (ret < 0)
        return ret;
    }
  return ret;
}

/* Try to connect to SNMP agent. */
s_int32_t
smux_connect (struct thread *t)
{
  s_int32_t ret;
  struct lib_globals *zg = THREAD_GLOB (t);

  if (IS_SUBAG_DEBUG)
    zlog_info (zg, "SMUX connect try %d", zg->snmp.fail + 1);

  /* Clear thread poner of myself. */
  zg->snmp.t_connect = NULL;

  /* Make socket.  Try to connect. */
  zg->snmp.sock = smux_socket (zg);
  if (zg->snmp.sock < 0)
    {
      if (++zg->snmp.fail < SMUX_MAX_FAILURE)
        {
        smux_event (zg, SMUX_CONNECT, 0);
        }
      return 0;
    }

  /* Send OPEN PDU. */
  ret = smux_open (zg, zg->snmp.sock);
  if (ret < 0)
    {
      zlog_warn (zg, "SMUX open message send failed: %s",
                 pal_strerror (errno));
      pal_sock_close (zg, zg->snmp.sock);
      zg->snmp.sock = -1;
      if (++zg->snmp.fail < SMUX_MAX_FAILURE)
        smux_event (zg, SMUX_CONNECT, 0);

      return -1;
    }

  /* Send any outstanding register PDUs. */
  ret = smux_register (zg, zg->snmp.sock);
  if (ret < 0)
    {
      zlog_warn (zg, "SMUX register message send failed: %s",
                 pal_strerror (errno));
      pal_sock_close (zg, zg->snmp.sock);
      zg->snmp.sock = -1;
      if (++zg->snmp.fail < SMUX_MAX_FAILURE)
        smux_event (zg, SMUX_CONNECT, 0);

      return -1;
    }

  /* Everything goes fine. */
  smux_event (zg, SMUX_READ, zg->snmp.sock);

  return 0;
}

/* Clear all SMUX related resources. */
void
smux_stop (struct lib_globals *zg)
{
  if (zg->snmp.t_read)
    THREAD_OFF (zg->snmp.t_read);
  if (zg->snmp.t_connect)
    THREAD_OFF (zg->snmp.t_connect);

  if (zg->snmp.sock >= 0)
    {
      pal_sock_close (zg, zg->snmp.sock);
      zg->snmp.sock = -1;
    }
}

void
smux_event (struct lib_globals *zg, enum smux_event event,
            pal_sock_handle_t sock)
{
  switch (event)
    {
    case SMUX_SCHEDULE:
      if (zg->snmp.t_connect == NULL)
        zg->snmp.t_connect = thread_add_event (zg, smux_connect, NULL, 0);
      break;
    case SMUX_CONNECT:
      if (zg->snmp.t_connect == NULL)
        zg->snmp.t_connect = thread_add_timer (zg, smux_connect, NULL, 10);
      break;
    case SMUX_READ:
      if (zg->snmp.t_read == NULL)
        zg->snmp.t_read = thread_add_read (zg, smux_read, NULL, sock);
      break;
    case SMUX_RESTART:
      smux_stop (zg);
      if (zg->snmp.t_connect == NULL)
        zg->snmp.t_connect = thread_add_event (zg, smux_connect, NULL, 0);
      break;
    case SMUX_STOP:
      smux_stop (zg);
      break;
    default:
      break;
    }
}

s_int32_t
smux_str2oid (char *str, oid *oid, size_t *oid_len)
{
  s_int32_t len;
  s_int32_t val;

  len = 0;
  val = 0;
  *oid_len = 0;

  if (*str == '.')
    str++;
  if (*str == '\0')
    return 0;

  while (1)
    {
      if (! pal_char_isdigit ((int) *str))
        return -1;

      while (pal_char_isdigit ((int) *str))
        {
          val *= 10;
          val += (*str - '0');
          str++;
        }

      if (*str == '\0')
        break;
      if (*str != '.')
        return -1;

      oid[len++] = val;
      val = 0;
      str++;
    }

  oid[len++] = val;
  *oid_len = len;

  return 0;
}

oid *
smux_oid_dup (oid *objid, size_t objid_len)
{
  oid *new;

  new = XMALLOC (MTYPE_TMP, sizeof (oid) * objid_len);
  oid_copy (new, objid, objid_len);

  return new;
}

s_int32_t
smux_peer_oid (struct cli *cli, char *oid_str, char *passwd_str)
{
  s_int32_t ret;
  oid oid[MAX_OID_LEN];
  size_t oid_len;

  ret = smux_str2oid (oid_str, oid, &oid_len);
  if (ret != 0)
    return CLI_ERROR;

  if (cli->zg->snmp.oid &&
      cli->zg->snmp.oid != cli->zg->snmp.default_oid)
    XFREE (MTYPE_TMP, cli->zg->snmp.oid);

  if (cli->zg->snmp.passwd && 
      cli->zg->snmp.passwd != cli->zg->snmp.default_passwd)
    {
      XFREE (MTYPE_TMP, cli->zg->snmp.passwd);
      cli->zg->snmp.passwd = cli->zg->snmp.default_passwd;
    }

  cli->zg->snmp.oid = smux_oid_dup (oid, oid_len);
  cli->zg->snmp.oid_len = oid_len;

  if (passwd_str)
    cli->zg->snmp.passwd = XSTRDUP (MTYPE_SMUX_PASSWD, passwd_str);

  /* Restart SMUX session. */
  smux_event (cli->zg, SMUX_RESTART, 0);

  return CLI_SUCCESS;
}

s_int32_t
smux_peer_default (struct lib_globals *zg)
{
  if (zg->snmp.oid != zg->snmp.default_oid)
    {
      XFREE (MTYPE_TMP, zg->snmp.oid);
      zg->snmp.oid = zg->snmp.default_oid;
      zg->snmp.oid_len = zg->snmp.default_oid_len;
    }
  if (zg->snmp.passwd != zg->snmp.default_passwd)
    {
      XFREE (MTYPE_TMP, zg->snmp.passwd);
      zg->snmp.passwd = zg->snmp.default_passwd;
    }

  /* Restart SMUX session. */
  smux_event (zg, SMUX_RESTART, 0);

  return CLI_SUCCESS;
}

#if 0
CLI (smux_peer,
     smux_peer_cmd,
     "smux peer OID",
     "SNMP MUX protocol settings",
     "SNMP MUX peer settings",
     "Object ID used in SMUX peering")
{
  return smux_peer_oid (cli, argv[0], NULL);
}

CLI (smux_peer_password,
       smux_peer_password_cmd,
       "smux peer OID PASSWORD",
       "SNMP MUX protocol settings",
       "SNMP MUX peer settings",
       "SMUX peering object ID",
       "SMUX peering password")
{
  return smux_peer_oid (cli, argv[0], argv[1]);
}

CLI (no_smux_peer,
       no_smux_peer_cmd,
       "no smux peer OID",
       CLI_NO_STR,
       "SNMP MUX protocol settings",
       "SNMP MUX peer settings",
       "Object ID used in SMUX peering")
{
  return smux_peer_default (cli->zg);
}

CLI (no_smux_peer_password,
       no_smux_peer_password_cmd,
       "no smux peer OID PASSWORD",
       CLI_NO_STR,
       "SNMP MUX protocol settings",
       "SNMP MUX peer settings",
       "SMUX peering object ID",
       "SMUX peering password")
{
  return smux_peer_default (cli->zg);
}

s_int32_t
config_write_smux (struct cli *cli)
{
  int first = 1;
  int i;

  if (cli->zg->snmp.oid != cli->zg->snmp.default_oid
      || cli->zg->snmp.passwd != cli->zg->snmp.default_passwd)
    {
      cli_out (cli, "smux peer ");
      for (i = 0; i < cli->zg->snmp.oid_len; i++)
        {
          cli_out (cli, "%s%d", first ? "" : ".", (int) cli->zg->snmp.oid[i]);
          first = 0;
        }
      cli_out (cli, " %s\n", cli->zg->snmp.passwd);
      cli_out (cli, "!\n");
    }
  return 0;
}
#endif /* 0 */

/* Register subtree to snmp master tree. */
void
smux_register_mib (struct lib_globals *zg,
                   char *descr, struct variable *var, size_t width,
                   s_int32_t num, oid name[], size_t namelen)
{
  struct subtree *tree;


  tree = XMALLOC (MTYPE_SNMP_SUBTREE, sizeof(struct subtree));
  oid_copy (tree->name, name, namelen);
  tree->name_len = namelen;
  tree->variables = var;
  tree->variables_num = num;
  tree->variables_width = width;
  tree->registered = 0;
  listnode_add_sort (zg->snmp.treelist, tree);
}

void
smux_reset (struct lib_globals *zg)
{
  /* Setting configuration to default. */
  smux_peer_default (zg);
}

/* Init for protocol. */
void
smux_initialize (struct lib_globals *zg)
{
  /* Set default SMUX password. */
  zg->snmp.default_passwd = "";
  zg->snmp.passwd = zg->snmp.default_passwd;
}

#endif  /* !HAVE_AGENTX */
#endif  /* HAVE_SNMP */
