/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>
#include <prefix.h>
/*********************************************************************/
/* FILE       : bgp_decode.c                                         */
/* PURPOSE    : This file contains 'BGP Peer Message Decoding'       */
/*              related function definitions.                        */
/* SUB-MODULE : BGP Peer Decode                                      */
/* NAME-TAG   : 'bpd_' (BGP Peer Decoder)                            */
/*********************************************************************/

/*
 * LEVEL 1 BGP Message Decoder function:
 * Decodes BGP Message Header
 */
enum ssock_error
bpd_msg_hdr (struct stream_sock_cb *ssock_cb,
             u_int32_t ssock_read_arg,
             struct lib_globals *blg)
{
  struct cqueue_buffer *cq_rbuf;
  u_int32_t bytes_to_read;
  u_int16_t msg_size_min;
  u_int16_t msg_size_max;
  struct bgp_peer *peer;
  enum ssock_error ret;
  u_int32_t tmp_uint;
  u_int16_t msg_size;
  u_int8_t msg_type;
  u_int32_t idx;

  msg_size_max = BGP_MAX_PACKET_SIZE;
  msg_size_min = BGP_HEADER_SIZE;
  bytes_to_read = 0;
  ret = 0;

  /* Sanity check */
  if (! ssock_cb || &BLG != blg)
    {
      zlog_err (&BLG, "[DECODE] Msg-Hdr: Invalid Sock CB (%X)",
                ssock_cb);
      ret = SSOCK_ERR_INVALID;
      goto EXIT;
    }

  /* Obtain the Socket CB's owning peer */
  peer = (struct bgp_peer *) SSOCK_CB_GET_OWNER (ssock_cb);
  if (! peer || peer->sock_cb != ssock_cb)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Msg-Hdr: Invalid Sock CB (%X)",
                peer ? peer->host : (u_int8_t *) "?",
                peer ? BGP_PEER_DIR_STR (peer) : "?", ssock_cb);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set BGP VR Context */
  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  /* Obtain the CQ Read Buffer */
  cq_rbuf = SSOCK_CB_GET_READ_CQ_BUF (ssock_cb, &BLG);

  /* If required number of bytes are not present just return */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read < BGP_HEADER_SIZE)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] Msg-Hdr: Bytes To Read (%u)",
                   peer->host, BGP_PEER_DIR_STR (peer), bytes_to_read);
      ret = SSOCK_ERR_NONE;
      goto EXIT;
    }

  /* Validate BGP Message Header Marker field */
  for (idx = 0; idx < (BGP_MARKER_SIZE >> 2); idx++)
    {
      CQUEUE_READ_4BYTES (cq_rbuf, &tmp_uint);
      if (tmp_uint != ~0)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Msg-Hdr: Invalid Marker in"
                    " 4-Bytes-set (%X)",
                    peer->host, BGP_PEER_DIR_STR (peer), tmp_uint);

          bpf_event_notify (peer, BPF_EVENT_HDR_ERR,
                            BGP_NOTIFY_HEADER_ERR,
                            BGP_NOTIFY_HEADER_NOT_SYNC,
                            NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

  /* Get 'size' and 'type'*/
  CQUEUE_READ_INT16 (cq_rbuf, msg_size);
  CQUEUE_READ_INT8 (cq_rbuf, msg_type);

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [DECODE] Msg-Hdr: type %d, length %d",
               peer->host, BGP_PEER_DIR_STR (peer), msg_type, msg_size);

  /* Validata BGP Message Type */
  switch (msg_type)
    {
    case BGP_MSG_OPEN:
      msg_size_min = BGP_MSG_OPEN_MIN_SIZE;
      msg_size_max = BGP_MAX_PACKET_SIZE;
      break;

    case BGP_MSG_UPDATE:
      msg_size_min = BGP_MSG_UPDATE_MIN_SIZE;
      msg_size_max = BGP_MAX_PACKET_SIZE;
      break;

    case BGP_MSG_NOTIFY:
      msg_size_min = BGP_MSG_NOTIFY_MIN_SIZE;
      msg_size_max = BGP_MAX_PACKET_SIZE;
      break;

    case BGP_MSG_KEEPALIVE:
      msg_size_min = BGP_MSG_KEEPALIVE_MIN_SIZE;
      msg_size_max = BGP_MSG_KEEPALIVE_MIN_SIZE;
      break;

    case BGP_MSG_ROUTE_REFRESH_OLD:
    case BGP_MSG_ROUTE_REFRESH_NEW:
      msg_size_min = BGP_MSG_ROUTE_REFRESH_MIN_SIZE;
      msg_size_max = BGP_MAX_PACKET_SIZE;
      break;

    case BGP_MSG_CAPABILITY:
      msg_size_min = BGP_MSG_CAPABILITY_MIN_SIZE;
      msg_size_max = BGP_MAX_PACKET_SIZE;
      break;

    default:
      zlog_err (&BLG, "%s-%s [DECODE] Msg-Hdr: Bad type %d",
                peer->host, BGP_PEER_DIR_STR (peer), msg_type);

      bpf_event_notify (peer, BPF_EVENT_HDR_ERR,
                        BGP_NOTIFY_HEADER_ERR,
                        BGP_NOTIFY_HEADER_BAD_MESTYPE,
                        &msg_type, sizeof (u_int8_t));
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validata BGP Message Length */
  if (msg_size < msg_size_min || msg_size > msg_size_max)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Msg-Hdr: Bad length %d (type %d)",
                peer->host, BGP_PEER_DIR_STR (peer), msg_size, msg_type);

      msg_size = pal_hton16 (msg_size),
      bpf_event_notify (peer, BPF_EVENT_HDR_ERR,
                        BGP_NOTIFY_HEADER_ERR,
                        BGP_NOTIFY_HEADER_BAD_MESLEN,
                        (u_int8_t *) &msg_size,
                        sizeof (u_int16_t));
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Discard the Header Size from Message Size */
  msg_size -= BGP_HEADER_SIZE;

  /* Set 'msg_size' as argument for the succeeding read_func */
  SSOCK_CB_SET_READ_FUNC_ARG (ssock_cb, msg_size);

  /*
   * Install appropriate Decoder-function based on 'msg_type' as the
   * succeeding read_func in SSOCK-CB
   */
  switch (msg_type)
    {
    case BGP_MSG_OPEN:
      SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_open);
      break;
    case BGP_MSG_UPDATE:
      SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_update);
      break;
    case BGP_MSG_NOTIFY:
      SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_notify);
      break;
    case BGP_MSG_KEEPALIVE:
      SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_keepalive);
      break;
    case BGP_MSG_ROUTE_REFRESH_NEW:
    case BGP_MSG_ROUTE_REFRESH_OLD:
      SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_route_refresh);
      break;
    case BGP_MSG_CAPABILITY:
      SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_dyna_cap);
      break;
    }

  /* If required number of bytes are present request immediate read */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read >= msg_size)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] Msg-Hdr: Requesting immediate Read (%u)",
                   peer->host, BGP_PEER_DIR_STR (peer), msg_size);
      ret = SSOCK_ERR_READ_LOOP;
    }
  else if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [DECODE] Msg-Hdr: Bytes To Read (%u)"
               " < msg_size (%u), no immediate read", peer->host,
               BGP_PEER_DIR_STR (peer), bytes_to_read, msg_size);

EXIT:

  /* In decoding BGP Meseage Header, we do not need any parameters */
  BGP_UNREFERENCED_PARAMETER (ssock_read_arg);

  return ret;
}

/*
 * LEVEL 1 BGP Message Decoder function:
 * Decodes BGP OPEN Message
 */
enum ssock_error
bpd_msg_open (struct stream_sock_cb *ssock_cb,
              u_int32_t msg_size,
              struct lib_globals *blg)
{
  struct cqueue_buffer *cq_rbuf;
  struct pal_in4_addr remote_id;
  u_int16_t conf_keepalive;
  u_int16_t conf_holdtime;
  u_int32_t bytes_to_read;
  struct bgp_peer *peer;
  enum ssock_error ret;
  u_int16_t holdtime;
  u_int16_t version;
  u_int8_t opt_size;
#ifndef HAVE_EXT_CAP_ASN 
  u_int16_t remote_as; 
#else
  as_t remote_as;
#endif /* HAVE_EXT_CAP_ASN */

  bytes_to_read = 0;
  ret = SSOCK_ERR_NONE;

  /* Sanity check */
  if (! ssock_cb || &BLG != blg)
    {
      zlog_err (&BLG, "[DECODE] Open: Invalid Sock CB (%X)",
                ssock_cb);
      ret = SSOCK_ERR_INVALID;
      goto EXIT;
    }

  /* Obtain the Socket CB's owning peer */
  peer = (struct bgp_peer *) SSOCK_CB_GET_OWNER (ssock_cb);
  if (! peer || peer->sock_cb != ssock_cb)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open: Invalid Sock CB (%X)",
                peer ? peer->host : (u_int8_t *) "?",
                peer ? BGP_PEER_DIR_STR (peer) : "?", ssock_cb);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set BGP VR Context */
  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  /* Obtain the CQ Read Buffer */
  cq_rbuf = SSOCK_CB_GET_READ_CQ_BUF (ssock_cb, &BLG);

  /* If required number of bytes are not present just return */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read < msg_size)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] Open: Bytes To Read (%u)"
                   " < msg_size (%u)",
                   peer ? peer->host : (u_int8_t *) "?",
                   peer ? BGP_PEER_DIR_STR (peer) : "?",
                   bytes_to_read, msg_size);
      ret = SSOCK_ERR_NONE;
      goto EXIT;
    }

  /* Count the Incoming OPEN message */
  peer->open_in++;

  /* Get BGP Peer 'version' */
  CQUEUE_READ_INT8 (cq_rbuf, version);

  /* Validate BGP Peer Version */
  if (version != BGP_VERSION_4)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open: Bad protocol version %d",
                peer->host, BGP_PEER_DIR_STR (peer), version);

      version = pal_hton16 (BGP_VERSION_4);
      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR,
                        BGP_NOTIFY_OPEN_UNSUP_VERSION,
                        (u_int8_t *) &version,
                        sizeof (u_int16_t));
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

   
  /* Get BGP Peer 'remote-as' */
  CQUEUE_READ_INT16 (cq_rbuf, remote_as);

  /* Validate My AS. */ 
  /* If the sender is 4-octet non-mappable NBGP, My AS contains AS_TRANS. */
  /* validate if local speaker is OBGP and neighbor is Non Mappable NBGP,
     OBGP should configure its remote_as as BGP_AS_TRANS */
  if (remote_as == BGP_AS_TRANS)
    {
       if (! CHECK_FLAG (BGP_VR.bvr_options,BGP_OPT_EXTENDED_ASN_CAP))
         {
           if (peer->as != BGP_AS_TRANS)  
             {
               zlog_err (&BLG, "%s-%s [DECODE] Open: Bad Remote-AS (%d), expected %d",
                         peer->host, BGP_PEER_DIR_STR (peer), remote_as, peer->as);

               remote_as = pal_hton32 (remote_as);
               bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                                 BGP_NOTIFY_OPEN_ERR,
                                 BGP_NOTIFY_OPEN_BAD_PEER_AS,
                                 (u_int8_t *) &remote_as,
                                 sizeof (u_int32_t));
               ret = SSOCK_ERR_CLOSE;
               goto EXIT; 
             }
         }
     }

  /* Sender is 2-octet mappable */ 
  /* Validate Remote-AS with locally configured value */
   else if (remote_as != peer->as)
     {
       zlog_err (&BLG, "%s-%s [DECODE] Open: Bad Remote-AS (%d), expected %d",
                 peer->host, BGP_PEER_DIR_STR (peer), remote_as, peer->as);
      
       remote_as = pal_hton32 (remote_as);
       bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                         BGP_NOTIFY_OPEN_ERR,
                         BGP_NOTIFY_OPEN_BAD_PEER_AS,
                         (u_int8_t *) &remote_as,
                         sizeof (u_int32_t));
       ret = SSOCK_ERR_CLOSE;
       goto EXIT;
     }

  /* Get BGP Peer 'holdtime' */
  CQUEUE_READ_INT16 (cq_rbuf, holdtime);

  /* Validate Hold-Timer value. We reject the connection if invalid */
  if (holdtime < 3 && holdtime != 0)
  {
      zlog_err (&BLG, "%s-%s [DECODE] Open: Bad Hold-time (%d)",
                peer->host, BGP_PEER_DIR_STR (peer), holdtime);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR,
                        BGP_NOTIFY_OPEN_UNACEP_HOLDTIME,
                        NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }
  else if (holdtime == 0 && 
           CHECK_FLAG (peer->flags, PEER_DISALLOW_INFINITE_HOLD_TIME) )
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open: Unacceptable Hold-time (%d)",
                peer->host, BGP_PEER_DIR_STR (peer), holdtime);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR,
                        BGP_NOTIFY_OPEN_UNACEP_HOLDTIME,
                        NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }
  /* Validate Hold-Timer value for Peer member of Peer-Group */
    if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
      {
        if (peer->group)
          if (holdtime == 0 &&
             CHECK_FLAG (peer->group->conf->flags, PEER_DISALLOW_INFINITE_HOLD_TIME))
          {
            zlog_err (&BLG, "%s-%s [DECODE] Open: Unacceptable Hold-time (%d)",
                  peer->host, BGP_PEER_DIR_STR (peer), holdtime);
  
            bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                              BGP_NOTIFY_OPEN_ERR,
                              BGP_NOTIFY_OPEN_UNACEP_HOLDTIME,
                              NULL, 0);
            ret = SSOCK_ERR_CLOSE;
            goto EXIT;
          }
      }

  /* Get BGP Peer 'router-id' */
  CQUEUE_READ_4BYTES (cq_rbuf, &remote_id.s_addr);

  /* Validate BGP Peer Remote Router-ID */
  if (remote_id.s_addr == 0
      || pal_ntoh32 (remote_id.s_addr) >= 0xe0000000
      || pal_ntoh32 (peer->local_id.s_addr) == pal_ntoh32 (remote_id.s_addr))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open: Invalid Router ID %r",
                peer->host, BGP_PEER_DIR_STR (peer), &remote_id);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR,
                        BGP_NOTIFY_OPEN_BAD_BGP_IDENT,
                        (u_int8_t *) &remote_id.s_addr,
                        sizeof (struct pal_in4_addr));
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'options length' */
  CQUEUE_READ_INT8 (cq_rbuf, opt_size);

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [DECODE] Open: Optional param len %d",
               peer->host, BGP_PEER_DIR_STR (peer), opt_size);

  if (opt_size)
    {
      ret = bpd_msg_open_opt (cq_rbuf, peer, opt_size);
      if (ret != SSOCK_ERR_NONE)
        goto EXIT;
    }
  else
    {
      SET_FLAG (peer->cap, PEER_CAP_NONE_RCV);

     /* If the BGP peer has not sent any optional parameters, but user has locally
      * configured strict capability match then unsupported capability error code
      * should be sent to the peer and the BGP session should not be established. */

      if (CHECK_FLAG (peer->flags, PEER_FLAG_STRICT_CAP_MATCH)
          && CHECK_FLAG (peer->flags, PEER_FLAG_NO_ROUTE_REFRESH_CAP))
        {
          zlog_err (&BLG, "%s-%s [DECODE] Open Opt: Strict, Cap mis-match",
                peer->host, BGP_PEER_DIR_STR (peer));
 
          if (CHECK_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN))
            UNSET_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN);
     
          bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                            BGP_NOTIFY_OPEN_ERR,
                            BGP_NOTIFY_OPEN_UNSUP_CAPBL,
                            NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      if (CHECK_FLAG (peer->flags, PEER_FLAG_STRICT_CAP_MATCH)
          && CHECK_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN)
          && ! CHECK_FLAG (peer->flags, PEER_FLAG_DONT_CAPABILITY))
        {
          bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                            BGP_NOTIFY_OPEN_ERR,
                            BGP_NOTIFY_OPEN_UNSUP_CAPBL,
                            NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

  /* Set negotiated 'version' */
  peer->version = version;

  /* Set remote router-id */
  peer->remote_id = remote_id;

  /* Obtain the configured 'hold-time' and 'keepalive-time */
  conf_holdtime = peer->holdtime;
  conf_keepalive = peer->keepalive;
  if (peer->real_peer)
    {
      conf_holdtime = peer->real_peer->holdtime;
      conf_keepalive = peer->real_peer->keepalive;
    }

  /*
   * BGP speaker MUST calculate the value of the Hold Timer by using
   * the smaller of its configured Hold Time and the Hold Time
   * received in the OPEN message
   */
  if (holdtime < conf_holdtime)
    peer->v_holdtime = holdtime;
  else
    peer->v_holdtime = conf_holdtime;

  /*
   * When localy configured keepalive is smaller than holdtime / 3,
   * use localy configured value as keepalive.  Otherwise use
   * calculated value
   */
  if (conf_keepalive <= peer->v_holdtime / 3)
    peer->v_keepalive = conf_keepalive;
  else
    peer->v_keepalive = peer->v_holdtime / 3;

  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_OPEN_VALID);

  /* Reset argument for succeeding read_func, viz., Header Decoder */
  SSOCK_CB_SET_READ_FUNC_ARG (ssock_cb, BGP_HEADER_SIZE);

  /* Install Header Decoder as the succeeding read_func in SSOCK-CB */
  SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_hdr);

  /* If required number of bytes are present request immediate read */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read >= BGP_HEADER_SIZE)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] Open: Requesting immediate Read (%u)",
                   peer->host, BGP_PEER_DIR_STR (peer), BGP_HEADER_SIZE);
      ret = SSOCK_ERR_READ_LOOP;
    }

EXIT:

  return ret;
}

/*
 * LEVEL 1 BGP Message Decoder function:
 * Decodes BGP UPDATE Message
 */
enum ssock_error
bpd_msg_update (struct stream_sock_cb *ssock_cb,
                u_int32_t msg_size,
                struct lib_globals *blg)
{
  struct cqueue_buf_snap_shot tmp_cqbss;
  struct bgp_dec_update_info *bdui;
  struct bgp_nlri_snap_shot bnss;
  struct cqueue_buffer *cq_rbuf;
  u_int32_t bytes_to_read;
  u_int16_t attribute_len;
  struct bgp_peer *peer;
  enum ssock_error ret;
  u_int32_t alloc_size;
  struct attr *attr;

  bytes_to_read = 0;
  ret = SSOCK_ERR_NONE;
  attr = NULL;

  /* Sanity check */
  if (! ssock_cb || &BLG != blg)
    {
      zlog_err (&BLG, "[DECODE] Update: Invalid Sock CB (%X)",
                ssock_cb);
      ret = SSOCK_ERR_INVALID;
      goto EXIT;
    }

  /* Obtain the Socket CB's owning peer */
  peer = (struct bgp_peer *) SSOCK_CB_GET_OWNER (ssock_cb);
  if (! peer || peer->sock_cb != ssock_cb)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Update: Invalid Sock CB (%X)",
                peer ? peer->host : (u_int8_t *) "?",
                peer ? BGP_PEER_DIR_STR (peer) : "?", ssock_cb);

      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set BGP VR Context */
  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  /* Obtain the CQ Read Buffer */
  cq_rbuf = SSOCK_CB_GET_READ_CQ_BUF (ssock_cb, &BLG);

  /* If required number of bytes are not present just return */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read < msg_size)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] Update: Bytes To Read (%u)"
                   " < msg_size (%u)", peer->host,
                   BGP_PEER_DIR_STR (peer), bytes_to_read, msg_size);

      ret = SSOCK_ERR_NONE;
      goto EXIT;
    }

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [DECODE] Update: Starting UPDATE decoding"
               "... Bytes To Read (%u), msg_size (%u)", peer->host,
               BGP_PEER_DIR_STR (peer), bytes_to_read, msg_size);

  /* Allocate the Attribute Structure */
  attr = XCALLOC (MTYPE_ATTR, sizeof (struct attr));
  if (! attr)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Update:"
                " Cannot allocate memory (%d) @ %s:%d",
                peer->host, BGP_PEER_DIR_STR (peer),
                sizeof (struct attr), __FILE__, __LINE__);

      /* Lets try our luck with next message */
      CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, msg_size);
      ret = SSOCK_ERR_NONE;
      goto READ_NEXT_MSG;
    }

  /* Count the Incoming UPDATE message */
  peer->update_in++;

  /* Reset the Last-Update-Received-Time */
  peer->update_time = pal_time_current (NULL);

  /* Clear the NLRI Snap-shot structure */
  pal_mem_set (&bnss, 0, sizeof (struct bgp_nlri_snap_shot));

  /* Get 'Withdrawn Routes Length' */
  CQUEUE_READ_INT16 (cq_rbuf, bnss.withdrawn_len);

  /* Validate 'Withdrawn Routes Length' */
  if (bnss.withdrawn_len + 4 > msg_size)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Update: Bad Withdrawn-Routes-Len"
                " (%u) + 4 > msg_size (%u)", peer->host,
                BGP_PEER_DIR_STR (peer), bnss.withdrawn_len, msg_size);

      bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                        BGP_NOTIFY_UPDATE_ERR,
                        BGP_NOTIFY_UPDATE_MAL_ATTR,
                        NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Snap-shot CQueue-Buf at Start of Withdrawn NLRIs */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_rbuf, &bnss.withdrawn_cqbss);

  /*
   * We now need to get 'Total Path Attributes Length'.
   * So advance in Read CQueue and get 'Attributes Length.
   */
  CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, bnss.withdrawn_len);
  CQUEUE_READ_INT16 (cq_rbuf, attribute_len);

  /* Validate 'Withdrawn Routes Length' & 'Tot Attributes Length */
  if (bnss.withdrawn_len + attribute_len + 4 > msg_size)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Update: Bad Withdrawn-Routes-Len"
                " (%u) + Tot-Attributes-Len (%u) + 4 > msg_size (%u)",
                peer->host, BGP_PEER_DIR_STR (peer), bnss.withdrawn_len,
                attribute_len, msg_size);

      bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                        BGP_NOTIFY_UPDATE_ERR,
                        BGP_NOTIFY_UPDATE_MAL_ATTR,
                        NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Determine 'Advertised NLRIs' length */
  bnss.advertised_len = msg_size - 4 - attribute_len - bnss.withdrawn_len;

  /*
   * NOTE: First we decode and validate the Path-Attributes. Then
   * we'll go-back (re-wind), and decode and validate Withdrawn-NLRIs.
   * Then we'll advance (skip-over) Path-Attributes to decode and
   * validate Advertised-NLRIs. [As suggested in RFC 4271 Sec Appendix F.2]
   */

  /* Decode Path-Attributes */
  ret = bpd_msg_update_attr (cq_rbuf, peer, attribute_len,
                             attr, &bnss);
  switch (ret)
    {
    case SSOCK_ERR_NONE:
      break;

    case SSOCK_ERR_READ_LOOP:
      /* We need to ignore this UPDATE message */
      CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf,
                                  bnss.advertised_len);

      ret = SSOCK_ERR_NONE;
      goto READ_NEXT_MSG;
      break;

    case SSOCK_ERR_INVALID:
    case SSOCK_ERR_CLOSE:
      goto EXIT;
      break;
    }

  /* Snap-shot CQueue-Buf for Advertised NLRIs */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_rbuf, &bnss.advertised_cqbss);

  /* Validate Well-Known Mandatory Attributes for IPv4-UNICAST */
  if (peer->afc[BAAI_IP][BSAI_UNICAST] && bnss.advertised_len)
    {
      if (PAL_TRUE != bgp_peer_attr_check (peer, attr, PAL_TRUE))
        {
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

  /* Validate Well-Known Mandatory Attributes other than NEXTHOP for
   * other address families (if activated)
  */
  if (peer->afc [BGP_AFI2BAAI (bnss.mp_reach_afi)]
                [BGP_SAFI2BSAI (bnss.mp_reach_safi)]
      && bnss.mp_reach_len)
    {
      if (PAL_TRUE != bgp_peer_attr_check (peer, attr, PAL_FALSE))
        {
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

  /* Decode 'Withdrawn Routes' if present */
  if (bnss.withdrawn_len)
    {
      /* Enliven Snap-Shot to the start of 'Withdrawn Routes' */
      CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_rbuf, &bnss.withdrawn_cqbss);

      if (BGP_DEBUG (update, UPDATE_IN))
        zlog_info (&BLG, "%s-%s [DECODE] Update: Withdrawn Len(%d)",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   bnss.withdrawn_len);

      /* Decode and validate Withdrawn-NLRI list */
      ret = bpd_msg_update_nlri_validate (cq_rbuf, peer, AFI_IP,
                                          SAFI_UNICAST,
                                          bnss.withdrawn_len);
      if (ret != SSOCK_ERR_NONE)
        goto EXIT;

      /* Restore CQueue to start of 'Advertised NLRIs' */
      CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_rbuf, &bnss.advertised_cqbss);
    }

  /* Decode 'Advertised NLRI' if present */
  if (bnss.advertised_len)
    {
      if (BGP_DEBUG (events, EVENTS) || BGP_DEBUG (update, UPDATE_IN))
        zlog_info (&BLG, "%s-%s [DECODE] Update: NLRI Len(%d)",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   bnss.advertised_len);

      /* Decode and validate Advertised-NLRI list */
      ret = bpd_msg_update_nlri_validate (cq_rbuf, peer, AFI_IP,
                                          SAFI_UNICAST,
                                          bnss.advertised_len);
      if (ret != SSOCK_ERR_NONE)
        goto EXIT;
    }

  /* Send decoded UPDATE Message Information to Peer FSM */
  alloc_size = sizeof (struct bgp_dec_update_info) - 1 +
               bnss.withdrawn_len + bnss.advertised_len +
               bnss.mp_unreach_len + bnss.mp_reach_len;
  bdui = XCALLOC (MTYPE_TMP, alloc_size);
  if (! bdui)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Update:"
                " Cannot allocate memory (%d) @ %s:%d",
                peer->host, BGP_PEER_DIR_STR (peer),
                alloc_size, __FILE__, __LINE__);

      /* Lets try our luck with next message */
      ret = SSOCK_ERR_NONE;
      goto READ_NEXT_MSG;
    }

  /* Initialize the FIFO */
  FIFO_INIT (&bdui->ui_fifo);

  /* Snap-shot current CQueue-Buf for later restoration */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_rbuf, &tmp_cqbss);

  /* Store 'attr' info */
  bdui->ui_attr = attr;

  /* Store 'Withdrawn NLRI' info */
  if (bnss.withdrawn_len)
    {
      bdui->ip_withdrawn.ni_present = PAL_TRUE;
      bdui->ip_withdrawn.ni_afi = AFI_IP;
      bdui->ip_withdrawn.ni_safi = SAFI_UNICAST;
      bdui->ip_withdrawn.ni_length = bnss.withdrawn_len;
      bdui->ip_withdrawn.ni_data = &bdui->ui_nlri[0];

      /* Now enliven corresponding snap-shot and copy data */
      CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_rbuf, &bnss.withdrawn_cqbss);
      CQUEUE_READ_NBYTES (cq_rbuf, bdui->ip_withdrawn.ni_data,
                          bnss.withdrawn_len);
    }
  else
    bdui->ip_withdrawn.ni_present = PAL_FALSE;

  /* Store 'Advertised NLRI' info */
  if (bnss.advertised_len)
    {
      bdui->ip_advertised.ni_present = PAL_TRUE;
      bdui->ip_advertised.ni_afi = AFI_IP;
      bdui->ip_advertised.ni_safi = SAFI_UNICAST;
      bdui->ip_advertised.ni_length = bnss.advertised_len;
      bdui->ip_advertised.ni_data = &bdui->ui_nlri[0] +
                                    bnss.withdrawn_len;

      /* Now enliven corresponding snap-shot and copy data */
      CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_rbuf, &bnss.advertised_cqbss);
      CQUEUE_READ_NBYTES (cq_rbuf, bdui->ip_advertised.ni_data,
                          bnss.advertised_len);
    }
  else
    bdui->ip_advertised.ni_present = PAL_FALSE;

  /* Store 'MP Un-Reach NLRI' info */
  if (bnss.mp_unreach_len)
    {
      bdui->mp_unreach.ni_present = PAL_TRUE;
      bdui->mp_unreach.ni_afi = bnss.mp_unreach_afi;
      bdui->mp_unreach.ni_safi = bnss.mp_unreach_safi;
      bdui->mp_unreach.ni_length = bnss.mp_unreach_len;
      bdui->mp_unreach.ni_data = &bdui->ui_nlri[0] +
                                 bnss.withdrawn_len +
                                 bnss.advertised_len;

      /* Now enliven corresponding snap-shot and copy data */
      CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_rbuf, &bnss.mp_unreach_cqbss);
      CQUEUE_READ_NBYTES (cq_rbuf, bdui->mp_unreach.ni_data,
                          bnss.mp_unreach_len);
    }
  else
    bdui->mp_unreach.ni_present = PAL_FALSE;

  /* Store 'MP Reach NLRI' info */
  if (bnss.mp_reach_len)
    {
      bdui->mp_reach.ni_present = PAL_TRUE;
      bdui->mp_reach.ni_afi = bnss.mp_reach_afi;
      bdui->mp_reach.ni_safi = bnss.mp_reach_safi;
      bdui->mp_reach.ni_length = bnss.mp_reach_len;
      bdui->mp_reach.ni_data = &bdui->ui_nlri[0] +
                               bnss.withdrawn_len +
                               bnss.advertised_len +
                               bnss.mp_unreach_len;

      /* Now enliven corresponding snap-shot and copy data */
      CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_rbuf, &bnss.mp_reach_cqbss);
      CQUEUE_READ_NBYTES (cq_rbuf, bdui->mp_reach.ni_data,
                          bnss.mp_reach_len);
    }
  else
    bdui->mp_reach.ni_present = PAL_FALSE;

  /* Restore CQ-Buffer to present state */
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_rbuf, &tmp_cqbss);

  /* Enqueue into Peer's 'bdui_fifo' */
  FIFO_ADD (&peer->bdui_fifo, &bdui->ui_fifo);

  /* Generate BGP Peer FSM Valid UPDATE Event */
  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_UPDATE_VALID);

  /* Loose pointer to 'attr' */
  attr = NULL;

READ_NEXT_MSG:

  /* Reset argument for succeeding read_func, viz., Header Decoder */
  SSOCK_CB_SET_READ_FUNC_ARG (ssock_cb, BGP_HEADER_SIZE);

  /* Install Header Decoder as the succeeding read_func in SSOCK-CB */
  SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_hdr);

  /* If required number of bytes are present request immediate read */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read >= BGP_HEADER_SIZE)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] Update: Requesting immediate Read (%u)",
                   peer->host, BGP_PEER_DIR_STR (peer), BGP_HEADER_SIZE);
      ret = SSOCK_ERR_READ_LOOP;
    }

EXIT:

  /* Free 'attr' if some error has occured */
  if (attr)
    {
      if (attr->aspath)
        aspath_unintern (attr->aspath);
#ifdef HAVE_EXT_CAP_ASN
      if (attr->as4path)
        as4path_unintern (attr->as4path);
      if (attr->aspath4B)
        aspath4B_unintern (attr->aspath4B);
#endif /* HAVE_EXT_CAP_ASN */
       
      if (attr->community)
        community_unintern (attr->community);
      if (attr->ecommunity)
        ecommunity_unintern (attr->ecommunity);
      if (attr->cluster)
        cluster_unintern (attr->cluster);
      if (attr->transit)
        transit_unintern (attr->transit);
      XFREE (MTYPE_ATTR, attr);
    }

  return ret;
}

/*
 * LEVEL 1 BGP Message Decoder function:
 * Decodes BGP NOTIFICATION Message
 */
enum ssock_error
bpd_msg_notify (struct stream_sock_cb *ssock_cb,
                u_int32_t msg_size,
                struct lib_globals *blg)
{
  struct cqueue_buffer *cq_rbuf;
  u_int32_t bytes_to_read;
  u_int32_t tmp_err_dlen;
  struct bgp_peer *peer;
  enum ssock_error ret;

  bytes_to_read = 0;
  ret = SSOCK_ERR_NONE;

  /* Sanity check */
  if (! ssock_cb || &BLG != blg)
    {
      zlog_err (&BLG, "[DECODE] Notify: Invalid Sock CB (%X)",
                ssock_cb);
      ret = SSOCK_ERR_INVALID;
      goto EXIT;
    }

  /* Obtain the Socket CB's owning peer */
  peer = (struct bgp_peer *) SSOCK_CB_GET_OWNER (ssock_cb);
  if (! peer || peer->sock_cb != ssock_cb)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Notify: Invalid Sock CB (%X)",
                peer ? peer->host : (u_int8_t *) "?",
                peer ? BGP_PEER_DIR_STR (peer) : "?", ssock_cb);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set BGP VR Context */
  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  /* Obtain the CQ Read Buffer */
  cq_rbuf = SSOCK_CB_GET_READ_CQ_BUF (ssock_cb, &BLG);

  /* If required number of bytes are not present just return */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read < msg_size)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] Notify: Bytes To Read (%u)"
                   " < msg_size (%u)",
                   peer ? peer->host : (u_int8_t *) "?",
                   peer ? BGP_PEER_DIR_STR (peer) : "?", bytes_to_read,
                   msg_size);
      ret = SSOCK_ERR_NONE;
      goto EXIT;
    }

  /* Count the Incoming NOTIFICATION message */
  peer->notify_in++;

  /* Free previous Notification information */
  if (peer->notify_info)
    XFREE (MTYPE_BGP_PEER_NOTIFY_DATA, peer->notify_info);

  tmp_err_dlen = msg_size - (BGP_MSG_NOTIFY_MIN_SIZE - BGP_HEADER_SIZE);

  peer->notify_info = XCALLOC (MTYPE_BGP_PEER_NOTIFY_DATA,
                            sizeof (struct bgp_peer_notify_info) - 1
                            + tmp_err_dlen);

  if (! peer->notify_info)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Notify:"
                " Cannot allocate memory (%d) @ %s:%d",
                peer->host, BGP_PEER_DIR_STR (peer),
                sizeof (struct bgp_peer_notify_info) - 1 + tmp_err_dlen,
                __FILE__, __LINE__);
      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_AUTO_STOP);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

   peer->notify_info->not_err_dir_sent = PAL_FALSE;

  /* Preserve Notification information */
  CQUEUE_READ_INT8 (cq_rbuf, peer->notify_info->not_err_code);
  CQUEUE_READ_INT8 (cq_rbuf, peer->notify_info->not_err_sub_code);
  peer->notify_info->not_err_dlen = tmp_err_dlen;
  if (tmp_err_dlen)
    {
      CQUEUE_READ_NBYTES (cq_rbuf,
                          peer->notify_info->not_err_data,
                          peer->notify_info->not_err_dlen);
    }

  if (BGP_DEBUG (events, EVENTS))
    bgp_log_neighbor_notify_print (peer, peer->notify_info,
                                   (u_int8_t *) "received from");

  /* Generate BGP Peer FSM Valid NOTIFICATION Event */
  if (peer->notify_info->not_err_code == BGP_NOTIFY_OPEN_ERR
      && peer->notify_info->not_err_code == BGP_NOTIFY_OPEN_UNSUP_VERSION)
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_NOTIFY_VER_ERR);
  else
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_NOTIFY_VALID);

  /* Reset argument for succeeding read_func, viz., Header Decoder */
  SSOCK_CB_SET_READ_FUNC_ARG (ssock_cb, BGP_HEADER_SIZE);

  /* Install Header Decoder as the succeeding read_func in SSOCK-CB */
  SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_hdr);

  /* If required number of bytes are present request immediate read */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read >= BGP_HEADER_SIZE)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] Notify: Requesting immediate Read(%u)",
                   peer->host, BGP_PEER_DIR_STR (peer), BGP_HEADER_SIZE);
      ret = SSOCK_ERR_READ_LOOP;
    }

EXIT:

  return ret;
}

/*
 * LEVEL 1 BGP Message Decoder function:
 * Decodes BGP KEEPALIVE Message
 */
enum ssock_error
bpd_msg_keepalive (struct stream_sock_cb *ssock_cb,
                   u_int32_t msg_size,
                   struct lib_globals *blg)
{
  struct cqueue_buffer *cq_rbuf;
  u_int32_t bytes_to_read;
  struct bgp_peer *peer;
  enum ssock_error ret;

  bytes_to_read = 0;
  ret = SSOCK_ERR_NONE;

  /* Sanity check */
  if (! ssock_cb || &BLG != blg)
    {
      zlog_err (&BLG, "[DECODE] KAlive: Invalid Sock CB (%X)",
                ssock_cb);
      ret = SSOCK_ERR_INVALID;
      goto EXIT;
    }

  /* Obtain the Socket CB's owning peer */
  peer = (struct bgp_peer *) SSOCK_CB_GET_OWNER (ssock_cb);
  if (! peer || peer->sock_cb != ssock_cb)
    {
      zlog_err (&BLG, "%s-%s [DECODE] KAlive: Invalid Sock CB (%X)",
                peer ? peer->host : (u_int8_t *) "?",
                peer ? BGP_PEER_DIR_STR (peer) : "?", ssock_cb);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set BGP VR Context */
  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  /* Obtain the CQ Read Buffer */
  cq_rbuf = SSOCK_CB_GET_READ_CQ_BUF (ssock_cb, &BLG);

  /* If required number of bytes are not present just return */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read < msg_size)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] KAlive: Bytes To Read (%u)"
                   " < msg_size (%u)",
                   peer ? peer->host : (u_int8_t *) "?",
                   peer ? BGP_PEER_DIR_STR (peer) : "?",
                   bytes_to_read, msg_size);
      ret = SSOCK_ERR_NONE;
      goto EXIT;
    }

  if (BGP_DEBUG (events, EVENTS) || BGP_DEBUG (keepalive, KEEPALIVE))
    zlog_info (&BLG, "%s-%s [DECODE] KAlive: Received!",
               peer->host, BGP_PEER_DIR_STR (peer));

  /* Count the Incoming KEEPALIVE message */
  peer->keepalive_in++;

  /* Generate BGP Peer FSM Valid KEEP-ALIVE Event */
  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_KEEPALIVE_VALID);

  /* Reset argument for succeeding read_func, viz., Header Decoder */
  SSOCK_CB_SET_READ_FUNC_ARG (ssock_cb, BGP_HEADER_SIZE);

  /* Install Header Decoder as the succeeding read_func in SSOCK-CB */
  SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_hdr);

  /* If required number of bytes are present request immediate read */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read >= BGP_HEADER_SIZE)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] KAlive: Requesting immediate Read(%u)",
                   peer->host, BGP_PEER_DIR_STR (peer), BGP_HEADER_SIZE);
      ret = SSOCK_ERR_READ_LOOP;
    }

EXIT:

  return ret;
}

/*
 * LEVEL 1 BGP Message Decoder function:
 * Decodes BGP ROUTE-REFRESH Message
 */
enum ssock_error
bpd_msg_route_refresh (struct stream_sock_cb *ssock_cb,
                       u_int32_t msg_size,
                       struct lib_globals *blg)
{
  u_int8_t orf_name [SU_ADDRSTRLEN];
  struct cqueue_buffer *cq_rbuf;
  u_int8_t when_to_refresh;
  u_int32_t bytes_to_read;
  struct orf_prefix orfp;
  struct bgp_peer *peer;
  enum ssock_error ret;
  u_int8_t orf_action;
  u_int8_t orf_match;
  u_int8_t orf_type;
  u_int16_t orf_len;
  s_int32_t tmp_ret;
  struct ipi_vr *vr;
  u_int8_t psize;
  safi_t safi;
  afi_t afi;

  bytes_to_read = 0;
  ret = SSOCK_ERR_NONE;
  vr = ipi_vr_get_privileged (&BLG);

  /* Sanity check */
  if (! ssock_cb || &BLG != blg)
    {
      zlog_err (&BLG, "[DECODE] R-Refresh: Invalid Sock CB (%X)",
                ssock_cb);
      ret = SSOCK_ERR_INVALID;
      goto EXIT;
    }

  /* Obtain the Socket CB's owning peer */
  peer = (struct bgp_peer *) SSOCK_CB_GET_OWNER (ssock_cb);
  if (! peer || peer->sock_cb != ssock_cb)
    {
      zlog_err (&BLG, "%s-%s [DECODE] R-Refresh: Invalid Sock CB (%X)",
                peer ? peer->host : (u_int8_t *) "?",
                peer ? BGP_PEER_DIR_STR (peer) : "?", ssock_cb);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set BGP VR Context */
  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  /* Obtain the CQ Read Buffer */
  cq_rbuf = SSOCK_CB_GET_READ_CQ_BUF (ssock_cb, &BLG);

  /* If required number of bytes are not present just return */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read < msg_size)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] R-Refresh: Bytes To Read (%u)"
                   " < msg_size (%u)",
                   peer ? peer->host : (u_int8_t *) "?",
                   peer ? BGP_PEER_DIR_STR (peer) : "?",
                   bytes_to_read, msg_size);
      ret = SSOCK_ERR_NONE;
      goto EXIT;
    }

  /* Count the Incoming REFRESH message */
  peer->refresh_in++;

  /* Get 'AFI' value */
  CQUEUE_READ_INT16 (cq_rbuf, afi);
  msg_size -= sizeof (u_int16_t);

  /* Get 'Reserved' field and discard it */
  CQUEUE_READ_INT8 (cq_rbuf, safi);
  msg_size -= 1;

  /* Get 'SAFI' value */
  CQUEUE_READ_INT8 (cq_rbuf, safi);
  msg_size -= 1;

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [DECODE] R-Refresh: AFI/SAFI (%d/%d)",
               peer->host, BGP_PEER_DIR_STR (peer), afi, safi);

  /* Validate 'AFI-SAFI' combination value */
  if (! BGP_AFI_VALID_CHECK (afi)
      || ! BGP_SAFI_VALID_CHECK (safi)
      || ! BGP_AFI_SAFI_SUPPORT_CHECK (afi, safi))
    {
      zlog_warn (&BLG, "%s-%s [DECODE] R-Refresh: AFI-SAFI(%d-%d)"
                 " combination not-supported, Ignoring RR request...",
                 peer->host, BGP_PEER_DIR_STR (peer), afi, safi);

      /* We need to ignore this Route-Refresh message */
      CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, msg_size -
                   (BGP_MSG_ROUTE_REFRESH_MIN_SIZE - BGP_HEADER_SIZE));

      ret = SSOCK_ERR_NONE;
      goto READ_NEXT_MSG;
    }

  /* If RR has not been negotiated, ignore this message */
  if (! CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_ADV))
    {
      zlog_warn (&BLG, "%s-%s [DECODE] R-Refresh: Cap not negotiated"
                 " Ignoring RR request for AFI/SAFI (%d/%d)",
                 peer->host, BGP_PEER_DIR_STR (peer), afi, safi);

      CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, msg_size -
                   (BGP_MSG_ROUTE_REFRESH_MIN_SIZE - BGP_HEADER_SIZE));

      ret = SSOCK_ERR_NONE;
      goto READ_NEXT_MSG;
    }

  /* Decode ORFs */
  if (msg_size)
    {
      if (msg_size < (BGP_MSG_RR_ORF_WHEN2RR_MIN_SIZE +
                      BGP_MSG_RR_ORF_ENTRY_MIN_SIZE ))
        {
          zlog_err (&BLG, "%s-%s [DECODE] R-Refresh: AFI-SAFI(%d-%d)"
                    " Msg-Size(%d) too small for ORF Entry",
                    peer->host, BGP_PEER_DIR_STR (peer),
                    afi, safi, msg_size);

          bpf_event_notify (peer, BPF_EVENT_ROUTE_REFRESH_ERR,
                            BGP_NOTIFY_HEADER_ERR,
                            BGP_NOTIFY_HEADER_BAD_MESLEN, NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Get 'when_to_refresh' value */
      CQUEUE_READ_INT8 (cq_rbuf, when_to_refresh);
      msg_size -= 1;

      /* Validate 'when_to_refresh' value */
      if (when_to_refresh != BGP_ORF_REFRESH_IMMEDIATE
          && when_to_refresh != BGP_ORF_REFRESH_DEFER)
        {
          zlog_err (&BLG, "%s-%s [DECODE] R-Refresh: AFI/SAFI(%d/%d)"
                    " Invalid ORF When2Refresh(%d) value", peer->host,
                    BGP_PEER_DIR_STR (peer), afi, safi, when_to_refresh);

          bpf_event_notify (peer, BPF_EVENT_ROUTE_REFRESH_ERR,
                            BGP_NOTIFY_CEASE, 0, NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /*
       * If Message is RR wout ORFs or if REFRESH_IMMEDIATE,
       * release Route-Announcement lock
       */
      if (! msg_size || when_to_refresh == BGP_ORF_REFRESH_IMMEDIATE)
        {
          if (CHECK_FLAG (peer->af_sflags[BGP_AFI2BAAI (afi)]
                          [BGP_SAFI2BSAI (safi)],
                          PEER_STATUS_ORF_WAIT_REFRESH))
            {
              UNSET_FLAG (peer->af_sflags[BGP_AFI2BAAI (afi)]
                          [BGP_SAFI2BSAI (safi)],
                          PEER_STATUS_ORF_WAIT_REFRESH);
              if (BGP_DEBUG (events, EVENTS))
                zlog_info (&BLG, "%s-%s [DECODE] PEER_STATUS_ORF_WAIT_REFRESH"
                           " unset!\n", peer->host, BGP_PEER_DIR_STR (peer));
            }
          else
            {
              SET_FLAG (peer->af_sflags[BGP_AFI2BAAI (afi)]
                        [BGP_SAFI2BSAI (safi)],
                        PEER_STATUS_ORF_NOT_WAIT_REFRESH);
              if (BGP_DEBUG (events, EVENTS))
                zlog_info (&BLG, "%s-%s [DECODE] PEER_STATUS_ORF_NOT_WAIT_REFRESH"
                           " set!\n", peer->host, BGP_PEER_DIR_STR (peer));
            }
        }

      /* Decode ORF Entries */
      while (msg_size)
        {
          if (msg_size < BGP_MSG_RR_ORF_ENTRY_MIN_SIZE)
            {
              zlog_err (&BLG, "%s-%s [DECODE] R-Refresh: AFI-SAFI"
                        "(%d-%d) Msg-Size(%d) too small for ORF Entry",
                        peer->host, BGP_PEER_DIR_STR (peer), afi, safi,
                        msg_size);

              bpf_event_notify (peer, BPF_EVENT_ROUTE_REFRESH_ERR,
                                BGP_NOTIFY_HEADER_ERR,
                                BGP_NOTIFY_HEADER_BAD_MESLEN, NULL, 0);
              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
            }

          /* Get ORF Type */
          CQUEUE_READ_INT8 (cq_rbuf, orf_type);
          msg_size -= 1;

          /* Get ORF Length */
          CQUEUE_READ_INT16 (cq_rbuf, orf_len);
          msg_size -= sizeof (u_int16_t);

          /* Sanity check of ORF Length */
          if (msg_size < orf_len)
            {
              zlog_err (&BLG, "%s-%s [DECODE] R-Refresh: AFI-SAFI"
                        "(%d-%d) Msg-Size(%d) < ORF Len(%d)",
                        peer->host, BGP_PEER_DIR_STR (peer), afi, safi,
                        msg_size, orf_len);

              bpf_event_notify (peer, BPF_EVENT_ROUTE_REFRESH_ERR,
                                BGP_NOTIFY_HEADER_ERR,
                                BGP_NOTIFY_HEADER_BAD_MESLEN, NULL, 0);
              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
            }

          switch (orf_type)
            {
            case BGP_ORF_TYPE_PREFIX:
            case BGP_ORF_TYPE_PREFIX_OLD:
              /* Prepare ORF prefix-list name */
              pal_snprintf (orf_name, SU_ADDRSTRLEN, "%s.%d.%d",
                            (u_int8_t *) peer->host, afi, safi);

              if (BGP_DEBUG (events, EVENTS))
                zlog_info (&BLG, "%s-%s [DECODE] R-Refresh: ORF Type"
                           ":%d Length:%d Name:%s", peer->host,
                           BGP_PEER_DIR_STR (peer), orf_type, orf_len,
                           orf_name);

              while (msg_size)
                {
                  pal_mem_set (&orfp, 0, sizeof (struct orf_prefix));

                  /* Get ORF Action & Match bits (common-part) */
                  CQUEUE_READ_INT8 (cq_rbuf, orf_action);
                  msg_size -= 1;
                  orf_match = orf_action & BGP_ORF_COMMON_MATCH_MASK;
                  orf_action = orf_action & BGP_ORF_COMMON_ACTION_MASK;

                  if (BGP_DEBUG (events, EVENTS))
                    zlog_info (&BLG, "%s-%s [DECODE] R-Refresh: ORF:%s"
                               " Action:%X Match:%X", peer->host,
                               BGP_PEER_DIR_STR (peer), orf_name,
                               orf_action, orf_match);

                  switch (orf_action)
                    {
                    case BGP_ORF_COMMON_ACTION_REMOVE_ALL:
                      /* Validate ORF Length */
                      if (orf_len != 1)
                        {
                          zlog_err (&BLG, "%s-%s [DECODE] R-Refresh: ORF:%s"
                                    "Invalid REMOVE-ALL ORF Len(%d)", peer->host,
                                    BGP_PEER_DIR_STR (peer), orf_name, orf_len);

                          bpf_event_notify (peer, BPF_EVENT_ROUTE_REFRESH_ERR,
                                            BGP_NOTIFY_HEADER_ERR,
                                            BGP_NOTIFY_HEADER_BAD_MESLEN, NULL, 0);
                          ret = SSOCK_ERR_CLOSE;
                          goto EXIT;
                        }

                      prefix_bgp_orf_remove_all (vr, orf_name);
                      break;

                    case BGP_ORF_COMMON_ACTION_ADD:
                    case BGP_ORF_COMMON_ACTION_REMOVE:
                      /* Validate ORF Length */
                      if (orf_len < BGP_ORF_PREFIX_ENTRY_MIN_SIZE)
                        {
                          zlog_err (&BLG, "%s-%s [DECODE] R-Refresh: ORF:%s"
                                    "Invalid Prefix ORF Len(%d)", peer->host,
                                    BGP_PEER_DIR_STR (peer), orf_name, orf_len);

                          bpf_event_notify (peer, BPF_EVENT_ROUTE_REFRESH_ERR,
                                            BGP_NOTIFY_HEADER_ERR,
                                            BGP_NOTIFY_HEADER_BAD_MESLEN, NULL, 0);
                          ret = SSOCK_ERR_CLOSE;
                          goto EXIT;
                        }

                      /* Get 'Sequence' value */
                      CQUEUE_READ_INT32 (cq_rbuf, orfp.seq);
                      msg_size -= sizeof (u_int32_t);

                      /* Get 'Min Len' value */
                      CQUEUE_READ_INT8 (cq_rbuf, orfp.ge);
                      msg_size -= 1;

                      /* Get 'Max Len' value */
                      CQUEUE_READ_INT8 (cq_rbuf, orfp.le);
                      msg_size -= 1;

                      /* Get 'Prefix Len' value */
                      CQUEUE_READ_INT8 (cq_rbuf, orfp.p.prefixlen);
                      msg_size -= 1;

                      /* Calculate PreLen in Bytes and Validate ORF Len */
                      psize = PSIZE (orfp.p.prefixlen);
                      if (orf_len < BGP_ORF_PREFIX_ENTRY_MIN_SIZE + psize)
                        {
                          zlog_err (&BLG, "%s-%s [DECODE] R-Refresh: "
                                    "ORF:%s ORF Len(%d) < psize(%d) + 7",
                                    peer->host, BGP_PEER_DIR_STR (peer),
                                    orf_name, orf_len, psize);

                          bpf_event_notify (peer, BPF_EVENT_ROUTE_REFRESH_ERR,
                                            BGP_NOTIFY_HEADER_ERR,
                                            BGP_NOTIFY_HEADER_BAD_MESLEN, NULL, 0);
                          ret = SSOCK_ERR_CLOSE;
                          goto EXIT;
                        }

                      /* Set the AF-Family for the prefix */
                      orfp.p.family = afi2family (afi);
                      if (psize)
                        {
                          CQUEUE_READ_NBYTES (cq_rbuf,
                                              &orfp.p.u.prefix, psize);
                          msg_size -= psize;
                        }

                      if (BGP_DEBUG (events, EVENTS))
                        zlog_info (&BLG, "%s-%s [DECODE] R-Refresh: "
                                   "ORF:%s seq %u %O ge %d le %d",
                                   peer->host, BGP_PEER_DIR_STR (peer),
                                   orf_name, orfp.seq, &orfp.p, orfp.ge,
                                   orfp.le);
                      tmp_ret = prefix_bgp_orf_set (vr, orf_name, afi, &orfp,
                                (orf_match == BGP_ORF_COMMON_MATCH_PERMIT),
                                (orf_action == BGP_ORF_COMMON_ACTION_ADD));
                      if (tmp_ret != CLI_SUCCESS)
                        {
                          zlog_warn (&BLG, "%s-%s [DECODE] R-Refresh:"
                                     "ORF(%s) Misformatted prefixlist. "
                                     "Removing All its prefixlists...",
                                     peer->host, BGP_PEER_DIR_STR (peer),
                                     orf_name);

                          prefix_bgp_orf_remove_all (vr, orf_name);
                        }
                      break;

                    default:
                      break;
                    }
                }

              /* Get the Prefix-ORF linkage, if any */
              peer->orf_plist[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)] =
              prefix_list_lookup (vr, AFI_ORF_PREFIX, orf_name);
              break;

            default:
              /* Ignore ALL un-recognised ORF-Types */
              zlog_warn (&BLG, "%s-%s [DECODE] R-Refresh: Ignoring "
                         " un-recognised ORF Type:%d...",
                         peer->host, BGP_PEER_DIR_STR (peer),
                         orf_type);

              CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, orf_len);
              msg_size -= orf_len;
              break;
            }
        }
    }
  else
    {
      /*  When msg_size is zero, we need unset the
          PEER_STATUS_ORF_WAIT_REFRESH flag.  */
      if (CHECK_FLAG (peer->af_sflags[BGP_AFI2BAAI (afi)]
                      [BGP_SAFI2BSAI (safi)],
                      PEER_STATUS_ORF_WAIT_REFRESH))
        {
          UNSET_FLAG (peer->af_sflags[BGP_AFI2BAAI (afi)]
                      [BGP_SAFI2BSAI (safi)],
                      PEER_STATUS_ORF_WAIT_REFRESH);
          if (BGP_DEBUG (events, EVENTS))
            zlog_info (&BLG, "%s-%s [DECODE] PEER_STATUS_ORF_WAIT_REFRESH"
                       " unset!\n", peer->host, BGP_PEER_DIR_STR (peer));
        }
      else
        {
          SET_FLAG (peer->af_sflags[BGP_AFI2BAAI (afi)]
                    [BGP_SAFI2BSAI (safi)],
                    PEER_STATUS_ORF_NOT_WAIT_REFRESH);
          if (BGP_DEBUG (events, EVENTS))
            zlog_info (&BLG, "%s-%s [DECODE] PEER_STATUS_ORF_NOT_WAIT_REFRESH"
                       " set!\n", peer->host, BGP_PEER_DIR_STR (peer));
        }
    }

  /* Set AF-Flag for Route-Refresh received */
  SET_FLAG (peer->af_sflags [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)],
            PEER_STATUS_AF_ROUTE_REFRESH_RCVD);

  /* Generate BGP Peer FSM Valid ROUTE-REFRESH Event */
  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_ROUTE_REFRESH_VALID);

READ_NEXT_MSG:

  /* Reset argument for succeeding read_func, viz., Header Decoder */
  SSOCK_CB_SET_READ_FUNC_ARG (ssock_cb, BGP_HEADER_SIZE);

  /* Install Header Decoder as the succeeding read_func in SSOCK-CB */
  SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_hdr);

  /* If required number of bytes are present request immediate read */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read >= BGP_HEADER_SIZE)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] R-Refresh: Requesting immediate Read (%u)",
                   peer->host, BGP_PEER_DIR_STR (peer), BGP_HEADER_SIZE);
      ret = SSOCK_ERR_READ_LOOP;
    }

EXIT:

  return ret;
}

/*
 * LEVEL 1 BGP Message Decoder function:
 * Decodes BGP DYNAMIC-CAPABILITY Message
 */
enum ssock_error
bpd_msg_dyna_cap (struct stream_sock_cb *ssock_cb,
                  u_int32_t msg_size,
                  struct lib_globals *blg)
{
  struct cqueue_buffer *cq_rbuf;
  struct bgp_capability dyn_cap;
  u_int32_t bytes_to_read;
  struct bgp_peer *peer;
  enum ssock_error ret;
  u_int8_t cap_action;
  u_int32_t cap_read;
  struct capbilitymessage capabilitymsg;

  pal_mem_set (&capabilitymsg.cap_header.action_header, 0, 1);
  bytes_to_read = 0;
  ret = SSOCK_ERR_NONE;

  /* Sanity check */
  if (! ssock_cb || &BLG != blg)
    {
      zlog_err (&BLG, "[DECODE] DYNA-CAP: Invalid Sock CB (%X)",
                ssock_cb);
      ret = SSOCK_ERR_INVALID;
      goto EXIT;
    }

  /* Obtain the Socket CB's owning peer */
  peer = (struct bgp_peer *) SSOCK_CB_GET_OWNER (ssock_cb);
  if (! peer || peer->sock_cb != ssock_cb)
    {
      zlog_err (&BLG, "%s-%s [DECODE] DYNA-CAP: Invalid Sock CB (%X)",
                peer ? peer->host : (u_int8_t *) "?",
                peer ? BGP_PEER_DIR_STR (peer) : "?", ssock_cb);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set BGP VR Context */
  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  /* Obtain the CQ Read Buffer */
  cq_rbuf = SSOCK_CB_GET_READ_CQ_BUF (ssock_cb, &BLG);

  /* If required number of bytes are not present just return */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read < msg_size)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] DYNA-CAP: Bytes To Read (%u)"
                   " < msg_size (%u)",
                   peer ? peer->host : (u_int8_t *) "?",
                   peer ? BGP_PEER_DIR_STR (peer) : "?",
                   bytes_to_read, msg_size);
      ret = SSOCK_ERR_NONE;
      goto EXIT;
    }

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [DECODE] DYNA-CAP: msg_size %d",
               peer->host, BGP_PEER_DIR_STR (peer), msg_size);

  /* Parse all the Capability Optional Parameters */
  while (msg_size)
    {
      /* Get 'Action' value */
      CQUEUE_READ_INT8 (cq_rbuf, capabilitymsg.cap_header.action_header);
    
      /* sending ACK on receiving Init/ACK bit set is not supported yet */
      cap_action = capabilitymsg.cap_header.action;
 
      /* Get 'Secquence' value */
      CQUEUE_READ_INT32 (cq_rbuf, capabilitymsg.seqno);
 
      /* Get 'Cap Code' value */
      CQUEUE_READ_INT8 (cq_rbuf, dyn_cap.cap_code);

      /* Get 'Cap Length' value */
      CQUEUE_READ_INT8 (cq_rbuf, dyn_cap.cap_len);

      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] DYNA-CAP: Action(%d) Secquence(%d)  Code(%d)"
                   " Len(%d)", peer->host, BGP_PEER_DIR_STR (peer),
                   cap_action,capabilitymsg.seqno , dyn_cap.cap_code, dyn_cap.cap_len);

      /* Account for the bytes read */
      msg_size -= BGP_MSG_CAP_OPT_MIN_SIZE;

      /* Reset the number of bytes of 'Cap-value' field read */
      cap_read = 0;

      /* Validate the length */
      if (msg_size < dyn_cap.cap_len
          || (msg_size != dyn_cap.cap_len
              && (msg_size - dyn_cap.cap_len) < BGP_MSG_CAP_OPT_MIN_SIZE))
        {
          zlog_err (&BLG, "%s-%s [DECODE] DYNA-CAP: Cap-len(%d) > "
                    "msg_size(%d), Cap-code %d",
                    peer->host, BGP_PEER_DIR_STR (peer), dyn_cap.cap_len,
                    msg_size, dyn_cap.cap_code);

          bpf_event_notify_cap (cq_rbuf, peer,
                                BPF_EVENT_DYNA_CAP_ERR,
                                cap_action, dyn_cap.cap_code,
                                dyn_cap.cap_len,
                                msg_size, cap_read,
                                BGP_NOTIFY_CAPABILITY_ERR,
                                BGP_NOTIFY_CAPABILITY_INVALID_LENGTH);

          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Validate 'action' value */
      if (cap_action != BGP_CAPABILITY_ACTION_SET
          && cap_action != BGP_CAPABILITY_ACTION_UNSET)
        {
          zlog_err (&BLG, "%s-%s [DECODE] DYNA-CAP: action(%d) invalid"
                    ", Cap-code %d", peer->host, BGP_PEER_DIR_STR (peer),
                    cap_action, dyn_cap.cap_code);

          bpf_event_notify_cap (cq_rbuf, peer,
                                BPF_EVENT_DYNA_CAP_ERR,
                                cap_action, dyn_cap.cap_code,
                                dyn_cap.cap_len,
                                msg_size, cap_read,
                                BGP_NOTIFY_CAPABILITY_ERR,
                                BGP_NOTIFY_CAPABILITY_INVALID_ACTION);

          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Parse the Capability Attributes */
      switch (dyn_cap.cap_code)
        {
        case BGP_CAPABILITY_CODE_MP:
          /* Get 'Cap-AFI' */
          CQUEUE_READ_INT16 (cq_rbuf, dyn_cap.cap_mp.afi);
          msg_size -= sizeof (u_int16_t);
          cap_read += sizeof (u_int16_t);

          /* Get and ignore 'Cap-resv' */
          CQUEUE_READ_INT8 (cq_rbuf, dyn_cap.cap_mp.reserved);
          msg_size -= 1;
          cap_read -= 1;

          /* Get 'Cap-SAFI' */
          CQUEUE_READ_INT8 (cq_rbuf, dyn_cap.cap_mp.safi);
          msg_size -= 1;
          cap_read -= 1;

          /* Ignore capability when override-capability is set */
          if (CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
            {
              zlog_warn (&BLG, "%s-%s [DECODE] DYNA-CAP: Override Cap"
                         " set, Ignoring MP Cap", peer->host,
                         BGP_PEER_DIR_STR (peer));

              break;
            }

          /* Validate AFI-SAFI combination */
          if (! BGP_AFI_SAFI_SUPPORT_CHECK (dyn_cap.cap_mp.afi,
                                            dyn_cap.cap_mp.safi))
            {
              zlog_err (&BLG, "%s-%s [DECODE] DYNA-CAP: AFI/SAFI(%d/"
                        "%d) !supported", peer->host,
                        BGP_PEER_DIR_STR (peer), dyn_cap.cap_mp.afi,
                        dyn_cap.cap_mp.safi);

              bpf_event_notify_cap (cq_rbuf, peer,
                                    BPF_EVENT_DYNA_CAP_ERR,
                                    cap_action, dyn_cap.cap_code,
                                    dyn_cap.cap_len,
                                    msg_size, cap_read,
                                    BGP_NOTIFY_CAPABILITY_ERR,
                                    BGP_NOTIFY_CAPABILITY_MALFORMED_CODE);

              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
            }

          if (BGP_DEBUG (events, EVENTS))
            zlog_info (&BLG, "%s-%s [DECODE] DYNA-CAP: MP Cap "
                       "AFI/SAFI(%d/%d) Action: %s", peer->host,
                       BGP_PEER_DIR_STR (peer), dyn_cap.cap_mp.afi,
                       dyn_cap.cap_mp.safi,
                       cap_action == BGP_CAPABILITY_ACTION_SET ?
                       "Set" : "Unset");

          peer->afc_recv [BGP_AFI2BAAI (dyn_cap.cap_mp.afi)]
                         [BGP_SAFI2BSAI (dyn_cap.cap_mp.safi)] =
                          (cap_action == BGP_CAPABILITY_ACTION_SET);
          break;

        case BGP_CAPABILITY_CODE_REFRESH_OLD:
        case BGP_CAPABILITY_CODE_REFRESH:
          /* Validate Capability length */
          if (dyn_cap.cap_len != 0)
            {
              zlog_err (&BLG, "%s-%s [DECODE] DYNA CAP: RR-Cap"
                        " len error %d", peer->host,
                        BGP_PEER_DIR_STR (peer), dyn_cap.cap_len);

              bpf_event_notify_cap (cq_rbuf, peer,
                                    BPF_EVENT_DYNA_CAP_ERR,
                                    cap_action, dyn_cap.cap_code,
                                    dyn_cap.cap_len,
                                    msg_size, cap_read,
                                    BGP_NOTIFY_CAPABILITY_ERR,
                                    BGP_NOTIFY_CAPABILITY_INVALID_LENGTH);

              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
            }

          if (BGP_DEBUG (events, EVENTS))
            zlog_info (&BLG, "%s-%s [DECODE] DYNA CAP:"
                       " RR Cap(%s) for all address-families",
                       peer->host, BGP_PEER_DIR_STR (peer),
                       dyn_cap.cap_code == BGP_CAPABILITY_CODE_REFRESH_OLD ?
                       "old" : "new");

          /* BGP refresh capability */
          if (cap_action == BGP_CAPABILITY_ACTION_SET)
            {
              if (dyn_cap.cap_code == BGP_CAPABILITY_CODE_REFRESH_OLD)
                SET_FLAG (peer->cap, PEER_CAP_REFRESH_OLD_RCV);
              else
                SET_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV);
            }
          else
            {
              if (dyn_cap.cap_code == BGP_CAPABILITY_CODE_REFRESH_OLD)
                UNSET_FLAG (peer->cap, PEER_CAP_REFRESH_OLD_RCV);
              else
                UNSET_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV);
            }
          break;

        default:
          zlog_warn (&BLG, "%s-%s [DECODE] Open Cap:"
                     " unrecognized capability code %d len %d",
                     peer->host, BGP_PEER_DIR_STR (peer),
                     dyn_cap.cap_code, dyn_cap.cap_len);
          break;
        } /* end switch (dyn_cap.cap_code) */
    }

  /* Count the Incoming DYNA-CAP message */
  peer->dynamic_cap_in++;

  /* Generate BGP Peer FSM Valid ROUTE-REFRESH Event */
  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_DYNA_CAP_VALID);

  /* Reset argument for succeeding read_func, viz., Header Decoder */
  SSOCK_CB_SET_READ_FUNC_ARG (ssock_cb, BGP_HEADER_SIZE);

  /* Install Header Decoder as the succeeding read_func in SSOCK-CB */
  SSOCK_CB_SET_READ_FUNC (ssock_cb, bpd_msg_hdr);

  /* If required number of bytes are present request immediate read */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read >= BGP_HEADER_SIZE)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] R-Refresh: Requesting immediate Read (%u)",
                   peer->host, BGP_PEER_DIR_STR (peer), BGP_HEADER_SIZE);
      ret = SSOCK_ERR_READ_LOOP;
    }

EXIT:

  return ret;
}

/*
 * LEVEL 2 BGP Message Decoder function:
 * Decodes BGP OPEN Message Optional Parameters
 */
enum ssock_error
bpd_msg_open_opt (struct cqueue_buffer *cq_rbuf,
                  struct bgp_peer *peer,
                  u_int32_t opt_size)
{
  u_int8_t not_err_data[BGP_MAX_PACKET_SIZE];
  u_int32_t bytes_to_read;
  enum ssock_error ret;
  bool_t capability;
  u_int8_t opt_type;
  u_int8_t *not_err;
  u_int8_t opt_len;

  ret = SSOCK_ERR_NONE;
  not_err = not_err_data;
  capability = PAL_FALSE;

  /* If required number of bytes are not present generate error */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read < opt_size)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open Opt: Bytes To Read (%u)"
                " < opt_size (%u)",
                peer ? peer->host : (u_int8_t *) "?",
                peer ? BGP_PEER_DIR_STR (peer) : "?",
                bytes_to_read, opt_size);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Parse all the Optional Attributes */
  while (opt_size)
    {
      /* Check the length */
      if (opt_size < BGP_MSG_OPEN_OPT_MIN_SIZE)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Open Opt: Opt-length error %d",
                    peer->host, BGP_PEER_DIR_STR (peer), opt_size);

          bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                            BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Get 'Option-type' */
      CQUEUE_READ_INT8 (cq_rbuf, opt_type);
      opt_size--;

      /* Get 'Option-len' */
      CQUEUE_READ_INT8 (cq_rbuf, opt_len);
      opt_size--;

      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] Open Opt: Option Type %u,"
                   " Option Len %u", peer->host,
                   BGP_PEER_DIR_STR (peer), opt_type, opt_len);

      /* Option length check. */
      if (opt_len > opt_size)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Open Opt: Opt-length error %d",
                    peer->host, BGP_PEER_DIR_STR (peer), opt_len);

          bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                            BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      switch (opt_type)
        {
        case BGP_OPEN_OPT_CAP:
            if (CHECK_FLAG (peer->flags, PEER_FLAG_DONT_CAPABILITY))
              {
                zlog_err (&BLG, "%s-%s [DECODE] Open Opt: Dont-Cap, Cap received",
                          peer->host, BGP_PEER_DIR_STR (peer));
                bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                                  BGP_NOTIFY_OPEN_ERR,
                                  BGP_NOTIFY_OPEN_UNSUP_PARAM,
                                  NULL, 0);
                ret = SSOCK_ERR_CLOSE;
              }
            else
              ret = bpd_msg_open_cap (cq_rbuf, peer, opt_len, &not_err);

            if (ret != SSOCK_ERR_NONE)
              goto EXIT;

            capability = PAL_TRUE;
            break;

        case BGP_OPEN_OPT_AUTH:
        default:
            zlog_err (&BLG, "%s-%s [DECODE] Open Opt: Auth not supported",
                      peer->host, BGP_PEER_DIR_STR (peer));

            bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                              BGP_NOTIFY_OPEN_ERR,
                              BGP_NOTIFY_OPEN_UNSUP_PARAM,
                              NULL, 0);
            ret = SSOCK_ERR_CLOSE;
            goto EXIT;
            break;
        }

      opt_size -= opt_len;
    }

  /* If Unsupported Capability exists, send notification in case of strict match */
  if ((not_err != not_err_data)
      && CHECK_FLAG (peer->flags, PEER_FLAG_STRICT_CAP_MATCH))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open Opt: Strict, Err-Data present",
                peer->host, BGP_PEER_DIR_STR (peer));

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR,
                        BGP_NOTIFY_OPEN_UNSUP_CAPBL,
                        not_err_data,
                        not_err - not_err_data);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Enforce match of Configured and Negotiated Capabilities */
  if (capability == PAL_TRUE
      && CHECK_FLAG (peer->flags, PEER_FLAG_STRICT_CAP_MATCH)
      && PAL_TRUE != bgp_peer_strict_cap_same (peer))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open Opt: Strict, Cap mis-match",
                peer->host, BGP_PEER_DIR_STR (peer));

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR,
                        BGP_NOTIFY_OPEN_UNSUP_CAPBL,
                        NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* If no common Capabilities, send Unsupported Capability error */
  if (capability == PAL_TRUE
      && ! CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
    {
      if (! peer->cap
          && ! peer->afc_recv [BGP_AFI2BAAI (AFI_IP)]
                              [BGP_SAFI2BSAI (SAFI_UNICAST)]
          && ! peer->afc_recv [BGP_AFI2BAAI (AFI_IP)]
                              [BGP_SAFI2BSAI (SAFI_MULTICAST)]
#ifdef HAVE_IPV6
          && BGP_CAP_HAVE_IPV6
          && ! peer->afc_recv [BGP_AFI2BAAI (AFI_IP6)]
                              [BGP_SAFI2BSAI (SAFI_UNICAST)]
          && ! peer->afc_recv [BGP_AFI2BAAI (AFI_IP6)]
                              [BGP_SAFI2BSAI (SAFI_MULTICAST)]
#endif /* HAVE_IPV6 */
         )
        {
          zlog_err (&BLG, "%s-%s [DECODE] Open Opt: No common capabilities",
                    peer->host, BGP_PEER_DIR_STR (peer));

          if (not_err != not_err_data)
            bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                              BGP_NOTIFY_OPEN_ERR,
                              BGP_NOTIFY_OPEN_UNSUP_CAPBL,
                              not_err_data,
                              not_err - not_err_data);
          else
            bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                              BGP_NOTIFY_OPEN_ERR,
                              BGP_NOTIFY_OPEN_UNSUP_CAPBL,
                              NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }
  else if (capability == PAL_FALSE)
    SET_FLAG (peer->cap, PEER_CAP_NONE_RCV);

EXIT:

  return ret;
}

/*
 * LEVEL 2 BGP Message Decoder function:
 * Decodes BGP UPDATE Message Attributes
 */
enum ssock_error
bpd_msg_update_attr (struct cqueue_buffer *cq_rbuf,
                     struct bgp_peer *peer,
                     u_int32_t attr_size,
                     struct attr *attr,
                     struct bgp_nlri_snap_shot *bnss)
{
  u_int8_t attr_seen[BGP_ATTR_BITMAP_SIZE];
  u_int32_t bytes_to_read;
  enum ssock_error ret;
  u_int16_t attr_len;
  u_int8_t attr_type;
  u_int8_t attr_flag;

  ret = SSOCK_ERR_NONE;
  attr_type = 0;
  attr_flag = 0;
  attr_len = 0;

  /* If required number of bytes are not present generate error */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read < attr_size)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Update Attr: Bytes To Read (%u)"
                " < attr_size (%u)", peer->host, BGP_PEER_DIR_STR (peer),
                bytes_to_read, attr_size);

      bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                        BGP_NOTIFY_UPDATE_ERR,
                        BGP_NOTIFY_UPDATE_MAL_ATTR,
                        NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Initialize 'attr_seen' bitmap */
  pal_mem_set (attr_seen, 0, BGP_ATTR_BITMAP_SIZE);

  /* Parse all the UPDATE Message Attributes */
  while (attr_size)
    {
      /* Check remaining length check.*/
      if (attr_size < BGP_ATTR_MIN_SIZE)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Update Attr: Attr-len error %d",
                    peer->host, BGP_PEER_DIR_STR (peer), attr_size);

          bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                            BGP_NOTIFY_UPDATE_ERR,
                            BGP_NOTIFY_UPDATE_MAL_ATTR,
                            NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Get 'attr_flag' */
      CQUEUE_READ_INT8 (cq_rbuf, attr_flag);
      attr_flag &= 0xF0;
      attr_size--;

      /* Get 'attr_type'. */
      CQUEUE_READ_INT8 (cq_rbuf, attr_type);
      attr_size--;

      /* Remaining length check if extended attribue length */
      if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_EXTLEN))
        if (attr_size < BGP_ATTR_EXT_LEN_SIZE)
          {
            zlog_err (&BLG, "%s-%s [DECODE] Update Attr: Ext-Attr-len"
                      " (%d) > attr_size (%d)",
                      peer->host, BGP_PEER_DIR_STR (peer),
                      BGP_ATTR_EXT_LEN_SIZE, attr_size);

            bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                              BGP_NOTIFY_UPDATE_ERR,
                              BGP_NOTIFY_UPDATE_MAL_ATTR,
                              NULL, 0);
            ret = SSOCK_ERR_CLOSE;
            goto EXIT;
          }

      /* Attribute re-occurance check */
      if (CHECK_BITMAP (attr_seen, attr_type))
        {
          zlog_err (&BLG, "%s-%s [DECODE] Update Attr: Attr-type (%d)"
                    " occured twice",
                    peer->host, BGP_PEER_DIR_STR (peer), attr_type);

          bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                            BGP_NOTIFY_UPDATE_ERR,
                            BGP_NOTIFY_UPDATE_MAL_ATTR,
                            NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Set 'attr_type' to bitmap to check for re-occurance */
      SET_BITMAP (attr_seen, attr_type);

      /* Get 'attr_len' */
      if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_EXTLEN))
        {
          CQUEUE_READ_INT16 (cq_rbuf, attr_len);
          attr_size -= sizeof (u_int16_t);
        }
      else
        {
          CQUEUE_READ_INT8 (cq_rbuf, attr_len);
          attr_size--;
        }

      /* Validate 'attr_len' */
      if (attr_len > attr_size)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Update Attr: Attr-len (%d)"
                    " > attr_size (%d)",
                    peer->host, BGP_PEER_DIR_STR (peer),
                    attr_len, attr_size);

          bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                 attr_type, attr_len, attr_size,
                                 0, BGP_NOTIFY_UPDATE_ERR,
                                 BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Parse the recognised Path-Attributes */
      switch (attr_type)
        {
        case BGP_ATTR_ORIGIN:
          ret = bpd_msg_attr_origin (cq_rbuf, peer, attr_flag,
                                     attr_type, attr_len, attr);
          break;
        case BGP_ATTR_AS_PATH:
#ifndef HAVE_EXT_CAP_ASN
          ret = bpd_msg_attr_aspath (cq_rbuf, peer, attr_flag,
                                     attr_type, attr_len, attr);
          break;
#else
          ret = bpd_msg_attr_new_aspath (cq_rbuf, peer, attr_flag,
                                         attr_type, attr_len, attr);
          break;
          case BGP_ATTR_AS4_PATH:
            if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
               ret = bpd_msg_attr_as4path (cq_rbuf, peer, attr_flag,
                                        attr_type, attr_len, attr); 
            else 
              ret = bpd_msg_attr_unknown (cq_rbuf, peer, attr_flag,
                                      attr_type, attr_len, attr);
          break; 
#endif /* HAVE_EXT_CAP_ASN */         

        case BGP_ATTR_NEXT_HOP:
          ret = bpd_msg_attr_nhop (cq_rbuf, peer, attr_flag,
                                   attr_type, attr_len, attr);
          break;

        case BGP_ATTR_MULTI_EXIT_DISC:
          ret = bpd_msg_attr_med (cq_rbuf, peer, attr_flag,
                                  attr_type, attr_len, attr);
          break;

        case BGP_ATTR_LOCAL_PREF:
          ret = bpd_msg_attr_locpref (cq_rbuf, peer, attr_flag,
                                      attr_type, attr_len, attr);
          break;

        case BGP_ATTR_ATOMIC_AGGREGATE:
          ret = bpd_msg_attr_atomic (cq_rbuf, peer, attr_flag,
                                     attr_type, attr_len, attr);
          break;

        case BGP_ATTR_AGGREGATOR:
#ifndef HAVE_EXT_CAP_ASN
          ret = bpd_msg_attr_aggregator (cq_rbuf, peer, attr_flag,
                                         attr_type, attr_len, attr);
          break;
#else
          ret = bpd_msg_attr_new_aggregator (cq_rbuf, peer, attr_flag,
                                             attr_type, attr_len, attr);
          break;
#endif /* HAVE_EXT_CAP_ASN */
#ifdef HAVE_EXT_CAP_ASN
          case BGP_ATTR_AS4_AGGREGATOR:
            if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
              ret = bpd_msg_attr_as4_aggregator (cq_rbuf, peer, attr_flag,
                                                attr_type, attr_len, attr);
            else
              ret = bpd_msg_attr_unknown (cq_rbuf, peer, attr_flag,
                                          attr_type, attr_len, attr);
          break; 
#endif /* HAVE_EXT_CAP_ASN */       
        
        case BGP_ATTR_COMMUNITIES:
          ret = bpd_msg_attr_comm (cq_rbuf, peer, attr_flag,
                                   attr_type, attr_len, attr);
          break;

        case BGP_ATTR_EXT_COMMUNITIES:
          ret = bpd_msg_attr_ecomm (cq_rbuf, peer, attr_flag,
                                    attr_type, attr_len, attr);
          break;

        case BGP_ATTR_ORIGINATOR_ID:
          ret = bpd_msg_attr_orig_id (cq_rbuf, peer, attr_flag,
                                      attr_type, attr_len, attr);
          break;

        case BGP_ATTR_CLUSTER_LIST:
          ret = bpd_msg_attr_cluster (cq_rbuf, peer, attr_flag,
                                      attr_type, attr_len, attr);
          break;

        case BGP_ATTR_MP_REACH_NLRI:
          ret = bpd_msg_attr_mp_reach (cq_rbuf, peer, attr_flag,
                                       attr_type, attr_len, attr,
                                       bnss);
          break;

        case BGP_ATTR_MP_UNREACH_NLRI:
          ret = bpd_msg_attr_mp_unreach (cq_rbuf, peer, attr_flag,
                                         attr_type, attr_len, attr,
                                         bnss);
          break;

        default:
          ret = bpd_msg_attr_unknown (cq_rbuf, peer, attr_flag,
                                      attr_type, attr_len, attr);
          break;
        }

      /* Account for the Attr Len just parsed */
      attr_size -= attr_len;

      /* Exit upon error */
      if (ret != SSOCK_ERR_NONE)
        goto EXIT;
    }

  /* Finally intern Unknown-Transitive attribute */
  if (attr->transit)
    attr->transit = transit_intern (attr->transit);

  /* Dump the attribute */
#ifdef HAVE_BGP_DUMP
  if (BGP_DEBUG (events, EVENTS) || BGP_DEBUG (update, UPDATE_IN))
    {
      u_int8_t attrstr [BGP_MAX_PACKET_SIZE];

      bgp_dump_attr (peer, attr, attrstr, BGP_MAX_PACKET_SIZE);
      zlog_info (&BLG, "%s-%s [DECODE] Update Attr: ATTR log: %s",
                 peer->host, BGP_PEER_DIR_STR (peer), attrstr);
    }
#endif /* HAVE_BGP_DUMP */

EXIT:

  if (ret == SSOCK_ERR_READ_LOOP)
    CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, attr_size);

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes OPEN Message Capabilities Optional Parameter
 */
enum ssock_error
bpd_msg_open_cap (struct cqueue_buffer *cq_rbuf,
                  struct bgp_peer *peer,
                  u_int32_t cap_size,
                  u_int8_t **pp_not_err)
{
  struct bgp_capability bo_cap;
  u_int32_t bytes_to_read;
  enum ssock_error ret;

  ret = SSOCK_ERR_NONE;

  /* If required number of bytes are not present generate error */
  bytes_to_read = CQUEUE_BUF_GET_BYTES_TBR (cq_rbuf);
  if (bytes_to_read < cap_size)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open Cap: Bytes To Read (%u)"
                " < cap_size (%u)",
                peer ? peer->host : (u_int8_t *) "?",
                peer ? BGP_PEER_DIR_STR (peer) : "?",
                bytes_to_read, cap_size);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Parse all the Capability Optional Parameters */
  while (cap_size)
    {
      /* Check the length */
      if (cap_size < BGP_MSG_OPEN_OPT_CAP_MIN_SIZE)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Open Cap: Cap-len error (%u)",
                    peer->host, BGP_PEER_DIR_STR (peer), cap_size);

          bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                            BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Get 'Option-type' */
      CQUEUE_READ_INT8 (cq_rbuf, bo_cap.cap_code);
      cap_size--;

      /* Get 'Option-len' */
      CQUEUE_READ_INT8 (cq_rbuf, bo_cap.cap_len);
      cap_size--;

      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [DECODE] Open Cap: Cap Code %u,"
                   " Cap Len %u", peer->host, BGP_PEER_DIR_STR (peer),
                   bo_cap.cap_code, bo_cap.cap_len);

      /* Validate Option length */
      if (bo_cap.cap_len > cap_size)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Open Cap: Cap-length error %d",
                    peer->host, BGP_PEER_DIR_STR (peer), bo_cap.cap_len);

          bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                            BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Parse the Capability Attributes */
      switch (bo_cap.cap_code)
        {
        case BGP_CAPABILITY_CODE_REFRESH:
        case BGP_CAPABILITY_CODE_REFRESH_OLD:
          /* Validate Capability length */
          if (bo_cap.cap_len != 0)
            {
              zlog_err (&BLG, "%s-%s [DECODE] Open Cap: RR-Cap"
                        " len error %d", peer->host,
                        BGP_PEER_DIR_STR (peer), bo_cap.cap_len);

              bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                                BGP_NOTIFY_OPEN_ERR, 0,
                                NULL, 0);

              CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, cap_size);

              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
            }

          if (BGP_DEBUG (events, EVENTS))
            zlog_info (&BLG, "%s-%s [DECODE] Open Cap:"
                       " RR Cap(%s) for all address-families",
                       peer->host, BGP_PEER_DIR_STR (peer),
                       bo_cap.cap_code == BGP_CAPABILITY_CODE_REFRESH_OLD ?
                       "old" : "new");

          if (bo_cap.cap_code == BGP_CAPABILITY_CODE_REFRESH_OLD)
            SET_FLAG (peer->cap, PEER_CAP_REFRESH_OLD_RCV);
          else
            SET_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV);
          break;

        case BGP_CAPABILITY_CODE_DYNAMIC:
        case BGP_CAPABILITY_CODE_DYNAMIC_OLD:
          
          if (BGP_DEBUG (events, EVENTS))
            zlog_info (&BLG, "%s-%s [DECODE] Open DYN: Dynamic Cap"
                       " recvd", peer->host, BGP_PEER_DIR_STR (peer));
          if (bo_cap.cap_len != 0)
          {
              ret = bpd_msg_open_cap_code_dynamic (cq_rbuf, peer, &bo_cap,
                                             &cap_size, pp_not_err);
          }

          SET_FLAG (peer->cap, PEER_CAP_DYNAMIC_RCV);
          break;

        case BGP_CAPABILITY_CODE_MP:
          ret = bpd_msg_open_cap_mp (cq_rbuf, peer, &bo_cap,
                                     &cap_size, pp_not_err);
          break;

        case BGP_CAPABILITY_CODE_ORF:
        case BGP_CAPABILITY_CODE_ORF_OLD:
          ret = bpd_msg_open_cap_orf (cq_rbuf, peer, &bo_cap,
                                      &cap_size);
           
          break;

        /* 4-octet ASN Capability. */
#ifdef HAVE_EXT_CAP_ASN
        case BGP_CAPABILITY_CODE_EXTASN:
          ret = bpd_msg_open_cap_extasn (cq_rbuf, peer, &bo_cap,
                                         &cap_size, pp_not_err);
          break;
#endif /* HAVE_EXT_CAP_ASN */  

        default:
          zlog_warn (&BLG, "%s-%s [DECODE] Open Cap:"
                     " unrecognized capability code %d len %d",
                     peer->host, BGP_PEER_DIR_STR (peer),
                     bo_cap.cap_code, bo_cap.cap_len);

          /* Store unsupported Cap-data */
          (*pp_not_err)[0] = bo_cap.cap_code;
          (*pp_not_err)[1] = bo_cap.cap_len;
          CQUEUE_READ_NBYTES(cq_rbuf, &(*pp_not_err)[2],
                             bo_cap.cap_len);
          (*pp_not_err) += bo_cap.cap_len + 2;
          cap_size -= bo_cap.cap_len;
          break;

        } /* end switch (bo_cap.cap_code) */

        if (ret != SSOCK_ERR_NONE)
          goto EXIT;
    }

EXIT:

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes Origin attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_origin (struct cqueue_buffer *cq_rbuf,
                     struct bgp_peer *peer,
                     u_int8_t attr_flag,
                     u_int8_t attr_type,
                     u_int16_t attr_len,
                     struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;

  /* Validate 'attr_flag' value */
  if (attr_flag != BGP_ATTR_FLAG_TRANS)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Origin: Flag(%d) !Transitive",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
  if (attr_len != 1)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Origin: Len(%d) != One",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'Origin' value */
  CQUEUE_READ_INT8 (cq_rbuf, attr->origin);
  attr_read++;

  /* Validate 'Origin' value */
  if ((attr->origin != BGP_ORIGIN_IGP)
      && (attr->origin != BGP_ORIGIN_EGP)
      && (attr->origin != BGP_ORIGIN_INCOMPLETE))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Origin: Invalid Origin"
                "value (%d)", peer->host, BGP_PEER_DIR_STR (peer),
                attr->origin);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_INVAL_ORIGIN);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set presence of 'Origin' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGIN);

EXIT:

  return ret;
}


enum ssock_error
  bpd_msg_open_cap_code_dynamic (struct cqueue_buffer *cq_rbuf,
                        struct bgp_peer *peer,
                        struct bgp_capability *bo_cap,
                        u_int32_t *cap_size,
                        u_int8_t **pp_not_err)
  {
     enum ssock_error ret = SSOCK_ERR_NONE;
     u_int8_t dyn_cap_len = bo_cap->cap_len;
     u_int8_t dynamic_cap_type = 0;

     if (dyn_cap_len != 0)
       {
         while (dyn_cap_len)
         {
           CQUEUE_READ_INT8 (cq_rbuf, dynamic_cap_type);
           (*cap_size)--;
           dyn_cap_len--;
           switch (dynamic_cap_type)
           {
             case BGP_CAPABILITY_CODE_MP:
               SET_FLAG (peer->dyn_cap_flags , PEER_CAP_MP_NEW_DYN_CAP_RCV);
               break;
             case BGP_CAPABILITY_CODE_REFRESH_OLD:
               SET_FLAG (peer->dyn_cap_flags , PEER_CAP_REFRESH_OLD_DYN_CAP_RCV);
               break;
             case BGP_CAPABILITY_CODE_REFRESH:
               SET_FLAG (peer->dyn_cap_flags , PEER_CAP_REFRESH_NEW_DYN_CAP_RCV);
               break;
             default:
               zlog_warn (&BLG, "Dynamic Capability [DECODE] : Unsupported"
                    " Capability %d ...Ignoring the code...",dynamic_cap_type);
               break;

           }
         }
       }
     return ret;
  }





/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes AS-PATH attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_aspath (struct cqueue_buffer *cq_rbuf,
                     struct bgp_peer *peer,
                     u_int8_t attr_flag,
                     u_int8_t attr_type,
                     u_int16_t attr_len,
                     struct attr *attr)
{
  u_int8_t *tmp_aspath;
  enum ssock_error ret;
  u_int16_t attr_read;
  struct bgp *bgp;
  ret = SSOCK_ERR_NONE;
  tmp_aspath = NULL;
  bgp = peer->bgp;
  attr_read = 0;

  /* Temporary decode buffer */
  if (attr_len)
    {
      tmp_aspath = XCALLOC (MTYPE_TMP, attr_len);
      if (! tmp_aspath)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH:"
                    " Cannot allocate memory (%d) @ %s:%d",
                    peer->host, BGP_PEER_DIR_STR (peer),
                    attr_len, __FILE__, __LINE__);

          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

  /* Validate 'attr_flag' value */
  if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_OPTIONAL)
      || ! CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_TRANS)
      || CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Flag(%d) invalid",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'aspath list' value */
  if (attr_len)
    {
      CQUEUE_READ_NBYTES (cq_rbuf, tmp_aspath, attr_len);
      attr_read += attr_len;
    }

  /* Validate 'attr_len' value and 'aspath list' value */
  attr->aspath = aspath_parse (tmp_aspath, attr_len, peer);
  if (! attr->aspath)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Malformed Len %d",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_MAL_AS_PATH);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate IBGP AS-PATH value */
  if ( (peer_sort (peer) == BGP_PEER_IBGP || peer_sort (peer) == BGP_PEER_EBGP)
      && pal_strlen (attr->aspath->str) != 0 
      && ! aspath_as_value_check (attr->aspath))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Invalid AS Path value %s",
                peer->host, BGP_PEER_DIR_STR (peer), attr->aspath->str);
      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_MAL_AS_PATH);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Check leftmost AS number to be Peer's AS number */
  if (bgp && bgp_config_check (bgp, BGP_CFLAG_ENFORCE_FIRST_AS)
      && peer_sort (peer) == BGP_PEER_EBGP
      && ! aspath_firstas_check (attr->aspath, peer->as))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Incorrect leftmost"
                " AS number, should be %d",
                peer->host, BGP_PEER_DIR_STR (peer), peer->as);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_MAL_AS_PATH);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Check to ensure that if UPDATE with AS_CONFED_SET/SEQ AS_path
     attribute is accepted only when 'confederation' is enabled */
  if (bgp
      && aspath_confed_seg_check(attr->aspath)
      && ! bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Incorrect presence"
                " of AS_CONFED_SET/SEQ",
                peer->host, BGP_PEER_DIR_STR (peer));

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_MAL_AS_PATH);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set presence of 'ASPATH' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS_PATH);

EXIT:

  if (tmp_aspath)
    XFREE (MTYPE_TMP, tmp_aspath);

  return ret;
}
/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes AS-PATH attribute of the UPDATE message
 */
#ifdef HAVE_EXT_CAP_ASN
enum ssock_error
bpd_msg_attr_new_aspath (struct cqueue_buffer *cq_rbuf,
                         struct bgp_peer *peer,
                         u_int8_t attr_flag,
                         u_int8_t attr_type,
                         u_int16_t attr_len,
                         struct attr *attr)
{
  u_int8_t *tmp_aspath;
  enum ssock_error ret;
  u_int16_t attr_read;
  struct bgp *bgp;
  u_int32_t non_mappablecount;

  bool_t send_notify = PAL_FALSE;
  ret = SSOCK_ERR_NONE;
  tmp_aspath = NULL;
  bgp = peer->bgp;
  attr_read = 0;
  non_mappablecount = 0;
  


  /* Temporary decode buffer */
  if (attr_len)
    {
      tmp_aspath = XCALLOC (MTYPE_TMP, attr_len);
      if (! tmp_aspath)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH:"
                    " Cannot allocate memory (%d) @ %s:%d",
                    peer->host, BGP_PEER_DIR_STR (peer),
                    attr_len, __FILE__, __LINE__);

          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }
     

  /* Validate 'attr_flag' value */
  if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_OPTIONAL)
      || ! CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_TRANS)
      || CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Flag(%d) invalid",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);
      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'aspath list' value */
  if (attr_len)
    {
      CQUEUE_READ_NBYTES (cq_rbuf, tmp_aspath, attr_len);
      attr_read += attr_len;
    }

  /* Validate 'attr_len' value and 'aspath list' value */
  /* Check local speaker is OBGP */

  if (! CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      attr->aspath = aspath_parse (tmp_aspath, attr_len, peer);
      if (! attr->aspath)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Malformed Len %d",
                    peer->host, BGP_PEER_DIR_STR (peer), attr_len);

          bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                 attr_type, attr_len, 0, attr_read,
                                 BGP_NOTIFY_UPDATE_ERR,
                                 BGP_NOTIFY_UPDATE_MAL_AS_PATH);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

   /* Local speaker is NBGP and sender is NBGP */
   else if (CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
     {
       attr->aspath4B = aspath4B_parse (tmp_aspath, attr_len, peer);  
       if (! attr->aspath4B)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Malformed Len %d",
                    peer->host, BGP_PEER_DIR_STR (peer), attr_len);

          bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                 attr_type, attr_len, 0, attr_read,
                                 BGP_NOTIFY_UPDATE_ERR,
                                 BGP_NOTIFY_UPDATE_MAL_AS_PATH);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
      }

    /* Local speaker is NBGP and sender is OBGP */
    else
      {
        attr->aspath = aspath_parse (tmp_aspath, attr_len, peer);
        if (! attr->aspath)
          {
            zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Malformed Len %d",
                      peer->host, BGP_PEER_DIR_STR (peer), attr_len);

            bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                   attr_type, attr_len, 0, attr_read,
                                   BGP_NOTIFY_UPDATE_ERR,
                                   BGP_NOTIFY_UPDATE_MAL_AS_PATH);
            ret = SSOCK_ERR_CLOSE;
            goto EXIT;
          }
      }

  /* Speaker is OBGP. Validate AS-PATH value */
  if (! CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      if ( (peer_sort (peer) == BGP_PEER_IBGP || 
            peer_sort (peer) == BGP_PEER_EBGP)
            && pal_strlen (attr->aspath->str) != 0
            && ! aspath_as_value_check (attr->aspath))
        {
          zlog_err(&BLG, "%s-%s [DECODE] Attr ASPATH: Invalid AS Path value %s",
                    peer->host, BGP_PEER_DIR_STR (peer), attr->aspath->str);
          bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                 attr_type, attr_len, 0, attr_read,
                                 BGP_NOTIFY_UPDATE_ERR,
                                 BGP_NOTIFY_UPDATE_MAL_AS_PATH);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

  /* Speaker is NBGP. Validate AS-PATH value */
  else
    {
      if (! CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
        {
          if ( (peer_sort (peer) == BGP_PEER_IBGP || 
                peer_sort (peer) == BGP_PEER_EBGP)
                && pal_strlen (attr->aspath->str) != 0
                && ! aspath_as_value_check (attr->aspath))
            {
              zlog_err (&BLG, 
                        "%s-%s [DECODE] Attr ASPATH: Invalid AS Path value %s",
                        peer->host, BGP_PEER_DIR_STR (peer), attr->aspath->str);
              send_notify = PAL_TRUE;
            }
         }
       else
         {
           if ((peer_sort (peer) == BGP_PEER_IBGP || 
                peer_sort (peer) == BGP_PEER_EBGP)
               && pal_strlen (attr->aspath4B->str) != 0
               && ! as4path_as_value_check (attr->aspath4B))
             {
               zlog_err (&BLG, 
                         "%s-%s [DECODE] Attr ASPATH: Invalid AS Path value %s",
                         peer->host, BGP_PEER_DIR_STR (peer), 
                         attr->aspath4B->str);
               send_notify = PAL_TRUE;
             }
         }

       if (send_notify == PAL_TRUE)
         {
           bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                 attr_type, attr_len, 0, attr_read,
                                 BGP_NOTIFY_UPDATE_ERR,
                                 BGP_NOTIFY_UPDATE_MAL_AS_PATH);
           ret = SSOCK_ERR_CLOSE;
           goto EXIT;
         }
    }

  /* resetting the variable to be on safe side */
  send_notify = PAL_FALSE;

  /* Check leftmost AS number to be Peer's AS number */
  /* local speaker is NBGP and Nbr is OBGP or local speaker is OBGP */
  if ( (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)
        && !CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
       ||(!CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)) )
    {
      if (bgp && bgp_config_check (bgp, BGP_CFLAG_ENFORCE_FIRST_AS)
          && peer_sort (peer) == BGP_PEER_EBGP
          && ! aspath_firstas_check (attr->aspath, peer->as))
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Incorrect leftmost"
                    " AS number, should be %u",
                    peer->host, BGP_PEER_DIR_STR (peer), peer->as);
          send_notify = PAL_TRUE;
        }
    }
   /* Local speaker is NBGP and Nbr is NBGP */
  else if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)
           && CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV) )
    {
      if (bgp && bgp_config_check (bgp, BGP_CFLAG_ENFORCE_FIRST_AS)
          && peer_sort (peer) == BGP_PEER_EBGP
          && ! as4path_firstas_check (attr->aspath4B, peer->as))
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Incorrect leftmost"
                    " AS number, should be %u",
                    peer->host, BGP_PEER_DIR_STR (peer), peer->as);
          send_notify = PAL_TRUE;
        } 
    }

  if (send_notify == PAL_TRUE)
    {
      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_MAL_AS_PATH);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }
  send_notify = PAL_FALSE;
 
  /* Check to ensure that if UPDATE with AS_CONFED_SET/SEQ AS_path
     attribute is accepted only when 'confederation' is enabled */
  if (bgp)
    {
      if (! CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        {
          /* Validate all the error cases */
          if ((aspath_confed_seg_check(attr->aspath)
               && ! bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION))
               || (! aspath_confed_first_seg_check (attr->aspath)
                   && bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION)
                   && bgp_confederation_peers_check (bgp, peer->as)))

            {
              zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Incorrect presence"
                        " of AS_CONFED_SET/SEQ",
                        peer->host, BGP_PEER_DIR_STR (peer));

              bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                     attr_type, attr_len, 0, attr_read,
                                     BGP_NOTIFY_UPDATE_ERR,
                                     BGP_NOTIFY_UPDATE_MAL_AS_PATH);
              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
            } 
        } 
      /* local speaker is NBGP */
      /* Check for the sender */
      else if (! CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
        { 
          /* Validate all the error cases */
          if ((aspath_confed_seg_check(attr->aspath)
               && ! bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION))
               || (! aspath_confed_first_seg_check (attr->aspath)
                   && bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION)
                   && bgp_confederation_peers_check (bgp, peer->as)))
             {
               zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Incorrect presence"
                         " of AS_CONFED_SET/SEQ",
                         peer->host, BGP_PEER_DIR_STR (peer));
                         bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                                attr_type, attr_len, 0, attr_read,
                                                BGP_NOTIFY_UPDATE_ERR,
                                                BGP_NOTIFY_UPDATE_MAL_AS_PATH);
               ret = SSOCK_ERR_CLOSE;
               goto EXIT;
             }
         }
       /* Sender is NBGP */
       /* Validate all the error scenarios */
      else if ((as4path_confed_seg_check(attr->aspath4B)
                && ! bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION))
                || (! as4path_confed_first_seg_check (attr->aspath4B)
                    && bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION)
                    && bgp_confederation_peers_check (bgp, peer->as)))
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr ASPATH: Incorrect presence"
                    " of AS_CONFED_SET/SEQ",
                    peer->host, BGP_PEER_DIR_STR (peer));
          bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                 attr_type, attr_len, 0, attr_read,
                                 BGP_NOTIFY_UPDATE_ERR,
                                 BGP_NOTIFY_UPDATE_MAL_AS_PATH);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

   /* NBGP if received 2 Byte aspath from an OBGP should convert 2 byte aspath
      to 4 byte aspath. This is to ensure that NBGP always uses 4 byte aspath4B       for sending update to another NBGP */

   if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)
       && ! CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
     {
       if ( attr->aspath && attr->aspath->length)
         { 
           if (attr->aspath4B)
             aspath4B_unintern (attr->aspath4B);
           attr->aspath4B = as4path_new();
           attr->aspath4B = 
              as4path_copy_aspath_to_aspath4B (attr->aspath, attr->aspath4B);
           attr->aspath4B = aspath4B_intern (attr->aspath4B);
         }
     }
  
  /* NBGP if receives 4 byte aspath4B from NBGP  have to copy the 4 byte
     aspath4B to 2  byte aspath and corresponding 4 byte in as4path. This
     is required for sending to OBGP. If aspath4B contains 4 byte AS numbers,
     while consrtucting the paths it will add BGP_AS_TRANS in aspath and the
     corresponding 4 byte number is as4path  */
 
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)
      && CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV)
      )    
    {
       /* for IBGP length will be zero */
       if (attr->aspath4B && attr->aspath4B->length)
         {
           if (attr->aspath)
             aspath_unintern (attr->aspath);
           attr->aspath = aspath_new();
           attr->aspath = 
             aspath_copy_aspath4B_to_aspath (attr->aspath4B, attr->aspath);
           attr->aspath = aspath_intern (attr->aspath);
         }
       
       /* check any Non mappable AS Number in the recevied updates */
       /* Store the 4 byte non mappble ASs in as4path */
       if (attr->aspath4B)
         non_mappablecount = aspath4B_nonmappable_count (attr->aspath4B);  
       if (non_mappablecount)
         {
           if (attr->as4path)
             as4path_unintern (attr->as4path); 
           attr->as4path = as4path_new();
           attr->as4path = 
             construct_as4path_from_aspath4B (attr->aspath4B, attr->as4path);
           attr->as4path= as4path_intern (attr->as4path);
         }
   }

  /* Set presence of 'ASPATH' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS_PATH);
EXIT:

  if (tmp_aspath)
    XFREE (MTYPE_TMP, tmp_aspath);
   
return ret;
}


/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes AS4-PATH attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_as4path (struct cqueue_buffer *cq_rbuf,
                     struct bgp_peer *peer,
                     u_int8_t attr_flag,
                     u_int8_t attr_type,
                     u_int16_t attr_len,
                     struct attr *attr)
{
  u_int8_t *tmp_aspath;
  enum ssock_error ret;
  u_int16_t attr_read;
  struct as4path *aspath4B;
  struct as4path *aspath4B_recon;
  unsigned int as4count;
  int as4octetcount;

  ret = SSOCK_ERR_NONE;
  tmp_aspath = NULL;
  attr_read = 0;
  aspath4B = NULL;
  aspath4B_recon = NULL;
  as4count = 0;
  as4octetcount = 0;

  /* Temporary decode buffer */
  if (attr_len)
    {
      tmp_aspath = XCALLOC (MTYPE_TMP, attr_len);
      if (! tmp_aspath)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr AS4_PATH:"
                    " Cannot allocate memory (%d) @ %s:%d",
                    peer->host, BGP_PEER_DIR_STR (peer),
                    attr_len, __FILE__, __LINE__);

          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

  /* Validate 'attr_flag' value */
  if (! CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_OPTIONAL)
      || ! CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_TRANS)
      || ! CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr AS4_PATH: Flag(%d) invalid",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }
  /* Get 'aspath list' value */
  if (attr_len)
  {
    CQUEUE_READ_NBYTES (cq_rbuf, tmp_aspath, attr_len);
    attr_read += attr_len;
  }

 attr->as4path = as4path_parse (tmp_aspath, attr_len, peer);
 if (! attr->as4path)
   {
     zlog_err (&BLG, "%s-%s [DECODE] Attr AS4_PATH: Malformed Len %d",
               peer->host, BGP_PEER_DIR_STR (peer), attr_len);
 
     bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                            attr_type, attr_len, 0, attr_read,
                            BGP_NOTIFY_UPDATE_ERR,
                            BGP_NOTIFY_UPDATE_MAL_AS4_PATH);
     ret = SSOCK_ERR_CLOSE;
     goto EXIT;
   }

  /* Validate IBGP AS4-PATH value */
  if ( (peer_sort (peer) == BGP_PEER_IBGP || peer_sort (peer) == BGP_PEER_EBGP)
        && pal_strlen (attr->as4path->str) != 0
        && ! as4path_as_value_check (attr->as4path))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr AS_PATH: Invalid AS4 Path value %s",
                peer->host, BGP_PEER_DIR_STR (peer), attr->as4path->str);
      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_MAL_AS4_PATH);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set presence of 'AS4PATH' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS4_PATH);

  /* NBGP if recevied both aspath and as4path should reconstuct the aspath */ 
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)) 
    {
      as4octetcount = aspath_as_value_astrans_check(attr->aspath);
      as4count = as4path_as4_count(attr->as4path); 
      /* Check Number of Entries in the AS4 path. If it is less than total number
         of AS_TRANS in the AS path send notification */ 
      if (as4octetcount > as4count)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr AS4_PATH : (error)AS4_PATH contains less entries",
                    peer->host, BGP_PEER_DIR_STR (peer));
          bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                 attr_type, attr_len, 0,
                                 attr_read, BGP_NOTIFY_UPDATE_ERR,
                                 BGP_NOTIFY_UPDATE_MAL_AS4_PATH);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
       else
         {
           if ( attr->aspath4B && attr->aspath4B->length)
             {
               aspath4B =  attr->aspath4B;
               aspath4B_recon = as4path_reconstruct_aspath4B (attr->aspath4B, attr->as4path);
               if (attr->aspath4B)   
               aspath4B_unintern (aspath4B);
               attr->aspath4B = aspath4B_intern (aspath4B_recon);
             }
         }
    }

EXIT:
  if (tmp_aspath)
    XFREE (MTYPE_TMP, tmp_aspath);
 return ret;
}
#endif /* HAVE_EXT_CAP_ASN */


/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes Next-Hop attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_nhop (struct cqueue_buffer *cq_rbuf,
                   struct bgp_peer *peer,
                   u_int8_t attr_flag,
                   u_int8_t attr_type,
                   u_int16_t attr_len,
                   struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;
  s_int32_t nhop_err;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;
  nhop_err = 0;

  /* Validate 'attr_flag' value */
  if (attr_flag != BGP_ATTR_FLAG_TRANS)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr NHop: Flag(%d) !Transitive",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
  if (attr_len != 4)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr NHop: Len(%d) != Four",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  CQUEUE_READ_4BYTES(cq_rbuf, &attr->nexthop.s_addr);
  attr_read += attr_len;

  /* Validate IPv4 Next-Hop Address */
  nhop_err = bpd_msg_update_nhop_validate (peer, &attr->nexthop);

  if (nhop_err < 0)
    {
      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set presence of 'NHop' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP);

EXIT:

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes MED attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_med (struct cqueue_buffer *cq_rbuf,
                  struct bgp_peer *peer,
                  u_int8_t attr_flag,
                  u_int8_t attr_type,
                  u_int16_t attr_len,
                  struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;

  /* Validate 'attr_flag' value */
  if (attr_flag != BGP_ATTR_FLAG_OPTIONAL)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MED: Flag(%d) !Optional",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
  if (attr_len != 4)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MED: Len(%d) != Four",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  CQUEUE_READ_INT32 (cq_rbuf, attr->med);

  if (attr->med > BGP_MED_MAX)
    attr->med = BGP_MED_MAX;

  attr_read += sizeof (u_int32_t);

  /* Set presence of 'NHop' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

EXIT:

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes Local-Preference attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_locpref (struct cqueue_buffer *cq_rbuf,
                      struct bgp_peer *peer,
                      u_int8_t attr_flag,
                      u_int8_t attr_type,
                      u_int16_t attr_len,
                      struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;

  /* Ignore if received from EBGP peer */
  if (peer_sort (peer) == BGP_PEER_EBGP)
    {
      zlog_warn (&BLG, "%s-%s [DECODE] Attr LPref: Received from EBGP"
                 " peer, Ignoring Local-Preference",
                 peer->host, BGP_PEER_DIR_STR (peer));

      CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, attr_len);

      ret = SSOCK_ERR_NONE;
      goto EXIT;
    }

  /* Validate 'attr_flag' value */
  if (attr_flag != BGP_ATTR_FLAG_TRANS)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr LPref: Flag(%d) !Transitive",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
  if (attr_len != 4)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr LPref: Len(%d) != Four",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'Local preference' value */
  CQUEUE_READ_INT32 (cq_rbuf, attr->local_pref);
  attr_read += sizeof (u_int32_t);

  /* Set presence of 'Local-Preference' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);

EXIT:

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes Atomic-Aggregate attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_atomic (struct cqueue_buffer *cq_rbuf,
                     struct bgp_peer *peer,
                     u_int8_t attr_flag,
                     u_int8_t attr_type,
                     u_int16_t attr_len,
                     struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;

  /* Validate 'attr_flag' value */
  if (attr_flag != BGP_ATTR_FLAG_TRANS)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Atomic: Flag(%d) !Transitive",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
  if (attr_len != 0)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Atomic: Len(%d) != Zero",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set presence of 'Atomic-Aggregate' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);

EXIT:

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes Aggregator attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_aggregator (struct cqueue_buffer *cq_rbuf,
                         struct bgp_peer *peer,
                         u_int8_t attr_flag,
                         u_int8_t attr_type,
                         u_int16_t attr_len,
                         struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;
  s_int32_t tmp_as;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;

  /* Mask partial bit in Flag for validation */
  if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL))
    SET_FLAG (attr->partial_flag, BGP_ATTR_AGGREGATOR_PARTIAL);
  UNSET_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL);

  /* Validate 'attr_flag' value */
  if (attr_flag != (BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: Flag(%X) "
                " ! (Optional && Transitive)",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
  if (attr_len != 6)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: Len(%d) != Six",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'Aggregator-AS' value */
  CQUEUE_READ_INT16 (cq_rbuf, attr->aggregator_as);
  attr_read += sizeof (u_int16_t);

  /* Validate 'Aggregator-AS' value */
  tmp_as = (s_int32_t) attr->aggregator_as;

  if (tmp_as < BGP_AS_MIN || tmp_as > BGP_AS_MAX)
    {
      /*
       * Some versions of released software from established vendors
       * do not set the Aggregator AS value. So we make an exception
       * and just log a warning.
       */
      if (attr->aggregator_as == 0)
        zlog_warn (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                   "error(%u), Ignoring error...", peer->host,
                   BGP_PEER_DIR_STR (peer), attr->aggregator_as);
      else
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                    "error(%u)", peer->host, BGP_PEER_DIR_STR (peer),
                    attr->aggregator_as);

          bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                 attr_type, attr_len, 0,
                                 attr_read, BGP_NOTIFY_UPDATE_ERR,
                                 BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

  /* Get 'Aggregator-Router-ID' value */
  CQUEUE_READ_4BYTES (cq_rbuf, &attr->aggregator_addr.s_addr);
  attr_read += sizeof (u_int32_t);

  /* Set presence of 'Aggregator' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR);

EXIT:

  return ret;
}

#ifdef HAVE_EXT_CAP_ASN
/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes Aggregator attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_new_aggregator (struct cqueue_buffer *cq_rbuf,
                         struct bgp_peer *peer,
                         u_int8_t attr_flag,
                         u_int8_t attr_type,
                         u_int16_t attr_len,
                         struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;
  u_int32_t tmp_as;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;

  /* Mask partial bit in Flag for validation */
  if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL))
    SET_FLAG (attr->partial_flag, BGP_ATTR_AGGREGATOR_PARTIAL);
  UNSET_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL);

  /* Validate 'attr_flag' value */
  if (attr_flag != (BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: Flag(%X) "
                " ! (Optional && Transitive)",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }
  /* Validate 'attr_len' value */
  /* Check the local speaker is NBGP */
  if ( CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      if (CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
        {
          if (attr_len != 8)
            {
              zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: Len(%d) != Eight",
                               peer->host, BGP_PEER_DIR_STR (peer), attr_len);

              bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                     attr_type, attr_len, 0, attr_read,
                                     BGP_NOTIFY_UPDATE_ERR,
                                     BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
            }
         /* Get 'Aggregator-AS' value */
         CQUEUE_READ_INT32 (cq_rbuf, attr->aggregator_as4);
         attr_read += sizeof (u_int32_t);
         tmp_as = attr->aggregator_as4;
         if (tmp_as > BGP_AS_MAX)
            attr->aggregator_as = BGP_AS_TRANS;
         else 
            attr->aggregator_as = (u_int16_t)tmp_as; 
         if (tmp_as < BGP_AS4_MIN || tmp_as > BGP_AS4_MAX)
           {
             /*
             * Some versions of released software from established vendors
             * do not set the Aggregator AS value. So we make an exception
             * and just log a warning.
             */
             if (attr->aggregator_as4 == 0)
               zlog_warn (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                          "error(%u), Ignoring error...", peer->host,
                          BGP_PEER_DIR_STR (peer), attr->aggregator_as4);
             else
               {
                 zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                           "error(%u)", peer->host, BGP_PEER_DIR_STR (peer),
                           attr->aggregator_as4);

                 bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                        attr_type, attr_len, 0,
                                        attr_read, BGP_NOTIFY_UPDATE_ERR,
                                        BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
                 ret = SSOCK_ERR_CLOSE;
                 goto EXIT;
         
               }
            }
         }

       /* Neighbor is OBGP */
       else
         {
           if (attr_len != 6)
            {
              zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: Len(%d) != Six",
                               peer->host, BGP_PEER_DIR_STR (peer), attr_len);

              bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                     attr_type, attr_len, 0, attr_read,
                                     BGP_NOTIFY_UPDATE_ERR,
                                     BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
            }
             /* Get 'Aggregator-AS' value */
           CQUEUE_READ_INT16 (cq_rbuf, attr->aggregator_as);
           attr_read += sizeof (u_int16_t);

           /* Validate 'Aggregator-AS' value */
           tmp_as = (u_int16_t) attr->aggregator_as;
           /* Update attr->aggregator_as4 */
           attr->aggregator_as4 = tmp_as;
           if (tmp_as < BGP_AS_MIN || tmp_as > BGP_AS_MAX)
             {
               /*
               * Some versions of released software from established vendors
               * do not set the Aggregator AS value. So we make an exception
               * and just log a warning.
               */
               if (attr->aggregator_as == 0)
                 zlog_warn (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                            "error(%u), Ignoring error...", peer->host,
                            BGP_PEER_DIR_STR (peer), attr->aggregator_as);
               else
                 {
                   zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                             "error(%u)", peer->host, BGP_PEER_DIR_STR (peer),
                             attr->aggregator_as);

                   bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                          attr_type, attr_len, 0,
                                          attr_read, BGP_NOTIFY_UPDATE_ERR,
                                          BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
                   ret = SSOCK_ERR_CLOSE;
                   goto EXIT;
                 }
             }
          }
    }
    /* local speaker is OBGP */ 
    /* Check for the sender */
    else if (CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV)) 
      {
        if (attr_len != 6)
          {
              zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: Len(%d) != Six",
                               peer->host, BGP_PEER_DIR_STR (peer), attr_len);

              bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                     attr_type, attr_len, 0, attr_read,
                                     BGP_NOTIFY_UPDATE_ERR,
                                     BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
          }
        /* Get 'Aggregator-AS' value */
        CQUEUE_READ_INT16 (cq_rbuf, attr->aggregator_as);
        attr_read += sizeof (u_int16_t);

        /* Validate 'Aggregator-AS' value */
        tmp_as = (u_int16_t) attr->aggregator_as;
        if (! BGP_IS_AS4_MAPPABLE(peer->as))
          {
            if (tmp_as != BGP_AS_TRANS)
              {
                zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                             "error(%u)", peer->host, BGP_PEER_DIR_STR (peer),
                              attr->aggregator_as);

                bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                       attr_type, attr_len, 0,
                                       attr_read, BGP_NOTIFY_UPDATE_ERR,
                                       BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
                ret = SSOCK_ERR_CLOSE;
                goto EXIT;
              }
           } 
         else if (tmp_as < BGP_AS_MIN || tmp_as > BGP_AS_MAX)
            {
              /*
              * Some versions of released software from established vendors
              * do not set the Aggregator AS value. So we make an exception
              * and just log a warning.
              */
              if (attr->aggregator_as == 0)
                  zlog_warn (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                             "error(%u), Ignoring error...", peer->host,
                             BGP_PEER_DIR_STR (peer), attr->aggregator_as);
              else
                {
                  zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                            "error(%u)", peer->host, BGP_PEER_DIR_STR (peer),
                            attr->aggregator_as);

                  bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                         attr_type, attr_len, 0,
                                         attr_read, BGP_NOTIFY_UPDATE_ERR,
                                         BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
                  ret = SSOCK_ERR_CLOSE;
                  goto EXIT;
                }
             }
         }
     /* sender is OBGP */  
     else
       {
         /* Validate 'attr_len' value */
         if (attr_len != 6)
           {
             zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: Len(%d) != Six",
                       peer->host, BGP_PEER_DIR_STR (peer), attr_len);

             bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                    attr_type, attr_len, 0, attr_read,
                                    BGP_NOTIFY_UPDATE_ERR,
                                    BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
             ret = SSOCK_ERR_CLOSE;
             goto EXIT;
           }

        /* Get 'Aggregator-AS' value */
        CQUEUE_READ_INT16 (cq_rbuf, attr->aggregator_as);
        attr_read += sizeof (u_int16_t);

        /* Validate 'Aggregator-AS' value */
        tmp_as = (u_int16_t) attr->aggregator_as;
        if (tmp_as < BGP_AS_MIN || tmp_as > BGP_AS_MAX)
          {
            /*
            * Some versions of released software from established vendors
            * do not set the Aggregator AS value. So we make an exception
            * and just log a warning.
            */
            if (attr->aggregator_as == 0)
               zlog_warn (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                          "error(%u), Ignoring error...", peer->host,
                          BGP_PEER_DIR_STR (peer), attr->aggregator_as);
            else
              {
                zlog_err (&BLG, "%s-%s [DECODE] Attr Aggregator: AS value "
                          "error(%u)", peer->host, BGP_PEER_DIR_STR (peer),
                          attr->aggregator_as);

                bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                       attr_type, attr_len, 0,
                                       attr_read, BGP_NOTIFY_UPDATE_ERR,
                                       BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
                ret = SSOCK_ERR_CLOSE;
                goto EXIT;
              }
          }
        }
       
  /* Get 'Aggregator-Router-ID' value */
  CQUEUE_READ_4BYTES (cq_rbuf, &attr->aggregator_addr.s_addr);
  attr_read += sizeof (u_int32_t);

  /* Set presence of 'Aggregator' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR);

EXIT:

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes AS4 Aggregator attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_as4_aggregator (struct cqueue_buffer *cq_rbuf,
                             struct bgp_peer *peer,
                             u_int8_t attr_flag,
                             u_int8_t attr_type,
                             u_int16_t attr_len,
                             struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;
  u_int32_t tmp_as;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;

     
  /* Mask partial bit in Flag for validation */
  if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL))
    SET_FLAG (attr->partial_flag, BGP_ATTR_AS4_AGGREGATOR_PARTIAL);
  UNSET_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL);

  /* Validate 'attr_flag' value */
  if (attr_flag != (BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr AS4 Aggregator: Flag(%X) "
                " ! (Optional && Transitive)",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
     if (attr_len != 8)
       {
         zlog_err (&BLG, "%s-%s [DECODE] Attr AS4 Aggregator: Len(%d) != Eight",
                   peer->host, BGP_PEER_DIR_STR (peer), attr_len);

         bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                attr_type, attr_len, 0, attr_read,
                                BGP_NOTIFY_UPDATE_ERR,
                                BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
         ret = SSOCK_ERR_CLOSE;
         goto EXIT;
       }
  /* Check whether it received aggregator attr */
     else if ( ! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR)))  
       {
         /* AS4 Aggregator Attr without AS Aggregator */
         zlog_err (&BLG, "%s-%s [DECODE] Attr AS4 Aggregator: (error)AS Aggregator missing ",
                   peer->host, BGP_PEER_DIR_STR (peer));
         bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                attr_type, attr_len, 0,
                                attr_read, BGP_NOTIFY_UPDATE_ERR,
                                BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
         ret = SSOCK_ERR_CLOSE;
         goto EXIT;
       }
    /* Get 'Aggregator-AS4' value */
    CQUEUE_READ_INT32 (cq_rbuf, attr->aggregator_as4);
    attr_read += sizeof (u_int32_t);

    /* Validate 'Aggregator-AS4' value */
    tmp_as =  attr->aggregator_as4;

    /* AS4 Aggregator value should be 4 byte */
    if (tmp_as < BGP_AS_MAX || tmp_as > BGP_AS4_MAX)
      {
        zlog_err (&BLG, "%s-%s [DECODE] Attr AS4 Aggregator: AS value "
                  "error(%u)", peer->host, BGP_PEER_DIR_STR (peer),
                   attr->aggregator_as4);

         bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                attr_type, attr_len, 0,
                                attr_read, BGP_NOTIFY_UPDATE_ERR,
                                BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
         ret = SSOCK_ERR_CLOSE;
         goto EXIT;
      }

/* Get 'Aggregator-Router-ID' value */
  CQUEUE_READ_4BYTES (cq_rbuf, &attr->aggregator_addr.s_addr);
  attr_read += sizeof (u_int32_t);

  /* Set presence of 'Aggregator' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS4_AGGREGATOR);

EXIT:

  return ret;
}
#endif /* HAVE_EXT_CAP_ASN */

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes Community attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_comm (struct cqueue_buffer *cq_rbuf,
                   struct bgp_peer *peer,
                   u_int8_t attr_flag,
                   u_int8_t attr_type,
                   u_int16_t attr_len,
                   struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;
  u_int8_t *tmp_comm;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;

  /* Temporary decode buffer */
  tmp_comm = XCALLOC (MTYPE_TMP, attr_len);
  if (! tmp_comm)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Comm:"
                " Cannot allocate memory (%d) @ %s:%d",
                peer->host, BGP_PEER_DIR_STR (peer),
                attr_len, __FILE__, __LINE__);

      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Mask partial bit in Flag for validation */
  if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL))
    SET_FLAG (attr->partial_flag, BGP_ATTR_COMMUNITY_PARTIAL);
  UNSET_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL);

  /* Validate 'attr_flag' value */
  if (attr_flag != (BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Comm: Flag(%X) "
                " ! (Optional && Transitive)",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
  if (! attr_len || attr_len % 4)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Comm: Len(%d) invalid",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'Community list' value */
  CQUEUE_READ_NBYTES (cq_rbuf, tmp_comm, attr_len);
  attr_read += attr_len;

  /* Validate 'Community list' value */
  attr->community = community_parse (tmp_comm, attr_len);
  if (! attr->community)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Comm: Invalid Community List",
                peer->host, BGP_PEER_DIR_STR (peer));

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set presence of 'Community' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);

EXIT:

  if (tmp_comm)
    XFREE (MTYPE_TMP, tmp_comm);

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes BGP Extended-Communities attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_ecomm (struct cqueue_buffer *cq_rbuf,
                    struct bgp_peer *peer,
                    u_int8_t attr_flag,
                    u_int8_t attr_type,
                    u_int16_t attr_len,
                    struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;
  u_int8_t *tmp_ecomm;

  ret = SSOCK_ERR_NONE;
  tmp_ecomm = NULL;
  attr_read = 0;

  /* Temporary decode buffer */
  if (attr_len)
    {
      tmp_ecomm = XCALLOC (MTYPE_TMP, attr_len);
      if (! tmp_ecomm)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr E-Comm:"
                    " Cannot allocate memory (%d) @ %s:%d",
                    peer->host, BGP_PEER_DIR_STR (peer),
                    attr_len, __FILE__, __LINE__);

          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

  /* Mask partial bit in Flag for validation */
  if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL))
    SET_FLAG (attr->partial_flag, BGP_ATTR_ECOMMUNITY_PARTIAL);
  UNSET_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL);

  /* Validate 'attr_flag' value */
  if (attr_flag != (BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS)) 
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr E-Comm: Flag(%X) "
                " ! (Optional && Transitive) OR Partial",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
  if (! attr_len || attr_len % 4)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr E-Comm: Len(%d) invalid",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'Ext-Community list' value */
  CQUEUE_READ_NBYTES (cq_rbuf, tmp_ecomm, attr_len);
  attr_read += attr_len;

  /* Validate 'Ext-Community list' value */
  attr->ecommunity = ecommunity_parse (tmp_ecomm, attr_len);
  if (! attr->ecommunity)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr E-Comm: Invalid Ext-Community"
                " List", peer->host, BGP_PEER_DIR_STR (peer));

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  ecommunity_logging (attr->ecommunity);

  /* Set presence of 'Community' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);

EXIT:

  if (tmp_ecomm)
    XFREE (MTYPE_TMP, tmp_ecomm);

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes Originator-ID attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_orig_id (struct cqueue_buffer *cq_rbuf,
                      struct bgp_peer *peer,
                      u_int8_t attr_flag,
                      u_int8_t attr_type,
                      u_int16_t attr_len,
                      struct attr *attr)
{
  enum ssock_error ret;
  u_int16_t attr_read;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;

  /* Validate 'attr_len' value */
  if (attr_len != 4)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr OrigID: Len(%d) != Four",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'Originator-ID' value */
  CQUEUE_READ_4BYTES (cq_rbuf, &attr->originator_id.s_addr);
  attr_read += sizeof (u_int32_t);

  /* Set presence of 'Originator-ID' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID);

  /* If Originator-ID is self, ignore this UPDATE */
  if (IPV4_ADDR_SAME (&peer->local_id, &attr->originator_id))
    {
      zlog_warn (&BLG, "%s-%s [DECODE] Attr OrigID: OrigID(%r)"
                 " same as Self, Ignoring UPDATE...",
                 peer->host, BGP_PEER_DIR_STR (peer),
                 &attr->originator_id.s_addr);

      ret = SSOCK_ERR_READ_LOOP;
      goto EXIT;
    }

EXIT:

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes Cluster-List attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_cluster (struct cqueue_buffer *cq_rbuf,
                      struct bgp_peer *peer,
                      u_int8_t attr_flag,
                      u_int8_t attr_type,
                      u_int16_t attr_len,
                      struct attr *attr)
{
  u_int8_t *tmp_clust_list;
  enum ssock_error ret;
  u_int16_t attr_read;

  tmp_clust_list = NULL;
  ret = SSOCK_ERR_NONE;
  attr_read = 0;

  /* Temporary decode buffer */
  if (attr_len)
    {
      tmp_clust_list = XCALLOC (MTYPE_TMP, attr_len);
      if (! tmp_clust_list)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr Cluster:"
                    " Cannot allocate memory (%d) @ %s:%d",
                    peer->host, BGP_PEER_DIR_STR (peer),
                    attr_len, __FILE__, __LINE__);

          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }

  /* Validate 'attr_len' value */
  if (! attr_len || attr_len % 4)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Cluster: Len(%d) invalid",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'Cluster list' value */
  CQUEUE_READ_NBYTES (cq_rbuf, tmp_clust_list, attr_len);
  attr_read += attr_len;

  /* Validate 'attr_len' value and 'aspath list' value */
  attr->cluster = cluster_parse (tmp_clust_list, attr_len);
  if (! attr->cluster)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Cluster: Invalid Cluster List",
                peer->host, BGP_PEER_DIR_STR (peer));

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Set presence of 'Cluster-List' in attribute flags */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_CLUSTER_LIST);

EXIT:

  if (tmp_clust_list)
    XFREE (MTYPE_TMP, tmp_clust_list);

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes MP-Reach-NLRI attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_mp_reach (struct cqueue_buffer *cq_rbuf,
                       struct bgp_peer *peer,
                       u_int8_t attr_flag,
                       u_int8_t attr_type,
                       u_int16_t attr_len,
                       struct attr *attr,
                       struct bgp_nlri_snap_shot *bnss)
{
  enum ssock_error ret;
  u_int16_t attr_read;
  s_int32_t nhop_err;
  u_int8_t snpa_num;
  u_int8_t snpa_len;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;
  nhop_err = 0;

  /* Validate 'attr_flag' value */
  if (! (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_OPTIONAL)
         && ! CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_TRANS)))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPReach: Flag(%X) "
                " ! (Optional && Non-Transitive)",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
  if (attr_len < BGP_ATTR_MP_REACH_MIN_SIZE)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPReach: Len(%d) < %d",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len,
                BGP_ATTR_MP_REACH_MIN_SIZE);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'AFI' value */
  CQUEUE_READ_INT16 (cq_rbuf, bnss->mp_reach_afi);
  attr_read += sizeof (u_int16_t);

  /* Validate 'AFI' value */
  if (! BGP_AFI_VALID_CHECK (bnss->mp_reach_afi))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPReach: AFI(%d) invalid",
                peer->host, BGP_PEER_DIR_STR (peer), bnss->mp_reach_afi);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_len,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'SAFI' value */
  CQUEUE_READ_INT8 (cq_rbuf, bnss->mp_reach_safi);
  attr_read += sizeof (u_int8_t);

  /* Validate 'SAFI' value */
  if (! BGP_SAFI_VALID_CHECK (bnss->mp_reach_safi))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPReach: SAFI(%d) invalid",
                peer->host, BGP_PEER_DIR_STR (peer), bnss->mp_reach_safi);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'AFI-SAFI' combination value */
  if (! BGP_AFI_SAFI_SUPPORT_CHECK (bnss->mp_reach_afi,
                                    bnss->mp_reach_safi))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPReach: AFI-SAFI(%d-%d)"
                " combination not-supported",
                peer->host, BGP_PEER_DIR_STR (peer),
                bnss->mp_reach_afi, bnss->mp_reach_safi);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }
  
  /* Get 'MP NHop Len' value */
  CQUEUE_READ_INT8 (cq_rbuf, attr->mp_nexthop_len);
  attr_read += sizeof (u_int8_t);

  /* Sanity check for 'MP NHop Len' value [+1 for SNPA No.] */
  if ((attr->mp_nexthop_len + 1) > (attr_len - attr_read))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPReach: MP Nexthop Len(%d)"
                " > attr_len(%d)", peer->host, BGP_PEER_DIR_STR (peer),
                attr->mp_nexthop_len, attr_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'MP NHop Len' value and get NHop value */
  if (attr->mp_nexthop_len == IPV4_MAX_BYTELEN)
    {
      CQUEUE_READ_4BYTES (cq_rbuf, &attr->mp_nexthop_global_in);
      attr_read += attr->mp_nexthop_len;

      /* Validate IPv4 Next-Hop Address */
      nhop_err = bpd_msg_update_nhop_validate (peer,
                                     &attr->mp_nexthop_global_in);

      if (nhop_err < 0)
        {
          bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                 attr_type, attr_len, 0, attr_read,
                                 BGP_NOTIFY_UPDATE_ERR,
                                 BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6)
    {
      if (attr->mp_nexthop_len == IPV6_MAX_BYTELEN)
        {
          CQUEUE_READ_NBYTES (cq_rbuf,
                              &attr->mp_nexthop_global,
                              IPV6_MAX_BYTELEN);
          attr_read += attr->mp_nexthop_len;
        }
      else if (attr->mp_nexthop_len == IPV6_MAX_BYTELEN * 2)
        {
          CQUEUE_READ_NBYTES (cq_rbuf, &attr->mp_nexthop_global,
                              IPV6_MAX_BYTELEN);
          CQUEUE_READ_NBYTES (cq_rbuf, &attr->mp_nexthop_local,
                              IPV6_MAX_BYTELEN);
          attr_read += attr->mp_nexthop_len;
          if (! IN6_IS_ADDR_LINKLOCAL (&attr->mp_nexthop_local))
            {
              zlog_warn (&BLG, "%s-%s [DECODE] Attr MPReach: Got 2 "
                         "Nexthops %R %R but 2nd one is not Link-"
                         "Local, Ignoring 2nd NHop...",
                         peer->host, BGP_PEER_DIR_STR (peer),
                         &attr->mp_nexthop_global,
                         &attr->mp_nexthop_local);

              attr->mp_nexthop_len = IPV6_MAX_BYTELEN;
            }
        }
    }
#endif /* HAVE_IPV6 */
  else
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPReach: MP Nexthop Len(%d)"
                " invalid", peer->host, BGP_PEER_DIR_STR (peer),
                attr->mp_nexthop_len);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'snpa_num' value */
  /* Check whether the received MP_REACH_NLRI is RFC 2858
   * compliant or RFC 4760 compliant.
  */
  CQUEUE_READ_INT8 (cq_rbuf, snpa_num);
  attr_read += sizeof (u_int8_t);

  /* Read and discard all SNPA's as we dont support SNPA */
  /* If the snpa_num is non-zero, the received RFC 2858 compliant MP_REACH_NLRI
   * which is no more supported. So skip the SNPA fields.
   * RFC 4760 reserves SNPA_NUM field with zero-values. 
  */
  while (snpa_num)
    {
      /* Get 'snpa_len' value */
      CQUEUE_READ_INT8 (cq_rbuf, snpa_len);
      attr_read += sizeof (u_int8_t);

      /* Sanity check for SNPA Length */
      if (snpa_len > (attr_len - attr_read))
        {
          zlog_err (&BLG, "%s-%s [DECODE] Attr MPReach: SNPA Len(%d)"
                    " > attr_len - attr_read (%d)", peer->host,
                    BGP_PEER_DIR_STR (peer), snpa_len,
                    attr_len - attr_read);

          bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                                 attr_type, attr_len, 0,
                                 attr_read, BGP_NOTIFY_UPDATE_ERR,
                                 BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Skip-over the SNPA value */
      CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, (snpa_len + 1) >> 1);
      attr_read += ((snpa_len + 1) >> 1);

      snpa_num -= 1;
    } /* while */

  /* Calculate the NLRI length */
  bnss->mp_reach_len = attr_len - attr_read;

  /* Decode and validate NLRI list */
  ret = bpd_msg_update_nlri_validate (cq_rbuf, peer,
                                      bnss->mp_reach_afi,
                                      bnss->mp_reach_safi,
                                      bnss->mp_reach_len);
  if (ret != SSOCK_ERR_NONE)
    goto EXIT;

  /* Rewind by 'nlri_len' */
  CQUEUE_READ_REWIND_NBYTES (cq_rbuf, bnss->mp_reach_len);

  /* Snap-shot CQueue-Buf for Advertised NLRIs */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_rbuf, &bnss->mp_reach_cqbss);

  /* Restore CQueue to pre-Snap-shot state */
  CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, bnss->mp_reach_len);

EXIT:

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes MP-UnReach-NLRI attribute of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_mp_unreach (struct cqueue_buffer *cq_rbuf,
                         struct bgp_peer *peer,
                         u_int8_t attr_flag,
                         u_int8_t attr_type,
                         u_int16_t attr_len,
                         struct attr *attr,
                         struct bgp_nlri_snap_shot *bnss)
{
  enum ssock_error ret;
  u_int16_t attr_read;

  ret = SSOCK_ERR_NONE;
  attr_read = 0;

  /* Validate 'attr_flag' value */
  if (! (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_OPTIONAL)
         && ! CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_TRANS)))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPUnReach: Flag(%X) "
                " ! (Optional && Non-Transitive)",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'attr_len' value */
  if (attr_len < BGP_ATTR_MP_UNREACH_MIN_SIZE)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPUnReach: Len(%d) < %d",
                peer->host, BGP_PEER_DIR_STR (peer), attr_len,
                BGP_ATTR_MP_UNREACH_MIN_SIZE);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'AFI' value */
  CQUEUE_READ_INT16 (cq_rbuf, bnss->mp_unreach_afi);
  attr_read += sizeof (u_int16_t);

  /* Validate 'AFI' value */
  if (! BGP_AFI_VALID_CHECK (bnss->mp_unreach_afi))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPUnReach: AFI(%d) invalid",
                peer->host, BGP_PEER_DIR_STR (peer), bnss->mp_unreach_afi);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_len,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'SAFI' value */
  CQUEUE_READ_INT8 (cq_rbuf, bnss->mp_unreach_safi);
  attr_read += sizeof (u_int8_t);

  /* Validate 'SAFI' value */
  if (! BGP_SAFI_VALID_CHECK (bnss->mp_unreach_safi))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPUnReach: SAFI(%d) invalid",
                peer->host, BGP_PEER_DIR_STR (peer), bnss->mp_unreach_safi);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate 'AFI-SAFI' combination value */
  if (! BGP_AFI_SAFI_SUPPORT_CHECK (bnss->mp_unreach_afi,
                                    bnss->mp_unreach_safi))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr MPReach: AFI-SAFI(%d-%d)"
                "combination not-supported",
                peer->host, BGP_PEER_DIR_STR (peer),
                bnss->mp_unreach_afi, bnss->mp_unreach_safi);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Calculate the NLRI length */
  bnss->mp_unreach_len = attr_len - attr_read;

  /* Decode and validate NLRI list */
  ret = bpd_msg_update_nlri_validate (cq_rbuf, peer,
                                      bnss->mp_unreach_afi,
                                      bnss->mp_unreach_safi,
                                      bnss->mp_unreach_len);
  if (ret != SSOCK_ERR_NONE)
    goto EXIT;

  /* Rewind by 'nlri_len' */
  CQUEUE_READ_REWIND_NBYTES (cq_rbuf, bnss->mp_unreach_len);

  /* Snap-shot CQueue-Buf for Advertised NLRIs */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_rbuf, &bnss->mp_unreach_cqbss);

  /* Restore CQueue to pre-Snap-shot state */
  CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, bnss->mp_unreach_len);

EXIT:

  return ret;
}

/*
 * LEVEL 3 BGP Message Decoder function:
 * Decodes BGP Unknown-Transitive attribute(s) of the UPDATE message
 */
enum ssock_error
bpd_msg_attr_unknown (struct cqueue_buffer *cq_rbuf,
                      struct bgp_peer *peer,
                      u_int8_t attr_flag,
                      u_int8_t attr_type,
                      u_int16_t attr_len,
                      struct attr *attr)
{
  struct transit *transit;
  enum ssock_error ret;
  u_int16_t attr_read;
  u_int16_t attr_size;

  ret = SSOCK_ERR_NONE;
  attr_size = 0;
  attr_read = 0;

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [DECODE] Update Attr: Recvd Unknown attr"
               "- Flag(%X) Type(%d) Len(%d)", peer->host,
               BGP_PEER_DIR_STR (peer), attr_flag, attr_type, attr_len);

  /* Validate 'attr_flag' value */
  if (! CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_OPTIONAL))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Attr Unknown: Flag(%X) !Optional",
                peer->host, BGP_PEER_DIR_STR (peer), attr_flag);

      bpf_event_notify_attr (cq_rbuf, peer, attr_flag,
                             attr_type, attr_len, 0, attr_read,
                             BGP_NOTIFY_UPDATE_ERR,
                             BGP_NOTIFY_UPDATE_UNREC_ATTR);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Unrecognized non-transitive optional attributes must be ignored */
  if (! CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_TRANS))
    {
      zlog_warn (&BLG, "%s-%s [DECODE] Attr Unknown: Ignoring "
                 "Non-Transitive Optional attr...",
                 peer->host, BGP_PEER_DIR_STR (peer));

      CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, attr_len);
      attr_read += attr_len;

      ret = SSOCK_ERR_NONE;
      goto EXIT;
    }

  /* Store transitive attribute to the end of attr->transit. */
  if (! attr->transit)
    {
      attr->transit = XMALLOC (MTYPE_TRANSIT, sizeof (struct transit));
      pal_mem_set (attr->transit, 0, sizeof (struct transit));
    }

  transit = attr->transit;

  attr_size = BGP_ATTR_MIN_SIZE + attr_len +
              (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_EXTLEN) ? 1 : 0);

  if (transit->val)
    transit->val = XREALLOC (MTYPE_TRANSIT_VAL, transit->val,
                             transit->length + attr_size);
  else
    transit->val = XMALLOC (MTYPE_TRANSIT_VAL, attr_size);

  /* Set the 'Partial Flag' for advertising */
  SET_FLAG (attr_flag, BGP_ATTR_FLAG_PARTIAL);

  (transit->val + transit->length)[0] = attr_flag;
  (transit->val + transit->length)[1] = attr_type;

  if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_EXTLEN))
    {
      CQUEUE_READ_NBYTES(cq_rbuf,
                         &(transit->val + transit->length)[4], attr_len);
      attr_read += attr_len;
      attr_len = pal_hton16 (attr_len);
      pal_mem_cpy (&(transit->val + transit->length)[2],
                   &attr_len, BGP_ATTR_EXT_LEN_SIZE);
    }
  else
    {
      (transit->val + transit->length)[2] = attr_len;
      CQUEUE_READ_NBYTES(cq_rbuf,
                         &(transit->val + transit->length)[3], attr_len);
      attr_read += attr_len;
    }

  transit->length += attr_size;

EXIT:

  return ret;
}

/*
 * LEVEL 4 BGP Message Decoder function:
 * Decodes OPEN Message Capabilities - Multi-Protocol
 */
enum ssock_error
bpd_msg_open_cap_mp (struct cqueue_buffer *cq_rbuf,
                     struct bgp_peer *peer,
                     struct bgp_capability *bo_cap,
                     u_int32_t *cap_size,
                     u_int8_t **pp_not_err)
{
  enum ssock_error ret;

  ret = SSOCK_ERR_NONE;

  /* Validate Option length */
  if (bo_cap->cap_len != sizeof (struct bgp_cap_mp))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open MPC: Cap-length error %d",
                peer->host, BGP_PEER_DIR_STR (peer), bo_cap->cap_len);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'Cap-AFI' */
  CQUEUE_READ_INT16 (cq_rbuf, bo_cap->cap_mp.afi);
  (*cap_size) -= sizeof (u_int16_t);

  /* Get and ignore 'Cap-resv' */
  CQUEUE_READ_INT8 (cq_rbuf, bo_cap->cap_mp.reserved);
  (*cap_size)--;

  /* Get 'Cap-SAFI' */
  CQUEUE_READ_INT8 (cq_rbuf, bo_cap->cap_mp.safi);
  (*cap_size)--;

  /* Validate AFI value */
  if (! BGP_AFI_VALID_CHECK (bo_cap->cap_mp.afi))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open MPC: Invalid AFI(%d)",
                peer->host, BGP_PEER_DIR_STR (peer),
                bo_cap->cap_mp.afi);

      bo_cap->cap_mp.afi = pal_hton16 (bo_cap->cap_mp.afi);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR,
                        BGP_NOTIFY_OPEN_UNSUP_CAPBL,
                        (u_int8_t *) bo_cap,
                        bo_cap->cap_len + 2);

      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate SAFI value */
  if (! BGP_SAFI_VALID_CHECK (bo_cap->cap_mp.safi))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open MPC: Invalid SAFI(%d)",
                peer->host, BGP_PEER_DIR_STR (peer),
                bo_cap->cap_mp.safi);

      bo_cap->cap_mp.afi = pal_hton16 (bo_cap->cap_mp.afi);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR,
                        BGP_NOTIFY_OPEN_UNSUP_CAPBL,
                        (u_int8_t *) bo_cap,
                        bo_cap->cap_len + 2);

      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Ignore capability when override-capability is set */
  if (! CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
    {
      if (! BGP_AFI_SAFI_SUPPORT_CHECK (bo_cap->cap_mp.afi,
                                      bo_cap->cap_mp.safi))
        {
          zlog_err (&BLG, "%s-%s [DECODE] Open MPC: AFI/SAFI(%d/%d)"
                    " not supported", peer->host, BGP_PEER_DIR_STR (peer),
                    bo_cap->cap_mp.afi, bo_cap->cap_mp.safi);

          /* Store unsupported Cap-data */
          pal_mem_cpy ((*pp_not_err), bo_cap, bo_cap->cap_len + 2);
          ((struct bgp_capability *)(*pp_not_err))->cap_mp.afi =
                                    pal_hton16 (bo_cap->cap_mp.afi);
          (*pp_not_err) += bo_cap->cap_len + 2;
        }
      else
        peer->afc_recv [BGP_AFI2BAAI (bo_cap->cap_mp.afi)]
                       [BGP_SAFI2BSAI (bo_cap->cap_mp.safi)] = 1;
    }

EXIT:

  return ret;
}

#ifdef HAVE_EXT_CAP_ASN
/*
 * LEVEL 4 BGP Message Decoder function:
 * Decodes OPEN Message Capabilities - 4-octet ASN Capability  
 */
enum ssock_error
bpd_msg_open_cap_extasn (struct cqueue_buffer *cq_rbuf,
                         struct bgp_peer *peer,
                         struct bgp_capability *bo_cap,
                         u_int32_t *cap_size,
                         u_int8_t **pp_not_err)
{
  enum ssock_error ret;


  ret = SSOCK_ERR_NONE;

  /* Validate Capability Option length. */
  if (bo_cap->cap_len != sizeof (struct bgp_cap_as4ext))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open EXTASNC: Cap-length error %d",
                peer->host, BGP_PEER_DIR_STR (peer), bo_cap->cap_len);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'Capability, 4-octet ASN. */
  CQUEUE_READ_INT32 (cq_rbuf, bo_cap->cap_as4ext.as4ext);
  (*cap_size) -= sizeof (u_int32_t);

 /* Validate 4-octet ASN Capability value */
 /* Only NBGP Understands Extended ASN Capability */ 
 if (CHECK_FLAG (BGP_VR.bvr_options,BGP_OPT_EXTENDED_ASN_CAP))
   {
     if (bo_cap->cap_as4ext.as4ext < BGP_AS4_MIN
         || bo_cap->cap_as4ext.as4ext > BGP_AS4_MAX
         || bo_cap->cap_as4ext.as4ext == BGP_AS_TRANS
         || peer->as != bo_cap->cap_as4ext.as4ext)
       {
          zlog_err (&BLG, "%s-%s [DECODE] Open : Bad Remote-AS (%u), expected %u",
                    peer->host, BGP_PEER_DIR_STR (peer),
                    bo_cap->cap_as4ext.as4ext, peer->as);

          bo_cap->cap_as4ext.as4ext = pal_hton32 (bo_cap->cap_as4ext.as4ext);

          bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                            BGP_NOTIFY_OPEN_ERR,
                            BGP_NOTIFY_OPEN_BAD_PEER_AS,
                            (u_int8_t *) &bo_cap->cap_as4ext.as4ext,
                            sizeof (u_int32_t));
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
       }
   }
 if (CHECK_FLAG (BGP_VR.bvr_options,BGP_OPT_EXTENDED_ASN_CAP))
    SET_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV);
 
  
EXIT: 
  return ret;
}
#endif /* HAVE_EXT_CAP_ASN */

/*
 * LEVEL 4 BGP Message Decoder function:
 * Decodes OPEN Message Capabilities - Outbound-Route-Filters
 */
enum ssock_error
bpd_msg_open_cap_orf (struct cqueue_buffer *cq_rbuf,
                      struct bgp_peer *peer,
                      struct bgp_capability *bo_cap,
                      u_int32_t *cap_size)
{
  enum ssock_error ret;
  u_int8_t orf_type;
  u_int8_t orf_mode;
  u_int16_t sm_cap;
  u_int16_t rm_cap;
  u_int32_t idx;

  ret = SSOCK_ERR_NONE;
  sm_cap = 0;
  rm_cap = 0;

  /* Validate ORF Capability Length */
  if (bo_cap->cap_len < BGP_MSG_OPEN_OPT_CAP_ORF_MIN_SIZE)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open ORF: Cap-len error %d",
                peer->host, BGP_PEER_DIR_STR (peer), bo_cap->cap_len);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Get 'Cap-AFI' */
  CQUEUE_READ_INT16 (cq_rbuf, bo_cap->cap_orf.afi);
  (*cap_size) -= sizeof (u_int16_t);

  /* Get and ignore 'Cap-resv' */
  CQUEUE_READ_INT8 (cq_rbuf, bo_cap->cap_orf.reserved);
  (*cap_size)--;

  /* Get 'Cap-SAFI' */
  CQUEUE_READ_INT8 (cq_rbuf, bo_cap->cap_orf.safi);
  (*cap_size)--;

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [DECODE] Open ORF: ORF Cap (%s)"
               " for afi/safi: %u/%u",
               peer->host, BGP_PEER_DIR_STR (peer),
               bo_cap->cap_code == BGP_CAPABILITY_CODE_ORF ? "new" :
               "old", bo_cap->cap_orf.afi, bo_cap->cap_orf.safi);

  /* Validate AFI and SAFI values */
  if (! BGP_AFI_VALID_CHECK (bo_cap->cap_orf.afi)
      || ! BGP_SAFI_VALID_CHECK (bo_cap->cap_orf.safi))
    {
      zlog_err (&BLG, "%s-%s [DECODE] Open ORF: AFI/SAFI %d/%d error",
                peer->host, BGP_PEER_DIR_STR (peer),
                bo_cap->cap_orf.afi, bo_cap->cap_orf.safi);

      bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                        BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
      ret = SSOCK_ERR_CLOSE;
      goto EXIT;
    }

  /* Validate AFI and SAFI supported combination */
  if (! BGP_AFI_SAFI_SUPPORT_CHECK (bo_cap->cap_orf.afi,
                                    bo_cap->cap_orf.safi))
    {
      zlog_warn (&BLG, "%s-%s [DECODE] Open ORF: Addr-Family %u/%u"
                 " not supported, Ignoring ORF Cap",
                 peer->host, BGP_PEER_DIR_STR (peer),
                 bo_cap->cap_orf.afi, bo_cap->cap_orf.safi);

      CQUEUE_READ_ADVANCE_NBYTES (cq_rbuf, bo_cap->cap_len -
                                  sizeof (struct bgp_cap_mp));
      (*cap_size) -= (bo_cap->cap_len - sizeof (struct bgp_cap_mp));

      ret = SSOCK_ERR_NONE;
      goto EXIT;
    }

  /* Get 'Number of ORFs' */
  CQUEUE_READ_INT8 (cq_rbuf, bo_cap->cap_orf.num_orfs);
  (*cap_size)--;

  for (idx = 0 ; idx < bo_cap->cap_orf.num_orfs; idx++)
    {
      /* Get 'ORF type' */
      CQUEUE_READ_INT8 (cq_rbuf, orf_type);
      (*cap_size)--;

      /* Get 'ORF mode' */
      CQUEUE_READ_INT8 (cq_rbuf, orf_mode);
      (*cap_size)--;

      /* ORF Mode error check */
      if (orf_mode != BGP_ORF_MODE_BOTH
          && orf_mode != BGP_ORF_MODE_SEND
          && orf_mode != BGP_ORF_MODE_RECEIVE)
        {
          zlog_err (&BLG, "%s-%s [DECODE] Open ORF: Mode %d error",
                    peer->host, BGP_PEER_DIR_STR (peer), orf_mode);

          bpf_event_notify (peer, BPF_EVENT_OPEN_ERR,
                            BGP_NOTIFY_OPEN_ERR, 0, NULL, 0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* ORF Type and afi/safi error check */
      if (bo_cap->cap_code == BGP_CAPABILITY_CODE_ORF
          && orf_type == BGP_ORF_TYPE_PREFIX)
        {
          sm_cap = PEER_CAP_ORF_PREFIX_SM_RCV;
          rm_cap = PEER_CAP_ORF_PREFIX_RM_RCV;

          if (BGP_DEBUG (events, EVENTS))
            zlog_info (&BLG, "%s-%s [DECODE] Open ORF: Prefixlist"
                       " ORF(%d) mode %s AFI/SAFI %d/%d", peer->host,
                       BGP_PEER_DIR_STR (peer), BGP_ORF_TYPE_PREFIX,
                       orf_mode == BGP_ORF_MODE_SEND ? "SEND" :
                       orf_mode == BGP_ORF_MODE_RECEIVE ? "RECEIVE" :
                       "BOTH", bo_cap->cap_orf.afi, bo_cap->cap_orf.safi);
        }
      else if (bo_cap->cap_code == BGP_CAPABILITY_CODE_ORF_OLD
               && orf_type == BGP_ORF_TYPE_PREFIX_OLD)
        {
          sm_cap = PEER_CAP_ORF_PREFIX_SM_OLD_RCV;
          rm_cap = PEER_CAP_ORF_PREFIX_RM_OLD_RCV;

          if (BGP_DEBUG (events, EVENTS))
            zlog_info (&BLG, "%s-%s [DECODE] Open ORF: Prefixlist"
                       " ORF(%d) mode %s AFI/SAFI %d/%d", peer->host,
                       BGP_PEER_DIR_STR (peer), BGP_ORF_TYPE_PREFIX,
                       orf_mode == BGP_ORF_MODE_SEND ? "SEND" :
                       orf_mode == BGP_ORF_MODE_RECEIVE ? "RECEIVE" :
                       "BOTH", bo_cap->cap_orf.afi, bo_cap->cap_orf.safi);
        }
      else
        {
          if (BGP_DEBUG (events, EVENTS))
            zlog_info (&BLG, "%s-%s [DECODE] Open ORF: AFI/SAFI"
                       " %d/%d ORF type/mode %d/%d not supported",
                       peer->host, BGP_PEER_DIR_STR (peer),
                       bo_cap->cap_orf.afi, bo_cap->cap_orf.safi,
                       orf_type, orf_mode);

          continue;
        }

      switch (orf_mode)
        {
        case BGP_ORF_MODE_BOTH:
          SET_FLAG (peer->af_cap [BGP_AFI2BAAI (bo_cap->cap_orf.afi)]
                                 [BGP_SAFI2BSAI (bo_cap->cap_orf.safi)],
                                 sm_cap);
          SET_FLAG (peer->af_cap [BGP_AFI2BAAI (bo_cap->cap_orf.afi)]
                                 [BGP_SAFI2BSAI (bo_cap->cap_orf.safi)],
                                 rm_cap);
          break;
        case BGP_ORF_MODE_SEND:
          SET_FLAG (peer->af_cap [BGP_AFI2BAAI (bo_cap->cap_orf.afi)]
                                 [BGP_SAFI2BSAI (bo_cap->cap_orf.safi)],
                                 sm_cap);
          break;
        case BGP_ORF_MODE_RECEIVE:
          SET_FLAG (peer->af_cap [BGP_AFI2BAAI (bo_cap->cap_orf.afi)]
                                 [BGP_SAFI2BSAI (bo_cap->cap_orf.safi)],
                                 rm_cap);
          break;
        }
    }

EXIT:

  return ret;
}

/*
 * LEVEL 2-4 BGP Message Decoder function:
 * Validate NLRIs for syntactic and semantic correctness
 */
enum ssock_error
bpd_msg_update_nlri_validate (struct cqueue_buffer *cq_rbuf,
                              struct bgp_peer *peer,
                              afi_t afi,
                              safi_t safi,
                              u_int16_t nlri_size)
{
  enum ssock_error ret;
  struct prefix p;
  u_int8_t psize;
  ret = SSOCK_ERR_NONE;

  while (nlri_size)
    {
      /* Clear Prefix structure */
      pal_mem_set (&p, 0, sizeof (struct prefix));

      /* Determine Prefix Family */
      p.family = afi2family (afi);

      /* Get 'PrefixLen' structure */
      CQUEUE_READ_INT8 (cq_rbuf, p.prefixlen);
      nlri_size -= sizeof (u_int8_t);

      /* Determine Prefix size */
      psize = PSIZE (p.prefixlen);

      /* Sanity check the remaining size */
      if (psize > nlri_size)
        {
          zlog_err (&BLG, "%s-%s [DECODE] NLRI: Invalid Prefix Len(%d)",
                    peer->host, BGP_PEER_DIR_STR (peer), p.prefixlen);

          bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                            BGP_NOTIFY_UPDATE_ERR,
                            BGP_NOTIFY_UPDATE_INVAL_NETWORK,
                            NULL, 0);

          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      switch (safi)
        {
        /* Removed UNICAST_MULTICAST case as is not supported by RFC 4760 */
        case SAFI_UNICAST:
        case SAFI_MULTICAST:
          /* Validate Prefix-Len */
          if ((afi == AFI_IP && p.prefixlen > 32)
              || (afi == AFI_IP6 && p.prefixlen > 128))
            {
              zlog_err (&BLG, "%s-%s [DECODE] NLRI: SAFI-Unicast,"
                        " Invalid Prefix Len(%d)", peer->host,
                        BGP_PEER_DIR_STR (peer), p.prefixlen);

              bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                                BGP_NOTIFY_UPDATE_ERR,
                                BGP_NOTIFY_UPDATE_INVAL_NETWORK,
                                NULL, 0);

              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
            }

          /* Get 'Prefix' value */
          CQUEUE_READ_NBYTES (cq_rbuf, &p.u.prefix, psize);
          nlri_size -= psize;
          break;

        default:
          /* We have earlier ensured AFI-SAFI validation */
          pal_assert (0);
          ret = SSOCK_ERR_CLOSE;
          goto EXIT;
        }

      /* Validate Prefix value for Syntactic correctness */
      if (afi == AFI_IP
          && safi == SAFI_UNICAST)
        {
          if (p.u.prefix4.s_addr == INADDR_ANY && p.prefixlen == 32)
            {
              zlog_err (&BLG, "%s-%s [DECODE] NLRI: Invalid Unicast "
                        "NLRI(%r/%d)", peer->host, BGP_PEER_DIR_STR (peer),
                        &p.u.prefix4, p.prefixlen);

              bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                                BGP_NOTIFY_UPDATE_ERR,
                                BGP_NOTIFY_UPDATE_INVAL_NETWORK,
                                NULL, 0);

              ret = SSOCK_ERR_CLOSE;
              goto EXIT;
            }
        }
    }

EXIT:

  return ret;
}

/*
 * LEVEL 2-4 BGP Message Decoder function:
 * Validate IPv4 Next-Hop Address for semantic correctness
 */
s_int32_t
bpd_msg_update_nhop_validate (struct bgp_peer *peer,
                              struct pal_in4_addr *nhop_addr)
{
  struct pal_in4_addr addrval;
  s_int32_t ret;

  ret = 0;

  if (! nhop_addr)
    {
      ret = -1;
      goto EXIT;
    }

  addrval.s_addr = pal_ntoh32 (nhop_addr->s_addr);
  if (IN_CLASSD (addrval.s_addr))
    {
      zlog_err (&BLG, "%s-%s [DECODE] NHop Validate: "
                "Multicast NHop hop address %r received",
                peer->host, BGP_PEER_DIR_STR (peer), &addrval);
      ret = -1;
    }
  else if (IN_EXPERIMENTAL (addrval.s_addr))
    {
      zlog_err (&BLG, "%s-%s [DECODE] NHop Validate: "
                "Experimental NHop address %r received",
                peer->host, BGP_PEER_DIR_STR (peer), &addrval);
      ret = -1;
    }
  else if (addrval.s_addr == INADDR_ANY)
    {
      zlog_err (&BLG, "%s-%s [DECODE] NHop Validate: "
                "Invalid NHop address %r received",
                peer->host, BGP_PEER_DIR_STR (peer), &addrval);
      ret = -1;
    }

EXIT:

  return ret;
}

