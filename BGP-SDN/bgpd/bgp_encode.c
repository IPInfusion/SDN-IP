/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/*********************************************************************/
/* FILE       : bgp_encode.c                                         */
/* PURPOSE    : This file contains 'BGP Peer Message Encoding'       */
/*              related function definitions.                        */
/* SUB-MODULE : BGP Peer Encode                                      */
/* NAME-TAG   : 'bpe_' (BGP Peer Encoder)                            */
/*********************************************************************/

/* Formulate KEEP-ALIVE Message and send it to the Peer */
void
bgp_peer_send_keepalive (struct bgp_peer *peer)
{
  struct cqueue_buffer *cq_wbuf;

  /* Obtain CQ Buffer for writing */
  cq_wbuf = SSOCK_CB_GET_WRITE_CQ_BUF (peer->sock_cb,
                                       BGP_MSG_KEEPALIVE_MIN_SIZE, &BLG);
  if (! cq_wbuf)
    {
      zlog_err (&BLG, "%s-%s [ENCODE] Keepalive: Failed to get CQBuf",
                peer->host, BGP_PEER_DIR_STR (peer));
      return;
    }

  /* Count this Keepalive */
  peer->keepalive_out++;

  /* Encode the Message Header */
  bpe_msg_hdr (cq_wbuf, peer, BGP_MSG_KEEPALIVE,
               BGP_MSG_KEEPALIVE_MIN_SIZE);

  if (BGP_DEBUG (keepalive, KEEPALIVE)
      || BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [ENCODE] Keepalive: %d KAlive msg(s) sent",
               peer->host, BGP_PEER_DIR_STR (peer),
               peer->keepalive_out);

  /* Send Message out on socket */
  stream_sock_cb_write_mesg (peer->sock_cb, &BLG);

  return;
}

/* Formulate OPEN Message and send it to the Peer */
void
bgp_peer_send_open (struct bgp_peer *peer)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  struct cqueue_buffer *cq_wbuf;
  u_int16_t msg_size;

  /*
   * Obtain CQ Buffer for writing. Ask for MAX PKT LEN since
   * message size is not yet known.
   */
  cq_wbuf = SSOCK_CB_GET_WRITE_CQ_BUF (peer->sock_cb,
                                       BGP_MSG_OPEN_MAX_SIZE, &BLG);
  if (! cq_wbuf)
    {
      zlog_err (&BLG, "%s-%s [ENCODE] Open: Failed to get CQBuf",
                peer->host, BGP_PEER_DIR_STR (peer));
      return;
    }

  /* Count this OPEN Message */
  peer->open_out++;

  /*
   * Encode the Message Header. Need to SnapShot CQBUf here
   * to overwrite with correct Mesg-Size later.
   */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  bpe_msg_hdr (cq_wbuf, peer, BGP_MSG_OPEN, BGP_MSG_OPEN_MAX_SIZE);

  /* Encode OPEN Message */
  bpe_msg_open (cq_wbuf, peer);

  /* Obtain the Message Size and overwrite previous value in CQBuf */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
  msg_size = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                               &tmp_cqbss1);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  CQUEUE_WRITE_ADVANCE_NBYTES (cq_wbuf, BGP_MARKER_SIZE);
  CQUEUE_WRITE_INT16 (cq_wbuf, msg_size);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [ENCODE] Open: Msg-Size %d",
               peer->host, BGP_PEER_DIR_STR (peer), msg_size);

  /* Send Message out on socket */
  stream_sock_cb_write_mesg (peer->sock_cb, &BLG);

  return;
}

/*
 * Check if peer_fifo (one of peer->{adv_list,asorig}[][]->{reach,unreach})
 * is empty.
 * If it is empty,
 *  1. peer_fifo->next = 1st element of the fifo (FIFO head)
 *     peer_fifo->prev = pointer to peer group fifo
 *     (group_fifo, i.e.,
 *      &peer->group->conf->{adv_list,asorig}[][]->{reach,unreach})
 *
 * Input:
 *  peer:       Points to the peer data structure
 *  peer_fifo:  Points to one of
 *               'peer->{adv_list,asorig}[][]->{reach,unreach}'
 *  group_fifo: Points to one of
 *               'peer->group->conf->{adv_list,asorig}[][]->{reach,unreach}'
 *  fifo_type:  Pointer to a variable holding the type of FIFO.
 *              Value must be one of BGP_ADV_FIFO_XXX (in bgp_advertise.h)
 *              
 * Output:
 *  fifo_type:  0 if group FIFO is empty. The original value otherwise.
 *
 * Return:
 *  1: send to the wire
 *  0: do not send to the wire (reached the end of FIFO)
 */
u_int32_t
bgp_peer_group_check_adv_fifo (struct bgp_peer *peer,
                               struct fifo *peer_fifo,
                               struct fifo *group_fifo,
                               u_int32_t *fifo_type)
{
  if (FIFO_EMPTY (group_fifo))
    {
      *fifo_type = 0;
      return 0;
    }
  if (FIFO_EMPTY (peer_fifo))
    {
      peer_fifo->next = FIFO_HEAD (group_fifo);
      peer_fifo->prev = group_fifo;
    }
  else
    {
      /*
       * Check if reached the end of FIFO.
       */
      if (FIFO_NODE_NEXT (peer_fifo->prev, peer_fifo->next) == NULL)
        return 0;
    }

  return 1;
}

void
bgp_peer_group_init_adv_lists (struct bgp_peer_group *group,
                               pal_size_t offset, u_int32_t type,
                               u_int32_t baai, u_int32_t bsai)
{
  struct bgp_peer *peer;
  struct bgp_peer_adv_list *adv_list;
  struct fifo *fifo;
  struct listnode *nn;

  if (!group)
    {
      zlog_err (&BLG, "[ENCODE] NULL group");
      return;
    }

  LIST_LOOP (group->peer_list, peer, nn)
    {
      
      adv_list = *((struct bgp_peer_adv_list **)((pal_size_t)peer + offset));
      fifo = (type == BGP_REACH) ? &adv_list->reach : &adv_list->unreach;
      FIFO_INIT (fifo);

      if (BGP_DEBUG (update, UPDATE_OUT))
        {
          char *buf[] = {"adv_list", "asorig_adv_list"};
          char *s;

          s = (offset == ipi_offsetof
               (struct bgp_peer, adv_list [baai][bsai])) ? buf[0] : buf[1];

          zlog_info (&BLG, "%s: peer group %s: peer (0x%08x, id: %d): offset %d",
                     __FUNCTION__, group->name, (unsigned long)peer,
		     peer->peer_id, offset);
          zlog_info (&BLG, "  %s[%d][%d].%s (0x%08x): n: 0x%08x, p: 0x%08x",
                     s, baai, bsai, (type == BGP_REACH) ? "reach" : "unreach",
                     (unsigned long)fifo, (unsigned long)fifo->next,
		     (unsigned long)fifo->prev);
        }
    }
}

/*
 * Formulate BGP UPDATE Message(s) and send it to a peer
 * in the same peer group
 */
void
bgp_peer_group_send_update (struct bgp_peer *peer, bool_t auto_summary_update)
{
  struct bgp_peer *peer_gr = peer->group->conf;
  bool_t start_routeadv_timer;
  u_int32_t update_out_count;
  bool_t to_continue;
  u_int32_t baai;
  u_int32_t bsai;
  u_int32_t group_fifos = 0;
  u_int32_t group_fifo;
  int doit;

  start_routeadv_timer = PAL_TRUE;
  update_out_count = peer->update_out;

  assert(peer_gr);


  /* Checkout if an UPDATE needs to be sent */
  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        to_continue = PAL_FALSE;

        if (bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
          {
            assert(1);

            if ((FIFO_HEAD (&peer->adv_list_new [baai][bsai]->unreach)
                  || FIFO_HEAD (&peer->adv_list_new [baai][bsai]->reach))

                ||(FIFO_HEAD (&peer->asorig_adv_list_new [baai][bsai]->unreach)
                  || FIFO_HEAD (&peer->asorig_adv_list_new [baai][bsai]->reach))
               )
              {
                if (BGP_DEBUG (update, UPDATE_OUT))
                  zlog_info (&BLG, "populate the adj out for peer : %s afi : %d"
                      " safi : %d \n", peer->host, baai, bsai);
                bgp_populate_adj_out (peer, baai, bsai);
              }

          }

        group_fifo = BGP_ADV_FIFO_ADV_UNREACH;
        doit = bgp_peer_group_check_adv_fifo (peer,
                         &peer->adv_list [baai][bsai]->unreach,
                         &peer_gr->adv_list [baai][bsai]->unreach,
                                              &group_fifo);
        group_fifos |= group_fifo;
        group_fifo = BGP_ADV_FIFO_ADV_REACH;
        doit += bgp_peer_group_check_adv_fifo (peer,
                          &peer->adv_list [baai][bsai]->reach,
                          &peer_gr->adv_list [baai][bsai]->reach,
                                               &group_fifo);
        group_fifos |= group_fifo;
       if (doit)
          {
            to_continue = bgp_peer_send_update_adv_list (peer,
                                                         peer->adv_list
                                                               [baai][bsai],
                                                         BGP_BAAI2AFI (baai),
                                                         BGP_BSAI2SAFI (bsai),
                                                         auto_summary_update);

            if (BGP_DEBUG (update, UPDATE_OUT))
              {
                zlog_info (&BLG, "%s: peer (0x%08x, id: %d):",
                           __FUNCTION__, (unsigned long)peer, peer->peer_id);
                zlog_info (&BLG,
                           "  adv_list.reach (0x%08x): n: 0x%08x, p: 0x%08x",
                           (unsigned long)&(peer->adv_list [baai][bsai]->reach),
                           (unsigned long)peer->adv_list [baai][bsai]->reach.next,
                           (unsigned long)peer->adv_list [baai][bsai]->reach.prev);
                zlog_info (&BLG,
                           "         unreach (0x%08x): n: 0x%08x, p: 0x%08x",
                           (unsigned long)&(peer->adv_list [baai][bsai]->unreach),
                           (unsigned long)peer->adv_list [baai][bsai]->unreach.next,
                           (unsigned long)peer->adv_list [baai][bsai]->unreach.prev);
                zlog_info (&BLG, "peer group FIFO:");
                zlog_info (&BLG,
                           "  adv_list.reach (0x%08x): n: 0x%08x, p: 0x%08x",
                           (unsigned long)&(peer_gr->adv_list [baai][bsai]->reach),
                           (unsigned long)peer_gr->adv_list [baai][bsai]->reach.next,
                           (unsigned long)peer_gr->adv_list [baai][bsai]->reach.prev);
                zlog_info (&BLG,
                           "         unreach (0x%08x): n: 0x%08x, p: 0x%08x\n",
                           (unsigned long)&(peer_gr->adv_list [baai][bsai]->unreach),
                           (unsigned long)peer_gr->adv_list [baai][bsai]->unreach.next,
                           (unsigned long)peer_gr->adv_list [baai][bsai]->unreach.prev);
              }
            /*
             * Reset peer FIFO pointers when finished sending the last one
             */
            if (FIFO_EMPTY (&peer_gr->adv_list [baai][bsai]->unreach) &&
                (group_fifos & BGP_ADV_FIFO_ADV_UNREACH))
              bgp_peer_group_init_adv_lists (peer->group,
                                             ipi_offsetof (struct bgp_peer,
                                                           adv_list
                                                           [baai][bsai]),
                                             BGP_UNREACH, baai, bsai);
            if (FIFO_EMPTY (&peer_gr->adv_list [baai][bsai]->reach) &&
                (group_fifos & BGP_ADV_FIFO_ADV_REACH))
              bgp_peer_group_init_adv_lists (peer->group,
                                             ipi_offsetof (struct bgp_peer,
                                                           adv_list
                                                           [baai][bsai]),
                                             BGP_REACH, baai, bsai);
          }

        if (to_continue == PAL_FALSE
            && CHECK_FLAG (peer->af_sflags [baai][bsai],
                           PEER_STATUS_AF_ASORIG_ROUTE_ADV))
          {
            group_fifo = BGP_ADV_FIFO_ASORIG_UNREACH;
            doit = bgp_peer_group_check_adv_fifo (peer,
                           &peer->asorig_adv_list [baai][bsai]->unreach,
                           &peer_gr->asorig_adv_list [baai][bsai]->unreach,
                                                  &group_fifo);
            group_fifos |= group_fifo;
            group_fifo = BGP_ADV_FIFO_ASORIG_REACH;
            doit += bgp_peer_group_check_adv_fifo (peer,
                            &peer->asorig_adv_list [baai][bsai]->reach,
                            &peer_gr->asorig_adv_list [baai][bsai]->reach,
                                                   &group_fifo);
            if (doit)
              {
                to_continue =
                  bgp_peer_send_update_adv_list (peer,
                                                 peer->asorig_adv_list
                                                       [baai][bsai],
                                                 BGP_BAAI2AFI (baai),
                                                 BGP_BSAI2SAFI (bsai),
                                                 auto_summary_update);
                /*
                 * Reset peer FIFO pointers when finished sending the last one
                 */
                if (FIFO_EMPTY
                    (&peer_gr->asorig_adv_list [baai][bsai]->unreach) &&
                    (group_fifos & BGP_ADV_FIFO_ASORIG_UNREACH))
                  bgp_peer_group_init_adv_lists (peer->group,
                                                 ipi_offsetof (struct bgp_peer,
                                                               asorig_adv_list
                                                               [baai][bsai]),
                                                 BGP_UNREACH, baai, bsai);
                if (FIFO_EMPTY (&peer_gr->asorig_adv_list [baai][bsai]->reach) &&
                                        (group_fifos & BGP_ADV_FIFO_ASORIG_REACH))
                  bgp_peer_group_init_adv_lists (peer->group,
                                                 ipi_offsetof (struct bgp_peer,
                                                               asorig_adv_list
                                                               [baai][bsai]),
                                                 BGP_REACH, baai, bsai);
              }
            if (to_continue == PAL_FALSE && peer->v_asorig)
              UNSET_FLAG (peer->af_sflags [baai][bsai],
                          PEER_STATUS_AF_ASORIG_ROUTE_ADV);
          }

        if (to_continue == PAL_TRUE)
          {
            start_routeadv_timer = PAL_FALSE;
            BGP_PEER_FSM_EVENT_LOW_ADD (&BLG, peer,
                                        BPF_EVENT_ROUTEADV_EXP);
            goto EXIT;
          }
        else
          {
            /* Record Completion of Table Announcement */
            peer->table_version[baai][bsai] =
                                  peer->bgp->table_version[baai][bsai];
            bgp_af_status_set (peer->bgp,
                               BGP_BAAI2AFI (baai),
                               BGP_BSAI2SAFI (bsai),
                               BGP_AF_SFLAG_TABLE_ANNOUNCED);
          }
      }

EXIT:

  /* Restart RouteAdv Timer if required , do not restart the 
   * RouteAdv Timer if advertisement interval is set to zero
   */
  if (start_routeadv_timer == PAL_TRUE
      && !CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE))
    {
      if (peer->v_routeadv && ! peer->t_routeadv)
        BGP_TIMER_ON (&BLG, peer->t_routeadv, peer, bpf_timer_routeadv,
                      bpf_timer_generate_jitter (peer->v_routeadv));
      else if (! peer->v_routeadv && ! peer->t_routeadv)
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_ROUTEADV_EXP);
    }

  /* Restart Keepalive Timer if any UPDATE msg(s) were sent */
  if (update_out_count < peer->update_out)
    {
      /*
       * Do not modify 'advtime' if we deferred sending UPDATES
       * by posting Low-Priority Event
       */
      if (start_routeadv_timer == PAL_TRUE)
        peer->advtime = pal_time_sys_current (NULL);

      /* Now restart the Keep-alive Timer */
      if (peer->v_holdtime && peer->v_keepalive)
        BGP_TIMER_ON (&BLG, peer->t_keepalive, peer, bpf_timer_keepalive,
                      bpf_timer_generate_jitter (peer->v_keepalive));
    }

  return;
}

/* Formulate BGP UPDATE Message(s) and send it to the Peer */
void
bgp_peer_send_update (struct bgp_peer *peer, bool_t auto_summary_update)
{
  bool_t start_routeadv_timer;
  u_int32_t update_out_count;
  bool_t to_continue;
  u_int32_t baai;
  u_int32_t bsai;

  start_routeadv_timer = PAL_TRUE;
  update_out_count = peer->update_out;

  /* Checkout if an UPDATE needs to be sent */
  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        to_continue = PAL_FALSE;

        if (bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
          {
            if ((FIFO_HEAD (&peer->adv_list_new [baai][bsai]->unreach)
                  || FIFO_HEAD (&peer->adv_list_new [baai][bsai]->reach))

                ||(FIFO_HEAD (&peer->asorig_adv_list_new [baai][bsai]->unreach)
                  || FIFO_HEAD (&peer->asorig_adv_list_new [baai][bsai]->reach))
               )
              {
                if (BGP_DEBUG (update, UPDATE_OUT))
                  zlog_info (&BLG, "populate the adj out for peer : %s afi : %d"
                      " safi : %d \n", peer->host, baai, bsai);
                bgp_populate_adj_out (peer, baai, bsai);
              }

          }

        if (FIFO_HEAD (&peer->adv_list [baai][bsai]->unreach)
            || FIFO_HEAD (&peer->adv_list [baai][bsai]->reach))
          to_continue = bgp_peer_send_update_adv_list (peer,
                                                       peer->adv_list
                                                             [baai][bsai],
                                                       BGP_BAAI2AFI (baai),
                                                       BGP_BSAI2SAFI (bsai),
                                                       auto_summary_update);

        if (to_continue == PAL_FALSE
            && CHECK_FLAG (peer->af_sflags [baai][bsai],
                           PEER_STATUS_AF_ASORIG_ROUTE_ADV))
          {
            if (FIFO_HEAD (&peer->asorig_adv_list [baai][bsai]->unreach)
                || FIFO_HEAD (&peer->asorig_adv_list [baai][bsai]->reach))
              to_continue = bgp_peer_send_update_adv_list (peer,
                                                           peer->asorig_adv_list
                                                                 [baai][bsai],
                                                           BGP_BAAI2AFI (baai),
                                                           BGP_BSAI2SAFI (bsai),
                                                           auto_summary_update);
            if (to_continue == PAL_FALSE && peer->v_asorig)
              UNSET_FLAG (peer->af_sflags [baai][bsai],
                          PEER_STATUS_AF_ASORIG_ROUTE_ADV);
          }

        if (to_continue == PAL_TRUE)
          {
            start_routeadv_timer = PAL_FALSE;
            BGP_PEER_FSM_EVENT_LOW_ADD (&BLG, peer,
                                        BPF_EVENT_ROUTEADV_EXP);
            goto EXIT;
          }
        else
          {
            /* Record Completion of Table Announcement */
            peer->table_version[baai][bsai] =
                                  peer->bgp->table_version[baai][bsai];
            bgp_af_status_set (peer->bgp,
                               BGP_BAAI2AFI (baai),
                               BGP_BSAI2SAFI (bsai),
                               BGP_AF_SFLAG_TABLE_ANNOUNCED);
          }
      }

EXIT:

  /* Restart RouteAdv Timer if required , do not restart the 
   * RouteAdv Timer if advertisement interval is set to zero
   */
  if (start_routeadv_timer == PAL_TRUE
      && !CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE))
    {
      if (peer->v_routeadv && ! peer->t_routeadv)
        BGP_TIMER_ON (&BLG, peer->t_routeadv, peer, bpf_timer_routeadv,
                      bpf_timer_generate_jitter (peer->v_routeadv));
      else if (! peer->v_routeadv && ! peer->t_routeadv)
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_ROUTEADV_EXP);
    }

  /* Restart Keepalive Timer if any UPDATE msg(s) were sent */
  if (update_out_count < peer->update_out)
    {
      /*
       * Do not modify 'advtime' if we deferred sending UPDATES
       * by posting Low-Priority Event
       */
      if (start_routeadv_timer == PAL_TRUE)
        peer->advtime = pal_time_sys_current (NULL);

      /* Now restart the Keep-alive Timer */
      if (peer->v_holdtime && peer->v_keepalive)
        BGP_TIMER_ON (&BLG, peer->t_keepalive, peer, bpf_timer_keepalive,
                      bpf_timer_generate_jitter (peer->v_keepalive));
    }

  return;
}

/* Formulate BGP UPDATE Message(s) from the specified Advertisement-List */
bool_t
bgp_peer_send_update_adv_list (struct bgp_peer *peer,
                               struct bgp_peer_adv_list *adv_list,
                               afi_t afi, safi_t safi,
                               bool_t auto_summary_update)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  struct cqueue_buffer *cq_wbuf;
  u_int32_t msg_count;
  u_int16_t msg_size;
  bool_t to_continue;

  msg_count = 0;

  do {
    to_continue = PAL_FALSE;

    /*
     * Obtain CQ Buffer for writing. Ask for MAX PKT LEN
     * since message size is not yet known.
     */
    cq_wbuf = SSOCK_CB_GET_WRITE_CQ_BUF (peer->sock_cb,
                                         BGP_MAX_PACKET_SIZE,
                                         &BLG);
    if (! cq_wbuf)
      {
        zlog_err (&BLG, "%s-%s [ENCODE] Update: Failed to get"
                  " CQBuf", peer->host, BGP_PEER_DIR_STR (peer));

        to_continue = PAL_TRUE;
        break;
      }

    /*
     * Encode the Message Header. Need to SnapShot CQBUf
     * here to overwrite with correct Mesg-Size later.
     */
    CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
    bpe_msg_hdr (cq_wbuf, peer, BGP_MSG_UPDATE,
                 BGP_MAX_PACKET_SIZE);

    /* Encode one UPDATE Message */
    to_continue = bpe_msg_update (cq_wbuf, peer, adv_list,
                                  afi, safi, auto_summary_update);

    /*
     * Obtain the Message Size and overwrite previous
     * value in CQBuf
     */
    CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
    msg_size = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                                 &tmp_cqbss1);
    CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
    CQUEUE_WRITE_ADVANCE_NBYTES (cq_wbuf, BGP_MARKER_SIZE);
    CQUEUE_WRITE_INT16 (cq_wbuf, msg_size);
    CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);

    /* Send Message out on socket */
    stream_sock_cb_write_mesg (peer->sock_cb, &BLG);

    /* Count this UPDATE Message */
    peer->update_out++;

    msg_count += 1;

    /* Turn-off Keepalive Timer, we'll restart it in a bit */
    BGP_TIMER_OFF (peer->t_keepalive);

    if (BGP_DEBUG (events, EVENTS))
      zlog_info (&BLG, "%s-%s [ENCODE] Update: Msg #%d Size %d",
                 peer->host, BGP_PEER_DIR_STR (peer),
                 peer->update_out, msg_size);
  } while (to_continue == PAL_TRUE
           && msg_count < BGP_SEND_MSG_CLUST_MAX_COUNT);

  return to_continue;
}

/* Formulate NOTIFICATION Message and send it to the Peer */
void
bgp_peer_send_notify (struct bgp_peer *peer)
{
  struct cqueue_buffer *cq_wbuf;
  u_int32_t msg_size;

  if (! peer->notify_info)
    goto EXIT;

  /* Purge All Unsent (queued) Whole Messages */
  stream_sock_cb_purge_unsent_bufs (peer->sock_cb, &BLG);
    
  /* Determine Notification Message Size */
  msg_size = peer->notify_info->not_err_dlen + BGP_MSG_NOTIFY_MIN_SIZE;

  /* Obtain CQ Buffer for writing */
  cq_wbuf = SSOCK_CB_GET_WRITE_CQ_BUF (peer->sock_cb, msg_size, &BLG);
  if (! cq_wbuf)
    {
      /* Not an error since the Sock-CB may have IDLEd already */
      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [ENCODE] Notify: Failed to get CQBuf",
                   peer->host, BGP_PEER_DIR_STR (peer));
      goto EXIT;
    }

  /* Count this NOTIFICATION Message */
  peer->notify_out++;

  /* Encode the Message Header */
  bpe_msg_hdr (cq_wbuf, peer, BGP_MSG_NOTIFY, msg_size);

  /* Encode OPEN Message */
  bpe_msg_notify (cq_wbuf, peer);

  if (BGP_DEBUG (normal, NORMAL)
      || bgp_config_check (peer->bgp, BGP_CFLAG_LOG_NEIGHBOR_CHANGES))
    bgp_log_neighbor_notify_print (peer, peer->notify_info,
                                   (u_int8_t *) "sending to");

  /* Make the best possible effort to send-out NOTIFY */
  bpn_sock_set_opt_nodelay (peer);

  /* Send Message out on socket */
  stream_sock_cb_write_mesg (peer->sock_cb, &BLG);

  peer->notify_info->not_err_dir_sent = PAL_TRUE;

EXIT:

  return;
}

/* Formulate Route-Refresh Message and send it to the Peer */
void
bgp_peer_send_route_refresh (struct bgp_peer *peer,
                             afi_t afi, safi_t safi,
                             u_int8_t orf_type,
                             u_int8_t when_to_refresh,
                             u_int32_t orf_remove)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  struct cqueue_buffer *cq_wbuf;
  u_int16_t msg_size;

#ifdef DISABLE_BGP_ANNOUNCE
  return;
#endif /* DISABLE_BGP_ANNOUNCE */

  /*
   * Obtain CQ Buffer for writing. Ask for MAX PKT LEN since
   * message size is not yet known.
   */
  cq_wbuf = SSOCK_CB_GET_WRITE_CQ_BUF (peer->sock_cb,
                                       BGP_MSG_OPEN_MAX_SIZE, &BLG);
  if (! cq_wbuf)
    {
      zlog_err (&BLG, "%s-%s [ENCODE] R-Refresh: Failed to get CQBuf",
                peer->host, BGP_PEER_DIR_STR (peer));
      return;
    }

  /* Count this Route-Refresh Message */
  peer->refresh_out++;

  /*
   * Encode the Message Header. Need to SnapShot CQBUf here
   * to overwrite with correct Mesg-Size later.
   */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  if (CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV))
    bpe_msg_hdr (cq_wbuf, peer, BGP_MSG_ROUTE_REFRESH_NEW,
                 BGP_MAX_PACKET_SIZE);
  else
    bpe_msg_hdr (cq_wbuf, peer, BGP_MSG_ROUTE_REFRESH_OLD,
                 BGP_MAX_PACKET_SIZE);

  /* Encode Route-Refresh Message */
  bpe_msg_route_refresh (cq_wbuf, peer, afi, safi,
                         orf_type, when_to_refresh, orf_remove);

  /* Obtain the Message Size and overwrite previous value in CQBuf */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
  msg_size = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                               &tmp_cqbss1);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  CQUEUE_WRITE_ADVANCE_NBYTES (cq_wbuf, BGP_MARKER_SIZE);
  CQUEUE_WRITE_INT16 (cq_wbuf, msg_size);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [ENCODE] Route-Refresh: RR-Type %s MsgSize %d",
               peer->host, BGP_PEER_DIR_STR (peer),
               CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV) ?
               "New" : "Old", msg_size);

  /* Send Message out on socket */
  stream_sock_cb_write_mesg (peer->sock_cb, &BLG);

  return;
}

/* Formulate CAPABILITY Message and send it to the Peer */
void
bgp_peer_send_dyna_cap (struct bgp_peer *peer,
                        afi_t afi, safi_t safi,
                        u_int8_t cap_code,
                        u_int8_t cap_action)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  struct cqueue_buffer *cq_wbuf;
  u_int16_t msg_size;

  /*
   * Obtain CQ Buffer for writing. Ask for MAX PKT LEN since
   * message size is not yet known.
   */
  cq_wbuf = SSOCK_CB_GET_WRITE_CQ_BUF (peer->sock_cb,
                                       BGP_MSG_DYNA_CAP_MAX_SIZE, &BLG);
  if (! cq_wbuf)
    {
      zlog_err (&BLG, "%s-%s [ENCODE] DYNA-CAP: Failed to get CQBuf",
                peer->host, BGP_PEER_DIR_STR (peer));
      return;
    }

  /* Count this DYNA-CAP Message */
  peer->dynamic_cap_out++;

  /*
   * Encode the Message Header. Need to SnapShot CQBUf here
   * to overwrite with correct Mesg-Size later.
   */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  bpe_msg_hdr (cq_wbuf, peer, BGP_MSG_CAPABILITY,
               BGP_MSG_DYNA_CAP_MAX_SIZE);

  /* Encode DYNA-CAP Message */
  bpe_msg_dyna_cap (cq_wbuf, peer, afi, safi, cap_code, cap_action);

  /* Obtain the Message Size and overwrite previous value in CQBuf */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
  msg_size = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                               &tmp_cqbss1);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  CQUEUE_WRITE_ADVANCE_NBYTES (cq_wbuf, BGP_MARKER_SIZE);
  CQUEUE_WRITE_INT16 (cq_wbuf, msg_size);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [ENCODE] DYNA-CAP: AFI-SAFI %d-%d",
               peer->host, BGP_PEER_DIR_STR (peer), afi, safi);

  /* Send Message out on socket */
  stream_sock_cb_write_mesg (peer->sock_cb, &BLG);

  return;
}

/*
 * LEVEL 1 BGP Message Encoder function:
 * Encodes BGP Message Header
 */
s_int32_t
bpe_msg_hdr (struct cqueue_buffer *cq_wbuf,
             struct bgp_peer *peer,
             u_int8_t msg_type,
             u_int16_t msg_size)
{
  u_int32_t tmp_uint;
  u_int32_t idx;

  tmp_uint = ~0;

  /* Encode BGP Message Header Marker */
  for (idx = 0; idx < (BGP_MARKER_SIZE >> 2); idx++)
    CQUEUE_WRITE_4BYTES (cq_wbuf, &tmp_uint);

  /* Encode 'msg_len' value */
  CQUEUE_WRITE_INT16 (cq_wbuf, msg_size);

  /* Encode 'msg_type' value */
  CQUEUE_WRITE_INT8 (cq_wbuf, msg_type);

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [ENCODE] Msg-Hdr: Type %d",
               peer->host, BGP_PEER_DIR_STR (peer), msg_type);

  return 0;
}

/*
 * LEVEL 1 BGP Message Encoder function:
 * Encodes BGP OPEN Message
 */
s_int32_t
bpe_msg_open (struct cqueue_buffer *cq_wbuf,
              struct bgp_peer *peer)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  u_int16_t send_holdtime;
  u_int8_t opt_param_len;

  opt_param_len = 0;

  /* Encode BGP 'Version' value */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_VERSION_4);

  /* Encode 'My AS' value */
#ifndef HAVE_EXT_CAP_ASN
  CQUEUE_WRITE_INT16 (cq_wbuf, peer->local_as);
#else
  /* 4-octet Non-mappable NBGP sends AS_TRANS as its My AS. */
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)
      && ! BGP_IS_AS4_MAPPABLE(peer->local_as))
    CQUEUE_WRITE_INT16 (cq_wbuf, BGP_AS_TRANS);
  else 
    CQUEUE_WRITE_INT16 (cq_wbuf, peer->local_as);          
#endif /* HAVE_EXT_CAP_ASN */
  /* Determine the 'hold-time' value */
  send_holdtime = peer->holdtime;
  if (peer->real_peer)
    send_holdtime = peer->real_peer->holdtime;

  /* Encode 'Holdtime' value */
  CQUEUE_WRITE_INT16 (cq_wbuf, send_holdtime);

  /* Encode 'BGP ID' value */
  CQUEUE_WRITE_4BYTES (cq_wbuf, &peer->local_id);

  /* Encode 'OPEN Opt Param Len' value */
  CQUEUE_WRITE_INT8 (cq_wbuf, opt_param_len);

  /* Check if OPEN Caps need be sent */
  if (CHECK_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN)
      && ! CHECK_FLAG (peer->flags, PEER_FLAG_DONT_CAPABILITY))
    {
      /*
       * Take a CQBuf SnapShot here to overwrite with revised
       * 'Opt Param Len' later.
       */
      CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);

      /* Encode 'BGP Capablities Optional Parameter' */
      bpe_msg_open_cap (cq_wbuf, peer);

      /* Obtain 'Opt Param Len' and overwrite previous value */
      CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
      opt_param_len = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                                        &tmp_cqbss1);
      CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
      CQUEUE_WRITE_REWIND_NBYTES (cq_wbuf,
                                  BGP_MSG_OPEN_OPT_LEN_FIELD_SIZE);
      CQUEUE_WRITE_INT8 (cq_wbuf, opt_param_len);
      CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
    }

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [ENCODE] Open: Ver %d MyAS %d Holdtime %d",
               peer->host, BGP_PEER_DIR_STR (peer), BGP_VERSION_4,
               peer->local_as, send_holdtime);

  return 0;
}

/*
 * LEVEL 1 BGP Message Encoder function:
 * Encodes BGP UPDATE Message
 */
bool_t
bpe_msg_update (struct cqueue_buffer *cq_wbuf,
                struct bgp_peer *peer,
                struct bgp_peer_adv_list *adv_list,
                afi_t afi, safi_t safi,
                bool_t auto_summary_update)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  struct bgp_advertise *adv_out;
  struct bgp_peer *from_peer;
  u_int16_t tot_attr_len;
  bool_t mp_unreach_done;
  bool_t withdrawn_done;
  struct fifo *ba_fifo;
  bool_t to_continue;
  struct attr *attr;

  mp_unreach_done = PAL_FALSE;
  withdrawn_done = PAL_FALSE;
  to_continue = PAL_FALSE;
  from_peer = NULL;
  tot_attr_len = 0;
  attr = NULL;

  if (afi == AFI_IP && safi == SAFI_UNICAST)
    {
      /* First Encode Withdrawn NLRIs if any */
      ba_fifo = FIFO_HEAD (&adv_list->unreach);
      if (ba_fifo)
        {
          withdrawn_done = PAL_TRUE;

          to_continue = bpe_msg_update_withdrawn (cq_wbuf, peer,
                                                  &adv_list->unreach,
                                                  auto_summary_update);
        }
      else
        {
          /* Write a 'withdrawn_len' of ZERO */
          CQUEUE_WRITE_INT16 (cq_wbuf, 0);
        }

      /* Next Encode Path-Attributes and NLRIs if any */
      ba_fifo = FIFO_HEAD (&adv_list->reach);
      if (ba_fifo && to_continue == PAL_FALSE)
        {
          adv_out = (struct bgp_advertise *) ba_fifo;

          if (! adv_out->rn)
            {
              /* Encode End-of-Rib Marker */
              if (withdrawn_done == PAL_FALSE)
                {
                  to_continue = bpe_msg_update_endofrib (cq_wbuf, peer);

                  /* Free this End-of-Rib Marker from Adv-List */
                  if (!bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
                    bgp_advertise_clean (peer, &adv_out->adj,
                                         AFI_IP, SAFI_UNICAST);
                  else
                    bgp_rib_out_free (adv_out->rn, adv_out->adj, peer,
                                      AFI_IP, SAFI_UNICAST,
                                      auto_summary_update); 
                }
            }
          else
            {
              attr = adv_out->baa ? adv_out->baa->attr : NULL;
              from_peer = adv_out->binfo ? adv_out->binfo->peer
                          : peer->bgp->peer_self;

              /* Encode Path-Attributes */
              if (to_continue == PAL_FALSE)
                to_continue = bpe_msg_attr_ip (cq_wbuf, peer,
                                               from_peer, attr);

              /* Encode Advertised NLRIs */
              if (to_continue == PAL_FALSE)
                to_continue = bpe_msg_update_nlri (cq_wbuf, peer,
                                                   &adv_list->reach,
                                                   auto_summary_update);
            }
        }
      else /* Write the 'tot_attr_len' of ZERO */
        CQUEUE_WRITE_INT16 (cq_wbuf, 0);
    }
  else /* MP UPDATE Message Encoding */
    {
      /* Encode a 'withdrawn_len' of ZERO */
      CQUEUE_WRITE_INT16 (cq_wbuf, 0);

      /* Write a dummy 'tot_attr_len' */
      CQUEUE_WRITE_INT16 (cq_wbuf, tot_attr_len);

      /*
       * Take a CQBuf SnapShot here to overwrite with correct
       * 'tot_attr_len' later.
       */
      CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);

      /* Encode MP UnReach NLRIs if any */
      ba_fifo = FIFO_HEAD (&adv_list->unreach);
      if (ba_fifo)
        {
          mp_unreach_done = PAL_TRUE;

          to_continue = bpe_msg_attr_mp_unreach (cq_wbuf, peer, afi, safi,
                                                 &adv_list->unreach);
        }

      /* Next Encode MP Attributes and MP Reach NLRIs if any */
      ba_fifo = FIFO_HEAD (&adv_list->reach);
      if (ba_fifo && to_continue == PAL_FALSE)
        {
          adv_out = (struct bgp_advertise *) ba_fifo;

          if (! adv_out->rn)
            {
              /* Encode MP Unreach End-of-Rib Marker */
              if (mp_unreach_done == PAL_FALSE)
                {
                  to_continue = bpe_msg_attr_mp_endofrib (cq_wbuf, peer,
                                                          afi, safi);

                  /* Free this End-of-Rib Marker from Adv-List */
                  if (!bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
                    bgp_advertise_clean (peer, &adv_out->adj, afi, safi);
                  else
                     bgp_rib_out_free (adv_out->rn, adv_out->adj, peer,
                                       afi, safi, auto_summary_update);
                }
            }
          else
            {
              attr = adv_out->baa ? adv_out->baa->attr : NULL;
              from_peer = adv_out->binfo ? adv_out->binfo->peer
                          : peer->bgp->peer_self;

              /* Encode MP Path-Attributes */
              if (to_continue == PAL_FALSE)
                to_continue = bpe_msg_attr_mp (cq_wbuf, peer, from_peer,
                                               attr, afi, safi);

              /* Encode MP Reach NLRIs */
              if (to_continue == PAL_FALSE)
                to_continue = bpe_msg_attr_mp_reach (cq_wbuf, peer, attr, afi,
                                                     safi, &adv_list->reach);
            }
        }

      /* Obtain 'tot_attr_len' and overwrite previous value */
      CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
      tot_attr_len = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                                       &tmp_cqbss1);
      CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
      CQUEUE_WRITE_REWIND_NBYTES (cq_wbuf, BGP_TOTAL_ATTR_LEN_FIELD_SIZE);
      CQUEUE_WRITE_INT16 (cq_wbuf, tot_attr_len);
      CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);

      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [ENCODE] Update: AFI/SAFI (%d/%d) "
                   "Tot-attr-len %d", peer->host,
                   BGP_PEER_DIR_STR (peer), afi, safi, tot_attr_len);
    }

  return to_continue;
}

/*
 * LEVEL 1 BGP Message Encoder function:
 * Encodes BGP NOTIFICATION Message
 */
s_int32_t
bpe_msg_notify (struct cqueue_buffer *cq_wbuf,
                struct bgp_peer *peer)
{
  /* Encode 'Err Code' value */
  CQUEUE_WRITE_INT8 (cq_wbuf, peer->notify_info->not_err_code);

  /* Encode 'Err Sub-Code' value */
  CQUEUE_WRITE_INT8 (cq_wbuf, peer->notify_info->not_err_sub_code);

  /* Encode 'Err Sub-Code' value */
  if (peer->notify_info->not_err_dlen)
    CQUEUE_WRITE_NBYTES (cq_wbuf, peer->notify_info->not_err_data,
                         peer->notify_info->not_err_dlen);

  return 0;
}

/*
 * LEVEL 1 BGP Message Encoder function:
 * Encodes BGP ROUTE-REFRESH Message
 */
s_int32_t
bpe_msg_route_refresh (struct cqueue_buffer *cq_wbuf,
                       struct bgp_peer *peer,
                       afi_t afi, safi_t safi,
                       u_int8_t orf_type,
                       u_int8_t when_to_refresh,
                       u_int32_t orf_remove)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  struct prefix_list_entry *pentry;
  struct bgp_filter *filter;
  u_int16_t orf_len;
  struct prefix *p;
  u_int32_t baai;
  u_int32_t bsai;
  u_int8_t psize;
  u_int8_t flag;
  s_int32_t ret;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);
  orf_len = 0;
  ret = 0;

  /* Encode 'AFI-SAFI' values */
  CQUEUE_WRITE_INT16 (cq_wbuf, afi);
  CQUEUE_WRITE_INT8 (cq_wbuf, 0);
  CQUEUE_WRITE_INT8 (cq_wbuf, safi);

  if (orf_type == BGP_ORF_TYPE_PREFIX
      || orf_type == BGP_ORF_TYPE_PREFIX_OLD)
    {
      filter = &peer->filter [baai][bsai];

      if (orf_remove || (filter && filter->plist [FILTER_IN].plist))
        {
          CQUEUE_WRITE_INT8 (cq_wbuf, when_to_refresh);
          CQUEUE_WRITE_INT8 (cq_wbuf, orf_type);

          /*
           * Take a CQBuf SnapShot here to overwrite with correct
           * 'orf_len' later.
           */
          CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);

          /* Write a dummy 'withdrawn_len' */
          CQUEUE_WRITE_INT16 (cq_wbuf, orf_len);

          if (orf_remove)
            {
              UNSET_FLAG (peer->af_sflags [baai][bsai],
                          PEER_STATUS_ORF_PREFIX_SEND);

              CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ORF_COMMON_ACTION_REMOVE_ALL);

              if (BGP_DEBUG (events, EVENTS))
                zlog_info (&BLG, "%s-%s [ENCODE] R-Refresh: Remove ORF "
                           "Type: %d (%s) for AFI/SAFI: %d/%d",
                           peer->host, BGP_PEER_DIR_STR (peer), orf_type,
                           (when_to_refresh == BGP_ORF_REFRESH_DEFER ?
                            "defer" : "immediate"), afi, safi);
            }
          else
            {
              SET_FLAG (peer->af_sflags [baai][bsai],
                        PEER_STATUS_ORF_PREFIX_SEND);

              for (pentry = filter->plist [FILTER_IN].plist->head;
                   pentry; pentry = pentry->next)
                {
                  p = &pentry->prefix;

                  flag = BGP_ORF_COMMON_ACTION_ADD;
                  flag |= (pentry->type == PREFIX_PERMIT ?
                           BGP_ORF_COMMON_MATCH_PERMIT :
                           BGP_ORF_COMMON_MATCH_DENY);

                  /* Encode 'Flag', 'SeqNo' ... */
                  CQUEUE_WRITE_INT8 (cq_wbuf, flag);
                  CQUEUE_WRITE_INT32 (cq_wbuf, (u_int32_t)pentry->seq);
                  CQUEUE_WRITE_INT8 (cq_wbuf, (u_int8_t)pentry->ge);
                  CQUEUE_WRITE_INT8 (cq_wbuf, (u_int8_t)pentry->le);

                  /* Encode Prefix value */
                  psize = PSIZE (p->prefixlen);
                  CQUEUE_WRITE_INT8 (cq_wbuf, p->prefixlen);
                  CQUEUE_WRITE_NBYTES (cq_wbuf, &p->u.prefix, psize);
                }

              if (BGP_DEBUG (events, EVENTS))
                zlog_info (&BLG, "%s-%s [ENCODE] R-Refresh: Add ORF "
                           "Type: %d (%s) for AFI/SAFI: %d/%d",
                           peer->host, BGP_PEER_DIR_STR (peer), orf_type,
                           (when_to_refresh == BGP_ORF_REFRESH_DEFER ?
                            "defer" : "immediate"), afi, safi);
            }

          /* Obtain 'ORF Len' and overwrite previous value in CQBuf */
          CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
          orf_len = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                                      &tmp_cqbss1) - 2;
          CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
          CQUEUE_WRITE_INT16 (cq_wbuf, orf_len);
          CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
        }
    }

  return ret;
}

/*
 * LEVEL 1 BGP Message Encoder function:
 * Encodes BGP DYNAMIC-CAPABILITY Message
 */
s_int32_t
bpe_msg_dyna_cap (struct cqueue_buffer *cq_wbuf,
                  struct bgp_peer *peer,
                  afi_t afi, safi_t safi,
                  u_int8_t cap_code,
                  u_int8_t cap_action)
{
  s_int32_t ret;
  ret = 0;
  static u_int32_t sequence =0;
  struct capbilitymessage capabilitymsg;

  pal_mem_set (&capabilitymsg.cap_header.action_header, 0,1);

   /* currently setting INIT/ACK bit is always set to 0 i.e. no ACK is requested.*/
   capabilitymsg.seqno= sequence;
    
    switch (cap_code)
    {
    case BGP_CAPABILITY_CODE_MP:
      capabilitymsg.cap_header.action = cap_action & 0x1;
      CQUEUE_WRITE_INT8 (cq_wbuf, capabilitymsg.cap_header.action_header);
      CQUEUE_WRITE_INT32(cq_wbuf, capabilitymsg.seqno);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP_LEN);
      CQUEUE_WRITE_INT16 (cq_wbuf, afi);
      CQUEUE_WRITE_INT8 (cq_wbuf, 0);
      CQUEUE_WRITE_INT8 (cq_wbuf, safi);

      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [ENCODE] DYNA-CAP: %s MP_EXT CAP",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   cap_action == BGP_CAPABILITY_ACTION_SET ?
                   "Advertising" : "Removing");
      break;

    case BGP_CAPABILITY_CODE_REFRESH:
    case BGP_CAPABILITY_CODE_REFRESH_OLD:
      capabilitymsg.cap_header.action = cap_action & 0x1;
      CQUEUE_WRITE_INT8 (cq_wbuf,  capabilitymsg.cap_header.action_header);
      CQUEUE_WRITE_INT32(cq_wbuf, capabilitymsg.seqno);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH_LEN);
      capabilitymsg.cap_header.action =cap_action & 0x1;
      CQUEUE_WRITE_INT8 (cq_wbuf,  capabilitymsg.cap_header.action_header);
      CQUEUE_WRITE_INT32 (cq_wbuf, capabilitymsg.seqno);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH_OLD);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH_LEN);

      if (BGP_DEBUG (events, EVENTS))
        zlog_info (&BLG, "%s-%s [ENCODE] DYNA-CAP: %s R-Refresh(New+Old)"
                   " CAP", peer->host, BGP_PEER_DIR_STR (peer),
                   cap_action == BGP_CAPABILITY_ACTION_SET ?
                   "Advertising" : "Removing");
      break;
#ifdef HAVE_EXT_CAP_ASN
     /* Encode EXTASN Capability. */
    case BGP_CAPABILITY_CODE_EXTASN:
       if (CHECK_FLAG (BGP_VR.bvr_options,BGP_OPT_EXTENDED_ASN_CAP))
         {    
           capabilitymsg.cap_header.action = cap_action & 0x1;
           CQUEUE_WRITE_INT8  (cq_wbuf, capabilitymsg.cap_header.action_header);
           CQUEUE_WRITE_INT32 (cq_wbuf, capabilitymsg.seqno);
           CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_EXTASN);
           CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_EXTASN_LEN);
           CQUEUE_WRITE_INT32 (cq_wbuf,peer->local_as);

           if (BGP_DEBUG (events, EVENTS))
           zlog_info (&BLG, "%s-%s [ENCODE] DYNA-CAP: %s  EXTENDED_ASN CAP",
                      peer->host, BGP_PEER_DIR_STR (peer),
                      cap_action == BGP_CAPABILITY_ACTION_SET ?
                      "Advertising" : "Removing");
          } 
      break;
 
#endif /* HAVE_EXT_CAP_ASN */

    default:
      pal_assert (0);
      break;
    }
  sequence++;
  return ret;
}

/*
 * LEVEL 2 BGP Message Encoder function:
 * Encodes BGP OPEN Message Capabilities Optional Parameter
 */
void
bpe_msg_open_cap (struct cqueue_buffer *cq_wbuf,
                  struct bgp_peer *peer)
{
  u_int32_t baai;
  u_int32_t bsai;
  /* When the peer is IPv4-UNICAST only, do not send capability */
  if (! peer->afc [BAAI_IP][BSAI_MULTICAST]
      && ! peer->afc [BAAI_IP6][BSAI_UNICAST]
      && ! peer->afc [BAAI_IP6][BSAI_MULTICAST]
      && CHECK_FLAG (peer->flags, PEER_FLAG_NO_ROUTE_REFRESH_CAP)
      && ! CHECK_FLAG (peer->flags, PEER_FLAG_DYNAMIC_CAPABILITY)
      && (PAL_FALSE == bgp_peer_orf_capability_active (peer))
      )
    return;

  /* Encode IPv4-UNICAST Capability */
  if (peer->afc [BAAI_IP][BSAI_UNICAST])
    {
      peer->afc_adv [BAAI_IP][BSAI_UNICAST] = 1;
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_OPEN_OPT_CAP);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP_LEN + 2);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP_LEN);
      CQUEUE_WRITE_INT16 (cq_wbuf, AFI_IP);
      CQUEUE_WRITE_INT8 (cq_wbuf, 0);
      CQUEUE_WRITE_INT8 (cq_wbuf, SAFI_UNICAST);
    }

  /* Encode IPv4-MULTICAST Capability */
  if (peer->afc [BAAI_IP][BSAI_MULTICAST])
    {
      peer->afc_adv [BAAI_IP][BSAI_MULTICAST] = 1;
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_OPEN_OPT_CAP);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP_LEN + 2);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP_LEN);
      CQUEUE_WRITE_INT16 (cq_wbuf, AFI_IP);
      CQUEUE_WRITE_INT8 (cq_wbuf, 0);
      CQUEUE_WRITE_INT8 (cq_wbuf, SAFI_MULTICAST);
    }

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      /* Encode IPv6-UNICAST Capability */
      if (peer->afc [BAAI_IP6][BSAI_UNICAST])
        {
          peer->afc_adv [BAAI_IP6][BSAI_UNICAST] = 1;
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_OPEN_OPT_CAP);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP_LEN + 2);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP_LEN);
          CQUEUE_WRITE_INT16 (cq_wbuf, AFI_IP6);
          CQUEUE_WRITE_INT8 (cq_wbuf, 0);
          CQUEUE_WRITE_INT8 (cq_wbuf, SAFI_UNICAST);
        }

      /* Encode IPv6-MULTICAST Capability */
      if (peer->afc [BAAI_IP6][BSAI_MULTICAST])
        {
          peer->afc_adv [BAAI_IP6][BSAI_MULTICAST] = 1;
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_OPEN_OPT_CAP);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP_LEN + 2);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP_LEN);
          CQUEUE_WRITE_INT16 (cq_wbuf, AFI_IP6);
          CQUEUE_WRITE_INT8 (cq_wbuf, 0);
          CQUEUE_WRITE_INT8 (cq_wbuf, SAFI_MULTICAST);
        }
      }
#endif /* HAVE_IPV6 */

  /* Encode Route-Refresh Capability */
  if (! CHECK_FLAG (peer->flags, PEER_FLAG_NO_ROUTE_REFRESH_CAP))
    {
      SET_FLAG (peer->cap, PEER_CAP_REFRESH_ADV);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_OPEN_OPT_CAP);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH_LEN + 2);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH_OLD);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH_LEN);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_OPEN_OPT_CAP);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH_LEN + 2);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH_LEN);
    }

  /* Encode Dynamic Capability */
    /* Encode Dynamic Capability */
    if (CHECK_FLAG (peer->flags, PEER_FLAG_DYNAMIC_CAPABILITY))
      {
          struct cqueue_buf_snap_shot tmp_cqbss1;
          struct cqueue_buf_snap_shot tmp_cqbss2;
          struct cqueue_buf_snap_shot tmp_cqbss3;
          u_int8_t dyn_cap_len = 0;
          SET_FLAG (peer->cap, PEER_CAP_DYNAMIC_ADV);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_OPEN_OPT_CAP);
          CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_DYNAMIC_LEN);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_DYNAMIC);
          CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_DYNAMIC_LEN);

         if (! CHECK_FLAG (peer->flags, PEER_FLAG_NO_ROUTE_REFRESH_CAP))
           {
             CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_REFRESH);
             dyn_cap_len++;
           }

         if ( (peer->afc [BAAI_IP][BSAI_UNICAST]) ||
              (peer->afc [BAAI_IP][BSAI_MULTICAST])
#ifdef HAVE_IPV6
             || (peer->afc [BAAI_IP6][BSAI_UNICAST]) ||
              (peer->afc [BAAI_IP6][BSAI_MULTICAST])
#endif         
            )
            {
              CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_MP);
              dyn_cap_len++;
            }

          CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss3);
          CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
          CQUEUE_WRITE_INT8 ( cq_wbuf , dyn_cap_len+2);
          CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
          CQUEUE_WRITE_INT8 ( cq_wbuf , dyn_cap_len);
          CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss3);
      }


#ifdef HAVE_EXT_CAP_ASN
   /* Encode EXTASN Capability. */
   if (CHECK_FLAG (BGP_VR.bvr_options,BGP_OPT_EXTENDED_ASN_CAP))
     {
       SET_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_ADV);
       CQUEUE_WRITE_INT8 (cq_wbuf, BGP_OPEN_OPT_CAP);
       CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_EXTASN_LEN + 2);     
       CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_EXTASN);
       CQUEUE_WRITE_INT8 (cq_wbuf, BGP_CAPABILITY_CODE_EXTASN_LEN);
       CQUEUE_WRITE_INT32 (cq_wbuf, (u_int32_t)peer->local_as);
     } 
#endif /* HAVE_EXT_CAP_ASN */

  /* Encode ORF Capability */
  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      if (CHECK_FLAG (peer->af_flags [baai][bsai],
                      PEER_FLAG_ORF_PREFIX_SM | PEER_FLAG_ORF_PREFIX_RM))
        {
          bpe_msg_open_cap_orf (cq_wbuf, peer, BGP_BAAI2AFI (baai),
                                BGP_BSAI2SAFI (bsai),
                                BGP_CAPABILITY_CODE_ORF_OLD);
          bpe_msg_open_cap_orf (cq_wbuf, peer, BGP_BAAI2AFI (baai),
                                BGP_BSAI2SAFI (bsai),
                                BGP_CAPABILITY_CODE_ORF);
        }

  return;
}

/*
 * LEVEL 2 BGP Message Encoder function:
 * Encodes BGP UPDATE Message End-of-Rib Marker for IPv4 UNICAST
 */
bool_t
bpe_msg_update_endofrib (struct cqueue_buffer *cq_wbuf,
                         struct bgp_peer *peer)
{
  bool_t to_continue;

  to_continue = PAL_FALSE;

  /* Encode 'tot-path-attr-len' of ZERO */
  CQUEUE_WRITE_INT16 (cq_wbuf, 0);

  return to_continue;
}

/*
 * LEVEL 2 BGP Message Encoder function:
 * Encodes BGP UPDATE Message Withdrawn IPv4 UNICAST NLRIs
 */
bool_t
bpe_msg_update_withdrawn (struct cqueue_buffer *cq_wbuf,
                          struct bgp_peer *peer,
                          struct fifo *unreach_fifo,
                          bool_t auto_summary_update)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  struct bgp_advertise *adv_out;
  u_int16_t withdrawn_len;
  struct bgp_node *rn;
  bool_t to_continue;
  struct prefix rnp;

  to_continue = PAL_FALSE;
  withdrawn_len = 0;

  /* Write a dummy 'withdrawn_len' */
  CQUEUE_WRITE_INT16 (cq_wbuf, withdrawn_len);

  /*
   * Take a CQBuf SnapShot here to overwrite with correct
   * 'withdrawn_len' later.
   */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);

  /* Encode Withdrawn NLRIs */
  while ((adv_out = ((struct bgp_advertise *) FIFO_HEAD (unreach_fifo))))
    {
      rn = adv_out->rn;

      to_continue = bpe_msg_update_nlri_prefix (cq_wbuf, rn, NULL,
                                                AFI_IP, SAFI_UNICAST,
                                                PAL_TRUE,
                                                auto_summary_update);
      if (to_continue == PAL_TRUE)
        goto EXIT;

      if (BGP_DEBUG (update, UPDATE_OUT))
      {
	BGP_GET_PREFIX_FROM_NODE (rn);
        zlog_info (&BLG, "%s-%s [ENCODE] Update Withdrawn: Prefix %O",
                   peer->host, BGP_PEER_DIR_STR (peer), &rnp);
      }
      if (!auto_summary_update)
        peer->scount [BAAI_IP][BSAI_UNICAST]--;
      
     if (!bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))  
       bgp_adj_out_remove (rn, adv_out->adj, peer, AFI_IP, 
                           SAFI_UNICAST, auto_summary_update);
     else
       bgp_rib_out_free (rn, adv_out->adj, peer, AFI_IP,
                         SAFI_UNICAST, auto_summary_update);
    }

EXIT:

  /* Obtain 'Withdrawn Len' and overwrite previous value in CQBuf */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
  withdrawn_len = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                                    &tmp_cqbss1);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  CQUEUE_WRITE_REWIND_NBYTES (cq_wbuf, BGP_WITHDRAWN_NLRI_LEN_FIELD_SIZE);
  CQUEUE_WRITE_INT16 (cq_wbuf, withdrawn_len);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);

  return to_continue;
}

#ifdef HAVE_EXT_CAP_ASN

/*
 * Function name: bge_msg_ext_asn_aggregator ()
 * Input        : cq_wbuf, to_peer, from_peer, attr  
 * Output       : None 
 * Purpose      : For Encoding the AGGREGATOR attribute
*/

void
bge_msg_ext_asn_aggregator (struct cqueue_buffer *cq_wbuf,
                            struct bgp_peer *to_peer,
                            struct bgp_peer *from_peer,
                            struct attr *attr)
{
  
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AGGREGATOR);
  /* Local Speaker is configured as NBGP */
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)) 
    {
      if (CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
        {
          /* if the peer is NBGP send 4-octet AGGREGATOR */
          CQUEUE_WRITE_INT8 (cq_wbuf, 8);
          CQUEUE_WRITE_INT32 (cq_wbuf, attr->aggregator_as4);
          CQUEUE_WRITE_NBYTES (cq_wbuf, &attr->aggregator_addr.s_addr, 4);
        }
      else if (!CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV) &&
               ! BGP_IS_AS4_MAPPABLE (to_peer->local_as))
        {
          /* if peer is OBGP and local speaker is configured with 
            4-octet ASN send AS_TRANS */
          CQUEUE_WRITE_INT8 (cq_wbuf, 6);
          /* if this is the orginator, attr->aggregator_as 0 will be zero */
          if (attr->aggregator_as == 0)
            CQUEUE_WRITE_INT16 (cq_wbuf, BGP_AS_TRANS);
          else
            CQUEUE_WRITE_INT16 (cq_wbuf, attr->aggregator_as);
          CQUEUE_WRITE_NBYTES (cq_wbuf, &attr->aggregator_addr.s_addr, 4);
        }
     else if (!CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV) &&
               BGP_IS_AS4_MAPPABLE(to_peer->local_as) )
        {
          /* local speaker is NBGP and configured with 2-octet ASN */
          CQUEUE_WRITE_INT8 (cq_wbuf, 6);
          CQUEUE_WRITE_INT16 (cq_wbuf, attr->aggregator_as);
          CQUEUE_WRITE_NBYTES (cq_wbuf, &attr->aggregator_addr.s_addr, 4);
        }
    }
}
#endif /* HAVE_EXT_CAP_ASN */

/*
 * LEVEL 2 BGP Message Encoder function:
 * Encodes BGP UPDATE Message IPv4 UNICAST Path-Attributes
 */
bool_t
bpe_msg_attr_ip (struct cqueue_buffer *cq_wbuf,
                 struct bgp_peer *to_peer,
                 struct bgp_peer *from_peer,
                 struct attr *attr)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  u_int16_t tot_attr_len;
  bool_t to_continue;
  struct bgp *bgp;

  to_continue = PAL_FALSE;
  tot_attr_len = 0;

  /* Write a dummy 'tot_attr_len' */
  CQUEUE_WRITE_INT16 (cq_wbuf, tot_attr_len);

  /*
   * Take a CQBuf SnapShot here to overwrite with correct
   * 'tot_attr_len' later.
   */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);

  if (! from_peer)
    {
      to_continue = PAL_TRUE;
      goto EXIT;
    }

  /* Obtain Default BGP Instance */
  bgp = from_peer->bgp;

  if (! bgp || ! attr)
    {
      to_continue = PAL_TRUE;

      goto EXIT;
    }

  /*
   * Encode IPv4-UNICAST Path-Attributes
   */

  /* Encode 'Origin' attribute. */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_ORIGIN);
  CQUEUE_WRITE_INT8 (cq_wbuf, 1);
  CQUEUE_WRITE_INT8 (cq_wbuf, attr->origin);

  /* Encode AS-Path Attribute */
#ifndef HAVE_EXT_CAP_ASN
  bpe_msg_attr_aspath (cq_wbuf, to_peer, from_peer, attr,
                       AFI_IP, SAFI_UNICAST);
#else
  bpe_msg_attr_new_aspath (cq_wbuf, to_peer, from_peer, attr,
                           AFI_IP, SAFI_UNICAST); 
#endif /* HAVE_EXT_CAP_ASN */
  
  /* Encode Nexthop attribute */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_NEXT_HOP);
  CQUEUE_WRITE_INT8 (cq_wbuf, 4);
  CQUEUE_WRITE_4BYTES (cq_wbuf, &attr->nexthop.s_addr);

  /* Encode MED attribute if REMOVE_MED (RFC 4271 Section 5.1.4)  is not present*/
    if (!(bgp_config_check (bgp, BGP_CFLAG_MED_REMOVE_SEND)))
      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    {
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_MULTI_EXIT_DISC);
      CQUEUE_WRITE_INT8 (cq_wbuf, 4);
      CQUEUE_WRITE_INT32 (cq_wbuf, attr->med);
    }

  /* Encode Local-preference */
  if (peer_sort (to_peer) == BGP_PEER_IBGP ||
      peer_sort (to_peer) == BGP_PEER_CONFED)
    {
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_LOCAL_PREF);
      CQUEUE_WRITE_INT8 (cq_wbuf, 4);
      CQUEUE_WRITE_INT32 (cq_wbuf, attr->local_pref);
    }

  /* Encode Atomic-Aggregate */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE))
    {
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_ATOMIC_AGGREGATE);
      CQUEUE_WRITE_INT8 (cq_wbuf, 0);
    }

  /* Encode Aggregator */

  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR))
    {
      if (CHECK_FLAG (attr->partial_flag, BGP_ATTR_AGGREGATOR_PARTIAL))
        CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                    BGP_ATTR_FLAG_TRANS |
                                    BGP_ATTR_FLAG_PARTIAL);
      else
        CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                    BGP_ATTR_FLAG_TRANS);
#ifdef HAVE_EXT_CAP_ASN
      if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        bge_msg_ext_asn_aggregator (cq_wbuf, to_peer, from_peer, attr); 
      else
        {
#endif /* HAVE_EXT_CAP_ASN */
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AGGREGATOR);
          CQUEUE_WRITE_INT8 (cq_wbuf, 6);
          CQUEUE_WRITE_INT16 (cq_wbuf, attr->aggregator_as);
          CQUEUE_WRITE_NBYTES (cq_wbuf, &attr->aggregator_addr.s_addr, 4);
#ifdef HAVE_EXT_CAP_ASN
        }
#endif /* HAVE_EXT_CAP_ASN */
    }

  /* Encode Community Attribute */
  if (CHECK_FLAG (to_peer->af_flags [BAAI_IP][BSAI_UNICAST],
                  PEER_FLAG_SEND_COMMUNITY)
      && (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES)))
    {
      if (attr->community->size * 4 > 255)
        {
          if (CHECK_FLAG (attr->partial_flag, BGP_ATTR_COMMUNITY_PARTIAL))
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS |
                                        BGP_ATTR_FLAG_PARTIAL |
                                        BGP_ATTR_FLAG_EXTLEN);
          else
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS |
                                        BGP_ATTR_FLAG_EXTLEN);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_COMMUNITIES);
          CQUEUE_WRITE_INT16 (cq_wbuf, attr->community->size * 4);
        }
      else
        {
          if (CHECK_FLAG (attr->partial_flag, BGP_ATTR_COMMUNITY_PARTIAL))
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS |
                                        BGP_ATTR_FLAG_PARTIAL);
          else
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_COMMUNITIES);
          CQUEUE_WRITE_INT8 (cq_wbuf, attr->community->size * 4);
        }

      CQUEUE_WRITE_NBYTES (cq_wbuf, attr->community->val,
                           attr->community->size * 4);
    }

  /* Encode Route-Reflector related Attributes */
  if (peer_sort (to_peer) == BGP_PEER_IBGP
      && peer_sort (from_peer) == BGP_PEER_IBGP)
    {
      /* Encode Originator ID. */
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_ORIGINATOR_ID);
      CQUEUE_WRITE_INT8 (cq_wbuf, 4);

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
        CQUEUE_WRITE_4BYTES (cq_wbuf, &attr->originator_id);
      else
        CQUEUE_WRITE_4BYTES (cq_wbuf, &from_peer->remote_id);

      /* Encode Cluster list. */
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_CLUSTER_LIST);
      if (attr->cluster)
        {
          CQUEUE_WRITE_INT8 (cq_wbuf, attr->cluster->length + 4);

          /* Encode configured Cluster-ID or the  Router-ID */
          if (bgp_config_check (bgp, BGP_CFLAG_CLUSTER_ID))
            CQUEUE_WRITE_4BYTES (cq_wbuf, &bgp->cluster_id);
          else
            CQUEUE_WRITE_4BYTES (cq_wbuf, &bgp->router_id);
          CQUEUE_WRITE_NBYTES (cq_wbuf, attr->cluster->list,
                               attr->cluster->length);
        }
      else
        {
          CQUEUE_WRITE_INT8 (cq_wbuf, 4);

          /* Encode configured Cluster-ID or the  Router-ID */
          if (bgp_config_check (bgp, BGP_CFLAG_CLUSTER_ID))
            CQUEUE_WRITE_4BYTES (cq_wbuf, &bgp->cluster_id);
          else
            CQUEUE_WRITE_4BYTES (cq_wbuf, &bgp->router_id);
        }
    }
    
  /* Encode Extended-Communities Attribute */
  if (CHECK_FLAG (to_peer->af_flags [BAAI_IP][BSAI_UNICAST],
                  PEER_FLAG_SEND_EXT_COMMUNITY)
       && (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES))
       && attr->ecommunity && attr->ecommunity->size)
    {
      bpe_msg_encode_extnd_attr (cq_wbuf, to_peer, attr);
    }

#ifdef HAVE_EXT_CAP_ASN
  /* Encode 4-Octet AS4 Aggregator */
  /* NBGP never send AS4_AGGREGATOR to other NBGP */
  /* Only Unmappable NBGP sends this attribute to OBGP */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR) 
      && (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)) 
      && (!CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV)))
    {
      if ((!BGP_IS_AS4_MAPPABLE (to_peer->local_as)
          && (attr->aggregator_as4 == to_peer->local_as))
          || (attr->aggregator_as4 > BGP_AS_MAX))  
        {
          if (CHECK_FLAG (attr->partial_flag, BGP_ATTR_AS4_AGGREGATOR_PARTIAL))
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                               BGP_ATTR_FLAG_TRANS |
                               BGP_ATTR_FLAG_PARTIAL);
          else
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                               BGP_ATTR_FLAG_TRANS);
     
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS4_AGGREGATOR);
          CQUEUE_WRITE_INT8 (cq_wbuf, 8);
          CQUEUE_WRITE_INT32 (cq_wbuf, attr->aggregator_as4);
          CQUEUE_WRITE_NBYTES (cq_wbuf, &attr->aggregator_addr.s_addr, 4);
        }
     }
#endif /* HAVE_EXT_CAP_ASN */

  /* Encode Unknown-Transitive Attribute, if any */
  if (attr->transit)
    CQUEUE_WRITE_NBYTES (cq_wbuf, attr->transit->val,
                         attr->transit->length);


EXIT:

  /* Obtain 'tot_attr_len' and overwrite previous value in CQBuf */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
  tot_attr_len = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                                   &tmp_cqbss1);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  CQUEUE_WRITE_REWIND_NBYTES (cq_wbuf, BGP_TOTAL_ATTR_LEN_FIELD_SIZE);
  CQUEUE_WRITE_INT16 (cq_wbuf, tot_attr_len);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);

  if (BGP_DEBUG (events, EVENTS))
    zlog_info (&BLG, "%s-%s [ENCODE] Attr IP-Unicast: Tot-attr-len %d",
               to_peer->host, BGP_PEER_DIR_STR (to_peer), tot_attr_len);

  return to_continue;
}
/****************************************************************************
 * Function : bgp_msg_encode_extnd_attr                                     *
 *                                                                          *
 * Description : This function will encode the extended attribute, based    *
 *               on tansitive and non-transitive flag. If the attribute is  *
 *               non-transitive attribute and peer is EBGP then the         *
 *               attribute  will be stripped.                               *
 *                                                                          *
 * Input :                                                                  *
 *    to_peer : peer to which attribute to be sent                          *
 *    attr    : attribute associated with update message                    *
 *                                                                          *
 * Output :  CQBUF is updated with exteneded attribute based on the above   *
 *           mentioned description                                          *
 *                                                                          *
 ****************************************************************************/
int 
bpe_msg_encode_extnd_attr (struct cqueue_buffer *cq_wbuf, 
                           struct bgp_peer * to_peer, 
                           struct attr *attr)
{
  u_int8_t * pnt = NULL;
  u_int8_t extnd_buff [65536];
  u_int16_t tot_ext_attr_len = 0;
  u_int8_t flag = 0; 
  u_int8_t * curr_pnt = NULL;
  u_int16_t attr_ext = 0;

  /* validate the input parameters */
  if (!to_peer || !attr)
    return -1;
  
  pal_mem_set (extnd_buff, 0x00, sizeof (extnd_buff));
  /* point to the first attribute */
  pnt = attr->ecommunity->val;
  curr_pnt = (u_int8_t*)&extnd_buff[0];
 
  if (!pnt)
    return -1;

  if (peer_sort (to_peer) == BGP_PEER_EBGP)
    {
      for (attr_ext =0; attr_ext < (attr->ecommunity->size * 8 ); )
        {
          if (!pnt)
            return -1;

          flag = *pnt & 0xf0; 
          /* check if it is not non-transitive attribute */
          if (!CHECK_FLAG (flag, ECOMMUNITY_NON_TRANSITIVE_ATTR)) 
            {
              pal_mem_cpy (curr_pnt, pnt , 8);
              tot_ext_attr_len += 8;
              pnt += 8;
              curr_pnt += 8;
            }
          /* strip this attribute */
          else 
              pnt += 8;

          attr_ext += 8;
        }
    }
  /* do not strip non-transitive attribute if peer is IBGP */
  else
    {
      pal_mem_cpy (extnd_buff, attr->ecommunity->val,
                   attr->ecommunity->size * 8);
      tot_ext_attr_len = attr->ecommunity->size * 8;
    }
     
   /* check if there is anything to encode */
   if (!tot_ext_attr_len) 
     return 0;    

      if (tot_ext_attr_len > 255)
        {
          if (CHECK_FLAG (attr->partial_flag, BGP_ATTR_ECOMMUNITY_PARTIAL))
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS |
                                        BGP_ATTR_FLAG_PARTIAL |
                                        BGP_ATTR_FLAG_EXTLEN);
          else
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS |
                                        BGP_ATTR_FLAG_EXTLEN);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_EXT_COMMUNITIES);
          CQUEUE_WRITE_INT16 (cq_wbuf, tot_ext_attr_len);
        }
        else
        {
          if (CHECK_FLAG (attr->partial_flag, BGP_ATTR_ECOMMUNITY_PARTIAL))
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS |
                                        BGP_ATTR_FLAG_PARTIAL);
          else
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_EXT_COMMUNITIES);
          CQUEUE_WRITE_INT8 (cq_wbuf, tot_ext_attr_len);
        }

  CQUEUE_WRITE_NBYTES (cq_wbuf, extnd_buff, tot_ext_attr_len);

  return 0;
}


/*
 * LEVEL 2 BGP Message Encoder function:
 * Encodes BGP UPDATE Message MP Path-Attributes (all except MP-Reach
 * and MP-UnReach Attributes)
 */
bool_t
bpe_msg_attr_mp (struct cqueue_buffer *cq_wbuf,
                 struct bgp_peer *to_peer,
                 struct bgp_peer *from_peer,
                 struct attr *attr,
                 afi_t afi, safi_t safi)
{
  bool_t to_continue;
  struct bgp *bgp;

  to_continue = PAL_FALSE;
  
  if (! from_peer)
    {
      to_continue = PAL_TRUE;
      goto EXIT;
    }  
  bgp = from_peer->bgp;
  if (! bgp || ! attr)
    {
      to_continue = PAL_TRUE;
      goto EXIT;
    }

  /*
   * Encode MP Path-Attributes (all except MP-Reach and MP-UnReach)
   * 'Origin´, 'AS-Path' and 'Local-Pref/MED' are mandatory
   */

  /* Encode 'Origin' attribute. */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_ORIGIN);
  CQUEUE_WRITE_INT8 (cq_wbuf, 1);
  CQUEUE_WRITE_INT8 (cq_wbuf, attr->origin);

  /* Encode AS-Path Attribute */
#ifndef HAVE_EXT_CAP_ASN
  bpe_msg_attr_aspath (cq_wbuf, to_peer, from_peer, attr, afi, safi);
#else
  bpe_msg_attr_new_aspath (cq_wbuf, to_peer, from_peer, attr, afi, safi); 
#endif /* HAVE_EXT_CAP_ASN */  

  /* Encode MED attribute if REMOVE_MED (RFC 4271 section 5.1.4) is not present */
    if (!(bgp_config_check (bgp, BGP_CFLAG_MED_REMOVE_SEND)))
      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
      {
        CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL);
        CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_MULTI_EXIT_DISC);
        CQUEUE_WRITE_INT8 (cq_wbuf, 4);
        CQUEUE_WRITE_INT32 (cq_wbuf, attr->med);
      }

  /* Encode Local-preference */
  if (peer_sort (to_peer) == BGP_PEER_IBGP ||
      peer_sort (to_peer) == BGP_PEER_CONFED)
    {
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_LOCAL_PREF);
      CQUEUE_WRITE_INT8 (cq_wbuf, 4);
      CQUEUE_WRITE_INT32 (cq_wbuf, attr->local_pref);
    }

  /* Encode Atomic-Aggregate */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE))
    {
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_ATOMIC_AGGREGATE);
      CQUEUE_WRITE_INT8 (cq_wbuf, 0);
    }

  /* Encode Aggregator */
   
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR))
    {
      if (CHECK_FLAG (attr->partial_flag, BGP_ATTR_AGGREGATOR_PARTIAL))
        CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                    BGP_ATTR_FLAG_TRANS |
                                    BGP_ATTR_FLAG_PARTIAL);
      else
        CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                    BGP_ATTR_FLAG_TRANS);
#ifdef HAVE_EXT_CAP_ASN
      if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        bge_msg_ext_asn_aggregator(cq_wbuf, to_peer, from_peer, attr);
      else
        {
#endif /* HAVE_EXT_CAP_ASN */
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AGGREGATOR);
          CQUEUE_WRITE_INT8 (cq_wbuf, 6);
          CQUEUE_WRITE_INT16 (cq_wbuf, attr->aggregator_as);
          CQUEUE_WRITE_NBYTES (cq_wbuf, &attr->aggregator_addr.s_addr, 4);
#ifdef HAVE_EXT_CAP_ASN
        }
#endif /* HAVE_EXT_CAP_ASN */
    }

  /* Encode Community Attribute */
  if (CHECK_FLAG (to_peer->af_flags [BGP_AFI2BAAI (afi)]
                                    [BGP_SAFI2BSAI (safi)],
                  PEER_FLAG_SEND_COMMUNITY)
      && (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES)))
    {
      if (attr->community->size * 4 > 255)
        {
          if (CHECK_FLAG (attr->partial_flag, BGP_ATTR_COMMUNITY_PARTIAL))
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS |
                                        BGP_ATTR_FLAG_PARTIAL |
                                        BGP_ATTR_FLAG_EXTLEN);
          else
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS |
                                        BGP_ATTR_FLAG_EXTLEN);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_COMMUNITIES);
          CQUEUE_WRITE_INT16 (cq_wbuf, attr->community->size * 4);
        }
      else
        {
          if (CHECK_FLAG (attr->partial_flag, BGP_ATTR_COMMUNITY_PARTIAL))
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS |
                                        BGP_ATTR_FLAG_PARTIAL);
          else
            CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                        BGP_ATTR_FLAG_TRANS);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_COMMUNITIES);
          CQUEUE_WRITE_INT8 (cq_wbuf, attr->community->size * 4);
        }
      CQUEUE_WRITE_NBYTES (cq_wbuf, attr->community->val,
                           attr->community->size * 4);
    }

  /* Encode Route-Reflector related Attributes */
  if (peer_sort (to_peer) == BGP_PEER_IBGP
      && peer_sort (from_peer) == BGP_PEER_IBGP)
    {
      /* Encode Originator ID. */
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_ORIGINATOR_ID);
      CQUEUE_WRITE_INT8 (cq_wbuf, 4);

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
        CQUEUE_WRITE_4BYTES (cq_wbuf, &attr->originator_id);
      else
        CQUEUE_WRITE_4BYTES (cq_wbuf, &from_peer->remote_id);

      /* Encode Cluster list. */
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_CLUSTER_LIST);
      if (attr->cluster)
        {
          CQUEUE_WRITE_INT8 (cq_wbuf, attr->cluster->length + 4);

          /* Encode configured Cluster-ID or the  Router-ID */
          if (bgp_config_check (bgp, BGP_CFLAG_CLUSTER_ID))
            CQUEUE_WRITE_4BYTES (cq_wbuf, &bgp->cluster_id);
          else
            CQUEUE_WRITE_4BYTES (cq_wbuf, &bgp->router_id);
          CQUEUE_WRITE_NBYTES (cq_wbuf, attr->cluster->list,
                               attr->cluster->length);
        }
      else
        {
          CQUEUE_WRITE_INT8 (cq_wbuf, 4);

          /* Encode configured Cluster-ID or the  Router-ID */
          if (bgp_config_check (bgp, BGP_CFLAG_CLUSTER_ID))
            CQUEUE_WRITE_4BYTES (cq_wbuf, &bgp->cluster_id);
          else
            CQUEUE_WRITE_4BYTES (cq_wbuf, &bgp->router_id);
        }
    }

  /* Encode Extended-Communities Attribute */
  if (CHECK_FLAG (to_peer->af_flags [BGP_AFI2BAAI (afi)]
                                    [BGP_SAFI2BSAI (safi)],
                  PEER_FLAG_SEND_EXT_COMMUNITY)
      && (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES))
      && attr->ecommunity && attr->ecommunity->size)
    {
      bpe_msg_encode_extnd_attr (cq_wbuf, to_peer, attr);
    }

#ifdef HAVE_EXT_CAP_ASN
 /* Encode 4-Octet AS4 Aggregator */
  /* NBGP never send AS4_AGGREGATOR to other NBGP */
  /* Only Unmappable NBGP sends this attribute to OBGP */
      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR)
          && (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
          && (!CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV)))
        { 
          if ((!BGP_IS_AS4_MAPPABLE(to_peer->local_as) 
              && (attr->aggregator_as4 == to_peer->local_as))
              || (attr->aggregator_as4 > BGP_AS_MAX)) 
            {
              if (CHECK_FLAG (attr->partial_flag, BGP_ATTR_AS4_AGGREGATOR_PARTIAL))
                CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                   BGP_ATTR_FLAG_TRANS |
                                   BGP_ATTR_FLAG_PARTIAL);
              else
                CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                   BGP_ATTR_FLAG_TRANS);

                CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS4_AGGREGATOR);
                CQUEUE_WRITE_INT8 (cq_wbuf, 8);
                CQUEUE_WRITE_INT32 (cq_wbuf, attr->aggregator_as4);
                CQUEUE_WRITE_NBYTES (cq_wbuf, &attr->aggregator_addr.s_addr, 4);
            }
       }
#endif /* HAVE_EXT_CAP_ASN */

/* Encode Unknown-Transitive Attribute, if any */
  if (attr->transit)
    CQUEUE_WRITE_NBYTES (cq_wbuf, attr->transit->val,
                         attr->transit->length);

EXIT:

  return to_continue;
}

/*
 * LEVEL 2 BGP Message Encoder function:
 * Encodes BGP UPDATE Message Advertised IPv4 UNICAST NLRIs
 */
bool_t
bpe_msg_update_nlri (struct cqueue_buffer *cq_wbuf,
                     struct bgp_peer *peer,
                     struct fifo *reach_fifo,
                     bool_t auto_summary_update)
{
  struct bgp_advertise *adv_out;
  bool_t to_continue;
  struct prefix rnp;

  to_continue = PAL_FALSE;

  /* Encode Advertised NLRIs */
  adv_out = (struct bgp_advertise *) FIFO_HEAD (reach_fifo);

  while (adv_out)
    {
      to_continue = bpe_msg_update_nlri_prefix (cq_wbuf, adv_out->rn,
                                                adv_out->binfo, AFI_IP,
                                                SAFI_UNICAST,
                                                PAL_FALSE,
                                                auto_summary_update);
      if (to_continue == PAL_TRUE)
        goto EXIT;

      if (BGP_DEBUG (update, UPDATE_OUT))
      {
	BGP_GET_PREFIX_FROM_NODE (adv_out->rn);
        zlog_info (&BLG, "%s-%s [ENCODE] Update NLRI: Prefix %O",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   &rnp);
      }

      if (adv_out->adj->attr)
        {
          if (!auto_summary_update)
            bgp_attr_unintern (adv_out->adj->attr);
        }
      else
        peer->scount [BAAI_IP][BSAI_UNICAST]++;

      adv_out->adj->attr = bgp_attr_intern (adv_out->baa->attr);
  
      if (!bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
        adv_out = bgp_advertise_clean (peer, &adv_out->adj,
                                       AFI_IP, SAFI_UNICAST);
      else
        adv_out = bgp_rib_out_free (adv_out->rn, adv_out->adj, peer,
                                    AFI_IP, SAFI_UNICAST, auto_summary_update);
    }

  /* To continue if we need to change 'attr' and be back */
  if (FIFO_HEAD (reach_fifo))
    to_continue = PAL_TRUE;

EXIT:

  return to_continue;
}

/*
 * LEVEL 2 BGP Message Encoder function:
 * Encodes BGP UPDATE Message Attribute MP UnReach End-of-Rib
 */
bool_t
bpe_msg_attr_mp_endofrib (struct cqueue_buffer *cq_wbuf,
                          struct bgp_peer *peer,
                          afi_t afi, safi_t safi)
{
  bool_t to_continue;

  to_continue = PAL_FALSE;

  /* Encode Attribute Flags byte */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                              BGP_ATTR_FLAG_EXTLEN);

  /* Encode Attribute Type byte */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_MP_UNREACH_NLRI);

  /* Encode dummy 'Ext-Len' value */
  CQUEUE_WRITE_INT16 (cq_wbuf, BGP_ATTR_MP_UNREACH_MIN_SIZE);

  /* Encode 'AFI' value */
  CQUEUE_WRITE_INT16 (cq_wbuf, afi);

  /* Encode 'SAFI' value */
  CQUEUE_WRITE_INT8 (cq_wbuf, safi);

  return to_continue;
}

/*
 * LEVEL 2 BGP Message Encoder function:
 * Encodes BGP UPDATE Message Attribute MP UnReach NLRIs
 */
bool_t
bpe_msg_attr_mp_unreach (struct cqueue_buffer *cq_wbuf,
                         struct bgp_peer *peer,
                         afi_t afi, safi_t safi,
                         struct fifo *unreach_fifo)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  struct bgp_advertise *adv_out;
  struct bgp_node *rn;
  u_int16_t attr_len;
  bool_t to_continue;
  u_int32_t baai;
  u_int32_t bsai;
  struct prefix rnp;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);
  to_continue = PAL_FALSE;
  attr_len = 0;

  /* Encode Attribute Flags byte */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                              BGP_ATTR_FLAG_EXTLEN);

  /* Encode Attribute Type byte */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_MP_UNREACH_NLRI);

  /* Encode dummy 'Ext-Len' value */
  CQUEUE_WRITE_INT16 (cq_wbuf, attr_len);

  /*
   * Take a CQBuf SnapShot here to overwrite with correct
   * 'MP UnReach Attribute Len' later.
   */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);

  /* Encode 'AFI' value */
  CQUEUE_WRITE_INT16 (cq_wbuf, afi);

  /* Encode 'SAFI' value */
  CQUEUE_WRITE_INT8 (cq_wbuf, safi);

  /* Encode Withdrawn NLRIs */
  while ((adv_out = ((struct bgp_advertise *) FIFO_HEAD (unreach_fifo))))
    {
      rn = adv_out->rn;

      to_continue = bpe_msg_update_nlri_prefix (cq_wbuf, rn, NULL, afi,
                                                safi, PAL_TRUE, PAL_FALSE);
      if (to_continue == PAL_TRUE)
        goto EXIT;

      if (BGP_DEBUG (update, UPDATE_OUT))
      {
        BGP_GET_PREFIX_FROM_NODE (rn);	
        zlog_info (&BLG, "%s-%s [ENCODE] Update Withdrawn: Prefix %O",
                   peer->host, BGP_PEER_DIR_STR (peer), &rnp);
      }

      peer->scount [baai][bsai]--;
      
      if (!bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
        bgp_adj_out_remove (rn, adv_out->adj, peer, afi, safi, PAL_FALSE);
      else
         bgp_rib_out_free (rn, adv_out->adj, peer, afi, safi, PAL_FALSE);
    }

EXIT:

  /* Obtain 'Withdrawn Len' and overwrite previous value in CQBuf */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
  attr_len = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                               &tmp_cqbss1);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  CQUEUE_WRITE_REWIND_NBYTES (cq_wbuf, BGP_ATTR_EXT_LEN_SIZE);
  CQUEUE_WRITE_INT16 (cq_wbuf, attr_len);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);

  return to_continue;
}

/*
 * LEVEL 2 BGP Message Encoder function:
 * Encodes BGP UPDATE Message Attribute MP Reach NLRIs
 */
bool_t
bpe_msg_attr_mp_reach (struct cqueue_buffer *cq_wbuf,
                       struct bgp_peer *peer,
                       struct attr *attr,
                       afi_t afi, safi_t safi,
                       struct fifo *reach_fifo)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  struct bgp_advertise *adv_out;
  struct bgp_rd tmp_rd;
  u_int16_t attr_len;
  bool_t to_continue;
  u_int32_t baai;
  u_int32_t bsai;
  struct prefix rnp;
  pal_mem_set (&tmp_rd, 0, sizeof (struct bgp_rd));
  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  to_continue = PAL_FALSE;
  attr_len = 0;

  /* Encode Attribute Flags byte */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                              BGP_ATTR_FLAG_EXTLEN);

  /* Encode Attribute Type byte */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_MP_REACH_NLRI);

  /* Encode dummy 'Ext-Len' value */
  CQUEUE_WRITE_INT16 (cq_wbuf, attr_len);

  /*
   * Take a CQBuf SnapShot here to overwrite with correct
   * 'MP Reach Attribute Len' later.
   */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);

  /* Encode 'AFI' value */
  CQUEUE_WRITE_INT16 (cq_wbuf, afi);

  /* Encode 'SAFI' value */
  CQUEUE_WRITE_INT8 (cq_wbuf, safi);

  /* Encode 'MP NHop Len' value */
  CQUEUE_WRITE_INT8 (cq_wbuf, attr->mp_nexthop_len);

  /* Encode 'MP NHop' value */
  if (attr->mp_nexthop_len == IPV4_MAX_BYTELEN)
    {
      CQUEUE_WRITE_4BYTES (cq_wbuf, &attr->mp_nexthop_global_in);
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6)
    {
	  if (attr->mp_nexthop_len == IPV6_MAX_BYTELEN)
        {
          CQUEUE_WRITE_NBYTES (cq_wbuf, &attr->mp_nexthop_global,
                               IPV6_MAX_BYTELEN);
        }
      else if (attr->mp_nexthop_len == IPV6_MAX_BYTELEN * 2)
        {
          CQUEUE_WRITE_NBYTES (cq_wbuf, &attr->mp_nexthop_global,
                               IPV6_MAX_BYTELEN);
          CQUEUE_WRITE_NBYTES (cq_wbuf, &attr->mp_nexthop_local,
                               IPV6_MAX_BYTELEN);
        }
    }
#endif /* HAVE_IPV6 */
  else /* Terrible Error, Reset Self */
    {
      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_AUTO_STOP);

      to_continue = PAL_FALSE;

      goto EXIT;
    }

  /* Encode 'snpa_num' value of ZERO */
  CQUEUE_WRITE_INT8 (cq_wbuf, 0);

  /* Encode Advertised NLRIs */
  adv_out = (struct bgp_advertise *) FIFO_HEAD (reach_fifo);

  while (adv_out)
    {
      to_continue = bpe_msg_update_nlri_prefix (cq_wbuf, adv_out->rn,
                                                adv_out->binfo, afi,
                                                safi, PAL_TRUE, PAL_FALSE);
      if (to_continue == PAL_TRUE)
        goto FINISH_ENC;

      if (BGP_DEBUG (update, UPDATE_OUT))
      {
        BGP_GET_PREFIX_FROM_NODE (adv_out->rn);
        zlog_info (&BLG, "%s-%s [ENCODE] Update MP Reach: Prefix %O",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   &rnp);
       }

      if (adv_out->adj->attr)
        bgp_attr_unintern (adv_out->adj->attr);
      else
        peer->scount [baai][bsai]++;

      adv_out->adj->attr = bgp_attr_intern (adv_out->baa->attr);
    
      if (!bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
        adv_out = bgp_advertise_clean (peer, &adv_out->adj, afi, safi);
      else
        adv_out = bgp_rib_out_free (adv_out->rn, adv_out->adj, peer,
                                    afi, safi, PAL_FALSE);
    }

  /* To continue if we need to change 'attr' and be back */
  if (FIFO_HEAD (reach_fifo))
    to_continue = PAL_TRUE;

FINISH_ENC:

  /* Obtain 'MP Reach Attr Len' and overwrite the field in CQBuf */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
  attr_len = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                               &tmp_cqbss1);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  CQUEUE_WRITE_REWIND_NBYTES (cq_wbuf, BGP_ATTR_EXT_LEN_SIZE);
  CQUEUE_WRITE_INT16 (cq_wbuf, attr_len);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);

EXIT:
  return to_continue;
}

/*
 * LEVEL 3 BGP Message Encoder function:
 * Encodes BGP OPEN Message GRST Capabilities Optional Parameter
 */
void
bpe_msg_open_cap_orf (struct cqueue_buffer *cq_wbuf,
                      struct bgp_peer *peer,
                      afi_t afi, safi_t safi,
                      u_int8_t cap_code)
{
  struct cqueue_buf_snap_shot tmp_cqbss1;
  struct cqueue_buf_snap_shot tmp_cqbss2;
  u_int8_t opt_param_len;
  u_int8_t num_orfs;
  u_int8_t cap_len;
  u_int32_t baai;
  u_int32_t bsai;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  opt_param_len = 0;
  num_orfs = 0;
  cap_len = 0;

  /* Encode OPEN Opt Param Type */
  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_OPEN_OPT_CAP);

  /* Encode dummy Param Len */
  CQUEUE_WRITE_INT8 (cq_wbuf, opt_param_len);

  /*
   * Take a CQBuf SnapShot here to overwrite 'opt_param_len',
   * 'cap_len' and 'num_orfs' fields with correct values.
   */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss1);

  /* Encode Cap Code */
  CQUEUE_WRITE_INT8 (cq_wbuf, cap_code);

  /* Encode dummy Cap Len */
  CQUEUE_WRITE_INT8 (cq_wbuf, cap_len);

  /* Encode AFI-SAFI fields */
  CQUEUE_WRITE_INT16 (cq_wbuf, afi);
  CQUEUE_WRITE_INT8 (cq_wbuf, 0);
  CQUEUE_WRITE_INT8 (cq_wbuf, safi);

  /* Encode dummy Num-ORFs value */
  CQUEUE_WRITE_INT8 (cq_wbuf, num_orfs);

  /* Encode 'Address-Prefix ORF' Capabilities */
  if (CHECK_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_ORF_PREFIX_SM)
      || CHECK_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_ORF_PREFIX_RM))
    {
      CQUEUE_WRITE_INT8 (cq_wbuf, cap_code == BGP_CAPABILITY_CODE_ORF ?
                         BGP_ORF_TYPE_PREFIX : BGP_ORF_TYPE_PREFIX_OLD);

      if (CHECK_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_ORF_PREFIX_SM)
          && CHECK_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_ORF_PREFIX_RM))
        {
          SET_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_SM_ADV);
          SET_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_RM_ADV);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ORF_MODE_BOTH);
        }
      else if (CHECK_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_ORF_PREFIX_SM))
        {
          SET_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_SM_ADV);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ORF_MODE_SEND);
        }
      else
        {
          SET_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_RM_ADV);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ORF_MODE_RECEIVE);
        }

      num_orfs++;
    }

  /* Obtain 'param_len' and 'cap_len' and overwrite previous values */
  CQUEUE_BUF_TAKE_SNAPSHOT (cq_wbuf, &tmp_cqbss2);
  opt_param_len = CQUEUE_BUF_GET_SNAPSHOT_LEN_DIFF (&tmp_cqbss2,
                                                    &tmp_cqbss1);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss1);
  CQUEUE_WRITE_REWIND_NBYTES (cq_wbuf,
                              BGP_MSG_OPEN_OPT_LEN_FIELD_SIZE);
  CQUEUE_WRITE_INT8 (cq_wbuf, opt_param_len);
  cap_len = opt_param_len - BGP_MSG_OPEN_OPT_CAP_MIN_SIZE;
  CQUEUE_WRITE_ADVANCE_NBYTES (cq_wbuf,
                               BGP_MSG_OPEN_OPT_CAP_CODE_FIELD_SIZE);
  CQUEUE_WRITE_INT8 (cq_wbuf, cap_len);

  /* Overwrite 'num_orfs' field value */
  CQUEUE_WRITE_ADVANCE_NBYTES (cq_wbuf,
                               BGP_MSG_OPEN_OPT_CAP_ORF_AFI_SAFI_SIZE);
  CQUEUE_WRITE_INT8 (cq_wbuf, num_orfs);
  CQUEUE_BUF_ENLIVEN_SNAPSHOT (cq_wbuf, &tmp_cqbss2);

  return;
}

/*
 * LEVEL 3 BGP Message Encoder function:
 * Encodes BGP UPDATE Message AS Path-Attribute
 */
void
bpe_msg_attr_aspath (struct cqueue_buffer *cq_wbuf,
                     struct bgp_peer *to_peer,
                     struct bgp_peer *from_peer,
                     struct attr *attr,
                     afi_t afi, safi_t safi)
{
  struct aspath *aspath=NULL;
  u_int32_t baai;
  u_int32_t bsai;
  as_t   local_as;
  struct bgp *bgp;
  enum bgp_peer_type peer_type;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);
  bgp = bgp_lookup_default();
  peer_type = peer_sort (to_peer);
  
  /* 
   * RFC 4271 Sec 9.2.2.2, If as_set is the first AS type, 
   * it should not allow MED 
   */
  if((attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC)) 
            && ((attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR)) || 
     (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR)))
            && !bgp_config_check (from_peer->bgp, BGP_CFLAG_MED_REMOVE_SEND))
  {
    UNSET_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC)); 
  }

  
  /* Determine the AS-Path to be encoded */

  if (BGP_PEER_EBGP == peer_type) 
    {
      if ((! CHECK_FLAG (to_peer->af_flags [baai][bsai],
                        PEER_FLAG_AS_PATH_UNCHANGED) ||
           (0 == attr->aspath->length)) &&

         ! (CHECK_FLAG (from_peer->af_flags [baai][bsai],
                        PEER_FLAG_RSERVER_CLIENT) &&
            CHECK_FLAG (to_peer->af_flags [baai][bsai],
                           PEER_FLAG_RSERVER_CLIENT)))
      {
        aspath = aspath_dup (attr->aspath);

        if (CHECK_FLAG (to_peer->config, PEER_FLAG_LOCAL_AS))
          {
            /* Add our true AS, local AS will be added below. */
            aspath = aspath_add_seq (aspath, to_peer->bgp->as);
            local_as = to_peer->local_as;
          }
        else if (bgp_config_check (to_peer->bgp, BGP_CFLAG_CONFEDERATION))
          {
            /* Strip CONFED info and stuff our CONFED_ID in front */
            aspath = aspath_delete_confed_seq (aspath);
            local_as = to_peer->bgp->confed_id;
          }
        else 
          {
            local_as = to_peer->bgp->as;
          }

        /* Add the true local AS 1+ times */
        if (bgp && bgp->aslocal_count > 1)
          {
            int i;

            for (i = 0; i < bgp->aslocal_count; i++)
               aspath = aspath_add_seq (aspath, local_as);
          }
        else
          {
            aspath = aspath_add_seq (aspath, local_as);
          }

      }
    }
  else if (BGP_PEER_CONFED == peer_type)
    {
#ifdef BGP_STRICT_RFC3065
      struct assegment *asseg;

      /* When we do strict RFC3065, we need to check first AS segment
         is AS_CONFED_SEQUENCE or not.  This method is not really used
         in real network.  */
      aspath = aspath_dup (attr->aspath);
      asseg = (struct assegment *) aspath->data;

      if (asseg
          && asseg->length
          && asseg->type != BGP_AS_CONFED_SEQUENCE)
        aspath = aspath_add_confed_seq (aspath, to_peer->bgp->confed_id);
      else
        aspath = aspath_add_confed_seq (aspath, to_peer->local_as);
#else /* ! BGP_STRICT_RFC3065 */
      /* This is a method which is deployed in real network.  So if
         there is no reason, we should use this one.  Otherwise we
         will encounter really bad problem.  */
      aspath = aspath_dup (attr->aspath);
      aspath = aspath_add_confed_seq (aspath, to_peer->local_as);
#endif /* BGP_STRICT_RFC3065 */
    }
  else
    aspath = attr->aspath;

  if (!aspath) /*Safety check as aspath is accessed further*/
    return;

  /* Encode AS Path Attribute */
  if (aspath->length > 255)
    {
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS |
                                  BGP_ATTR_FLAG_EXTLEN);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS_PATH);
      CQUEUE_WRITE_INT16 (cq_wbuf, aspath->length);
    }
  else
    {
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
      CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS_PATH);
      CQUEUE_WRITE_INT8 (cq_wbuf, aspath->length);
    }
  CQUEUE_WRITE_NBYTES (cq_wbuf, aspath->data, aspath->length);
 
 /* Free allocated 'aspath' */
  if (aspath != attr->aspath)
    aspath_free (aspath);

  return;
}

/*
 * Encode the specified AS into the AS path and AS4 path.
 */
static void
bpe_aspath_add_as (struct aspath **aspath, struct as4path **as4path, 
                   unsigned as)
{
  if (BGP_IS_AS4_MAPPABLE (as))
    {
      *aspath = aspath_add_seq (*aspath, as);
    }
  else
    {
      *aspath  = aspath_add_seq (*aspath, BGP_AS_TRANS);
      *as4path = as4path_add_seq (*as4path, as);
    }
}

/*
 * LEVEL 3 BGP Message Encoder function:
 * Encodes BGP UPDATE Message AS Path-Attribute
 */

#ifdef HAVE_EXT_CAP_ASN 
void
bpe_msg_attr_new_aspath (struct cqueue_buffer *cq_wbuf,
                         struct bgp_peer *to_peer,
                         struct bgp_peer *from_peer,
                         struct attr *attr,
                         afi_t afi, safi_t safi)
{
  struct aspath *aspath;
  struct as4path *aspath4B;
  struct as4path *as4path;
  struct bgp *bgp;
  enum bgp_peer_type peer_type;
  int ascount;
  unsigned int as4count;
  int as4octetcount;
  int cnt;
  u_int32_t baai;
  u_int32_t bsai;

  ascount = 0;
  as4count = 0;
  as4octetcount = 0;
  aspath = NULL;
  aspath4B = NULL;
  as4path = NULL;


  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  bgp = bgp_lookup_default();

  peer_type = peer_sort (to_peer);


  /* 
   * Determine how the AS-Path is to be encoded. There are 3 major 
   * blocks here. They are: 
   *   1) Normal EBGP.
   *   2) Confederated IBGP.
   *   3) No AS path changes (all IBGP, and some EBGP)
   */
  if (peer_type == BGP_PEER_EBGP

      && (! CHECK_FLAG (to_peer->af_flags [baai][bsai],
                        PEER_FLAG_AS_PATH_UNCHANGED)
          || ! attr->aspath->length)

      && ! (CHECK_FLAG (from_peer->af_flags [baai][bsai],
                        PEER_FLAG_RSERVER_CLIENT)
            && CHECK_FLAG (to_peer->af_flags [baai][bsai],
                           PEER_FLAG_RSERVER_CLIENT)))
    {
      if (! bgp_config_check (to_peer->bgp, BGP_CFLAG_CONFEDERATION) )
        { 
          if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
            {
              if (!CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV))     
                { 
                  /*
                   * Peering: EBGP, speaker not in a confederation. 
                   * Peers:   Remote is OBGP. Local is NBGP. 
                   * Actions: Use 2-byte AS path and use AS_PATH attribute.
                   *          Add true AS path if Local-AS used.
                   *          Add local_as N times. 
                   */
                  aspath = aspath_new_or_dup(attr->aspath);
                  as4path = as4path_new_or_dup(attr->as4path);

                 /* if Local AS used, prepend true AS first */
                 if (CHECK_FLAG (to_peer->config, PEER_FLAG_LOCAL_AS))
                    bpe_aspath_add_as(&aspath, &as4path, to_peer->bgp->as);

                  /* Prepend our AS 1 or more times */
                  for (cnt = 0; cnt < bgp->aslocal_count; cnt++)
                    bpe_aspath_add_as(&aspath, &as4path, to_peer->local_as);  
                }
              else
                {
                  /*
                   * Peering: EBGP, speaker not in a confederation. 
                   * Peers:   Remote is NBGP. Local is NBGP. 
                   * Actions: Use 4-byte AS path
                   *          Add true AS path if Local-AS used.
                   *          Add local_as N times. 
                   */

                  aspath4B = as4path_new_or_dup(attr->aspath4B);

                  /* if Local AS used, prepend true AS first */
                  if (CHECK_FLAG (to_peer->config, PEER_FLAG_LOCAL_AS))
                    aspath4B = as4path_add_seq (aspath4B, to_peer->bgp->as);

                  /* Prepend our AS 1 or more times */
                  for (cnt = 0; cnt < bgp->aslocal_count; cnt++)
                    aspath4B = as4path_add_seq (aspath4B, to_peer->local_as);
                }
            }
          else 
            {
              /*
               * Peering: EBGP, speaker not in a confederation. 
               * Peers:   Local is OBGP. 
               * Actions: Use 2-byte AS path.
               *          Add true AS path if Local-AS used.
               *          Add local_as N times. 
               */

              aspath = aspath_new_or_dup(attr->aspath);

              /* if Local AS used, prepend true AS first */
              if (CHECK_FLAG (to_peer->config, PEER_FLAG_LOCAL_AS))
                aspath = aspath_add_seq (aspath, to_peer->bgp->as);

              /* Prepend our AS 1 or more times */
              for (cnt = 0; cnt < bgp->aslocal_count; cnt++)
                aspath = aspath_add_seq (aspath, to_peer->local_as);
            }
        }
      else if (bgp_config_check (to_peer->bgp, BGP_CFLAG_CONFEDERATION)) 
        {
          if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
            {
              if (! CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
                {
                  /*
                   * Peering: EBGP. Speaker in a confederation. 
                   *          Neighbor is not in this confederation.
                   * Peers:   Remote is OBGP. Local is NBGP. 
                   * Actions: Use 2-byte aspath and AS_PATH attribute.
                   *          Add confederation AS 1 or more times.
                   *          Add Local AS if Local-AS used.
                   */

                  aspath = aspath_new_or_dup (attr->aspath);                        
                  as4path = as4path_new_or_dup(attr->as4path);

                  aspath = aspath_delete_confed_seq (aspath);

                  /* Prepend our AS 1 or more times */
                  for (cnt = 0; cnt < bgp->aslocal_count; cnt++)
                    bpe_aspath_add_as(&aspath, &as4path, 
                                      to_peer->bgp->confed_id);

                  /* if Local AS used, prepend true AS first */
                  if (CHECK_FLAG (to_peer->config, PEER_FLAG_LOCAL_AS))
                    bpe_aspath_add_as(&aspath, &as4path, to_peer->local_as);  
                }
              else
                {
                  /*
                   * Peering: EBGP, speaker in a confederation. 
                   *          Neighbor is not in this confederation.
                   * Peers:   Remote is NBGP. Local is NBGP. 
                   * Actions: Use 4-byte AS path. 
                   *          Add confederation AS 1 or more times.
                   *          Add Local AS if Local-AS used.
                   */

                  aspath4B = as4path_new_or_dup (attr->aspath4B);
                  aspath4B = as4path_delete_confed_seq (aspath4B);

                  /* Prepend our AS 1 or more times */
                  for (cnt = 0; cnt < bgp->aslocal_count; cnt++)
                    aspath4B = as4path_add_seq (aspath4B, 
                                                to_peer->bgp->confed_id);

                  /* if Local AS used, prepend true AS first */
                  if (CHECK_FLAG (to_peer->config, PEER_FLAG_LOCAL_AS))
                    aspath4B = as4path_add_seq (aspath4B, to_peer->local_as);
                }
             }
           else
             {
                /*
                 * Peering: EBGP, speaker in a confederation. 
                 *          Neighbor is not in this confederation.
                 * Peers:   Local is OBGP. 
                 * Actions: Use 2-byte aspath. 
                 *          Add confederation AS 1 or more times.
                 *          Add Local AS if Local-AS used.
                 */
                aspath = aspath_new_or_dup (attr->aspath); 
                aspath = aspath_delete_confed_seq (aspath);

                /* Prepend our AS 1 or more times */
                for (cnt = 0; cnt < bgp->aslocal_count; cnt++)
                  aspath = aspath_add_seq (aspath, to_peer->bgp->confed_id);    

                /* Prepend our AS 1 or more times */
                for (cnt = 0; cnt < bgp->aslocal_count; cnt++)
                  aspath = aspath_add_seq (aspath, to_peer->local_as);
             }
          }
    }
  else if (peer_type == BGP_PEER_CONFED)
    {
      /*
       * Peering: EBGP, Speaker & neighbor in a confederation.
       * Peers:   OBGP/NBGP as indicated.
       * Actions: Local AS and as_count are not supported.
       *          between confederated neighbors.
       */

#ifdef BGP_STRICT_RFC3065
      struct assegment *asseg;
      struct as4segment *asseg_4b;
      
      /* 
       * When we do strict RFC3065, we need to check first AS segment
       * is AS_CONFED_SEQUENCE or not.  This method is not really used
       * in real network.  
       */

      /* Determine if local speaker is NBGP */
      if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        {
          /* Determine if remote peer is OBGP */
          /* AS4_PATH attr is not valid for CONFEDERATION  */
          if (! CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
            {
              aspath = aspath_new_or_dup (attr->aspath);
              asseg = (struct assegment *) aspath->data;              
            }
          /* Neighbor is NBGP */
          else
            {
              aspath4B = as4path_new_or_dup (attr->aspath4B);
              asseg_4b = (struct as4segment *) aspath4B->data;
            }
         }
       /* Local Speaker is OBGP */
       else
         {
           aspath = aspath_new_or_dup (attr->aspath);
           asseg = (struct assegment *) aspath->data;
         }

      /* Determine if local speaker is NBGP */
      if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        {
         /* Determine if neighbor is OBGP */ 
          if (! CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV)) 
            {
                  if (asseg
                      && asseg->length
                      && asseg->type != BGP_AS_CONFED_SEQUENCE)
                    aspath = aspath_add_confed_seq (aspath, 
                                                    to_peer->bgp->confed_id);

                  else if (BGP_IS_AS4_MAPPABLE(to_peer->local_as))
                    aspath = aspath_add_confed_seq (aspath, to_peer->local_as);
                  else
                    aspath = aspath_add_confed_seq (aspath, BGP_AS_TRANS);  
            }
          /* Neighbor is NBGP */
          else if (asseg_4b
                   && asseg_4b->length
                   && asseg_4b->type != BGP_AS_CONFED_SEQUENCE)
             aspath4B = as4path_add_confed_seq (aspath4B, 
                                                to_peer->bgp->confed_id);
           else
             aspath4B = as4path_add_confed_seq (aspath4B, to_peer->local_as);   
       }
       /* Local Speaker is OBGP */
       else if (asseg
                && asseg->length
                && asseg->type != BGP_AS_CONFED_SEQUENCE)
         aspath = aspath_add_confed_seq (aspath, to_peer->bgp->confed_id);    
       else
         aspath = aspath_add_confed_seq (aspath, to_peer->local_as);            

#else /* ! BGP_STRICT_RFC3065 */
      /* 
       * This is a method which is deployed in real network.  So if
       * there is no reason, we should use this one.  Otherwise we
       * will encounter really bad problem.  
       */

    /* Determine if local speaker is NBGP */
    if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
      {
         /* Neighbor is OBGP */
        if (! CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV)) 
          {
            if (BGP_IS_AS4_MAPPABLE(to_peer->local_as))
              {
                aspath = aspath_new_or_dup (attr->aspath);
                aspath = aspath_add_confed_seq (aspath, to_peer->local_as);
              }
            else
              {
                aspath = aspath_new_or_dup (attr->aspath);
                aspath = aspath_add_confed_seq (aspath, BGP_AS_TRANS);
              }  
           }
         else
          {
            aspath4B = as4path_new_or_dup (attr->aspath4B); 
            aspath4B = as4path_add_confed_seq (aspath4B, to_peer->local_as);
          }
      }
     /* Local Speaker is OBGP */
     else
       {
         aspath = aspath_new_or_dup (attr->aspath);
         aspath = aspath_add_confed_seq (aspath, to_peer->local_as);
       }
#endif /* BGP_STRICT_RFC3065 */
    }
  else
    {
      /*
       * Peering: IBRP or EBGP where no AS path changes are needed. 
       * Peers:   Doesn't matter. No AS path changes.
       * Actions: Local AS and as_count are not supported.
       */

      if (! CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        {
          aspath = attr->aspath;
          if (!aspath)
            aspath = aspath_new ();
        }
      else
       {
         aspath = attr->aspath;
         if (!aspath)
            aspath = aspath_new ();
         aspath4B = attr->aspath4B;
         if (!aspath4B)
            aspath4B = as4path_new ();
         as4path = attr->as4path;
         if (!as4path)
            as4path = as4path_new ();
       }
    }



  /* Encoding AS Path Attribute */
  /* Check Local speaker is NBGP */
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      /* Check neighbor is OBGP */
      if (! CHECK_FLAG (to_peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
        {
          if (aspath->length > 255)
            {
              CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS |
                                          BGP_ATTR_FLAG_EXTLEN);
              CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS_PATH);
              CQUEUE_WRITE_INT16 (cq_wbuf, aspath->length);
              CQUEUE_WRITE_NBYTES (cq_wbuf, aspath->data, aspath->length);
            }
          else
            {
              CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
              CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS_PATH);
              CQUEUE_WRITE_INT8 (cq_wbuf, aspath->length);
              CQUEUE_WRITE_NBYTES (cq_wbuf, aspath->data, aspath->length);
            }
           
          /* encoding AS4 path attribute */
          /* Check whether AS4 attribute is required to send */
          ascount = aspath_as_count(aspath);
          as4count = as4path_as4_count(as4path);
          as4octetcount = aspath_as_value_astrans_check (aspath);
          if (ascount && as4count && as4octetcount)
            {
              if (as4path->length > 255)
                {
                  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                              BGP_ATTR_FLAG_TRANS |
                                              BGP_ATTR_FLAG_EXTLEN);
                  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS4_PATH);
                  CQUEUE_WRITE_INT16 (cq_wbuf, as4path->length);
                }
              else
                {
                  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_OPTIONAL |
                                              BGP_ATTR_FLAG_TRANS);
                  CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS4_PATH);
                  CQUEUE_WRITE_INT8 (cq_wbuf, as4path->length);
                }
              CQUEUE_WRITE_NBYTES (cq_wbuf, as4path->data, as4path->length);
            }
        }
      /* Neighbor is NBGP */
      /* NBGP should not send AS4 attr to another NGBP */
      else
        {
          if (aspath4B->length > 255)
            {
              CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS |
                                          BGP_ATTR_FLAG_EXTLEN);
              CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS_PATH);
              CQUEUE_WRITE_INT16 (cq_wbuf, aspath4B->length);
              CQUEUE_WRITE_NBYTES (cq_wbuf, aspath4B->data, aspath4B->length); 
            }
          else
            {
              CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
              CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS_PATH);
              CQUEUE_WRITE_INT8 (cq_wbuf, aspath4B->length);
              CQUEUE_WRITE_NBYTES (cq_wbuf, aspath4B->data, aspath4B->length);
            }
        }
    }
  /* Local Speaker is OBGP */
  else
    {
      if (aspath->length > 255)
        {
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS |
                                      BGP_ATTR_FLAG_EXTLEN);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS_PATH);
          CQUEUE_WRITE_INT16 (cq_wbuf, aspath->length);
          CQUEUE_WRITE_NBYTES (cq_wbuf, aspath->data, aspath->length);
        }
      else
        {
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_FLAG_TRANS);
          CQUEUE_WRITE_INT8 (cq_wbuf, BGP_ATTR_AS_PATH);
          CQUEUE_WRITE_INT8 (cq_wbuf, aspath->length);
          CQUEUE_WRITE_NBYTES (cq_wbuf, aspath->data, aspath->length);
        }
    }



  /* 
   * Free allocated aspath data. Some will only have been used for 
   * the NBGP case, but will be NULL here so this approach is safe. 
   */
  if (aspath != attr->aspath)
    aspath_free (aspath);
  if (as4path != attr->as4path)
    as4path_free (as4path);
  if (aspath4B != attr->aspath4B)
    as4path_free (aspath4B);

  return;
}
#endif /* HAVE_EXT_CAP_ASN */

/*
 * LEVEL 3 BGP Message Encoder function:
 * Encodes BGP UPDATE Message NLRIs Prefix
 */
bool_t
bpe_msg_update_nlri_prefix (struct cqueue_buffer *cq_wbuf,
                            struct bgp_node *rn,
                            struct bgp_info *ri,
                            afi_t afi,
                            safi_t safi,
                            bool_t withdrawn_prefix,
                            bool_t auto_summary_update)
{
  u_int32_t residual_len_req;
  bool_t to_continue;
  u_int8_t psize;
  struct prefix rnp;
  u_int8_t prefixlen;
  struct bgp *bgp;
  to_continue = PAL_FALSE;
  bgp = bgp_lookup_default();
  residual_len_req = BGP_NLRI_MIN_SIZE + (withdrawn_prefix == PAL_TRUE) ?
                     BGP_TOTAL_ATTR_LEN_FIELD_SIZE : 0;

  /* Determine Prefix size */
  BGP_GET_PREFIX_FROM_NODE (rn);
  psize = PSIZE (rnp.prefixlen);
  prefixlen = rnp.prefixlen;

  switch (safi)
    {
    /* Removed UNICAST_MULTICAST case as it is not supported by RFC 4760 */
    case SAFI_UNICAST:
    case SAFI_MULTICAST:
      /* Residual Length check */
      if (CQUEUE_BUF_GET_BYTES_EMPTY (cq_wbuf) <=
          residual_len_req + psize)
        {
          to_continue = PAL_TRUE;
          goto EXIT;
        }

      /* Auto-summarise the static networks before encoding if required 
      */

      if (IPV4_MAX_PREFIXLEN != prefixlen) /* Dont maniputale host routes */
        if (bgp && ((bgp_af_config_check (bgp, afi, safi, BGP_AF_CFLAG_AUTO_SUMMARY) &&
               (!withdrawn_prefix || (!auto_summary_update && withdrawn_prefix))) ||
             (!bgp_af_config_check (bgp, afi, safi, BGP_AF_CFLAG_AUTO_SUMMARY) &&
               auto_summary_update && withdrawn_prefix)))
          {
            if ( IN_CLASSA (pal_ntoh32 (rnp.u.prefix4.s_addr)) )
              prefixlen = IN_CLASSA_PREFIXLEN;
            else if ( IN_CLASSB (pal_ntoh32 (rnp.u.prefix4.s_addr)) )
              prefixlen = IN_CLASSB_PREFIXLEN;
            else if ( IN_CLASSC (pal_ntoh32 (rnp.u.prefix4.s_addr)) )
              prefixlen = IN_CLASSC_PREFIXLEN;

            psize = PSIZE(prefixlen);
          }

      /* Encode 'PrefixLen' value */
      CQUEUE_WRITE_INT8 (cq_wbuf, prefixlen);

      /* Encode the 'Prefix' */
      CQUEUE_WRITE_NBYTES (cq_wbuf, &rnp.u.prefix, psize);
      break;

    default:
      /* We have earlier ensured AFI-SAFI validation */
      pal_assert (0);
      to_continue = PAL_TRUE;
      goto EXIT;
    }

EXIT:

  return to_continue;
}

