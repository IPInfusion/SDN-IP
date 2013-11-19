/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/*********************************************************************/
/* FILE       : bgp_fsm.c                                            */
/* PURPOSE    : This file contains 'BGP Peer FSM' related function   */
/*              definitions.                                         */
/* SUB-MODULE : BGP Peer FSM                                         */
/* NAME-TAG   : 'bpf_' (BGP Peer FSM)                                */
/*********************************************************************/

/*
 * Action Function Array for current State
 */
bpf_act_func_t bpf_action_func [BPF_STATE_MAX] =
{
  bpf_action_invalid,
  bpf_action_idle,
  bpf_action_connect,
  bpf_action_active,
  bpf_action_open_sent,
  bpf_action_open_cfm,
  bpf_action_established
};

/* BGP Peer FSM Event Handler */
s_int32_t
bpf_process_event (struct thread *t_event)
{
  struct lib_globals *blg;
  struct bgp_peer *peer;
  u_int32_t bpf_event;
  s_int32_t ret;

  ret = 0;

  /* Obtain the BGP Lib Global pointer */
  blg = THREAD_GLOB (t_event);

  /* Sanity check */
  if (! blg || blg != &BLG)
    {
      ret = -1;
      goto EXIT;
    }

  /* Obtain the Peer structure */
  peer = THREAD_ARG (t_event);

  /* Sanity check */
  if (! peer)
    {
      zlog_err (&BLG, "[FSM] Event: Invalid Peer(%X)", peer);
      ret = -1;
      goto EXIT;
    }

  /* Obtain the Event value */
  bpf_event = THREAD_VAL (t_event);

  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  if (BGP_DEBUG (fsm, FSM))
    zlog_info (&BLG, "%s-%s [FSM] State: %s Event: %d",
               peer->host, BGP_PEER_DIR_STR (peer),
               BGP_PEER_FSM_STATE_STR (peer->bpf_state), bpf_event);

  /* Invoke Action-Func defined for the current-state */
  ret = bpf_action_func [peer->bpf_state] (peer, bpf_event);

EXIT:

  return ret;
}

s_int32_t
bpf_action_invalid (struct bgp_peer *peer,
                    u_int32_t bpf_event)
{
  s_int32_t ret;

  ret = 0;

  zlog_err (&BLG, "%s-%s [FSM] State: INVALID Event: %d",
            peer->host, BGP_PEER_DIR_STR (peer), bpf_event);

  pal_assert (0);

  return ret;
}

s_int32_t
bpf_action_idle (struct bgp_peer *peer,
                 u_int32_t bpf_event)
{
  s_int32_t ret;

  ret = 0;

  switch (bpf_event)
    {
    case BPF_EVENT_MANUAL_START:
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      break;

    case BPF_EVENT_AUTO_START:
      if (! CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
        {
          peer->bpf_conn_retry_count = 0;
          if (CHECK_FLAG (peer->config, PEER_CONFIG_CONNECT))
            peer->v_connect = peer->connect;
          else
            peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;
          BGP_TIMER_ON (&BLG, peer->t_connect, peer, bpf_timer_conn_retry,
                        bpf_timer_generate_jitter (peer->v_connect));
          bpn_sock_cb_connect (peer);
          bpf_change_state (peer, BPF_STATE_CONNECT);
        }
      break;

    case BPF_EVENT_MANUAL_START_TCP_PASSIVE:
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      break;

    case BPF_EVENT_AUTO_START_TCP_PASSIVE:
      peer->bpf_conn_retry_count = 0;
      bpf_change_state (peer, BPF_STATE_ACTIVE);
      break;

    case BPF_EVENT_TCP_CONN_VALID:
    case BPF_EVENT_TCP_CONN_INVALID:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_IGNORE);
      break;

    case BPF_EVENT_MANUAL_STOP:
    case BPF_EVENT_AUTO_STOP:
    case BPF_EVENT_CONN_RETRY_EXP:
    case BPF_EVENT_HOLD_EXP:
    case BPF_EVENT_KEEPALIVE_EXP:
    case BPF_EVENT_TCP_CONN_ACKED:
    case BPF_EVENT_TCP_CONN_CFM:
    case BPF_EVENT_TCP_CONN_FAIL:
    case BPF_EVENT_OPEN_VALID:
    case BPF_EVENT_HDR_ERR:
    case BPF_EVENT_OPEN_ERR:
    case BPF_EVENT_OPEN_COLLISION_DUMP:
    case BPF_EVENT_NOTIFY_VER_ERR:
    case BPF_EVENT_NOTIFY_VALID:
    case BPF_EVENT_KEEPALIVE_VALID:
    case BPF_EVENT_UPDATE_VALID:
    case BPF_EVENT_UPDATE_ERR:
    case BPF_EVENT_ROUTE_REFRESH_VALID:
    case BPF_EVENT_ROUTE_REFRESH_ERR:
    case BPF_EVENT_DYNA_CAP_VALID:
    case BPF_EVENT_DYNA_CAP_ERR:
    case BPF_EVENT_ASORIG_EXP:
    case BPF_EVENT_ROUTEADV_EXP:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring event %d in state %s",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));
      break;

    case BPF_EVENT_MANUAL_RESET:
      /* Unsetting the flags so that an actual reset is performed, when the 
       * BPF_EVENT_MANUAL_RESET event is received in the open_sent, open_cfm 
       * and established state.
       */
      if (CHECK_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_IN))
        UNSET_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_IN);
      else if (CHECK_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_OUT))
        UNSET_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_OUT);
    break;

    case BPF_EVENT_AUTO_START_POD:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE_POD:
    case BPF_EVENT_DELAY_OPEN_EXP:
    case BPF_EVENT_IDLE_HOLD_EXP:
    case BPF_EVENT_OPEN_VALID_DELAY_OPEN:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring Unsupported event %d in state %s",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));

      break;

    default:
      pal_assert (0);
      ret = -1;
    }

  return ret;
}

s_int32_t
bpf_action_connect (struct bgp_peer *peer,
                    u_int32_t bpf_event)
{
  s_int32_t ret;

  ret = 0;

  switch (bpf_event)
    {
    case BPF_EVENT_MANUAL_STOP:
      peer->bpf_conn_retry_count = 0;
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      bpn_sock_cb_disconnect (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      break;

    case BPF_EVENT_CONN_RETRY_EXP:
      bpn_sock_cb_disconnect (peer);
      if (CHECK_FLAG (peer->config, PEER_CONFIG_CONNECT))
        peer->v_connect = peer->connect;
      else
        peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;
      BGP_TIMER_ON (&BLG, peer->t_connect, peer, bpf_timer_conn_retry,
                    bpf_timer_generate_jitter (peer->v_connect));
      bpn_sock_cb_connect (peer);
      break;

    case BPF_EVENT_TCP_CONN_VALID:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_ACCEPT);
      break;

    case BPF_EVENT_TCP_CONN_INVALID:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_IGNORE);
      break;

    case BPF_EVENT_TCP_CONN_ACKED:
    case BPF_EVENT_TCP_CONN_CFM:
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      bpn_sock_cb_get_id (peer);
      if (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER))
        peer->v_holdtime = peer->holdtime;
      else if (bgp_config_check (peer->bgp, BGP_CFLAG_DEFAULT_TIMER))
        peer->v_holdtime = peer->bgp->default_holdtime;
      else
        peer->v_holdtime = BGP_DEFAULT_HOLDTIME_LARGE;
      if(peer->v_holdtime)
        BGP_TIMER_ON (&BLG, peer->t_holdtime, peer, bpf_timer_holdtime,
                      peer->v_holdtime);
      bgp_peer_send_open (peer);
      bpf_change_state (peer, BPF_STATE_OPEN_SENT);
      break;

    case BPF_EVENT_TCP_CONN_FAIL:
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      bpn_sock_cb_disconnect (peer);
      if (CHECK_FLAG (peer->config, PEER_CONFIG_CONNECT))
        peer->v_connect = peer->connect;
      else
        peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;
      BGP_TIMER_ON (&BLG, peer->t_connect, peer, bpf_timer_conn_retry,
                    bpf_timer_generate_jitter (peer->v_connect));
      bpf_change_state (peer, BPF_STATE_ACTIVE);
      break;

    case BPF_EVENT_HDR_ERR:
    case BPF_EVENT_OPEN_ERR:
      bgp_peer_send_notify (peer);
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      peer->bpf_conn_retry_count += 1;
      bpn_sock_cb_disconnect (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      bpf_change_state (peer, BPF_STATE_IDLE);
      break;

    case BPF_EVENT_NOTIFY_VER_ERR:
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      peer->bpf_conn_retry_count += 1;
      bpn_sock_cb_disconnect (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      bpf_change_state (peer, BPF_STATE_IDLE);
      break;

    case BPF_EVENT_MANUAL_RESET:
      if (CHECK_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_IN))
        UNSET_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_IN);
      else if (CHECK_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_OUT))
        UNSET_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_OUT);
      else
        {
          peer->v_connect = 0;
          BGP_TIMER_OFF (peer->t_connect);
          peer->bpf_conn_retry_count += 1;
          bpn_sock_cb_disconnect (peer);
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
          bpf_change_state (peer, BPF_STATE_IDLE);
        }
      break;

    case BPF_EVENT_AUTO_STOP:
    case BPF_EVENT_HOLD_EXP:
    case BPF_EVENT_KEEPALIVE_EXP:
    case BPF_EVENT_OPEN_VALID:
    case BPF_EVENT_OPEN_COLLISION_DUMP:
    case BPF_EVENT_NOTIFY_VALID:
    case BPF_EVENT_KEEPALIVE_VALID:
    case BPF_EVENT_UPDATE_VALID:
    case BPF_EVENT_UPDATE_ERR:
    case BPF_EVENT_ROUTE_REFRESH_VALID:
    case BPF_EVENT_ROUTE_REFRESH_ERR:
    case BPF_EVENT_DYNA_CAP_VALID:
    case BPF_EVENT_DYNA_CAP_ERR:
    case BPF_EVENT_ASORIG_EXP:
    case BPF_EVENT_ROUTEADV_EXP:
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      peer->bpf_conn_retry_count += 1;
      bpn_sock_cb_disconnect (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      bpf_change_state (peer, BPF_STATE_IDLE);
      break;

    case BPF_EVENT_MANUAL_START:
    case BPF_EVENT_AUTO_START:
    case BPF_EVENT_MANUAL_START_TCP_PASSIVE:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring event %d in state %s",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));

      break;

    case BPF_EVENT_AUTO_START_POD:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE_POD:
    case BPF_EVENT_DELAY_OPEN_EXP:
    case BPF_EVENT_IDLE_HOLD_EXP:
    case BPF_EVENT_OPEN_VALID_DELAY_OPEN:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring Unsupported event %d in state %s",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));

      break;

    default:
      pal_assert (0);
      ret = -1;
    }

  return ret;
}

s_int32_t
bpf_action_active (struct bgp_peer *peer,
                   u_int32_t bpf_event)
{
  s_int32_t ret;

  ret = 0;

  switch (bpf_event)
    {
    case BPF_EVENT_MANUAL_STOP:
      peer->bpf_conn_retry_count = 0;
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      bpn_sock_cb_disconnect (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      break;

    case BPF_EVENT_CONN_RETRY_EXP:
      bpn_sock_cb_disconnect (peer);
      if (CHECK_FLAG (peer->config, PEER_CONFIG_CONNECT))
        peer->v_connect = peer->connect;
      else
        peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;
      BGP_TIMER_ON (&BLG, peer->t_connect, peer, bpf_timer_conn_retry,
                    bpf_timer_generate_jitter (peer->v_connect));
      bpn_sock_cb_connect (peer);
      bpf_change_state (peer, BPF_STATE_CONNECT);
      break;

    case BPF_EVENT_TCP_CONN_VALID:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_ACCEPT);
      break;

    case BPF_EVENT_TCP_CONN_INVALID:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_IGNORE);
      break;

    case BPF_EVENT_TCP_CONN_ACKED:
    case BPF_EVENT_TCP_CONN_CFM:
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      bpn_sock_cb_get_id (peer);
      if (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER))
        peer->v_holdtime = peer->holdtime;
      else if (bgp_config_check (peer->bgp, BGP_CFLAG_DEFAULT_TIMER))
        peer->v_holdtime = peer->bgp->default_holdtime;
      else
        peer->v_holdtime = BGP_DEFAULT_HOLDTIME_LARGE;
      BGP_TIMER_ON (&BLG, peer->t_holdtime, peer, bpf_timer_holdtime,
                    peer->v_holdtime);
      bgp_peer_send_open (peer);
      bpf_change_state (peer, BPF_STATE_OPEN_SENT);
      break;

    case BPF_EVENT_TCP_CONN_FAIL:
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      peer->bpf_conn_retry_count += 1;
      bpn_sock_cb_disconnect (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      break;

    case BPF_EVENT_HDR_ERR:
    case BPF_EVENT_OPEN_ERR:
      bgp_peer_send_notify (peer);
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      peer->bpf_conn_retry_count += 1;
      bpn_sock_cb_disconnect (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      break;

    case BPF_EVENT_NOTIFY_VER_ERR:
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      peer->bpf_conn_retry_count += 1;
      bpn_sock_cb_disconnect (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      break;

    case BPF_EVENT_MANUAL_RESET:
      if (CHECK_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_IN))
        UNSET_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_IN);
      else if (CHECK_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_OUT))
        UNSET_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_OUT);
      else
        {
          peer->v_connect = 0;
          BGP_TIMER_OFF (peer->t_connect);
          peer->bpf_conn_retry_count += 1;
          bpn_sock_cb_disconnect (peer);
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
          bpf_change_state (peer, BPF_STATE_IDLE);
        }
      break;

    case BPF_EVENT_AUTO_STOP:
    case BPF_EVENT_HOLD_EXP:
    case BPF_EVENT_KEEPALIVE_EXP:
    case BPF_EVENT_OPEN_COLLISION_DUMP:
    case BPF_EVENT_OPEN_VALID:
    case BPF_EVENT_NOTIFY_VALID:
    case BPF_EVENT_KEEPALIVE_VALID:
    case BPF_EVENT_UPDATE_VALID:
    case BPF_EVENT_UPDATE_ERR:
    case BPF_EVENT_ROUTE_REFRESH_VALID:
    case BPF_EVENT_ROUTE_REFRESH_ERR:
    case BPF_EVENT_DYNA_CAP_VALID:
    case BPF_EVENT_DYNA_CAP_ERR:
    case BPF_EVENT_ASORIG_EXP:
    case BPF_EVENT_ROUTEADV_EXP:
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      peer->bpf_conn_retry_count += 1;
      bpn_sock_cb_disconnect (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      bpf_change_state (peer, BPF_STATE_IDLE);
      break;

    case BPF_EVENT_MANUAL_START:
    case BPF_EVENT_AUTO_START:
    case BPF_EVENT_MANUAL_START_TCP_PASSIVE:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring event %d in state %s",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));
      break;

    case BPF_EVENT_AUTO_START_POD:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE_POD:
    case BPF_EVENT_DELAY_OPEN_EXP:
    case BPF_EVENT_IDLE_HOLD_EXP:
    case BPF_EVENT_OPEN_VALID_DELAY_OPEN:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring Unsupported event %d "
                   "in state %s", peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));

      break;

    default:
      pal_assert (0);
      ret = -1;
    }

  return ret;
}

s_int32_t
bpf_action_open_sent (struct bgp_peer *peer,
                      u_int32_t bpf_event)
{
  struct bgp_peer *clone_peer;
  struct listnode *nn;
  s_int32_t ret;

  ret = 0;

  switch (bpf_event)
    {
    case BPF_EVENT_MANUAL_STOP:
      bpf_register_notify (peer, BGP_NOTIFY_CEASE,
                           BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN,
                           NULL, 0);
      bgp_peer_send_notify (peer);
      peer->bpf_conn_retry_count = 0;
      bgp_peer_stop (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else if (peer->clones_list)
        LIST_LOOP (peer->clones_list, clone_peer, nn)
          BGP_PEER_FSM_EVENT_ADD (&BLG, clone_peer, BPF_EVENT_MANUAL_STOP);
      break;

    case BPF_EVENT_AUTO_STOP:
      bpf_register_notify (peer, BGP_NOTIFY_CEASE,
                           BGP_NOTIFY_CEASE_ADMIN_RESET,
                           NULL, 0);
      bgp_peer_send_notify (peer);
      peer->bpf_conn_retry_count += 1;
      bgp_peer_stop (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else if (peer->clones_list)
        LIST_LOOP (peer->clones_list, clone_peer, nn)
          BGP_PEER_FSM_EVENT_ADD (&BLG, clone_peer, BPF_EVENT_AUTO_STOP);
      break;

    case BPF_EVENT_MANUAL_RESET:
      bpf_process_manual_reset (peer);
      break;

    case BPF_EVENT_HOLD_EXP:
      bpf_register_notify (peer, BGP_NOTIFY_HOLD_ERR,
                           0, NULL, 0);
      bgp_peer_send_notify (peer);
      peer->bpf_conn_retry_count += 1;
      bgp_peer_stop (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      break;

    case BPF_EVENT_TCP_CONN_VALID:
    case BPF_EVENT_TCP_CONN_ACKED:
    case BPF_EVENT_TCP_CONN_CFM:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_TRACK);
      break;

    case BPF_EVENT_TCP_CONN_INVALID:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_IGNORE);
      break;

    case BPF_EVENT_TCP_CONN_FAIL:
      bpn_sock_cb_reset (peer);
      bgp_peer_stop (peer);
      if (CHECK_FLAG (peer->config, PEER_CONFIG_CONNECT))
        peer->v_connect = peer->connect;
      else
        peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;
      BGP_TIMER_ON (&BLG, peer->t_connect, peer, bpf_timer_conn_retry,
                    bpf_timer_generate_jitter (peer->v_connect));
      bpf_change_state (peer, BPF_STATE_ACTIVE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      break;

    case BPF_EVENT_OPEN_VALID:
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      BGP_TIMER_OFF (peer->t_holdtime);
      ret = bpf_collision_detect (peer);
      if (ret >= 0)
        {
          bpf_transform_incoming2real_peer (&peer);
          bgp_peer_send_keepalive (peer);
          if (peer->v_holdtime && peer->v_keepalive)
            {
              BGP_TIMER_OFF (peer->t_keepalive);
              BGP_TIMER_ON (&BLG, peer->t_keepalive, peer,
                            bpf_timer_keepalive, peer->v_keepalive);
              BGP_TIMER_OFF (peer->t_holdtime);
              BGP_TIMER_ON (&BLG, peer->t_holdtime, peer,
                            bpf_timer_holdtime, peer->v_holdtime);
            }
          bpf_process_open (peer);
          bpf_change_state (peer, BPF_STATE_OPEN_CFM);
        }
      else
        {
          bpf_register_notify (peer, BGP_NOTIFY_CEASE,
                               BGP_NOTIFY_CEASE_CONNECT_REJECT,
                               NULL, 0);
          bgp_peer_send_notify (peer);
          bgp_peer_delete (peer);
        }
      break;

    case BPF_EVENT_HDR_ERR:
    case BPF_EVENT_OPEN_ERR:
      bgp_peer_send_notify (peer);
      peer->bpf_conn_retry_count += 1;
      bgp_peer_stop (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_OPEN_COLLISION_DUMP:
      bpf_register_notify (peer, BGP_NOTIFY_CEASE, BGP_NOTIFY_CEASE_CONN_COLLISION_RES, NULL, 0);
      bgp_peer_send_notify (peer);
      peer->bpf_conn_retry_count += 1;
      bgp_peer_stop (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_NOTIFY_VER_ERR:
      bgp_peer_stop (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_NOTIFY_VALID:
      bpf_process_notification (peer);
      peer->bpf_conn_retry_count += 1;
      bgp_peer_stop (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_CONN_RETRY_EXP:
    case BPF_EVENT_KEEPALIVE_EXP:
    case BPF_EVENT_KEEPALIVE_VALID:
    case BPF_EVENT_UPDATE_VALID:
    case BPF_EVENT_UPDATE_ERR:
    case BPF_EVENT_ROUTE_REFRESH_VALID:
    case BPF_EVENT_ROUTE_REFRESH_ERR:
    case BPF_EVENT_DYNA_CAP_VALID:
    case BPF_EVENT_DYNA_CAP_ERR:
    case BPF_EVENT_ASORIG_EXP:
    case BPF_EVENT_ROUTEADV_EXP:
      bpf_register_notify (peer, BGP_NOTIFY_FSM_ERR, 0, NULL, 0);
      bgp_peer_send_notify (peer);
      peer->bpf_conn_retry_count += 1;
      bgp_peer_stop (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_MANUAL_START:
    case BPF_EVENT_AUTO_START:
    case BPF_EVENT_MANUAL_START_TCP_PASSIVE:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring event %d in state %s",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));
      break;

    case BPF_EVENT_AUTO_START_POD:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE_POD:
    case BPF_EVENT_DELAY_OPEN_EXP:
    case BPF_EVENT_IDLE_HOLD_EXP:
    case BPF_EVENT_OPEN_VALID_DELAY_OPEN:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring Unsupported event %d "
                   "in state %s", peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));

      break;

    default:
      pal_assert (0);
      ret = -1;
    }

  return ret;
}

s_int32_t
bpf_action_open_cfm (struct bgp_peer *peer,
                     u_int32_t bpf_event)
{
  struct bgp_peer *clone_peer;
  struct listnode *nn;
  s_int32_t ret;

  ret = 0;

  switch (bpf_event)
    {
    case BPF_EVENT_MANUAL_STOP:
      bpf_register_notify (peer, BGP_NOTIFY_CEASE,
                           BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN,
                           NULL, 0);
      bgp_peer_send_notify (peer);
      peer->bpf_conn_retry_count = 0;
      bpf_change_state (peer, BPF_STATE_IDLE);
      bgp_peer_stop (peer);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else if (peer->clones_list)
        LIST_LOOP (peer->clones_list, clone_peer, nn)
          BGP_PEER_FSM_EVENT_ADD (&BLG, clone_peer, BPF_EVENT_MANUAL_STOP);
      break;

    case BPF_EVENT_AUTO_STOP:
      bpf_register_notify (peer, BGP_NOTIFY_CEASE,
                           BGP_NOTIFY_CEASE_ADMIN_RESET, NULL, 0);
      bgp_peer_send_notify (peer);
      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
      bgp_peer_stop (peer);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else if (peer->clones_list)
        LIST_LOOP (peer->clones_list, clone_peer, nn)
          BGP_PEER_FSM_EVENT_ADD (&BLG, clone_peer, BPF_EVENT_AUTO_STOP);
      break;

    case BPF_EVENT_MANUAL_RESET:
      bpf_process_manual_reset (peer);
      break;

    case BPF_EVENT_HOLD_EXP:
      bpf_register_notify (peer, BGP_NOTIFY_HOLD_ERR,
                           0, NULL, 0);
      bgp_peer_send_notify (peer);
      peer->v_connect = 0;
      BGP_TIMER_OFF (peer->t_connect);
      bpn_sock_cb_disconnect (peer);
      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_KEEPALIVE_EXP:
      bgp_peer_send_keepalive (peer);
      if (peer->v_holdtime && peer->v_keepalive)
        BGP_TIMER_ON (&BLG, peer->t_keepalive, peer, bpf_timer_keepalive,
                      peer->v_keepalive);
      break;

    case BPF_EVENT_TCP_CONN_CFM:
    case BPF_EVENT_TCP_CONN_ACKED:
    case BPF_EVENT_TCP_CONN_VALID:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_TRACK);
      break;

    case BPF_EVENT_TCP_CONN_INVALID:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_IGNORE);
      break;

    case BPF_EVENT_TCP_CONN_FAIL:
      bpn_sock_cb_reset (peer);
      bgp_peer_stop (peer);
      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_NOTIFY_VER_ERR:
      bpn_sock_cb_reset (peer);
      bgp_peer_stop (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_NOTIFY_VALID:
      bpf_process_notification (peer);
      bpn_sock_cb_reset (peer);
      bgp_peer_stop (peer);
      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_HDR_ERR:
    case BPF_EVENT_OPEN_ERR:
      bgp_peer_send_notify (peer);
      bgp_peer_stop (peer);
      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_OPEN_COLLISION_DUMP:
      bpf_register_notify (peer, BGP_NOTIFY_CEASE, BGP_NOTIFY_CEASE_CONN_COLLISION_RES, NULL, 0);
      bgp_peer_send_notify (peer);
      peer->bpf_conn_retry_count += 1;
      bgp_peer_stop (peer);
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_KEEPALIVE_VALID:
      BGP_TIMER_OFF (peer->t_holdtime);
      if (peer->v_holdtime)
        BGP_TIMER_ON (&BLG, peer->t_holdtime, peer,
                      bpf_timer_holdtime, peer->v_holdtime);
      peer->established++;
      peer->uptime = pal_time_current (NULL);
      bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_UP, "");
#ifdef HAVE_SNMP
      bgpSnmpNotifyEstablished (peer);
#endif /* HAVE_SNMP */
      bgp_peer_initial_announce (peer);
      bpf_change_state (peer, BPF_STATE_ESTABLISHED);
      break;
    case BPF_EVENT_CONN_RETRY_EXP:
    case BPF_EVENT_OPEN_VALID:
    case BPF_EVENT_UPDATE_VALID:
    case BPF_EVENT_UPDATE_ERR:
    case BPF_EVENT_ROUTE_REFRESH_VALID:
    case BPF_EVENT_ROUTE_REFRESH_ERR:
    case BPF_EVENT_DYNA_CAP_VALID:
    case BPF_EVENT_DYNA_CAP_ERR:
    case BPF_EVENT_ASORIG_EXP:
    case BPF_EVENT_ROUTEADV_EXP:
      bpf_register_notify (peer, BGP_NOTIFY_FSM_ERR, 0, NULL, 0);
      bgp_peer_send_notify (peer);
      bgp_peer_stop (peer);
      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
      if (peer->real_peer)
        bgp_peer_delete (peer);
      else
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                        bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_MANUAL_START:
    case BPF_EVENT_AUTO_START:
    case BPF_EVENT_MANUAL_START_TCP_PASSIVE:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring event %d in state %s",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));

      break;

    case BPF_EVENT_AUTO_START_POD:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE_POD:
    case BPF_EVENT_DELAY_OPEN_EXP:
    case BPF_EVENT_IDLE_HOLD_EXP:
    case BPF_EVENT_OPEN_VALID_DELAY_OPEN:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring Unsupported event %d "
                   "in state %s", peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));

      break;

    default:
      pal_assert (0);
      ret = -1;
    }

  return ret;
}

s_int32_t
bpf_action_established (struct bgp_peer *peer,
                        u_int32_t bpf_event)
{
  struct bgp_peer *clone_peer;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;
  
  ret = 0;

  switch (bpf_event)
    {
    case BPF_EVENT_MANUAL_STOP:
      bpf_register_notify (peer, BGP_NOTIFY_CEASE,
                           BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN,
                           NULL, 0);
      bgp_peer_send_notify (peer);
      bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                     "BGP Notification CEASE");
      peer->bpf_conn_retry_count = 0;
      peer->dropped++;

      bpf_change_state (peer, BPF_STATE_IDLE);
#ifdef HAVE_SNMP
      bgpSnmpNotifyBackwardTransition (peer);
#endif /* HAVE_SNMP */

      bgp_peer_stop (peer);
      if (peer->clones_list)
        LIST_LOOP (peer->clones_list, clone_peer, nn)
          BGP_PEER_FSM_EVENT_ADD (&BLG, clone_peer,
                                  BPF_EVENT_MANUAL_STOP);
      break;

    case BPF_EVENT_AUTO_STOP:
      bpf_register_notify (peer, BGP_NOTIFY_CEASE,
                           BGP_NOTIFY_CEASE_ADMIN_RESET, NULL, 0);
      bgp_peer_send_notify (peer);
      bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                     "BGP Notification CEASE");
      peer->bpf_conn_retry_count += 1;
      peer->dropped++;

      bpf_change_state (peer, BPF_STATE_IDLE);
#ifdef HAVE_SNMP
      bgpSnmpNotifyBackwardTransition (peer);
#endif /* HAVE_SNMP */
      bgp_peer_stop (peer);
      if (peer->clones_list)
        LIST_LOOP (peer->clones_list, clone_peer, nn)
          BGP_PEER_FSM_EVENT_ADD (&BLG, clone_peer, BPF_EVENT_AUTO_STOP);
      break;

    case BPF_EVENT_MANUAL_RESET:
      bpf_process_manual_reset (peer);
      break;

    case BPF_EVENT_HOLD_EXP:
      bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                     "Hold Timer Exipred");
      bpf_register_notify (peer, BGP_NOTIFY_HOLD_ERR,
                           0, NULL, 0);
      bgp_peer_send_notify (peer);
      peer->dropped++;

      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
#ifdef HAVE_SNMP
      bgpSnmpNotifyBackwardTransition (peer);
#endif /* HAVE_SNMP */
      bgp_peer_stop (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      break;

    case BPF_EVENT_KEEPALIVE_EXP:
      bgp_peer_send_keepalive (peer);
      if (peer->v_holdtime && peer->v_keepalive)
        BGP_TIMER_ON (&BLG, peer->t_keepalive, peer, bpf_timer_keepalive,
                      peer->v_keepalive);
      break;

    case BPF_EVENT_TCP_CONN_CFM:
    case BPF_EVENT_TCP_CONN_ACKED:
    case BPF_EVENT_TCP_CONN_VALID:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_TRACK);
      break;

    case BPF_EVENT_TCP_CONN_INVALID:
      bpf_process_inconn_req (peer, BGP_PEER_ICR_IGNORE);
      break;

    case BPF_EVENT_OPEN_COLLISION_DUMP:
      bpf_register_notify (peer, BGP_NOTIFY_CEASE, BGP_NOTIFY_CEASE_CONN_COLLISION_RES, NULL, 0);
      bgp_peer_send_notify (peer);
      peer->dropped++;

      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
#ifdef HAVE_SNMP
      bgpSnmpNotifyBackwardTransition (peer);
#endif /* HAVE_SNMP */
      bgp_peer_stop (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      break;

    case BPF_EVENT_TCP_CONN_FAIL:
      peer->dropped++;

      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
#ifdef HAVE_SNMP
      bgpSnmpNotifyBackwardTransition (peer);
#endif /* HAVE_SNMP */
      bpn_sock_cb_reset (peer);
      bgp_peer_stop (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                     "Peer closed the session");
      break;

    case BPF_EVENT_NOTIFY_VER_ERR:
    case BPF_EVENT_NOTIFY_VALID:
      bpf_process_notification (peer);
      bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                     "BGP Notification CEASE");
      peer->dropped++;

      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
#ifdef HAVE_SNMP
      bgpSnmpNotifyBackwardTransition (peer);
#endif /* HAVE_SNMP */
      bpn_sock_cb_reset (peer);
      bgp_peer_stop (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      break;

    case BPF_EVENT_ASORIG_EXP:
      for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
        for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
          if (! CHECK_FLAG (peer->af_sflags [baai][bsai],
                            PEER_STATUS_AF_ASORIG_ROUTE_ADV)
              && (FIFO_HEAD (&peer->asorig_adv_list [baai][bsai]->unreach)
                  || FIFO_HEAD (&peer->asorig_adv_list [baai][bsai]->reach)))
            {
              SET_FLAG (peer->af_sflags [baai][bsai],
                        PEER_STATUS_AF_ASORIG_ROUTE_ADV);
              
              /* Normally, a call to bgp_peer_send_update() is made when
               * minimum router-advertisement interval expires. But set 
               * route-expiry event now if router advertisement timer is set 
               * to zero.
               */ 
              if (CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE))
                BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_ROUTEADV_EXP); 
            }

      if (peer->v_asorig)
        BGP_TIMER_ON (&BLG, peer->t_asorig, peer,
                      bpf_timer_asorig, peer->v_asorig);
      break;

    case BPF_EVENT_ROUTEADV_EXP:
      bgp_peer_send_update (peer, PAL_FALSE);
      break;

    case BPF_EVENT_KEEPALIVE_VALID:
      BGP_TIMER_OFF (peer->t_holdtime);
      if (peer->v_holdtime)
        BGP_TIMER_ON (&BLG, peer->t_holdtime, peer,
                      bpf_timer_holdtime, peer->v_holdtime);
      
      if (peer->bgp->conv_complete != PAL_TRUE)
        if (!CHECK_FLAG (peer->sflags, PEER_STATUS_CONV_FOR_IGP)) 
          {
            SET_FLAG (peer->sflags, PEER_STATUS_CONV_FOR_IGP);
            peer->bgp->neighbors_converged++;
            bgp_check_peer_convergence (peer->bgp);
          }
      break;

    case BPF_EVENT_UPDATE_VALID:
      BGP_TIMER_OFF (peer->t_holdtime);
      if (peer->v_holdtime)
        BGP_TIMER_ON (&BLG, peer->t_holdtime, peer,
                      bpf_timer_holdtime, peer->v_holdtime);
      bpf_process_update (peer);
      break;

    case BPF_EVENT_HDR_ERR:
    case BPF_EVENT_UPDATE_ERR:
    case BPF_EVENT_ROUTE_REFRESH_ERR:
    case BPF_EVENT_DYNA_CAP_ERR:
      bgp_peer_send_notify (peer);
      peer->dropped++;

      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
#ifdef HAVE_SNMP
      bgpSnmpNotifyBackwardTransition (peer);
#endif /* HAVE_SNMP */
      bgp_peer_stop (peer);
      if (!CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
        {
          peer->v_auto_start = BGP_DEFAULT_AUTO_START;
          BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
        }
      break;

    case BPF_EVENT_ROUTE_REFRESH_VALID:
      bpf_process_route_refresh (peer);
      break;

    case BPF_EVENT_DYNA_CAP_VALID:
      bpf_process_dyna_cap (peer);
      break;

    case BPF_EVENT_CONN_RETRY_EXP:
    case BPF_EVENT_OPEN_ERR:
    case BPF_EVENT_OPEN_VALID:
      bpf_register_notify (peer, BGP_NOTIFY_FSM_ERR, 0, NULL, 0);
      bgp_peer_send_notify (peer);
      bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                     "BGP Notification FSM-ERR");
      peer->dropped++;

      peer->bpf_conn_retry_count += 1;
      bpf_change_state (peer, BPF_STATE_IDLE);
#ifdef HAVE_SNMP
      bgpSnmpNotifyBackwardTransition (peer);
#endif /* HAVE_SNMP */
      bgp_peer_stop (peer);
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      break;

    case BPF_EVENT_MANUAL_START:
    case BPF_EVENT_AUTO_START:
    case BPF_EVENT_MANUAL_START_TCP_PASSIVE:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring event %d in state %s",
                   peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));

      break;

    case BPF_EVENT_AUTO_START_POD:
    case BPF_EVENT_AUTO_START_TCP_PASSIVE_POD:
    case BPF_EVENT_DELAY_OPEN_EXP:
    case BPF_EVENT_IDLE_HOLD_EXP:
    case BPF_EVENT_OPEN_VALID_DELAY_OPEN:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Ignoring Unsupported event %d "
                   "in state %s", peer->host, BGP_PEER_DIR_STR (peer),
                   bpf_event, BGP_PEER_FSM_STATE_STR (peer->bpf_state));

      break;

    default:
      pal_assert (0);
      ret = -1;
    }

  return ret;
}

/* Change BGP Peer FSM State */
void
bpf_change_state (struct bgp_peer *peer,
                  u_int32_t bpf_state)
{
#ifdef HAVE_BGP_DUMP
  bgp_dump_state (peer, peer->bpf_state, bpf_state);
#endif /* HAVE_BGP_DUMP */

  if (BGP_DEBUG (fsm, FSM))
    zlog_info (&BLG, "%s-%s [FSM] State Change: %s(%d)->%s(%d)",
               peer->host, BGP_PEER_DIR_STR (peer),
               BGP_PEER_FSM_STATE_STR (peer->bpf_state),
               peer->bpf_state, BGP_PEER_FSM_STATE_STR (bpf_state),
               bpf_state);

  /* Change to new state */
  peer->bpf_state = bpf_state;
}

/* If 'peer' is an Incoming one, transform it as Real-Peer */
void
bpf_transform_incoming2real_peer (struct bgp_peer **peer_pp)
{
  struct bgp_peer *real_peer;
  struct bgp_peer *peer;
  u_int32_t baai;
  u_int32_t bsai;

  peer = *peer_pp;
  real_peer = peer->real_peer;

  /* Transform Incoming-Peer into Real-Peer */
  if (real_peer)
    {
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Transforming Incoming2RealPeer...",
                   peer->host, BGP_PEER_DIR_STR (peer));

      /* Stop operation of Real-Peer */
      bpf_register_notify (real_peer, BGP_NOTIFY_CEASE, BGP_NOTIFY_CEASE_ADMIN_RESET, NULL, 0);
      bgp_peer_send_notify (real_peer);
      bgp_peer_stop (real_peer);

      /* Dissociate Socket-CB of Real-Peer */
      stream_sock_cb_free (real_peer->sock_cb, &BLG);

      /* Transfer Socket-CB from Incoming-Peer to Real-Peer */
      SSOCK_CB_SET_OWNER (peer->sock_cb, real_peer);
      real_peer->sock_cb = peer->sock_cb;
      real_peer->su_local = peer->su_local;
      real_peer->su_remote = peer->su_remote;
      real_peer->nexthop = peer->nexthop;
      real_peer->shared_network = peer->shared_network;
      peer->sock_cb = NULL;

      /* Transfer capability advertise information */
      for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
        for (bsai = BSAI_UNICAST ; bsai < BSAI_MAX ; bsai++)
          {
            real_peer->af_cap [baai][bsai] = peer->af_cap [baai][bsai];
            real_peer->afc_adv [baai][bsai] = peer->afc_adv [baai][bsai];
            real_peer->afc_recv [baai][bsai] = peer->afc_recv [baai][bsai];
            real_peer->afc_nego [baai][bsai] = peer->afc_nego [baai][bsai];
          }

      /* Transfer negotiated timer values */
      real_peer->v_auto_start = peer->v_auto_start;
      real_peer->v_connect = peer->v_connect;
      real_peer->v_holdtime = peer->v_holdtime;
      real_peer->v_keepalive = peer->v_keepalive;
      real_peer->v_asorig = peer->v_asorig;
      real_peer->v_routeadv = peer->v_routeadv;

      /* Transfer additional information */
      real_peer->holdtime = peer->holdtime;
      real_peer->keepalive = peer->keepalive;
      real_peer->remote_id = peer->remote_id;
      real_peer->cap = peer->cap;

      /* Transfer FSM State */
      real_peer->bpf_state = peer->bpf_state;

      /* Delete the Incoming Peer */
      bgp_peer_delete (peer);

      /* Complete the transformation */
      *peer_pp = real_peer;
    }

  return;
}

/* BGP Peer FSM generic timer-jitter generator */
u_int32_t
bpf_timer_generate_jitter (u_int32_t time)
{
  u_int32_t jittered_time;
  u_int32_t rand_val;

  rand_val = 75 + (u_int32_t)(25.0 * pal_rand()/RAND_MAX);

  jittered_time = (time * rand_val / 100);

  return (jittered_time > 1 ? jittered_time : 1);
}

/* BGP Peer FSM auto-start timer */
s_int32_t
bpf_timer_auto_start (struct thread *t_timer)
{
  struct lib_globals *blg;
  struct bgp_peer *peer;
  s_int32_t ret;

  ret = 0;

  /* Obtain the BGP Lib Global pointer */
  blg = THREAD_GLOB (t_timer);

  /* Sanity check */
  if (! blg || &BLG != blg)
    {
      ret = -1;
      goto EXIT;
    }


  /* Obtain the Peer structure */
  peer = THREAD_ARG (t_timer);


  /* Sanity check */
  if (! peer)
    {
      zlog_err (&BLG, "[FSM] Auto-Start Timer: Invalid Peer(%X)", peer);
      ret = -1;
      goto EXIT;
    }


  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  if (BGP_DEBUG (fsm, FSM))
    zlog_info (&BLG, "%s-%s [FSM] Auto-Start Timer Expiry",
               peer->host, BGP_PEER_DIR_STR (peer));

  peer->t_auto_start = NULL;

  /* Post the Timer Expiry FSM Event */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_PASSIVE))
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_AUTO_START_TCP_PASSIVE);
  else
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_AUTO_START);

EXIT:

  return ret;
}

/* BGP Peer FSM connect-retry timer */
s_int32_t
bpf_timer_conn_retry (struct thread *t_timer)
{
  struct lib_globals *blg;
  struct bgp_peer *peer;
  s_int32_t ret;

  ret = 0;

  /* Obtain the BGP Lib Global pointer */
  blg = THREAD_GLOB (t_timer);

  /* Sanity check */
  if (! blg || &BLG != blg)
    {
      ret = -1;
      goto EXIT;
    }

  /* Obtain the Peer structure */
  peer = THREAD_ARG (t_timer);

  /* Sanity check */
  if (! peer)
    {
      zlog_err (&BLG, "[FSM] Conn-Retry Timer: Invalid Peer(%X)", peer);
      ret = -1;
      goto EXIT;
    }

  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  if (BGP_DEBUG (fsm, FSM))
    zlog_info (&BLG, "%s-%s [FSM] Conn-Retry Timer Expiry",
               peer->host, BGP_PEER_DIR_STR (peer));

  peer->t_connect = NULL;

  /* Post the Timer Expiry FSM Event */
  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_CONN_RETRY_EXP);

EXIT:

  return ret;
}

/* BGP Peer FSM Hold-time timer */
s_int32_t
bpf_timer_holdtime (struct thread *t_timer)
{
  struct lib_globals *blg;
  struct bgp_peer *peer;
  s_int32_t ret;

  ret = 0;

  /* Obtain the BGP Lib Global pointer */
  blg = THREAD_GLOB (t_timer);

  /* Sanity check */
  if (! blg || blg != &BLG)
    {
      ret = -1;
      goto EXIT;
    }

  /* Obtain the Peer structure */
  peer = THREAD_ARG (t_timer);

  /* Sanity check */
  if (! peer)
    {
      zlog_err (&BLG, "[FSM] Hold-Timer: Invalid Peer(%X)", peer);
      ret = -1;
      goto EXIT;
    }

  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  if (BGP_DEBUG (fsm, FSM))
    zlog_info (&BLG, "%s-%s [FSM] Hold-Timer Expiry",
               peer->host, BGP_PEER_DIR_STR (peer));

  peer->t_holdtime = NULL;

  /* Post the Timer Expiry FSM Event */
  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_HOLD_EXP);

EXIT:

  return ret;
}

/* BGP Peer FSM Keep-alive timer */
s_int32_t
bpf_timer_keepalive (struct thread *t_timer)
{
  struct lib_globals *blg;
  struct bgp_peer *peer;
  s_int32_t ret;

  ret = 0;

  /* Obtain the BGP Lib Global pointer */
  blg = THREAD_GLOB (t_timer);

  /* Sanity check */
  if (! blg || blg != &BLG)
    {
      ret = -1;
      goto EXIT;
    }

  /* Obtain the Peer structure */
  peer = THREAD_ARG (t_timer);

  /* Sanity check */
  if (! peer)
    {
      zlog_err (&BLG, "[FSM] Keep-alive-Timer: Invalid Peer(%X)", peer);
      ret = -1;
      goto EXIT;
    }

  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);

  if (BGP_DEBUG (fsm, FSM))
    zlog_info (&BLG, "%s-%s [FSM] Keep-alive-Timer Expiry",
               peer->host, BGP_PEER_DIR_STR (peer));

  peer->t_keepalive = NULL;

  /* Post the Timer Expiry FSM Event */
  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_KEEPALIVE_EXP);

EXIT:

  return ret;
}

/* BGP Peer FSM AS-Origination timer */
s_int32_t
bpf_timer_asorig (struct thread *t_timer)
{
  struct lib_globals *blg;
  struct bgp_peer *peer;
  s_int32_t ret;

  ret = 0;

  /* Obtain the BGP Lib Global pointer */
  blg = THREAD_GLOB (t_timer);

  /* Sanity check */
  if (! blg || blg != &BLG)
    {
      ret = -1;
      goto EXIT;
    }

  /* Obtain the Peer structure */
  peer = THREAD_ARG (t_timer);

  /* Sanity check */
  if (! peer)
    {
      zlog_err (&BLG, "[FSM] AS-Origination-Timer: Invalid Peer(%X)", peer);
      ret = -1;
      goto EXIT;
    }

  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);
  
  if (BGP_DEBUG (fsm, FSM))
    zlog_info (&BLG, "%s-%s [FSM] AS-Origination Timer Expiry",
               peer->host, BGP_PEER_DIR_STR (peer));

  peer->t_asorig = NULL;

  /* Post the Timer Expiry FSM Event */
  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_ASORIG_EXP);

EXIT:

  return ret;
}

/* BGP Peer FSM Route-Advertisement timer */
s_int32_t
bpf_timer_routeadv (struct thread *t_timer)
{
  struct lib_globals *blg;
  struct bgp_peer *peer;
  s_int32_t ret;

  ret = 0;

  /* Obtain the BGP Lib Global pointer */
  blg = THREAD_GLOB (t_timer);

  /* Sanity check */
  if (! blg || blg != &BLG)
    {
      ret = -1;
      goto EXIT;
    }

  /* Obtain the Peer structure */
  peer = THREAD_ARG (t_timer);

  /* Sanity check */
  if (! peer)
    {
      zlog_err (&BLG, "[FSM] Routeadv Timer: Invalid Peer(%X)", peer);
      ret = -1;
      goto EXIT;
    }

  BGP_SET_VR_CONTEXT (&BLG, peer->bgp->owning_bvr);
  
  if (BGP_DEBUG (fsm, FSM))
    zlog_info (&BLG, "%s-%s [FSM] Routeadv Timer Expiry)",
               peer->host, BGP_PEER_DIR_STR (peer));

  peer->t_routeadv = NULL;

  /* Post the Timer Expiry FSM Event */
  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_ROUTEADV_EXP);

EXIT:

  return ret;
}

/* RFC 4271 Sec6.8: Connection collision detection */
s_int32_t
bpf_collision_detect_check (struct bgp_peer *peer,
                            struct pal_in4_addr remote_id)
{
  /*
   * 1. The BGP Identifier of the local system is compared to the BGP
   * Identifier of the remote system (as specified in the OPEN mes-
   * sage).  Comparing BGP Identifiers is done by converting them to
   * host byte order and treating them as (4-octet long) unsigned inte-
   * gers.
   */

  if (pal_ntoh32 (peer->local_id.s_addr) < pal_ntoh32 (remote_id.s_addr))
    {
      /*
       * 2. If the value of the local BGP Identifier is less than the
       * remote one, the local system closes the BGP connection that
       * already exists (the one that is already in the OpenConfirm state),
       * and accepts the BGP connection initiated by the remote system.
       */

      return 0;
    }

  /*
   * 3. Otherwise, the local system closes newly created BGP connection
   * (the one associated with the newly received OPEN message), and
   * continues to use the existing one (the one that is already in the
   * OpenConfirm state).
   */

  return -1;
}

s_int32_t
bpf_collision_detect (struct bgp_peer *new_peer)
{
  struct bgp_peer *real_peer;
  struct bgp_peer *peer;
  struct listnode *nn;
  s_int32_t ret;

  real_peer = new_peer;
  ret = 0;

  if (new_peer->real_peer)
    real_peer = new_peer->real_peer;

  /* First check against the other Incoming Peers */
  LIST_LOOP (real_peer->clones_list, peer, nn)
    {
      if (peer != new_peer && peer->bpf_state == BPF_STATE_OPEN_CFM)
        {
          ret = bpf_collision_detect_check (peer, new_peer->remote_id);

          /* If ret is -1, return ERROR and 'new_peer' gets deleted */
          if (ret < 0)
            return ret;
          else /* Post OPEN-Collision-dump to 'peer' */
            BGP_PEER_FSM_EVENT_ADD (&BLG, peer,
                                    BPF_EVENT_OPEN_COLLISION_DUMP);
        }
    }

  /* Now check against the Real-Peer */
  if (real_peer != new_peer)
    {
      if (real_peer->bpf_state == BPF_STATE_OPEN_CFM
          || real_peer->bpf_state == BPF_STATE_OPEN_SENT
          || (real_peer->bpf_state == BPF_STATE_ESTABLISHED
              && (CHECK_FLAG (real_peer->flags,
                              PEER_FLAG_COLLIDE_ESTABLISHED))))
        {
          ret = bpf_collision_detect_check (real_peer, new_peer->remote_id);

          /* If ret is -1, return ERROR and 'new_peer' gets deleted */
          if (ret < 0)
            return ret;
          else /* Post OPEN-Collision-dump to 'real_peer' */
            BGP_PEER_FSM_EVENT_ADD (&BLG, real_peer,
                                    BPF_EVENT_OPEN_COLLISION_DUMP);
        }
      else if (real_peer->bpf_state == BPF_STATE_ESTABLISHED)
        {
          /* Return ERROR and 'new_peer' gets deleted */
          return -1;
        }
    }

  return 0;
}

s_int32_t
bpf_process_open (struct bgp_peer *peer)
{
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;

  ret = 0;

  if (! peer)
    {
      ret = -1;
      goto EXIT;
    }

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        /* MP Capability Information Processing */
        if (peer->afc [baai][bsai]
            && (peer->afc_recv [baai][bsai]
                || CHECK_FLAG (peer->cap, PEER_CAP_NONE_RCV)))
          peer->afc_nego [baai][bsai] = 1;

        /* Override with Configured capabilities */
        if (CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
          peer->afc_nego [baai][bsai] = peer->afc [baai][bsai];
      }

EXIT:

  return ret;
}

s_int32_t
bpf_process_update (struct bgp_peer *peer)
{
  struct bgp_dec_update_info *bdui;
  s_int32_t ret;

  ret = 0;

  if (! peer || FIFO_EMPTY (&peer->bdui_fifo))
    {
      ret = -1;
      goto EXIT;
    }

  /* Dequeue One UPDATE-INFO for processing */
  bdui = (struct bgp_dec_update_info *) FIFO_HEAD (&peer->bdui_fifo);
  FIFO_DEL (&bdui->ui_fifo);

  if (peer->afc [BAAI_IP][BSAI_UNICAST])
    {
      /* Process Withdrawn IPv4-Unicast NLRIs */
      if (bdui->ip_withdrawn.ni_present == PAL_TRUE
          && bdui->ip_withdrawn.ni_length)
        {
          bgp_peer_process_nlri (peer, NULL, &bdui->ip_withdrawn);
          bdui->ip_withdrawn.ni_present = PAL_FALSE;
        }

      /* Process Advertised IPv4-Unicast NLRIs */
      if (bdui->ip_advertised.ni_present == PAL_TRUE
          && bdui->ip_advertised.ni_length)
        {
          bgp_peer_process_nlri (peer, bdui->ui_attr,
                                 &bdui->ip_advertised);
          bdui->ip_advertised.ni_present = PAL_FALSE;
        }
    }

  if (bdui->mp_unreach.ni_present == PAL_TRUE
      && ! bdui->mp_unreach.ni_length
      && bdui->mp_reach.ni_present == PAL_FALSE)
    {
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] Update: AFI-SAFI:%d-%d End-Of-Rib"
                   "Marker Received", peer->host, BGP_PEER_DIR_STR (peer),
                   bdui->mp_unreach.ni_afi, bdui->mp_unreach.ni_safi);

      bdui->mp_unreach.ni_present = PAL_FALSE;
    }
  else /* Process MP Reach and Unreach NLRIs */
    {
      if (bdui->mp_unreach.ni_present == PAL_TRUE
          && bdui->mp_unreach.ni_length
          && peer->afc [BGP_AFI2BAAI (bdui->mp_unreach.ni_afi)]
                       [BGP_SAFI2BSAI (bdui->mp_unreach.ni_safi)])
        {
          bgp_peer_process_nlri (peer, NULL, &bdui->mp_unreach);
          bdui->mp_unreach.ni_present = PAL_FALSE;
        }

      if (bdui->mp_reach.ni_present == PAL_TRUE
          && bdui->mp_reach.ni_length
          && peer->afc [BGP_AFI2BAAI (bdui->mp_reach.ni_afi)]
                       [BGP_SAFI2BSAI (bdui->mp_reach.ni_safi)])
        {
          bgp_peer_process_nlri (peer, bdui->ui_attr, &bdui->mp_reach);
          bdui->mp_reach.ni_present = PAL_FALSE;
        }
    }

    {
      /* Unintern structures which were interned during ATTR decoding */
      if (bdui->ui_attr->aspath)
        aspath_unintern (bdui->ui_attr->aspath);
#ifdef HAVE_EXT_CAP_ASN
      if (bdui->ui_attr->aspath4B)
        aspath4B_unintern (bdui->ui_attr->aspath4B);
      if (bdui->ui_attr->as4path)
        as4path_unintern (bdui->ui_attr->as4path);
#endif /* HAVE_EXT_CAP_ASN */ 
      if (bdui->ui_attr->community)
        community_unintern (bdui->ui_attr->community);
      if (bdui->ui_attr->ecommunity)
        ecommunity_unintern (bdui->ui_attr->ecommunity);
      if (bdui->ui_attr->cluster)
        cluster_unintern (bdui->ui_attr->cluster);
      if (bdui->ui_attr->transit)
        transit_unintern (bdui->ui_attr->transit);

      /* Free the BDUI */
      XFREE (MTYPE_ATTR, bdui->ui_attr);
      XFREE (MTYPE_TMP, bdui);
    }

EXIT:

  return ret;
}

s_int32_t
bpf_process_notification (struct bgp_peer *peer)
{
  s_int32_t ret;

  ret = 0;

  if (! peer || ! peer->notify_info)
    {
      ret = -1;
      goto EXIT;
    }

  /*
   * Check for Notify with Unsupported Optional Parameter and fallback
   * to open without the capability option. But this done in bgp_stop.
   * We just mark it here to avoid changing the FSM tables
   */
  if (peer->notify_info->not_err_code == BGP_NOTIFY_OPEN_ERR
      && peer->notify_info->not_err_sub_code == BGP_NOTIFY_OPEN_UNSUP_PARAM)
    UNSET_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

  /*
   * Check for Notify with Unsupported Capability and fallback to
   * OPEN without the capability.
   */
  if (peer->notify_info->not_err_code == BGP_NOTIFY_OPEN_ERR
      && peer->notify_info->not_err_sub_code == BGP_NOTIFY_OPEN_UNSUP_CAPBL)
    SET_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

  if (BGP_DEBUG (fsm, FSM))
    zlog_info (&BLG, "%s-%s [FSM] BGP Notification received ",
               peer->host, BGP_PEER_DIR_STR (peer));

EXIT:

  return ret;
}

s_int32_t
bpf_process_route_refresh (struct bgp_peer *peer)
{
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;

  ret = 0;

  if (! peer)
    {
      ret = -1;
      goto EXIT;
    }

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      /* Announce Routes if Route-Announcement is not locked */
      if (CHECK_FLAG (peer->af_sflags [baai][bsai],
                      PEER_STATUS_AF_ROUTE_REFRESH_RCVD)
          && ! CHECK_FLAG (peer->af_sflags [baai][bsai],
                           PEER_STATUS_ORF_WAIT_REFRESH))
        {
          bgp_announce_route (peer, BGP_BAAI2AFI (baai),
                              BGP_BSAI2SAFI (bsai));

          UNSET_FLAG (peer->af_sflags [baai][bsai],
                      PEER_STATUS_AF_ROUTE_REFRESH_RCVD);
        }

EXIT:

  return ret;
}

s_int32_t
bpf_process_dyna_cap (struct bgp_peer *peer)
{
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;

  ret = 0;

  if (! peer)
    {
      ret = -1;
      goto EXIT;
    }

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        /* MP Capability Information Processing */
        if (peer->afc [baai][bsai]
            && peer->afc_recv [baai][bsai]
            && ! peer->afc_nego [baai][bsai])
          {
            peer->afc_nego [baai][bsai] = 1;
            bgp_announce_route (peer, BGP_BAAI2AFI (baai),
                                BGP_BSAI2SAFI (bsai));
          }

        if (peer->afc [baai][bsai]
            && ! peer->afc_recv [baai][bsai]
            && peer->afc_nego [baai][bsai])
          {
            peer->afc_nego [baai][bsai] = 0;
            bgp_clear_route (peer, BGP_BAAI2AFI (baai),
                             BGP_BSAI2SAFI (bsai));
          }
      }

EXIT:

  return ret;
}

/* Process Incoming Connection Request */
s_int32_t
bpf_process_inconn_req (struct bgp_peer *peer,
                        enum bgp_peer_icr_act icr_act)
{
  struct bgp_peer_inconn_req *peer_icr;
  struct bgp_peer *clone_peer;
  s_int32_t ret;

  peer_icr = NULL;
  ret = 0;

  if (! peer || FIFO_EMPTY (&peer->bicr_fifo))
    {
      ret = -1;
      goto EXIT;
    }

  /* Dequeue One Incoming Connection Req. for processing */
  peer_icr = (struct bgp_peer_inconn_req *) FIFO_HEAD (&peer->bicr_fifo);
  FIFO_DEL (&peer_icr->icr_fifo);

  /* Process the ICR */
  switch (icr_act)
    {
    case BGP_PEER_ICR_IGNORE:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] InConnReq: Ignoring...",
                   peer->host, BGP_PEER_DIR_STR (peer));

      SSOCK_FD_CLOSE (&BLG, peer_icr->icr_sock);
      break;

    case BGP_PEER_ICR_ACCEPT:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] InConnReq: Accepting...",
                   peer->host, BGP_PEER_DIR_STR (peer));

      bpn_sock_cb_disconnect (peer);

      ret = bpn_sock_set_opt (peer, peer_icr->icr_sock, PAL_FALSE);
      if (ret != 0)
        {
          zlog_err (&BLG, "%s-%s [FSM] InConnReq: SetSockOpt Failed on "
                    "accepted Sock-FD (%d), closing connection...",
                    peer->host, BGP_PEER_DIR_STR (peer),
                    peer_icr->icr_sock);

          SSOCK_FD_CLOSE (&BLG, peer_icr->icr_sock);

          BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_TCP_CONN_FAIL);

          ret = -1;
          goto EXIT;
        }

      ret = stream_sock_cb_accept (peer->sock_cb,
                                   peer_icr->icr_sock, &BLG);
      if (ret < 0)
        {
          zlog_err (&BLG, "%s-%s [FSM] InConnReq: Sock-CB Accept Failed "
                    "for Sock-FD (%d)", peer->host,
                    BGP_PEER_DIR_STR (peer), peer_icr->icr_sock);

          SSOCK_FD_CLOSE (&BLG, peer_icr->icr_sock);

          BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_TCP_CONN_FAIL);

          ret = -1;
          goto EXIT;
        }
      break;

    case BGP_PEER_ICR_TRACK:
      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] InConnReq: Tracking...",
                   peer->host, BGP_PEER_DIR_STR (peer));

      clone_peer = bgp_peer_create_clone (peer);
      if (! clone_peer)
        {
          zlog_err (&BLG, "%s-%s [FSM] InConnReq: Peer Cloning Failed",
                    peer->host, BGP_PEER_DIR_STR (peer));

          SSOCK_FD_CLOSE (&BLG, peer_icr->icr_sock);

          ret = -1;
          goto EXIT;
        }

      ret = bpn_sock_set_opt (clone_peer, peer_icr->icr_sock,
                              PAL_FALSE);
      if (ret != 0)
        {
          zlog_err (&BLG, "%s-%s [FSM] InConnReq: SetSockOpt Failed on "
                    "Clone, deleting Clone...",
                    clone_peer->host, BGP_PEER_DIR_STR (clone_peer));

          SSOCK_FD_CLOSE (&BLG, peer_icr->icr_sock);

          bgp_peer_delete (clone_peer);

          ret = -1;
          goto EXIT;
        }

      if (BGP_DEBUG (fsm, FSM))
        zlog_info (&BLG, "%s-%s [FSM] InConnReq: Clone creation successful",
                   clone_peer->host, BGP_PEER_DIR_STR (clone_peer));

      ret = stream_sock_cb_accept (clone_peer->sock_cb,
                                   peer_icr->icr_sock, &BLG);
      if (ret < 0)
        {
          zlog_err (&BLG, "%s-%s [FSM] InConnReq: Sock-CB Accept Failed "
                    "for Sock-FD (%d)", peer->host,
                    BGP_PEER_DIR_STR (peer), peer_icr->icr_sock);

          SSOCK_FD_CLOSE (&BLG, peer_icr->icr_sock);

          bgp_peer_delete (clone_peer);

          ret = -1;
          goto EXIT;
        }
      break;
    }

EXIT:

  /* Free the ICR */
  if (peer_icr)
    XFREE (MTYPE_TMP, peer_icr);

  return ret;
}

s_int32_t
bpf_process_manual_reset (struct bgp_peer *peer)
{
  struct bgp_peer *clone_peer;
  struct listnode *nn;
  bool_t send_notify;
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;

  send_notify = PAL_TRUE;
  ret = 0;

  /* Event Valid ONLY for Configured Peers */
  if (peer->real_peer)
    {
      ret = -1;
      goto EXIT;
    }

  if (CHECK_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_IN))
    {
      if (CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_OLD_RCV)
          || CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV))
        {
          bgp_peer_send_route_refresh (peer, AFI_IP, SAFI_UNICAST,
                                       0, 0, 0);

          send_notify = PAL_FALSE;
        }
      else
        send_notify = PAL_TRUE;

      UNSET_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_IN);
    }
  else if (CHECK_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_OUT))
    {
      bgp_announce_route (peer, AFI_IP, SAFI_UNICAST);

      send_notify = PAL_FALSE;

      UNSET_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_OUT);
    }
  else if (CHECK_FLAG (peer->sflags, PEER_STATUS_CAP_ROUTE_REFRESH))
    {
      if (CHECK_FLAG (peer->flags, PEER_FLAG_NO_ROUTE_REFRESH_CAP)
          && ! CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_ADV))
        {
          SET_FLAG (peer->cap, PEER_CAP_REFRESH_ADV);

          if (CHECK_FLAG (peer->flags, PEER_FLAG_DYNAMIC_CAPABILITY)
              && CHECK_FLAG (peer->cap, PEER_CAP_DYNAMIC_ADV)
              && CHECK_FLAG (peer->cap, PEER_CAP_DYNAMIC_RCV))
            {
              bgp_peer_send_dyna_cap (peer, AFI_IP, SAFI_UNICAST,
                                      BGP_CAPABILITY_CODE_REFRESH,
                                      BGP_CAPABILITY_ACTION_SET);

              send_notify = PAL_FALSE;
            }
        }
      else if (! CHECK_FLAG (peer->flags, PEER_FLAG_NO_ROUTE_REFRESH_CAP)
               && CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_ADV))
        {
          UNSET_FLAG (peer->cap, PEER_CAP_REFRESH_ADV);

          if (CHECK_FLAG (peer->flags, PEER_FLAG_DYNAMIC_CAPABILITY)
              && CHECK_FLAG (peer->cap, PEER_CAP_DYNAMIC_ADV)
              && CHECK_FLAG (peer->cap, PEER_CAP_DYNAMIC_RCV))
            {
              bgp_peer_send_dyna_cap (peer, AFI_IP, SAFI_UNICAST,
                                      BGP_CAPABILITY_CODE_REFRESH,
                                      BGP_CAPABILITY_ACTION_UNSET);

              send_notify = PAL_FALSE;
            }
        }

      UNSET_FLAG (peer->sflags, PEER_STATUS_CAP_ROUTE_REFRESH);
    }

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        if (CHECK_FLAG (peer->af_sflags [baai][bsai],
                        PEER_STATUS_AF_SOFT_RESET_IN))
          {
            if (CHECK_FLAG (peer->af_cap [baai][bsai],
                            PEER_CAP_REFRESH_OLD_RCV)
                || CHECK_FLAG (peer->af_cap [baai][bsai],
                               PEER_CAP_REFRESH_NEW_RCV))
              {
                bgp_peer_send_route_refresh (peer,
                                             BGP_BAAI2AFI (baai),
                                             BGP_BSAI2SAFI (bsai),
                                             0, 0, 0);
                send_notify = PAL_FALSE;
              }
            else
              send_notify = PAL_TRUE;

            UNSET_FLAG (peer->af_sflags [baai][bsai],
                        PEER_STATUS_AF_SOFT_RESET_IN);
          }
        else if (CHECK_FLAG (peer->af_sflags [baai][bsai],
                             PEER_STATUS_AF_SOFT_RESET_OUT))
          {
            bgp_announce_route (peer, BGP_BAAI2AFI (baai),
                                BGP_BSAI2SAFI (bsai));
            send_notify = PAL_FALSE;

            UNSET_FLAG (peer->af_sflags [baai][bsai],
                        PEER_STATUS_AF_SOFT_RESET_OUT);
          }
        else if (CHECK_FLAG (peer->af_sflags [baai][bsai],
                             PEER_STATUS_AF_ROUTE_REFRESH_SEND))
          {
            bgp_peer_send_route_refresh (peer,
                                         BGP_BAAI2AFI (baai),
                                         BGP_BSAI2SAFI (bsai),
                                         0, 0, 0);

            send_notify = PAL_FALSE;

            UNSET_FLAG (peer->af_sflags [baai][bsai],
                        PEER_STATUS_AF_ROUTE_REFRESH_SEND);
          }
        else if (CHECK_FLAG (peer->af_sflags [baai][bsai],
                             PEER_STATUS_AF_DEFAULT_ORIGINATE))
          {
            bgp_peer_default_originate (peer,
                                        BGP_BAAI2AFI (baai),
                                        BGP_BSAI2SAFI (bsai),
                                        CHECK_FLAG
                                        (peer->af_flags [baai][bsai],
                                         PEER_FLAG_DEFAULT_ORIGINATE) ?
                                        PAL_FALSE : PAL_TRUE);

            send_notify = PAL_FALSE;

            UNSET_FLAG (peer->af_sflags [baai][bsai],
                        PEER_STATUS_AF_DEFAULT_ORIGINATE);
          }

        if (! CHECK_FLAG (peer->flags, PEER_FLAG_DYNAMIC_CAPABILITY)
            || ! CHECK_FLAG (peer->cap, PEER_CAP_DYNAMIC_ADV)
            || ! CHECK_FLAG (peer->cap, PEER_CAP_DYNAMIC_RCV))
          continue;

        /* MP Capability Modification Handling */
        if (peer->afc [baai][bsai]
            && ! peer->afc_adv [baai][bsai])
          {
            peer->afc_adv [baai][bsai] = 1;

            bgp_peer_send_dyna_cap (peer,
                                    BGP_BAAI2AFI (baai),
                                    BGP_BSAI2SAFI (bsai),
                                    BGP_CAPABILITY_CODE_MP,
                                    BGP_CAPABILITY_ACTION_SET);

            if (peer->afc_recv [baai][bsai])
              {
                peer->afc_nego [baai][bsai] = 1;

                bgp_announce_route (peer,
                                    BGP_BAAI2AFI (baai),
                                    BGP_BSAI2SAFI (bsai));
              }

            send_notify = PAL_FALSE;
          }
        else if (! peer->afc [baai][bsai]
                 && peer->afc_adv [baai][bsai])
          {
            peer->afc_adv [baai][bsai] = 0;

            bgp_peer_send_dyna_cap (peer,
                                    BGP_BAAI2AFI (baai),
                                    BGP_BSAI2SAFI (bsai),
                                    BGP_CAPABILITY_CODE_MP,
                                    BGP_CAPABILITY_ACTION_UNSET);

            if (peer->afc_recv [baai][bsai])
              {
                peer->afc_nego [baai][bsai] = 0;

                bgp_clear_route (peer,
                                 BGP_BAAI2AFI (baai),
                                 BGP_BSAI2SAFI (bsai));

                peer->pcount [baai][bsai] = 0;
              }

            send_notify = PAL_FALSE;
          }

          /* Extended ASN capability handling */
          if (CHECK_FLAG (BGP_VR.bvr_options,BGP_OPT_EXTENDED_ASN_CAP)
                   && CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_ADV))
            {
              bgp_peer_send_dyna_cap (peer,
                                      AFI_IP,
                                      SAFI_UNICAST,
                                      BGP_CAPABILITY_CODE_EXTASN,
                                      BGP_CAPABILITY_ACTION_SET);
              
              SET_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_ADV);
              send_notify = PAL_FALSE;
            }
          if ( CHECK_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV))
            UNSET_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV);
      }

  if (send_notify == PAL_TRUE)
    {
      bpf_register_notify (peer, BGP_NOTIFY_CEASE,
                           BGP_NOTIFY_CEASE_CONFIG_CHANGE, NULL, 0);
      bgp_peer_send_notify (peer);
      bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                     "BGP Notification CEASE");
      peer->bpf_conn_retry_count += 1;
      peer->dropped++;

      bpf_change_state (peer, BPF_STATE_IDLE);
#ifdef HAVE_SNMP
      bgpSnmpNotifyBackwardTransition (peer);
#endif /* HAVE_SNMP */
      bgp_peer_stop (peer);
      bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                     "User reset");
      peer->v_auto_start = BGP_DEFAULT_AUTO_START;
      BGP_TIMER_ON (&BLG, peer->t_auto_start, peer,
                    bpf_timer_auto_start, peer->v_auto_start);
      if (peer->clones_list)
        LIST_LOOP (peer->clones_list, clone_peer, nn)
          BGP_PEER_FSM_EVENT_ADD (&BLG, clone_peer,
                                  BPF_EVENT_MANUAL_STOP);
    }

EXIT:

  return ret;
}

s_int32_t
bpf_register_notify (struct bgp_peer *peer,
                     u_int32_t not_ecode,
                     u_int32_t not_esubcode,
                     u_int8_t *not_edata,
                     u_int32_t not_edlen)
{
  struct bgp_peer_notify_info *notify_info;
  u_int32_t alloc_size;
  s_int32_t ret;

  ret = 0;

  alloc_size = sizeof (struct bgp_peer_notify_info) - 1 + not_edlen;
  notify_info = XCALLOC (MTYPE_BGP_PEER_NOTIFY_DATA, alloc_size);
  if (! notify_info)
    {
      zlog_err (&BLG, "%s-%s [FSM] Post Notify:"
                " Cannot allocate memory (%d) @ %s:%d",
                peer->host, BGP_PEER_DIR_STR (peer),
                alloc_size, __FILE__, __LINE__);
      ret = -1;
      goto EXIT;
    }

  notify_info->not_err_code = not_ecode;
  notify_info->not_err_sub_code = not_esubcode;
  notify_info->not_err_dlen = not_edlen;

  if (not_edlen)
    pal_mem_cpy (notify_info->not_err_data, not_edata,
                 notify_info->not_err_dlen);

  if (peer->notify_info)
    XFREE (MTYPE_BGP_PEER_NOTIFY_DATA, peer->notify_info);
  peer->notify_info = notify_info;

EXIT:

  return ret;
}

s_int32_t
bpf_event_notify (struct bgp_peer *peer,
                  u_int32_t bpf_event,
                  u_int32_t not_ecode,
                  u_int32_t not_esubcode,
                  u_int8_t *not_edata,
                  u_int32_t not_edlen)
{
  struct bgp_peer_notify_info *notify_info;
  u_int32_t alloc_size;
  s_int32_t ret;

  ret = 0;

  alloc_size = sizeof (struct bgp_peer_notify_info) - 1 + not_edlen;
  notify_info = XCALLOC (MTYPE_BGP_PEER_NOTIFY_DATA, alloc_size);
  if (! notify_info)
    {
      zlog_err (&BLG, "%s-%s [FSM] Post Notify:"
                " Cannot allocate memory (%d) @ %s:%d",
                peer->host, BGP_PEER_DIR_STR (peer),
                alloc_size, __FILE__, __LINE__);
      ret = -1;
      goto EXIT;
    }

  notify_info->not_err_code = not_ecode;
  notify_info->not_err_sub_code = not_esubcode;
  notify_info->not_err_dlen = not_edlen;

  if (not_edlen)
    pal_mem_cpy (notify_info->not_err_data, not_edata,
                 notify_info->not_err_dlen);

  if (peer->notify_info)
    XFREE (MTYPE_BGP_PEER_NOTIFY_DATA, peer->notify_info);
  peer->notify_info = notify_info;

  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, bpf_event);

EXIT:

  return ret;
}

s_int32_t
bpf_event_notify_attr (struct cqueue_buffer *cq_rbuf,
                       struct bgp_peer *peer,
                       u_int8_t attr_flag,
                       u_int8_t attr_type,
                       u_int16_t attr_len,
                       u_int16_t attr_len_ceil,
                       u_int16_t attr_rewind,
                       u_int32_t not_ecode,
                       u_int32_t not_esubcode)
{
  struct bgp_peer_notify_info *notify_info;
  u_int32_t alloc_size;
  s_int32_t ret;

  ret = 0;

  /*
   * Since the 'attr_len' could potentially over-flow 'msg-size'
   * or 'attr_size', we use 'attr_len_ceil' to limit its value.
   * If 'attr_len_ceil' is ZERO, 'attr_len' is valid and to be used.
   */
  if (! attr_len_ceil)
    attr_len_ceil = attr_len;

  /*
   * Adjust the 'attr_len_ceil' to be the lower of 'attr_len'
   * and 'attr_len_ceil' to avoid over-shooting Message Size
   */
  attr_len_ceil = BGP_MIN (attr_len, attr_len_ceil);

  alloc_size = sizeof (struct bgp_peer_notify_info) - 1 +
               BGP_ATTR_MIN_SIZE +
               (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_EXTLEN) ?
                1 : 0) + attr_len_ceil;
  notify_info = XCALLOC (MTYPE_BGP_PEER_NOTIFY_DATA, alloc_size);
  if (! notify_info)
    {
      zlog_err (&BLG, "%s-%s [FSM] Update Attr:"
                " Cannot allocate memory (%d) @ %s:%d",
                peer->host, BGP_PEER_DIR_STR (peer),
                alloc_size, __FILE__, __LINE__);
      ret = -1;
      goto EXIT;
    }

  notify_info->not_err_code = not_ecode;
  notify_info->not_err_sub_code = not_esubcode;
  notify_info->not_err_dlen = alloc_size + 1 -
                           sizeof (struct bgp_peer_notify_info);
  notify_info->not_err_data [0] = attr_flag;
  notify_info->not_err_data [1] = attr_type;

  /*
   * If Áttribute Value field has already been read into, rewind
   * back to start of Attribute Value field
   */
  if (attr_rewind)
    CQUEUE_READ_REWIND_NBYTES (cq_rbuf, attr_rewind);

  if (CHECK_FLAG (attr_flag, BGP_ATTR_FLAG_EXTLEN))
    {
      CQUEUE_READ_NBYTES(cq_rbuf,
                         &notify_info->not_err_data [4],
                         attr_len_ceil);
      attr_len = pal_hton16 (attr_len);
      pal_mem_cpy (&notify_info->not_err_data [2],
                   &attr_len, BGP_ATTR_EXT_LEN_SIZE);
    }
  else
    {
      notify_info->not_err_data [2] = attr_len;
      CQUEUE_READ_NBYTES(cq_rbuf, &notify_info->not_err_data [3],
                         attr_len_ceil);
    }

  if (peer->notify_info)
    XFREE (MTYPE_BGP_PEER_NOTIFY_DATA, peer->notify_info);
  peer->notify_info = notify_info;

  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_UPDATE_ERR);

EXIT:

  return ret;
}

s_int32_t
bpf_event_notify_cap (struct cqueue_buffer *cq_rbuf,
                      struct bgp_peer *peer,
                      u_int32_t bpf_event,
                      u_int8_t cap_action,
                      u_int8_t cap_code,
                      u_int8_t cap_len,
                      u_int8_t cap_len_ceil,
                      u_int8_t cap_rewind,
                      u_int32_t not_ecode,
                      u_int32_t not_esubcode)
{
  struct bgp_peer_notify_info *notify_info;
  u_int32_t alloc_size;
  s_int32_t ret;

  ret = 0;

  /*
   * Since the 'cap_len' could potentially over-flow 'msg-size'
   * or 'cap_size', we use 'cap_len_ceil' to limit its value.
   * If 'cap_len_ceil' is ZERO, 'cap_len' is valid and to be used.
   */
  if (! cap_len_ceil)
    cap_len_ceil = cap_len;

  /*
   * Adjust the 'cap-len-ceil' to be the lower of 'cap_len'
   * and 'cap_len_ceil' to avoid over-shooting Message Size
   */
  cap_len_ceil = BGP_MIN (cap_len, cap_len_ceil);

  alloc_size = sizeof (struct bgp_peer_notify_info) - 1 + cap_len_ceil +
               (bpf_event == BPF_EVENT_OPEN_ERR ?
                BGP_MSG_OPEN_OPT_MIN_SIZE : BGP_MSG_CAP_OPT_MIN_SIZE);
  notify_info = XCALLOC (MTYPE_BGP_PEER_NOTIFY_DATA, alloc_size);
  if (! notify_info)
    {
      zlog_err (&BLG, "%s-%s [FSM] Update Attr:"
                " Cannot allocate memory (%d) @ %s:%d",
                peer->host, BGP_PEER_DIR_STR (peer),
                alloc_size, __FILE__, __LINE__);
      ret = -1;
      goto EXIT;
    }

  notify_info->not_err_code = not_ecode;
  notify_info->not_err_sub_code = not_esubcode;
  notify_info->not_err_dlen = alloc_size + 1 -
                           sizeof (struct bgp_peer_notify_info);

  /*
   * If Capability Value field has already been read into, rewind
   * back to start of Capability Value field
   */
  if (cap_rewind)
    CQUEUE_READ_REWIND_NBYTES (cq_rbuf, cap_rewind);

  if (bpf_event == BPF_EVENT_OPEN_ERR)
    {
      notify_info->not_err_data [0] = cap_code;
      notify_info->not_err_data [1] = cap_len;
      CQUEUE_READ_NBYTES(cq_rbuf, &notify_info->not_err_data [2],
                         cap_len_ceil);
    }
  else
    {
      notify_info->not_err_data [0] = cap_action;
      notify_info->not_err_data [1] = cap_code;
      notify_info->not_err_data [2] = cap_len;
      CQUEUE_READ_NBYTES(cq_rbuf, &notify_info->not_err_data [3],
                         cap_len_ceil);
    }

  if (peer->notify_info)
    XFREE (MTYPE_BGP_PEER_NOTIFY_DATA, peer->notify_info);
  peer->notify_info = notify_info;

  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, bpf_event);

EXIT:

  return ret;
}

