/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

#ifdef HAVE_SNMP
int
bgp_get_version (u_int32_t vr_id, int proc_id, u_char *version)
{
  *version = (0x80 >> (BGP_VERSION_4 - 1));
  return BGP_API_GET_SUCCESS;
}

int
bgp_get_local_as (u_int32_t vr_id, int proc_id, int *as)
{
  struct bgp *bgp;

  bgp = bgp_lookup_by_id (BGP_LIB_GLOBAL_VAR, vr_id);

  if (bgp)
    {
      *as = (int) bgp->as;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_identifier (u_int32_t vr_id, int proc_id, struct pal_in4_addr *id)
{
  struct bgp *bgp;

  bgp = bgp_lookup_by_id (BGP_LIB_GLOBAL_VAR, vr_id);

  if (bgp)
    {
      pal_mem_cpy (id, &bgp->router_id, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_identifier (u_int32_t vr_id, int proc_id,
                         struct pal_in4_addr *addr,
                         struct pal_in4_addr *id)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      pal_mem_cpy (id, &peer->remote_id, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_identifier (u_int32_t vr_id, int proc_id,
                              struct pal_in4_addr *addr,
                              struct pal_in4_addr *id)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      pal_mem_cpy (id, &peer->remote_id, sizeof (struct pal_in4_addr));
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_state (u_int32_t vr_id, int proc_id, struct pal_in4_addr *addr,
                    int *state)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *state = peer->bpf_state;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_state (u_int32_t vr_id, int proc_id,
                         struct pal_in4_addr *addr,
                         int *state)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *state = peer->bpf_state;
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_admin_status (u_int32_t vr_id, int proc_id,
                           struct pal_in4_addr *addr,
                           int *status)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      if (CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
        *status = BGP_API_PEERADMIN_STOP;
      else
        *status = BGP_API_PEERADMIN_START;

      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_admin_status (u_int32_t vr_id, int proc_id,
                                struct pal_in4_addr *addr,
                                int *status)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      if (CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
        *status = BGP_API_PEERADMIN_STOP;
      else
        *status = BGP_API_PEERADMIN_START;

      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));

      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_set_peer_admin_status (u_int32_t vr_id, int proc_id,
                           struct pal_in4_addr *addr,
                           s_int32_t flag)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      if (flag ==  BGP_API_PEERADMIN_STOP)
        {
          if (! CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
            {
              SET_FLAG (peer->flags, PEER_FLAG_SHUTDOWN);
              BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_STOP);
            }
        }
      else
        {
          if (CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
            {
              UNSET_FLAG (peer->flags, PEER_FLAG_SHUTDOWN);
              BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_START);
            }
        }
      return BGP_API_SET_SUCCESS;
    }
  return BGP_API_SET_ERROR;
}

int
bgp_set_next_peer_admin_status (u_int32_t vr_id, int proc_id,
                                struct pal_in4_addr *addr,
                                s_int32_t flag)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      if (flag ==  BGP_API_PEERADMIN_STOP)
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_STOP);

      return BGP_API_SET_SUCCESS;
    }
  return BGP_API_SET_ERROR;
}

int
bgp_get_peer_negotiated_version (u_int32_t vr_id, int proc_id,
                                 struct pal_in4_addr *addr,
                                 int *version)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *version = (int) (peer->version);
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_negotiated_version (u_int32_t vr_id, int proc_id,
                                      struct pal_in4_addr *addr,
                                      int *version)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *version = (int) (peer->version);
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_local_addr (u_int32_t vr_id, int proc_id,
                         struct pal_in4_addr *addr,
                         struct pal_in4_addr *out)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      if (peer->su_local)
        pal_mem_cpy (out, &peer->su_local->sin.sin_addr,
                     sizeof (struct pal_in4_addr));
      else
        pal_mem_set (out, 0, sizeof(struct pal_in4_addr));

      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_local_addr (u_int32_t vr_id, int proc_id,
                              struct pal_in4_addr *addr,
                              struct pal_in4_addr *out)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      if (peer->su_local)
        pal_mem_cpy (out, &peer->su_local->sin.sin_addr,
                     sizeof (struct pal_in4_addr));
      else
        pal_mem_set (out, 0, sizeof(struct pal_in4_addr));
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_local_port (u_int32_t vr_id, int proc_id,
                         struct pal_in4_addr *addr,
                         int *port)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *port = (peer->su_local)? (pal_ntoh16 (peer->su_local->sin.sin_port)):0;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_local_port (u_int32_t vr_id, int proc_id,
                              struct pal_in4_addr *addr,
                              int *port)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *port = (peer->su_local)? (pal_ntoh16 (peer->su_local->sin.sin_port)):0;
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_remote_addr (u_int32_t vr_id, int proc_id,
                          struct pal_in4_addr *addr,
                          struct pal_in4_addr *out)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      if (peer->su_remote)
        pal_mem_cpy (out, &peer->su_remote->sin.sin_addr,
                     sizeof (struct pal_in4_addr));
      else
        pal_mem_set (out, 0, sizeof(struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_remote_addr (u_int32_t vr_id, int proc_id,
                               struct pal_in4_addr *addr,
                               struct pal_in4_addr *out)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      if (peer->su_remote)
        pal_mem_cpy (out, &peer->su_remote->sin.sin_addr,
                     sizeof (struct pal_in4_addr));
      else
        pal_mem_set (out, 0, sizeof(struct pal_in4_addr));
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_remote_port (u_int32_t vr_id, int proc_id,
                          struct pal_in4_addr *addr,
                          int *port)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *port = (peer->su_remote)? (pal_ntoh16(peer->su_remote->sin.sin_port)):0;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_remote_port (u_int32_t vr_id, int proc_id,
                               struct pal_in4_addr *addr,
                               int *port)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *port = (peer->su_remote)? (pal_ntoh16 (peer->su_remote->sin.sin_port)):0;
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_remote_as (u_int32_t vr_id, int proc_id,
                        struct pal_in4_addr *addr,
                        int *as)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *as = (int) peer->as;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_remote_as (u_int32_t vr_id, int proc_id,
                             struct pal_in4_addr *addr,
                             int *as)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *as = (int) peer->as;
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_in_updates (u_int32_t vr_id, int proc_id,
                         struct pal_in4_addr *addr,
                         int *in)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *in = (int) peer->update_in;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_in_updates (u_int32_t vr_id, int proc_id,
                              struct pal_in4_addr *addr,
                              int *in)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *in = (int) peer->update_in;
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_out_updates (u_int32_t vr_id, int proc_id,
                          struct pal_in4_addr *addr,
                          int *out)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *out = (int) peer->update_out;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_out_updates (u_int32_t vr_id, int proc_id,
                               struct pal_in4_addr *addr,
                               int *out)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *out = (int) peer->update_out;
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_in_total_messages (u_int32_t vr_id, int proc_id,
                                struct pal_in4_addr *addr,
                                int *in)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *in = (peer->open_in + peer->update_in + peer->keepalive_in
             + peer->notify_in + peer->refresh_in + peer->dynamic_cap_in);

      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_in_total_messages (u_int32_t vr_id, int proc_id,
                                     struct pal_in4_addr *addr,
                                     int *in)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *in = (peer->open_in + peer->update_in + peer->keepalive_in
             + peer->notify_in + peer->refresh_in + peer->dynamic_cap_in);

      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_out_total_messages (u_int32_t vr_id, int proc_id,
                                 struct pal_in4_addr *addr,
                                 int *out)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *out = (peer->open_out + peer->update_out + peer->keepalive_out
              + peer->notify_out + peer->refresh_out + peer->dynamic_cap_out);

      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_out_total_messages (u_int32_t vr_id, int proc_id,
                                      struct pal_in4_addr *addr,
                                      int *out)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *out = (peer->open_out + peer->update_out + peer->keepalive_out
              + peer->notify_out + peer->refresh_out + peer->dynamic_cap_out);
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));

      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_last_error (u_int32_t vr_id, int proc_id,
                         struct pal_in4_addr *addr,
                         u_char *error)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      if (peer->notify_info)
        {
          error[0] = peer->notify_info->not_err_code;
          error[1] = peer->notify_info->not_err_sub_code;
        }
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_last_error (u_int32_t vr_id, int proc_id,
                              struct pal_in4_addr *addr,
                              u_char *error)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      if (peer->notify_info)
        {
          error[0] = peer->notify_info->not_err_code;
          error[1] = peer->notify_info->not_err_sub_code;
        }
      pal_mem_cpy (addr, &peer->su.sin.sin_addr,
                   sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_fsm_established_transitions (u_int32_t vr_id, int proc_id,
                                          struct pal_in4_addr *addr,
                                          int *est)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *est  = (int) (peer->established);
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_fsm_established_transitions (u_int32_t vr_id, int proc_id,
                                               struct pal_in4_addr *addr,
                                               int *est)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *est  = (int) (peer->established);
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_fsm_established_time (u_int32_t vr_id, int proc_id,
                                   struct pal_in4_addr *addr,
                                   int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *tm = (int) (peer->uptime == 0) ? 0 :
                  (pal_time_current (NULL) - peer->uptime);
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_fsm_established_time (u_int32_t vr_id, int proc_id,
                                        struct pal_in4_addr *addr,
                                        int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *tm = (int) (peer->uptime == 0) ? 0 :
                  (pal_time_current (NULL) - peer->uptime);
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_connect_retry_interval (u_int32_t vr_id, int proc_id,
                                     struct pal_in4_addr *addr,
                                     int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      if (CHECK_FLAG (peer->config, PEER_CONFIG_CONNECT))
        *tm = (int) (peer->connect);
      else
        *tm = (int) BGP_DEFAULT_CONNECT_RETRY;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_connect_retry_interval (u_int32_t vr_id, int proc_id,
                                          struct pal_in4_addr *addr,
                                          int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      if (CHECK_FLAG (peer->config, PEER_CONFIG_CONNECT))
        *tm = (int) (peer->connect);
      else
        *tm = (int) BGP_DEFAULT_CONNECT_RETRY;
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_set_peer_connect_retry_interval (u_int32_t vr_id, int proc_id,
                                     struct pal_in4_addr *addr,
                                     int tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      SET_FLAG (peer->config, PEER_CONFIG_CONNECT);
      peer->connect = (u_int32_t) tm;
      return BGP_API_SET_SUCCESS;
    }
  return BGP_API_SET_ERROR;
}

int
bgp_set_next_peer_connect_retry_interval (u_int32_t vr_id, int proc_id,
                                          struct pal_in4_addr *addr,
                                          int tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      SET_FLAG (peer->config, PEER_CONFIG_CONNECT);
      peer->connect = (u_int32_t) tm;
      return BGP_API_SET_SUCCESS;
    }
  return BGP_API_SET_ERROR;
}

int
bgp_get_peer_hold_time (u_int32_t vr_id, int proc_id,
                        struct pal_in4_addr *addr,
                        int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *tm = (int) (peer->v_holdtime);
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_hold_time (u_int32_t vr_id, int proc_id,
                             struct pal_in4_addr *addr,
                             int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *tm = (int) (peer->v_holdtime);
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_keep_alive (u_int32_t vr_id, int proc_id,
                         struct pal_in4_addr *addr,
                         int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *tm = (int) (peer->v_keepalive);
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_keep_alive (u_int32_t vr_id, int proc_id,
                              struct pal_in4_addr *addr,
                              int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *tm = (int) (peer->v_keepalive);
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_peer_hold_time_configured (u_int32_t vr_id, int proc_id,
                                   struct pal_in4_addr *addr,
                                   int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *tm = (int) (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER) ?
                   peer->holdtime: peer->v_holdtime);
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_hold_time_configured (u_int32_t vr_id, int proc_id,
                                        struct pal_in4_addr *addr,
                                        int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *tm = (int) (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER)
                   ? peer->holdtime: peer->v_holdtime);
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_set_peer_hold_time_configured (u_int32_t vr_id, int proc_id,
                                   struct pal_in4_addr *addr,
                                   int tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      SET_FLAG (peer->config, PEER_CONFIG_TIMER);
      peer->holdtime = (u_int32_t) tm;
      return BGP_API_SET_SUCCESS;
    }
  return BGP_API_SET_ERROR;
}

int
bgp_set_next_peer_hold_time_configured (u_int32_t vr_id, int proc_id,
                                        struct pal_in4_addr *addr,
                                        int tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      SET_FLAG (peer->config, PEER_CONFIG_TIMER);
      peer->holdtime = (u_int32_t) tm;
      return BGP_API_SET_SUCCESS;
    }
  return BGP_API_SET_ERROR;
}

int
bgp_get_peer_keep_alive_configured (u_int32_t vr_id, int proc_id,
                                    struct pal_in4_addr *addr,
                                     int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *tm = (int) (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER) ?
                   peer->keepalive: peer->v_keepalive);
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_keep_alive_configured (u_int32_t vr_id, int proc_id,
                                         struct pal_in4_addr *addr,
                                         int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *tm = (int) (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER) ?
                   peer->keepalive: peer->v_keepalive);
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_set_peer_keep_alive_configured (u_int32_t vr_id, int proc_id,
                                    struct pal_in4_addr *addr,
                                    int tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      SET_FLAG (peer->config, PEER_CONFIG_TIMER);
      peer->keepalive = (u_int32_t) tm;
      return BGP_API_SET_SUCCESS;
    }
  return BGP_API_SET_ERROR;
}

int
bgp_set_next_peer_keep_alive_configured (u_int32_t vr_id, int proc_id,
                                         struct pal_in4_addr *addr,
                                         int tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      SET_FLAG (peer->config, PEER_CONFIG_TIMER);
      peer->keepalive = (u_int32_t) tm;
      return BGP_API_SET_SUCCESS;
    }
  return BGP_API_SET_ERROR;
}

int
bgp_get_peer_min_as_origination_interval (u_int32_t vr_id, int proc_id,
                                          struct pal_in4_addr *addr,
                                          int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    {
      *tm = (int) (peer->v_asorig);
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_min_as_origination_interval (u_int32_t vr_id, int proc_id,
                                               struct pal_in4_addr *addr,
                                               int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    {
      *tm = (int) (peer->v_asorig);
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_set_peer_min_as_origination_interval (u_int32_t vr_id, int proc_id,
                                          struct pal_in4_addr *addr,
                                          int tm)
{
  struct bgp_peer *peer = NULL;
  s_int32_t ret;

  ret = BGP_API_SET_ERROR;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    ret = peer_asorig_interval_set (peer, tm);

  return ret;
}

int
bgp_set_next_peer_min_as_origination_interval (u_int32_t vr_id, int proc_id,
                                               struct pal_in4_addr *addr,
                                               int tm)
{
  struct bgp_peer *peer = NULL;
  s_int32_t ret;

  ret = BGP_API_SET_ERROR;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    ret = peer_asorig_interval_set (peer, tm);

  return ret;
}

int
bgp_get_peer_min_route_advertisement_interval (u_int32_t vr_id, int proc_id,
                                               struct pal_in4_addr *addr,
                                               int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);
  if (peer)
    {
      *tm = (int) (peer->v_routeadv);
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_min_route_advertisement_interval (u_int32_t vr_id,
                                                    int proc_id,
                                                    struct pal_in4_addr *addr,
                                                    int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);
  if (peer)
    {
      *tm = (int) (peer->v_routeadv);
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_set_peer_min_route_advertisement_interval (u_int32_t vr_id, int proc_id,
                                               struct pal_in4_addr *addr,
                                               int tm)
{
  struct bgp_peer *peer = NULL;
  s_int32_t ret;

  ret = BGP_API_SET_ERROR;

  peer = bgp_peer_lookup (vr_id, addr);

  if (peer)
    ret = peer_advertise_interval_set (peer, tm, PAL_FALSE);

  return ret;
}

int
bgp_set_next_peer_min_route_advertisement_interval (u_int32_t vr_id,
                                                    int proc_id,
                                                    struct pal_in4_addr *addr,
                                                    int tm)
{
  struct bgp_peer *peer = NULL;
  s_int32_t ret;

  ret = BGP_API_SET_ERROR;

  peer = bgp_peer_lookup_next (vr_id, addr);

  if (peer)
    ret = peer_advertise_interval_set (peer, tm, PAL_FALSE);

  return ret;
}

int
bgp_get_peer_in_update_elapsed_time (u_int32_t vr_id, int proc_id,
                                     struct pal_in4_addr *addr,
                                     int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup (vr_id, addr);
  if (peer)
    {
      *tm = (int) ((peer->update_time == 0)
                   ? 0 : (pal_time_current (NULL) - peer->update_time));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp_get_next_peer_in_update_elapsed_time (u_int32_t vr_id, int proc_id,
                                          struct pal_in4_addr *addr,
                                          int *tm)
{
  struct bgp_peer *peer = NULL;

  peer = bgp_peer_lookup_next (vr_id, addr);
  if (peer)
    {
      *tm = (int) ((peer->update_time == 0)
                   ? 0 : (pal_time_current (NULL) - peer->update_time));
      pal_mem_cpy (addr, &peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_peer (u_int32_t vr_id, int proc_id, struct prefix_ipv4 *addr,
                         union sockunion *su, struct pal_in4_addr *out)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      pal_mem_cpy (out,  &binfo->peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_ip_addr_prefix_len (u_int32_t vr_id, int proc_id,
                                       struct prefix_ipv4 *addr,
                                       union sockunion *su,
                                       int *len)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      *len = addr->prefixlen;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_ip_addr_prefix (u_int32_t vr_id, int proc_id,
                                   struct prefix_ipv4 *addr,
                                   union sockunion *su,
                                   struct pal_in4_addr *out)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      pal_mem_cpy (out, &addr->prefix, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_origin (u_int32_t vr_id, int proc_id,
                           struct prefix_ipv4 *addr,
                           union sockunion *su,
                           int *origin)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      *origin = binfo->attr->origin + 1;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_as_path_segment (u_int32_t vr_id, int proc_id,
                                    struct prefix_ipv4 *addr,
                                    union sockunion *su,
                                    u_char **pnt,
                                    size_t *len)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      if (binfo->attr && binfo->attr->aspath)
        {
          *pnt = binfo->attr->aspath->data;
          *len = binfo->attr->aspath->length;
        }
      else
        {
          *len = 0;
          *pnt = NULL;
        }
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_next_hop (u_int32_t vr_id, int proc_id,
                             struct prefix_ipv4 *addr,
                             union sockunion *su,
                             struct pal_in4_addr *out)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      pal_mem_cpy (out, &binfo->attr->nexthop, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_multi_exit_disc (u_int32_t vr_id, int proc_id,
                                    struct prefix_ipv4 *addr,
                                    union sockunion *su, int *med)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      *med = (binfo->attr->med == 0)? -1: binfo->attr->med;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_local_pref (u_int32_t vr_id, int proc_id,
                               struct prefix_ipv4 *addr,
                               union sockunion *su,
                               int *pref)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      *pref = (binfo->attr->local_pref == 0) ? -1: binfo->attr->local_pref;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_atomic_aggregate (u_int32_t vr_id, int proc_id,
                                     struct prefix_ipv4 *addr,
                                     union sockunion *su,
                                     int *atomic)
{
  *atomic = 1;
  return BGP_API_GET_SUCCESS;
}

int
bgp4_get_path_attr_aggregator_as (u_int32_t vr_id, int proc_id,
                                  struct prefix_ipv4 *addr,
                                  union sockunion *su,
                                  int *as)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      *as = binfo->attr->aggregator_as;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_aggregator_addr (u_int32_t vr_id, int proc_id,
                                    struct prefix_ipv4 *addr,
                                    union sockunion *su,
                                    struct pal_in4_addr *out)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      pal_mem_cpy (out, &binfo->attr->aggregator_addr,
                   sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_calc_local_pref (u_int32_t vr_id, int proc_id,
                                    struct prefix_ipv4 *addr,
                                    union sockunion *su,
                                    int *local_pref)
{
  *local_pref = -1;
  return BGP_API_GET_SUCCESS;
}

int
bgp4_get_path_attr_best (u_int32_t vr_id, int proc_id, struct prefix_ipv4 *addr,
                         union sockunion *su, int *best)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      *best = (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
        ? BGP_API_PATHATTRBEST_TRUE
        : BGP_API_PATHATTRBEST_FALSE;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_path_attr_unknown (u_int32_t vr_id, int proc_id,
                            struct prefix_ipv4 *addr,
                            union sockunion *su,
                            u_char **pnt,
                            size_t *len)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4 (vr_id, addr, su);
  if (binfo)
    {
      if (binfo->attr && binfo->attr->transit)
        {
          *len = binfo->attr->transit->length;
          *pnt = binfo->attr->transit->val;
        }
      else
        {
          *len = 0;
          *pnt = NULL;
        }
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_peer (u_int32_t vr_id, int proc_id,
                              struct prefix_ipv4 *addr,
                              union sockunion *su,
                              int offsetlen,
                              struct pal_in4_addr *out)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      pal_mem_cpy (out, &binfo->peer->su.sin.sin_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_ip_addr_prefix_len (u_int32_t vr_id, int proc_id,
                                            struct prefix_ipv4 *addr,
                                            union sockunion *su,
                                            int offsetlen, int *len)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      *len = addr->prefixlen;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_ip_addr_prefix (u_int32_t vr_id, int proc_id,
                                        struct prefix_ipv4 *addr,
                                        union sockunion *su,
                                        int offsetlen,
                                        struct pal_in4_addr *out)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      pal_mem_cpy (out, &addr->prefix, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_origin (u_int32_t vr_id, int proc_id,
                                struct prefix_ipv4 *addr,
                                union sockunion *su,
                                int offsetlen,
                                int *origin)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      *origin = binfo->attr->origin + 1;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_as_path_segment (u_int32_t vr_id, int proc_id,
                                         struct prefix_ipv4 *addr,
                                         union sockunion *su,
                                         int offsetlen,
                                         u_char **pnt,
                                         size_t *len)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      if (binfo->attr && binfo->attr->aspath)
        {
          *pnt = binfo->attr->aspath->data;
          *len = binfo->attr->aspath->length;
        }
      else
        {
          *len = 0;
          *pnt = NULL;
        }
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_next_hop (u_int32_t vr_id, int proc_id,
                                  struct prefix_ipv4 *addr,
                                  union sockunion *su,
                                  int offsetlen,
                                  struct pal_in4_addr *out)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      pal_mem_cpy (out, &binfo->attr->nexthop, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_multi_exit_disc (u_int32_t vr_id, int proc_id,
                                         struct prefix_ipv4 *addr,
                                         union sockunion *su,
                                         int offsetlen,
                                         int *med)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      *med = (binfo->attr->med == 0) ? -1 : binfo->attr->med;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_local_pref (u_int32_t vr_id, int proc_id,
                                    struct prefix_ipv4 *addr,
                                    union sockunion *su,
                                    int offsetlen,
                                    int *pref)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      *pref = (binfo->attr->local_pref == 0) ? -1 : binfo->attr->local_pref;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_atomic_aggregate (u_int32_t vr_id, int proc_id,
                                          struct prefix_ipv4 *addr,
                                          union sockunion *su,
                                          int offsetlen,
                                          int *atomic)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      if (binfo->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)) 
        *atomic = BGP_API_PATHATTR_LESS_SPEC_ROUTE_SELECTED;
      else
        *atomic = BGP_API_PATHATTR_LESS_SPEC_ROUTE_NOT_SELECTED; 

      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_aggregator_as (u_int32_t vr_id, int proc_id,
                                       struct prefix_ipv4 *addr,
                                       union sockunion *su,
                                       int offsetlen,
                                       int *as)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      *as = binfo->attr->aggregator_as;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_aggregator_addr (u_int32_t vr_id, int proc_id,
                                         struct prefix_ipv4 *addr,
                                         union sockunion *su,
                                         int offsetlen,
                                         struct pal_in4_addr *out)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      pal_mem_cpy (out,  &binfo->attr->aggregator_addr, sizeof (struct pal_in4_addr));
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_calc_local_pref (u_int32_t vr_id, int proc_id,
                                         struct prefix_ipv4 *addr,
                                         union sockunion *su,
                                         int offsetlen,
                                         int *local_pref)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      *local_pref = -1;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_best (u_int32_t vr_id, int proc_id,
                              struct prefix_ipv4 *addr,
                              union sockunion *su,
                              int offsetlen,
                              int *best)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      *best = (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
        ? BGP_API_PATHATTRBEST_TRUE
        : BGP_API_PATHATTRBEST_FALSE;
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

int
bgp4_get_next_path_attr_unknown (u_int32_t vr_id, int proc_id,
                                 struct prefix_ipv4 *addr,
                                 union sockunion *su,
                                 int offsetlen,
                                 u_char **pnt,
                                 size_t *len)
{
  struct bgp_info *binfo;

  binfo = bgp_path_attr_lookup_addr_ipv4_next (vr_id, addr, su, offsetlen);
  if (binfo)
    {
      if (binfo->attr && binfo->attr->transit)
        {
          *len = binfo->attr->transit->length;
          *pnt = binfo->attr->transit->val;
        }
      else
        {
          *len = 0;
          *pnt = NULL;
        }
      return BGP_API_GET_SUCCESS;
    }
  return BGP_API_GET_ERROR;
}

struct bgp_peer *
bgp_peer_lookup (u_int32_t vr_id, struct pal_in4_addr *src)
{
  struct pal_in4_addr addr;
  struct bgp_peer *peer;
  struct listnode *nn;
  struct bgp *bgp;
  int ret;

  bgp = bgp_lookup_by_id (BGP_LIB_GLOBAL_VAR, vr_id);
  if (! bgp)
    return NULL;

  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      ret = pal_inet_pton (AF_INET, peer->host, &addr);
      if (ret > 0)
        {
          if (IPV4_ADDR_SAME (&addr, src))
            return peer;
        }
    }
  return NULL;
}

struct bgp_peer *
bgp_peer_lookup_next (u_int32_t vr_id, struct pal_in4_addr *src)
{
  struct bgp *bgp;
  struct bgp_peer *peer;
  struct listnode *nn;
  struct pal_in4_addr *p;
  union sockunion su;
  int ret;

  pal_mem_set (&su, 0, sizeof (union sockunion));

  bgp = bgp_lookup_by_id (BGP_LIB_GLOBAL_VAR, vr_id);
  if (! bgp)
    return NULL;

  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      ret = pal_inet_pton (AF_INET, peer->host, &su.sin.sin_addr);
      if (ret > 0)
        {
          p = &su.sin.sin_addr;

          if (pal_ntoh32 (p->s_addr) > pal_ntoh32 (src->s_addr))
            {
              src->s_addr = p->s_addr;
              return peer;
            }
        }
    }
  return NULL;
}

struct bgp_info *
bgp_path_attr_lookup_addr_ipv4 (u_int32_t vr_id, struct prefix_ipv4 *addr,
                                union sockunion *su)
{
  struct bgp_info *binfo;
  struct bgp_node *rn;
  struct bgp *bgp;

  bgp = bgp_lookup_by_id (BGP_LIB_GLOBAL_VAR, vr_id);
  if (! bgp)
    return NULL;

  /* Lookup node. */
  rn = bgp_node_lookup (bgp->rib[BAAI_IP][BSAI_UNICAST],
                        (struct prefix *) addr);
  if (rn)
    {
      bgp_unlock_node (rn);

      for (binfo = rn->info; binfo; binfo = binfo->next)
        if (sockunion_same (&binfo->peer->su, su))
          return binfo;
    }
  return NULL;
}

struct bgp_info *
bgp_path_attr_lookup_addr_ipv4_next (u_int32_t vr_id, struct prefix_ipv4 *addr,
                                     union sockunion *su,
                                     int offsetlen)
{
  struct bgp *bgp;
  struct bgp_info *binfo;
  struct bgp_info *min;
  struct bgp_node *rn;
  struct prefix rnp;

  bgp = bgp_lookup_by_id (BGP_LIB_GLOBAL_VAR, vr_id);
  if (! bgp)
    return NULL;

  offsetlen -= sizeof (struct pal_in4_addr);

  if (offsetlen < 0)
    rn = bgp_table_top (bgp->rib[BAAI_IP][BSAI_UNICAST]);
  else
    rn = bgp_node_get (bgp->rib[BAAI_IP][BSAI_UNICAST],
                       (struct prefix *) addr);
  if (! rn)
    return NULL;

  offsetlen -= 1 + sizeof (struct pal_in4_addr);

  do
    {
      min = NULL;

      for (binfo = rn->info; binfo; binfo = binfo->next)
        {
          if (binfo->peer->su.sin.sin_family != AF_INET)
            continue;

          if (offsetlen < 0 ||
              (pal_ntoh32 (su->sin.sin_addr.s_addr)
               < pal_ntoh32 (binfo->peer->su.sin.sin_addr.s_addr)))
            {
              if (min)
                {
                  if (pal_ntoh32 (binfo->peer->su.sin.sin_addr.s_addr)
                      < pal_ntoh32 (min->peer->su.sin.sin_addr.s_addr))
                    min = binfo;
                }
              else
                min = binfo;
            }
        }

      if (min)
        {
          BGP_GET_PREFIX_FROM_NODE (rn);
          addr->prefix = rnp.u.prefix4;
          addr->prefixlen = rnp.prefixlen;

          pal_mem_cpy (&su->sin.sin_addr.s_addr, &min->peer->su.sin.sin_addr,
                  sizeof (struct pal_in4_addr));
          bgp_unlock_node (rn);
          return min;
        }

      /* Force to pick up first BGP information.  */
      offsetlen = -1;
    }
  while ((rn = bgp_route_next (rn)) != NULL);

  return NULL;
}

/* SNMP Notification Callback API. */

/*
 * Set BGP snmp notification callback function.
 * If snmp_notify_id == BGP_SNMP_NOTIFY_ALL (which is 0), register all
 * supported notifications
 */
s_int32_t
bgp_snmp_notification_callback_set (u_int32_t snmp_notify_id,
                                    SNMP_TRAP_CALLBACK func)
{
  u_int32_t i, j;
  bool_t found;
  vector v;

  if (snmp_notify_id > BGP_SNMP_NOTIFY_ID_MAX)
    return BGP_API_SET_ERROR;

  if (snmp_notify_id == BGP_SNMP_NOTIFY_ALL)
    {
      for (i = 0; i < BGP_SNMP_NOTIFY_ID_MAX; i++)
        {
          found = PAL_FALSE;
          v = BGP_VR.snmp_notifications [i];

          for (j = 0; j < vector_max (v); j++)
            if (vector_slot (v, j) == func)
              {
                found = PAL_TRUE;
                break;
              }

          if (found == PAL_FALSE)
            vector_set (v, func);
        }
      return BGP_API_SET_SUCCESS;
    }

  /* Get snmp notifications callback vector. */
  v = BGP_VR.snmp_notifications [snmp_notify_id - 1];

  for (j = 0; j < vector_max (v); j++)
    if (vector_slot (v, j) == func)
      return BGP_API_SET_SUCCESS;

  vector_set (v, func);

  return BGP_API_SET_SUCCESS;
}

s_int32_t
bgp_snmp_notification_callback_unset (u_int32_t snmp_notify_id,
                         SNMP_TRAP_CALLBACK func)
{
  u_int32_t i, j;
  vector v;

  if (snmp_notify_id == BGP_SNMP_NOTIFY_ALL)
    {
      for (i = 0; i < BGP_SNMP_NOTIFY_ID_MAX; i++)
        {
          v = BGP_VR.snmp_notifications [i];

          for (j = 0; j < vector_max (v); j++)
            if (vector_slot (v, j) == func)
              vector_unset (v, j);
        }
      return BGP_API_SET_SUCCESS;
    }

  if (snmp_notify_id > BGP_SNMP_NOTIFY_ID_MAX)
    return BGP_API_SET_ERROR;

  /* Get snmp notifications callback vector. */
  v = BGP_VR.snmp_notifications [snmp_notify_id - 1];

  for (i = 0; i < vector_max (v); i++)
    if (vector_slot (v, i) == func)
      {
        vector_unset (v, i);
        return BGP_API_SET_SUCCESS;
      }
  return BGP_API_SET_ERROR;
}
#endif /* HAVE_SNMP */
