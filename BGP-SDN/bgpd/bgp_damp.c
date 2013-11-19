/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/*********************************************************************/
/* FILE       : bgp_damp.c                                           */
/* PURPOSE    : This file contains BGP Route-Flap-Dampening          */
/*              (RFC 2439) related function definitions.             */
/* SUB-MODULE : BGP Route-Flap-Dampening                             */
/* NAME-TAG   : 'bgp_rfd_' (BGP Route-Flap-Dampening)                */
/*********************************************************************/

/* Reuse-list Timer handler */
s_int32_t
bgp_rfd_reuse_timer (struct thread *t_rfd_reuse)
{
  struct bgp_rfd_hist_info *rfd_hinfo_next;
  struct bgp_rfd_hist_info *rfd_hinfo;
  s_int32_t ret;
  struct prefix rnp;

  BGP_VR.t_rfd_reuse = NULL;
  ret = 0;

  /*
   * 1. Save a pointer to current zeroth queue head and zero the
   * list head entry
   */
  rfd_hinfo = BGP_VR.rfd_reuse_list [BGP_VR.rfd_reuse_list_offset];
  BGP_VR.rfd_reuse_list [BGP_VR.rfd_reuse_list_offset] = NULL;

  /*
   * 2.  set offset = modulo reuse-list-size (offset + 1), thereby
   * rotating the circular queue of list-heads
   */
  BGP_VR.rfd_reuse_list_offset = (BGP_VR.rfd_reuse_list_offset + 1) %
                                 BGP_RFD_REUSE_LIST_SIZE;

  /*
   * 3. if (the saved list head pointer is non-empty)
   *    for each entry {
   *      - Update figure-of-merit
   *      - Re-use / Re-insert the route
   *    }
   */
  for (; rfd_hinfo; rfd_hinfo = rfd_hinfo_next)
    {
      BGP_GET_PREFIX_FROM_NODE (rfd_hinfo->rfdh_rn);
      rfd_hinfo_next = rfd_hinfo->rfdh_reuse_next;

      ret = bgp_rfd_update_penalty (rfd_hinfo,
                                    BGP_RFD_RT_EVENT_REUSE_TIMER);

      if (ret)
        {
          if (BGP_DEBUG (rfd, RFD))
            zlog_info (&BLG, "[DAMP] bgp_rfd_reuse_timer(): Penalty "
                       "Updation failed for hinfo (%X), reusing route...",
                       rfd_hinfo);

          /* Reuse the route */
          if (rfd_hinfo->rfdh_rec_event == BGP_RFD_RT_EVENT_REACH)
            {
              bgp_aggregate_increment (rfd_hinfo->rfdh_binfo->peer->bgp,
                           &rnp,
                           rfd_hinfo->rfdh_binfo,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi);
              bgp_process (rfd_hinfo->rfdh_binfo->peer->bgp,
                           rfd_hinfo->rfdh_rn,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_safi, NULL);
            }

          bgp_rfd_hinfo_delete (rfd_hinfo);

          continue;
        }

      /* if (figure-of-merit < reuse) */
      if (rfd_hinfo->rfdh_penalty < rfd_hinfo->rfdh_rfd_cb->rfd_reuse)
        {
          /* Reuse the route */
          rfd_hinfo->rfdh_suppress_time = 0;

          /* Switch over to Non-Reuse List */
          if (rfd_hinfo->rfdh_reuse_idx != BGP_RFD_REUSE_LIST_INV_IDX)
            {
              bgp_rfd_reuse_list_remove (rfd_hinfo);
              bgp_rfd_non_reuse_list_insert (rfd_hinfo);
            }

          if (rfd_hinfo->rfdh_rec_event == BGP_RFD_RT_EVENT_REACH)
            {
              bgp_aggregate_increment (rfd_hinfo->rfdh_binfo->peer->bgp,
                           &rnp,
                           rfd_hinfo->rfdh_binfo,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi);
              bgp_process (rfd_hinfo->rfdh_binfo->peer->bgp,
                           rfd_hinfo->rfdh_rn,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_safi, NULL);
            }

          if (rfd_hinfo->rfdh_penalty <=
              rfd_hinfo->rfdh_rfd_cb->rfd_penalty_floor)
            {
              if (BGP_DEBUG (rfd, RFD))
                zlog_info (&BLG, "[DAMP] bgp_rfd_non_reuse_timer():"
                           "Deleting RFD_HINFO (%X)", rfd_hinfo);

              bgp_rfd_hinfo_delete (rfd_hinfo);
            }
        }
      else
        {
          /* Re-insert into reuse-list arrays */
          ret = bgp_rfd_reuse_list_insert (rfd_hinfo);

          /* Reuse the route since we failed to insert */
          if (ret)
            {
              rfd_hinfo->rfdh_suppress_time = 0;

              /* Switch over to Non-Reuse List */
              if (rfd_hinfo->rfdh_reuse_idx != BGP_RFD_REUSE_LIST_INV_IDX)
                {
                  bgp_rfd_reuse_list_remove (rfd_hinfo);
                  bgp_rfd_non_reuse_list_insert (rfd_hinfo);
                }

              if (rfd_hinfo->rfdh_rec_event == BGP_RFD_RT_EVENT_REACH)
                {
                  bgp_aggregate_increment (rfd_hinfo->rfdh_binfo->peer->bgp,
                               &rnp,
                               rfd_hinfo->rfdh_binfo,
                               rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi,
                               rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi);
                  bgp_process (rfd_hinfo->rfdh_binfo->peer->bgp,
                               rfd_hinfo->rfdh_rn,
                               rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi,
                               rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_safi,
                               NULL);
                }
            }
        }
    }

  BGP_TIMER_ON (&BLG, BGP_VR.t_rfd_reuse, NULL,
                bgp_rfd_reuse_timer, BGP_RFD_REUSE_TICK);

  return 0;
}

/*
 * Non-Reuse-list Timer handler:
 *  This is used to update Penalty values periodically and
 *  delete the History Info is (penalty < reuse/2)
 */
s_int32_t
bgp_rfd_non_reuse_timer (struct thread *t_rfd_non_reuse)
{
  struct bgp_rfd_hist_info *rfd_hinfo_next;
  struct bgp_rfd_hist_info *rfd_hinfo;
  struct prefix rnp;

  BGP_VR.t_rfd_non_reuse = NULL;

  for (rfd_hinfo = BGP_VR.rfd_non_reuse_list;
       rfd_hinfo;
       rfd_hinfo = rfd_hinfo_next)
    {
      rfd_hinfo_next = rfd_hinfo->rfdh_reuse_next;

      if (bgp_rfd_update_penalty (rfd_hinfo,
                                  BGP_RFD_RT_EVENT_NON_REUSE_TIMER))
        {
          if (BGP_DEBUG (rfd, RFD))
            zlog_info (&BLG, "[DAMP] bgp_rfd_non_reuse_timer(): Penalty "
                       "Updation failed for hinfo (%X), reusing route...",
                       rfd_hinfo);

          /* Reuse the route */
          if (rfd_hinfo->rfdh_rec_event == BGP_RFD_RT_EVENT_REACH)
            {
              BGP_GET_PREFIX_FROM_NODE (rfd_hinfo->rfdh_rn);
              bgp_aggregate_increment (rfd_hinfo->rfdh_binfo->peer->bgp,
                           &rnp,
                           rfd_hinfo->rfdh_binfo,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi);
              bgp_process (rfd_hinfo->rfdh_binfo->peer->bgp,
                           rfd_hinfo->rfdh_rn,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_afi,
                           rfd_hinfo->rfdh_rfd_cb->rfd_cfg->rfdg_safi, NULL);
            }

          bgp_rfd_hinfo_delete (rfd_hinfo);

          continue;
        }

      /* if (figure-of-merit < penalty_floor), delete Hist Info */
      if (rfd_hinfo->rfdh_penalty <=
          rfd_hinfo->rfdh_rfd_cb->rfd_penalty_floor)
        {
          if (BGP_DEBUG (rfd, RFD))
            zlog_info (&BLG, "[DAMP] bgp_rfd_non_reuse_timer():"
                       "Deleting RFD_HINFO (%X)", rfd_hinfo);

          bgp_rfd_hinfo_delete (rfd_hinfo);
        }
    }

  BGP_TIMER_ON (&BLG, BGP_VR.t_rfd_non_reuse, NULL,
                bgp_rfd_non_reuse_timer, BGP_RFD_NON_REUSE_TICK);

  return 0;
}

/* Allocate an RFD History Information */
s_int32_t
bgp_rfd_hinfo_create (struct bgp_rfd_cb *rfd_cb,
                      struct bgp_rfd_hist_info **rfd_hinfo)
{
  *rfd_hinfo = XCALLOC (MTYPE_BGP_RFD_HINFO,
                       sizeof (struct bgp_rfd_hist_info));
  if (! *rfd_hinfo)
    {
      zlog_err (&BLG, "[DAMP] bgp_rfd_hinfo_create():"
                " Cannot allocate memory (%d) @ %s:%d",
                sizeof (struct bgp_rfd_hist_info), __FILE__, __LINE__);
      return -1;
    }

  (*rfd_hinfo)->rfdh_reuse_idx = BGP_RFD_REUSE_LIST_INV_IDX;
  (*rfd_hinfo)->rfdh_penalty = BGP_RFD_DEF_PENALTY;
  (*rfd_hinfo)->rfdh_rec_duration =
     (*rfd_hinfo)->rfdh_lupdate = pal_time_current (NULL);
  (*rfd_hinfo)->rfdh_flap_count = 1;
  (*rfd_hinfo)->rfdh_rfd_cb = rfd_cb;
  (*rfd_hinfo)->rfdh_first_withdraw_done = 0;
  bgp_rfd_non_reuse_list_insert (*rfd_hinfo);
  bgp_rfd_rfdcb_list_insert (rfd_cb, *rfd_hinfo);

  return 0;
}

/* Delete the RFD History Information */
s_int32_t
bgp_rfd_hinfo_delete (struct bgp_rfd_hist_info *rfd_hinfo)
{
  struct bgp_info *binfo;
  struct bgp_node *rn;

  if (! rfd_hinfo)
    return -1;

  binfo = rfd_hinfo->rfdh_binfo;
  rn = rfd_hinfo->rfdh_rn;
  binfo->rfd_hinfo = NULL;

  if (rfd_hinfo->rfdh_rec_event == BGP_RFD_RT_EVENT_UNREACH)
    {
      bgp_info_delete (rn, binfo);
      bgp_info_free (binfo);
      bgp_unlock_node (rn);
    }

  /* Free the History Information */
  bgp_rfd_hinfo_free (rfd_hinfo);

  return 0;
}

/* Release strings for RFD History Information and free it */
s_int32_t
bgp_rfd_hinfo_free (struct bgp_rfd_hist_info *rfd_hinfo)
{
  if (! rfd_hinfo)
    return -1;

  /* Release from associated RFD-CB list */
  bgp_rfd_rfdcb_list_remove (rfd_hinfo);

  /* Ensure removal from both Reuse & Non-Reuse Lists */
  if (rfd_hinfo->rfdh_reuse_idx != BGP_RFD_REUSE_LIST_INV_IDX)
    bgp_rfd_reuse_list_remove (rfd_hinfo);
  else
    bgp_rfd_non_reuse_list_remove (rfd_hinfo);

  XFREE (MTYPE_BGP_RFD_HINFO, rfd_hinfo);

  return 0;
}

/* Clear Flap Statistics for the RFD History Information */
s_int32_t
bgp_rfd_hinfo_clear_flap_stats (struct bgp_rfd_hist_info *rfd_hinfo)
{
  if (! rfd_hinfo)
    return -1;

  rfd_hinfo->rfdh_flap_count = 0;
  rfd_hinfo->rfdh_rec_duration = pal_time_current (NULL);

  return 0;
}

/* Insert BGP RFD history information into RFD-CB list */
s_int32_t
bgp_rfd_rfdcb_list_insert (struct bgp_rfd_cb *rfd_cb,
                           struct bgp_rfd_hist_info *rfd_hinfo)
{
  if (! rfd_cb || ! rfd_hinfo)
    return -1;

  rfd_hinfo->rfdh_rfdcb_prev = NULL;
  rfd_hinfo->rfdh_rfdcb_next = rfd_cb->rfd_hinfo_list;
  if (rfd_cb->rfd_hinfo_list)
    rfd_cb->rfd_hinfo_list->rfdh_rfdcb_prev = rfd_hinfo;
  rfd_cb->rfd_hinfo_list = rfd_hinfo;

  return 0;
}

/* Remove BGP RFD history information from RFD-CB list */
s_int32_t
bgp_rfd_rfdcb_list_remove (struct bgp_rfd_hist_info *rfd_hinfo)
{
  if (! rfd_hinfo || ! rfd_hinfo->rfdh_rfd_cb)
    return -1;

  if (rfd_hinfo->rfdh_rfdcb_next)
    rfd_hinfo->rfdh_rfdcb_next->rfdh_rfdcb_prev =
                                           rfd_hinfo->rfdh_rfdcb_prev;
  if (rfd_hinfo->rfdh_rfdcb_prev)
    rfd_hinfo->rfdh_rfdcb_prev->rfdh_rfdcb_next =
                                           rfd_hinfo->rfdh_rfdcb_next;
  else
    rfd_hinfo->rfdh_rfd_cb->rfd_hinfo_list =
                                           rfd_hinfo->rfdh_reuse_next;

  return 0;
}

/* Calculate reuse list index */
s_int32_t
bgp_rfd_reuse_list_index (struct bgp_rfd_hist_info *rfd_hinfo)
{
  s_int32_t reuse_idx_ary_idx;
  struct bgp_rfd_cb *rfd_cb;
  s_int32_t reuse_list_idx;
  u_int32_t *reuse_idx_ary;

  rfd_cb = rfd_hinfo->rfdh_rfd_cb;
  reuse_idx_ary = NULL;

  if (rfd_hinfo->rfdh_rec_event == BGP_RFD_RT_EVENT_REACH)
    {
      reuse_idx_ary = &rfd_cb->rfd_reach_reuse_idx_ary[0];

      reuse_idx_ary_idx = ((((float64_t)rfd_hinfo->rfdh_penalty) /
                            ((float64_t)rfd_cb->rfd_reuse)) - 1.0) *
                           rfd_cb->rfd_rscale_factor;
    }
  else
    {
      reuse_idx_ary = &rfd_cb->rfd_unreach_reuse_idx_ary[0];

      reuse_idx_ary_idx = ((((float64_t)rfd_hinfo->rfdh_penalty) /
                            ((float64_t)rfd_cb->rfd_reuse)) - 1.0) *
                           rfd_cb->rfd_uscale_factor;
    }

  if (reuse_idx_ary_idx >= 0
      && reuse_idx_ary_idx < BGP_RFD_REUSE_IDX_ARY_SIZE)
    reuse_list_idx = reuse_idx_ary [reuse_idx_ary_idx];
  else
    reuse_list_idx = BGP_RFD_REUSE_LIST_SIZE - 1;

  reuse_list_idx = (reuse_list_idx + BGP_VR.rfd_reuse_list_offset) %
                   BGP_RFD_REUSE_LIST_SIZE;

  return reuse_list_idx;
}

/* Insert BGP RFD history information into reuse list */
s_int32_t
bgp_rfd_reuse_list_insert (struct bgp_rfd_hist_info *rfd_hinfo)
{
  s_int32_t reuse_list_idx;

  if (! rfd_hinfo)
    return -1;

  reuse_list_idx = bgp_rfd_reuse_list_index (rfd_hinfo);

  /* If already on the same list, release from Reuse-Lists */
  if (rfd_hinfo->rfdh_reuse_idx == reuse_list_idx)
    return -1;

  /* If already on another Reuse List, remove it */
  if (rfd_hinfo->rfdh_reuse_idx != BGP_RFD_REUSE_LIST_INV_IDX)
    bgp_rfd_reuse_list_remove (rfd_hinfo);

  /* Now insert into re-calculated Reuse List */
  rfd_hinfo->rfdh_reuse_idx = reuse_list_idx;
  rfd_hinfo->rfdh_reuse_prev = NULL;
  rfd_hinfo->rfdh_reuse_next = BGP_VR.rfd_reuse_list [reuse_list_idx];
  if (BGP_VR.rfd_reuse_list[reuse_list_idx])
    BGP_VR.rfd_reuse_list[reuse_list_idx]->rfdh_reuse_prev = rfd_hinfo;
  BGP_VR.rfd_reuse_list[reuse_list_idx] = rfd_hinfo;

  return 0;
}

/* Remove BGP RFD history information from reuse list */
s_int32_t
bgp_rfd_reuse_list_remove (struct bgp_rfd_hist_info *rfd_hinfo)
{
  if (! rfd_hinfo)
    return -1;

  if (rfd_hinfo->rfdh_reuse_idx == BGP_RFD_REUSE_LIST_INV_IDX)
    return 0;

  if (rfd_hinfo->rfdh_reuse_next)
    rfd_hinfo->rfdh_reuse_next->rfdh_reuse_prev =
                                           rfd_hinfo->rfdh_reuse_prev;
  if (rfd_hinfo->rfdh_reuse_prev)
    rfd_hinfo->rfdh_reuse_prev->rfdh_reuse_next =
                                           rfd_hinfo->rfdh_reuse_next;
  else
    BGP_VR.rfd_reuse_list[rfd_hinfo->rfdh_reuse_idx] =
                                           rfd_hinfo->rfdh_reuse_next;

  rfd_hinfo->rfdh_reuse_idx = BGP_RFD_REUSE_LIST_INV_IDX;

  return 0;
}

/* Insert BGP RFD history information into non-reuse list */
s_int32_t
bgp_rfd_non_reuse_list_insert (struct bgp_rfd_hist_info *rfd_hinfo)
{
  if (! rfd_hinfo
      || rfd_hinfo->rfdh_reuse_idx != BGP_RFD_REUSE_LIST_INV_IDX)
    return -1;

  rfd_hinfo->rfdh_reuse_prev = NULL;
  rfd_hinfo->rfdh_reuse_next = BGP_VR.rfd_non_reuse_list;
  if (BGP_VR.rfd_non_reuse_list)
    BGP_VR.rfd_non_reuse_list->rfdh_reuse_prev = rfd_hinfo;
  BGP_VR.rfd_non_reuse_list = rfd_hinfo;

  return 0;
}

/* Remove BGP RFD history information from non-reuse list */
s_int32_t
bgp_rfd_non_reuse_list_remove (struct bgp_rfd_hist_info *rfd_hinfo)
{
  if (! rfd_hinfo)
    return -1;

  if (rfd_hinfo->rfdh_reuse_idx != BGP_RFD_REUSE_LIST_INV_IDX)
    return 0;

  if (rfd_hinfo->rfdh_reuse_next)
    rfd_hinfo->rfdh_reuse_next->rfdh_reuse_prev =
                                           rfd_hinfo->rfdh_reuse_prev;
  if (rfd_hinfo->rfdh_reuse_prev)
    rfd_hinfo->rfdh_reuse_prev->rfdh_reuse_next =
                                           rfd_hinfo->rfdh_reuse_next;
  else
    BGP_VR.rfd_non_reuse_list = rfd_hinfo->rfdh_reuse_next;

  return 0;
}

/* Update the Penalty value and updated time */
s_int32_t
bgp_rfd_update_penalty (struct bgp_rfd_hist_info *rfd_hinfo,
                        enum bgp_rfd_rt_event rt_event)
{
  struct bgp_rfd_cb *rfd_cb;
  pal_time_t t_now;
  u_int32_t idx;

  if (! rfd_hinfo || ! rfd_hinfo->rfdh_rfd_cb)
    return -1;

  rfd_cb = rfd_hinfo->rfdh_rfd_cb;
  t_now = pal_time_current (NULL);

  idx = (t_now - rfd_hinfo->rfdh_lupdate) / BGP_RFD_DECAY_TICK;

  switch (rt_event)
    {
      case BGP_RFD_RT_EVENT_REACH:
        if (idx < rfd_cb->rfd_nudecay)
	  {
            rfd_hinfo->rfdh_penalty *= rfd_cb->rfd_udecay [idx];
	    if (idx && !rfd_hinfo->rfdh_first_withdraw_done)
              {
		/*
		 * When first time a route is withdrawn, rfd_hinfo is created.
	         * At that time the route is not damped and put into histroy state
		 * and penalty is updated by the NON_REUSE timer event periodically.
		 * At this time the penalty value is set to default (1000).
		 * The penalty value is adjusted when the route flaps again, and thus becomes 
		 * reachable again. At that time bgp_rfd_update_penalty() is called
		 * with EVENT_REACH from bgp_rfd_rt_update() and penalty is calculated.
		 * If the configured penalty is higher than default penalty, the penalty
	         * calculation and corresponding re-use time is calculated correctly.
		 * If the configured suppress penalty is much less than default penalty then 
		 * re-use time gets very high. Customer wants to see re-use time not to exceed
		 * max-suppress time. Thus this piece of code is adjusted to the ceiling value
		 * for the first time only if the calculated penalty is higher than max-suppress penalty.
		 * RFC 2439 only allows the following penalty calculation
		 * for unreachable case. But in BGP-SDN, we have to do it first time
		 * we have implicit withdraw happens.
                 */

		rfd_hinfo->rfdh_first_withdraw_done = 1;
                rfd_hinfo->rfdh_penalty += BGP_RFD_DEF_PENALTY;

                if (rfd_hinfo->rfdh_penalty > rfd_cb->rfd_penalty_ceil)
                  rfd_hinfo->rfdh_penalty = rfd_cb->rfd_penalty_ceil;

              }
          }
        else
          rfd_hinfo->rfdh_penalty = 0;
        break;

      case BGP_RFD_RT_EVENT_UNREACH:
        if (idx < rfd_cb->rfd_nrdecay)
          {
            rfd_hinfo->rfdh_penalty *= rfd_cb->rfd_rdecay [idx];

            /* If idx==0, no penalty updation */
            if (idx)
              {
                rfd_hinfo->rfdh_penalty += BGP_RFD_DEF_PENALTY;

                if (rfd_hinfo->rfdh_penalty > rfd_cb->rfd_penalty_ceil)
                  rfd_hinfo->rfdh_penalty = rfd_cb->rfd_penalty_ceil;
              }
          }
        else
          /* If idx >= ARY_SIZE, ZERO the penalty */
          rfd_hinfo->rfdh_penalty = 0;
        break;

      case BGP_RFD_RT_EVENT_REUSE_TIMER:
      case BGP_RFD_RT_EVENT_NON_REUSE_TIMER:
        if (rfd_hinfo->rfdh_rec_event == BGP_RFD_RT_EVENT_REACH)
          {
            if (idx < rfd_cb->rfd_nrdecay)
              rfd_hinfo->rfdh_penalty *= rfd_cb->rfd_rdecay [idx];
            else
              rfd_hinfo->rfdh_penalty = 0;
          }
        else
          {
            if (idx < rfd_cb->rfd_nudecay)
              rfd_hinfo->rfdh_penalty *= rfd_cb->rfd_udecay [idx];
            else
              rfd_hinfo->rfdh_penalty = BGP_RFD_DEF_PENALTY;
          }
        break;
    }

  rfd_hinfo->rfdh_lupdate = t_now;

  return 0;
}

/* Record un-reachability */
s_int32_t
bgp_rfd_rt_withdraw (struct bgp *bgp, struct bgp_peer *peer,
                     afi_t afi, safi_t safi,
                     struct bgp_node *rn, struct bgp_info *binfo,
                     enum bgp_rfd_rt_state *rt_state)
{
  struct bgp_rfd_hist_info *rfd_hinfo;
  struct bgp_rfd_cb *rfd_cb;
  s_int32_t ret;

  *rt_state = BGP_RFD_RT_STATE_NONE;
  rfd_hinfo = binfo->rfd_hinfo;
  ret = 0;

  if (! rfd_hinfo)
    {
      /* RFD is meant only for EBGP/Confed-external peers */
      if (BGP_PEER_EBGP != peer_sort (peer))
        {
          if (BGP_DEBUG (rfd, RFD))
            zlog_info (&BLG, "[DAMP] bgp_rfd_rt_withdraw(): Non "
                       "EBGP Peer, no dampening reqd");
          ret = 0;
          goto EXIT;
        }

      /* Now check for RFD-CB configured for address-family */
      ret = bgp_rfd_cb_lookup (bgp, afi, safi, rn, binfo, &rfd_cb);

      if (ret || ! rfd_cb)
        {
          if (BGP_DEBUG (rfd, RFD))
            zlog_info (&BLG, "[DAMP] bgp_rfd_rt_withdraw(): No dampening reqd");
          ret = 0;
          goto EXIT;
        }

      ret = bgp_rfd_hinfo_create (rfd_cb, &rfd_hinfo);
      if (ret || ! rfd_hinfo)
        {
          if (BGP_DEBUG (rfd, RFD))
            zlog_info (&BLG, "[DAMP] bgp_rfd_rt_withdraw(): hinfo create failed");
          ret = -1;
          goto EXIT;
        }

      rfd_hinfo->rfdh_rn = rn;
      rfd_hinfo->rfdh_binfo = binfo;
      binfo->rfd_hinfo = rfd_hinfo;
      *rt_state = BGP_RFD_RT_STATE_USE;
    }
  else
    {
      rfd_cb = rfd_hinfo->rfdh_rfd_cb;

      ret = bgp_rfd_update_penalty (rfd_hinfo, BGP_RFD_RT_EVENT_UNREACH);

      if (ret)
        {
          if (BGP_DEBUG (rfd, RFD))
            zlog_info (&BLG, "[DAMP] bgp_rfd_rt_withdraw():"
                       " Penalty Updation failed for hinfo (%X)", rfd_hinfo);

          bgp_rfd_hinfo_delete (rfd_hinfo);
          *rt_state = BGP_RFD_RT_STATE_USE;
          ret = -1;
          goto EXIT;
        }

      rfd_hinfo->rfdh_flap_count ++;

      /* Switch over to Non-Reuse List */
      if (rfd_hinfo->rfdh_reuse_idx != BGP_RFD_REUSE_LIST_INV_IDX)
        {
          bgp_rfd_reuse_list_remove (rfd_hinfo);
          bgp_rfd_non_reuse_list_insert (rfd_hinfo);
        }

      *rt_state = BGP_RFD_RT_STATE_USE;
    }

  rfd_hinfo->rfdh_rec_event = BGP_RFD_RT_EVENT_UNREACH;

  /*
   * Re-insert into a reuse-list already suppressed.
   * At this point, rfd_hinfo MUST be in Non-Reuse List
   */
  if (rfd_hinfo->rfdh_suppress_time)
    {
      /* Switch over to Reuse List */
      bgp_rfd_non_reuse_list_remove (rfd_hinfo);
      bgp_rfd_reuse_list_insert (rfd_hinfo);

      *rt_state = BGP_RFD_RT_STATE_DAMPED;
    }

EXIT:

  if (BGP_DEBUG (rfd, RFD))
    zlog_info (&BLG, "[DAMP] bgp_rfd_rt_withdraw(): %s, ret=%d",
               BGP_RFD_RT_STATE_STR (*rt_state), ret);

  return ret;
}

/* Record reachability */
s_int32_t
bgp_rfd_rt_update (struct bgp_info *binfo,
                   enum bgp_rfd_rt_state *rt_state)
{
  struct bgp_rfd_hist_info *rfd_hinfo;
  struct bgp_rfd_cb *rfd_cb;
  s_int32_t ret;

  *rt_state = BGP_RFD_RT_STATE_NONE;
  rfd_hinfo = binfo->rfd_hinfo;
  ret = 0;

  if (! rfd_hinfo)
    {
      ret = 0;
      goto EXIT;
    }

  rfd_cb = rfd_hinfo->rfdh_rfd_cb;
  if (! rfd_cb)
    {
      ret = -1;
      goto EXIT;
    }

  ret = bgp_rfd_update_penalty (rfd_hinfo, BGP_RFD_RT_EVENT_REACH);
  if (ret)
    {
      ret = -1;
      goto EXIT;
    }

  rfd_hinfo->rfdh_rec_event = BGP_RFD_RT_EVENT_REACH;

  if (! rfd_hinfo->rfdh_suppress_time
      && rfd_hinfo->rfdh_penalty < rfd_cb->rfd_suppress)
    *rt_state = BGP_RFD_RT_STATE_USE;
  else if (rfd_hinfo->rfdh_suppress_time
           && rfd_hinfo->rfdh_penalty < rfd_cb->rfd_reuse)
    {
      rfd_hinfo->rfdh_suppress_time = 0;

      /* Switch over to Non-Reuse List */
      if (rfd_hinfo->rfdh_reuse_idx != BGP_RFD_REUSE_LIST_INV_IDX)
        {
          bgp_rfd_reuse_list_remove (rfd_hinfo);
          bgp_rfd_non_reuse_list_insert (rfd_hinfo);
        }

      *rt_state = BGP_RFD_RT_STATE_USE;
    }
  else
    {
      if (! rfd_hinfo->rfdh_suppress_time)
        rfd_hinfo->rfdh_suppress_time = pal_time_current (NULL);

      /* Switch over to Reuse List */
      bgp_rfd_non_reuse_list_remove (rfd_hinfo);
      bgp_rfd_reuse_list_insert (rfd_hinfo);

      *rt_state = BGP_RFD_RT_STATE_DAMPED;

      /* increment flap counter */
      rfd_hinfo->rfdh_flap_count++;
    }

  if (rfd_hinfo->rfdh_penalty <= rfd_cb->rfd_penalty_floor)
    {
      *rt_state = BGP_RFD_RT_STATE_USE;
      bgp_rfd_hinfo_delete (rfd_hinfo);
    }


EXIT:

  if (BGP_DEBUG (rfd, RFD))
    zlog_info (&BLG, "[DAMP] bgp_rfd_rt_update(): %s, ret=%d",
               BGP_RFD_RT_STATE_STR (*rt_state), ret);

  return ret;
}

/* Obtain the RFD-CB if configured */
s_int32_t
bgp_rfd_cb_lookup (struct bgp *bgp, afi_t afi, safi_t safi,
                   struct bgp_node *rn, struct bgp_info *binfo,
                   struct bgp_rfd_cb **rfd_cb_p)
{
  route_map_result_t rmap_ret;
  struct bgp_rfd_cfg *rfd_cfg;
  struct bgp_rmap_info brmi;
  struct bgp_info tmp_binfo;
  struct attr tmp_attr;
  s_int32_t ret;
  struct prefix rnp;

  pal_mem_set (&brmi, 0, sizeof (struct bgp_rmap_info));
  pal_mem_set (&tmp_binfo, 0, sizeof (struct bgp_info));
  pal_mem_set (&tmp_attr, 0, sizeof (struct attr));
  *rfd_cb_p = NULL;
  ret = 0;

  rfd_cfg = bgp->rfd_cfg[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];
  if (rfd_cfg && rn && binfo)
    {
      /* Check for route-map match first */
      if (rfd_cfg->rfdg_rmap.name)
        {
          if (rfd_cfg->rfdg_rmap.map)
            {
              tmp_attr = *binfo->attr;
              tmp_binfo.peer = binfo->peer;
              tmp_binfo.attr = &tmp_attr;

              brmi.brmi_type = BGP_RMAP_INFO_REGULAR;
              brmi.brmi_bgp = bgp;
              brmi.brmi_bri = &tmp_binfo;

	      BGP_GET_PREFIX_FROM_NODE (rn);
              rmap_ret = route_map_apply (rfd_cfg->rfdg_rmap.map,
                                          &rnp, &brmi);
              if (rmap_ret == RMAP_MATCH && tmp_binfo.attr->rfd_cb_cfg)
                ret = bgp_rfd_cb_create (rfd_cfg,
                                         tmp_binfo.attr->rfd_cb_cfg,
                                         rfd_cb_p);

              bgp_attr_flush (&tmp_attr);
            }
        }
      /* Now check for non route-map configuration */
      else if (LISTHEAD (rfd_cfg->rfdg_rfd_cb_list))
        *rfd_cb_p = GETDATA (LISTHEAD (rfd_cfg->rfdg_rfd_cb_list));
    }

  return ret;
}

/* BGP RFD Control Block working param computation */
s_int32_t
bgp_rfd_cb_enable (struct bgp_rfd_cb *rfd_cb)
{
  float64_t *tmp_decay_array;
  float64_t reuse_max_ratio;
  float64_t tmp_doub_var;
  float64_t ln_of_half;
  s_int32_t idx;

  if (! rfd_cb)
    return -1;

  if (BGP_DEBUG (rfd, RFD))
    zlog_info (&BLG, "[DAMP] dampening %u %u %u %u %u",
               rfd_cb->rfd_reach_hlife / ONE_MIN_SECOND,
               rfd_cb->rfd_reuse,
               rfd_cb->rfd_suppress,
               rfd_cb->rfd_max_suppress / ONE_MIN_SECOND,
               rfd_cb->rfd_unreach_hlife / ONE_MIN_SECOND);

  ln_of_half = pal_logarithm (0.5);

  /*
   * Compute Max-Penalty Ceiling:
   * NOTE: RFC 2439 has typo. Correction:
   * ceiling = reuse * (exp((T-hold/decay-half-life) * log (2)))
   */
  rfd_cb->rfd_penalty_ceil = rfd_cb->rfd_reuse *
             pal_exponential (((float64_t) rfd_cb->rfd_max_suppress /
                               (float64_t) rfd_cb->rfd_unreach_hlife) *
                              (-ln_of_half));

  if (BGP_DEBUG (rfd, RFD))
    zlog_info (&BLG, "[DAMP] Penalty Ceil = %u",
               rfd_cb->rfd_penalty_ceil);

  /*
   * We retain History record till 'Min non-zero penalty' < (reuse / 2)
   */
  rfd_cb->rfd_penalty_floor = rfd_cb->rfd_reuse / 2;
  if (! rfd_cb->rfd_penalty_floor)
    rfd_cb->rfd_penalty_floor = 1;

  if (BGP_DEBUG (rfd, RFD))
    zlog_info (&BLG, "[DAMP] Penalty Floor = %u",
               rfd_cb->rfd_penalty_floor);

  /*
   * Now we compute Tmax and hence 'reach_decay' and 'unreach_decay'
   * array sizes based on the above assumption.
   */
  /* First, Reach Decay array size */
  tmp_doub_var = pal_logarithm (((float64_t) rfd_cb->rfd_penalty_ceil) /
                                ((float64_t) rfd_cb->rfd_penalty_floor)) *
                 (1.0 / (-ln_of_half));

  if (BGP_DEBUG (rfd, RFD))
    zlog_info (&BLG, "[DAMP] tmp_doub_var = %lf", tmp_doub_var);

  /* Initialize the 'decay arrays' */
  rfd_cb->rfd_nrdecay = (rfd_cb->rfd_reach_hlife * tmp_doub_var) /
                        BGP_RFD_DECAY_TICK;

  if (BGP_DEBUG (rfd, RFD))
    zlog_info (&BLG, "[DAMP] Reach Decay array size (calc) = %u",
               rfd_cb->rfd_nrdecay);

  if (rfd_cb->rfd_nrdecay < 2)
    rfd_cb->rfd_nrdecay = 2;
  else if (rfd_cb->rfd_nrdecay >= BGP_RFD_DECAY_ARY_MAX_SIZE)
    rfd_cb->rfd_nrdecay = BGP_RFD_DECAY_ARY_MAX_SIZE;

  if (BGP_DEBUG (rfd, RFD))
    zlog_info (&BLG, "[DAMP] Reach Decay array size (finl) = %u",
               rfd_cb->rfd_nrdecay);

  /* Now, Un-reach Decay array size */
  rfd_cb->rfd_nudecay = (rfd_cb->rfd_unreach_hlife * tmp_doub_var) /
                        BGP_RFD_DECAY_TICK;

  if (BGP_DEBUG (rfd, RFD))
    zlog_info (&BLG, "[DAMP] Un-Reach Decay array size (calc) = %u",
               rfd_cb->rfd_nudecay);

  if (rfd_cb->rfd_nudecay < 2)
    rfd_cb->rfd_nudecay = 2;
  else if (rfd_cb->rfd_nudecay >= BGP_RFD_DECAY_ARY_MAX_SIZE)
    rfd_cb->rfd_nudecay = BGP_RFD_DECAY_ARY_MAX_SIZE;

  if (BGP_DEBUG (rfd, RFD))
    zlog_info (&BLG, "[DAMP] Reach Decay array size (finl) = %u",
               rfd_cb->rfd_nrdecay);

  tmp_decay_array = XCALLOC (MTYPE_BGP_RFD_DECAY_ARRAY, sizeof (float64_t) *
                             (rfd_cb->rfd_nrdecay + rfd_cb->rfd_nudecay));
  if (! tmp_decay_array)
    {
      zlog_err (&BLG, "[DAMP] bgp_rfd_cb_enable():"
                " Cannot allocate memory (%d) @ %s:%d",
                (rfd_cb->rfd_nrdecay + rfd_cb->rfd_nudecay) *
                sizeof (float32_t), __FILE__, __LINE__);

      return -1;
    }
  rfd_cb->rfd_rdecay = tmp_decay_array;
  rfd_cb->rfd_udecay = tmp_decay_array + rfd_cb->rfd_nrdecay;

  /* Pre-compute values into reachablity-decay-array */
  rfd_cb->rfd_rdecay[0] = 1.0;
  rfd_cb->rfd_rdecay[1] = pal_exponential ((1.0 /
                          ((float32_t)rfd_cb->rfd_reach_hlife /
                           BGP_RFD_DECAY_TICK)) * ln_of_half);
  for (idx = 2; idx < rfd_cb->rfd_nrdecay; idx++)
    rfd_cb->rfd_rdecay[idx] = rfd_cb->rfd_rdecay[idx - 1] *
                              rfd_cb->rfd_rdecay[1];

  /* Pre-compute values into unreachablity-decay-array */
  rfd_cb->rfd_udecay[0] = 1.0;
  rfd_cb->rfd_udecay[1] = pal_exponential ((1.0 /
                          ((float32_t)rfd_cb->rfd_unreach_hlife /
                           BGP_RFD_DECAY_TICK)) * ln_of_half);
  for (idx = 2; idx < rfd_cb->rfd_nudecay; idx++)
    rfd_cb->rfd_udecay[idx] = rfd_cb->rfd_udecay[idx - 1] *
                              rfd_cb->rfd_udecay[1];

  /* Reachability reuse-index-array computations */
  /* Reuse max-ratio */
  reuse_max_ratio = BGP_MIN (((float64_t)rfd_cb->rfd_penalty_ceil /
                              (float64_t)rfd_cb->rfd_reuse),
            pal_exponential ((1.0 /
                               ((float64_t)rfd_cb->rfd_reach_hlife /
                                (float64_t)(BGP_RFD_REUSE_LIST_SIZE *
                                            BGP_RFD_REUSE_TICK))) *
                             (-ln_of_half)));
  /* Reuse scale-factor */
  rfd_cb->rfd_rscale_factor = ((float64_t)BGP_RFD_REUSE_IDX_ARY_SIZE /
                               (reuse_max_ratio - 1.0));
  /* Pre-compute values into reuse-index-array */
  for (idx = 0; idx < BGP_RFD_REUSE_IDX_ARY_SIZE; idx++)
    {
      rfd_cb->rfd_reach_reuse_idx_ary[idx] =
        ((float64_t)(rfd_cb->rfd_reach_hlife / BGP_RFD_REUSE_TICK)) *
        pal_logarithm (1.0 / (1.0 + (((float64_t)idx) /
                              rfd_cb->rfd_rscale_factor))) / (ln_of_half);
    }

  if (BGP_DEBUG (rfd, RFD))
    {
      zlog_info (&BLG, "[DAMP] Reach Reuse Idx: max_ratio = %lf",
                 reuse_max_ratio);
      zlog_info (&BLG, "[DAMP]                  scale-factor = %lf",
                 rfd_cb->rfd_rscale_factor);
      zlog_info (&BLG, "[DAMP]                  array size = %u",
                 BGP_RFD_REUSE_IDX_ARY_SIZE);
    }

  /* Un-reachability reuse-index-array computations */
  /* Reuse max-ratio */
  reuse_max_ratio = BGP_MIN (((float64_t)rfd_cb->rfd_penalty_ceil /
                              (float64_t)rfd_cb->rfd_reuse),
            pal_exponential (((float64_t)(BGP_RFD_REUSE_LIST_SIZE *
                                          BGP_RFD_REUSE_TICK) /
                              (float64_t)rfd_cb->rfd_unreach_hlife) *
                             (-ln_of_half)));
  /* Reuse scale-factor */
  rfd_cb->rfd_uscale_factor = BGP_RFD_REUSE_IDX_ARY_SIZE /
                              (reuse_max_ratio - 1);
  /* Pre-compute values into reuse-index-array */
  for (idx = 0; idx < BGP_RFD_REUSE_IDX_ARY_SIZE; idx++)
    {
      rfd_cb->rfd_unreach_reuse_idx_ary[idx] =
        ((float64_t)(rfd_cb->rfd_unreach_hlife / BGP_RFD_REUSE_TICK)) *
        pal_logarithm (1.0 / (1.0 + (((float64_t)idx) /
                              rfd_cb->rfd_uscale_factor))) / (ln_of_half);
    }

  if (BGP_DEBUG (rfd, RFD))
    {
      zlog_info (&BLG, "[DAMP] Un-Reach Reuse Idx: max_ratio = %lf",
                 reuse_max_ratio);
      zlog_info (&BLG, "[DAMP]                     scale-factor = %lf",
                 rfd_cb->rfd_uscale_factor);
      zlog_info (&BLG, "[DAMP]                     array size = %u",
                 BGP_RFD_REUSE_IDX_ARY_SIZE);
    }

  return 0;
}

/* BGP RFD Control Block - cease operation */
s_int32_t
bgp_rfd_cb_disable (struct bgp_rfd_cb *rfd_cb)
{
  struct bgp_rfd_hist_info *rfd_hinfo;
  struct bgp_rfd_hist_info *rfd_hinfo_next;

  if (! rfd_cb)
    return -1;

  /* Release all associated history information */
  for (rfd_hinfo = rfd_cb->rfd_hinfo_list;
       rfd_hinfo;
       rfd_hinfo = rfd_hinfo_next)
    {
      rfd_hinfo_next = rfd_hinfo->rfdh_rfdcb_next;

      bgp_rfd_hinfo_delete (rfd_hinfo);
    }

  /* Free decay array */
  if (rfd_cb->rfd_rdecay)
    {
      XFREE (MTYPE_BGP_RFD_DECAY_ARRAY, rfd_cb->rfd_rdecay);
      rfd_cb->rfd_rdecay = NULL;
    }

  /* Zero-out necessary parameters */
  pal_mem_set (&rfd_cb->rfd_config, 0, sizeof (struct bgp_rfd_cb_cfg_param));
  rfd_cb->rfd_penalty_ceil = 0;
  rfd_cb->rfd_penalty_floor = 0;
  rfd_cb->rfd_nrdecay = 0;
  rfd_cb->rfd_rdecay = NULL;
  rfd_cb->rfd_nudecay = 0;
  rfd_cb->rfd_udecay = NULL;
  pal_mem_set (rfd_cb->rfd_reach_reuse_idx_ary, 0,
               sizeof (u_int32_t) * BGP_RFD_REUSE_IDX_ARY_SIZE);
  rfd_cb->rfd_rscale_factor = 0;
  pal_mem_set (rfd_cb->rfd_unreach_reuse_idx_ary, 0,
               sizeof (u_int32_t) * BGP_RFD_REUSE_IDX_ARY_SIZE);
  rfd_cb->rfd_uscale_factor = 0;
  rfd_cb->rfd_hinfo_list = NULL;

  return 0;
}

/* Restart an RFD Control Block */
s_int32_t
bgp_rfd_cb_restart (struct bgp_rfd_cb *rfd_cb)
{
  struct bgp_rfd_cb_cfg_param rfd_cb_cfg;
  s_int32_t ret;

  ret = 0;

  if (! rfd_cb)
    return -1;

  /* Save the config params */
  rfd_cb_cfg = rfd_cb->rfd_config;

  /* Disable the RFD CB */
  bgp_rfd_cb_disable (rfd_cb);

  /* Restore the config params */
  rfd_cb->rfd_config = rfd_cb_cfg;

  /* Re-enable the RFD CB */
  ret = bgp_rfd_cb_enable (rfd_cb);

  return ret;
}

/* Clear Flap Statistics RFD Control Block routes */
s_int32_t
bgp_rfd_cb_clear_flap_stats (struct bgp_rfd_cb *rfd_cb)
{
  struct bgp_rfd_hist_info *rfd_hinfo;

  if (! rfd_cb)
    return -1;

  /* Release all associated history information */
  for (rfd_hinfo = rfd_cb->rfd_hinfo_list;
       rfd_hinfo;
       rfd_hinfo = rfd_hinfo->rfdh_rfdcb_next)
    bgp_rfd_hinfo_clear_flap_stats (rfd_hinfo);

  return 0;
}

/* Create / Re-configure a RFD Control Block */
s_int32_t
bgp_rfd_cb_create (struct bgp_rfd_cfg *rfd_cfg,
                   struct bgp_rfd_cb_cfg_param *rfd_cb_cfg,
                   struct bgp_rfd_cb **rfd_cb_p)
{
  struct bgp_rfd_cb *rfd_cb;
  struct listnode *nn;
  s_int32_t ret;

  if (! rfd_cfg || ! rfd_cb_cfg || ! rfd_cb_p)
    return -1;

  *rfd_cb_p = NULL;
  rfd_cb = NULL;

  LIST_LOOP (rfd_cfg->rfdg_rfd_cb_list, rfd_cb, nn)
    if (rfd_cb->rfd_reach_hlife == rfd_cb_cfg->rfdc_reach_hlife
        && rfd_cb->rfd_reuse == rfd_cb_cfg->rfdc_reuse
        && rfd_cb->rfd_suppress == rfd_cb_cfg->rfdc_suppress
        && rfd_cb->rfd_max_suppress == rfd_cb_cfg->rfdc_max_suppress
        && rfd_cb->rfd_unreach_hlife == rfd_cb_cfg->rfdc_unreach_hlife)
      {
        *rfd_cb_p = rfd_cb;
        return 0;
      }

  if (LISTHEAD (rfd_cfg->rfdg_rfd_cb_list))
    rfd_cb = GETDATA (LISTHEAD (rfd_cfg->rfdg_rfd_cb_list));

  /* If RMAP is not configured, modify existing 'rfd_cb' */
  if (rfd_cb && ! rfd_cfg->rfdg_rmap.name)
    bgp_rfd_cb_disable (rfd_cb);
  else
    {
      rfd_cb = XCALLOC (MTYPE_BGP_RFD_CB, sizeof (struct bgp_rfd_cb));
      if (! rfd_cb)
        {
          zlog_err (&BLG, "[DAMP] bgp_rfd_cb_create():"
                    " Cannot allocate memory (%d) @ %s:%d",
                    sizeof (struct bgp_rfd_cb), __FILE__, __LINE__);
          return -1;
        }

      if (! listnode_add (rfd_cfg->rfdg_rfd_cb_list, rfd_cb))
        {
          zlog_err (&BLG, "[DAMP] bgp_rfd_cb_create():"
                    " listnode_add () failed!");

          XFREE (MTYPE_BGP_RFD_CB, rfd_cb);
          return -1;
        }

      rfd_cb->rfd_cfg = rfd_cfg;
    }

  /* Copy the config parameters */
  rfd_cb->rfd_reach_hlife = rfd_cb_cfg->rfdc_reach_hlife;
  rfd_cb->rfd_reuse = rfd_cb_cfg->rfdc_reuse;
  rfd_cb->rfd_suppress = rfd_cb_cfg->rfdc_suppress;
  rfd_cb->rfd_max_suppress = rfd_cb_cfg->rfdc_max_suppress;
  rfd_cb->rfd_unreach_hlife = rfd_cb_cfg->rfdc_unreach_hlife;

  ret = bgp_rfd_cb_enable (rfd_cb);
  if (ret)
    {
      zlog_err (&BLG, "[DAMP] bgp_rfd_cb_create():"
                " Failed to enable RFD CB, deleting RFD CB(%X)...",
                rfd_cb);

      bgp_rfd_cb_delete (rfd_cb);
      return -1;
    }

  /* Start the reuse timers if not running */
  BGP_TIMER_ON (&BLG, BGP_VR.t_rfd_reuse, NULL,
                bgp_rfd_reuse_timer, BGP_RFD_REUSE_TICK);

  BGP_TIMER_ON (&BLG, BGP_VR.t_rfd_non_reuse, NULL,
                bgp_rfd_non_reuse_timer, BGP_RFD_NON_REUSE_TICK);

  *rfd_cb_p = rfd_cb;

  return 0;
}

/* Delete a RFD Control Block */
s_int32_t
bgp_rfd_cb_delete (struct bgp_rfd_cb *rfd_cb)
{
  struct bgp_rfd_cfg *rfd_cfg;

  if (! rfd_cb)
    return -1;

  rfd_cfg = rfd_cb->rfd_cfg;

  if (! rfd_cfg || ! rfd_cfg->rfdg_rfd_cb_list)
    return -1;

  listnode_delete (rfd_cfg->rfdg_rfd_cb_list, rfd_cb);
  bgp_rfd_cb_disable (rfd_cb);

  XFREE (MTYPE_BGP_RFD_CB, rfd_cb);

  return 0;
}

/* Create / Re-configure a RFD Configuration Block */
s_int32_t
bgp_rfd_cfg_create (struct bgp *bgp, afi_t afi, safi_t safi,
                    struct bgp_rfd_cb_cfg_param *rfd_cb_cfg,
                    s_int8_t *rmap_name)
{
  struct bgp_rfd_cfg *rfd_cfg;
  route_map_result_t rmap_ret;
  struct prefix dummy_prefix;
  struct bgp_rfd_cb *rfd_cb;
  struct bgp_info tmp_binfo;
  struct bgp_rmap_info brmi;
  struct listnode *next;
  struct listnode *nn;
  s_int32_t ret;

  pal_mem_set (&dummy_prefix, 0, sizeof (struct prefix));
  pal_mem_set (&tmp_binfo, 0, sizeof (struct bgp_info));
  pal_mem_set (&brmi, 0, sizeof (struct bgp_rmap_info));
  ret = 0;

  /* Validate Parameters */
  if (! bgp
      || (rfd_cb_cfg && rmap_name)
      || (! rfd_cb_cfg && ! rmap_name))
    {
      zlog_err (&BLG, "[DAMP] bgp_rfd_cfg_create(): Invalid param set");
      ret = -1;
      goto EXIT;
    }

  rfd_cfg = bgp->rfd_cfg [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (! rfd_cfg)
    {
      rfd_cfg = XCALLOC (MTYPE_BGP_RFD_CFG, sizeof (struct bgp_rfd_cfg));
      if (! rfd_cfg)
        {
          zlog_err (&BLG, "[DAMP] bgp_rfd_cfg_create():"
                    " Cannot allocate memory (%d) @ %s:%d",
                    sizeof (struct bgp_rfd_cfg), __FILE__, __LINE__);
          ret = -1;
          goto EXIT;
        }

      rfd_cfg->rfdg_rfd_cb_list = list_new ();

      if (! rfd_cfg->rfdg_rfd_cb_list)
        {
          zlog_err (&BLG, "[DAMP] bgp_rfd_cfg_create():"
                    " Cannot allocate memory (%d) @ %s:%d",
                    sizeof (struct list), __FILE__, __LINE__);

          XFREE (MTYPE_BGP_RFD_CFG, rfd_cfg);

          ret = -1;
          goto EXIT;
        }
    }

  bgp->rfd_cfg [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)] = rfd_cfg;
  rfd_cfg->rfdg_afi = afi;
  rfd_cfg->rfdg_safi = safi;

  if (rmap_name)
    {
      /* Delete existing RFD Control Block(s) */
      for (nn = LISTHEAD (rfd_cfg->rfdg_rfd_cb_list); nn; nn = next)
        {
          next = nn->next;
          if ((rfd_cb = GETDATA (nn)))
            ret = bgp_rfd_cb_delete (rfd_cb);
        }

      if (rfd_cfg->rfdg_rmap.name)
        XFREE (MTYPE_TMP, rfd_cfg->rfdg_rmap.name);
      rfd_cfg->rfdg_rmap.name = XSTRDUP (MTYPE_TMP, rmap_name);
      rfd_cfg->rfdg_rmap.map = route_map_lookup_by_name (BGP_VR.owning_ivr,
                                                         rmap_name);

      if (rfd_cfg->rfdg_rmap.map)
        {
          tmp_binfo.attr = XCALLOC (MTYPE_TMP, sizeof (struct attr));
          if (! tmp_binfo.attr)
            {
              zlog_err (&BLG, "[DAMP] bgp_rfd_cfg_create():"
                        " Cannot allocate memory (%d) @ %s:%d",
                        sizeof (struct attr), __FILE__, __LINE__);

              ret = -1;
              goto EXIT;
            }

          /* Setup Default Attribute */
          bgp_attr_default_set (tmp_binfo.attr, BGP_ORIGIN_INCOMPLETE);

          brmi.brmi_type = BGP_RMAP_INFO_REGULAR;
          brmi.brmi_bgp = bgp;
          brmi.brmi_bri = &tmp_binfo;

          rmap_ret = route_map_apply (rfd_cfg->rfdg_rmap.map,
                                      &dummy_prefix, &brmi);
          if (rmap_ret == RMAP_MATCH
              && tmp_binfo.attr->rfd_cb_cfg)
            ret = bgp_rfd_cb_create (rfd_cfg,
                                     tmp_binfo.attr->rfd_cb_cfg,
                                     &rfd_cb);

          XFREE (MTYPE_TMP, tmp_binfo.attr);
        }
    }
  else if (rfd_cb_cfg)
    ret = bgp_rfd_cb_create (rfd_cfg, rfd_cb_cfg, &rfd_cb);

EXIT:

  return ret;
}

/* Delete a RFD Configuration Block */
s_int32_t
bgp_rfd_cfg_delete (struct bgp *bgp, afi_t afi, safi_t safi)
{
  struct bgp_rfd_cfg *rfd_cfg;
  struct bgp_rfd_cb *rfd_cb;
  struct listnode *next;
  struct listnode *nn;
  s_int32_t ret;

  ret = 0;

  if (! bgp)
    {
      zlog_err (&BLG, "[DAMP] bgp_rfd_cfg_delete(): Invalid param set");
      ret = -1;
      goto EXIT;
    }

  rfd_cfg = bgp->rfd_cfg [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (! rfd_cfg)
    {
      zlog_info (&BLG, "[DAMP] bgp_rfd_cfg_delete():"
                 " No Dampening Configured for address-family");
      ret = -1;
      goto EXIT;
    }

  if (rfd_cfg->rfdg_rmap.name)
    XFREE (MTYPE_TMP, rfd_cfg->rfdg_rmap.name);

  /* Delete existing RFD Control Block(s) */
  for (nn = LISTHEAD (rfd_cfg->rfdg_rfd_cb_list); nn; nn = next)
    {
      next = nn->next;
      if ((rfd_cb = GETDATA (nn)))
        ret = bgp_rfd_cb_delete (rfd_cb);
    }
  list_free (rfd_cfg->rfdg_rfd_cb_list);

  XFREE (MTYPE_BGP_RFD_CFG, rfd_cfg);

  bgp->rfd_cfg [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)] = NULL;

EXIT:

  return ret;
}

/* Parser for values entered after 'set dampening' route-map cmd */
s_int32_t
bgp_rfd_str2cfgparams (s_int8_t *str,
                       struct bgp_rfd_cb_cfg_param *rfd_cb_cfg)
{
  u_int32_t tmp_u32_val;
  u_int8_t *curr_p;

  /* Sanity checks */
  if (! str || ! rfd_cb_cfg)
    return -1;

  curr_p = str;

  /* Check and obtain Reach Half-life value */
  tmp_u32_val = pal_strtou32 (curr_p, (char **)((char *) &curr_p), 10);
  while (pal_char_isspace ((u_int32_t) *curr_p)) curr_p++;
  if ((! *curr_p == '\0') && ! pal_char_isdigit ((u_int32_t) *curr_p))
    {
      return -1;
    }

  if (tmp_u32_val < BGP_RFD_REACH_HLIFE_MIN_VAL
      || tmp_u32_val > BGP_RFD_REACH_HLIFE_MAX_VAL)
    {
      return -1;
    }

  rfd_cb_cfg->rfdc_reach_hlife = tmp_u32_val * ONE_MIN_SECOND;
  rfd_cb_cfg->rfdc_max_suppress = rfd_cb_cfg->rfdc_reach_hlife * 4;
  rfd_cb_cfg->rfdc_unreach_hlife = rfd_cb_cfg->rfdc_reach_hlife;

  if (*curr_p == '\0')
    return 0;

  /* Check and obtain Reuse value */
  tmp_u32_val = pal_strtou32 (curr_p, (char **)((char *) &curr_p), 10);
  while (pal_char_isspace ((u_int32_t) *curr_p)) curr_p++;
  if (! pal_char_isdigit ((u_int32_t) *curr_p))
    {
      return -1;
    }

  if (tmp_u32_val < BGP_RFD_REUSE_MIN_VAL
      || tmp_u32_val > BGP_RFD_REUSE_MAX_VAL)
    {
      return -1;
    }

  rfd_cb_cfg->rfdc_reuse = tmp_u32_val;

  /* Check and obtain Suppress value */
  tmp_u32_val = pal_strtou32 (curr_p, (char **)((char *) &curr_p), 10);
  while (pal_char_isspace ((u_int32_t) *curr_p)) curr_p++;
  if (! pal_char_isdigit ((u_int32_t) *curr_p))
    {
      return -1;
    }

  if (tmp_u32_val < BGP_RFD_SUPPRESS_MIN_VAL
      || tmp_u32_val > BGP_RFD_SUPPRESS_MAX_VAL)
    {
      return -1;
    }

  rfd_cb_cfg->rfdc_suppress = tmp_u32_val;
  if (rfd_cb_cfg->rfdc_suppress < rfd_cb_cfg->rfdc_reuse)
    {
      return -1;
    }

  /* Check and obtain Max-Suppress value */
  tmp_u32_val = pal_strtou32 (curr_p, (char **)((char *) &curr_p), 10);
  while (pal_char_isspace ((u_int32_t) *curr_p)) curr_p++;
  if ((! *curr_p == '\0') && ! pal_char_isdigit ((u_int32_t) *curr_p))
    {
      return -1;
    }

  if (tmp_u32_val < BGP_RFD_MAX_SUPPRESS_MIN_VAL
      || tmp_u32_val > BGP_RFD_MAX_SUPPRESS_MAX_VAL)
    {
      return -1;
    }

  rfd_cb_cfg->rfdc_max_suppress = tmp_u32_val * ONE_MIN_SECOND;
  if (rfd_cb_cfg->rfdc_max_suppress <
      rfd_cb_cfg->rfdc_reach_hlife)
    {
      return -1;
    }

  rfd_cb_cfg->rfdc_unreach_hlife = rfd_cb_cfg->rfdc_reach_hlife;

  if (*curr_p == '\0')
    return 0;

  /* Check and obtain Unreach Half-Life value */
  tmp_u32_val = pal_strtou32 (curr_p, (char **)((char *) &curr_p), 10);
  while (pal_char_isspace ((u_int32_t) *curr_p)) curr_p++;
  if (! *curr_p == '\0')
    {
      return -1;
    }

  if (tmp_u32_val < BGP_RFD_UREACH_HLIFE_MIN_VAL
      || tmp_u32_val > BGP_RFD_UREACH_HLIFE_MAX_VAL)
    {
      return -1;
    }

  rfd_cb_cfg->rfdc_unreach_hlife = tmp_u32_val * ONE_MIN_SECOND;
  if (rfd_cb_cfg->rfdc_unreach_hlife <
      rfd_cb_cfg->rfdc_reach_hlife)
    {
      return -1;
    }

  return 0;
}

/* Display running-config for an address-family */
s_int32_t
bgp_rfd_config_write (struct cli *cli, struct bgp *bgp,
                      afi_t afi, safi_t safi, u_int32_t *write)
{
  struct bgp_rfd_cfg *rfd_cfg;
  struct bgp_rfd_cb *rfd_cb;

  rfd_cfg = bgp->rfd_cfg [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (rfd_cfg)
    {
      if (rfd_cfg->rfdg_rmap.name)
        {
          /* "address-family" header display.  */
          bgp_config_write_family_header (cli, afi, safi, write);

          cli_out (cli, " bgp dampening route-map %s\n",
                   rfd_cfg->rfdg_rmap.name);
        }
      else if (LISTHEAD (rfd_cfg->rfdg_rfd_cb_list)
               && (rfd_cb = GETDATA (LISTHEAD (rfd_cfg->rfdg_rfd_cb_list))))
        {

          /* "address-family" header display.  */
          bgp_config_write_family_header (cli, afi, safi, write);

          if ((rfd_cb->rfd_reach_hlife / ONE_MIN_SECOND ==
               BGP_RFD_REACH_HLIFE_DEF_VAL)
              && rfd_cb->rfd_reuse == BGP_RFD_REUSE_DEF_VAL
              && rfd_cb->rfd_suppress == BGP_RFD_SUPPRESS_DEF_VAL
              && ((rfd_cb->rfd_max_suppress / ONE_MIN_SECOND ==
                   BGP_RFD_MAX_SUPPRESS_DEF_VAL)
                  || (rfd_cb->rfd_max_suppress ==
                      rfd_cb->rfd_reach_hlife * 4))
              && ((rfd_cb->rfd_unreach_hlife / ONE_MIN_SECOND ==
                   BGP_RFD_UREACH_HLIFE_DEF_VAL)
                  || (rfd_cb->rfd_unreach_hlife ==
                      rfd_cb->rfd_reach_hlife)))
            cli_out (cli, " bgp dampening\n");
          else if ((rfd_cb->rfd_reach_hlife / ONE_MIN_SECOND !=
                    BGP_RFD_REACH_HLIFE_DEF_VAL)
                   && rfd_cb->rfd_reuse == BGP_RFD_REUSE_DEF_VAL
                   && rfd_cb->rfd_suppress == BGP_RFD_SUPPRESS_DEF_VAL
                   && ((rfd_cb->rfd_max_suppress / ONE_MIN_SECOND ==
                        BGP_RFD_MAX_SUPPRESS_DEF_VAL)
                       || (rfd_cb->rfd_max_suppress ==
                           rfd_cb->rfd_reach_hlife * 4))
                   && ((rfd_cb->rfd_unreach_hlife / ONE_MIN_SECOND ==
                        BGP_RFD_UREACH_HLIFE_DEF_VAL)
                       || (rfd_cb->rfd_unreach_hlife ==
                           rfd_cb->rfd_reach_hlife)))
            cli_out (cli, " bgp dampening %d\n",
                     rfd_cb->rfd_reach_hlife / ONE_MIN_SECOND);
          else if (((rfd_cb->rfd_unreach_hlife / ONE_MIN_SECOND) ==
                    BGP_RFD_UREACH_HLIFE_DEF_VAL)
                   || (rfd_cb->rfd_unreach_hlife ==
                           rfd_cb->rfd_reach_hlife))
            cli_out (cli, " bgp dampening %d %d %d %d\n",
                     rfd_cb->rfd_reach_hlife / ONE_MIN_SECOND,
                     rfd_cb->rfd_reuse,
                     rfd_cb->rfd_suppress,
                     rfd_cb->rfd_max_suppress / ONE_MIN_SECOND);
          else
            cli_out (cli, " bgp dampening %d %d %d %d %d\n",
                     rfd_cb->rfd_reach_hlife / ONE_MIN_SECOND,
                     rfd_cb->rfd_reuse,
                     rfd_cb->rfd_suppress,
                     rfd_cb->rfd_max_suppress / ONE_MIN_SECOND,
                     rfd_cb->rfd_unreach_hlife / ONE_MIN_SECOND);
        }
    }

  return 0;
}

/* Display Configured RFD-CB parameters for an address-family */
s_int32_t
bgp_rfd_config_show (struct cli *cli, struct bgp *bgp,
                     afi_t afi, safi_t safi)
{
  struct bgp_rfd_cfg *rfd_cfg;
  struct bgp_rfd_cb *rfd_cb;
  struct listnode *nn;

  rfd_cb = NULL;

  rfd_cfg = bgp->rfd_cfg [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (rfd_cfg)
    {
      cli_out (cli, "\n");

      if (LISTHEAD (rfd_cfg->rfdg_rfd_cb_list))
        rfd_cb = GETDATA (LISTHEAD (rfd_cfg->rfdg_rfd_cb_list));

      if (rfd_cfg->rfdg_rmap.name)
        cli_out (cli, " dampening route-map %s\n",
                 rfd_cfg->rfdg_rmap.name);
      else if (rfd_cb)
        cli_out (cli, " dampening %u %u %u %u %u\n",
                 rfd_cb->rfd_reach_hlife / ONE_MIN_SECOND,
                 rfd_cb->rfd_reuse,
                 rfd_cb->rfd_suppress,
                 rfd_cb->rfd_max_suppress / ONE_MIN_SECOND,
                 rfd_cb->rfd_unreach_hlife / ONE_MIN_SECOND);
      else
        cli_out (cli, " dampening ?\n");

      if (rfd_cb)
        cli_out (cli, " Dampening Control Block(s):\n");

      LIST_LOOP (rfd_cfg->rfdg_rfd_cb_list, rfd_cb, nn)
        {
          cli_out (cli, "  Reachability Half-Life time    : %u min\n",
                   rfd_cb->rfd_reach_hlife / ONE_MIN_SECOND);
          cli_out (cli, "  Reuse penalty                  : %u\n",
                   rfd_cb->rfd_reuse);
          cli_out (cli, "  Suppress penalty               : %u\n",
                   rfd_cb->rfd_suppress);
          cli_out (cli, "  Max suppress time              : %u min\n",
                   rfd_cb->rfd_max_suppress / ONE_MIN_SECOND);
          cli_out (cli, "  Un-reachability Half-Life time : %u min\n",
                   rfd_cb->rfd_unreach_hlife / ONE_MIN_SECOND);
          cli_out (cli, "  Max penalty (ceil)             : %u\n",
                   rfd_cb->rfd_penalty_ceil);
          cli_out (cli, "  Min penalty (floor)            : %u\n",
                   rfd_cb->rfd_penalty_floor);
          cli_out (cli, "\n");
        }
    }

  return 0;
}

