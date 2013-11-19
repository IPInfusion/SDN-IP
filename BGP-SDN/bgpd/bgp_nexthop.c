/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/*********************************************************************/
/* FILE       : bgp_nexthop.c                                        */
/* PURPOSE    : This file contains 'BGP NLRI Nexthop' related        */
/*              function definitions.                                */
/* SUB-MODULE : BGP Next-Hop                                         */
/* NAME-TAG   : 'bnh_' (BGP Next-Hop)                                */
/*********************************************************************/

s_int32_t
bnh_network_scan_afi (struct bgp *bgp, afi_t afi)
{
  struct bgp_static *bstatic;
  struct bgp_peer *peer;
  struct listnode *nn;
  struct bgp_node *rn;
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;
  struct prefix rnp;

  baai = BGP_AFI2BAAI (afi);
  ret = 0;

  /* Scan and validate all static network routes */
  for (rn = bgp_table_top (bgp->route [baai][BSAI_UNICAST]);
       rn; rn = bgp_route_next (rn))
    {
      if (! (bstatic = rn->info))
        continue;

      BGP_GET_PREFIX_FROM_NODE(rn);
      
      bgp_static_network_update (bgp, &rnp, bstatic,
                                 afi, SAFI_UNICAST, PAL_FALSE);
    }

  /* Scan and validate default routes (once for each AFI-SAFI) */
  for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
    LIST_LOOP (bgp->peer_list, peer, nn)
      if (CHECK_FLAG (peer->af_flags [baai][bsai],
                      PEER_FLAG_DEFAULT_ORIGINATE))
        {
          /* Send default route only if the PEER_FLAG_DEFAULT_ORIGINATE flag
             for this peer is set. */
          bgp_peer_default_originate (peer, afi, BGP_BSAI2SAFI (bsai),
                                      PAL_FALSE);
        }

  return ret;
}

/* BGP Network Routes Scan */
s_int32_t
bnh_network_scan (struct thread *t_network_scan)
{
  struct lib_globals *blg;
  struct bgp *bgp;
  s_int32_t ret;

  ret = 0;
  bgp = THREAD_ARG (t_network_scan);
  blg = THREAD_GLOB (t_network_scan);

  if (! blg || &BLG != blg || ! bgp)
    {
      ret = -1;
      goto EXIT;
    }

  bgp->t_network_scan = NULL;

  BGP_SET_VR_CONTEXT (&BLG, bgp->owning_bvr);

  if (BGP_DEBUG (normal, NORMAL))
    zlog_info (&BLG, "[RIB] Scanning BGP Network Routes...");

  bnh_network_scan_afi (bgp, AFI_IP);

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    bnh_network_scan_afi (bgp, AFI_IP6);
#endif /* HAVE_IPV6 */

  if (bgp->network_scan_interval)
    BGP_TIMER_ON (&BLG, bgp->t_network_scan, bgp, bnh_network_scan,
                  bgp->network_scan_interval);

EXIT:

  return ret;
}

/* BGP RIB Scan and Network Scan Initialization */
s_int32_t
bnh_scan_init (struct bgp *bgp)
{
  if (! bgp)
    {
      return -1;
    }

  bgp->network_scan_interval = BGP_NETWORK_SCAN_INTERVAL_DEFAULT;

  /* BGP Network Scan Timer */
  if (bgp->network_scan_interval)
    BGP_TIMER_ON (&BLG, bgp->t_network_scan, bgp, bnh_network_scan,
                  bgp->network_scan_interval);

  return 0;
}

/* BGP RIB Scan and Network Scan Un-initialization */
s_int32_t
bnh_scan_uninit (struct bgp *bgp)
{
  if (! bgp)
    {
      return -1;
    }

  /* Stop BGP Network Scan Timer */
  BGP_TIMER_OFF (bgp->t_network_scan);

  return 0;
}
