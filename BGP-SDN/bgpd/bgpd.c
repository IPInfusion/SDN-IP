/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */
#include <bgp_incl.h>
#include <bgp_community.h>
struct bgp_peer_flag_action peer_flag_action_list[] =
  {
    { PEER_FLAG_PASSIVE,                  0, peer_change_reset },
    { PEER_FLAG_SHUTDOWN,                 0, peer_change_reset },
    { PEER_FLAG_DONT_CAPABILITY,          0, peer_change_none },
    { PEER_FLAG_COLLIDE_ESTABLISHED,      0, peer_change_none },
    { PEER_FLAG_OVERRIDE_CAPABILITY,      0, peer_change_none },
    { PEER_FLAG_STRICT_CAP_MATCH,         0, peer_change_none },
    { PEER_FLAG_NO_ROUTE_REFRESH_CAP,     0, peer_change_reset },
    { PEER_FLAG_DYNAMIC_CAPABILITY,       0, peer_change_reset },
    { PEER_FLAG_ENFORCE_MULTIHOP,         0, peer_change_reset },
    { 0, 0, 0 }
  };
 
struct bgp_peer_flag_action peer_af_flag_action_list[] =
  {
    { PEER_FLAG_NEXTHOP_SELF,             1, peer_change_none },
    { PEER_FLAG_SEND_COMMUNITY,           1, peer_change_reset_out },
    { PEER_FLAG_SEND_EXT_COMMUNITY,       1, peer_change_reset_out },
    { PEER_FLAG_SOFT_RECONFIG,            0, peer_change_reset_in },
    { PEER_FLAG_REFLECTOR_CLIENT,         1, peer_change_reset },
    { PEER_FLAG_RSERVER_CLIENT,           1, peer_change_reset },
    { PEER_FLAG_AS_PATH_UNCHANGED,        1, peer_change_reset_out },
    { PEER_FLAG_NEXTHOP_UNCHANGED,        1, peer_change_reset_out },
    { PEER_FLAG_MED_UNCHANGED,            1, peer_change_reset_out },
    { PEER_FLAG_REMOVE_PRIVATE_AS,        1, peer_change_reset_out },
    { PEER_FLAG_ALLOWAS_IN,               0, peer_change_reset_in },
    { PEER_FLAG_ORF_PREFIX_SM,            1, peer_change_reset },
    { PEER_FLAG_ORF_PREFIX_RM,            1, peer_change_reset },
    { PEER_FLAG_AS_OVERRIDE,              0, peer_change_reset },
    { PEER_FLAG_SITE_ORIGIN,              0, peer_change_reset },
    { PEER_FLAG_EBGP_VPN_ALLOW,           1, peer_change_none },
    { 0, 0, 0 }
  };

/* BGP-VR Global Options Flags Manipulation Functions */
pal_inline s_int32_t
bgp_option_set (u_int32_t flag)
{
  struct bgp *bgp;
  s_int32_t ret;

  ret = BGP_API_SET_SUCCESS;
  bgp = bgp_lookup_default ();

  if (flag == BGP_OPT_DISABLE_ADJ_OUT
      && ! CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_DISABLE_ADJ_OUT)
      && (bgp && bgp->as))
     ret = BGP_API_SET_ERR_ADJ_OUT_DYNAMIC;
  
  else if ((flag == BGP_OPT_MULTIPLE_INSTANCE
            && ! CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_MULTIPLE_INSTANCE))
            && (! bgp
                || bgp->as
                || LISTCOUNT (BGP_VR.bgp_list) > 1))
    ret = BGP_API_SET_ERR_MULT_INST_DEL_CONFIG;
  else if ( (flag == BGP_OPT_MULTI_INS_ALLOW_SAME_PEER
          && !CHECK_FLAG (BGP_VR.bvr_options, 
                           BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
           && (! bgp
                || bgp->as
                || LISTCOUNT (BGP_VR.bgp_list) > 1))
    ret = BGP_API_SET_ERR_MULT_INST_DEL_CONFIG;
  else
    SET_FLAG (BGP_VR.bvr_options, flag);

  return ret;
}
 
pal_inline s_int32_t
bgp_option_unset (u_int32_t flag)
{
  struct bgp *bgp;
  s_int32_t ret;

  ret = BGP_API_SET_SUCCESS;
  bgp = bgp_lookup_default ();

  if (flag == BGP_OPT_DISABLE_ADJ_OUT
      && CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_DISABLE_ADJ_OUT)
      && (bgp && bgp->as))
    ret = BGP_API_SET_ERR_ADJ_OUT_DYNAMIC;


  else if (flag == BGP_OPT_MULTIPLE_INSTANCE
           && CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_MULTIPLE_INSTANCE)
           && (! bgp
               || bgp->as
               || LISTCOUNT (BGP_VR.bgp_list) > 1))
    ret = BGP_API_SET_ERR_MULTIPLE_INSTANCE_USED;

  else if (flag == BGP_OPT_MULTI_INS_ALLOW_SAME_PEER
           && (LISTCOUNT(BGP_VR.bgp_list) > 1) )
    ret = BGP_API_SET_ERR_MULTIPLE_INSTANCE_USED;
  else
    UNSET_FLAG (BGP_VR.bvr_options, flag);

  return ret;
}

pal_inline s_int32_t
bgp_option_check (u_int32_t flag)
{
  return CHECK_FLAG (BGP_VR.bvr_options, flag);
}


void
bgp_reset_all_peers (struct bgp *bgp)
{
  struct bgp_peer *peer;
  struct listnode *nn;

  /* Set all peer's local identifier with this value */
  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      IPV4_ADDR_COPY (&peer->local_id, &bgp->router_id);

      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
    }

  return;
}

/* Validate BGP Router-ID */
s_int32_t
bgp_router_id_validate (struct pal_in4_addr *addr)
{
  u_int32_t destination;

  /* Convert to host byte order. */
  destination = pal_ntoh32 (addr->s_addr);

  if (IN_CLASSD (destination)
      || IN_EXPERIMENTAL (destination)
      || IPV4_NET127 (destination)
      || destination == INADDR_ANY)
    return -1;

  return 0;
}

/* Get default router id */
u_int32_t 
bgp_get_default_router_id(struct bgp *bgp)
{
  struct interface *ifp;
  struct if_vr_master ifm = bgp->owning_ivrf->vr->ifm;
  struct route_node *rn;
  struct connected *ifc;
  struct prefix *p;
  struct pal_in4_addr *addr;
  struct pal_in4_addr router_id;

  /* Default router id to INADDR_ANY */
  router_id.s_addr = INADDR_ANY;
	
  /* Check all interfaces allocated to the VR */
  for (rn = route_top (ifm.if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      {
       /* Check all IP address.  */
        for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)
          {
            p = ifc->address;
            addr = &p->u.prefix4;
            if (router_id.s_addr == INADDR_ANY)
              {
            	router_id.s_addr = addr->s_addr;
              }
	    else
	      {
		/* Compare addresses and pick the largest one */
 		if (pal_ntoh32 (router_id.s_addr) < pal_ntoh32 (addr->s_addr))
		   router_id.s_addr = addr->s_addr;                
	      }
         }	    
      }
  return router_id.s_addr;
}

/* Get the current Automatic Router-ID */
s_int32_t
bgp_router_id_auto_get (struct bgp *bgp)
{
  if (! bgp)
    return -1;

#ifdef HAVE_BGP_SDN
  if (bgp->router_id.s_addr != INADDR_ANY)
    bgp_delete_routerid (bgp);
#endif

  /* Check BGP_VR.router_id */
  if (BGP_VR.router_id.s_addr == INADDR_ANY )
    {
      BGP_VR.router_id.s_addr = bgp_get_default_router_id(bgp);
    }

  /* Update Automatic Router-ID in all VRFs */
  IPV4_ADDR_COPY (&bgp->router_id,
                  (struct pal_in4_addr *) &BGP_VR.router_id);

  bgp_reset_all_peers (bgp);

#ifdef HAVE_BGP_SDN
  if (bgp->router_id.s_addr != INADDR_ANY)
    bgp_post_routerid (bgp);
#endif
  return 0;
}

/* Set BGP router identifier */
s_int32_t
bgp_router_id_set (struct bgp *bgp, struct pal_in4_addr *id)
{
  if (bgp_config_check (bgp, BGP_CFLAG_ROUTER_ID)
      && IPV4_ADDR_SAME (&bgp->router_id, id))
    return 0;

#ifdef HAVE_BGP_SDN
  if (bgp->router_id.s_addr != INADDR_ANY)
    bgp_delete_routerid (bgp);
#endif

  IPV4_ADDR_COPY (&bgp->router_id, id);
  bgp_config_set (bgp, BGP_CFLAG_ROUTER_ID);

  bgp_reset_all_peers (bgp);

#ifdef HAVE_BGP_SDN
  if (bgp->router_id.s_addr != INADDR_ANY)
    bgp_post_routerid (bgp);
#endif

  return 0;
}

/* Unset BGP router identifier */
s_int32_t
bgp_router_id_unset (struct bgp *bgp)
{
#ifdef HAVE_BGP_SDN
  if (bgp->router_id.s_addr != INADDR_ANY)
    bgp_delete_routerid (bgp);
#endif

  bgp->router_id.s_addr = INADDR_ANY;
  bgp_config_unset (bgp, BGP_CFLAG_ROUTER_ID);

  bgp_router_id_auto_get (bgp);

  return 0;
}


/* Validate BGP Cluster-ID */
s_int32_t
bgp_cluster_id_validate (struct pal_in4_addr *addr)
{
  u_int32_t destination;

  /* Convert to host byte order. */
  destination = pal_ntoh32 (addr->s_addr);

  if (IPV4_NET127 (destination)
      || destination == INADDR_ANY)
    return -1;

  return 0;
}

/* BGP's cluster-id control. */
int
bgp_cluster_id_set (struct bgp *bgp,
                    struct pal_in4_addr *cluster_id)
{
  IPV4_ADDR_COPY (&bgp->cluster_id, cluster_id);
  bgp_config_set (bgp, BGP_CFLAG_CLUSTER_ID);
  bgp_config_unset (bgp, BGP_CFLAG_CLUSTER_ID_DIGIT);
  return 0;
}

int
bgp_cluster_id_digit_set (struct bgp *bgp,
                          u_int32_t cluster_id)
{
  bgp->cluster_id.s_addr = pal_hton32 (cluster_id);
  bgp_config_set (bgp, BGP_CFLAG_CLUSTER_ID);
  bgp_config_set (bgp, BGP_CFLAG_CLUSTER_ID_DIGIT);
  return 0;
}

int
bgp_cluster_id_unset (struct bgp *bgp)
{
  bgp->cluster_id.s_addr = 0;
  bgp_config_unset (bgp, BGP_CFLAG_CLUSTER_ID);
  bgp_config_unset (bgp, BGP_CFLAG_CLUSTER_ID_DIGIT);
  return 0;
}


/* BGP timer configuration.  */
int
bgp_timers_set (struct bgp *bgp,
                u_int16_t keepalive,
                u_int16_t holdtime)
{
  struct bgp_peer *peer;
  struct listnode *mm;

  bgp->default_keepalive = keepalive;
  bgp->default_holdtime = holdtime;

  bgp_config_set (bgp, BGP_CFLAG_DEFAULT_TIMER);

  /* Set all peer's with new timer values */
  LIST_LOOP (bgp->peer_list, peer, mm)
    {
      if (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER))
        continue;

      peer->keepalive = keepalive;
      peer->holdtime = holdtime;
    }

  return 0;
}

int
bgp_timers_unset (struct bgp *bgp)
{
  struct bgp_peer *peer;
  struct listnode *mm;

  bgp->default_keepalive = BGP_DEFAULT_KEEPALIVE;
  bgp->default_holdtime = BGP_DEFAULT_HOLDTIME;

  bgp_config_unset (bgp, BGP_CFLAG_DEFAULT_TIMER);

  /* Set all peer's with new timer values */
  LIST_LOOP (bgp->peer_list, peer, mm)
    {
      if (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER))
        continue;

      peer->keepalive = BGP_DEFAULT_KEEPALIVE;
      peer->holdtime = BGP_DEFAULT_HOLDTIME;
    }

  return 0;
}

int
peer_disallow_hold_timer_set (struct bgp_peer *peer)
{
  pal_assert(peer!=NULL);

  /* Not for peer group memeber.  */
  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

 /* Set disallow_infinite_holdtime  */ 
    SET_FLAG (peer->flags, PEER_DISALLOW_INFINITE_HOLD_TIME);

  return 0;
}

int
peer_disallow_hold_timer_unset (struct bgp_peer *peer)
{
  pal_assert(peer!=NULL);

  /* Not for peer group memeber.  */
  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Clear disallow_infinite_holdtime configuration. */
  UNSET_FLAG (peer->flags, PEER_DISALLOW_INFINITE_HOLD_TIME);

  return 0;
}


/* BGP confederation configuration.  */
int
bgp_confederation_id_set (struct bgp *bgp, as_t as)
{
  struct bgp_peer *peer;
  struct listnode *nn;

  if (as == 0)
    return BGP_API_SET_ERR_INVALID_AS;

  /* Save the confederation AS */
  bgp->confed_id = as;
  bgp_config_set (bgp, BGP_CFLAG_CONFEDERATION);

  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      /* 
       * Apply the Confederation AS to all peers that are eBGP 
       * peers and do not have a static local AS configured.
       */
      if ((peer_sort (peer) == BGP_PEER_EBGP) && 
          (!CHECK_FLAG (peer->config, PEER_FLAG_LOCAL_AS))) 
        {

          peer->local_as = as;
        }
     }

  return 0;
}

int
bgp_confederation_id_unset (struct bgp *bgp)
{
  struct bgp_peer *peer;
  struct listnode *nn;

  /* Clear the confederation AS */
  bgp->confed_id = 0;
  bgp_config_unset (bgp, BGP_CFLAG_CONFEDERATION);

  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      /* 
       * Remove the Confederation AS from all peers that are eBGP 
       * peers and do not have a static local AS configured.
       */
      if ((peer_sort (peer) != BGP_PEER_IBGP) &&
          (!CHECK_FLAG (peer->config, PEER_FLAG_LOCAL_AS)))
        {
          peer->local_as = bgp->as;
        }
     }

  return 0;
}

s_int32_t
bgp_peer_set_local_as (struct bgp_peer *peer, as_t local_as)
{
  struct bgp *bgp;
  enum bgp_peer_type bpt;

  bgp = peer->bgp;

  /* Feature can only be used with EBGP peers */
  if ( (bpt = peer_sort(peer)) != BGP_PEER_EBGP )
      {
        if ( bpt == BGP_PEER_INTERNAL )
           {
            if (bgp->as == local_as)
              return BGP_API_SET_ERR_LOCAL_AS_EQUAL_TRUE_AS;
   
            peer->local_as = local_as; 	              
            SET_FLAG (peer->config, PEER_FLAG_LOCAL_AS);
            return 0; 
           }
        return BGP_API_SET_ERR_PEER_NOT_EBGP;
      }
 
  /* Local-AS cannot be equal to confederation AS */
  if (bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION) &&
      bgp->confed_id == local_as) 
    return BGP_API_SET_ERR_INVALID_AS;

  /* Local-AS cannot equal the true local AS */
  if (bgp->as == local_as) 
    return BGP_API_SET_ERR_LOCAL_AS_EQUAL_TRUE_AS;

  /* Local-AS cannot equal peer's AS */
  if (peer->as == local_as)
    return BGP_API_SET_ERR_LOCAL_AS_EQUAL_PEER_AS;

  if (peer->group && peer->group->peer_list)
    {
      struct bgp_peer *peer1, *each_peer;
      struct listnode *node;
      peer1 = listnode_head (peer->group->peer_list);
      /* peer is added to peer-group and setting local-as for peer-group */
      if (peer1 && (peer == peer1->group->conf))
        {
             peer->local_as = local_as;
             SET_FLAG (peer->config, PEER_FLAG_LOCAL_AS);
             LIST_LOOP (peer->group->peer_list, each_peer, node)
               {
                 each_peer->local_as = peer->local_as;
                 each_peer->config = peer->config;
               }
             return 0;
        }
       /* Local-AS for any peer in the same peer-group is not allowed to modify */
      else if (peer1 && (peer->group == peer1->group) && (peer1->local_as != local_as))
             return BGP_API_SET_ERR_LOCAL_AS_TO_PEER_GROUP_MEMBER;
    }
  
  peer->local_as = local_as; 
  SET_FLAG (peer->config, PEER_FLAG_LOCAL_AS);
        
  return 0;
} 

s_int32_t
bgp_peer_unset_local_as (struct bgp_peer *peer)
{
  enum bgp_peer_type peer_type;

  peer->local_as = 0;
  UNSET_FLAG (peer->config, PEER_FLAG_LOCAL_AS);

  peer_type = peer_sort(peer);

  if (((peer_type == BGP_PEER_EBGP) || (peer_type == BGP_PEER_CONFED)) &&
      bgp_config_check (peer->bgp, BGP_CFLAG_CONFEDERATION))

    peer->local_as = peer->bgp->confed_id;
  else
    peer->local_as = peer->bgp->as;

  return 0;
}


/* Is an AS part of the confed or not? */
int
bgp_confederation_peers_check (struct bgp *bgp, as_t as)
{
  int i;

  if (! bgp)
    return 0;

  for (i = 0; i < bgp->confed_peers_cnt; i++)
    if (bgp->confed_peers[i] == as)
      return 1;

  return 0;
}

/* Add an AS to the confederation set.  */
int
bgp_confederation_peers_add (struct bgp *bgp, as_t as)
{
  struct bgp_peer *peer;
  struct listnode *nn;

  if (! bgp)
    return BGP_API_SET_ERR_INVALID_BGP;

  if (bgp_confederation_peers_check (bgp, as))
    return BGP_API_GET_SUCCESS;

  if (bgp->as == as)
    return BGP_API_SET_ERR_INVALID_AS;

  if (bgp->confed_peers)
    bgp->confed_peers = XREALLOC (MTYPE_BGP_CONFED_LIST,
                                  bgp->confed_peers,
                                  (bgp->confed_peers_cnt + 1) * sizeof (as_t));
  else
    bgp->confed_peers = XCALLOC (MTYPE_BGP_CONFED_LIST,
                                 (bgp->confed_peers_cnt + 1) * sizeof (as_t));

  bgp->confed_peers[bgp->confed_peers_cnt] = as;
  bgp->confed_peers_cnt++;

  if (bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION))
    {
      LIST_LOOP (bgp->peer_list, peer, nn)

        if (!CHECK_FLAG(peer->config, PEER_FLAG_LOCAL_AS) && peer->as == as)
          {
            peer->local_as = bgp->as;

            BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
          }
    }

  return 0;
}

/* Delete an AS from the confederation set.  */
int
bgp_confederation_peers_remove (struct bgp *bgp, as_t as)
{
  int i;
  int j;
  struct bgp_peer *peer;
  struct listnode *nn;

  if (! bgp || !as)
    return -1;

  if (! bgp_confederation_peers_check (bgp, as))
    return -1;

  for (i = 0; i < bgp->confed_peers_cnt; i++)
    if (bgp->confed_peers[i] == as)
      for(j = i + 1; j < bgp->confed_peers_cnt; j++)
        bgp->confed_peers[j - 1] = bgp->confed_peers[j];

  bgp->confed_peers_cnt--;

  if (bgp->confed_peers_cnt == 0)
    {
      if (bgp->confed_peers)
        XFREE (MTYPE_BGP_CONFED_LIST, bgp->confed_peers);
      bgp->confed_peers = NULL;
    }
  else
    bgp->confed_peers = XREALLOC (MTYPE_BGP_CONFED_LIST,
                                  bgp->confed_peers,
                                  bgp->confed_peers_cnt * sizeof (as_t));

  if (bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION))
    {
      LIST_LOOP (bgp->peer_list, peer, nn)
        if (!CHECK_FLAG(peer->config, PEER_FLAG_LOCAL_AS) && peer->as == as)
          {
            peer->local_as = bgp->confed_id;

            BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
          }
    }

  return 0;
}

/* Local preference configuration.  */
int
bgp_default_local_preference_set (struct bgp *bgp, u_int32_t local_pref)
{
  if (! bgp)
    return -1;

  bgp_config_set (bgp, BGP_CFLAG_DEFAULT_LOCAL_PREF);
  bgp->default_local_pref = local_pref;

  return 0;
}

int
bgp_default_local_preference_unset (struct bgp *bgp)
{
  if (! bgp)
    return -1;

  bgp_config_unset (bgp, BGP_CFLAG_DEFAULT_LOCAL_PREF);
  bgp->default_local_pref = BGP_DEFAULT_LOCAL_PREF;

  return 0;
}

/* Check in BGP if all peers are converged */
void
bgp_check_peer_convergence (struct bgp *bgp)
{
  if (!bgp)
    return;

  if (bgp->peer_list->count == bgp->neighbors_converged)
    {
      bgp->conv_complete = PAL_TRUE;
      
      /* clear the flags */
      bgp->neighbors_converged = 0;
    }
  return ;
}


/* BGP auto-summary update (i.e. set or unset) */
s_int32_t
bgp_auto_summary_update (struct bgp *bgp,
                         afi_t afi, 
                         safi_t safi, 
                         bool_t auto_summary_set)
{
  s_int32_t ret = BGP_API_SET_SUCCESS;
  u_int32_t baai;
  u_int32_t bsai;
  u_int32_t src_addr;
  struct bgp_info *ri = NULL;
  struct listnode *nn = NULL;
  struct bgp_node *rn = NULL;
  struct bgp_node *rn1 = NULL;
  struct bgp_ptree *table = NULL;
  struct bgp_adj_out *aout = NULL;
  struct bgp_advertise *adv = NULL;
  struct bgp_info *new_select = NULL;
  enum bgp_peer_type peer_type;
  struct bgp_peer *peer = NULL;
  struct bgp_info *binfo = NULL;
  struct prefix rnp;
  struct prefix rnp1;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);
  
  if ( !bgp )
    {
      ret = BGP_API_SET_ERR_INVALID_VALUE;
      goto EXIT;
    }

  /* Auto-summary enable */
  if ( auto_summary_set )
    {
      if ( CHECK_FLAG (bgp->bgp_af_cflags [baai][bsai], BGP_AF_CFLAG_AUTO_SUMMARY) )
        {
          ret = BGP_API_SET_ERR_AUTO_SUMMARY_ENABLED;
          goto EXIT;
        }
      else
        {
          ret = bgp_af_config_set (bgp, afi, safi, BGP_AF_CFLAG_AUTO_SUMMARY);
          if ( ret != 0 )
            goto EXIT;
        }
    }
  /* Auto-summary disable */
  else
    {
      if ( !CHECK_FLAG (bgp->bgp_af_cflags [baai][bsai], BGP_AF_CFLAG_AUTO_SUMMARY) )
        {
          ret = BGP_API_SET_ERR_AUTO_SUMMARY_DISABLED;
          goto EXIT;
        }
      else
        {
          ret = bgp_af_config_unset (bgp, afi, safi, BGP_AF_CFLAG_AUTO_SUMMARY);
          if ( ret != 0 )
            goto EXIT;
        }
    }

  /* List all the nbrs and send summarised/non-summarised routes */ 
  LIST_LOOP (bgp->peer_list, peer, nn)
      {
        table = bgp->route[baai][bsai];
         
        for (rn1 = bgp_table_top (table); rn1; rn1 = bgp_route_next (rn1))
          {
            bgp_ptree_get_prefix_from_node (rn1, &rnp1);
            rn = bgp_afi_node_get (bgp, afi, safi, &rnp1, NULL);
 
            if (! rn)
              {
                ret = BGP_API_INVALID_ROUTE_NODE;
                goto EXIT;
              }
             
            bgp_ptree_get_prefix_from_node (rn, &rnp);
            src_addr = pal_ntoh32 (rnp.u.prefix4.s_addr); 
            /* Do not manipulate host routes with prefix length 32 */ 
            if ( (IPV4_MAX_PREFIXLEN == rnp.prefixlen) 
                || (IN_CLASSA (src_addr) 
                    && (IN_CLASSA_PREFIXLEN == rnp.prefixlen) 
                    && (src_addr & IN_CLASSA_NET) == src_addr) 
                || (IN_CLASSB (src_addr) 
                    && (IN_CLASSB_PREFIXLEN == rnp.prefixlen) 
                    && (src_addr & IN_CLASSB_NET) == src_addr) 
                || (IN_CLASSC (src_addr) 
                    && (IN_CLASSC_PREFIXLEN == rnp.prefixlen) 
                    && (src_addr & IN_CLASSC_NET) == src_addr))
              continue;

            if (rn && rn->adj_out)
              {
                for (aout = rn->adj_out; aout; aout = aout->next)
                  {
                    if (aout->peer == peer)
                       break;
                  }
                 
                 /* if out is NULL do not process */
                 if (NULL == aout)
                   continue;

                /* if this route is not advertised to the peer, 
                 *  conitnue with another route 
                 */
                if (aout->peer != peer)
                  continue;
 
                /* Advertise summarised/non-summarised routes when 
                 * Auto-summary is enabled/disabled respectively
                 * Start of Advertising 
                 */

                /* Clean up previous advertisement */
                if (aout->adv)
                  bgp_advertise_clean (aout->peer, &aout, afi, safi);

                if (NULL == aout)
                  continue;
                
                new_select = NULL;
                for (ri = rn->info; ri; ri = ri->next)
                  {
                    peer_type = peer_sort (ri->peer);

                    if (BGP_INFO_HOLDDOWN (ri))
                      {
                        ri->as_selected = 0;
                        continue;
                      }
 
                    if (bgp_af_config_check (ri->peer->bgp, afi, safi,
                                             BGP_AF_CFLAG_SYNCHRONIZATION)
                        && (peer_type == BGP_PEER_IBGP
                             || peer_type == BGP_PEER_CONFED)
                        && CHECK_FLAG (ri->flags, BGP_INFO_UNSYNCHRONIZED))
                      continue;

                    if (bgp_config_check (bgp, BGP_CFLAG_DETERMINISTIC_MED)
                        && ri->as_selected != 1)
                      {
                        ri->as_selected = 0;
                        continue;
                      }

                    ri->as_selected = 0;

                    if (bgp_info_cmp (bgp, ri, new_select))
                      binfo = ri;
                  } /* for (ri = rn->info) */

                if ( binfo )
                  aout->from_peer = binfo->peer;
 
                aout->adv = bgp_advertise_new ();
                if (!aout->adv)
                  continue;
                adv = aout->adv;
                adv->adj = aout;
                adv->rn = rn;
                adv->binfo = binfo;
 
                if (aout->attr)
                  {
                    adv->baa = bgp_advertise_intern (
                                            aout->peer->baa_hash [baai][bsai],
                                            aout->attr);
 
                    /* Add new advertisement to BAA list */
                    bgp_advertise_add (adv->baa, adv);
                  }

                if (binfo)
                  {
                    SET_FLAG (aout->peer->af_sflags [baai][bsai],
                              PEER_STATUS_AF_ASORIG_ROUTE_ADV);
                    if (binfo->peer == aout->peer->bgp->peer_self)
                      FIFO_ADD (&aout->peer->asorig_adv_list [baai][bsai]->reach,
                                &adv->badv_fifo);
                  }
 
                bgp_peer_send_update (aout->peer, PAL_TRUE);
                /* End of Advertise */ 
 
                /* Withdraw non-summarised/summarised routes 
                 * when Auto-summary is enabled/disabled respectively 
                 * Start of Withdraw 
                 */ 
                 for (aout = rn->adj_out; aout; aout = aout->next)
                  {
                    if (aout->peer == peer)
                      break;
                  }

                if (!aout)
                  continue;
                 
                /* Clean up previous advertisement */
                if (aout->adv)
                  bgp_advertise_clean (aout->peer, &aout, afi, safi);

                if (NULL == aout)
                  continue;
 
                if (aout->attr)
                  {
                    /* We need advertisement structure.  */
                    aout->adv = bgp_advertise_new ();

                    if (NULL ==  aout->adv)
                      continue;

                    adv = aout->adv;
                    adv->rn = rn;
                    adv->adj = aout;

                    /* Add the unreachability entry for withdrawal */
                    SET_FLAG (aout->peer->af_sflags [baai][bsai],
                              PEER_STATUS_AF_ASORIG_ROUTE_ADV);
                    if (aout->from_peer == aout->peer->bgp->peer_self)
                      FIFO_ADD (
                      &aout->peer->asorig_adv_list [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)]->unreach,
                            &adv->badv_fifo);
                  }

                bgp_peer_send_update (aout->peer, PAL_TRUE);
                /* End of Withdraw */ 
              } /* if(rn && rn->adj_out) */
            else
              continue;
          } /* end of for loop */
      } /* End of List Loop */

EXIT:

return ret;
}



/* BGP Static Network Synchronization set */
s_int32_t
bgp_network_sync_set (struct bgp *bgp,
                      afi_t afi, safi_t safi)
{
  s_int32_t ret;

  ret = bgp_af_config_set (bgp, afi, safi, BGP_AF_CFLAG_NETWORK_SYNC);

  return ret;
}

/* BGP Static Network Synchronization unset */
s_int32_t
bgp_network_sync_unset (struct bgp *bgp,
                        afi_t afi, safi_t safi)
{
  s_int32_t ret;

  ret = bgp_af_config_unset (bgp, afi, safi, BGP_AF_CFLAG_NETWORK_SYNC);

  return ret;
}


/* Peer comparison function for sorting.  */
int
bgp_peer_cmp (struct bgp_peer *p1, struct bgp_peer *p2)
{
  return sockunion_cmp (&p1->su, &p2->su);
}


/* bgp multipath set  */

int
bgp_set_maxpath (bool_t setflag, struct bgp *bgp, int bgptype, int multipath)
{

  int ebgp = 0;
  int ibgp = 0;


  if (bgptype == BGP_PEER_EBGP)
      {
        ebgp++;
        /* multipath number is unchanged then return SUCCESS */
       if ((setflag && bgp->cfg_maxpath_ebgp == multipath)
                || (!setflag && bgp->cfg_maxpath_ebgp == BGP_DEFAULT_MAXPATH_ECMP))
         return BGP_API_SET_SUCCESS;
      }
     else if (bgptype == BGP_PEER_IBGP)
      {
        ibgp++;
        if ((setflag && bgp->cfg_maxpath_ibgp == multipath)
          || (!setflag && bgp->cfg_maxpath_ibgp ==  BGP_DEFAULT_MAXPATH_ECMP))
          return BGP_API_SET_SUCCESS;
       }
      else
        return BGP_API_SET_ERR_MALFORMED_ARG;

     if (setflag && ebgp)
       {
          bgp->cfg_maxpath_ebgp = multipath;
          /*
           * Multipath is enabled and effective immediately if it
           * was disabled before.
           */
          if (bgp->maxpath_ebgp == BGP_DEFAULT_MAXPATH_ECMP)
            bgp->maxpath_ebgp = multipath;
       }
     else if (!setflag && ebgp)
        bgp->cfg_maxpath_ebgp = BGP_DEFAULT_MAXPATH_ECMP;

     if (setflag && ibgp)
       {
         bgp->cfg_maxpath_ibgp = multipath;
         if (bgp->maxpath_ibgp == BGP_DEFAULT_MAXPATH_ECMP)
           bgp->maxpath_ibgp = multipath;
        }
     else if (!setflag && ibgp)
        bgp->cfg_maxpath_ibgp = BGP_DEFAULT_MAXPATH_ECMP;

     /* Enable/Disable cfg flag becomes effective immediately
      * But the NSM updates throughout the FIB becomes effective
      * at next SCAN time.
      */
     if (setflag && !CHECK_FLAG(bgp->bgp_cflags, BGP_CFLAG_ECMP_ENABLE))
       SET_FLAG (bgp->bgp_cflags, BGP_CFLAG_ECMP_ENABLE);

     if (!setflag && CHECK_FLAG(bgp->bgp_cflags, BGP_CFLAG_ECMP_ENABLE))
       {
          if (bgp->cfg_maxpath_ibgp == BGP_DEFAULT_MAXPATH_ECMP &&
                (bgp->cfg_maxpath_ebgp == BGP_DEFAULT_MAXPATH_ECMP))
            UNSET_FLAG(bgp->bgp_cflags, BGP_CFLAG_ECMP_ENABLE);
       }
     else if (!setflag)
       return BGP_API_FEATURE_NOT_ENABLED_SET_ERR;

     return BGP_API_SET_SUCCESS;
}


/* Reset all address family specific configuration.  */
static void
peer_af_flag_reset (struct bgp_peer *peer, afi_t afi, safi_t safi)
{
  u_int8_t orf_name [SU_ADDRSTRLEN];
  struct bgp_filter *filter;
  u_int32_t baai;
  u_int32_t bsai;
  u_int32_t i;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);
  filter = &peer->filter [baai][bsai];

  /* Clear neighbor filter and route-map */
  for (i = FILTER_IN; i < FILTER_MAX; i++)
    {
      if (filter->dlist[i].name)
        {
          XFREE (MTYPE_TMP, filter->dlist[i].name);
          filter->dlist[i].name = NULL;
        }
      if (filter->plist[i].name)
        {
          XFREE (MTYPE_TMP, filter->plist[i].name);
          filter->plist[i].name = NULL;
        }
      if (filter->aslist[i].name)
        {
          XFREE (MTYPE_TMP, filter->aslist[i].name);
          filter->aslist[i].name = NULL;
        }
      if (filter->map[i].name)
        {
          XFREE (MTYPE_TMP, filter->map[i].name);
          filter->map[i].name = NULL;
        }
    }

  /* Clear unsuppress map.  */
  if (filter->usmap.name)
    XFREE (MTYPE_TMP, filter->usmap.name);
  filter->usmap.name = NULL;
  filter->usmap.map = NULL;

  /* Clear neighbor's all address family flags.  */
  peer->af_flags [baai][bsai] = 0;

  /* Clear neighbor's all address family sflags. */
  peer->af_sflags [baai][bsai] = 0;

  /* Clear neighbor's all address family capabilities. */
  peer->af_cap [baai][bsai] = 0;

  /* Clear ORF info */
  peer->orf_plist [baai][bsai] = NULL;
  pal_snprintf (orf_name, SU_ADDRSTRLEN, "%s.%d.%d",
                peer->host, afi, safi);
  prefix_bgp_orf_remove_all (BGP_VR.owning_ivr, orf_name);

  /* Set default neighbor send-community.  */
  if (! bgp_option_check (BGP_OPT_CONFIG_STANDARD))
    {
      SET_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_SEND_COMMUNITY);
      SET_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_SEND_EXT_COMMUNITY);
    }

  /* Clear neighbor default_originate_rmap */
  if (peer->default_rmap [baai][bsai].name)
    XFREE (MTYPE_TMP, peer->default_rmap [baai][bsai].name);
  peer->default_rmap [baai][bsai].name = NULL;
  peer->default_rmap [baai][bsai].map = NULL;

  /* Clear neighbor maximum-prefix */
  peer->pmax [baai][bsai] = 0;

  return;
}

/* Sets address family configuration */
s_int8_t
peer_afc_set (struct bgp_peer *peer, afi_t afi, safi_t safi)
{
  struct bgp *bgp;
  u_int32_t index;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  /* When the address family is already activated, return FALSE  */
  if (peer->afc [baai][bsai])
    return BGP_API_SET_ERR_OBJECT_ALREADY_EXIST;

  /* Calculate index for the peer */
  bgp = peer->bgp;
  index = vector_set (bgp->peer_index [baai][bsai], peer);

  if (index == VECTOR_MEM_ALLOC_ERROR)
    {
      zlog_err (&BLG, "Cannot allocate memory!!!\n");
      return -1;
    }

  peer->index [baai][bsai].val = index;
  peer->index [baai][bsai].offset = index / 8;
  peer->index [baai][bsai].mask = (1 << index % 8);

  /* Set afc flag */
  peer->afc [baai][bsai] = 1;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP)
      && peer->group && peer->group->conf != peer)
    peer->af_group[baai][bsai] = 1;

  return 1;
}

/* Unset address family configuration.  */
s_int8_t
peer_afc_unset (struct bgp_peer *peer, afi_t afi, safi_t safi)
{
  struct bgp *bgp;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  /* When the address family is already de-activated, return FALSE */
  if (! peer->afc [baai][bsai])
    return BGP_API_SET_ERR_UNKNOWN_OBJECT;

  /* Calculate index for the peer */
  bgp = peer->bgp;
  vector_unset (bgp->peer_index [baai][bsai], peer->index [baai][bsai].val);
  peer->index [baai][bsai].offset = 0;
  peer->index [baai][bsai].mask = 0;

  /* Un-Set afc flag */
  peer->afc [baai][bsai] = 0;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP)
      && peer->group && peer->group->conf != peer)
    peer->af_group [baai][bsai] = 0;

  return BGP_API_SET_SUCCESS;
}

/* peer global config reset */
void
peer_global_config_reset (struct bgp_peer *peer)
{
  u_int32_t baai = 0;
  u_int32_t bsai = 0;

  peer->ttl = (peer_sort (peer) == BGP_PEER_IBGP ? 255 : 1);
  if (peer->update_source)
    {
      sockunion_free (peer->update_source);
      peer->update_source = NULL;
    }
  if (peer->update_if)
    {
      XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
      peer->update_if = NULL;
    }

  if (peer_sort (peer) == BGP_PEER_IBGP)
    peer->v_routeadv = BGP_DEFAULT_IBGP_ROUTEADV;
  else
    peer->v_routeadv = BGP_DEFAULT_EBGP_ROUTEADV;

  peer->flags = 0;
  peer->config = 0;
  peer->holdtime = 0;
  peer->keepalive = 0;
  peer->connect = 0;
  peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        peer->weight [baai][bsai] = BGP_DEFAULT_WEIGHT;
      }

  return;
}

/* Check peer's AS number and determin is this peer IBGP or EBGP */
enum bgp_peer_type
peer_sort (struct bgp_peer *peer)
{
  struct bgp *bgp;

  bgp = peer->bgp;

  /* Peer-group */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (! peer->as && peer->group)
        {
          struct bgp_peer *peer1;
          peer1 = listnode_head (peer->group->peer_list);
          if (peer1)
            return ((peer1->local_as == peer1->as)
                    ? BGP_PEER_IBGP : BGP_PEER_EBGP);
        }
    }

  if (peer->local_as == 0)
    return BGP_PEER_INTERNAL;

  if (peer->local_as == peer->as)
    return BGP_PEER_IBGP;

  if (CHECK_FLAG(peer->config, PEER_FLAG_LOCAL_AS))
    return BGP_PEER_EBGP;

  if (bgp && bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION) &&
      bgp_confederation_peers_check (bgp, peer->as))
    return BGP_PEER_CONFED;

  return BGP_PEER_EBGP;
}

/* Allocate new peer object.  */
struct bgp_peer *
bgp_peer_new (bool_t config_only)
{
  struct bgp_peer *peer;
  u_int32_t baai;
  u_int32_t bsai;

  /* Allocate new peer. */
  peer = XCALLOC (MTYPE_BGP_PEER, sizeof (struct bgp_peer));

  if (! peer)
    return peer;

  /* Peer structure not for configuration only (externally active) */
  if (config_only == PAL_FALSE)
    {
      peer->sock_cb = stream_sock_cb_alloc (peer, BGP_MAX_PACKET_SIZE,
                                            bpn_sock_cb_status_hdlr, &BLG);
      if (! peer->sock_cb)
        {
          XFREE (MTYPE_BGP_PEER, peer);
          return NULL;
        }

      bgp_peer_adv_list_init (peer);
    }

  /* Set default values */
  peer->v_auto_start = BGP_DEFAULT_AUTO_START;
  peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;
  peer->v_asorig = BGP_DEFAULT_ASORIG;
  peer->sock_port = BGP_PORT_DEFAULT;
  peer->bpf_state = BPF_STATE_IDLE;
  peer->version = BGP_VERSION_4;
  SET_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

  /* Initialize structures */
  FIFO_INIT (&peer->bdui_fifo);
  FIFO_INIT (&peer->bicr_fifo);

  /* Set default flags.  */
  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        peer->weight [baai][bsai] = BGP_DEFAULT_WEIGHT;

        if (! bgp_option_check (BGP_OPT_CONFIG_STANDARD))
          {
            SET_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_SEND_COMMUNITY);
            SET_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_SEND_EXT_COMMUNITY);
          }
        peer->orf_plist[baai][bsai] = NULL;
      }

  return peer;
}

s_int32_t 
peer_bgp_node_cmp (void *v1, void *v2)
{
  struct peer_bgp_node *node1 = NULL;
  struct peer_bgp_node *node2 = NULL;
  
  node1 = (struct peer_bgp_node *)v1;
  node2 = (struct peer_bgp_node *)v2;

  return (pal_strcmp (node1->bgp->name, node2->bgp->name));
}

/* Create New BGP Peer through configuration */
struct bgp_peer *
bgp_peer_create (union sockunion *su,
                 struct bgp *bgp,
                 as_t local_as,
                 as_t remote_as,
                 afi_t afi, safi_t safi)
{
  u_int8_t buf [SU_ADDRSTRLEN];
  struct bgp_peer *peer;
  u_int32_t active;
  s_int32_t ret;
  struct peer_bgp_node *peer_bgp_node=NULL;
  u_int32_t baai;
  u_int32_t bsai;
  s_int8_t ret1;
  
  peer = bgp_peer_new (PAL_FALSE);
  if (!peer)
    return peer;

  if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER) && !peer->master_bgp)
    {
       peer->master_bgp = bgp;
       peer->bgp = bgp;
    }
  else
    peer->bgp = bgp;

  peer->su = *su;

  baai = BGP_AFI2BAAI(afi);
  bsai = BGP_SAFI2BSAI(safi);

   /*
    * If the peer is not part of our confederation,
    * and its not an IBGP peer then spoof the source AS
    */
  if (bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION)
      && ! bgp_confederation_peers_check (bgp, remote_as)
      && local_as != remote_as)
    peer->local_as = bgp->confed_id;
  else
    peer->local_as = local_as;

  peer->as = remote_as;
  peer->local_id = bgp->router_id;
  peer->holdtime = bgp->default_holdtime;
  peer->keepalive = bgp->default_keepalive;
  peer->v_holdtime = peer->holdtime;
  peer->v_keepalive = peer->keepalive;

  if (peer_sort (peer) == BGP_PEER_IBGP)
    peer->v_routeadv = BGP_DEFAULT_IBGP_ROUTEADV;
  else
    peer->v_routeadv = BGP_DEFAULT_EBGP_ROUTEADV;

  listnode_add_sort (bgp->peer_list, peer);

  active = peer_active (peer);

  if (afi && safi)
    {
      ret1 = peer_afc_set (peer, afi, safi);

      if (ret1 < 0)
        return NULL;
    }

  /* List for Incoming Peers */
  if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER) && !peer->master_bgp)
    peer->clones_list = list_new ();
  else
    peer->clones_list = list_new ();
    

  /* Create bgp_node list in peer for route-server */
  if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
    {
      peer->peer_bgp_node_list = list_new();
      peer->peer_bgp_node_list->cmp = peer_bgp_node_cmp;
      peer_bgp_node = XCALLOC(MTYPE_PEER_BGP_NODE,sizeof(struct peer_bgp_node));
      peer_bgp_node->bgp = bgp;
      peer_bgp_node->afc[baai][bsai] = peer->afc[baai][bsai];
      listnode_add_sort (peer->peer_bgp_node_list, peer_bgp_node);
      bgp_peer_lock (peer);
    }
  else
    peer->peer_bgp_node_list = NULL;

  /* Keep this peer disabled if no interfaces are bound */
  ret = route_table_has_info (LIB_VRF_GET_IF_TABLE
                              (bgp->owning_ivrf));
  if (! ret)
    SET_FLAG (peer->flags, PEER_FLAG_NO_IF_BINDING);

  /* Default TTL set. */
  peer->ttl = (peer_sort (peer) == BGP_PEER_IBGP ? 255 : 1);

  /* By default the default-originated route will not be sent
     to the peer. So this will be FALSE. */
  peer->def_orig_route_sent = PAL_FALSE;

  /* Make peer's address string. */
  sockunion2str (su, buf, SU_ADDRSTRLEN);
  peer->host = XSTRDUP (MTYPE_TMP, buf);

  if (active == PAL_FALSE && PAL_TRUE == peer_active (peer))
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_START);

  return peer;
}

/* Clone BGP Peer for Tracking Incoming Connection request */
struct bgp_peer *
bgp_peer_create_clone (struct bgp_peer *real_peer)
{
  struct bgp_peer *peer;
  u_int32_t baai;
  u_int32_t bsai;

  peer = bgp_peer_new (PAL_FALSE);
  if (! peer)
    return peer;

  peer->bgp = real_peer->bgp;
  peer->su = real_peer->su;
  listnode_add_sort (real_peer->clones_list, peer);
  peer->real_peer = real_peer;

  peer->as = real_peer->as;
  peer->remote_id = real_peer->remote_id;
  peer->local_id = real_peer->local_id;
  peer->local_as = real_peer->local_as;

  peer->config = real_peer->config;
  peer->keepalive = real_peer->keepalive;
  peer->holdtime = real_peer->holdtime;

  peer->v_auto_start = real_peer->v_auto_start;
  peer->v_connect = real_peer->v_connect;
  peer->v_holdtime = real_peer->v_holdtime;
  peer->v_keepalive = real_peer->v_keepalive;
  peer->v_asorig = real_peer->v_asorig;
  peer->v_routeadv = real_peer->v_routeadv;

  peer->bpf_state = BPF_STATE_ACTIVE;

  peer->sflags = real_peer->sflags;
  peer->flags = real_peer->flags;

  peer->cap = real_peer->cap;
  peer->ttl = real_peer->ttl;

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        peer->af_flags [baai][bsai] = real_peer->af_flags [baai][bsai];
        peer->af_cap [baai][bsai] = real_peer->af_cap [baai][bsai];

        peer->afc [baai][bsai] = real_peer->afc [baai][bsai];
        peer->afc_adv [baai][bsai] = real_peer->afc_adv [baai][bsai];
        peer->afc_recv [baai][bsai] = real_peer->afc_recv [baai][bsai];
      }

  if (real_peer->host)
    peer->host = XSTRDUP (MTYPE_TMP, real_peer->host);

  if (real_peer->ifname)
    peer->ifname = XSTRDUP (MTYPE_TMP, real_peer->ifname);

#ifdef HAVE_TCP_MD5SIG
  if (real_peer->password)
    peer->password = XSTRDUP (MTYPE_TMP, real_peer->password);
#endif /* TCP_MD5SIG */

  if (real_peer->update_if)
    peer->update_if = XSTRDUP (MTYPE_PEER_UPDATE_SOURCE,
                               real_peer->update_if);
  else if (peer->update_source)
    peer->update_source = sockunion_dup (real_peer->update_source);

  return peer;
}

/* Change Peer's Remote-AS number */
void
bgp_peer_as_change (struct bgp_peer *peer, as_t as)
{
  enum bgp_peer_type type, new_type;

  type = peer_sort (peer);
  peer->as = as;

  if (bgp_config_check (peer->bgp, BGP_CFLAG_CONFEDERATION)
      && ! bgp_confederation_peers_check (peer->bgp, as)
      && peer->bgp->as != as)
    peer->local_as = peer->bgp->confed_id;
  else
    peer->local_as = peer->bgp->as;

  new_type = peer_sort (peer);

  /* Advertisement-interval reset */
  if (new_type == BGP_PEER_IBGP)
    peer->v_routeadv = BGP_DEFAULT_IBGP_ROUTEADV;
  else
    peer->v_routeadv = BGP_DEFAULT_EBGP_ROUTEADV;

  /* TTL reset */
   if (new_type == BGP_PEER_IBGP)
      peer->ttl = 255;
   else if (new_type == BGP_PEER_EBGP)
   {  
     if( new_type != type)
       peer->ttl = 1;
   }

  /* reflector-client reset */
  if (peer_sort (peer) != BGP_PEER_IBGP)
    {
      UNSET_FLAG (peer->af_flags[BAAI_IP][BSAI_UNICAST],
                  PEER_FLAG_REFLECTOR_CLIENT);
      UNSET_FLAG (peer->af_flags[BAAI_IP][BSAI_MULTICAST],
                  PEER_FLAG_REFLECTOR_CLIENT);
      UNSET_FLAG (peer->af_flags[BAAI_IP6][BSAI_UNICAST],
                  PEER_FLAG_REFLECTOR_CLIENT);
      UNSET_FLAG (peer->af_flags[BAAI_IP6][BSAI_MULTICAST],
                  PEER_FLAG_REFLECTOR_CLIENT);
    }

  if (! CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

  return;
}

s_int32_t
bgp_peer_activate_all (struct bgp *bgp)
{
  struct bgp_peer *peer;
  struct listnode *nn;
  s_int32_t ret;

  ret = 0;

  if (! bgp)
    {
      ret = -1;
      goto EXIT;
    }

  LIST_LOOP (bgp->peer_list, peer, nn)
    if (CHECK_FLAG (peer->flags, PEER_FLAG_NO_IF_BINDING))
      {
        UNSET_FLAG (peer->flags, PEER_FLAG_NO_IF_BINDING);

        /* Activate the BGP Peer */
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_AUTO_START);
      }

EXIT:

  return ret;
}

s_int32_t
bgp_peer_deactivate_all (struct bgp *bgp)
{
  struct bgp_peer *peer;
  struct listnode *nn;
  s_int32_t ret;

  ret = 0;

  if (! bgp)
    {
      ret = -1;
      goto EXIT;
    }

  LIST_LOOP (bgp->peer_list, peer, nn)
    if (! CHECK_FLAG (peer->flags, PEER_FLAG_NO_IF_BINDING))
      {
        SET_FLAG (peer->flags, PEER_FLAG_NO_IF_BINDING);

        /* Deactivate the BGP Peer */
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_AUTO_STOP);
      }

EXIT:

  return ret;
}

s_int32_t
bgp_peer_fast_external_failover (struct bgp *bgp,
                                 struct interface *ifp, u_int32_t afi)
{
  struct interface *peer_if;
  struct bgp_peer *peer;
  struct listnode *nn;
  s_int32_t ret;

  ret = 0;

  if (! bgp || ! ifp)
    {
      ret = -1;
      goto EXIT;
    }

  if (! bgp_config_check (bgp, BGP_CFLAG_NO_FAST_EXT_FAILOVER))
    {
      LIST_LOOP (bgp->peer_list, peer, nn)
        {
          peer_if = NULL;

          if (peer_sort (peer) != BGP_PEER_EBGP || peer->ttl != 1)
            continue;

          if (peer->su.sa.sa_family == AF_INET && afi == AF_INET)
            peer_if = if_match_by_ipv4_address
                      (LIB_VR_GET_IF_MASTER (BGP_VR.owning_ivr),
                       &peer->su.sin.sin_addr,
                       LIB_VRF_GET_VRF_ID (bgp->owning_ivrf));
          else
#ifdef HAVE_IPV6
          if (BGP_CAP_HAVE_IPV6
              && peer->su.sa.sa_family == AF_INET6 && afi == AF_INET6)
            peer_if = if_match_by_ipv6_address
                      (LIB_VR_GET_IF_MASTER (BGP_VR.owning_ivr),
                       &peer->su.sin6.sin6_addr,
                       LIB_VRF_GET_VRF_ID (bgp->owning_ivrf));
          if (!peer_if && afi == AF_INET6
              && (peer->nexthop.ifp == ifp))
            peer_if = peer->nexthop.ifp;
          else
#endif /* HAVE_IPV6 */
            continue;

          if (ifp == peer_if)
            {
              BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
              bgp_log_neighbor_status_print (peer,
                                             PEER_LOG_STATUS_DOWN,
                                             "Interface Flap");
            }
        }
    }

EXIT:

  return ret;
}

/*
 * If peer does not exist, create new one. If peer already
 * exists, set AS number to the peer
 */
s_int32_t
bgp_peer_remote_as (struct bgp *bgp,
                    union sockunion *su,
                    as_t *as, afi_t afi, safi_t safi)
{
  struct bgp_peer *peer;
  struct peer_bgp_node *pbgp_node = NULL;
  struct listnode * node = NULL;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI(afi);
  bsai = BGP_SAFI2BSAI(safi);

  peer = bgp_peer_search (bgp, su);


  if (peer)
    {
      /* When this peer is a member of peer-group.  */
      if (peer->group)
        {
          if (peer->group->conf->as)
            {
              /* Return peer group's AS number.  */
              *as = peer->group->conf->as;
              return BGP_API_SET_ERR_PEER_GROUP_MEMBER;
            }
          if (peer_sort (peer->group->conf) == BGP_PEER_IBGP)
            {
              if (bgp->as != *as)
                {
                  *as = peer->as;
                  return BGP_API_SET_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
                }
            }
          else
            {
              if (bgp->as == *as)
                {
                  *as = peer->as;
                  return BGP_API_SET_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
                }
            }
        }

      /* If the allow same peer flag is set then allow same peer
         in multiple instances */
      if (bgp_option_check(BGP_OPT_MULTI_INS_ALLOW_SAME_PEER)
          && peer->master_bgp) 
        {
          /* check if the peer is already enabled in the same view */
          LIST_LOOP (peer->peer_bgp_node_list, pbgp_node, node)
            {
              if (pbgp_node->bgp == bgp)
                return BGP_API_SET_ERROR;
            }
          /* validate the AS number. AS number of peer & instance should match
           * with master instance AS number.
           */ 
          if ((peer->as != *as) || peer->master_bgp->as != bgp->as)
            return BGP_API_SET_ERR_AS_MISMATCH;

          listnode_add_sort (bgp->peer_list, peer);
          pbgp_node = XCALLOC (MTYPE_PEER_BGP_NODE, 
                               sizeof (struct peer_bgp_node));
          if (!pbgp_node)
            return BGP_API_SET_ERROR;

          pbgp_node->bgp = bgp;
          pbgp_node->afc[baai][bsai] = 1;
          listnode_add_sort (peer->peer_bgp_node_list,pbgp_node);
          bgp_peer_lock (peer);
          return BGP_API_SET_SUCCESS;
        }

      /* Peers showuld be unique across Multiple-Instances */
      if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE)
          && peer->bgp != bgp)
        return BGP_API_SET_ERR_PEER_CONFIG_IN_ANOTHER_INST;

      /* Existing peer's AS number change */
      if (peer->as != *as)
        bgp_peer_as_change (peer, *as);
      else if (! CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_START);
    }
  else
    {
      /*
       * If this is IPv4 unicast configuration and
       * "no bgp default ipv4-unicast" is specified
       */
      if (bgp_config_check (bgp, BGP_CFLAG_NO_DEFAULT_IPV4)
          && afi == AFI_IP && safi == SAFI_UNICAST)
        peer = bgp_peer_create (su, bgp, bgp->as, *as, 0, 0);
      else
        peer = bgp_peer_create (su, bgp, bgp->as, *as, afi, safi);
    }

  if (peer)
    return BGP_API_SET_SUCCESS;
  else
    return BGP_API_SET_ERR_MEM_ALLOC_FAIL;
}

/* Activate the peer for specified AFI and SAFI.  */
s_int8_t
peer_afc_activate (struct bgp_peer *peer, afi_t afi, safi_t safi)
{
  bool_t active;
  s_int8_t ret;

  active = peer_active (peer);

  ret = peer_afc_set (peer, afi, safi);
  
  if (ret == BGP_API_SET_ERR_OBJECT_ALREADY_EXIST)  
    return ret;

  if (ret < 0)
    return BGP_API_SET_ERR_MEM_ALLOC_FAIL;

  if (ret > 0)
    {
      if (active == PAL_TRUE)
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
      else if (! CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_START);
    }

  return BGP_API_SET_SUCCESS;
}

/* Activate the peer or peer group for specified AFI and SAFI.  */
int
peer_activate (struct bgp *bgp, struct bgp_peer *peer,
               afi_t afi, safi_t safi)
{
  struct bgp_peer_group *group;
  struct bgp_peer *peer1;
  struct listnode *nn;
  struct peer_bgp_node *bgp_node=NULL;
  u_int32_t baai;
  u_int32_t bsai;
  s_int8_t ret = BGP_API_SET_SUCCESS;
  s_int8_t ret1;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  /* Activate the address family configuration. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->afc [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
        return BGP_API_SET_SUCCESS;

      group = peer->group;

      if (!group)
        return BGP_API_SET_ERROR;

      if (peer->group->conf == peer)
        {
          ret1 = peer_afc_set (peer, afi, safi);
          if (ret1 < 0)
            return BGP_API_SET_ERR_MEM_ALLOC_FAIL;

          LIST_LOOP (group->peer_list, peer1, nn)
            {
              ret = peer_afc_activate (peer1, afi, safi);
              if ( ret != BGP_API_SET_SUCCESS)
                return ret;
            }
        }
      else
        ret = peer_afc_activate (peer, afi, safi);
    }
  else
    ret = peer_afc_activate (peer, afi, safi);

  if (bgp_option_check(BGP_OPT_MULTI_INS_ALLOW_SAME_PEER)
      && peer->peer_bgp_node_list)
    LIST_LOOP(peer->peer_bgp_node_list, bgp_node,nn)
      {
        if (bgp_node->bgp == bgp)
          bgp_node->afc[baai][bsai] = peer->afc[baai][bsai];
      }

  return ret;
}

s_int8_t
peer_deactivate (struct bgp_peer *peer, afi_t afi, safi_t safi)
{
  bool_t active = PAL_TRUE;
  s_int8_t ret = BGP_API_SET_SUCCESS;

  /* De-activate the address family configuration. */
  ret = peer_afc_unset (peer, afi, safi);
  if (BGP_API_SET_SUCCESS == ret)
    {
      peer_af_flag_reset (peer, afi, safi);
      active = peer_active (peer);
      if (! CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP)
          || ! (peer->group && peer->group->conf == peer))
        {
          if (PAL_FALSE == active)
            BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_STOP);
          else
            BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
        }
    }
    
  return ret;
}

void
peer_group_config_reset (struct bgp_peer_group *group)
{
  struct bgp_peer *conf = group->conf;

  if (peer_sort (conf) == BGP_PEER_INTERNAL 
     || conf->as == 0)
    {
      conf->ttl = 1;
      conf->v_routeadv = BGP_DEFAULT_EBGP_ROUTEADV;
      UNSET_FLAG (conf->af_flags[BAAI_IP][BSAI_UNICAST],
                  PEER_FLAG_REFLECTOR_CLIENT);
      UNSET_FLAG (conf->af_flags[BAAI_IP][BSAI_MULTICAST ],
                  PEER_FLAG_REFLECTOR_CLIENT);
      UNSET_FLAG (conf->af_flags[BAAI_IP6][BSAI_UNICAST],
                  PEER_FLAG_REFLECTOR_CLIENT);
      UNSET_FLAG (conf->af_flags[BAAI_IP6][BSAI_MULTICAST],
                  PEER_FLAG_REFLECTOR_CLIENT);
    }

  return;
}

bool_t
bgp_peer_orf_capability_active (struct bgp_peer *peer)
{
  if (! CHECK_FLAG (peer->af_flags [BAAI_IP][BSAI_UNICAST],
                    (PEER_FLAG_ORF_PREFIX_SM | PEER_FLAG_ORF_PREFIX_RM))
      && ! CHECK_FLAG (peer->af_flags [BAAI_IP6][BSAI_MULTICAST],
                       (PEER_FLAG_ORF_PREFIX_SM | PEER_FLAG_ORF_PREFIX_RM)))
    return PAL_FALSE;

  return PAL_TRUE;
}

/* Check for Stirct Match of Negotiated Capabilities */
bool_t
bgp_peer_strict_cap_same (struct bgp_peer *peer)
{
  u_int32_t baai;
  u_int32_t bsai;

  if (CHECK_FLAG (peer->cap, PEER_CAP_DYNAMIC_RCV)
      && ! CHECK_FLAG (peer->flags, PEER_FLAG_DYNAMIC_CAPABILITY))
    return PAL_FALSE;

  if ((CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_OLD_RCV)
       || CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV))
      && CHECK_FLAG (peer->flags, PEER_FLAG_NO_ROUTE_REFRESH_CAP))
    return PAL_FALSE;

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        if (CHECK_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_ORF_PREFIX_SM)
            && ! CHECK_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_SM_RCV))
          return PAL_FALSE;
        if (CHECK_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_ORF_PREFIX_RM)
            && ! CHECK_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_RM_RCV))
          return PAL_FALSE;

        if (peer->afc [baai][bsai] != peer->afc_recv [baai][bsai])
          return PAL_FALSE;

      }

  return PAL_TRUE;
}

/* Cease BGP Peer operation and release dynamic resources */
void
bgp_peer_stop (struct bgp_peer *peer)
{
  u_int8_t orf_name [SU_ADDRSTRLEN];
  struct bgp_peer_inconn_req *picr;
  struct bgp_dec_update_info *bdui;
  u_int32_t baai;
  u_int32_t bsai;
  struct peer_bgp_node *pbgp_node = NULL;
  struct listnode *node = NULL;

  /* Clear all routes: clear all the routes in all the views only if the peer 
   * is configured peer not the real peer
   */
  if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER) && !peer->real_peer)
    {
      LIST_LOOP (peer->peer_bgp_node_list,pbgp_node,node)
        {
           peer->bgp = pbgp_node->bgp;
           bgp_peer_clear_route_all (peer);
        }
       /* reset the peer->bgp to master_bgp */
         peer->bgp = peer->master_bgp;
    }
  else
    bgp_peer_clear_route_all (peer);

  /* Reset time-stamps and counters */
  peer->uptime = 0;
  peer->update_time = 0;
  peer->advtime = 0;

  /* Get the current time */
  peer->last_reset_time = pal_time_current(NULL);

  /* Stop all timers */
  peer->v_auto_start = 0;
  peer->v_connect = 0;
  peer->v_holdtime = 0;
  peer->v_keepalive = 0;
  BGP_TIMER_OFF (peer->t_auto_start);
  BGP_TIMER_OFF (peer->t_connect);
  BGP_TIMER_OFF (peer->t_holdtime);
  BGP_TIMER_OFF (peer->t_keepalive);
  BGP_TIMER_OFF (peer->t_asorig);
  BGP_TIMER_OFF (peer->t_routeadv);
  BGP_TIMER_OFF (peer->t_gshut_timer);

  /* Reset keepalive and holdtime */
  peer->v_keepalive = peer->keepalive;
  peer->v_holdtime = peer->holdtime;

  /* Delete all existing High-Priority events of for the Peer */
  BGP_PEER_FSM_EVENT_DELETE (&BLG, peer);

  /* Delete all existing Low-Priority events of for the Peer */
  BGP_PEER_FSM_EVENT_LOW_DELETE (&BLG, peer);

  /* Clear the Incoming-Connection-Request FIFO */
  while (! FIFO_EMPTY (&peer->bicr_fifo))
    {
      picr = (struct bgp_peer_inconn_req *) FIFO_HEAD (&peer->bicr_fifo);
      FIFO_DEL (&picr->icr_fifo);

      SSOCK_FD_CLOSE (&BLG, picr->icr_sock);

      /* Free the ICR */
      XFREE (MTYPE_TMP, picr);
    }

  /* Clear the Decoded-Update-Information FIFO */
  while (! FIFO_EMPTY (&peer->bdui_fifo))
    {
      bdui = (struct bgp_dec_update_info *) FIFO_HEAD (&peer->bdui_fifo);
      FIFO_DEL (&bdui->ui_fifo);

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

  /* Clear remote router-id. */
  peer->remote_id.s_addr = 0;

  /* Reset route refresh flag. */
  UNSET_FLAG (peer->cap, PEER_CAP_REFRESH_ADV);
  UNSET_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV);
  UNSET_FLAG (peer->cap, PEER_CAP_REFRESH_OLD_RCV);
  UNSET_FLAG (peer->cap, PEER_CAP_DYNAMIC_ADV);
  UNSET_FLAG (peer->cap, PEER_CAP_DYNAMIC_RCV);

  /* reset extasn cap flag */
#ifdef HAVE_EXT_CAP_ASN
  UNSET_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_ADV);
  UNSET_FLAG (peer->cap, PEER_CAP_EXTENDED_ASN_RCV);
#endif /* HAVE_EXT_CAP_ASN */ 

  /* Reset all Capability variables */
  for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
    for (bsai = BSAI_UNICAST ; bsai < BSAI_MAX ; bsai++)
      {
        /* peer address family capability flags*/
        peer->af_cap[baai][bsai] = 0;

        /* peer address family status flags*/
        peer->af_sflags[baai][bsai] = 0;

        /* Received capabilities */
        peer->afc_recv[baai][bsai] = 0;

        /* Advertised capabilities */
        peer->afc_adv[baai][bsai] = 0;

        /* Negotiated capabilities */
        peer->afc_nego[baai][bsai] = 0;

        /* Received ORF prefix-filter */
        peer->orf_plist[baai][bsai] = NULL;

        /* Table version clear.  */
        peer->table_version[baai][bsai] = 0;

        /* ORF received prefix-filter pnt */
        pal_snprintf (orf_name, SU_ADDRSTRLEN,"%s.%d.%d", peer->host,
                      BGP_BAAI2AFI (baai), BGP_BSAI2SAFI (bsai));
        prefix_bgp_orf_remove_all (BGP_VR.owning_ivr, orf_name);

        /*
         * Unset the SENT default route flag.
         * We need to send default route again.
         */
        if (CHECK_FLAG (peer->af_flags [baai][bsai],
                        PEER_FLAG_DEFAULT_ORIGINATE))
          peer->def_orig_route_sent = PAL_FALSE;
      }

  /* De-activate Socket-CB */
  bpn_sock_cb_disconnect (peer);

  return;
}

/* Deletes BGP Peer structure */
s_int32_t
bgp_peer_delete (struct bgp_peer *peer)
{
  struct bgp_filter *filter;
  struct bgp_peer *clone_peer;
  struct listnode *nn;
  struct bgp *bgp;
  u_int32_t baai;
  u_int32_t bsai;
  u_int32_t idx;
  s_int32_t ret;

  ret = 0;

  if (! peer || ! peer->bgp)
    {
      ret = -1;
      goto EXIT;
    }

  bgp = peer->bgp;

  /* Log the deletion */
  bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                 "Peer being deleted");

  /* Stop the Peer */
  bgp_peer_stop (peer);

  /* Delete Peer-Group Relationship */
  if (peer->group)
    {
      listnode_delete (peer->group->peer_list, peer);
      peer_group_config_reset (peer->group);
      peer->group = NULL;
    }

  /* Delete all existing High-Priority events of for the Peer */
  BGP_PEER_FSM_EVENT_DELETE (&BLG, peer);

  /* Delete all existing Low-Priority events of for the Peer */
  BGP_PEER_FSM_EVENT_LOW_DELETE (&BLG, peer);

  /* Dis-associte from Peers list */
  if (! peer->real_peer)
    listnode_delete (bgp->peer_list, peer);

  /* If Incoming Peer, dis-associate from Real-Peer */
  if (peer->real_peer)
    listnode_delete (peer->real_peer->clones_list, peer);

  /* If Real-Peer, delete all associated Clones */
  if (peer->clones_list)
    {
      LIST_LOOP (peer->clones_list, clone_peer, nn)
        {
          /* Send NOTIFY to Incomimg Peer and delete it */
          bpf_register_notify (clone_peer, BGP_NOTIFY_CEASE,
                               BGP_NOTIFY_CEASE_CONFIG_CHANGE,
                               NULL, 0);
          bgp_peer_send_notify (clone_peer);
          bgp_peer_delete (clone_peer);
        }
      list_delete (peer->clones_list);
    }

  /* Free associated Socket-CB, not needed for Config-Only Peers */
  if (peer->sock_cb)
    stream_sock_cb_free (peer->sock_cb, &BLG);

  /* Free Peer host-ID string */
  if (peer->host)
    XFREE (MTYPE_TMP, peer->host);

  /* Free Peer description string */
  if (peer->desc)
    XFREE (MTYPE_PEER_DESC, peer->desc);

  /* Free Peer interface-name string */
  if (peer->ifname)
    XFREE (MTYPE_TMP, peer->ifname);

  /* Free Peer notify data */
  if (peer->notify_info)
    XFREE (MTYPE_BGP_PEER_NOTIFY_DATA, peer->notify_info);

  /* Free Route-Advertisement List structures */
  bgp_peer_adv_list_delete (peer);
  /* set the context only if the peer is configured peer */
  if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER) && !peer->real_peer) 
    {
       bgp_peer_pbgp_node_inctx_get (bgp, peer);
    }

  /* Free filter related memory.  */
  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        /* free the filters from appropriate node*/
        if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER) 
            && !peer->real_peer )
          filter = &peer->pbgp_node_inctx->filter [baai][bsai];
        else
          filter = &peer->filter[baai][bsai];

        if (NULL == filter)
          continue;

        for (idx = FILTER_IN; idx < FILTER_MAX; idx++)
          {
            if (filter->dlist[idx].name)
              XFREE (MTYPE_TMP, filter->dlist[idx].name);
            if (filter->plist[idx].name)
              XFREE (MTYPE_TMP, filter->plist[idx].name);
            if (filter->aslist[idx].name)
              XFREE (MTYPE_TMP, filter->aslist[idx].name);
            if (filter->map[idx].name)
              XFREE (MTYPE_TMP, filter->map[idx].name);
          }

        if (filter->usmap.name)
          XFREE (MTYPE_TMP, filter->usmap.name);

        if (peer->default_rmap[baai][bsai].name)
          XFREE (MTYPE_TMP, peer->default_rmap[baai][bsai].name);

        /* Peer address family deactivate.  */
        peer_afc_unset (peer, BGP_BAAI2AFI (baai), BGP_BSAI2SAFI (bsai));
      }

  /* Delete the bgp nodes from this peer */
     if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER)
         && peer->peer_bgp_node_list 
         && !peer->real_peer && peer->refcnt == 1)
          list_delete (peer->peer_bgp_node_list);

  /* Free Update-source address string */
  if (peer->update_source)
    sockunion_free (peer->update_source);

  /* Free Update-source interface string */
  if (peer->update_if)
    XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);

  /* Free MD5-Auth Password string */
  if (peer->password)
    XFREE (MTYPE_TMP, peer->password);

  /* Free peer structure. */
  XFREE (MTYPE_BGP_PEER, peer);

EXIT:

  return ret;
}

/* Delete BGP Peer from Confguration - Performed only on Real-Peers */
s_int32_t
bgp_peer_config_delete (struct bgp_peer *peer)
{
  struct bgp_peer *clone_peer;
  struct thread t_bpf_event;
  struct listnode *nn;
  s_int32_t ret;
  u_int32_t baai;
  u_int32_t bsai;

  ret = 0;

  if (! peer || peer->real_peer)
    {
      ret = -1;
      goto EXIT;
    }
  
  /* Removing the default-originate */
  for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
    for (bsai = BSAI_UNICAST ; bsai < BSAI_MAX ; bsai++)
      if (CHECK_FLAG (peer->af_flags [baai][bsai],
                      PEER_FLAG_DEFAULT_ORIGINATE))
        peer_default_originate_unset (peer, BGP_BAAI2AFI (baai),
                                      BGP_BSAI2SAFI (bsai), PAL_TRUE);

  /*
   * Perform a Synchronous Manual-Stop Event on Cloned Peers.
   * This will delete them as well.
   */
  if (peer->clones_list)
    {
      LIST_LOOP (peer->clones_list, clone_peer, nn)
        {
          pal_mem_set (&t_bpf_event, 0, sizeof (struct thread));
          THREAD_GLOB (&t_bpf_event) = &BLG;
          THREAD_ARG (&t_bpf_event) = clone_peer;
          THREAD_VAL (&t_bpf_event) = BPF_EVENT_MANUAL_STOP;
          bpf_process_event (&t_bpf_event);
        }
      list_delete (peer->clones_list);
      peer->clones_list = NULL;
    }

  /* Perform a Synchronous Manual-Stop Event on Real Peer */
  pal_mem_set (&t_bpf_event, 0, sizeof (struct thread));
  THREAD_GLOB (&t_bpf_event) = &BLG;
  THREAD_ARG (&t_bpf_event) = peer;
  THREAD_VAL (&t_bpf_event) = BPF_EVENT_MANUAL_STOP;
  bpf_process_event (&t_bpf_event);

  /* Delete the Real-Peer */
  bgp_peer_delete (peer);

EXIT:

  return ret;
}

struct peer_bgp_node *
bgp_peer_pbgp_node_inctx_get (struct bgp *bgp,
                              struct bgp_peer *peer)
{
  struct peer_bgp_node *pbgp_node;
  struct listnode *node;

  pbgp_node = NULL;
  node = NULL;
  peer->pbgp_node_inctx = NULL;

  LIST_LOOP (peer->peer_bgp_node_list, pbgp_node, node)
    {
      if (pbgp_node
          && pbgp_node->bgp->name && bgp->name
          && !pal_strcmp (pbgp_node->bgp->name, bgp->name))
        {
          peer->pbgp_node_inctx = pbgp_node;
          break;
        }
    }
  return pbgp_node;
}

void
bgp_peer_lock (struct bgp_peer *peer)
{
  if (!peer->real_peer)
    peer->refcnt++;
}

void
bgp_peer_unlock (struct bgp_peer *peer)
{
    if (peer && peer->refcnt && !peer->real_peer)
      peer->refcnt--;
}

/* This function deletes a given peer from one view when
 * it is present in multiple views. 
*/
s_int32_t
bgp_peer_del_in_multi_ins (struct bgp *bgp,
                           struct bgp_peer *peer)
{
  struct peer_bgp_node *pbgp_node;
  struct listnode *node;
  u_int32_t baai;
  u_int32_t bsai;
  u_int32_t idx;
  struct bgp_filter *filter;
    
  pbgp_node = NULL;
  node = NULL;
  baai = 0;
  bsai = 0;
  filter = NULL;

  if (!peer || !bgp || !peer->pbgp_node_inctx)
    return BGP_API_SET_ERROR;

  pbgp_node = peer->pbgp_node_inctx;
  peer->bgp = pbgp_node->bgp;

  /* Clear this view's routing table 
     peer->bgp will be pointing to the correct view's bgp */
  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    {
      for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
        {
          if (!pbgp_node->afc[baai][bsai])
            continue;
          bgp_clear_all_routes (peer, 
                                BGP_BAAI2AFI (baai),
                                BGP_BSAI2SAFI (bsai),
                                NULL);

        }
    }

  /* Free filter related memory.  */
  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        filter = &peer->pbgp_node_inctx->filter [baai][bsai];

        if (!filter)
          continue;

        for (idx = FILTER_IN; idx < FILTER_MAX; idx++)
          {
            if (filter->dlist[idx].name)
              XFREE (MTYPE_TMP, filter->dlist[idx].name);
            if (filter->plist[idx].name)
              XFREE (MTYPE_TMP, filter->plist[idx].name);
            if (filter->aslist[idx].name)
              XFREE (MTYPE_TMP, filter->aslist[idx].name);
            if (filter->map[idx].name)
              XFREE (MTYPE_TMP, filter->map[idx].name);
          }

        if (filter->usmap.name)
          XFREE (MTYPE_TMP, filter->usmap.name);

        if (peer->default_rmap[baai][bsai].name)
          XFREE (MTYPE_TMP, peer->default_rmap[baai][bsai].name);
     }

  /* Delete the bgp node for this peer from the peer_bgp list */
  listnode_delete (peer->peer_bgp_node_list, pbgp_node);


  /* Delete the peer entry from peer list of this bgp instance */
  listnode_delete (bgp->peer_list, peer);
    
  /* Free the bgp node memory */
  XFREE (MTYPE_PEER_BGP_NODE, pbgp_node);

  /* check if the peer is getting deleted from master bgp, if yes then
   * modify the master bgp for this peer */
  if (peer->bgp == peer->master_bgp)
    {
      LIST_LOOP (peer->peer_bgp_node_list,pbgp_node,node)
        {
          if (pbgp_node->bgp != peer->master_bgp)
            {
              peer->master_bgp = pbgp_node->bgp;
              peer->bgp = pbgp_node->bgp;
              break;
            }
        } 
    }
  else 
     peer->bgp = peer->master_bgp;

  pbgp_node = NULL;
  bgp_peer_unlock(peer);

  return BGP_API_SET_SUCCESS;
}


s_int32_t
bgp_peer_group_cmp (struct bgp_peer_group *g1,
                    struct bgp_peer_group *g2)
{
  return pal_strcmp (g1->name, g2->name);
}

/* If peer is configured at least one address family return 1. */
int
bgp_peer_group_active (struct bgp_peer *peer)
{
  if (peer->af_group[BAAI_IP][BSAI_UNICAST]
      || peer->af_group[BAAI_IP][BSAI_MULTICAST]
      || peer->af_group[BAAI_IP6][BSAI_UNICAST]
      || peer->af_group[BAAI_IP6][BSAI_MULTICAST])
    return 1;
  return 0;
}

struct bgp_peer_group *
bgp_peer_group_lookup (struct bgp *bgp, u_int8_t *name)
{
  struct bgp_peer_group *group;
  struct listnode *nn;

  LIST_LOOP (bgp->group_list, group, nn)
    {
      if (pal_strcmp (group->name, name) == 0)
        return group;
    }

  return NULL;
}

struct bgp_peer_group *
bgp_peer_group_get (struct bgp *bgp, u_int8_t *name)
{
  struct bgp_peer_group *group;

  group = bgp_peer_group_lookup (bgp, name);
  if (group)
    return group;

  group = XCALLOC (MTYPE_BGP_PEER_GROUP, sizeof (struct bgp_peer_group));

  if (! group)
    {
      zlog_err (&BLG, "[%s]: out of memory.", __FUNCTION__);
      return group;
    }

  group->name = XSTRDUP (MTYPE_TMP, name);
  group->peer_list = list_new ();
  group->num = 0;
  group->conf = bgp_peer_new (PAL_TRUE);
  if (!group->conf)
    {
      zlog_err (&BLG, "[%s]: no memory for config.", __FUNCTION__);
      XFREE (MTYPE_BGP_PEER_GROUP, group);
      return NULL;
    }
  bgp_peer_adv_list_init (group->conf);
  if (! bgp_config_check (bgp, BGP_CFLAG_NO_DEFAULT_IPV4))
    group->conf->afc[BAAI_IP][BSAI_UNICAST] = 1;
  group->conf->host = XSTRDUP (MTYPE_TMP, name);
  group->conf->bgp = bgp;
  group->conf->group = group;
  group->conf->as = 0;
  group->conf->local_as = 0;
  group->conf->ttl = 1;
  group->conf->v_routeadv = BGP_DEFAULT_EBGP_ROUTEADV;
  UNSET_FLAG (group->conf->config, PEER_CONFIG_TIMER);
  UNSET_FLAG (group->conf->config, PEER_CONFIG_CONNECT);
  group->conf->keepalive = bgp->default_keepalive;
  group->conf->holdtime = bgp->default_holdtime;
  group->conf->connect = 0;
  SET_FLAG (group->conf->flags, PEER_FLAG_IN_GROUP);
  group->bgp = bgp;
  listnode_add_sort (bgp->group_list, group);

  return group;
}

void
peer_group2peer_config_copy (struct bgp_peer_group *group,
                             struct bgp_peer *peer,
                             afi_t afi, safi_t safi)
{
  struct bgp_filter *pfilter;
  struct bgp_filter *gfilter;
  struct bgp_peer *conf;
  u_int32_t baai;
  u_int32_t bsai;
  u_int32_t out;
  u_int32_t in;
  u_int32_t temp_config = 0;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  conf = group->conf;
  in = FILTER_IN;
  out = FILTER_OUT;

  pfilter = &peer->filter [baai][bsai];
  gfilter = &conf->filter [baai][bsai];

  /* remote-as */
  if (conf->as)
    peer->as = conf->as;

  /* local-as */
  if (conf->local_as)
    peer->local_as = conf->local_as;

  /* TTL */
  peer->ttl = conf->ttl;

  /* Weight */
  peer->weight[baai][bsai] = conf->weight[baai][bsai];

  /* Version */
  peer->version = conf->version;

  /* peer flags apply */
  peer->flags = conf->flags;
   
  /* Unset Disallow-Infinite-Holdtime Flag for the peer as it is not allowed per peer basis of a peer group*/
   if (CHECK_FLAG (conf->flags, PEER_DISALLOW_INFINITE_HOLD_TIME))
     UNSET_FLAG (peer->flags, PEER_DISALLOW_INFINITE_HOLD_TIME);    

  /* Unset Disallow-Infinite-Holdtime Flag for the peer as it is not
   allowed per peer basis of a peer group*/ 
  if (CHECK_FLAG (conf->flags, PEER_DISALLOW_INFINITE_HOLD_TIME))
    UNSET_FLAG (peer->flags, PEER_DISALLOW_INFINITE_HOLD_TIME); 

  /* peer af_flags apply */
  peer->af_flags [baai][bsai] = conf->af_flags[baai][bsai];

  /* apply to peer config other than advertisement interval*/
  temp_config = conf->config;
  if (CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV))
    SET_FLAG (temp_config, PEER_CONFIG_ROUTEADV);
  else
    UNSET_FLAG (temp_config, PEER_CONFIG_ROUTEADV); 
 /* apply to peer config other than local as */ 
  if (CHECK_FLAG (peer->config, PEER_FLAG_LOCAL_AS))
    SET_FLAG (temp_config, PEER_FLAG_LOCAL_AS);
  else
    UNSET_FLAG (temp_config, PEER_FLAG_LOCAL_AS);

  peer->config = temp_config; 

  /* peer timers apply */
  peer->holdtime = conf->holdtime;
  peer->keepalive = conf->keepalive;
  peer->connect = conf->connect;
  if (CHECK_FLAG (conf->config, PEER_CONFIG_CONNECT))
    peer->v_connect = conf->connect;
  else
    peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;

  /* advertisement-interval reset */
  if ( !CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV))
    {
      if (CHECK_FLAG (conf->config, PEER_CONFIG_ROUTEADV))
        {
          peer->v_routeadv = conf->v_routeadv;
        }
      else
        {
          if (peer_sort (peer) == BGP_PEER_IBGP)
            peer->v_routeadv = BGP_DEFAULT_IBGP_ROUTEADV;
          else
            peer->v_routeadv = BGP_DEFAULT_EBGP_ROUTEADV;
        }
    }

#ifdef HAVE_TCP_MD5SIG
  /* While binding a peer to a peer-group, if a password exists for a
   * peer-group and its not configured for the peer then copy the 
   * peer-group's password and set the MD5 to the peer 
   */
  if (conf->password)
    {
      if (!peer->password)
        peer_password_set (peer, 0, conf->password);
    } 
#endif /* TCP_MD5SIG */

  /* maximum-prefix */
  peer->pmax [baai][bsai] = conf->pmax [baai][bsai];

  /* Threshold */
  peer->threshold [baai][bsai] = conf->threshold [baai][bsai];

  /* allowas-in */
  peer->allowas_in [baai][bsai] = conf->allowas_in [baai][bsai];

  /* default-originate route-map */
  if (conf->default_rmap [baai][bsai].name)
    {
      if (peer->default_rmap [baai][bsai].name)
        XFREE (MTYPE_TMP, peer->default_rmap [baai][bsai].name);
      peer->default_rmap [baai][bsai].name =
          XSTRDUP (MTYPE_TMP, conf->default_rmap [baai][bsai].name);
      peer->default_rmap [baai][bsai].map =
          conf->default_rmap [baai][bsai].map;
    }

  /* update-source apply */
  if (conf->update_source)
    {
      if (peer->update_source)
        sockunion_free (peer->update_source);
      if (peer->update_if)
        {
          XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
          peer->update_if = NULL;
        }
      peer->update_source = sockunion_dup (conf->update_source);
    }
  else if (conf->update_if)
    {
      if (peer->update_if)
        XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
      if (peer->update_source)
        {
          sockunion_free (peer->update_source);
          peer->update_source = NULL;
        }
      peer->update_if = XSTRDUP (MTYPE_PEER_UPDATE_SOURCE,
                                 conf->update_if);
    }

  /* inbound filter apply */
  if (gfilter->dlist[in].name && ! pfilter->dlist[in].name)
    {
      if (pfilter->dlist[in].name)
        XFREE (MTYPE_TMP, pfilter->dlist[in].name);
      pfilter->dlist[in].name = XSTRDUP (MTYPE_TMP, gfilter->dlist[in].name);
      pfilter->dlist[in].alist = gfilter->dlist[in].alist;
    }
  if (gfilter->plist[in].name && ! pfilter->plist[in].name)
    {
      if (pfilter->plist[in].name)
        XFREE (MTYPE_TMP, pfilter->plist[in].name);
      pfilter->plist[in].name = XSTRDUP (MTYPE_TMP, gfilter->plist[in].name);
      pfilter->plist[in].plist = gfilter->plist[in].plist;
    }
  if (gfilter->aslist[in].name && ! pfilter->aslist[in].name)
    {
      if (pfilter->aslist[in].name)
        XFREE (MTYPE_TMP, pfilter->aslist[in].name);
      pfilter->aslist[in].name = XSTRDUP (MTYPE_TMP, gfilter->aslist[in].name);
      pfilter->aslist[in].aslist = gfilter->aslist[in].aslist;
    }
  if (gfilter->map[in].name && ! pfilter->map[in].name)
    {
      if (pfilter->map[in].name)
        XFREE (MTYPE_TMP, pfilter->map[in].name);
      pfilter->map[in].name = XSTRDUP (MTYPE_TMP, gfilter->map[in].name);
      pfilter->map[in].map = gfilter->map[in].map;
    }

  /* outbound filter apply */
  if (gfilter->dlist[out].name)
    {
      if (pfilter->dlist[out].name)
        XFREE (MTYPE_TMP, pfilter->dlist[out].name);
      pfilter->dlist[out].name = XSTRDUP (MTYPE_TMP, gfilter->dlist[out].name);
      pfilter->dlist[out].alist = gfilter->dlist[out].alist;
    }
  else
    {
      if (pfilter->dlist[out].name)
        XFREE (MTYPE_TMP, pfilter->dlist[out].name);
      pfilter->dlist[out].name = NULL;
      pfilter->dlist[out].alist = NULL;
    }
  if (gfilter->plist[out].name)
    {
      if (pfilter->plist[out].name)
        XFREE (MTYPE_TMP, pfilter->plist[out].name);
      pfilter->plist[out].name = XSTRDUP (MTYPE_TMP,
                                          gfilter->plist[out].name);
      pfilter->plist[out].plist = gfilter->plist[out].plist;
    }
  else
    {
      if (pfilter->plist[out].name)
        XFREE (MTYPE_TMP, pfilter->plist[out].name);
      pfilter->plist[out].name = NULL;
      pfilter->plist[out].plist = NULL;
    }
  if (gfilter->aslist[out].name)
    {
      if (pfilter->aslist[out].name)
        XFREE (MTYPE_TMP, pfilter->aslist[out].name);
      pfilter->aslist[out].name = XSTRDUP (MTYPE_TMP,
                                           gfilter->aslist[out].name);
      pfilter->aslist[out].aslist = gfilter->aslist[out].aslist;
    }
  else
    {
      if (pfilter->aslist[out].name)
        XFREE (MTYPE_TMP, pfilter->aslist[out].name);
      pfilter->aslist[out].name = NULL;
      pfilter->aslist[out].aslist = NULL;
    }
  if (gfilter->map[out].name)
    {
      if (pfilter->map[out].name)
        XFREE (MTYPE_TMP, pfilter->map[out].name);
      pfilter->map[out].name = XSTRDUP (MTYPE_TMP,
                                        gfilter->map[out].name);
      pfilter->map[out].map = gfilter->map[out].map;
    }
  else
    {
      if (pfilter->map[out].name)
        XFREE (MTYPE_TMP, pfilter->map[out].name);
      pfilter->map[out].name = NULL;
      pfilter->map[out].map = NULL;
    }

  if (gfilter->usmap.name)
    {
      if (pfilter->usmap.name)
        XFREE (MTYPE_TMP, pfilter->usmap.name);
      pfilter->usmap.name = XSTRDUP (MTYPE_TMP, gfilter->usmap.name);
      pfilter->usmap.map = gfilter->usmap.map;
    }
  else
    {
      if (pfilter->usmap.name)
        XFREE (MTYPE_TMP, pfilter->usmap.name);
      pfilter->usmap.name = NULL;
      pfilter->usmap.map = NULL;
    }

  return;
}

/* Peer group's remote AS configuration.  */
s_int32_t
bgp_peer_group_remote_as (struct bgp *bgp,
                          u_int8_t *group_name,
                          as_t *as)
{
  struct bgp_peer_group *group;
  struct bgp_peer *peer;
  struct listnode *nn;

  group = bgp_peer_group_lookup (bgp, group_name);
  if (! group)
    return BGP_API_SET_ERROR;

  if (group->conf->as == *as)
    return BGP_API_SET_SUCCESS;

  bgp_peer_as_change (group->conf, *as);

  LIST_LOOP (group->peer_list, peer, nn)
    {
      if (peer->as != *as)
        bgp_peer_as_change (peer, *as);
      else if (! CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_START);
    }

  return BGP_API_SET_SUCCESS;
}

s_int32_t
bgp_peer_group_delete (struct bgp_peer_group *group)
{
  struct bgp_peer *peer;
  struct listnode *next;
  struct listnode *nn;
  struct bgp *bgp;

  bgp = group->bgp;

  /* Delete all Peers in Group */
  for (nn = LISTHEAD (group->peer_list); nn; nn = next)
    {
      next = nn->next;
      if ((peer = GETDATA (nn)) != NULL)
        bgp_peer_config_delete (peer);
    }
  list_delete (group->peer_list);

  XFREE (MTYPE_TMP, group->name);

  group->conf->group = NULL;
  bgp_peer_delete (group->conf);

  listnode_delete (bgp->group_list, group);

  XFREE (MTYPE_BGP_PEER_GROUP, group);

  return 0;
}

s_int32_t
bgp_peer_group_remote_as_delete (struct bgp_peer_group *group)
{
  struct bgp_peer *peer;
  struct listnode *nn;

  if (! group->conf->as)
    return 0;

  LIST_LOOP (group->peer_list, peer, nn)
    {
      peer->group = NULL;
      bgp_peer_config_delete (peer);
    }
  list_delete_all_node (group->peer_list);

  group->conf->as = 0;
  peer_group_config_reset (group);

  return 0;
}

s_int32_t
bgp_peer_group_get_id (struct bgp_peer_group *group)
{
  s_int32_t id;
  u_int32_t mask;

  pal_assert (group && group->num < BGP_MAX_PEERS_PER_GRP);
  for (id = 0, mask = 1; mask; ++id, (mask <<= 1))
    {
      if (group->peer_bitmap & mask)
        continue;

      group->peer_bitmap |= mask;
      ++group->num;
      return id;
    }
  pal_assert (1);
  return -1;
}

void
bgp_peer_group_return_id (struct bgp_peer_group *group, struct bgp_peer *peer)
{
  u_int32_t mask;

  pal_assert (group && group->num < BGP_MAX_PEERS_PER_GRP);
  pal_assert (peer && (peer->peer_id >= 0) &&
              (peer->peer_id < BGP_MAX_PEERS_PER_GRP));

  mask = 1 << peer->peer_id;

  pal_assert (group->peer_bitmap & mask);

  group->peer_bitmap &= (~mask);
  --group->num;
}

/* Bind specified Peer to Peer-Group */
s_int32_t
bgp_peer_group_bind (struct bgp *bgp,
                     union sockunion *su,
                     struct bgp_peer_group *group,
                     afi_t afi, safi_t safi, as_t *as)
{
  struct bgp_peer *peer;
  int first_member = 0;

  /* Check peer group's address family.  */
  if (! group->conf->afc[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    return BGP_API_SET_ERR_PEER_GROUP_AF_UNCONFIGURED;

  if (group->num >= BGP_MAX_PEERS_PER_GRP)
    return BGP_API_SET_ERR_TOO_MANY_PEERS_PER_GROUP;

  /* Lookup the peer.  */
  peer = bgp_peer_search (bgp, su);

  /* Create a new peer. */
  if (! peer)
    {
      if (! group->conf->as)
        return BGP_API_SET_ERR_PEER_GROUP_NO_REMOTE_AS;

      peer = bgp_peer_create (su, bgp, bgp->as,
                              group->conf->as, afi, safi);

      if (NULL == peer)
        return BGP_API_SET_ERR_MEM_ALLOC_FAIL;

      peer->group = group;
      peer->af_group[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)] = 1;
      listnode_add (group->peer_list, peer);
      peer->peer_id = bgp_peer_group_get_id (group);
      peer_group2peer_config_copy (group, peer, afi, safi);
      bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                     "Member added to peer group");

      return 0;
    }

  /* When the peer already belongs to peer group, check the consistency.  */
  if (peer->af_group[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    {
      if (pal_strcmp (peer->group->name, group->name) != 0)
        return BGP_API_SET_ERR_PEER_GROUP_CANT_CHANGE;

      return 0;
    }

  /* Check current peer group configuration.  */
  if (bgp_peer_group_active (peer)
      && pal_strcmp (peer->group->name, group->name) != 0)
    return BGP_API_SET_ERR_PEER_GROUP_MISMATCH;

  if (! group->conf->as)
    {
      if (peer_sort (group->conf) != BGP_PEER_INTERNAL
          && peer_sort (group->conf) != peer_sort (peer))
        {
          if (as)
            *as = peer->as;
          return BGP_API_SET_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
        }

      if (peer_sort (group->conf) == BGP_PEER_INTERNAL)
        first_member = 1;
    }

  peer->af_group[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)] = 1;
  peer->afc[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)] = 1;
  if (! peer->group)
    {
      peer->group = group;
      listnode_add (group->peer_list, peer);
      peer->peer_id = bgp_peer_group_get_id (group);
    }

  if (first_member)
    {
      /* Advertisement-interval reset */
      if (!CHECK_FLAG(group->conf->config, PEER_CONFIG_ROUTEADV))
        {
          if (peer_sort (group->conf) == BGP_PEER_IBGP)
            group->conf->v_routeadv = BGP_DEFAULT_IBGP_ROUTEADV;
          else
            group->conf->v_routeadv = BGP_DEFAULT_EBGP_ROUTEADV;
        }

      /* ebgp-multihop reset */
      if (peer_sort (group->conf) == BGP_PEER_IBGP)
        group->conf->ttl = 255;
    }
  peer_group2peer_config_copy (group, peer, afi, safi);

  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

  bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                 "Member added to peer group");
  return 0;
}

s_int32_t
bgp_peer_group_unbind (struct bgp *bgp,
                       struct bgp_peer *peer,
                       struct bgp_peer_group *group,
                       afi_t afi, safi_t safi)
{
  if (! peer->af_group [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    return 0;

  if (group != peer->group)
    return BGP_API_SET_ERR_PEER_GROUP_MISMATCH;

  peer->af_group [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)] = 0;
  peer->afc [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)] = 0;
  peer_af_flag_reset (peer, afi, safi);

  if (! bgp_peer_group_active (peer))
    {
      listnode_delete (group->peer_list, peer);
      bgp_peer_group_return_id (group, peer);
      peer_group_config_reset (group);
      peer->group = NULL;
      if (group->conf->as)
        {
          bgp_peer_config_delete (peer);

          return 0;
        }
      peer_global_config_reset (peer);
    }

  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

  bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                 "Member deleted from peer group");

  return 0;
}

/* BGP Creation */
struct bgp *
bgp_create (as_t as_num, u_int8_t *name, struct ipi_vrf *ivrf)
{
  struct bgp *bgp;
  u_int32_t baai;
  u_int32_t bsai;
  s_int8_t ret1;

  bgp = NULL;

  if (! ivrf)
    goto EXIT;

  bgp = XCALLOC (MTYPE_BGP, sizeof (struct bgp));
  if (! bgp)
    goto EXIT;

  /* Associate BGP Instance with corresponding Lib-VRF */
  bgp->owning_ivrf = ivrf;
  LIB_VRF_SET_PROTO_VRF (ivrf, bgp);

  /* Associate BGP VR Instance with BGP Instance */
  bgp->owning_bvr = &BGP_VR;

  /* Enlist into the 'bgp_list' */
  listnode_add (BGP_VR.bgp_list, bgp);

  bgp->peer_self = bgp_peer_new (PAL_TRUE);
  bgp->peer_self->host = XSTRDUP (MTYPE_TMP, "Self Peer");
  bgp->peer_self->bgp = bgp;

  bgp->peer_list = list_new ();
  bgp->peer_list->cmp = (int (*)(void *, void *)) bgp_peer_cmp;

  bgp->group_list = list_new ();
  bgp->group_list->cmp = (int (*)(void *, void *)) bgp_peer_group_cmp;
  
  /* When route selection is considered if the distance is 0 it is treated as
   * default distance value, bgp_distance_apply() function applies the 
   * appropriate distance. 
   */
  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        bgp->distance_ebgp[baai][bsai] =  0;
        bgp->distance_ibgp[baai][bsai] = 0;
        bgp->distance_local[baai][bsai] = 0;

        bgp->route [baai][bsai] = bgp_table_init (baai);
        bgp->aggregate [baai][bsai] = bgp_table_init (baai);
        bgp->rib [baai][bsai] = bgp_table_init (baai);
        bgp->peer_index [baai][bsai] = vector_init (1);
        ret1 = peer_afc_set (bgp->peer_self, BGP_BAAI2AFI (baai),
                             BGP_BSAI2SAFI (bsai));
       if (ret1 < 0)
          {
            bgp_delete (bgp);
            bgp = NULL;
            zlog_err (&BLG, "Cannot allocate memory!!!\n");
            goto EXIT;
          }

        bgp->table_version [baai][bsai] = 1;
      }

  bgp->default_local_pref = BGP_DEFAULT_LOCAL_PREF;
  bgp->default_holdtime = BGP_DEFAULT_HOLDTIME;
  bgp->default_keepalive = BGP_DEFAULT_KEEPALIVE;
  bgp->neighbors_converged = 0;
  bgp->conv_complete = PAL_FALSE;

  /* Multipath */
  bgp->maxpath_ebgp = 1;
  bgp->maxpath_ibgp = 1;
  /* Set the config value to 1 at the startup */
  bgp->cfg_maxpath_ebgp = 1;
  bgp->cfg_maxpath_ibgp = 1;
  bgp->aslocal_count = 1;

  /* Only IPv4 AFI */
  bgp->distance_table = bgp_table_init (BGP_IPV4_ADDR_AFI);

  /* Initialize the nexthop table which shall hold the nexthop information of 
   * the selected BGP routes. This is required to register the nexthops of 
   * already learnt routes when Nexthop tracking is enabled.
  */
  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    {
      bgp->selrt_count[baai] = 0;
      bgp->nhop_count[baai] = 0;
      if (!bgp->nh_tab[baai])
        bgp->nh_tab[baai] = bgp_table_init (baai);
    }

  if (as_num)
    bgp->as = as_num;

  if (name)
    bgp->name = XSTRDUP (MTYPE_TMP, name);

  bgp_config_set (bgp, BGP_CFLAG_PREFER_OLD_ROUTE);


EXIT:

  return bgp;
}

void
bgp_distance_config_set (struct cli *cli, char *distance_ebgp,
                         char *distance_ibgp, char *distance_local)
{
  struct bgp *bgp;
  afi_t afi = 0;
  safi_t safi = 0;
  u_int32_t baai = 0;
  u_int32_t bsai = 0;
  bgp = cli->index;

  /* Update only the particular AFI/SAFI with the configured value */
  afi =  bgp_cli_mode_afi (cli);
  safi = bgp_cli_mode_safi(cli);

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  bgp->distance_ebgp[baai][bsai] = pal_strtos32 (distance_ebgp,
                                                (char **) NULL, 10);
  bgp->distance_ibgp[baai][bsai] = pal_strtos32 (distance_ibgp,
                                                (char **) NULL, 10);
  bgp->distance_local[baai][bsai] = pal_strtos32 (distance_local,
                                                 (char **) NULL, 10);
}

int
bgp_distance_config_unset(struct cli *cli, u_int32_t distance_ebgp,
                          u_int32_t distance_ibgp, u_int32_t distance_local)
{
  afi_t afi = 0;
  safi_t safi = 0;
  u_int32_t baai = 0;
  u_int32_t bsai = 0;
  struct bgp *bgp = NULL;

  bgp = cli->index;

  afi =  bgp_cli_mode_afi (cli);
  safi = bgp_cli_mode_safi(cli);

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  /* Check if any values are given while unconfiguring, if given,
   * check if the given values are the previously configured values.
   */
  if ((bgp->distance_ebgp[baai][bsai] == distance_ebgp &&
       bgp->distance_ibgp[baai][bsai] == distance_ibgp &&
       bgp->distance_local[baai][bsai] == distance_local) ||
       (!distance_ebgp && !distance_ibgp && !distance_local)) 
    {
      /* Clear the distance only for a particular AFI/SAFI 
       * and only if the above specified conditions are met 
       */
      bgp->distance_ebgp[baai][bsai] = 0;
      bgp->distance_ibgp[baai][bsai] = 0;
      bgp->distance_local[baai][bsai] = 0;
    }
  else
    return CLI_ERROR;

  return CLI_SUCCESS;
}

/* Lookup Default BGP Instance */
struct bgp *
bgp_lookup_default (void)
{
  if (LISTHEAD (BGP_VR.bgp_list))
    return GETDATA (LISTHEAD (BGP_VR.bgp_list));

  return NULL;
}

struct bgp *
bgp_lookup_by_routerid (struct pal_in4_addr *addr)
{
  struct listnode *nn;
  struct bgp *bgp;

  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    if (!pal_mem_cmp (&bgp->router_id, addr, sizeof(struct pal_in4_addr)))
      return bgp;

  return NULL;
}

/* Lookup BGP Instance by 'name' */
struct bgp *
bgp_lookup_by_name (u_int8_t *name)
{
  struct listnode *nn;
  struct bgp *bgp;

  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    if ((! bgp->name && ! name)
        || (bgp->name && name
            && pal_strcmp (bgp->name, name) == 0))
      return bgp;

  return NULL;
}

/* Lookup BGP Instance by vr_id */
struct bgp *
bgp_lookup_by_id (struct lib_globals *zg, u_int32_t vr_id)
{
  struct bgp_vr *bvr = NULL;
  struct ipi_vr *vr;

  vr = ipi_vr_lookup_by_id (zg, vr_id);

  if (vr != NULL)
    bvr = (struct bgp_vr *) vr->proto;

  if (bvr && LISTHEAD (bvr->bgp_list))
    return GETDATA (LISTHEAD (bvr->bgp_list));

  return NULL;
}

struct bgp *
bgp_lookup_by_vrf_id (u_int32_t vr_id, vrf_id_t vrf_id)
{
  if (vrf_id == VRF_ID_DISABLE)
    return bgp_lookup_by_id (&BLG, vr_id);
  else
    {
      struct ipi_vr *vr = ipi_vr_lookup_by_id (&BLG, vr_id);
      if (vr)
	{
	  struct ipi_vrf *vrf = ipi_vrf_lookup_by_id (vr, vrf_id);
	  if (vrf)
	    return LIB_VRF_GET_PROTO_VRF (vrf);
	}
      return NULL;
    }
}

/* Lookup BGP Instance by AS and 'name' */
struct bgp *
bgp_lookup (as_t as, u_int8_t *name)
{
  struct listnode *nn;
  struct bgp *bgp;

  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    if (bgp->as == as
        && ((! bgp->name && ! name)
            || (bgp->name && name
                && pal_strcmp (bgp->name, name) == 0)))
      return bgp;

  return NULL;
}

/* BGP Instance look-up/creation */
s_int32_t
bgp_get (struct bgp **bgp_val, as_t *as, u_int8_t *name)
{
  struct ipi_vrf *ivrf;
  struct bgp *bgp;
  s_int32_t ret;

  ret = BGP_API_SET_SUCCESS;
  *bgp_val = NULL;
  ivrf = NULL;
  bgp = NULL;

  /* Multiple Instance check */
  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      if (name)
        {
          bgp = bgp_lookup_by_name (name);

          if (! bgp)
            {
              /* Associate new BGP Instances with Master Lib-VRF */
              ivrf = ipi_vrf_get_by_name (BGP_VR.owning_ivr, NULL);
              if (! ivrf)
                return BGP_API_SET_ERROR;

              /* Create a new BGP Instance */
              bgp = bgp_create (0, name, ivrf);
              if (! bgp)
                return BGP_API_SET_ERROR;
            }
        }
      else 
        {
          /* If allow-same-peer flag is enabled, donot allow 
             creation of default instance and throw an error */
          if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
             return BGP_API_SET_ERR_DEFAULTINS_FOR_SAMEPEER;
          bgp = bgp_lookup_default ();
        }

      if (! bgp->as)
        {
          bgp->as = *as;

          /* Obtain the Automatic Router-ID */
          bgp_router_id_auto_get (bgp);

	  /* Initialize BGP RIB and Import Scan */
          bnh_scan_init (bgp);

          /* Open BGP Server (Listen) Socket */
          bpn_sock_listen (bgp, BGP_PORT_DEFAULT);
        }
      else if (bgp->as != *as)
        {
          *as = bgp->as;
          return BGP_API_SET_ERR_INSTANCE_MISMATCH;
        }
    }
  else
    {
      /* BGP Instance Name is illegal for single instance */
      if (name)
        return BGP_API_SET_ERR_MULTIPLE_INSTANCE_NOT_SET;

      /* Get default BGP structure if exists. */
      bgp = bgp_lookup_default ();
      if (! bgp)
        return BGP_API_SET_ERROR;
     
      if (bgp->as && bgp->as != *as)
        {
          *as = bgp->as;
          return BGP_API_SET_ERR_AS_MISMATCH;
        }
      else if (! bgp->as)
        {
          bgp->as = *as;

          bgp_config_set (bgp, BGP_CFLAG_PREFER_OLD_ROUTE);

          /* Obtain the Automatic Router-ID */
          bgp_router_id_auto_get (bgp);

	  /* Initialize BGP RIB and Import Scan */
          bnh_scan_init (bgp);

          /* Open BGP Server (Listen) Socket */
          bpn_sock_listen (bgp, BGP_PORT_DEFAULT);
        }
    }

  *bgp_val = bgp;

  return ret;
}

/* Delete BGP Instance */
s_int32_t
bgp_delete (struct bgp *bgp)
{
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;

  ret = 0;

  /* Stop the BGP Scan */
  bnh_scan_uninit (bgp);

  /* Stop the BGP Instance Listen Socket */
  bpn_sock_listen_uninit (bgp);

  /* Delete BGP instance configuration */
  ret = bgp_config_delete (bgp);

  /* Default BGP Instance specific un-initialization */
  if (bgp == bgp_lookup_default ())
    {
      /* Reset all the Flags and fields */
      bgp->bgp_cflags = 0;
      bgp->bgp_sflags = 0;
      bgp->default_keepalive = BGP_DEFAULT_KEEPALIVE;
      bgp->default_holdtime = BGP_DEFAULT_HOLDTIME;
      bgp->default_local_pref = BGP_DEFAULT_LOCAL_PREF;
      bgp->neighbors_converged = 0;
      bgp->conv_complete = PAL_FALSE;

      /* Multipath */
      bgp->maxpath_ebgp = 1;
      bgp->maxpath_ibgp = 1;
      bgp->cfg_maxpath_ebgp = 1;
      bgp->cfg_maxpath_ibgp = 1;
      bgp->aslocal_count = 1;
      /* UNSET flag */
      UNSET_FLAG(bgp->bgp_cflags, BGP_CFLAG_ECMP_ENABLE);

      /* Loose the router-ID */
      bgp->router_id.s_addr = INADDR_ANY;

      /* Reset Confederation configuration */
      bgp->confed_peers_cnt = 0;
      if (bgp->confed_peers)
        {
          XFREE (MTYPE_BGP_CONFED_LIST, bgp->confed_peers);
          bgp->confed_peers = NULL;
        }

      /* Re-Initialize the RIBs for Default BGP Instance */
      for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
        {
          for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
            {
              /* Reset all the Flags and fields */
              bgp->bgp_af_cflags [baai][bsai] = 0;
              bgp->bgp_af_sflags [baai][bsai] = 0;

              bgp->distance_ebgp[baai][bsai] = 0;
              bgp->distance_ibgp[baai][bsai] = 0;
              bgp->distance_local[baai][bsai] = 0;

              peer_afc_set (bgp->peer_self, BGP_BAAI2AFI (baai),
                            BGP_BSAI2SAFI (bsai));
              bgp->table_version [baai][bsai] = 1;
            }
          bgp->selrt_count[baai] = 0;
        }
    }
  else
    bgp_free (bgp);

  return ret;
}

/* BGP Instance Configuration Deletion */
s_int32_t
bgp_config_delete (struct bgp *bgp)
{
  struct bgp_aggregate *aggregate;
  struct bgp_peer_group *group;
  struct bgp_static *bstatic;
  struct bgp_node *rn_next;
  struct bgp_peer *peer;
  struct listnode *next;
  struct listnode *nn;
  struct bgp_node *rn;
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;
  struct prefix rnp;
  ret = 0;

  /* Delete all Peer Groups */
  for (nn = LISTHEAD (bgp->group_list); nn; nn = next)
    {
      next = nn->next;
      if ((group = GETDATA (nn)) != NULL)
        bgp_peer_group_delete (group);
    }

  /* Delete all Peers */
  for (nn = LISTHEAD (bgp->peer_list); nn; nn = next)
    {
      next = nn->next;
      if ((peer = GETDATA (nn)) != NULL)
        {
          /* check if the peer is also visible another view, if yes then
           * dont perform config delete */
          if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER)
              && peer->refcnt >1)
            {
               bgp_peer_pbgp_node_inctx_get (bgp, peer);
               bgp_peer_del_in_multi_ins (bgp, peer);
               peer->pbgp_node_inctx = NULL;
            } 
          else 
             bgp_peer_config_delete (peer);
        }
    }

  /* Stop the Self-Peer (will delete locally originated routes) */
  if (bgp->peer_self)
    bgp_peer_stop (bgp->peer_self);

  /* Delete the RIBs */
  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    {
      for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
        {
          /* Delete all the configured Static Network routes */
          for (rn = bgp_table_top (bgp->route [baai][bsai]);
               rn; rn = rn_next)
            {
              rn_next = bgp_route_next (rn);

              if ((bstatic = rn->info))
                {
		  BGP_GET_PREFIX_FROM_NODE (rn);
                  bgp_static_network_update (bgp, &rnp, bstatic,
                                             BGP_BAAI2AFI (baai),
                                             BGP_BSAI2SAFI (bsai),
                                             PAL_TRUE);

                  rn->info = NULL;

                  if (bstatic->bs_rmap.name)
                    XFREE (MTYPE_TMP, bstatic->bs_rmap.name);

                  XFREE (MTYPE_BGP_STATIC, bstatic);

                  bgp_unlock_node (rn);
                }
            }

          /* Delete all the configured Aggregates */
          for (rn = bgp_table_top (bgp->aggregate [baai][bsai]);
               rn; rn = rn_next)
            {
              rn_next = bgp_route_next (rn);

              if ((aggregate = rn->info))
                {
		  BGP_GET_PREFIX_FROM_NODE (rn);
                  bgp_aggregate_remove_aggregator (bgp, &rnp, aggregate,
                                                   BGP_BAAI2AFI (baai),
                                                   BGP_BSAI2SAFI (bsai));

                  rn->info = NULL;

                  XFREE (MTYPE_BGP_AGGREGATE, aggregate);

                  bgp_unlock_node (rn);
                }
            }

          /* Delete all the BGP Dampening information */
          if (bgp->rfd_cfg [baai][bsai])
            bgp_rfd_cfg_delete (bgp, BGP_BAAI2AFI (baai),
                                BGP_BSAI2SAFI (bsai));
        }
    }

  /* Reset the Distance Table */
  bgp_distance_reset (bgp);

  /* Delete Instance Name */
  if (bgp->name)
    {
      XFREE (MTYPE_TMP, bgp->name);
      bgp->name = NULL;
    }

  /* Reset the AS number */
  bgp->as = 0;

  return ret;
}

/* BGP Instance Free Memory */
s_int32_t
bgp_free (struct bgp *bgp)
{
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;

  ret = 0;

  if (! bgp)
    {
      ret = -1;
      goto EXIT;
    }

  /* Delete the Self-peer */
  if (bgp->peer_self)
    bgp_peer_delete (bgp->peer_self);

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        /* Delete all the RIB entires */
        if (bgp->rib [baai][bsai])
          {
            /*
             * Only free 'table' structure since some nodes
             * might be present in Peer advertisement lists
             * pending withdrawals
             */
            bgp->rib [baai][bsai]->top = NULL;
            bgp_table_finish (bgp->rib [baai][bsai]);
            bgp->rib [baai][bsai] = NULL;
          }

        /* Delete all the Static Network Routes table */
        bgp_table_finish (bgp->route [baai][bsai]);
        bgp->route [baai][bsai] = NULL;

        /* Delete all the Aggregates table */
        bgp_table_finish (bgp->aggregate [baai][bsai]);
        bgp->aggregate [baai][bsai] = NULL;

        /* Delete all the Peer-Index vectors */
        if (bgp->peer_index [baai][bsai])
          vector_free (bgp->peer_index [baai][bsai]);
      }

  /* Free Confederation peers */
  if (bgp->confed_peers)
    XFREE (MTYPE_BGP_CONFED_LIST, bgp->confed_peers);

  /* Free Peer-Group LIst */
  list_free (bgp->group_list);

  /* Free Peer LIst */
  list_free (bgp->peer_list);

  /* Delete bgp distance table */
  if (bgp->distance_table)
    bgp_table_finish (bgp->distance_table);

  /* Delete node from bgp instance list */
  listnode_delete (BGP_VR.bgp_list, bgp);

  /* Dissociate BGP Instance with corresponding Lib-VRF */
  LIB_VRF_SET_PROTO_VRF (bgp->owning_ivrf, NULL);
  bgp->owning_ivrf = NULL;

  XFREE (MTYPE_BGP, bgp);

EXIT:

  return ret;
}

/* Sets bgp status flag to ADD_AS_LOCAL status */
int
bgp_set_local_as_count(struct bgp *bgp, int cnt)
{
  if (bgp == NULL)
    return BGP_API_SET_ERROR;
  if (cnt < 2 || cnt > BGP_LOCAL_AS_COUNT_MAX)
    return BGP_API_SET_ERR_INVALID_VALUE;


  /* This value is considered during encoding */
  bgp->aslocal_count = cnt;
  return BGP_API_SET_SUCCESS;
}


/* Unsets AS-LOCAL prepend CLI induced global config */
int
bgp_unset_local_as_count(struct bgp *bgp, int cnt)
{
  if (!bgp)
    return BGP_API_SET_ERROR;
  if (bgp->aslocal_count != cnt)
    return BGP_API_SET_ERR_INVALID_VALUE;

  bgp->aslocal_count = 1;

  return BGP_API_SET_SUCCESS;
}


/* Search Configured Peers for a Remote IP address match */
struct bgp_peer *
bgp_peer_search (struct bgp *bgp, union sockunion *su)
{
  struct listnode *nn, *nm;
  struct bgp_peer *peer;

  /*
   * If BGP Multiple Instance is configured, search
   * among all configured peers
   */
  if (bgp && ! bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      LIST_LOOP (bgp->peer_list, peer, nn)
        {
          if (sockunion_same (&peer->su, su))
            return peer;
        }
    }
  else
    {
      LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
        {
          LIST_LOOP (bgp->peer_list, peer, nm)
            {
              if (sockunion_same (&peer->su, su))
                return peer;
            }
        }
    }

  return NULL;
}

/* If peer is configured at least one address family return 1. */
bool_t
peer_active (struct bgp_peer *peer)
{
  if (peer->afc [BAAI_IP][BSAI_UNICAST]
      || peer->afc [BAAI_IP][BSAI_MULTICAST]
#ifdef HAVE_IPV6 /*6VPE*/      
      || peer->afc [BAAI_IP6][BSAI_UNICAST]
      || peer->afc [BAAI_IP6][BSAI_MULTICAST]
#endif /*HAVE_IPV6*/
      )
    return PAL_TRUE;

  return PAL_FALSE;
}

/* If peer is negotiated at least one address family return 1. */
bool_t
peer_active_nego (struct bgp_peer *peer)
{
  if (peer->afc_nego [BAAI_IP][BSAI_UNICAST]
      || peer->afc_nego [BAAI_IP][BSAI_MULTICAST]
      || peer->afc_nego [BAAI_IP6][BSAI_UNICAST]
      || peer->afc_nego [BAAI_IP6][BSAI_MULTICAST])
    return PAL_TRUE;

  return PAL_FALSE;
}


void
peer_change_action (struct bgp_peer *peer, afi_t afi, safi_t safi,
                    enum bgp_peer_change_type type, u_int32_t flag )
{
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    return;

  if (type == peer_change_reset)
    {
      if (flag == PEER_FLAG_NO_ROUTE_REFRESH_CAP)
        SET_FLAG (peer->flags,
                  PEER_FLAG_NO_ROUTE_REFRESH_CAP);
    }
  else if (type == peer_change_reset_in)
    {
      if (afi == AFI_IP && safi == SAFI_UNICAST)
        SET_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_IN);
      else
        SET_FLAG (peer->af_sflags [baai][bsai], PEER_STATUS_AF_SOFT_RESET_IN);
    }
  else if (type == peer_change_reset_out)
    {
      if (afi == AFI_IP && safi == SAFI_UNICAST)
        SET_FLAG (peer->sflags, PEER_STATUS_SOFT_RESET_OUT);
      else
        SET_FLAG (peer->af_sflags [baai][bsai], PEER_STATUS_AF_SOFT_RESET_OUT);
    }

  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

  return;
}

/* Proper action set. */
s_int32_t
peer_flag_action_set (struct bgp_peer_flag_action *action_list,
                      u_int32_t size,
                      struct bgp_peer_flag_action *action,
                      u_int32_t flag)
{
  int i;
  int found = 0;
  int reset_in = 0;
  int reset_out = 0;
  struct bgp_peer_flag_action *match = NULL;

  /* Check peer's frag action.  */
  for (i = 0; i < size; i++)
    {
      match = &action_list [i];

      if (match->flag == 0)
        break;

      if (match->flag & flag)
        {
          found = 1;

          if (match->type == peer_change_reset_in)
            reset_in = 1;
          if (match->type == peer_change_reset_out)
            reset_out = 1;
          if (match->type == peer_change_reset)
            {
              reset_in = 1;
              reset_out = 1;
            }
          if (match->not_for_member)
            action->not_for_member = 1;
        }
    }

  /* Set peer clear type.  */
  if (reset_in && reset_out)
    action->type = peer_change_reset;
  else if (reset_in)
    action->type = peer_change_reset_in;
  else if (reset_out)
    action->type = peer_change_reset_out;
  else
    action->type = peer_change_none;

  return found;
}

void
peer_flag_modify_action (struct bgp_peer *peer, u_int32_t flag)
{
  if (flag == PEER_FLAG_SHUTDOWN)
    {
      if (CHECK_FLAG (peer->flags, flag))
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_STOP);
      else
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_START);
    }
  else
    {
      if (flag == PEER_FLAG_NO_ROUTE_REFRESH_CAP)
        SET_FLAG (peer->sflags, PEER_STATUS_CAP_ROUTE_REFRESH);

      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
    }

  return;
}

/* Change specified peer flag. */
s_int32_t
peer_flag_modify (struct bgp_peer *peer,
                  u_int32_t flag, u_int32_t set)
{
  struct bgp_peer_flag_action action;
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t found;
  u_int32_t size;

  pal_mem_set (&action, 0, sizeof (struct bgp_peer_flag_action));
  size = sizeof peer_flag_action_list /
         sizeof (struct bgp_peer_flag_action);

  found = peer_flag_action_set (peer_flag_action_list, size,
                                &action, flag);

  /* No flag action is found.  */
  if (! found)
    return BGP_API_SET_ERR_INVALID_FLAG;

  /* Not for peer-group member.  */
  if (action.not_for_member && bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* When unset the peer-group member's flag we have to check
     peer-group configuration.  */
  if (! set && bgp_peer_group_active (peer))
    if (CHECK_FLAG (peer->group->conf->flags, flag))
      {
        if (flag == PEER_FLAG_SHUTDOWN)
          return BGP_API_SET_ERR_PEER_GROUP_SHUTDOWN;
        else
          return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      }

  /* Flag conflict check.  */
  if (set
      && CHECK_FLAG (peer->flags | flag, PEER_FLAG_STRICT_CAP_MATCH)
      && CHECK_FLAG (peer->flags | flag, PEER_FLAG_OVERRIDE_CAPABILITY))
    return BGP_API_SET_ERR_PEER_FLAG_CONFLICT;

  if ((set && CHECK_FLAG (peer->flags, flag) == flag)
      || (! set && ! CHECK_FLAG (peer->flags, flag)))
    return 0;

  if (set)
    SET_FLAG (peer->flags, flag);
  else
    UNSET_FLAG (peer->flags, flag);

  if ( CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              if ((set && CHECK_FLAG (peer->flags, flag))
                  || (! set && ! CHECK_FLAG (peer->flags, flag)))
                continue;

              if (set)
                SET_FLAG (peer->flags, flag);
              else
                UNSET_FLAG (peer->flags, flag);

              if (action.type == peer_change_reset)
                peer_flag_modify_action (peer, flag);
            }
        }
      else if (action.type == peer_change_reset)
        peer_flag_modify_action (peer, flag);
    }
  else
    {
      if (action.type == peer_change_reset)
        peer_flag_modify_action (peer, flag);
    }

  return 0;
}

s_int32_t
peer_flag_set (struct bgp_peer *peer, u_int32_t flag)
{
  return peer_flag_modify (peer, flag, 1);
}

s_int32_t
peer_flag_unset (struct bgp_peer *peer, u_int32_t flag)
{
  return peer_flag_modify (peer, flag, 0);
}

s_int32_t
peer_flag_check (struct bgp_peer *peer, u_int32_t flag)
{
  return CHECK_FLAG (peer->flags, flag);
}

s_int32_t
peer_is_group_member (struct bgp_peer *peer, afi_t afi, safi_t safi)
{
  if (peer->af_group [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    return 1;
  return 0;
}

s_int32_t
peer_af_flag_modify (struct bgp_peer *peer,
                     afi_t afi, safi_t safi,
                     u_int32_t flag, u_int32_t set)
{
  struct bgp_peer_flag_action action;
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t found;
  u_int32_t size;
  u_int32_t baai;
  u_int32_t bsai;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  pal_mem_set (&action, 0, sizeof (struct bgp_peer_flag_action));
  size = sizeof peer_af_flag_action_list /
         sizeof (struct bgp_peer_flag_action);

  found = peer_flag_action_set (peer_af_flag_action_list, size, &action, flag);

  /* No flag action is found.  */
  if (! found)
    return BGP_API_SET_ERR_INVALID_FLAG;

  /* Adress family must be activated.  */
  if (! peer->afc [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  /* Not for peer-group member.  */
  if (action.not_for_member && peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

 /* Spcecial check for reflector client.  */
  if (flag & PEER_FLAG_REFLECTOR_CLIENT
      && peer_sort (peer) != BGP_PEER_IBGP)
    return BGP_API_SET_ERR_NOT_INTERNAL_PEER;

  /* Spcecial check for remove-private-AS.  */
  if (flag & PEER_FLAG_REMOVE_PRIVATE_AS
      && peer_sort (peer) == BGP_PEER_IBGP)
    return BGP_API_SET_ERR_REMOVE_PRIVATE_AS;

  /* When unset the peer-group member's flag we have to check
     peer-group configuration.  */
  if (! set && peer->af_group [baai][bsai])
    if (CHECK_FLAG (peer->group->conf->af_flags [baai][bsai], flag))
      return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

  /* When current flag configuration is same as requested one.  */
  if ((set && CHECK_FLAG (peer->af_flags [baai][bsai], flag) == flag))
    return BGP_API_SET_ERR_OBJECT_ALREADY_EXIST;

  if (! set && ! CHECK_FLAG (peer->af_flags [baai][bsai], flag))
    return BGP_API_SET_ERR_UNKNOWN_OBJECT;

  if (set)
    SET_FLAG (peer->af_flags [baai][bsai], flag);
  else
    UNSET_FLAG (peer->af_flags [baai][bsai], flag);

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              if (! peer->af_group [baai][bsai])
                continue;

              if ((set && CHECK_FLAG (peer->af_flags [baai][bsai], flag) == flag)
                  || (! set && ! CHECK_FLAG (peer->af_flags [baai][bsai], flag)))
                continue;

              if (set)
                SET_FLAG (peer->af_flags [baai][bsai], flag);
              else
                UNSET_FLAG (peer->af_flags [baai][bsai], flag);

              peer_change_action (peer, afi, safi, action.type, flag);
            }
        }
      else
        peer_change_action (peer, afi, safi, action.type, flag);
    }
  else
    peer_change_action (peer, afi, safi, action.type, flag);

  return 0;
}

s_int32_t
peer_af_flag_set (struct bgp_peer *peer, afi_t afi, safi_t safi, u_int32_t flag)
{
  return peer_af_flag_modify (peer, afi, safi, flag, 1);
}

s_int32_t
peer_af_flag_unset (struct bgp_peer *peer, afi_t afi, safi_t safi, u_int32_t flag)
{
  return peer_af_flag_modify (peer, afi, safi, flag, 0);
}

s_int32_t
peer_af_flag_check (struct bgp_peer *peer,
                    afi_t afi, safi_t safi, u_int32_t flag)
{
  return CHECK_FLAG (peer->af_flags [BGP_AFI2BAAI (afi)]
                                    [BGP_SAFI2BSAI (safi)], flag);
}


/* EBGP multihop configuration. */
int
peer_ebgp_multihop_set (struct bgp_peer *peer, u_int8_t ttl)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;

  if (peer_sort (peer) == BGP_PEER_IBGP)
    return 0;

  peer->ttl = ttl;


  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
       if (peer->group)
         g_peer = peer->group->conf;
       else
         return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

       /* peer-group member updates. */
       if (g_peer == peer)
         {
           LIST_LOOP (peer->group->peer_list, peer, nn)
             {
               if (peer_sort (peer) == BGP_PEER_IBGP)
                 continue;

               peer->ttl = ttl;
               BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
             }
         }
       else if (peer_sort (peer) != BGP_PEER_IBGP)
         BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
     }
   else if (peer_sort (peer) != BGP_PEER_IBGP)
     BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

  return 0;
}

int
peer_ebgp_multihop_unset (struct bgp_peer *peer)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;

  if (peer_sort (peer) == BGP_PEER_IBGP)
    return 0;

  if (bgp_peer_group_active (peer))
    peer->ttl = peer->group->conf->ttl;
  else
    peer->ttl = 1;

   if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
     {
       if (peer->group)
         g_peer = peer->group->conf;
       else
         return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

       /* peer-group member updates. */
       if (g_peer == peer)
         {
           LIST_LOOP (peer->group->peer_list, peer, nn)
             {
               if (peer_sort (peer) == BGP_PEER_IBGP)
                 continue;

               peer->ttl = 1;
               BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
             }
         }
       else if (peer_sort (peer) != BGP_PEER_IBGP)
         BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
     }
   else if (peer_sort (peer) != BGP_PEER_IBGP)
     BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

  return 0;
}

/* Neighbor description. */
int
peer_description_set (struct bgp_peer *peer,
                      u_int8_t *desc)
{
  if (peer->desc)
    XFREE (MTYPE_PEER_DESC, peer->desc);

  peer->desc = XSTRDUP (MTYPE_PEER_DESC, desc);

  return 0;
}

int
peer_description_unset (struct bgp_peer *peer)
{
  if (peer->desc)
    XFREE (MTYPE_PEER_DESC, peer->desc);

  peer->desc = NULL;

  return 0;
}

/* Neighbor update-source. */
int
peer_update_source_if_set (struct bgp_peer *peer,
                           u_int8_t *ifname)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;

  if (peer->update_if)
    {
      if (! CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP)
          && pal_strcmp (peer->update_if, ifname) == 0)
        return 0;

      XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
      peer->update_if = NULL;
    }

  if (peer->update_source)
    {
      sockunion_free (peer->update_source);
      peer->update_source = NULL;
    }

  peer->update_if = XSTRDUP (MTYPE_PEER_UPDATE_SOURCE, ifname);

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              if (peer->update_if)
                {
                  if (pal_strcmp (peer->update_if, ifname) == 0)
                    continue;

                  XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
                  peer->update_if = NULL;
                }

              if (peer->update_source)
                {
                  sockunion_free (peer->update_source);
                  peer->update_source = NULL;
                }

              peer->update_if = XSTRDUP (MTYPE_PEER_UPDATE_SOURCE, ifname);

              BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
            }
        }
      else
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
    }
  else
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

  return 0;
}

int
peer_update_source_addr_set (struct bgp_peer *peer,
                             union sockunion *su)
{
  struct bgp_peer_group *group;
  struct listnode *nn;

  if (peer->update_source)
    {
      if (! CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP)
          && sockunion_cmp (peer->update_source, su) == 0)
        return 0;
      sockunion_free (peer->update_source);
      peer->update_source = NULL;
    }

  if (peer->update_if)
    {
      XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
      peer->update_if = NULL;
    }

  peer->update_source = sockunion_dup (su);

  if (! CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

      return 0;
    }

  /* peer-group member updates. */
  group = peer->group;
  LIST_LOOP (group->peer_list, peer, nn)
    {
      if (peer->update_source)
        {
          if (sockunion_cmp (peer->update_source, su) == 0)
            continue;
          sockunion_free (peer->update_source);
          peer->update_source = NULL;
        }

      if (peer->update_if)
        {
          XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
          peer->update_if = NULL;
        }

      peer->update_source = sockunion_dup (su);

      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
    }

  return 0;
}

int
peer_update_source_unset (struct bgp_peer *peer)
{
  struct bgp_peer_group *group;
  struct bgp_peer *g_peer;
  union sockunion *su;
  struct listnode *nn;

  if (! CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP)
      && ! peer->update_source
      && ! peer->update_if)
    return 0;

  if (peer->update_source)
    {
      sockunion_free (peer->update_source);
      peer->update_source = NULL;
    }
  if (peer->update_if)
    {
      XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
      peer->update_if = NULL;
    }

  if (bgp_peer_group_active (peer))
    {
      group = peer->group;

      if (group->conf->update_source)
        {
          su = sockunion_dup (group->conf->update_source);
          peer->update_source = su;
        }
      else if (group->conf->update_if)
        peer->update_if =
          XSTRDUP (MTYPE_PEER_UPDATE_SOURCE, group->conf->update_if);
    }

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              if (! peer->update_source && ! peer->update_if)
                continue;

              if (peer->update_source)
                {
                  sockunion_free (peer->update_source);
                  peer->update_source = NULL;
                }

              if (peer->update_if)
                {
                  XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
                  peer->update_if = NULL;
                }

              BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
            }
        }
      else
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
    }
  else
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

  return 0;
}

int
peer_default_originate_set (struct bgp_peer *peer,
                            afi_t afi, safi_t safi,
                            u_int8_t *rmap)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;

  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  /* SAFI must be Unicast */
  if (safi != SAFI_UNICAST)
    return BGP_API_SET_ERR_INVALID_AF;

  /* Adress family must be activated.  */
  if (! peer->afc [baai][bsai])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (! CHECK_FLAG (peer->af_flags [baai][bsai],
                    PEER_FLAG_DEFAULT_ORIGINATE)
      || (rmap && ! peer->default_rmap [baai][bsai].name)
      || (rmap && pal_strcmp (rmap, peer->default_rmap [baai][bsai].name)))
    {
      SET_FLAG (peer->af_flags [baai][bsai],
                PEER_FLAG_DEFAULT_ORIGINATE);

      if (rmap)
        {
          if (peer->default_rmap [baai][bsai].name)
            XFREE (MTYPE_TMP, peer->default_rmap [baai][bsai].name);
          peer->default_rmap [baai][bsai].name =
              XSTRDUP (MTYPE_TMP, rmap);
          peer->default_rmap [baai][bsai].map =
              route_map_lookup_by_name (BGP_VR.owning_ivr, rmap);
        }
    }

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
           LIST_LOOP (peer->group->peer_list, peer, nn)
             {
               SET_FLAG (peer->af_flags [baai][bsai],
                         PEER_FLAG_DEFAULT_ORIGINATE);
               if (rmap)
                 {
                   if (peer->default_rmap [baai][bsai].name)
                     XFREE (MTYPE_TMP, peer->default_rmap [baai][bsai].name);
                   peer->default_rmap [baai][bsai].name =
                     XSTRDUP (MTYPE_TMP, rmap);
                   peer->default_rmap [baai][bsai].map =
                     route_map_lookup_by_name (BGP_VR.owning_ivr, rmap);
                 }

               SET_FLAG (peer->af_sflags [baai][bsai],
                         PEER_STATUS_AF_DEFAULT_ORIGINATE);

               BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
             }
         }
       else
         {
           SET_FLAG (peer->af_sflags [baai][bsai],
                     PEER_STATUS_AF_DEFAULT_ORIGINATE);

           BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
         }
   }
 else
   {
     SET_FLAG (peer->af_sflags [baai][bsai],
               PEER_STATUS_AF_DEFAULT_ORIGINATE);

     BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
   }

  return 0;
}

int
peer_default_originate_unset (struct bgp_peer *peer,
                              afi_t afi, safi_t safi,
                              bool_t peer_remove)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  /* SAFI must be Unicast */
  if (safi != SAFI_UNICAST)
    return BGP_API_SET_ERR_INVALID_AF;

  /* Adress family must be activated.  */
  if (! peer->afc [baai][bsai])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (CHECK_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_DEFAULT_ORIGINATE))
    {
      UNSET_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_DEFAULT_ORIGINATE);

      if (peer->default_rmap [baai][bsai].name)
        XFREE (MTYPE_TMP, peer->default_rmap [baai][bsai].name);
      peer->default_rmap [baai][bsai].name = NULL;
      peer->default_rmap [baai][bsai].map = NULL;
    }

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
       g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              UNSET_FLAG (peer->af_flags [baai][bsai],
                          PEER_FLAG_DEFAULT_ORIGINATE);

              if (peer->default_rmap [baai][bsai].name)
                XFREE (MTYPE_TMP, peer->default_rmap [baai][bsai].name);
              peer->default_rmap [baai][bsai].name = NULL;
              peer->default_rmap [baai][bsai].map = NULL;

              /* If peer_remove is set, then call peer_default_originate()
                 directly to remove the Default routing entry otherwise
                 do manual reset */
              if (peer_remove)
                bgp_peer_default_originate (peer, afi, safi, PAL_TRUE);
              else
                {
                  SET_FLAG (peer->af_sflags [baai][bsai],
                            PEER_STATUS_AF_DEFAULT_ORIGINATE);

                  BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
                }
            }
        }
      else
        {
          /* Do manual-reset when peer-remove is not set. */
          if (peer_remove)
            bgp_peer_default_originate (peer, afi, safi, PAL_TRUE);
          else
            {
              SET_FLAG (peer->af_sflags [baai][bsai],
                        PEER_STATUS_AF_DEFAULT_ORIGINATE);

              BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
            }
        }
    }
  else
    {
      /* Do manual-reset when peer-remove is not set. */
      if (peer_remove)
        bgp_peer_default_originate (peer, afi, safi, PAL_TRUE);
      else
        {
          SET_FLAG (peer->af_sflags [baai][bsai],
                    PEER_STATUS_AF_DEFAULT_ORIGINATE);

          BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
        }
    }

  return 0;
}

int
peer_port_set (struct bgp_peer *peer, u_int16_t port)
{
   struct bgp_peer *g_peer;
   struct listnode *nn;

   if (bgp_peer_group_active (peer))
     return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
  
   peer->sock_port = port;

   if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
     {
       if (peer->group)
        g_peer = peer->group->conf;
       else
         return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

       /* peer-group member updates. */
       if (g_peer == peer)
         {
           LIST_LOOP (peer->group->peer_list, peer, nn)
             {
                peer->sock_port = port;
                BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
             }
         }
       else
         BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
     }
   else
     BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
 
  return 0;
}

int
peer_port_unset (struct bgp_peer *peer)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;

  peer->sock_port = BGP_PORT_DEFAULT;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              peer->sock_port = BGP_PORT_DEFAULT;
              BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
            }
        }
      else
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);
    }
  else
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

  return 0;
}

/* neighbor weight. */
int
peer_weight_set (struct bgp_peer *peer, u_int16_t weight,
                 afi_t afi, safi_t safi)
{
  u_int32_t baai = 0;
  u_int32_t bsai = 0;
  struct bgp_peer *g_peer = NULL;
  struct listnode *nn = NULL;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  peer->weight[baai][bsai] = weight;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              peer->weight[baai][bsai] = weight;
            }
        }
    }

  return BGP_API_SET_SUCCESS;
}

int
peer_weight_unset (struct bgp_peer *peer, afi_t afi, safi_t safi)
{
  u_int32_t baai = 0;
  u_int32_t bsai = 0;
  struct bgp_peer *g_peer;
  struct listnode *nn;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  /* If a weight has been set for a peer-group member then while unsetting
   * update its weight with that of the peer-group weight else clear it 
   */
  if (bgp_peer_group_active (peer))
    peer->weight[baai][bsai] = peer->group->conf->weight[baai][bsai];
  else
    peer->weight[baai][bsai] = BGP_DEFAULT_WEIGHT;

  /* If the weight is being unset for a peer-group then loop through all 
   * the members and clear the weight 
   */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* When the weight for a peer-group is unset, loop-through all the
       * members of the peer-group and clear the weight
       */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              peer->weight [baai][bsai] = BGP_DEFAULT_WEIGHT;
            }
        }
    }

  return BGP_API_SET_SUCCESS;
}

int
peer_timers_set (struct bgp_peer *peer,
                 u_int32_t keepalive,
                 u_int32_t holdtime)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t ret = 0;

  /* Not for peer group memeber.  */
  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* keepalive value check.  */
  if (keepalive > 65535)
    return BGP_API_SET_ERR_INVALID_VALUE;

  /* Holdtime value check.  */
  if (holdtime > 65535)
    return BGP_API_SET_ERR_INVALID_VALUE;

  /* Holdtime value must be either 0 or greater than 3.  */
  if (holdtime < 3 && holdtime != 0)
    return BGP_API_SET_ERR_INVALID_HOLD_TIME;

 /* Holdtime disallow_infinite_hold_time.  */
  if (holdtime == 0)
    if (CHECK_FLAG (peer->flags, PEER_DISALLOW_INFINITE_HOLD_TIME))
      return BGP_API_SET_ERR_INFINITE_HOLD_TIME_VALUE;  

 /* Holdtime value check */
  if (holdtime != 0 && holdtime < BGP_DEFAULT_HOLDTIME)
    ret = BGP_API_SET_WARN_HOLD_LESS_DEFAULT;  
  if (holdtime < keepalive || holdtime < (3 * keepalive))
    ret = BGP_API_SET_WARN_HOLD_AND_KEEPALIVE_INVALID;

  /* Set value to the configuration. */
  SET_FLAG (peer->config, PEER_CONFIG_TIMER);
  peer->holdtime = holdtime;
  peer->keepalive = keepalive;

   if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
     {
       if (peer->group)
         g_peer = peer->group->conf;
       else
         return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

       /* peer-group member updates. */
       if (g_peer == peer)
       {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              SET_FLAG (peer->config, PEER_CONFIG_TIMER);
              peer->holdtime = holdtime;
              peer->keepalive = keepalive;
            }
       }
     }
  return ret;
}

int
peer_timers_unset (struct bgp_peer *peer)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;

  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Clear configuration. */
  UNSET_FLAG (peer->config, PEER_CONFIG_TIMER);
  peer->keepalive = peer->bgp->default_keepalive;
  peer->holdtime = peer->bgp->default_holdtime;

   if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
     {
       if (peer->group)
         g_peer = peer->group->conf;
       else
         return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

       /* peer-group member updates. */
       if (g_peer == peer)
       {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              UNSET_FLAG (peer->config, PEER_CONFIG_TIMER);
              peer->holdtime = 0;
              peer->keepalive = 0;
            }
       }
    }
  return 0;
}

int
peer_timers_connect_set (struct bgp_peer *peer,
                         u_int32_t connect)
{
   struct bgp_peer *g_peer;
   struct listnode *nn;

  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  if (connect > 65535)
    return BGP_API_SET_ERR_INVALID_VALUE;

  /* Set value to the configuration. */
  SET_FLAG (peer->config, PEER_CONFIG_CONNECT);
  peer->connect = connect;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
     {
       if (peer->group)
         g_peer = peer->group->conf;
       else
         return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

       /* peer-group member updates. */
       if (g_peer == peer)
       {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              /* Set value to the configuration. */
              SET_FLAG (peer->config, PEER_CONFIG_CONNECT);
              peer->connect = connect;

            }
       }
   }
  return 0;
}

int
peer_timers_connect_unset (struct bgp_peer *peer)
{
   struct bgp_peer *g_peer;
   struct listnode *nn;

  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Clear configuration. */
  UNSET_FLAG (peer->config, PEER_CONFIG_CONNECT);
  peer->connect = 0;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
     {
       if (peer->group)
         g_peer = peer->group->conf;
       else
         return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

       /* peer-group member updates. */
       if (g_peer == peer)
       {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              /*Clear configuration. */
              UNSET_FLAG (peer->config, PEER_CONFIG_CONNECT);
              peer->connect = 0;

            }
       }
     }
  return 0;
}

int
peer_asorig_interval_set (struct bgp_peer *peer, u_int32_t asorig)
{
   struct bgp_peer *g_peer;
   struct listnode *nn;

  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;


  SET_FLAG (peer->config, PEER_CONFIG_ASORIG);
  peer->asorig = asorig;
  peer->v_asorig = asorig;

   if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
     {
       if (peer->group)
         g_peer = peer->group->conf;
       else
         return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

       /* peer-group member updates. */
       if (g_peer == peer)
         {
           LIST_LOOP (peer->group->peer_list, peer, nn)
             {
               SET_FLAG (peer->config, PEER_CONFIG_ASORIG);
               peer->asorig = asorig;
               peer->v_asorig = asorig;
             }
          }
     }
  return 0;
}

int
peer_asorig_interval_unset (struct bgp_peer *peer)
{
   struct bgp_peer *g_peer;
   struct listnode *nn;

  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  UNSET_FLAG (peer->config, PEER_CONFIG_ASORIG);
  peer->asorig = 0;

  peer->v_asorig = BGP_DEFAULT_ASORIG;

   if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
     {
       if (peer->group)
         g_peer = peer->group->conf;
       else
         return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

       /* peer-group member updates. */
       if (g_peer == peer)
         {
           LIST_LOOP (peer->group->peer_list, peer, nn)
             {
               UNSET_FLAG (peer->config, PEER_CONFIG_ASORIG);
               peer->asorig = 0;

               peer->v_asorig = BGP_DEFAULT_ASORIG;
             }
         }
     }

  return 0;
}

int
peer_advertise_interval_set (struct bgp_peer *peer, u_int32_t routeadv, 
                                                    bool_t grp_conf)
{

  if (grp_conf == PAL_FALSE)
    SET_FLAG (peer->config, PEER_CONFIG_ROUTEADV);

  peer->routeadv = routeadv;
  peer->v_routeadv = routeadv;

  /* If the advertisement-interval has been set to 0 */
  if (routeadv == 0)
    {
      if (CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE))
        return BGP_API_SET_ERR_ALREADY_SET;
      else
        {
          SET_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE);
          /* Send an FSM event, route adv expiry as we will be turning off 
           * the timer
           */
          BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_ROUTEADV_EXP);
          /* Turn off the timer so that it does not overload the CPU */ 
          if (peer->t_routeadv)
            {
              BGP_TIMER_OFF (peer->t_routeadv);
              if (BGP_DEBUG (normal, NORMAL))
                zlog_info (&BLG, "Route advertisement timer is stopped"); 
            }
        }
    }
  else
    {
      /* Restart routeadv timer if it had been stopped previously when the
       * advertisement-interval was set to 0 
       */
      if (CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE)
                      && !peer->t_routeadv)
        {
          /* Unset the flag so that we dont stop the timer accidently in 
           * bgp_peer_send_update()
           */
          UNSET_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE); 
          BGP_TIMER_ON (&BLG, peer->t_routeadv, peer, bpf_timer_routeadv,
                        bpf_timer_generate_jitter (peer->v_routeadv));      
          if (BGP_DEBUG (normal, NORMAL))
            zlog_info (&BLG, "Route advertisement timer is started"); 
        }
    }
  
  return BGP_API_SET_SUCCESS; 

}

int
peer_advertise_interval_unset (struct bgp_peer *peer)
{
  UNSET_FLAG (peer->config, PEER_CONFIG_ROUTEADV);
  peer->routeadv = 0;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP)
      && bgp_peer_group_active(peer))
    {
      peer->v_routeadv = peer->group->conf->v_routeadv;
    }
  else
    {
      if (peer_sort (peer) == BGP_PEER_IBGP)
        peer->v_routeadv = BGP_DEFAULT_IBGP_ROUTEADV;
      else
        peer->v_routeadv = BGP_DEFAULT_EBGP_ROUTEADV;
    }
  
  /* Restart routeadv timer if it had been stopped previously when the
     advertisement-interval was set to 0 */
  if (CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE)
                  && !peer->t_routeadv)
    {
      /* Unset the flag so that we dont stop the timer accidently in
       * bgp_peer_send_update()
       */
      UNSET_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE); 
      BGP_TIMER_ON (&BLG, peer->t_routeadv, peer, bpf_timer_routeadv,
                    bpf_timer_generate_jitter (peer->v_routeadv));
      if (BGP_DEBUG (normal, NORMAL))
            zlog_info (&BLG, "Route advertisement timer is started");
    }
  return BGP_API_SET_SUCCESS;
}

int
peer_version_set (struct bgp_peer *peer, u_int32_t version)
{
  if (version != BGP_VERSION_4)
    return BGP_API_SET_ERR_INVALID_VALUE;
  
  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
  
  peer->version = version;
  SET_FLAG (peer->flags, PEER_FLAG_VERSION_CHECK);

  return 0;
}

int
peer_version_unset (struct bgp_peer *peer)
{
  peer->version = BGP_VERSION_4;
  UNSET_FLAG (peer->flags, PEER_FLAG_VERSION_CHECK);
  return 0;
}

/* neighbor interface */
int
peer_interface_set (struct bgp_peer *peer, u_int8_t *ip_str, u_int8_t *str)
{
  struct interface *ifp;
  struct if_vr_master ivm = peer->bgp->owning_ivrf->vr->ifm;
  struct prefix_ipv4 p4;
  union sockunion su;
  s_int32_t ret;
  
  ifp = if_lookup_by_name(&ivm, str);
  
  if (ifp == NULL)
    return BGP_API_INVALID_INTERFACE_NAME;

  /* Determining address family */
  ret = str2sockunion (ip_str, &su);

  if (ret < 0)
    return BGP_API_SET_ERR_INVALID_VALUE;

  /* Prefix checks on IP addresses to determine whether they are on the same subnet */
  if (su.sa.sa_family == AF_INET)
    {
      /* Determining prefix of the entered IPv4 neighbor */
      ret = str2prefix_ipv4 (ip_str, &p4);

      if (ret == 0)
        {
	  /* str2prefix_ipv4 returns 0 in case of invalid IP-address */
	  return BGP_API_SET_ERR_INVALID_VALUE;
	}
      if (ifp->ifc_ipv4)
        {
          /* Comparing the prefix of the interface and the neighbor IP */
          ret = prefix_match (ifp->ifc_ipv4->address, (struct prefix *) &p4);

          if (ret == 0)
            return BGP_API_IP_NOT_IN_SAME_SUBNET;
 	}
      else
	{
	  /* Interface is not configured with IP-address */
	  return BGP_API_IP_NOT_IN_SAME_SUBNET;
	}	
    }
 
  if (peer->ifname)
    XFREE (MTYPE_TMP, peer->ifname);
  peer->ifname = XSTRDUP (MTYPE_TMP, str);

  return CLI_SUCCESS;
}

int
peer_interface_unset (struct bgp_peer *peer, u_int8_t *str)
{
  if (peer->ifname)
    {
      if ( (!pal_strcmp(peer->ifname, str)) )
        {
          XFREE (MTYPE_TMP, peer->ifname);
          peer->ifname = NULL;

          return 0;
        }
      else
	{
	  /* Invalid Interface */
	  return BGP_API_INVALID_INTERFACE_NAME;
	}
    }

  return BGP_API_SET_ERROR;
}

/* Allow-as in.  */
int
peer_allowas_in_set (struct bgp_peer *peer,
                     afi_t afi, safi_t safi,
                     u_int32_t allow_num)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  if (allow_num < 1 || allow_num > 10)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (peer->allowas_in [baai][bsai] != allow_num)
    {
      peer->allowas_in [baai][bsai] = allow_num;
      SET_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_ALLOWAS_IN);
    }

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              if (peer->allowas_in [baai][bsai] != allow_num)
                {
                  peer->allowas_in [baai][bsai] = allow_num;
                  SET_FLAG (peer->af_flags [baai][bsai],
                            PEER_FLAG_ALLOWAS_IN);
                  peer_change_action (peer, afi, safi,
                                      peer_change_reset_in,
                                      PEER_FLAG_ALLOWAS_IN);
                }
            }
        }
      else
       peer_change_action (peer, afi, safi, peer_change_reset_in,
                            PEER_FLAG_ALLOWAS_IN);
    }
  else
    peer_change_action (peer, afi, safi, peer_change_reset_in,
                        PEER_FLAG_ALLOWAS_IN);

  return 0;
}

int
peer_allowas_in_unset (struct bgp_peer *peer,
                       afi_t afi, safi_t safi)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;

  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  if (CHECK_FLAG (peer->af_flags [baai][bsai],
                  PEER_FLAG_ALLOWAS_IN))
    {
      peer->allowas_in [baai][bsai] = 0;
    }

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              if (CHECK_FLAG (peer->af_flags [baai][bsai],
                              PEER_FLAG_ALLOWAS_IN))
                {
                  peer->allowas_in [baai][bsai] = 0;
                  peer_af_flag_unset (peer, afi, safi,
                                      PEER_FLAG_ALLOWAS_IN);
                }
            }
        }
      else
        peer_af_flag_unset (peer, afi, safi, PEER_FLAG_ALLOWAS_IN);
     }
  else
    peer_af_flag_unset (peer, afi, safi, PEER_FLAG_ALLOWAS_IN);

  return 0;
}

/* Set distribute list to the peer. */
int
peer_distribute_set (struct bgp_peer *peer,
                     afi_t afi, safi_t safi,
                     u_int32_t direct, u_int8_t *name)
{
  struct bgp_filter *filter;
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;

  if (bgp_peer_group_active (peer))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  if (! peer->afc [baai][bsai])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (direct != FILTER_IN && direct != FILTER_OUT)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (direct == FILTER_OUT && peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  filter = &peer->filter [baai][bsai];

  if (filter->plist [direct].name)
    return BGP_API_SET_ERR_PEER_FILTER_CONFLICT;

  if (filter->dlist [direct].name)
    XFREE (MTYPE_TMP, filter->dlist [direct].name);
  filter->dlist [direct].name = XSTRDUP (MTYPE_TMP, name);
  filter->dlist [direct].alist =
      access_list_lookup (BGP_VR.owning_ivr, afi, name);

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              filter = &peer->filter [baai][bsai];

              if (! peer->af_group [baai][bsai])
                continue;

              if (filter->dlist [direct].name)
                XFREE (MTYPE_TMP, filter->dlist [direct].name);
              filter->dlist [direct].name = XSTRDUP (MTYPE_TMP, name);
              filter->dlist [direct].alist =
                      access_list_lookup (BGP_VR.owning_ivr, afi, name);
            }
        }
    }

  return 0;
}

int
peer_distribute_unset (struct bgp_peer *peer, afi_t afi,
                       safi_t safi, u_int32_t direct)
{
  struct bgp_filter *filter;
  struct bgp_filter *gfilter;
  struct bgp_peer *g_peer;
  struct listnode *nn;

  if (! peer->afc [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (direct != FILTER_IN && direct != FILTER_OUT)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (direct == FILTER_OUT && peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  filter = &peer->filter [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  /* apply peer-group filter */
  if (peer->af_group [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    {
      gfilter = &peer->group->conf->filter [BGP_AFI2BAAI (afi)]
                                           [BGP_SAFI2BSAI (safi)];

      if (gfilter->dlist [direct].name)
        {
          if (filter->dlist [direct].name)
            XFREE (MTYPE_TMP, filter->dlist [direct].name);
          filter->dlist [direct].name = XSTRDUP (MTYPE_TMP,
                                        gfilter->dlist [direct].name);
          filter->dlist [direct].alist = gfilter->dlist [direct].alist;
          return 0;
        }
    }

  if (filter->dlist [direct].name)
    XFREE (MTYPE_TMP, filter->dlist [direct].name);
  filter->dlist [direct].name = NULL;
  filter->dlist [direct].alist = NULL;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              filter = &peer->filter [BGP_AFI2BAAI (afi)]
                                     [BGP_SAFI2BSAI (safi)];

              if (! peer->af_group [BGP_AFI2BAAI (afi)]
                                   [BGP_SAFI2BSAI (safi)])
                continue;

              if (filter->dlist [direct].name)
                XFREE (MTYPE_TMP, filter->dlist [direct].name);
              filter->dlist [direct].name = NULL;
              filter->dlist [direct].alist = NULL;
            }
        }
    }

  return 0;
}

/* Update distribute list. */
void
peer_distribute_update (struct ipi_vr *ivr,
                        struct access_list *access,
                        struct filter_list *f)
{
  struct bgp_peer_group *group;
  struct bgp_filter *filter;
  struct listnode *nn, *nm;
  struct bgp_peer *peer;
  struct bgp *bgp;
  u_int32_t direct;
  u_int32_t baai;
  u_int32_t bsai;

  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    {
      LIST_LOOP (bgp->peer_list, peer, nm)
        {
          for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
            for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
              {
                filter = &peer->filter [baai][bsai];

                for (direct = FILTER_IN; direct < FILTER_MAX; direct++)
                  {
                    if (filter->dlist [direct].name)
                      filter->dlist [direct].alist =
                        access_list_lookup (ivr, BGP_BAAI2AFI (baai),
                                            filter->dlist [direct].name);
                    else
                      filter->dlist [direct].alist = NULL;
                  }
              }
        }
      LIST_LOOP (bgp->group_list, group, nm)
        {
          for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
            for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
              {
                filter = &group->conf->filter [baai][bsai];

                for (direct = FILTER_IN; direct < FILTER_MAX; direct++)
                  {
                    if (filter->dlist [direct].name)
                      filter->dlist [direct].alist =
                        access_list_lookup (ivr, BGP_BAAI2AFI (baai),
                                            filter->dlist [direct].name);
                    else
                      filter->dlist [direct].alist = NULL;
                  }
              }
        }
    }

  return;
}

/* Set prefix list to the peer. */
int
peer_prefix_list_set (struct bgp_peer *peer,
                      afi_t afi, safi_t safi,
                      u_int32_t direct, u_int8_t *name)
{
  struct bgp_peer *g_peer;
  struct bgp_filter *filter;
  struct listnode *nn;

  if (! peer->afc [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (direct != FILTER_IN && direct != FILTER_OUT)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (direct == FILTER_OUT && peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  filter = &peer->filter [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (filter->dlist [direct].name)
    return BGP_API_SET_ERR_PEER_FILTER_CONFLICT;

  if (filter->plist [direct].name)
    XFREE (MTYPE_TMP, filter->plist [direct].name);
  filter->plist [direct].name = XSTRDUP (MTYPE_TMP, name);
  filter->plist [direct].plist =
      prefix_list_lookup (BGP_VR.owning_ivr, afi, name);

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              filter = &peer->filter [BGP_AFI2BAAI (afi)]
                                     [BGP_SAFI2BSAI (safi)];

              if (! peer->af_group [BGP_AFI2BAAI (afi)]
                                   [BGP_SAFI2BSAI (safi)])
                continue;

              if (filter->plist [direct].name)
                XFREE (MTYPE_TMP, filter->plist [direct].name);
              filter->plist [direct].name = XSTRDUP (MTYPE_TMP, name);
              filter->plist [direct].plist =
                      prefix_list_lookup (BGP_VR.owning_ivr, afi, name);
            }
        }
   }

  return 0;
}

int
peer_prefix_list_unset (struct bgp_peer *peer,
                        afi_t afi, safi_t safi,
                        u_int32_t direct)
{
  struct bgp_peer *g_peer;
  struct bgp_filter *gfilter;
  struct bgp_filter *filter;
  struct listnode *nn;

  if (! peer->afc[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (direct != FILTER_IN && direct != FILTER_OUT)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (direct == FILTER_OUT && peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  filter = &peer->filter[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  /* apply peer-group filter */
  if (peer->af_group [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    {
      gfilter = &peer->group->conf->filter [BGP_AFI2BAAI (afi)]
                                           [BGP_SAFI2BSAI (safi)];

      if (gfilter->plist[direct].name)
        {
          if (filter->plist[direct].name)
            XFREE (MTYPE_TMP, filter->plist[direct].name);
          filter->plist[direct].name = XSTRDUP (MTYPE_TMP,
                                        gfilter->plist[direct].name);
          filter->plist[direct].plist = gfilter->plist[direct].plist;
          return 0;
        }
    }

  if (filter->plist[direct].name)
    XFREE (MTYPE_TMP, filter->plist[direct].name);
  filter->plist[direct].name = NULL;
  filter->plist[direct].plist = NULL;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              filter = &peer->filter[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

              if (! peer->af_group[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
                continue;

              if (filter->plist[direct].name)
                XFREE (MTYPE_TMP, filter->plist[direct].name);
              filter->plist[direct].name = NULL;
              filter->plist[direct].plist = NULL;
            }
        }
    }

  return 0;
}

/* Update prefix-struct list *list. */
void
peer_prefix_list_update (void)
{
  struct bgp_filter *filter;
  struct listnode *nn, *nm;
  struct bgp_peer_group *group;
  struct bgp_peer *peer;
  u_int32_t direct;
  struct bgp *bgp;
  u_int32_t baai;
  u_int32_t bsai;

  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    {
      LIST_LOOP (bgp->peer_list, peer, nm)
        {
          for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
            for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
              {
                filter = &peer->filter[baai][bsai];

                for (direct = FILTER_IN; direct < FILTER_MAX;
                     direct++)
                  {
                    if (filter->plist[direct].name)
                      filter->plist[direct].plist =
                        prefix_list_lookup (BGP_VR.owning_ivr,
                                            BGP_BAAI2AFI (baai),
                                            filter->plist[direct].name);
                    else
                      filter->plist[direct].plist = NULL;
                  }
              }
        }
      LIST_LOOP (bgp->group_list, group, nm)
        {
          for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
            for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
              {
                filter = &group->conf->filter[baai][bsai];

                for (direct = FILTER_IN; direct < FILTER_MAX;
                     direct++)
                  {
                    if (filter->plist[direct].name)
                      filter->plist[direct].plist =
                        prefix_list_lookup (BGP_VR.owning_ivr,
                                            BGP_BAAI2AFI (baai),
                                            filter->plist[direct].name);
                    else
                      filter->plist[direct].plist = NULL;
                  }
              }
        }
    }

  return;
}

int
peer_aslist_set (struct bgp_peer *peer,
                 afi_t afi, safi_t safi,
                 u_int32_t direct, u_int8_t *name)
{
  struct bgp_filter *filter;
  struct bgp_peer *g_peer;
  struct listnode *nn;

  if (! peer->afc[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (direct != FILTER_IN && direct != FILTER_OUT)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (direct == FILTER_OUT && peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  filter = &peer->filter[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (filter->aslist[direct].name)
    XFREE (MTYPE_TMP, filter->aslist[direct].name);
  filter->aslist[direct].name = XSTRDUP (MTYPE_TMP, name);
  filter->aslist[direct].aslist = as_list_lookup (name);

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              filter = &peer->filter [BGP_AFI2BAAI (afi)]
                                     [BGP_SAFI2BSAI (safi)];

              if (! peer->af_group [BGP_AFI2BAAI (afi)]
                                   [BGP_SAFI2BSAI (safi)])
                continue;

              if (filter->aslist[direct].name)
                XFREE (MTYPE_TMP, filter->aslist[direct].name);
              filter->aslist[direct].name = XSTRDUP (MTYPE_TMP, name);
              filter->aslist[direct].aslist = as_list_lookup (name);
            }
        }
    }

  return 0;
}

int
peer_aslist_unset (struct bgp_peer *peer,
                   afi_t afi, safi_t safi,
                   u_int32_t direct)
{
  struct bgp_peer *g_peer;
  struct bgp_filter *gfilter;
  struct bgp_filter *filter;
  struct listnode *nn;

  if (! peer->afc[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (direct != FILTER_IN && direct != FILTER_OUT)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (direct == FILTER_OUT && peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  filter = &peer->filter[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  /* apply peer-group filter */
  if (peer->af_group[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    {
      gfilter = &peer->group->conf->filter [BGP_AFI2BAAI (afi)]
                                           [BGP_SAFI2BSAI (safi)];

      if (gfilter->aslist[direct].name)
        {
          if (filter->aslist[direct].name)
            XFREE (MTYPE_TMP, filter->aslist[direct].name);
          filter->aslist[direct].name =
              XSTRDUP (MTYPE_TMP, gfilter->aslist[direct].name);
          filter->aslist[direct].aslist =
              gfilter->aslist[direct].aslist;
          return 0;
        }
    }

  if (filter->aslist[direct].name)
    XFREE (MTYPE_TMP, filter->aslist[direct].name);
  filter->aslist[direct].name = NULL;
  filter->aslist[direct].aslist = NULL;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              filter = &peer->filter [BGP_AFI2BAAI (afi)]
                                     [BGP_SAFI2BSAI (safi)];

              if (! peer->af_group [BGP_AFI2BAAI (afi)]
                                   [BGP_SAFI2BSAI (safi)])
                continue;

              if (filter->aslist[direct].name)
                XFREE (MTYPE_TMP, filter->aslist[direct].name);
              filter->aslist[direct].name = NULL;
              filter->aslist[direct].aslist = NULL;
            }
        }
    }

  return 0;
}

void
peer_aslist_update (void)
{
  struct listnode *nn, *nm;
  struct bgp *bgp;
  struct bgp_peer *peer;
  struct bgp_peer_group *group;
  struct bgp_filter *filter;
  u_int32_t baai;
  u_int32_t bsai;
  int direct;

  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    {
      LIST_LOOP (bgp->peer_list, peer, nm)
        {
          for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
            for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
              {
                filter = &peer->filter[baai][bsai];

                for (direct = FILTER_IN; direct < FILTER_MAX; direct++)
                  {
                    if (filter->aslist[direct].name)
                      filter->aslist[direct].aslist =
                        as_list_lookup (filter->aslist[direct].name);
                    else
                      filter->aslist[direct].aslist = NULL;
                  }
              }
        }
      LIST_LOOP (bgp->group_list, group, nm)
        {
          for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
            for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
              {
                filter = &group->conf->filter[baai][bsai];

                for (direct = FILTER_IN; direct < FILTER_MAX; direct++)
                  {
                    if (filter->aslist[direct].name)
                      filter->aslist[direct].aslist =
                        as_list_lookup (filter->aslist[direct].name);
                    else
                      filter->aslist[direct].aslist = NULL;
                  }
              }
        }
    }

  return;
}

/* Set route-map to the peer. */
int
peer_route_map_set (struct bgp_peer *peer,
                    afi_t afi, safi_t safi,
                    u_int32_t direct, u_int8_t *name)
{
  struct bgp_filter *filter;
  struct bgp_peer *g_peer;
  struct listnode *nn;

  if (! peer->afc[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (direct != FILTER_IN && direct != FILTER_OUT)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (direct == FILTER_OUT && peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  if (peer->pbgp_node_inctx)
    filter = &peer->pbgp_node_inctx->filter [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];
  else
    filter = &peer->filter [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (filter->map [direct].name)
    XFREE (MTYPE_TMP, filter->map [direct].name);

  filter->map [direct].name = XSTRDUP (MTYPE_TMP, name);
  filter->map [direct].map =
      route_map_lookup_by_name (BGP_VR.owning_ivr, name);

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
     {
       if (peer->group)
         g_peer = peer->group->conf;
       else
         return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
       /* peer-group member updates. */
       if (g_peer == peer)
         {
           LIST_LOOP (peer->group->peer_list, peer, nn)
             {
               filter = &peer->filter[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

               if (! peer->af_group[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
                 continue;

               if (filter->map [direct].name)
                 XFREE (MTYPE_TMP, filter->map [direct].name);
               filter->map [direct].name = XSTRDUP (MTYPE_TMP, name);
               filter->map [direct].map =
                       route_map_lookup_by_name (BGP_VR.owning_ivr, name);
             }
         }
      }

  return 0;
}

/* Unset route-map from the peer. */
int
peer_route_map_unset (struct bgp_peer *peer,
                      afi_t afi, safi_t safi,
                      u_int32_t direct)
{
  struct bgp_peer *g_peer;
  struct bgp_filter *gfilter;
  struct bgp_filter *filter;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  if (! peer->afc[baai][bsai])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (direct != FILTER_IN && direct != FILTER_OUT)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (direct == FILTER_OUT && peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER)
      && peer->pbgp_node_inctx)
    filter = &peer->pbgp_node_inctx->filter[baai][bsai];
  else
    filter = &peer->filter[baai][bsai];

  /* apply peer-group filter */
  if (peer->af_group[baai][bsai])
    {
      gfilter = &peer->group->conf->filter[baai][bsai];

      if (gfilter->map[direct].name)
        {
          if (filter->map[direct].name)
            XFREE (MTYPE_TMP, filter->map[direct].name);
          filter->map[direct].name = XSTRDUP (MTYPE_TMP,
                                     gfilter->map[direct].name);
          filter->map[direct].map = gfilter->map[direct].map;
          return 0;
        }
    }

  if (filter->map[direct].name)
    XFREE (MTYPE_TMP, filter->map[direct].name);
  filter->map[direct].name = NULL;
  filter->map[direct].map = NULL;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              filter = &peer->filter[baai][bsai];

              if (! peer->af_group[baai][bsai])
                continue;

              if (filter->map[direct].name)
                XFREE (MTYPE_TMP, filter->map[direct].name);
              filter->map[direct].name = NULL;
              filter->map[direct].map = NULL;
            }
        }
    }

  return 0;
}

/* Set unsuppress-map to the peer. */
int
peer_unsuppress_map_set (struct bgp_peer *peer,
                         afi_t afi, safi_t safi,
                         u_int8_t *name)
{
  struct bgp_filter *filter;
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  if (! peer->afc[baai][bsai])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  filter = &peer->filter [baai][bsai];

  if (filter->usmap.name)
    XFREE (MTYPE_TMP, filter->usmap.name);

  filter->usmap.name = XSTRDUP (MTYPE_TMP, name);
  filter->usmap.map =
      route_map_lookup_by_name (BGP_VR.owning_ivr, name);

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              filter = &peer->filter[baai][bsai];

              if (! peer->af_group[baai][bsai])
                continue;

              if (filter->usmap.name)
                XFREE (MTYPE_TMP, filter->usmap.name);
              filter->usmap.name = XSTRDUP (MTYPE_TMP, name);
              filter->usmap.map =
                      route_map_lookup_by_name (BGP_VR.owning_ivr, name);
            }
        }
    }

  return 0;
}

/* Unset route-map from the peer. */
int
peer_unsuppress_map_unset (struct bgp_peer *peer,
                           afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  if (! peer->afc[baai][bsai])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (peer_is_group_member (peer, afi, safi))
    return BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  filter = &peer->filter[baai][bsai];

  if (filter->usmap.name)
    XFREE (MTYPE_TMP, filter->usmap.name);
  filter->usmap.name = NULL;
  filter->usmap.map = NULL;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              filter = &peer->filter[baai][bsai];

              if (! peer->af_group[baai][bsai])
                continue;

              if (filter->usmap.name)
                XFREE (MTYPE_TMP, filter->usmap.name);
              filter->usmap.name = NULL;
              filter->usmap.map = NULL;
            }
        }
    }

  return 0;
}


/* "peer maximum-prefix" API functions. */
int
peer_maximum_prefix_set (struct bgp_peer *peer,
                         afi_t afi, safi_t safi,
                         u_int32_t max,
                         u_int32_t threshold,
                         bool_t warning)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  if (! peer->afc[baai][bsai])
    return BGP_API_SET_ERR_PEER_INACTIVE;

  if (threshold > 100 || threshold < 1 || max == 0)
    return BGP_API_SET_ERR_INVALID_VALUE;

  peer->pmax[baai][bsai] = max;
  peer->threshold[baai][bsai] = threshold;

  if (warning == PAL_TRUE)
    SET_FLAG (peer->af_flags [baai][bsai],
              PEER_FLAG_MAX_PREFIX_WARNING);
  else
    UNSET_FLAG (peer->af_flags [baai][bsai],
                PEER_FLAG_MAX_PREFIX_WARNING);

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              if (! peer->af_group[baai][bsai])
                continue;

              peer->pmax[baai][bsai] = max;
              peer->threshold[baai][bsai] = threshold;
              if (warning == PAL_TRUE)
                SET_FLAG (peer->af_flags[baai][bsai],
                          PEER_FLAG_MAX_PREFIX_WARNING);
              else
                UNSET_FLAG (peer->af_flags[baai][bsai],
                            PEER_FLAG_MAX_PREFIX_WARNING);

              /* apply maximum_prefix check. */
              bgp_peer_max_prefix_overflow (peer, afi, safi);
            }
        }
      else
        /* apply maximum_prefix check. */
        bgp_peer_max_prefix_overflow (peer, afi, safi);
    }
  else
    /* apply maximum_prefix check. */
    bgp_peer_max_prefix_overflow (peer, afi, safi);

  return 0;
}

int
peer_maximum_prefix_unset (struct bgp_peer *peer,
                           afi_t afi, safi_t safi)
{
  struct bgp_peer *g_peer;
  struct listnode *nn;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  if (! peer->afc[baai][bsai])
    return BGP_API_SET_ERR_PEER_INACTIVE;


  UNSET_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_MAX_PREFIX_WARNING);
  peer->pmax[baai][bsai] = 0;
  peer->threshold[baai][bsai] = 0;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;
      /* peer-group member updates. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              if (! peer->af_group[baai][bsai])
                continue;

              UNSET_FLAG (peer->af_flags[baai][bsai],
                          PEER_FLAG_MAX_PREFIX_WARNING);
              peer->pmax[baai][bsai] = 0;
              peer->threshold[baai][bsai] = 0;

             /* Restart the session for peer belongs to peer-group if MAX PREFIX OVERFLOW occured*/
                if (CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
                  {
                    UNSET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
                    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_START);
                  }
            }
        }
    }
 /* Restart the session for normal peer if MAX PREFIX OVERFLOW occured*/ 
    else if (CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
      {
        UNSET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_START);
      }

  return 0;
}


/* Clear BGP Peer through Confguration - Performed only on Real-Peers */
s_int32_t
bgp_peer_clear (struct bgp_peer *peer)
{
  s_int32_t ret;

  ret = 0;

  if (! peer || peer->real_peer)
    {
      ret = -1;
      goto EXIT;
    }

  if (CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
    {
      UNSET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
      BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_START);
    }
  else
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

EXIT:

  return ret;
}

int
peer_clear_soft (struct bgp_peer *peer,
                 afi_t afi, safi_t safi,
                 u_int32_t stype)
{
  struct bgp_filter *filter;
  u_int8_t prefix_type;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  if (peer->bpf_state != BPF_STATE_ESTABLISHED)
    return 0;

  if (! peer->afc[baai][bsai])
    return BGP_API_SET_ERR_AF_UNCONFIGURED;

  if (! BGP_API_CHECK_RANGE (stype, CLEAR_SOFT))
     return BGP_API_SET_ERR_INVALID_VALUE;

  if (stype == BGP_CLEAR_SOFT_OUT || stype == BGP_CLEAR_SOFT_BOTH)
    bgp_announce_route (peer, afi, safi);

  if (stype == BGP_CLEAR_SOFT_IN_ORF_PREFIX)
    {
      if (CHECK_FLAG (peer->af_cap[baai][bsai], PEER_CAP_ORF_PREFIX_SM_ADV)
          && (CHECK_FLAG (peer->af_cap[baai][bsai], PEER_CAP_ORF_PREFIX_RM_RCV)
              || CHECK_FLAG (peer->af_cap[baai][bsai], PEER_CAP_ORF_PREFIX_RM_OLD_RCV)))
        {
          filter = &peer->filter[baai][bsai];

          if (CHECK_FLAG (peer->af_cap[baai][bsai],
                          PEER_CAP_ORF_PREFIX_RM_RCV))
            prefix_type = BGP_ORF_TYPE_PREFIX;
          else
            prefix_type = BGP_ORF_TYPE_PREFIX_OLD;

          if (filter->plist[FILTER_IN].plist)
            {
              if (CHECK_FLAG (peer->af_sflags[baai][bsai],
                              PEER_STATUS_ORF_PREFIX_SEND))
                bgp_peer_send_route_refresh (peer, afi, safi, prefix_type,
                                             BGP_ORF_REFRESH_DEFER, 1);
              bgp_peer_send_route_refresh (peer, afi, safi, prefix_type,
                                           BGP_ORF_REFRESH_IMMEDIATE, 0);
            }
          else
            {
              if (CHECK_FLAG (peer->af_sflags[baai][bsai],
                              PEER_STATUS_ORF_PREFIX_SEND))
                bgp_peer_send_route_refresh (peer, afi, safi, prefix_type,
                                             BGP_ORF_REFRESH_IMMEDIATE, 1);
              else
                bgp_peer_send_route_refresh (peer, afi, safi, 0, 0, 0);
            }
          return 0;
        }
    }

  if (stype == BGP_CLEAR_SOFT_IN || stype == BGP_CLEAR_SOFT_BOTH
      || stype == BGP_CLEAR_SOFT_IN_ORF_PREFIX)
    {
      /* If neighbor has soft reconfiguration inbound flag.
         Use Adj-RIB-In database. */
      if (CHECK_FLAG (peer->af_flags[baai][bsai],
                      PEER_FLAG_SOFT_RECONFIG))
        bgp_soft_reconfig_in (peer, afi, safi);
      else
        {
          /* If neighbor has route refresh capability, send route refresh
             message to the peer. */
          if (CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_OLD_RCV)
              || CHECK_FLAG (peer->cap, PEER_CAP_REFRESH_NEW_RCV))
            bgp_peer_send_route_refresh (peer, afi, safi, 0, 0, 0);
          else
            return BGP_API_SET_ERR_SOFT_RECONFIG_UNCONFIGURED;
        }
    }

  return 0;
}

/* Clear all neighbors. */
int
bgp_clear_all_set (struct bgp *bgp,
                   afi_t afi, safi_t safi,
                   u_int32_t stype)
{
  struct bgp_peer *peer;
  struct listnode *nn;

  /* Update Multipath BGP variable */
  bgp->maxpath_ebgp = bgp->cfg_maxpath_ebgp;
  bgp->maxpath_ibgp = bgp->cfg_maxpath_ibgp;


  /* Clear all neighbors. */
  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      if (stype == BGP_CLEAR_SOFT_NONE)
        bgp_peer_clear (peer);
      else
        peer_clear_soft (peer, afi, safi, stype);
    }

  return 0;
}

/* Clear the specified neighbor connection. */
int
bgp_clear_peer_set (struct bgp *bgp,
                    afi_t afi, safi_t safi,
                    u_int32_t stype, u_int8_t *addr_str)
{
  union sockunion su;
  struct bgp_peer *peer;
  int ret;

  if (! BGP_API_CHECK_RANGE(stype, CLEAR_SOFT))
    return BGP_API_SET_ERR_INVALID_VALUE;

  /* Make sockunion for lookup. */
  ret = str2sockunion (addr_str, &su);
  if (ret < 0)
    return BGP_API_SET_ERR_INVALID_VALUE;

  peer = bgp_peer_search (bgp, &su);
  if (! peer)
    return BGP_API_SET_ERR_UNKNOWN_OBJECT;

  if (stype == BGP_CLEAR_SOFT_NONE)
    bgp_peer_clear (peer);
  else
    peer_clear_soft (peer, afi, safi, stype);

  return 0;
}

/* Clear the specified peer-group. */
int
bgp_clear_peer_group_set (struct bgp *bgp,
                          afi_t afi, safi_t safi,
                          u_int32_t stype,
                          u_int8_t *group_name)
{
  struct bgp_peer_group *group;
  struct bgp_peer *peer;
  struct listnode *nn;

  if (! BGP_API_CHECK_RANGE(stype, CLEAR_SOFT))
    return BGP_API_SET_ERR_INVALID_VALUE;

  group = bgp_peer_group_lookup (bgp, group_name);
  if (! group)
    return BGP_API_SET_ERR_UNKNOWN_OBJECT;

  LIST_LOOP (group->peer_list, peer, nn)
   {
     if (stype == BGP_CLEAR_SOFT_NONE)
       {
         bgp_peer_clear (peer);
         continue;
       }

     if (! peer->af_group[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
       continue;

     peer_clear_soft (peer, afi, safi, stype);
   }

  return 0;
}

/*  Clear all EBGP Connections. */
int
bgp_clear_external_set (struct bgp *bgp,
                        afi_t afi, safi_t safi,
                        u_int32_t stype)
{
  struct listnode *nn;
  struct bgp_peer *peer;

  if (! BGP_API_CHECK_RANGE(stype, CLEAR_SOFT))
    return BGP_API_SET_ERR_INVALID_VALUE;

  LIST_LOOP (bgp->peer_list, peer, nn)
   {
     if (peer_sort (peer) == BGP_PEER_IBGP)
       continue;

     if (stype == BGP_CLEAR_SOFT_NONE)
       bgp_peer_clear (peer);
     else
       peer_clear_soft (peer, afi, safi, stype);
   }

 return 0;
}

/* Clear all BGP connections belong to the specified AS. */
int
bgp_clear_as_set (struct bgp *bgp,
                  afi_t afi, safi_t safi,
                  u_int32_t stype, u_int32_t as_ul)
{
  as_t as;
  struct listnode *nn;
  struct bgp_peer *peer = NULL;

  if ((as_ul == ULONG_MAX) || (as_ul > USHRT_MAX))
    return BGP_API_SET_ERR_INVALID_AS;

  if (! BGP_API_CHECK_RANGE(stype, CLEAR_SOFT))
    return BGP_API_SET_ERR_INVALID_VALUE;

  as = (as_t) as_ul;

  LIST_LOOP (bgp->peer_list, peer, nn)
   {
     if (peer->as != as)
     continue;

     if (stype == BGP_CLEAR_SOFT_NONE)
       bgp_peer_clear (peer);
     else
       peer_clear_soft (peer, afi, safi, stype);
   }

  return 0;
}

/* "ip community-list" API functions. */
int
bgp_community_list_set (char *name, char *str,
                        int type, int direct, int style)
{
  if (direct != BGP_API_FILTER_PERMIT && direct != BGP_API_FILTER_DENY)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (type == COMMUNITY_LIST_NUMBER && ! all_digit (name))
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (style > COMMUNITY_LIST_AUTO || style < COMMUNITY_LIST_STANDARD)
    return BGP_API_SET_ERR_INVALID_VALUE;

  return community_list_set (bgp_clist, name, str, direct, style);
}

/* Support "no ip community-list name". */
int
bgp_community_list_unset (char *name)
{
   return community_list_unset (bgp_clist, name, NULL,
                                0, COMMUNITY_LIST_AUTO);
}

int
bgp_community_list_entry_unset (char *name, char *str,
                                int type, int direct, int style)
{
  if (direct != BGP_API_FILTER_PERMIT && direct != BGP_API_FILTER_DENY)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (type == COMMUNITY_LIST_NUMBER && ! all_digit (name))
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (style > COMMUNITY_LIST_AUTO || style < COMMUNITY_LIST_STANDARD)
    return BGP_API_SET_ERR_INVALID_VALUE;

  return community_list_unset (bgp_clist, name, str, direct, style);
}


/* "ip extcommunity-list" API functions. */
int
bgp_extcommunity_list_set (char *name, char *str,
                           int type, int direct, int style)
{
  if (direct != BGP_API_FILTER_PERMIT && direct != BGP_API_FILTER_DENY)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (type == COMMUNITY_LIST_NUMBER && ! all_digit (name))
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (style > EXTCOMMUNITY_LIST_AUTO || style < EXTCOMMUNITY_LIST_STANDARD)
    return BGP_API_SET_ERR_INVALID_VALUE;

  return extcommunity_list_set (bgp_clist, name, str, direct, style);
}

int
bgp_extcommunity_list_unset (char *name)
{
  return extcommunity_list_unset (bgp_clist, name, NULL, 0, EXTCOMMUNITY_LIST_AUTO);
}

int
bgp_extcommunity_list_entry_unset (char *name, char *str,
                                   int type, int direct, int style)
{
  if (direct != BGP_API_FILTER_PERMIT && direct != BGP_API_FILTER_DENY)
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (type == COMMUNITY_LIST_NUMBER && ! all_digit (name))
    return BGP_API_SET_ERR_INVALID_VALUE;

  if (style > EXTCOMMUNITY_LIST_AUTO || style < EXTCOMMUNITY_LIST_STANDARD)
    return BGP_API_SET_ERR_INVALID_VALUE;

  return extcommunity_list_unset (bgp_clist, name, str, direct, style);
}


/* "ip as-path access-list WORD (deny|permit) .LINE" API functions. */
int
bgp_aspath_access_list_set (char *name, char *regstr, int direct)
{
  if (direct != BGP_API_FILTER_DENY && direct != BGP_API_FILTER_PERMIT)
     return BGP_API_SET_ERR_INVALID_VALUE;

  return as_list_entry_make (name, regstr, direct);
}

/* "no ip as-path access-list WORD (deny|permit) .LINE" API function.
 *  Used to delete one entry from aslist.
 */
int
bgp_aspath_access_list_entry_unset (char *name, char *regstr, int direct)
{
  if (direct != BGP_API_FILTER_DENY && direct != BGP_API_FILTER_PERMIT)
     return BGP_API_SET_ERR_INVALID_VALUE;

  return as_list_entry_delete (name, regstr, direct);
}


/*
 * "no ip as-path access-list WORD" API function.
 *  Used to delete the whole access-list.
 */
int
bgp_aspath_access_list_unset (char *name)
{
  return as_list_entry_delete (name, NULL, 0);
}

/* "aggregate-address" API functions. */
s_int32_t
bgp_aggregate_addr_set (struct bgp *bgp,
                        u_int8_t *prefix_str,
                        afi_t afi, safi_t safi,
                        u_int32_t aggr_type)
{
  return bgp_aggregate_set (bgp, prefix_str, afi, safi, aggr_type);
}

s_int32_t
bgp_aggregate_addr_unset (struct bgp *bgp,
                          u_int8_t *prefix_str,
                          afi_t afi, safi_t safi)
{
  return bgp_aggregate_unset (bgp, prefix_str, afi, safi);
}

#ifdef HAVE_TCP_MD5SIG
int
peer_password_set (struct bgp_peer *peer,
                   u_int8_t type,
                   u_int8_t *password)
{
  struct bgp_listen_sock_lnode *tmp_lnode = NULL;
  pal_sock_handle_t ssock_fd;
  struct bgp_peer *g_peer = NULL;
  struct listnode *nn = NULL;
  int ret = 0;

  /* Same configuration exists.  */
  if (CHECK_FLAG (peer->config, PEER_CONFIG_PASSWORD)
      && peer->password_type == type
      && peer->password
      && pal_strcmp (peer->password, password) == 0)
    return 0;

  /* Set flag, type and password.  */
  SET_FLAG (peer->config, PEER_CONFIG_PASSWORD);
  peer->password_type = type;
  
  /* Check if a password is already present, if it exists delete it and assign 
   * the newly configured password.
   */
  if (peer->password)
    XFREE (MTYPE_TMP, peer->password);
  peer->password = XSTRDUP (MTYPE_TMP, password);
  
  /* peer-group member updates. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* If a password is being set for a peer-group, then loop-through its
       * peer-group members and copy the pass-word to its members only if they 
       * do not have any password configured. */
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              if (!peer->password)
                {
                  SET_FLAG (peer->config, PEER_CONFIG_PASSWORD);
                  peer->password = XSTRDUP (MTYPE_TMP, password);

                  /* set MD5 authentication password to each peer in the group */
                  ssock_fd = SSOCK_CB_GET_SSOCK_FD (peer->sock_cb);
                  if (ssock_fd >= 0
                      && sockunion_family (&peer->su) == AF_INET)
                    {
                      ret = bgp_md5_set (ssock_fd, &peer->su.sin.sin_addr,
                                         peer->password);
                      if (ret < 0)
                        return ret;
                    }

                  /* Set socket option for listening socket. */
                  for (tmp_lnode = peer->bgp->listen_sock_lnode; tmp_lnode;
                      tmp_lnode = tmp_lnode->next)
                    {
                      if ((tmp_lnode->listen_sock >= 0))
                        bgp_md5_set (tmp_lnode->listen_sock,
                              &peer->su.sin.sin_addr, peer->password);
                    }
                }
            }
        }
    }
 
  /* MD5 password to be set only to the peer not to the peer-group */
  if (g_peer != peer)
    { 
      ssock_fd = SSOCK_CB_GET_SSOCK_FD (peer->sock_cb);
      if (ssock_fd >= 0
          && sockunion_family (&peer->su) == AF_INET)
        {
          ret = bgp_md5_set (ssock_fd, &peer->su.sin.sin_addr, peer->password);
          if (ret < 0)
            return ret;
        }

      /* Set socket option for listening socket. */
      for (tmp_lnode = peer->bgp->listen_sock_lnode; tmp_lnode;
           tmp_lnode = tmp_lnode->next)
        {
          if ((tmp_lnode->listen_sock >= 0))
            bgp_md5_set (tmp_lnode->listen_sock,
                         &peer->su.sin.sin_addr, peer->password);
        }
    }

  return 0;
}

int
peer_password_unset (struct bgp_peer *peer)
{
  struct bgp_listen_sock_lnode *tmp_lnode;
  pal_sock_handle_t ssock_fd;
  struct bgp_peer *g_peer;
  struct listnode *nn;
  int ret = 0;

  /* No configuration exists.  */
  if (! CHECK_FLAG (peer->config, PEER_CONFIG_PASSWORD)
      && ! peer->password)
    return 0;

  ssock_fd = SSOCK_CB_GET_SSOCK_FD (peer->sock_cb);
  if (ssock_fd > 0
      && sockunion_family (&peer->su) == AF_INET)
    {
      ret = bgp_md5_unset (ssock_fd, &peer->su.sin.sin_addr, peer->password);
      if (ret < 0)
        return ret;
    }

  /* Set socket option for listening socket. */
  for (tmp_lnode = peer->bgp->listen_sock_lnode; tmp_lnode;
       tmp_lnode = tmp_lnode->next)
    {
      if ((tmp_lnode->listen_sock >= 0))
        bgp_md5_unset (tmp_lnode->listen_sock,
                       &peer->su.sin.sin_addr, peer->password);
    }

  /* Reset configuration.  */
  UNSET_FLAG (peer->config, PEER_CONFIG_PASSWORD);
  peer->password_type = 0;
  
  if (peer->password)
    {
      /* If the password is being unset for a peer-group member, then copy its
       * peer-group's password provided a password exists for a peer-group and
       * its not the same as that of peer else delete the password */
      if (bgp_peer_group_active (peer))
        {
          /* Password of peer-group is not same as that of peer. */
          if (peer->group->conf->password  && 
	      pal_strcmp (peer->password, peer->group->conf->password))
            {
              XFREE (MTYPE_TMP, peer->password);
              peer->password = NULL;
              
              peer->password = XSTRDUP (MTYPE_TMP, peer->group->conf->password);
              SET_FLAG (peer->config, PEER_CONFIG_PASSWORD);
            }
  	  /* Password of peer-group is same as that of peer. */ 
          else
            {
              XFREE (MTYPE_TMP, peer->password);
              peer->password = NULL;
 
              if (! peer->group->conf->password)
                return 0;
            }
        }
      else 
        {
          XFREE (MTYPE_TMP, peer->password);
          peer->password = NULL;
        }
    }

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG;

      /* If a password is being unset for a peer-group then loop through its 
       * peer-group members and delete the password*/
      if (g_peer == peer)
        {
          LIST_LOOP (peer->group->peer_list, peer, nn)
            {
              UNSET_FLAG (peer->config, PEER_CONFIG_PASSWORD);
              XFREE (MTYPE_TMP, peer->password);
              peer->password = NULL;
            }
        }
    }
  return 0;
}
#endif /* TCP_MD5SIG */

/* Convert time_t to week:day:hour:min:sec format string */
s_int8_t *
bgp_time_t2wdhms_str (pal_time_t uptime2,
                      s_int8_t *buf,
                      size_t len)
{
  pal_time_t uptime1;
  struct pal_tm tm;

  /* Check buffer length */
  if (len < BGP_UPTIME_LEN)
    {
      zlog_warn (&BLG, "bgp_time2wdhms_str(): buffer shortage %d", len);
      return "";
    }

  /* If uptime is ZERO, just return blank field */
  if (uptime2 == 0)
    {
      pal_snprintf (buf, len, "%8s", "");
      return buf;
    }

  /* Get current time */
  uptime1 = pal_time_current (NULL);
  uptime1 -= uptime2;
  pal_time_gmt (&uptime1, &tm);

  /* Making formatted timer strings */
  if (uptime1 < ONE_DAY_SECOND)
    pal_snprintf (buf, len, "%02d:%02d:%02d",
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
  else if (uptime1 < ONE_WEEK_SECOND)
    pal_snprintf (buf, len, "%dd%02dh%02dm",
                  tm.tm_yday, tm.tm_hour, tm.tm_min);
  else
    pal_snprintf (buf, len, "%02dw%dd%02dh", tm.tm_yday/7,
                  tm.tm_yday - ((tm.tm_yday/7) * 7), tm.tm_hour);
  return buf;
}

/* Convert seconds to week:day:hour:min:sec format string */
s_int8_t *
bgp_sec2wdhms_str (pal_time_t secs,
                   s_int8_t *buf,
                   size_t len)
{
  struct pal_tm tm;

  /* Check buffer length */
  if (len < BGP_UPTIME_LEN)
    {
      zlog_warn (&BLG, "bgp_sec2wdhms_str(): buffer shortage %d", len);
      return "";
    }

  /* If uptime is ZERO, just return blank field */
  if (secs == 0)
    {
      pal_snprintf (buf, len, "%8s", "");
      return buf;
    }

  /* Convert secs to tm struct */
  pal_time_gmt (&secs, &tm);

  /* Making formatted timer string */
  if (secs < ONE_DAY_SECOND)
    pal_snprintf (buf, len, "%02d:%02d:%02d",
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
  else if (secs < ONE_WEEK_SECOND)
    pal_snprintf (buf, len, "%dd%02dh%02dm",
                  tm.tm_yday, tm.tm_hour, tm.tm_min);
  else
    pal_snprintf (buf, len, "%02dw%dd%02dh", tm.tm_yday/7,
                  tm.tm_yday - ((tm.tm_yday/7) * 7), tm.tm_hour);
  return buf;
}

s_int32_t
bgp_global_init (void)
{
  struct bgp_global *bg;
  s_int32_t ret;

  ret = 0;

  bg = (struct bgp_global *) XCALLOC (MTYPE_BGP_GLOBAL,
                                      sizeof (struct bgp_global));
  if (! bg)
    {
      ret = -1;
      goto EXIT;
    }

  /* Set 'proto' variable in lib_globals */
  LIB_GLOB_SET_PROTO_GLOB (&BLG, bg);

  /* BGP Community List Handler Initialization */
  bgp_clist = bgp_community_list_init ();

  if (! bgp_clist)
    {
      ret = -1;
      goto EXIT;
    }

  /* BGP AS Path List Master Initialization */
  bgp_aslist_master = bgp_as_list_init ();
  as_list_add_hook (peer_aslist_update);
  as_list_delete_hook (peer_aslist_update);

  /* BGP Attribute-Handling Initialization */
  bgp_attr_init ();

  /* BGP Dump Initialization */
#ifdef HAVE_BGP_DUMP
  bgp_dump_all = (struct bgp_dump *) XCALLOC (MTYPE_BGP_DUMP,
                                     sizeof (struct bgp_dump));
  bgp_dump_updates = (struct bgp_dump *) XCALLOC (MTYPE_BGP_DUMP,
                                         sizeof (struct bgp_dump));
  bgp_dump_routes = (struct bgp_dump *) XCALLOC (MTYPE_BGP_DUMP,
                                        sizeof (struct bgp_dump));
  bgp_dump_obuf = stream_new (BGP_MAX_PACKET_SIZE + BGP_DUMP_HEADER_SIZE);
#endif /* HAVE_BGP_DUMP */

#ifdef HAVE_BGP_SDN
  bgp_onion_init ();

  if (! bgp_curl_list)
    {
      bgp_curl_list = list_new ();

      if (! bgp_curl_list)
        {
          ret = -1;
          goto EXIT;
        }
    }
  list_init (bgp_curl_list, NULL, bgp_curl_free);
    
  if (! bgp_curl_list_pending)
    {
      bgp_curl_list_pending = list_new ();

      if (! bgp_curl_list_pending)
        {
          ret = -1;
          goto EXIT;
        }
    }
  list_init (bgp_curl_list_pending, NULL, bgp_curl_free);

  if (! bgp_curlm)
    bgp_curlm = curl_multi_init ();

  curl_global_init (CURL_GLOBAL_ALL);
#endif /* bgp_onion_init */

EXIT:

  return ret;
}

void
bgp_global_delete (void)
{
#ifdef HAVE_BGP_SDN
  bgp_onion_stop ();

  if (bgp_curlm)
    curl_multi_cleanup (bgp_curlm);

  bgp_curlm = NULL;

  curl_global_cleanup ();

  if (bgp_curl_list)
    list_delete (bgp_curl_list);

  bgp_curl_list = NULL;
#endif /* HAVE_BGP_SDN */

#ifdef HAVE_BGP_DUMP
  if (bgp_dump_obuf)
    stream_free (bgp_dump_obuf);
  if (bgp_dump_all)
    XFREE (MTYPE_BGP_DUMP, bgp_dump_all);
  if (bgp_dump_updates)
    XFREE (MTYPE_BGP_DUMP, bgp_dump_updates);
  if (bgp_dump_routes)
    XFREE (MTYPE_BGP_DUMP, bgp_dump_routes);
#endif /* HAVE_BGP_DUMP */

  /* Community list delete */
  bgp_community_list_terminate (bgp_clist);

  /* AS Path list delete */
  bgp_as_list_terminate (bgp_aslist_master);

  /* Free the BGP Global structure */
  XFREE (MTYPE_BGP_GLOBAL, &BGP_GLOBAL);

  /* Set 'proto' variable in 'lib_globals' to NULL */
  LIB_GLOB_SET_PROTO_GLOB (&BLG, NULL);

  return;
}

/* BGP Process Termination Handler */
void
bgp_terminate (void)
{
  return;
}

/* BGP VR Creation */
s_int32_t
bgp_vr_create (struct ipi_vr *ivr)
{
  struct ipi_vrf *ivrf;
  struct bgp_vr *bvr;
  struct bgp *bgp;
  s_int32_t ret;
#ifdef HAVE_SNMP
  u_int32_t idx;
#endif /* HAVE_SNMP */

  ret = 0;

  bvr = XCALLOC (MTYPE_BGP_VR, sizeof (struct bgp_vr));
  if (! bvr)
    {
      zlog_err (&BLG, "[INIT] VR Create:"
                " Cannot allocate memory (%d) @ %s:%d",
                sizeof (struct bgp_vr), __FILE__, __LINE__);

      ret = -1;
      goto EXIT;
    }

  /* Bind BGP VR structure to Lib VR */
  bvr->owning_ivr = ivr;
  ivr->proto = bvr;

  /* Set the VR Context to the new VR */
  BGP_SET_VR_CONTEXT (&BLG, bvr);

  /* BGP VR Route-map initialization */
  bgp_route_map_init (ivr);

  /* BGP VR Access list initialization */
  access_list_add_hook (ivr, peer_distribute_update);
  access_list_delete_hook (ivr, peer_distribute_update);

  /* BGP VR Prefix list initialization */
  prefix_list_add_hook (ivr, peer_prefix_list_update);
  prefix_list_delete_hook (ivr, peer_prefix_list_update);

  /* BGP VR creation time-stamp */
  BGP_VR.start_time = pal_time_current (NULL);

  /* BGP Instance List initialization */
  BGP_VR.bgp_list = list_new ();

  /* BGP VR Route-Flap Dampening initialization */
  BGP_VR.rfd_reuse_list_offset = 0;
  BGP_VR.rfd_reuse_list = XCALLOC (MTYPE_BGP_RFD_REUSE_LIST_ARRAY,
                                   sizeof (struct bgp_rfd_hist_info *) *
                                   BGP_RFD_REUSE_LIST_SIZE);
  if (! BGP_VR.rfd_reuse_list)
    {
      zlog_err (&BLG, "[INIT] VR Init:"
                " Cannot allocate memory (%d) @ %s:%d",
                sizeof (struct bgp_rfd_hist_info),
                __FILE__, __LINE__);

      ret = -1;
      goto EXIT;
    }

  /* Initializing the NHT delay timer to 5 seconds. */
  BGP_VR.nh_tracking_delay_interval = BGP_NH_TRACKING_DELAY_INTERVAL_DEFAULT; 

#ifdef HAVE_SNMP
  /* BGP VR Traps initialization */
  for (idx = 0; idx < BGP_SNMP_NOTIFY_ID_MAX; idx++)
    BGP_VR.snmp_notifications [idx] = vector_init (BGP_SNMP_NOTIFY_VEC_MIN_SIZE);

  /* Register all BGP Traps */
  bgp_snmp_notification_callback_set (BGP_SNMP_NOTIFY_ALL, bgp_snmp_smux_notification);
#endif /* HAVE_SNMP */

  /* Obtain the Master Library VRF for the BGP_VR */
  ivrf = ipi_vrf_get_by_name (BGP_VR.owning_ivr, NULL);
  if (! ivrf)
    {
      ret = -1;
      goto EXIT;
    }

  /* Create the default BGP Instance */
  bgp = bgp_create (0, NULL, ivrf);
  if (! bgp)
    {
      ret = -1;
      goto EXIT;
    }

EXIT:

  return ret;
}

/* BGP VR Deletion */
s_int32_t
bgp_vr_delete (struct ipi_vr *ivr)
{
  struct ipi_vr *ivr_in_cxt;
  struct listnode *next;
  struct listnode *nn;
  struct bgp_vr *bvr;
  struct bgp *bgp;
  s_int32_t ret;

  ret = 0;
  ivr_in_cxt = LIB_GLOB_GET_VR_CONTEXT (&BLG);

  if (! ivr)
    {
      ret = -1;
      goto EXIT;
    }

  bvr = LIB_VR_GET_PROTO_VR (ivr);

  if (! bvr)
    {
      ret = -1;
      goto EXIT;
    }

  /* IMPORTANT : Change VR-Context to Deleting VR */
  BGP_SET_VR_CONTEXT (&BLG, bvr);

  /* Delete all BGP Instances */
  for (nn = LISTHEAD (bvr->bgp_list); nn; nn = next)
    {
      next = nn->next;
      if ((bgp = GETDATA (nn)))
        bgp_delete (bgp);
    }

  /* Delete the Default BGP Instance */
  bgp = bgp_lookup_default ();

  if (bgp)
    bgp_free (bgp);

  list_free (bvr->bgp_list);

  XFREE (MTYPE_BGP_VR, bvr);

EXIT:

  /* IMPORTANT : Restore VR-Context */
  LIB_GLOB_SET_VR_CONTEXT (&BLG, ivr_in_cxt);

  return ret;
}

#ifdef HAVE_EXT_CAP_ASN

/*
 * Function name: bgp_conf_ext_asn_cap()
 * Input        : structure bgp, extended asn flag, flag set 
 * Output       : returns api string 
 * Purpose      : Handling dynamic change of the extended asn capability option
*/

s_int32_t
bgp_conf_ext_asn_cap (struct bgp *bgp,
                      u_int32_t  flag,
                      bool_t     set)
{
  struct bgp_peer *peer     = NULL;
  struct listnode *tmpnode  = NULL;
   
  if (! bgp)
    return BGP_API_SET_ERR_INVALID_BGP;

  if (set && CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    return BGP_API_SET_ERR_ALREADY_EXTASNCAP;
  else if (set && !CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      /* check if BGP_AS_TRANS is configured as neighbor which is not valid
         in an NBGP router */
      if ((bgp->peer_list != NULL) && (bgp->peer_list->count != 0))
        {
          LIST_LOOP (bgp->peer_list, peer,tmpnode)
            if (peer->as == BGP_AS_TRANS)
              return BGP_API_SET_ERR_INVALID_REMOTEASN;
        }
      bgp_option_set (flag);
    }

  else if (!set
           && CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)
           && (bgp != NULL)
           && (! BGP_IS_AS4_MAPPABLE (bgp->as)))
     return BGP_API_SET_ERR_NONMAPPABLE;

  else if (! set && CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))

      bgp_option_unset(flag);
  else if (!set && !CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
     return BGP_API_SET_ERR_NO_EXTASNCAP;
 
 
  
  if (! bgp->as)
    return BGP_API_SET_SUCCESS;

  if (bgp->peer_list != NULL && (bgp->peer_list->count != 0))
    {
      LIST_LOOP (bgp->peer_list, peer,tmpnode)
      /* send notification to all the neighbors and reset the connection */
      if (PAL_TRUE == peer_active (peer))
        BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_MANUAL_RESET);

    }

  return BGP_API_SET_SUCCESS;
}
#endif /* HAVE_EXT_CAP_ASN */
