/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved */

#include <bgp_incl.h>


/* BGP advertise attribute is used for pack same attribute update into
   one packet.  To do that we maintain attribute hash in struct
   peer.  */
static struct bgp_advertise_attr *
baa_new ()
{
  return (struct bgp_advertise_attr *)
    XCALLOC (MTYPE_BGP_ADVERTISE_ATTR,
             sizeof (struct bgp_advertise_attr));
}

static void
baa_free (struct bgp_advertise_attr *baa)
{
  XFREE (MTYPE_BGP_ADVERTISE_ATTR, baa);
}

static void *
baa_hash_alloc (void *ref)
{
  struct bgp_advertise_attr *baa;

  baa = baa_new ();
  baa->attr = ((struct bgp_advertise_attr *) ref)->attr;
  return baa;
}

static u_int32_t
baa_hash_key (void *baa)
{
  return attrhash_key_make (((struct bgp_advertise_attr *) baa)->attr);
}

static bool_t
baa_hash_cmp (void *baa1, void *baa2)
{
  return attrhash_cmp (((struct bgp_advertise_attr *) baa1)->attr,
                       ((struct bgp_advertise_attr *) baa2)->attr);
}

/* BGP update and withdraw information is stored in BGP advertise
   structure.  This structure is referred from BGP adjacency
   information.  */
struct bgp_advertise *
bgp_advertise_new ()
{
  struct bgp_advertise *p;

  p = XCALLOC (MTYPE_BGP_ADVERTISE, sizeof (struct bgp_advertise));
  if (p)
    p->uid = BGP_ADV_UID_ADV;

  return p;
}

void
bgp_advertise_free (struct bgp_advertise *adv)
{
  XFREE (MTYPE_BGP_ADVERTISE, adv);
}

static struct bgp_adj_out *
bgp_adj_out_new (void)
{
    return (struct bgp_adj_out*)
      XCALLOC (MTYPE_BGP_ADJACENCY, sizeof (struct bgp_adj_out));
}

static struct adv_out *
bgp_adv_out_new (void)
{
    return (struct adv_out*)
      XCALLOC (MTYPE_BGP_ADJACENCY, sizeof (struct adv_out));
}

struct bgp_adv_attr_fifo *
bgp_adv_baa_fifo_new (void)
{
  struct bgp_adv_attr_fifo *p;

  p = XCALLOC (MTYPE_BGP_ADVERTISE, sizeof (struct bgp_adv_attr_fifo));
  if (p)
    p->uid = BGP_ADV_UID_ATTR;

  return p;
}

void
bgp_adv_baa_fifo_free (struct bgp_adv_attr_fifo *p)
{
  XFREE (MTYPE_BGP_ADVERTISE, p);
}

void
bgp_advertise_add (struct bgp_advertise_attr *baa,
                   struct bgp_advertise *adv)
{
  adv->next = baa->adv;
  if (baa->adv)
    baa->adv->prev = adv;
  baa->adv = adv;
}

void
bgp_advertise_delete (struct bgp_advertise_attr *baa,
                      struct bgp_advertise *adv)
{
  if (adv->next)
    adv->next->prev = adv->prev;
  if (adv->prev)
    adv->prev->next = adv->next;
  else
    baa->adv = adv->next;
}

struct bgp_advertise_attr *
bgp_advertise_intern (struct hash *hash, struct attr *attr)
{
  struct bgp_advertise_attr ref;
  struct bgp_advertise_attr *baa;

  pal_mem_set (&ref, 0, sizeof (struct bgp_advertise_attr));

  if (attr)
    ref.attr = bgp_attr_intern (attr);
  baa = (struct bgp_advertise_attr *) hash_get (hash, &ref, baa_hash_alloc);
  if (baa)
    baa->refcnt++;

  return baa;
}

void
bgp_advertise_unintern (struct hash *hash, struct bgp_advertise_attr *baa)
{
  pal_assert (baa->refcnt > 0);

  baa->refcnt--;

  if (! baa->refcnt)
    {
      if (baa->attr)
        {
          hash_release (hash, baa);
          bgp_attr_unintern (baa->attr);
        }
      baa_free (baa);
    }
  else if (baa->attr)
    bgp_attr_unintern (baa->attr);

  return;
}

/* BGP adjacency keeps minimal advertisement information.  */
void
bgp_adj_out_free (struct bgp_adj_out *adj)
{
  XFREE (MTYPE_BGP_ADJACENCY, adj);
}

static void
bgp_adv_out_free (struct adv_out * adv_out)
{
      XFREE (MTYPE_BGP_ADJACENCY, adv_out);
}

bool_t
bgp_adj_out_lookup (struct bgp_peer *peer,
                    struct bgp_node *rn)
{
  struct bgp_adj_out *adj;

  for (adj = rn->adj_out; adj; adj = adj->next)
    if (adj->peer == peer)
      break;

  if (! adj)
    return PAL_FALSE;

  return (adj->adv
          ? (adj->adv->baa ? PAL_TRUE : PAL_FALSE)
          : (adj->attr ? PAL_TRUE : PAL_FALSE));
}

bool_t
bgp_advertise_peer_id_isset (struct bgp_peer *peer, struct bgp_advertise *adv)
{
  if (!adv)
    {
      zlog_err (&BLG, "%s: NULL adv", __FUNCTION__);
      return PAL_FALSE;
    }
  pal_assert (peer->peer_id < BGP_MAX_PEERS_PER_GRP);

  return (adv->bitmap & (1 << peer->peer_id)) ? PAL_TRUE : PAL_FALSE;
}

void
bgp_advertise_peer_id_set (struct bgp_peer *peer, struct bgp_advertise *adv)
{
  if (!adv)
    {
      zlog_err (&BLG, "%s: NULL adv", __FUNCTION__);
      return;
    }
  pal_assert (peer->peer_id < BGP_MAX_PEERS_PER_GRP);
  adv->bitmap |= (1 << peer->peer_id);
}

void
bgp_advertise_peer_id_unset (struct bgp_peer *peer, struct bgp_advertise *adv)
{
  if (!adv)
    {
      zlog_err (&BLG, "%s: NULL adv", __FUNCTION__);
      return;
    }
  pal_assert (peer->peer_id < BGP_MAX_PEERS_PER_GRP);
  adv->bitmap &= (~(1 << peer->peer_id));
}

struct bgp_advertise *
bgp_advertise_clean (struct bgp_peer *peer, struct bgp_adj_out **ppadj,
                     afi_t afi, safi_t safi)

{
  struct bgp_advertise *adv;
  struct bgp_advertise_attr *baa;
  struct bgp_advertise *next;
  struct bgp_node *rn;
  struct bgp_adj_out *adj = NULL;

  if (ppadj == NULL)
    return NULL;

  adj = *ppadj;
  if (!adj)
    return NULL;

  adv = adj->adv;
  baa = adv->baa;
  rn = adv->rn;
  next = NULL;

  if (baa)
    {
      /* Unlink myself from advertise attribute FIFO.  */
      bgp_advertise_delete (baa, adv);

      /* Fetch next advertise candidate. */
      next = baa->adv;

      /* Unintern BGP advertise attribute.  */
      bgp_advertise_unintern (peer->baa_hash [BGP_AFI2BAAI (afi)]
                              [BGP_SAFI2BSAI (safi)],
                              baa);
    }

  /* Unlink myself from advertisement FIFO */
  FIFO_DEL (&adv->badv_fifo);
  if(! rn)
  *ppadj = NULL;
  
  /* Free memory.  */
  bgp_advertise_free (adv);

  /* rn == NULL ==> End-of-Rib Marker, 'adj' also needs to go */
  if (! rn)
    {
      bgp_adj_out_free (adj);
    }
  else
    adj->adv = NULL;

  return next;
}

#if 0
static char *
bgp_advertise_fifo_type_string (u_int16_t type)
{
  switch (type)
    {
    case BGP_ADV_FIFO_ADV_REACH:
      return "adv_list[][]->reach";
    case BGP_ADV_FIFO_ASORIG_REACH:
      return "asorig_adv_list[][]->reach";
    default:
      break;
    }
  return "invalid FIFO";
}

static void
bgp_rib_out_dump (struct bgp_peer *peer,
                  struct bgp_advertise *adv,
                  struct bgp_adv_attr_fifo *adv_attr)
{
  struct prefix rnp;
  char buf[256];
  int pos = 0;

  if ((!adv) || (!peer))
    return;

  if (peer->group)
      pos += snprintf (&buf[pos], sizeof(buf) - pos,
                       "peer group: %s, peer (0x%08x, id: %d, %s), "
                       "adv: 0x%08x, ", peer->group->name,
                       (int)peer, peer->peer_id, peer->host, (int)adv);
  else
    pos = snprintf (&buf[pos], sizeof(buf) - pos, "peer: (0x%08x, %s), "
                    "adv: 0x%08x", (int)peer, peer->host, (int)adv);

  if (adv->baa)
    pos += snprintf (&buf[pos], sizeof(buf) - pos,
                     "baa->refcnt: %d, ", adv->baa->refcnt);
      
  if (adv_attr)
    pos += snprintf (&buf[pos], sizeof(buf) - pos,
                     "FIFO: %s, baa->refcnt: %d, ",
                     bgp_advertise_fifo_type_string(adv_attr->type),
                     (adv->baa) ? adv->baa->refcnt : 0);

  if (adv->rn)
    {
      BGP_GET_PREFIX_FROM_NODE (adv->rn);
      zlog_info (&BLG, "%s, prefix: %O", buf, &rnp);
    }
  else
    zlog_info (&BLG, "%s", buf);
}
#endif

/****************************************************************************
 *  Function Name : bgp_rib_out_set                                         *
 *  Input                                                                   *
 *     rn : router node                                                     *
 *   peer : peering                                                         *
 *   afi  : adddress family                                                 *
 *  safi  : sub address family                                              *
 *  binfo : bgp info of selected (ri)                                       *
 *  Ouput                                                                   *
 *     None                                                                 *
 *  Description : This function does all the job for adj_out related        *
 *                data-structures and putting them in advertisement FIFO    *
 *                that is finally used during encoding of the advertisement *
 *                packet. This function is called by default by adj_out_set *
 ****************************************************************************/
static void
bgp_rib_out_set (struct bgp_node *rn, struct bgp_peer *peer,
                 struct attr *attr, afi_t afi, safi_t safi,
                 struct bgp_info *binfo)
{
  struct bgp_advertise *adv;
  struct bgp_adj_out *adj;
  u_int32_t baai;
  u_int32_t bsai;

#ifdef DISABLE_BGP_ANNOUNCE
  return;
#endif /* DISABLE_BGP_ANNOUNCE */

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);
  adj = NULL;

  /* Look for adjacency information. */
  if (rn)
    {
      for (adj = rn->adj_out; adj; adj = adj->next)
        if (adj->peer == peer)
          break;
    }

  if (! adj)
    {
      adj = bgp_adj_out_new ();

      if (rn)
        {
          /* Add Advertisement to Adjacency */
          BGP_ADJ_OUT_ADD (rn, adj);

          /* Lock Route-Node */
          bgp_lock_node (rn);
        }
    }

  if (adj->adv)
    bgp_advertise_clean (peer, &adj, afi, safi);
 
  if (adj == NULL)
    return;

  if (binfo)
    adj->from_peer = binfo->peer;
  adj->peer = peer;
  adj->adv = bgp_advertise_new ();

  adv = adj->adv;
  adv->adj = adj;
  adv->rn = rn;
  adv->binfo = binfo;
  if (attr)
    {
      if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_REFLECTOR_CLIENT)
        || CHECK_FLAG (binfo->peer->af_flags[baai][bsai], PEER_FLAG_REFLECTOR_CLIENT))
         pal_mem_cpy(&attr->originator_id, &binfo->peer->remote_id, 
                sizeof(struct pal_in4_addr));
      adv->baa = bgp_advertise_intern (peer->baa_hash [baai][bsai], attr);

      /* Add new advertisement to BAA list */
      bgp_advertise_add (adv->baa, adv);
    }

  /* Reachability advertisement */
  if (binfo)
    {
      if (binfo->peer == peer->bgp->peer_self)
        FIFO_ADD (&peer->asorig_adv_list [baai][bsai]->reach,
            &adv->badv_fifo);
      else
        FIFO_ADD (&peer->adv_list [baai][bsai]->reach,
            &adv->badv_fifo);
    }
  /* End-of-RIB Marker advertisement */
  else if (! rn)
    {
      /* Add EoR Marker to AS-Orig List if its non-empty */
      if (FIFO_HEAD (&peer->asorig_adv_list [baai][bsai]->reach))
        FIFO_ADD (&peer->asorig_adv_list [baai][bsai]->reach,
            &adv->badv_fifo);
      else
        FIFO_ADD (&peer->adv_list [baai][bsai]->reach,
            &adv->badv_fifo);
    }
  /* Error condition */
  else
    zlog_err (&BLG, "[RIB] Adv-Out Set: Invalid rn!");

  /* If the advertisement-interval has been set to 0 and
   * the route is a learned route from other BGP speaker.
   * As routes originated from this BGP speaker will be
   * handled by AS origin timer
   */
  if (CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE)
      && binfo && (binfo->peer != peer->bgp->peer_self))
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_ROUTEADV_EXP);

  return;
}

/****************************************************************************
 *  Function Name : bgp_adv_out_set                                         *
 *  Input                                                                   *
 *     rn : router node                                                     *
 *   peer : peering                                                         *
 *   afi  : adddress family                                                 *
 *  safi  : sub address family                                              *
 *  binfo  : route information                                              *
 *  reach  : boolean to indicate where place the rn.                        *
 *           TRUE - reach FIFO announce                                     *
 *           FALSE - unreach FIFO withdraw                                  *
 *  Ouput                                                                   *
 *     None                                                                 *
 *  Description : This function will create  adv_out (contains only rn)     *
 *                and updates the new fifo list. This function is called    *
 *                from bgp_adj_out_set() only when option                   *
 *                BGP_OPT_DISABLE_ADJ_OUT is set.                           *
 ****************************************************************************/
void
bgp_adv_out_set (struct bgp_node *rn, struct bgp_peer *peer,
                 afi_t afi, safi_t safi,
                 struct bgp_info *binfo, bool_t reach)
{
  struct adv_out *adv_out;
  bool_t is_adv_out_used = PAL_FALSE;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  /* Intialization */
  adv_out = NULL;

  adv_out = bgp_adv_out_new ();

  if (NULL == adv_out)
    {
      zlog_err (&BLG, "[RIB] Adj-Out Set: out of memory couldn't!"
                " allocate memory for adv_out \n");
      return;
    }
  adv_out->rn = rn;

  /* lock the node corresponding unlock
   * will be done in bgp_rib_out_free, after
   * successfully upadating.
   */
  if (rn)
    bgp_lock_node (rn);

  if (reach == PAL_TRUE)
    {
      /* Reachability advertisement */
      if (binfo)
        {
          if (binfo->peer == peer->bgp->peer_self)
            FIFO_ADD (&peer->asorig_adv_list_new [baai][bsai]->reach,
                &adv_out->adv_out_fifo);
          else
            FIFO_ADD (&peer->adv_list_new [baai][bsai]->reach,
                &adv_out->adv_out_fifo);

          is_adv_out_used = PAL_TRUE;
        }
      /* End-of-RIB Marker advertisement */
      else if (! rn)
        {
          /* Add EoR Marker to AS-Orig List if its non-empty */
          if (FIFO_HEAD (&peer->asorig_adv_list_new [baai][bsai]->reach))
            FIFO_ADD (&peer->asorig_adv_list [baai][bsai]->reach,
                &adv_out->adv_out_fifo);
          else
            FIFO_ADD (&peer->adv_list_new [baai][bsai]->reach,
                &adv_out->adv_out_fifo);

          is_adv_out_used = PAL_TRUE;
        }
    }
  /* update the unreach fifo */
  if (reach == PAL_FALSE)
    {
      if (binfo)
        {
          if (binfo->peer == peer->bgp->peer_self)
            FIFO_ADD (&peer->asorig_adv_list_new [baai][bsai]->unreach,
                &adv_out->adv_out_fifo);
          else
            FIFO_ADD (&peer->adv_list_new [baai][bsai]->unreach,
                &adv_out->adv_out_fifo);

          is_adv_out_used = PAL_TRUE;
        }
      /* End-of-RIB Marker advertisement */
      else if (! rn)
        {
          /* Add EoR Marker to AS-Orig List if its non-empty */
          if (FIFO_HEAD (&peer->asorig_adv_list_new [baai][bsai]->unreach))
            FIFO_ADD (&peer->asorig_adv_list [baai][bsai]->unreach,
                &adv_out->adv_out_fifo);
          else
            FIFO_ADD (&peer->adv_list_new [baai][bsai]->unreach,
                &adv_out->adv_out_fifo);

          is_adv_out_used = PAL_TRUE;
        }
    }

  /* If adv_out is not added into any of the FIFOs then free the adv_out */
  if (is_adv_out_used == PAL_FALSE)
    {
      if (rn)
        bgp_unlock_node (rn);
       
       bgp_adv_out_free (adv_out); 
    }

  return;
}

/****************************************************************************
 *  Function Name : bgp_update_adj_out                                      *
 *  Input                                                                   *
 *   fifo : reach fifo                                                      *
 *   peer : peering                                                         *
 *   afi  : adddress family                                                 *
 *  safi  : sub address family                                              *
 *  Ouput                                                                   *
 *     None                                                                 *
 * Description : This function will create adj_out and adv out of adv_out   *
 *               (contains only rn). and updates the appropriate fifo.      *
 *               It is called from bgp_populate_adj_out() during            *
 *               advertisement announcement when BGP_OPT_DISBALE_ADJ_OUT    *
 *               option is set.                                             *
 ****************************************************************************/
void
bgp_update_adj_out (struct fifo *fifo, struct bgp_peer *peer,
                    afi_t afi, safi_t safi)
{
  struct adv_out *adv_out;
  struct bgp_info *binfo;
  struct bgp_info *next;
  struct attr attr;
  struct bgp_node *rn;
  struct prefix rnp;

  /*initialize */
  adv_out = NULL;
  binfo = NULL;
  rn = NULL;
  next = NULL;

  pal_mem_set (&attr, 0x0, sizeof (struct attr));
  adv_out = (struct adv_out *)FIFO_HEAD (fifo);

  while (adv_out)
    {
      rn = adv_out->rn;
      for (binfo = rn->info; binfo; binfo = next)
        {
          next = binfo->next;
          /* get the selected route */
          if (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
            {
              if (binfo->peer != peer)
                {
                  BGP_GET_PREFIX_FROM_NODE (rn);
                  /* update the attribute, with nexthop and route-map out
                   * policy
                   */
                  if (bgp_announce_check (binfo, peer, &rnp, &attr, afi, safi))
                    bgp_rib_out_set (rn, peer, &attr, afi, safi, binfo);
                }
            }/* else ignore */
        }

      /* delete the current adv and update the head of the list */
      FIFO_DEL(&adv_out->adv_out_fifo);
      /* free the current adv out */
      bgp_adv_out_free (adv_out);
      /* get the next adv */
      adv_out = (struct adv_out *)FIFO_HEAD (fifo);
    }

}

/****************************************************************************
 *  Function Name : bgp_adv_out_unset                                       *
 *  Input                                                                   *
 *   fifo : reach fifo                                                      *
 *   peer : peering                                                         *
 *   afi  : adddress family                                                 *
 *  safi  : sub address family                                              *
 *  Ouput                                                                   *
 *     None                                                                 *
 *  Description :  This function will create adj_out and adv out of         *
 *                 adv_out (contains only rn).                              *
 *                 and updates the appropriate fifo. To handle withdraw,    *
 *                 by placing bgp_advertise and related data structures in  *
 *                 unreach FIFO.                                            *
 ***************************************************************************/
void
bgp_adv_out_unset (struct fifo *fifo, struct bgp_peer *peer,
                   afi_t afi, safi_t safi)
{
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;
  struct adv_out *adv_out;
  struct bgp_node *rn;


  /*initialize */
  adv = NULL;
  adv_out = NULL;
  rn = NULL;

  adv_out = (struct adv_out *)FIFO_HEAD (fifo);

  while (adv_out)
    {
      rn = adv_out->rn;
      adj = bgp_adj_out_new ();
      adj->adv = bgp_advertise_new ();
      adv = adj->adv;
      adv->rn = rn;
      adv->adj = adj;

      /* add the adj to run temporarly. same
       * is will removed and free in rib_out_free
       */
      if (rn)
        {
          /* Add Advertisement to Adjacency */
          BGP_ADJ_OUT_ADD (rn, adj);

          /* Lock Route-Node */
          bgp_lock_node (rn);
        }

      /* Add the unreachability entry for withdrawal */
      if (peer == peer->bgp->peer_self)
        FIFO_ADD (&peer->asorig_adv_list [BGP_AFI2BAAI (afi)]
            [BGP_SAFI2BSAI (safi)]->unreach, &adv->badv_fifo);
      else
        FIFO_ADD (&peer->adv_list [BGP_AFI2BAAI (afi)]
            [BGP_SAFI2BSAI (safi)]->unreach, &adv->badv_fifo);

      FIFO_DEL(&adv_out->adv_out_fifo);
      bgp_adv_out_free (adv_out);
      adv_out = (struct adv_out *)FIFO_HEAD (fifo);
    }

  return ;
}

/****************************************************************************
 *  Function Name : bgp_populate_adj_out                                    *
 *  Input                                                                   *
 *   peer  : peering                                                        *
 *   baai  : adddress family                                                *
 *   bsai  : sub address family                                             *
 *  Ouput                                                                   *
 *     None                                                                 *
 * Description : This function updates adv_list, asorg_adv_list FIFO-lists  *
 *               with bgp_advertise and related data structures just before *
 *               sending the advertisement from bgp_encode.c. This function *
 *               is only called when BGP_OPT_DISABLE_ADJ_OUT option is set. *
 *               This function in turn calls bgp_update_adj_out() to        *
 *               create/set adj_out, bgp_advertise, bgp_advertise_adv       *
 *               data structures.                                           *
 ****************************************************************************/
void
bgp_populate_adj_out (struct bgp_peer *peer, u_int32_t baai, u_int32_t bsai)
{
  afi_t afi;
  safi_t safi;

  afi = BGP_BAAI2AFI (baai);
  safi = BGP_BSAI2SAFI (bsai);

  if (FIFO_HEAD (&peer->adv_list_new [baai][bsai]->reach))
    bgp_update_adj_out (&peer->adv_list_new [baai][bsai]->reach, peer,
                        afi, safi);

  if (FIFO_HEAD (&peer->asorig_adv_list_new [baai][bsai]->reach))
    bgp_update_adj_out (&peer->asorig_adv_list_new [baai][bsai]->reach, peer,
        afi, safi);

  if (FIFO_HEAD (&peer->adv_list_new [baai][bsai]->unreach))
    bgp_adv_out_unset (&peer->adv_list_new [baai][bsai]->unreach, peer,
                       afi,safi);
  if (FIFO_HEAD (&peer->asorig_adv_list_new [baai][bsai]->unreach))
    bgp_adv_out_unset (&peer->asorig_adv_list_new [baai][bsai]->unreach, peer,
        afi, safi);

}
	  
void
bgp_adj_out_set (struct bgp_node *rn, struct bgp_peer *peer,
                 struct attr *attr, afi_t afi, safi_t safi,
                 struct bgp_info *binfo)
{
  if (!bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
    bgp_rib_out_set (rn, peer, attr, afi, safi, binfo);
  else
    {
      if (peer != binfo->peer)
        bgp_adv_out_set (rn, peer, afi, safi, binfo, PAL_TRUE);
    }
  return;
}

void
bgp_rib_out_unset (struct bgp_node *rn,
                   struct bgp_peer *peer,
                   afi_t afi, safi_t safi)
{
  
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;

#ifdef DISABLE_BGP_ANNOUNCE
  return;
#endif /* DISABLE_BGP_ANNOUNCE */

  /* Lookup existing adjacency, if it is not there return immediately.  */
  for (adj = rn->adj_out; adj; adj = adj->next)
    if (adj->peer == peer)
      break;

  if (! adj)
    return;

  /* Clean up previous advertisement */
  if (adj->adv)
    bgp_advertise_clean (peer, &adj, afi, safi);

  if (adj == NULL)
    return;

  if (adj->attr)
    {
      /* We need advertisement structure.  */
      adj->adv = bgp_advertise_new ();
      adv = adj->adv;
      adv->rn = rn;
      adv->adj = adj;

      /* Add the unreachability entry for withdrawal */
      if (adj->from_peer == peer->bgp->peer_self)
        FIFO_ADD (&peer->asorig_adv_list [BGP_AFI2BAAI (afi)]
                                         [BGP_SAFI2BSAI (safi)]->unreach,
                  &adv->badv_fifo);
      else
        FIFO_ADD (&peer->adv_list [BGP_AFI2BAAI (afi)]
                                  [BGP_SAFI2BSAI (safi)]->unreach,
                  &adv->badv_fifo);
    }
  else /* Withdrawing the Advertisement before advertising */
    {
      /* Remove Advertisement from Adjacency */
      BGP_ADJ_OUT_DEL (rn, adj);
      /* Free Adjacency-Advertisement information */
      bgp_adj_out_free (adj);


      /* Unlock Route-Node */
      bgp_unlock_node (rn);
      
      return;
    }

  /* If the advertisement-interval has been set to 0 and
   * the route is a learned route from other BGP speaker.
   * As routes originated from this BGP speaker will be
   * handled by AS origin timer
   */
  if (CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV_IMMEDIATE)
      && (adj->from_peer != peer->bgp->peer_self))
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_ROUTEADV_EXP);

  return;
}

void
bgp_adj_out_unset (struct bgp_node *rn,
                   struct bgp_peer *peer,
                   struct bgp_info *ri,
                   afi_t afi, safi_t safi)
{
    if (!bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
      bgp_rib_out_unset (rn, peer, afi, safi);
    else
      {
        /* pass the ri to to adv_out_set so that
         * the route is updated in appropriate fifo.
         */
        if (ri && (ri->peer != peer))
          bgp_adv_out_set (rn, peer, afi, safi, ri, PAL_FALSE);
      }
}

struct bgp_advertise *
bgp_adj_out_remove (struct bgp_node *rn,
                    struct bgp_adj_out *adj,
                    struct bgp_peer *peer,
                    afi_t afi, safi_t safi,
                    bool_t auto_summary_update)
{
    struct bgp_advertise *next = NULL;

    if (adj->attr)
      bgp_attr_unintern (adj->attr);

    if (adj->adv)
      next = bgp_advertise_clean (peer, &adj, afi, safi);
 
    if (adj == NULL)
      return next;

    if (!auto_summary_update
        || bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
      {
        /* Remove Advertisement from Adjacency */
        BGP_ADJ_OUT_DEL (rn, adj);
        /* Free Adjacency-Advertisement information */
        bgp_adj_out_free (adj);
      }

    /* Unlock Route-Node */
    bgp_unlock_node (rn);

    return next;

}

struct bgp_advertise *
bgp_rib_out_free (struct bgp_node *rn,
                  struct bgp_adj_out *adj,
                  struct bgp_peer *peer,
                  afi_t afi, safi_t safi,
                  bool_t auto_summary_update)
{
    struct bgp_advertise * adv;
    struct prefix rnp;

    /* Initialization  */
    adv = NULL;

    if (BGP_DEBUG (update, UPDATE_OUT))
      {
        BGP_GET_PREFIX_FROM_NODE (rn);
        zlog_info (&BLG, "bgp_rib_out_free :adj out is freed for the route :%O "
            "afi : %d safi : %d peer : %s", &rnp,
            afi, safi, peer->host);
      }
    /* get the next advertisment */
    adv = bgp_adj_out_remove (rn, adj, peer, afi, safi, auto_summary_update);

    /* unlokc the node */
    bgp_unlock_node (rn);

    return adv;
}


void
bgp_adj_in_set (struct bgp_node *rn, struct bgp_peer *peer, struct attr *attr)
{
  struct bgp_adj_in *adj;

  for (adj = rn->adj_in; adj; adj = adj->next)
    {
      if (adj->peer == peer)
        {
          if (PAL_FALSE == attrhash_cmp (adj->attr, attr))
            {
              bgp_attr_unintern (adj->attr);
              adj->attr = bgp_attr_intern (attr);
            }
          return;
        }
    }
  adj = XCALLOC (MTYPE_BGP_ADJ_IN, sizeof (struct bgp_adj_in));
  adj->peer = peer;
  adj->attr = bgp_attr_intern (attr);
  BGP_ADJ_IN_ADD (rn, adj);
  bgp_lock_node (rn);
}

void
bgp_adj_in_remove (struct bgp_node *rn, struct bgp_adj_in *bai)
{
  bgp_attr_unintern (bai->attr);

  BGP_ADJ_IN_DEL (rn, bai);

  XFREE (MTYPE_BGP_ADJ_IN, bai);

  bgp_unlock_node (rn);

  return;
}

void
bgp_adj_in_unset (struct bgp_node *rn, struct bgp_peer *peer)
{
  struct bgp_adj_in *adj;

  for (adj = rn->adj_in; adj; adj = adj->next)
    if (adj->peer == peer)
      break;

  if (! adj)
    return;

  bgp_adj_in_remove (rn, adj);

  return;
}


void
bgp_peer_adv_list_init (struct bgp_peer *peer)
{
  u_int32_t baai;
  u_int32_t bsai;

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        peer->adv_list [baai][bsai] =
            XCALLOC (MTYPE_TMP, sizeof (struct bgp_peer_adv_list));
        FIFO_INIT (&peer->adv_list [baai][bsai]->reach);
        FIFO_INIT (&peer->adv_list [baai][bsai]->unreach);

        peer->asorig_adv_list [baai][bsai] =
            XCALLOC (MTYPE_TMP, sizeof (struct bgp_peer_adv_list));
        FIFO_INIT (&peer->asorig_adv_list [baai][bsai]->reach);
        FIFO_INIT (&peer->asorig_adv_list [baai][bsai]->unreach);

        peer->baa_hash [baai][bsai] =
          hash_create (baa_hash_key, baa_hash_cmp);

        /* do not allocated the memory for the new fifo list
         * if the disable adj out feature is not enabled.
         * FIXME: Please remove this check when disable adj
         * out feature has to be supported on the fly.
         */
        if (!bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
            continue;

        /* new type  of fifo */
        peer->adv_list_new [baai][bsai] =
              XCALLOC (MTYPE_TMP, sizeof (struct bgp_peer_adv_list));
        FIFO_INIT (&peer->adv_list_new [baai][bsai]->reach);
        FIFO_INIT (&peer->adv_list_new [baai][bsai]->unreach);

        peer->asorig_adv_list_new [baai][bsai] =
              XCALLOC (MTYPE_TMP, sizeof (struct bgp_peer_adv_list));
        FIFO_INIT (&peer->asorig_adv_list_new [baai][bsai]->reach);
        FIFO_INIT (&peer->asorig_adv_list_new [baai][bsai]->unreach);

      }

  return;
}

void
bgp_peer_adv_list_delete (struct bgp_peer *peer)
{
  u_int32_t baai;
  u_int32_t bsai;

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
      {
        if (peer->adv_list [baai][bsai])
          XFREE (MTYPE_TMP, peer->adv_list [baai][bsai]);
        peer->adv_list [baai][bsai] = NULL;

        if (peer->asorig_adv_list [baai][bsai])
          XFREE (MTYPE_TMP, peer->asorig_adv_list [baai][bsai]);
        peer->asorig_adv_list [baai][bsai] = NULL;

        if (peer->baa_hash [baai][bsai])
          hash_free (peer->baa_hash [baai][bsai]);
        peer->baa_hash [baai][bsai] = NULL;
      }

  return;
}

