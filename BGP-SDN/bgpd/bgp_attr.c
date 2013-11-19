/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/* Attribute strings for logging. */
struct message attr_str [] =
{
  { BGP_ATTR_ORIGIN,           "ORIGIN" },
  { BGP_ATTR_AS_PATH,          "AS_PATH" },
  { BGP_ATTR_NEXT_HOP,         "NEXT_HOP" },
  { BGP_ATTR_MULTI_EXIT_DISC,  "MULTI_EXIT_DISC" },
  { BGP_ATTR_LOCAL_PREF,       "LOCAL_PREF" },
  { BGP_ATTR_ATOMIC_AGGREGATE, "ATOMIC_AGGREGATE" },
  { BGP_ATTR_AGGREGATOR,       "AGGREGATOR" },
  { BGP_ATTR_COMMUNITIES,      "COMMUNITY" },
  { BGP_ATTR_ORIGINATOR_ID,    "ORIGINATOR_ID" },
  { BGP_ATTR_CLUSTER_LIST,     "CLUSTERLIST" },
  { BGP_ATTR_DPA,              "DPA" },
  { BGP_ATTR_ADVERTISER,       "ADVERTISER"} ,
  { BGP_ATTR_RCID_PATH,        "RCID_PATH" },
  { BGP_ATTR_MP_REACH_NLRI,    "MP_REACH_NLRI" },
  { BGP_ATTR_MP_UNREACH_NLRI,  "MP_UNREACH_NLRI" },
  { BGP_ATTR_AS4_PATH,         "AS4_PATH" },
  { BGP_ATTR_AS4_AGGREGATOR,   "AS4_AGGREGATOR" },
  { 0, NULL }
};


void *
cluster_hash_alloc (void *val)
{
  struct cluster_list *cluster_in;
  struct cluster_list *cluster;

  cluster_in = (struct cluster_list *) val;

  cluster = XMALLOC (MTYPE_CLUSTER, sizeof (struct cluster_list));
  cluster->length = cluster_in->length;

  if (cluster->length)
    {
      cluster->list = XMALLOC (MTYPE_CLUSTER_VAL, cluster_in->length);
      pal_mem_cpy (cluster->list, cluster_in->list, cluster_in->length);
    }
  else
    cluster->list = NULL;

  cluster->refcnt = 0;

  return cluster;
}

/* Cluster list related functions. */
struct cluster_list *
cluster_parse (u_int8_t *pnt, int length)
{
  struct cluster_list tmp;
  struct cluster_list *cluster;

  tmp.length = length;
  tmp.list = (struct pal_in4_addr *) pnt;

  cluster = hash_get (bgp_clusterhash_tab, &tmp, cluster_hash_alloc);
  if (cluster)
    cluster->refcnt++;
  return cluster;
}

int
cluster_loop_check (struct cluster_list *cluster, struct pal_in4_addr originator)
{
  int i;

  for (i = 0; i < cluster->length / 4; i++)
    if (cluster->list[i].s_addr == originator.s_addr)
      return 1;
  return 0;
}

u_int32_t
cluster_hash_key_make (void *arg)
{
  struct cluster_list *cluster;
  u_int32_t length;
  u_int32_t key;
  u_int8_t *pnt;

  cluster = (struct cluster_list *) arg;
  key = 0;

  length = cluster->length;
  pnt = (u_int8_t *) cluster->list;

  while (length)
    key += pnt[--length];

  return key;
}

bool_t
cluster_hash_cmp (void *arg1, void *arg2)
{
  struct cluster_list *cluster1;
  struct cluster_list *cluster2;

  cluster1 = (struct cluster_list *) arg1;
  cluster2 = (struct cluster_list *) arg2;

  if (cluster1->length == cluster2->length
      && ! pal_mem_cmp (cluster1->list, cluster2->list, cluster1->length))
    return PAL_TRUE;

  return PAL_FALSE;
}

void
cluster_free (struct cluster_list *cluster)
{
  if (cluster->list)
    XFREE (MTYPE_CLUSTER_VAL, cluster->list);
  XFREE (MTYPE_CLUSTER, cluster);
}

struct cluster_list *
cluster_dup (struct cluster_list *cluster)
{
  struct cluster_list *new;

  new = XMALLOC (MTYPE_CLUSTER, sizeof (struct cluster_list));
  pal_mem_set (new, 0, sizeof (struct cluster_list));
  new->length = cluster->length;

  if (cluster->length)
    {
      new->list = XMALLOC (MTYPE_CLUSTER_VAL, cluster->length);
      pal_mem_cpy (new->list, cluster->list, cluster->length);
    }
  else
    new->list = NULL;

  return new;
}

struct cluster_list *
cluster_intern (struct cluster_list *cluster)
{
  struct cluster_list *find;

  find = hash_get (bgp_clusterhash_tab, cluster, cluster_hash_alloc);
  if (find)
    find->refcnt++;

  return find;
}

void
cluster_unintern (struct cluster_list *cluster)
{
  struct cluster_list *ret;

  if (cluster->refcnt)
    cluster->refcnt--;

  if (cluster->refcnt == 0)
    {
      ret = hash_release (bgp_clusterhash_tab, cluster);
      pal_assert (ret != NULL);
      cluster_free (cluster);
    }
}

void
bgp_cluster_init ()
{
  bgp_clusterhash_tab = hash_create (cluster_hash_key_make, cluster_hash_cmp);
}


void
transit_free (struct transit *transit)
{
  if (transit->val)
    XFREE (MTYPE_TRANSIT_VAL, transit->val);
  XFREE (MTYPE_TRANSIT, transit);
}

void *
transit_hash_alloc (void *transit)
{
  /* Transit structure is already allocated.  */
  return transit;
}

struct transit *
transit_intern (struct transit *transit)
{
  struct transit *find;

  find = hash_get (bgp_transithash_tab, transit, transit_hash_alloc);
  if (find)
   {
     if (find != transit)
       transit_free (transit);
     find->refcnt++;
   }
  return find;
}

void
transit_unintern (struct transit *transit)
{
  struct transit *ret;

  if (transit->refcnt)
    transit->refcnt--;

  if (transit->refcnt == 0)
    {
      ret = hash_release (bgp_transithash_tab, transit);
      pal_assert (ret != NULL);      
      transit_free (transit);
    }
}

u_int32_t
transit_hash_key_make (void *arg)
{
  struct transit *transit;
  u_int32_t length;
  u_int32_t key;
  u_int8_t *pnt;

  transit = (struct transit *) arg;
  key = 0;

  length = transit->length;
  pnt = (u_int8_t *) transit->val;

  while (length)
    key += pnt[--length];

  return key;
}

bool_t
transit_hash_cmp (void *arg1, void *arg2)
{
  struct transit *transit1;
  struct transit *transit2;

  transit1 = (struct transit *) arg1;
  transit2 = (struct transit *) arg2;

  if (transit1->length == transit2->length
      && ! pal_mem_cmp (transit1->val, transit2->val, transit1->length))
    return PAL_TRUE;

  return PAL_FALSE;
}

void
transit_init ()
{
  bgp_transithash_tab = hash_create (transit_hash_key_make,
                                     transit_hash_cmp);
}


/* Attribute hash routines. */
struct hash *
bgp_attr_hash ()
{
  return bgp_attrhash_tab;
}

u_int32_t
attrhash_key_make (void *arg)
{
  struct attr *attr;
  u_int32_t key;

  attr = (struct attr *) arg;
  key = 0;

  key += attr->origin;
  key += attr->nexthop.s_addr;
  key += attr->med;
  key += attr->local_pref;
  key += attr->aggregator_as;
#ifdef HAVE_EXT_CAP_ASN
  key += attr->aggregator_as4;
#endif /* HAVE_EXT_CAP_ASN */
  key += attr->aggregator_addr.s_addr;
  key += attr->weight;

  key += attr->mp_nexthop_global_in.s_addr;
  if (attr->aspath)
    key += aspath_key_make (attr->aspath);
#ifdef HAVE_EXT_CAP_ASN
  if (attr->as4path)
    key += as4path_key_make (attr->as4path);
  if (attr->aspath4B)
    key += as4path_key_make (attr->aspath4B);
#endif /* HAVE_EXT_CAP_ASN */
  if (attr->community)
    key += community_hash_make (attr->community);
  if (attr->ecommunity)
    key += ecommunity_hash_make (attr->ecommunity);
  if (attr->cluster)
    key += cluster_hash_key_make (attr->cluster);
  if (attr->transit)
    key += transit_hash_key_make (attr->transit);

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      int i;

      key += attr->mp_nexthop_len;
      for (i = 0; i < 16; i++)
        key += attr->mp_nexthop_global.s6_addr[i];
      for (i = 0; i < 16; i++)
        key += attr->mp_nexthop_local.s6_addr[i];
    }
#endif /* HAVE_IPV6 */

  return key;
}

bool_t
attrhash_cmp_ipv4 (struct attr *attr1, struct attr *attr2)
{
  if (attr1->flag == attr2->flag
      && attr1->origin == attr2->origin
      && attr1->nexthop.s_addr == attr2->nexthop.s_addr
      && attr1->med == attr2->med
      && attr1->local_pref == attr2->local_pref
      && attr1->distance == attr2->distance
      && attr1->aggregator_as == attr2->aggregator_as
#ifdef HAVE_EXT_CAP_ASN
      && attr1->aggregator_as4 == attr2->aggregator_as4
#endif /* HAVE_EXT_CAP_ASN */
      && attr1->aggregator_addr.s_addr == attr2->aggregator_addr.s_addr
      && attr1->weight == attr2->weight
      && attr1->originator_id.s_addr == attr2->originator_id.s_addr
      && IPV4_ADDR_SAME (&attr1->mp_nexthop_global_in, &attr2->mp_nexthop_global_in)
      && attr1->aspath == attr2->aspath
#ifdef HAVE_EXT_CAP_ASN
      && attr1->aspath4B == attr2->aspath4B
      && attr1->as4path == attr2->as4path 
#endif /* HAVE_EXT_CAP_ASN */ 
      && attr1->community == attr2->community
      && attr1->ecommunity == attr2->ecommunity
      && attr1->cluster == attr2->cluster
      && attr1->transit == attr2->transit)
    return PAL_TRUE;

  return PAL_FALSE;
}

#ifdef HAVE_IPV6
bool_t
attrhash_cmp_ipv6 (struct attr *attr1, struct attr *attr2)
{
  if (attr1->mp_nexthop_len == attr2->mp_nexthop_len
      && IPV6_ADDR_SAME (&attr1->mp_nexthop_global, &attr2->mp_nexthop_global)
      && IPV6_ADDR_SAME (&attr1->mp_nexthop_local, &attr2->mp_nexthop_local))
    return PAL_TRUE;

  return PAL_FALSE;
}
#endif /* HAVE_IPV6 */

bool_t
attrhash_cmp (void *arg1, void *arg2)
{
  struct attr *attr1;
  struct attr *attr2;

  attr1 = (struct attr *) arg1;
  attr2 = (struct attr *) arg2;

  if (attrhash_cmp_ipv4 (attr1, attr2) == PAL_FALSE)
    return PAL_FALSE;

#ifdef HAVE_IPV6
  if (BGP_CAP_HAVE_IPV6
      && attrhash_cmp_ipv6 (attr1, attr2) == PAL_FALSE)
    return PAL_FALSE;
#endif /* HAVE_IPV6 */

  return PAL_TRUE;
}

void
attrhash_init ()
{
  bgp_attrhash_tab = hash_create (attrhash_key_make, attrhash_cmp);
}

void *
bgp_attr_hash_alloc (void *val)
{
  struct attr *attr;

  attr = XCALLOC (MTYPE_ATTR, sizeof (struct attr));
  *attr = *((struct attr *) val);
  attr->refcnt = 0;
  return attr;
}

/* Internet argument attribute. */
/* aspath is for 2 byte as numbers and aspath4B is for 4 byte as numbers as4path is
   for storing Non mappable ASs when there is a communication between NBGP and OBGP.
   The two new attributes, aspath4B and as4path are stored in a separate hash table
   for increasing the efficiency specially in scenarios like many peers with NBGP,
   OBGP connection */ 
 
struct attr *
bgp_attr_intern (struct attr *attr)
{
  struct attr *find;

  /* Intern referenced strucutre. */
  if (attr->aspath)
    {
      if (! attr->aspath->refcnt)
        attr->aspath = aspath_intern (attr->aspath);
      else
        attr->aspath->refcnt++;
    }
#ifdef HAVE_EXT_CAP_ASN
  if (attr->aspath4B)
    {
      if (! attr->aspath4B->refcnt)
        attr->aspath4B = aspath4B_intern (attr->aspath4B);
      else
        attr->aspath4B->refcnt++;
    }
  if (attr->as4path)
    {
      if (! attr->as4path->refcnt)
        attr->as4path = as4path_intern (attr->as4path);
      else
        attr->as4path->refcnt++;
    }
#endif /* HAVE_EXT_CAP_ASN */

  if (attr->community)
    {
      if (! attr->community->refcnt)
        attr->community = community_intern (attr->community);
      else
        attr->community->refcnt++;
    }
  if (attr->ecommunity)
    {
      if (! attr->ecommunity->refcnt)
        attr->ecommunity = ecommunity_intern (attr->ecommunity);
      else
        attr->ecommunity->refcnt++;
    }
  if (attr->cluster)
    {
      if (! attr->cluster->refcnt)
        attr->cluster = cluster_intern (attr->cluster);
      else
        attr->cluster->refcnt++;
    }
  if (attr->transit)
    {
      if (! attr->transit->refcnt)
        attr->transit = transit_intern (attr->transit);
      else
        attr->transit->refcnt++;
    }

  find = (struct attr *) hash_get (bgp_attrhash_tab, attr,
                                   bgp_attr_hash_alloc);
  if (find)
    find->refcnt++;

  return find;
}

/* Make network statement's attribute. */
struct attr *
bgp_attr_default_set (struct attr *attr, u_int8_t origin)
{
  pal_mem_set (attr, 0, sizeof (struct attr));

  attr->origin = origin;
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGIN);
  attr->aspath = aspath_empty ();
#ifdef HAVE_EXT_CAP_ASN
  attr->aspath4B = aspath4B_empty ();
  attr->as4path = as4path_empty ();
#endif /* HAVE_EXT_CAP_ASN */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS_PATH);
  attr->weight = BGP_ATTR_WEIGHT_DEF;
  attr->distance = IPI_DISTANCE_EBGP;

  return attr;
}

struct attr *
bgp_attr_aggregate_intern (struct bgp *bgp,
                           u_int8_t origin,
                           struct aspath *aspath,
                           struct community *community,
                           u_int32_t as_set,
                           u_int32_t local_distance,
                           bool_t atomic_set)
{
  struct attr attr;
  struct attr *new;

  bgp_attr_default_set (&attr, origin);

  attr.distance = local_distance;
  if (aspath)
    {
      if (attr.aspath)
        aspath_unintern (attr.aspath);

      attr.aspath = aspath_intern (aspath);

      if (atomic_set)
        attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);
    }
  else
    attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);

  if (community)
    {
      attr.community = community;
      attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);
    }

  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR);
  if (bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION))
    attr.aggregator_as = bgp->confed_id;
  else
    attr.aggregator_as = bgp->as;
  attr.aggregator_addr = bgp->router_id;

  new = bgp_attr_intern (&attr);
  aspath_unintern (new->aspath);
  
  return new;
}

#ifdef HAVE_EXT_CAP_ASN
struct attr *
bgp_attr_aggregate_4b_intern (struct bgp *bgp,
                           u_int8_t origin,
                           struct aspath *aspath,
                           struct as4path *aspath4B, 
                           struct as4path *as4path,
                           struct community *community,
                           u_int32_t as_set, 
                           u_int32_t local_distance,
                           bool_t atomic_set)
{
  struct attr attr;
  struct attr *new;

  bgp_attr_default_set (&attr, origin);

  attr.distance = local_distance;
  if (aspath  && aspath->data)
    {
      if (attr.aspath)
        aspath_unintern (attr.aspath);

      attr.aspath = aspath_intern (aspath);

      if (atomic_set)
        attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);
    }
  if (aspath4B && aspath4B->data)
    {
      if (attr.aspath4B)
        aspath4B_unintern (attr.aspath4B);

      attr.aspath4B = aspath4B_intern (aspath4B);
    }
   if (as4path && as4path->data)
    {
      if (attr.as4path)
        as4path_unintern (attr.as4path);

      attr.as4path = as4path_intern (as4path);
    }
  else
    attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);

  if (community)
    {
      attr.community = community;
      attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);
    }

  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR);
  if (bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION))
    {
      if (! BGP_IS_AS4_MAPPABLE (bgp->confed_id))
        {
          attr.aggregator_as = BGP_AS_TRANS; 
          attr.aggregator_as4 = bgp->confed_id;
        }
      else
        {
          attr.aggregator_as = bgp->confed_id;
          attr.aggregator_as4 =  bgp->confed_id;
        }
    }
    
  else if (! BGP_IS_AS4_MAPPABLE (bgp->as))
    {
      attr.aggregator_as = BGP_AS_TRANS;
      attr.aggregator_as4 = bgp->as;
    }
  else
    {
      attr.aggregator_as = bgp->as;
      attr.aggregator_as4 = bgp->as;
    }
    
   attr.aggregator_addr = bgp->router_id;

  new = bgp_attr_intern (&attr);
  aspath_unintern (new->aspath); 
  aspath4B_unintern (new->aspath4B);
  as4path_unintern (new->as4path);

  return new;
}
#endif /* HAVE_EXT_CAP_ASN */
/* Free bgp attribute and aspath. */
void
bgp_attr_unintern (struct attr *attr)
{
  struct attr *ret;
  struct aspath *aspath;
#ifdef HAVE_EXT_CAP_ASN
  struct as4path *as4path;
  struct as4path *aspath4B;
#endif /* HAVE_EXT_CAP_ASN */
  struct community *community;
  struct ecommunity *ecommunity;
  struct cluster_list *cluster;
  struct transit *transit;

  /* Decrement attribute reference. */
  attr->refcnt--;
  aspath = attr->aspath;
#ifdef HAVE_EXT_CAP_ASN
  as4path = attr->as4path;
  aspath4B = attr->aspath4B;
#endif /* HAVE_EXT_CAP_ASN */
  community = attr->community;
  ecommunity = attr->ecommunity;
  cluster = attr->cluster;
  transit = attr->transit;

  /* If reference becomes zero then free attribute object. */
  if (attr->refcnt == 0)
    {
      ret = hash_release (bgp_attrhash_tab, attr);
      pal_assert (ret != NULL);
      XFREE (MTYPE_ATTR, attr);
    }

  /* aspath refcount shoud be decrement. */
  if (aspath)
    aspath_unintern (aspath);
#ifdef HAVE_EXT_CAP_ASN
  if (as4path)
    as4path_unintern (as4path);
  if (aspath4B)
    aspath4B_unintern (aspath4B);
#endif /* HAVE_EXT_CAP_ASN */
  if (community)
    community_unintern (community);
  if (ecommunity)
    ecommunity_unintern (ecommunity);
  if (cluster)
    cluster_unintern (cluster);
  if (transit)
    transit_unintern (transit);
}

void
bgp_attr_flush (struct attr *attr)
{
  if (attr->aspath && ! attr->aspath->refcnt)
    aspath_free (attr->aspath);
#ifdef HAVE_EXT_CAP_ASN
  if (attr->aspath4B && ! attr->aspath4B->refcnt)
    as4path_free (attr->aspath4B);
  if (attr->as4path && ! attr->as4path->refcnt)
    as4path_free (attr->as4path);
#endif /* HAVE_EXT_CAP_ASN */
  if (attr->community && ! attr->community->refcnt)
    community_free (attr->community);
  if (attr->ecommunity && ! attr->ecommunity->refcnt)
    ecommunity_free (attr->ecommunity);
  if (attr->cluster && ! attr->cluster->refcnt)
    cluster_free (attr->cluster);
  if (attr->transit && ! attr->transit->refcnt)
    transit_free (attr->transit);
}

/* BGP Attribute Initialization */
void
bgp_attr_init (void)
{
  aspath_init ();
#ifdef HAVE_EXT_CAP_ASN
  aspath4B_init ();
  as4path_init ();
#endif /* HAVE_EXT_CAP_ASN */
  attrhash_init ();
  community_init ();
  ecommunity_init ();
  bgp_cluster_init ();
  transit_init ();
}

/* Validate presence of Well-known Mandatory attributes */
/*
 * RFC 2858 (Section 2)
 * An UPDATE message that carries the MP REACH NLRI must also carry the ORIGIN
 * and the AS_PATH attributes (both in EBGP and in IBGP exchanges). Moreover,
 * in IBGP exchanges such a message must also carry the LOCAL_PREF attribute.
 * ...
 * An UPDATE message that carries no NLRI, other than the one encoded in
 * the MP_REACH_NLRI attribute, should not carry the NEXT_HOP attribute.
 * If such a message contains the NEXT_HOP attribute, the BGP speaker
 * that receives the message should ignore this attribute.
*/
bool_t
bgp_peer_attr_check (struct bgp_peer *peer,
                     struct attr *attr,
                     bool_t nhop_chk)
{
  u_int8_t attr_type = 0;

  if (! CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_ORIGIN)))
    attr_type = BGP_ATTR_ORIGIN;
  else if (! CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_AS_PATH)))
    attr_type = BGP_ATTR_AS_PATH;
  else if (nhop_chk == PAL_TRUE
           && ! CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP)))
    attr_type = BGP_ATTR_NEXT_HOP;
  else if (peer_sort (peer) == BGP_PEER_IBGP
           && ! CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF)))
    attr_type = BGP_ATTR_LOCAL_PREF;

  if (attr_type)
    {
      zlog_err (&BLG, "%s-%s [DECODE] Update Attr: Mandatory "
                "Well-known Attribute (Type %d) missing",
                peer->host, BGP_PEER_DIR_STR (peer), attr_type);

      bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                        BGP_NOTIFY_UPDATE_ERR,
                        BGP_NOTIFY_UPDATE_MISS_ATTR,
                        &attr_type, 1);

      return PAL_FALSE;
    }

  return PAL_TRUE;
}

