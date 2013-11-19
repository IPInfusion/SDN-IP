/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/*********************************************************************/
/* FILE       : bgp_routemap.c                                       */
/* PURPOSE    : This file contains 'BGP Route-Maps' related function */
/*              definitions.                                         */
/* SUB-MODULE : BGP Route-Map                                        */
/* NAME-TAG   : 'brm_' (BGP Route-Map)                               */
/*********************************************************************/

/* Memo of route-map commands.

o Cisco route-map

 match as-path          :  Done
       community        :  Done
       interface        :  Not yet
       ip address       :  Done
       ip next-hop      :  Done
       ip route-source  :  (This will not be implemented by bgpd)
       ip prefix-list   :  Done
       ipv6 address     :  Done
       ipv6 next-hop    :  Done
       ipv6 route-source:  (This will not be implemented by bgpd)
       ipv6 prefix-list :  Done
       length           :  (This will not be implemented by bgpd)
       metric           :  Done
       route-type       :  (This will not be implemented by bgpd)
       tag              :  (This will not be implemented by bgpd)

 set  as-path prepend   :  Done
      as-path tag       :  Not yet
      automatic-tag     :  (This will not be implemented by bgpd)
      community         :  Done
      comm-list         :  Not yet
      dampening         :  Done
      default           :  (This will not be implemented by bgpd)
      interface         :  (This will not be implemented by bgpd)
      ip default        :  (This will not be implemented by bgpd)
      ip next-hop       :  Done
      ip precedence     :  (This will not be implemented by bgpd)
      ip tos            :  (This will not be implemented by bgpd)
      level             :  (This will not be implemented by bgpd)
      local-preference  :  Done
      metric            :  Done
      metric-type       :  Not yet
      origin            :  Done
      tag               :  (This will not be implemented by bgpd)
      weight            :  Done

o mrt extension

  set dpa as %d %d      :  Not yet
      atomic-aggregate  :  Done
      aggregator as %d %M :  Done

o Local extention

  set ipv6 next-hop       : Done
  set ipv6 next-hop local : Done

*/

/* Convert AS-Path-List return codes into Route-Map return codes */
route_map_result_t
brm_aslist2rmap_rcode (enum as_filter_type asf_type)
{
  route_map_result_t ret;

  ret = RMAP_ERROR;

  switch (asf_type)
   {
     case AS_FILTER_DENY:
       ret = RMAP_DENYMATCH;
       break;

     case AS_FILTER_PERMIT:
       ret = RMAP_MATCH;
       break;

     case AS_FILTER_NO_MATCH:
       ret = RMAP_NOMATCH;
       break;

     default:
       break;
   }

  return ret;
}

/* Convert Community-List return codes into Route-Map return codes */
route_map_result_t
brm_clist2rmap_rcode (enum community_type comm_type)
{
  route_map_result_t ret;

  ret = RMAP_ERROR;

  switch (comm_type)
   {
     case COMMUNITY_DENY:
       ret = RMAP_DENYMATCH;
       break;

     case COMMUNITY_PERMIT:
       ret = RMAP_MATCH;
       break;

     case COMMUNITY_NO_MATCH:
       ret = RMAP_NOMATCH;
       break;

     default:
       break;
   }

  return ret;
}

/* Synchronize Prefix Reachability */
result_t
brm_prefix_synchronize (void *obj1, void *obj2)
{
  struct bgp_rmap_info *brmi;
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct prefix *p;
  u_int32_t baai;
  result_t ret;

  brmi = (struct bgp_rmap_info *) obj1;
  p = (struct prefix *) obj2;
  ret = PAL_FALSE;
  baai = BGP_AFI2BAAI (family2afi (p->family));
  
  rn =  bgp_node_lookup (brmi->brmi_bgp->rib [baai][BSAI_UNICAST], p);
  if (rn)
    {
      for (ri = rn->info; ri; ri = ri->next)
        if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
          {
            ret = PAL_TRUE;
            break;
          }
    }
   
  return ret;
}


/* `match ip address IP_ACCESS_LIST' */

route_map_result_t
brm_match_ip_address (void *rule, struct prefix *prefix,
                      struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct access_list *alist;
  enum filter_type acode;

  brmi = (struct bgp_rmap_info *) object;
  acode = FILTER_NO_MATCH;

  alist = access_list_lookup (BGP_VR.owning_ivr, AFI_IP, (char *) rule);

  if (! brmi)
    acode = access_list_apply (alist, prefix);
  else switch (brmi->brmi_type)
    {
    case BGP_RMAP_INFO_REGULAR:
      acode = access_list_apply (alist, prefix);
      break;


    case BGP_RMAP_INFO_SYNC_PREFIX:
      acode = access_list_custom_apply (alist,
                                        brm_prefix_synchronize,
                                        object);
      break;
    }

  return route_map_alist2rmap_rcode (acode);
}

void *
brm_match_ip_address_compile (char *asl_name)
{
  if (! access_list_reference_validate (asl_name))
    return NULL;

  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, asl_name);
}

void
brm_match_ip_address_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd brm_match_ip_address_cmd =
{
  "ip address",
  brm_match_ip_address,
  brm_match_ip_address_compile,
  brm_match_ip_address_free,
  "(access-lists)"
};


/* `match ip next-hop IP_ADDRESS' */

route_map_result_t
brm_match_ip_next_hop (void *rule, struct prefix *prefix,
                       struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct access_list *alist;
  enum filter_type acode;
  struct prefix_ipv4 p;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  p.family = AF_INET;
  p.prefix = ri->attr->nexthop;
  p.prefixlen = IPV4_MAX_BITLEN;

  alist = access_list_lookup (BGP_VR.owning_ivr, AFI_IP, (char *) rule);

  acode = access_list_apply (alist, &p);

  return route_map_alist2rmap_rcode (acode);
}

void *
brm_match_ip_next_hop_compile (char *asl_name)
{
  if (! access_list_reference_validate (asl_name))
    return NULL;

  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, asl_name);
}

void
brm_match_ip_next_hop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip next-hop matching */
struct route_map_rule_cmd brm_match_ip_next_hop_cmd =
{
  "ip next-hop",
  brm_match_ip_next_hop,
  brm_match_ip_next_hop_compile,
  brm_match_ip_next_hop_free
};

/* `match ip peer IP_ADDRESS' */
route_map_result_t
brm_match_ip_peer (void *rule, struct prefix *prefix,
                   struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct access_list *alist;
  enum filter_type acode;
  struct prefix_ipv4 p;
  struct bgp_info *ri;
   
  brmi = (struct bgp_rmap_info *) object;
  
  ri = brmi->brmi_bri;
  p.family = AF_INET;
  p.prefix = ri->peer->su_remote->sin.sin_addr;
  p.prefixlen = IPV4_MAX_BITLEN;
   
  alist = access_list_lookup (BGP_VR.owning_ivr, AFI_IP, (char *) rule);
   
  acode = access_list_apply (alist, &p);
 
  return route_map_alist2rmap_rcode (acode);
}
 
void *
brm_match_ip_peer_compile (char *asl_name)
{
  if (! access_list_reference_validate (asl_name))
    return NULL;
  
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, asl_name);
}
 
void
brm_match_ip_peer_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}
 
/* Route map commands for ip peer matching */
struct route_map_rule_cmd brm_match_ip_peer_cmd =
{
  "ip peer",
  brm_match_ip_peer,
  brm_match_ip_peer_compile,
  brm_match_ip_peer_free
};

#ifdef HAVE_IPV6
/* `match ip peer IP_ADDRESS' */
route_map_result_t
brm_match_ipv6_peer (void *rule, struct prefix *prefix,
                   struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct access_list *alist;
  enum filter_type acode;
  struct prefix_ipv6 p;
  struct bgp_info *ri;
   
  brmi = (struct bgp_rmap_info *) object;
  
  ri = brmi->brmi_bri;
  p.family = AF_INET;
  p.prefix = ri->peer->su_remote->sin6.sin6_addr;
  p.prefixlen = IPV6_MAX_BITLEN;
   
  alist = access_list_lookup (BGP_VR.owning_ivr, AFI_IP6, (char *) rule);
   
  acode = access_list_apply (alist, &p);
 
  return route_map_alist2rmap_rcode (acode);
}
 
void *
brm_match_ipv6_peer_compile (char *asl_name)
{
  if (! access_list_reference_validate (asl_name))
    return NULL;
  
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, asl_name);
}
 
void
brm_match_ipv6_peer_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}
 
/* Route map commands for ip peer matching */
struct route_map_rule_cmd brm_match_ipv6_peer_cmd =
{
  "ipv6 peer",
  brm_match_ipv6_peer,
  brm_match_ipv6_peer_compile,
  brm_match_ipv6_peer_free
};
#endif /*HAVE_IPV6*/

/* `match ip address prefix-list PREFIX_LIST' */

route_map_result_t
brm_match_ip_address_prefix_list (void *rule, struct prefix *prefix,
                                  struct route_map_rule *type, void *object)
{
  enum prefix_list_type pcode;
  struct bgp_rmap_info *brmi;
  struct prefix_list *plist;

  brmi = (struct bgp_rmap_info *) object;
  pcode = PREFIX_NO_MATCH;

  plist = prefix_list_lookup (BGP_VR.owning_ivr, AFI_IP, (char *) rule);

  if (! brmi)
    pcode = prefix_list_apply (plist, prefix);
  else switch (brmi->brmi_type)
    {
    case BGP_RMAP_INFO_REGULAR:
      pcode = prefix_list_apply (plist, prefix);
      break;

    case BGP_RMAP_INFO_SYNC_PREFIX:
      pcode = prefix_list_custom_apply (plist,
                                        brm_prefix_synchronize,
                                        object);
      break;
    }

  return route_map_plist2rmap_rcode (pcode);
}

void *
brm_match_ip_address_prefix_list_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
brm_match_ip_address_prefix_list_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

struct route_map_rule_cmd brm_match_ip_address_prefix_list_cmd =
{
  "ip address prefix-list",
  brm_match_ip_address_prefix_list,
  brm_match_ip_address_prefix_list_compile,
  brm_match_ip_address_prefix_list_free
};


/* `match ip next-hop prefix-list PREFIX_LIST' */

route_map_result_t
brm_match_ip_next_hop_prefix_list (void *rule, struct prefix *prefix,
                                   struct route_map_rule *type, void *object)
{
  enum prefix_list_type pcode;
  struct bgp_rmap_info *brmi;
  struct prefix_list *plist;
  struct prefix_ipv4 p;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  p.family = AF_INET;
  p.prefix = ri->attr->nexthop;
  p.prefixlen = IPV4_MAX_BITLEN;

  plist = prefix_list_lookup (BGP_VR.owning_ivr, AFI_IP, (char *) rule);

  pcode = prefix_list_apply (plist, &p);

  return route_map_plist2rmap_rcode (pcode);
}

void *
brm_match_ip_next_hop_prefix_list_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
brm_match_ip_next_hop_prefix_list_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

struct route_map_rule_cmd brm_match_ip_next_hop_prefix_list_cmd =
{
  "ip next-hop prefix-list",
  brm_match_ip_next_hop_prefix_list,
  brm_match_ip_next_hop_prefix_list_compile,
  brm_match_ip_next_hop_prefix_list_free
};


/* `match metric METRIC' */

route_map_result_t
brm_match_metric (void *rule, struct prefix *prefix,
                  struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;
  u_int32_t *med;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  med = rule;

  if (ri->attr->med == *med)
    return RMAP_MATCH;
  else
    return RMAP_NOMATCH;
}

void *
brm_match_metric_compile (char *arg)
{
  u_int32_t *med;
  u_int32_t val;
  int ret;

  /* +/- value is not allowed */
  if (! pal_char_isdigit ((int) arg[0]))
    return NULL;

  val = cmd_str2int (arg, &ret);
  if (ret < 0)
    return NULL;

  med = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  *med = val;

  return med;
}

void
brm_match_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Route map commands for metric matching */
struct route_map_rule_cmd brm_match_metric_cmd =
{
  "metric",
  brm_match_metric,
  brm_match_metric_compile,
  brm_match_metric_free
};

/* `match tag' */

route_map_result_t
brm_match_tag (void *rule, struct prefix *prefix,
                  struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;
  u_int32_t *tag;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  tag = rule;

  if (ri->tag == *tag)
    return RMAP_MATCH;
  else
    return RMAP_NOMATCH;
}

void *
brm_match_tag_compile (char *arg)
{
  u_int32_t *tag;
  u_int32_t val;
  int ret;

  /* +/- value is not allowed */
  if (! pal_char_isdigit ((int) arg[0]))
    return NULL;

  val = cmd_str2int (arg, &ret);
  if (ret < 0)
    return NULL;

  tag = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  *tag = val;

  return tag;
}

void
brm_match_tag_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Route map commands for tag matching */
struct route_map_rule_cmd brm_match_tag_cmd =
{
  "tag",
  brm_match_tag,
  brm_match_tag_compile,
  brm_match_tag_free
};



/* `match as-path ASPATH' */

route_map_result_t
brm_match_aspath (void *rule, struct prefix *prefix,
                  struct route_map_rule *type, void *object)
{
  enum as_filter_type ascode;
  struct bgp_rmap_info *brmi;
  struct as_list *as_list;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;

  as_list = as_list_lookup ((char *) rule);

#ifndef HAVE_EXT_CAP_ASN
  ascode = as_list_apply (as_list, ri->attr->aspath);
#else
  /* check for Local speaker */ 
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    ascode = as_list_apply (as_list, ri->attr->aspath4B);
  else
    ascode = as_list_apply (as_list, ri->attr->aspath);
#endif /* HAVE_EXT_CAP_ASN */
  return brm_aslist2rmap_rcode (ascode);
}

void *
brm_match_aspath_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
brm_match_aspath_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Route map commands for aspath matching */
struct route_map_rule_cmd brm_match_aspath_cmd =
{
  "as-path",
  brm_match_aspath,
  brm_match_aspath_compile,
  brm_match_aspath_free,
  "(as-path filter)"
};


/* `match community COMMUNIY' */

route_map_result_t
brm_match_community (void *rule, struct prefix *prefix,
                     struct route_map_rule *type, void *object)
{
  struct bgp_route_map_comm *rcom;
  enum community_type comm_code;
  struct community_list *clist;
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  rcom = rule;

  clist = community_list_lookup (bgp_clist, rcom->brmc_name, COMMUNITY_LIST_AUTO);

  if (rcom->brmc_exact)
    comm_code = community_list_exact_match (ri->attr->community, clist);
  else
    comm_code = community_list_match (ri->attr->community, clist);

  return brm_clist2rmap_rcode (comm_code);
}

void *
brm_match_community_compile (char *arg)
{
  struct bgp_route_map_comm *rcom;
  u_int32_t len;
  char *p;

  rcom = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct bgp_route_map_comm));

  if (! rcom)
    return rcom;

  p = pal_strchr (arg, ' ');
  if (p)
    {
      len = p - arg;
      rcom->brmc_name = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, len + 1);

      if (! rcom->brmc_name)
        {
          XFREE (MTYPE_ROUTE_MAP_COMPILED, rcom);
          rcom = NULL;

          return rcom;
        }

      pal_mem_cpy (rcom->brmc_name, arg, len);
      rcom->brmc_exact = PAL_TRUE;
    }
  else
    {
      rcom->brmc_name = XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);

      if (! rcom->brmc_name)
        {
          XFREE (MTYPE_ROUTE_MAP_COMPILED, rcom);
          rcom = NULL;

          return rcom;
        }

      rcom->brmc_exact = PAL_FALSE;
    }

  return rcom;
}

void
brm_match_community_free (void *rule)
{
  struct bgp_route_map_comm *rcom = rule;

  if (rcom)
    {
      if (rcom->brmc_name)
        XFREE (MTYPE_ROUTE_MAP_COMPILED, rcom->brmc_name);
      XFREE (MTYPE_ROUTE_MAP_COMPILED, rcom);
    }

  return;
}

/* Route map commands for community matching */
struct route_map_rule_cmd brm_match_community_cmd =
{
  "community",
  brm_match_community,
  brm_match_community_compile,
  brm_match_community_free
};

/* `match community COMMUNIY' */

route_map_result_t
brm_match_ecommunity (void *rule, struct prefix *prefix,
                     struct route_map_rule *type, void *object)
{
  struct bgp_route_map_comm *rcom;
  enum community_type comm_code = COMMUNITY_NO_MATCH;
  struct community_list *clist;
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  if (!brmi)
    return comm_code;

  ri = brmi->brmi_bri;
  
  if (!ri)
    return comm_code;
  
  rcom = rule;

  clist = community_list_lookup (bgp_clist, rcom->brmc_name, 
                                 EXTCOMMUNITY_LIST_AUTO);
  if (!clist)
    return comm_code;

  if (rcom->brmc_exact)
    comm_code = ecommunity_list_exact_match (ri->attr->ecommunity, clist);
                                             
  else
    comm_code = ecommunity_list_match (ri->attr->ecommunity, clist);

  return brm_clist2rmap_rcode (comm_code);
}

void *
brm_match_ecommunity_compile (char *arg)
{
  struct bgp_route_map_comm *rcom;
  u_int32_t len;
  char *p = NULL;

  if (!arg)
    return NULL;

  rcom = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct bgp_route_map_comm));

  if (! rcom)
    return rcom;

  p = pal_strchr (arg, ' ');
  if (p)
    {
      len = p - arg;
      rcom->brmc_name = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, len + 1);

      if (! rcom->brmc_name)
        {
          XFREE (MTYPE_ROUTE_MAP_COMPILED, rcom);
          rcom = NULL;

          return rcom;
        }

      pal_mem_cpy (rcom->brmc_name, arg, len);
      rcom->brmc_exact = PAL_TRUE;
    }
  else
    {
      rcom->brmc_name = XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);

      if (! rcom->brmc_name)
        {
          XFREE (MTYPE_ROUTE_MAP_COMPILED, rcom);
          rcom = NULL;

          return rcom;
        }

      rcom->brmc_exact = PAL_FALSE;
    }

  return rcom;
}

void
brm_match_ecommunity_free (void *rule)
{
  struct bgp_route_map_comm *rcom = rule;

  if (rcom)
    {
      if (rcom->brmc_name)
        XFREE (MTYPE_ROUTE_MAP_COMPILED, rcom->brmc_name);
      XFREE (MTYPE_ROUTE_MAP_COMPILED, rcom);
    }

  return;
}

/* Route map commands for community matching */
struct route_map_rule_cmd brm_match_ecommunity_cmd =
{
  "extcommunity",
  brm_match_ecommunity,
  brm_match_ecommunity_compile,
  brm_match_ecommunity_free
};


/* `match origin' */

route_map_result_t
brm_match_origin (void *rule, struct prefix *prefix,
                  struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;
  u_int8_t *origin;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  origin = rule;

  if (ri->attr->origin == *origin)
    return RMAP_MATCH;

  return RMAP_NOMATCH;
}

void *
brm_match_origin_compile (char *arg)
{
  u_int8_t *origin;

  origin = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int8_t));

  if (! pal_strcmp (arg, "igp"))
    *origin = BGP_ORIGIN_IGP;
  else if (! pal_strcmp (arg, "egp"))
    *origin = BGP_ORIGIN_EGP;
  else
    *origin = BGP_ORIGIN_INCOMPLETE;

  return origin;
}

void
brm_match_origin_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Route map commands for origin matching */
struct route_map_rule_cmd brm_match_origin_cmd =
{
  "origin",
  brm_match_origin,
  brm_match_origin_compile,
  brm_match_origin_free
};


/* `set ip next-hop IP_ADDRESS' */

route_map_result_t
brm_set_ip_nexthop (void *rule, struct prefix *prefix,
                    struct route_map_rule *type, void *object)
{
  struct pal_in4_addr *address;
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  address = rule;

  /* Set next hop value. */
  ri->attr->nexthop = *address;
  SET_FLAG (ri->flags_misc, BGP_INFO_RMAP_NEXTHOP_APPLIED);

  return RMAP_OKAY;
}

void *
brm_set_ip_nexthop_compile (char *arg)
{
  struct pal_in4_addr *address;
  s_int32_t ret;

  address = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct pal_in4_addr));

  if (! address)
    return address;

  ret = pal_inet_pton (AF_INET, arg, address);

  if (! ret)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      address = NULL;
    }

  return address;
}

void
brm_set_ip_nexthop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd brm_set_ip_nexthop_cmd =
{
  "ip next-hop",
  brm_set_ip_nexthop,
  brm_set_ip_nexthop_compile,
  brm_set_ip_nexthop_free
};

/* `set ip peer IP_ADDRESS' */

route_map_result_t
brm_set_ip_peer (void *rule, struct prefix *prefix,
                 struct route_map_rule *type, void *object)
{
  struct pal_in4_addr *address;
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;
  
  brmi = (struct bgp_rmap_info *) object;
   
  ri = brmi->brmi_bri;
  address = rule;
   
  /* Set next hop value. */
  ri->peer->su_remote->sin.sin_addr = *address;
   
  return RMAP_OKAY;
}
 
void *
brm_set_ip_peer_compile (char *arg)
{
  struct pal_in4_addr *address;
  s_int32_t ret;
   
  address = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct pal_in4_addr));
   
  if (! address)
    return address;
   
  ret = pal_inet_pton (AF_INET, arg, address);
   
  if (! ret)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      address = NULL;
    }
    
  return address;
}
 
void
brm_set_ip_peer_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
  return;
}
 
/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd brm_set_ip_peer_cmd =
{
  "ip peer",
  brm_set_ip_peer,
  brm_set_ip_peer_compile,
  brm_set_ip_peer_free
};

#ifdef HAVE_IPV6
/* `set ipv6 peer IP_ADDRESS' */
route_map_result_t
brm_set_ipv6_peer (void *rule, struct prefix *prefix,
                 struct route_map_rule *type, void *object)
{
  struct pal_in6_addr *address;
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;
  
  brmi = (struct bgp_rmap_info *) object;
   
  ri = brmi->brmi_bri;
  address = rule;
   
  /* Set next hop value. */
  ri->peer->su_remote->sin6.sin6_addr = *address;
   
  return RMAP_OKAY;
}
 
void *
brm_set_ipv6_peer_compile (char *arg)
{
  struct pal_in6_addr *address;
  s_int32_t ret;
   
  address = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct pal_in6_addr));
   
  if (! address)
    return address;
   
  ret = pal_inet_pton (AF_INET6, arg, address);
   
  if (! ret)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      address = NULL;
    }
    
  return address;
}
 
void
brm_set_ipv6_peer_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
  return;
}
 
/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd brm_set_ipv6_peer_cmd =
{
  "ipv6 peer",
  brm_set_ipv6_peer,
  brm_set_ipv6_peer_compile,
  brm_set_ipv6_peer_free
};
#endif /*HAVE_IPV6*/


/* `set local-preference LOCAL_PREF' */

route_map_result_t
brm_set_local_pref (void *rule, struct prefix *prefix,
                    struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  u_int32_t *local_pref;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  local_pref = rule;

  /* Set local preference value. */
  ri->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);
  ri->attr->local_pref = *local_pref;

  return RMAP_OKAY;
}

void *
brm_set_local_pref_compile (char *arg)
{
  u_int32_t *local_pref;
  u_int32_t val;
  s_int32_t ret;

  /* +/- value is not allowed. */
  if (! pal_char_isdigit ((int) arg[0]))
    return NULL;

  val = cmd_str2int (arg, &ret);
  if (ret < 0)
    return NULL;

  local_pref = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));

  if (! local_pref)
    return local_pref;

  *local_pref = val;

  return local_pref;
}

void
brm_set_local_pref_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Set local preference rule structure. */
struct route_map_rule_cmd brm_set_local_pref_cmd =
{
  "local-preference",
  brm_set_local_pref,
  brm_set_local_pref_compile,
  brm_set_local_pref_free,
};


/* `set weight WEIGHT' */

route_map_result_t
brm_set_weight (void *rule, struct prefix *prefix,
                struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;
  u_int32_t *weight;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  weight = rule;

  /* Set weight value. */
  ri->attr->weight = *weight;

  return RMAP_OKAY;
}

void *
brm_set_weight_compile (char *arg)
{
  u_int32_t *weight;
  u_int32_t val;
  s_int32_t ret;

  /* +/- value is not allowed. */
  if (! pal_char_isdigit ((int) arg[0]))
    return NULL;

  val = cmd_str2int (arg, &ret);
  if (ret < 0)
    return NULL;

  weight = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));

  if (! weight)
    return weight;

  *weight = val;

  return weight;
}

void
brm_set_weight_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Set local preference rule structure */
struct route_map_rule_cmd brm_set_weight_cmd =
{
  "weight",
  brm_set_weight,
  brm_set_weight_compile,
  brm_set_weight_free,
};


/* `set metric METRIC' */

route_map_result_t
brm_set_metric (void *rule, struct prefix *prefix,
                struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  u_int32_t metric_val;
  struct bgp_info *ri;
  u_int8_t *metric;
  s_int32_t ret;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  metric = rule;

  if (! (ri->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC)))
    ri->attr->med = 0;
  ri->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

  if (pal_char_isdigit ((int) metric[0]))
    {
      metric_val = cmd_str2int (metric, &ret);
      ri->attr->med = metric_val;
    }
  else
    {
      metric_val = cmd_str2int (metric + 1, &ret);

      if (pal_strncmp (metric, "+", 1) == 0)
        {
          if (ri->attr->med/2 + metric_val/2 > UINT_MAX/2)
            ri->attr->med = UINT_MAX-1;
          else
            ri->attr->med += metric_val;
        }
      else if (pal_strncmp (metric, "-", 1) == 0)
        {
          if (ri->attr->med <= metric_val)
            ri->attr->med = 0;
          else
            ri->attr->med -= metric_val;
        }
    }

  return RMAP_OKAY;
}

void *
brm_set_metric_compile (char *arg)
{
  u_int32_t metric;
  s_int32_t ret;

  /* +/- value is allowed. */
  if ((arg[0] == '+' || arg[0] == '-') && pal_char_isdigit ((int) arg[1]))
    metric = cmd_str2int (arg + 1, &ret);
  else
    metric = cmd_str2int (arg, &ret);

  if (ret < 0)
    return NULL;

  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
brm_set_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure */
struct route_map_rule_cmd brm_set_metric_cmd =
{
  "metric",
  brm_set_metric,
  brm_set_metric_compile,
  brm_set_metric_free,
};


/* `set as-path prepend ASPATH' */

route_map_result_t
brm_set_aspath_prepend (void *rule, struct prefix *prefix,
                        struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct aspath *aspath;
  struct bgp_info *ri;
  struct aspath *new;
#ifdef HAVE_EXT_CAP_ASN
  struct as4path *aspath4B;
  struct as4path *as4path;
  struct as4path *new_4b;
  struct as4path *new_as4;
  u_int32_t non_mappablecount;
#endif /* HAVE_EXT_CAP_ASN */
  aspath = NULL;
  new = NULL;
#ifdef HAVE_EXT_CAP_ASN
  aspath4B = NULL;
  new_4b = NULL;
  as4path = NULL;
  new_as4 = NULL;
  non_mappablecount = 0;
#endif /* HAVE_EXT_CAP_ASN */ 
  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
#ifndef HAVE_EXT_CAP_ASN
  aspath = rule;
  if (! aspath)
    return RMAP_ERROR;
#else
  aspath4B = rule;
  if (!aspath4B)
    return RMAP_ERROR;
  /* create aspath and as4path structure */
  aspath = aspath_new ();
  if (!aspath)
    return RMAP_ERROR;

  as4path = as4path_new ();
  if (!as4path)
    {
      if (aspath)
        aspath_free(aspath);
      return RMAP_ERROR; 
    }

  /* construct aspath and as4path structures from aspath4B */  
  aspath = aspath_copy_aspath4B_to_aspath (aspath4B, aspath);
  aspath->str = aspath_make_str_count (aspath);
  non_mappablecount = aspath4B_nonmappable_count (aspath4B);
  if (non_mappablecount)
    {
      as4path = construct_as4path_from_aspath4B (aspath4B, as4path);
      as4path->str = as4path_make_str_count (as4path);
    }

  /* Check if local speaker is NBGP */ 
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      /* prepending aspath4B */
      if (ri->attr->aspath4B)
        { 
          if (ri->attr->aspath4B->refcnt)
            new_4b = as4path_dup (ri->attr->aspath4B);
          else
            new_4b = ri->attr->aspath4B;
         /* prepend aspath4B */
          if ((aspath4B->str != NULL)
                && (ri->attr->aspath4B->str == NULL) )
            {
              as4path_prepend (aspath4B, new_4b);
              ri->attr->aspath4B = new_4b;
            }
          else if ( (aspath4B->str != NULL) 
                     && (ri->attr->aspath4B->str != NULL))
            {
              if (pal_strncmp (aspath4B->str,
                                      ri->attr->aspath4B->str,
                                      pal_strlen(aspath4B->str))!= 0)
               {
                 as4path_prepend (aspath4B, new_4b);
                 ri->attr->aspath4B = new_4b;
               }
              else
                 as4path_free (new_4b);
            }  
          else
              as4path_free (new_4b);
        } 

      /* prepending aspath */
      if (ri->attr->aspath)
        {
          if (ri->attr->aspath->refcnt)
            new = aspath_dup (ri->attr->aspath);
          else
            new = ri->attr->aspath;

          /* prepend aspath */
          if ((aspath->str != NULL) && (ri->attr->aspath->str == NULL))
            {
              aspath_prepend (aspath, new);
              ri->attr->aspath = new;
            }
          else if ((aspath->str != NULL) && (ri->attr->aspath->str != NULL))
            {
              if (pal_strncmp (aspath->str,
                                        ri->attr->aspath->str,
                                        pal_strlen(aspath->str))!= 0)
                {
                  aspath_prepend (aspath, new);
                  ri->attr->aspath = new;
                }
              else
                  aspath_free (new);
            } 
          else
              aspath_free (new);
        } 

      /* prepending as4path */
      if (non_mappablecount && ri->attr->as4path) 
        {
          if (ri->attr->as4path->refcnt)
            new_as4 = as4path_dup (ri->attr->as4path);
          else
            new_as4 = ri->attr->as4path;
          /* prepend as4path */
          if ((as4path->str != NULL) && (ri->attr->as4path->str == NULL))
            {
              as4path_prepend (as4path, new_as4);
              ri->attr->as4path = new_as4;
            }
          /* Do not prepend if it has been prepended already */
          else if ((as4path->str != NULL) && (ri->attr->as4path->str != NULL))
            {
              if (pal_strncmp (as4path->str,
                                          ri->attr->as4path->str,
                                          pal_strlen(as4path->str))!= 0)
                {
                  as4path_prepend (as4path, new_as4);
                  ri->attr->as4path = new_as4;
                }
              else
                as4path_free (new_as4);     
            }
          else
              as4path_free (new_as4);
        }
    }
  /* Local Speaker is OBGP or HAVE_EXT_CAP_ASN is not defined */
  else 
    {
#endif /* HAVE_EXT_CAP_ASN */
      if (ri->attr->aspath)
        {
          if (ri->attr->aspath->refcnt)
            new = aspath_dup (ri->attr->aspath);  
          else
            new = ri->attr->aspath;
          /* prepend aspath  */
          if ((aspath->str != NULL) && (ri->attr->aspath->str == NULL))
            {
              aspath_prepend (aspath, new);
              ri->attr->aspath = new;
            }
          /* Do not prepend if it has been prepended already */
          else if ((aspath->str != NULL) && (ri->attr->aspath->str != NULL))
            {
              if (pal_strncmp (aspath->str,
                                          ri->attr->aspath->str,
                                          pal_strlen(aspath->str))!= 0)
                {
                  aspath_prepend (aspath, new);
                  ri->attr->aspath = new;
                }
              else
                aspath_free (new);
            }
          else
              aspath_free (new);
        }
#ifdef HAVE_EXT_CAP_ASN
    }
  aspath_free (aspath);
  as4path_free (as4path);
#endif /* HAVE_EXT_CAP_ASN */
  return RMAP_OKAY;
}

void *
brm_set_aspath_prepend_compile (char *arg)
{
#ifndef HAVE_EXT_CAP_ASN
  struct aspath *aspath;
#else
  struct as4path *aspath4B;
#endif /* HAVE_EXT_CAP_ASN */
#ifndef HAVE_EXT_CAP_ASN 
  aspath = aspath_str2aspath (arg);
  return aspath ;
#else
  aspath4B = as4path_str2as4path (arg);
  return aspath4B;
#endif /* HAVE_EXT_CAP_ASN */
}

void
brm_set_aspath_prepend_free (void *rule)
{
#ifndef HAVE_EXT_CAP_ASN
  struct aspath *aspath;
#else
  struct as4path *aspath4B;
#endif /* HAVE_EXT_CAP_ASN */
#ifndef HAVE_EXT_CAP_ASN
  aspath = rule;
  aspath_free (aspath);
#else
  aspath4B = rule;
  as4path_free (aspath4B);
#endif /* HAVE_EXT_CAP_ASN */
  return;
}

/* Set metric rule structure. */
struct route_map_rule_cmd brm_set_aspath_prepend_cmd =
{
  "as-path prepend",
  brm_set_aspath_prepend,
  brm_set_aspath_prepend_compile,
  brm_set_aspath_prepend_free,
};


/* `set comm-list delete */

route_map_result_t
brm_set_commlist_delete (void *rule, struct prefix *prefix,
                         struct route_map_rule *type, void *object)
{
  struct community_list *clist;
  struct bgp_rmap_info *brmi;
  struct community *merge;
  struct community *new;
  struct community *old;
  struct bgp_info *ri;

  if (! rule)
    return RMAP_OKAY;

  brmi = (struct bgp_rmap_info *) object;
  ri = brmi->brmi_bri;

  clist = community_list_lookup (bgp_clist, rule, COMMUNITY_LIST_AUTO);
  old = ri->attr->community;

  if (clist && old)
    {
      merge = community_list_match_delete (old, clist);
      new = community_uniq_sort (merge);
      community_free (merge);

      if (new->size == 0)
        {
          ri->attr->community = NULL;
          ri->attr->flag &= ~ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);
          community_free (new);
        }
      else
        {
          ri->attr->community = new;
          ri->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);
        }
    }

  return RMAP_OKAY;
}

void *
brm_set_commlist_delete_compile (char *arg)
{
  u_int32_t len;
  char *str;
  char *p;

  p = pal_strchr (arg, ' ');
  if (p)
    {
      len = p - arg;
      str = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, len + 1);
      pal_mem_cpy (str, arg, len);
    }
  else
    str = NULL;

  return str;
}

void
brm_set_commlist_delete_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Set comm-list delete rule structure. */
struct route_map_rule_cmd brm_set_community_delete_cmd =
{
  "comm-list",
  brm_set_commlist_delete,
  brm_set_commlist_delete_compile,
  brm_set_commlist_delete_free,
};

/* `set community COMMUNITY' */

route_map_result_t
brm_set_community (void *rule, struct prefix *prefix,
                   struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct community *old_com;
  struct community *new_com;
  struct community *merge;
  struct community *com;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  if (! rule)
    return RMAP_OKAY;

  ri = brmi->brmi_bri;

  if (pal_strcmp (rule, "none") == 0)
    {
      ri->attr->flag &= ~(ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES));
      ri->attr->community = NULL;
    }
  else if (CHECK_FLAG (type->flags, ROUTE_MAP_FLAG_ADDITIVE))
    {
      com = rule;

      old_com = ri->attr->community;

      if (old_com)
        {
          merge = community_merge (community_dup (old_com), com);
          new_com = community_uniq_sort (merge);
          community_free (merge);
        }
      else
        new_com = community_dup (com);

      ri->attr->community = new_com;
      ri->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);
    }
  else
    {
      com = rule;

      ri->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);
      ri->attr->community = community_dup (com);
    }

  return RMAP_OKAY;
}

void *
brm_set_community_compile (char *arg)
{
  struct community *com;

  if (pal_strcmp (arg, "none") == 0)
    return "none";

  com = community_str2com (arg);

  return com;
}

void
brm_set_community_free (void *rule)
{
  struct community *com;

  if (! pal_strcmp (rule, "none"))
    return;

  com = rule;
  community_free (com);

  return;
}

/* Set community rule structure */
struct route_map_rule_cmd brm_set_community_cmd =
{
  "community",
  brm_set_community,
  brm_set_community_compile,
  brm_set_community_free,
};


/* `set extcommunity rt COMMUNITY' */

route_map_result_t
brm_set_ecommunity_rt (void *rule, struct prefix *prefix,
                       struct route_map_rule *type, void *object)
{
  struct ecommunity *new_ecom;
  struct ecommunity *old_ecom;
  struct bgp_rmap_info *brmi;
  struct ecommunity *ecom;
  struct bgp_info *ri;

  if (! rule)
    return RMAP_OKAY;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  ecom = rule;

  /* We assume additive for Extended Community. */
  old_ecom = ri->attr->ecommunity;

  if (old_ecom)
    new_ecom = ecommunity_merge (ecommunity_dup (old_ecom), ecom);
  else
    new_ecom = ecommunity_dup (ecom);

  ri->attr->ecommunity = new_ecom;

  ri->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);

  return RMAP_OKAY;
}

void *
brm_set_ecommunity_rt_compile (char *arg)
{
  struct ecommunity *ecom;

  ecom = ecommunity_str2com (arg, ECOMMUNITY_ROUTE_TARGET, 0);

  return ecom;
}

void
brm_set_ecommunity_rt_free (void *rule)
{
  struct ecommunity *ecom;

  ecom = rule;

  ecommunity_free (ecom);

  return;
}

/* Set community rule structure. */
struct route_map_rule_cmd brm_set_ecommunity_rt_cmd =
{
  "extcommunity rt",
  brm_set_ecommunity_rt,
  brm_set_ecommunity_rt_compile,
  brm_set_ecommunity_rt_free,
};

/* `set extcommunity soo COMMUNITY' */

route_map_result_t
brm_set_ecommunity_soo (void *rule, struct prefix *prefix,
                        struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct ecommunity *ecom;
  struct bgp_info *ri;

  if (! rule)
    return RMAP_OKAY;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  ecom = rule;

  ri->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);
  ri->attr->ecommunity = ecommunity_dup (ecom);

  return RMAP_OKAY;
}

void *
brm_set_ecommunity_soo_compile (char *arg)
{
  struct ecommunity *ecom;

  ecom = ecommunity_str2com (arg, ECOMMUNITY_SITE_ORIGIN, 0);

  return ecom;
}

void
brm_set_ecommunity_soo_free (void *rule)
{
  struct ecommunity *ecom;

  ecom = rule;

  ecommunity_free (ecom);

  return;
}

/* Set community rule structure */
struct route_map_rule_cmd brm_set_ecommunity_soo_cmd =
{
  "extcommunity soo",
  brm_set_ecommunity_soo,
  brm_set_ecommunity_soo_compile,
  brm_set_ecommunity_soo_free,
};


/* `set origin ORIGIN' */

route_map_result_t
brm_set_origin (void *rule, struct prefix *prefix,
                struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;
  u_int8_t *origin;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  origin = rule;

  ri->attr->origin = *origin;

  return RMAP_OKAY;
}

void *
brm_set_origin_compile (char *arg)
{
  u_int8_t *origin;

  origin = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int8_t));

  if (! origin)
    return origin;

  if (! pal_strcmp (arg, "igp"))
    *origin = BGP_ORIGIN_IGP;
  else if (! pal_strcmp (arg, "egp"))
    *origin = BGP_ORIGIN_EGP;
  else
    *origin = BGP_ORIGIN_INCOMPLETE;

  return origin;
}

void
brm_set_origin_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Set metric rule structure. */
struct route_map_rule_cmd brm_set_origin_cmd =
{
  "origin",
  brm_set_origin,
  brm_set_origin_compile,
  brm_set_origin_free,
};


/* `set atomic-aggregate' */

route_map_result_t
brm_set_atomic_aggregate (void *rule, struct prefix *prefix,
                          struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  ri->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);

  return RMAP_OKAY;
}

void *
brm_set_atomic_aggregate_compile (char *arg)
{
  return (void *) 1;
}

void
brm_set_atomic_aggregate_free (void *rule)
{
  return;
}

/* Set atomic aggregate rule structure. */
struct route_map_rule_cmd brm_set_atomic_aggregate_cmd =
{
  "atomic-aggregate",
  brm_set_atomic_aggregate,
  brm_set_atomic_aggregate_compile,
  brm_set_atomic_aggregate_free,
};


/* `set aggregator as AS A.B.C.D' */

route_map_result_t
brm_set_aggregator_as (void *rule, struct prefix *prefix,
                       struct route_map_rule *type, void *object)
{
  struct bgp_route_map_aggregator *aggregator;
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  aggregator = rule;
#ifndef HAVE_EXT_CAP_ASN
  ri->attr->aggregator_as = aggregator->brma_as;
#else
  ri->attr->aggregator_as = aggregator->brma_as;
  ri->attr->aggregator_as4 = aggregator->brma_as4;
#endif /* HAVE_EXT_CAP_ASN */
  ri->attr->aggregator_addr = aggregator->brma_address;
  ri->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR);

  return RMAP_OKAY;
}

void *
brm_set_aggregator_as_compile (char *arg)
{
  struct bgp_route_map_aggregator *aggregator;
  u_int8_t address[20];
  u_int8_t as[10];

  aggregator = XCALLOC (MTYPE_ROUTE_MAP_COMPILED,
                        sizeof (struct bgp_route_map_aggregator));

  if (! aggregator)
    return aggregator;

  pal_sscanf (arg, "%s %s", as, address);
#ifndef HAVE_EXT_CAP_ASN
  aggregator->brma_as = pal_strtou32 (as, NULL, 10);
#else
  aggregator->brma_as =  pal_strtou32 (as, NULL, 10);
  aggregator->brma_as4 = pal_strtou32 (as, NULL, 10);
#endif /* HAVE_EXT_CAP_ASN */
  pal_inet_aton (address, &aggregator->brma_address);

  return aggregator;
}

void
brm_set_aggregator_as_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

struct route_map_rule_cmd brm_set_aggregator_as_cmd =
{
  "aggregator as",
  brm_set_aggregator_as,
  brm_set_aggregator_as_compile,
  brm_set_aggregator_as_free,
};

#ifdef HAVE_IPV6

/* `match ipv6 address IP_ACCESS_LIST' */

route_map_result_t
brm_match_ipv6_address (void *rule, struct prefix *prefix,
                        struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct access_list *alist;
  enum filter_type acode;

  brmi = (struct bgp_rmap_info *) object;
  acode = FILTER_DENY;

  alist = access_list_lookup (BGP_VR.owning_ivr, AFI_IP6, (char *) rule);

  if (! brmi)
    acode = access_list_apply (alist, prefix);
  else switch (brmi->brmi_type)
    {
    case BGP_RMAP_INFO_REGULAR:
      acode = access_list_apply (alist, prefix);
      break;


    case BGP_RMAP_INFO_SYNC_PREFIX:
      acode = access_list_custom_apply (alist,
                                        brm_prefix_synchronize,
                                        object);
      break;
    }

  return route_map_alist2rmap_rcode (acode);
}

void *
brm_match_ipv6_address_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
brm_match_ipv6_address_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd brm_match_ipv6_address_cmd =
{
  "ipv6 address",
  brm_match_ipv6_address,
  brm_match_ipv6_address_compile,
  brm_match_ipv6_address_free
};


/* `match ipv6 next-hop IP_ADDRESS' */

route_map_result_t
brm_match_ipv6_next_hop (void *rule, struct prefix *prefix,
                         struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;
  enum filter_type acode;
  struct access_list *alist;
  struct prefix_ipv6 p;

  brmi = (struct bgp_rmap_info *) object;
  ri = brmi->brmi_bri;
  acode = FILTER_DENY;

  if ((alist = access_list_lookup (BGP_VR.owning_ivr, 
                                   AFI_IP6, (char *) rule)))
    {
      p.family = AF_INET6;
      p.prefix = ri->attr->mp_nexthop_global;
      p.prefixlen = IPV6_MAX_BITLEN;
      acode = access_list_apply (alist, &p);
      if (acode != FILTER_PERMIT && acode != FILTER_DYNAMIC)
        {
          if (ri->attr->mp_nexthop_len == 32)
            {
              p.prefix = ri->attr->mp_nexthop_local;
              acode = access_list_apply (alist, &p);
            }
        }
      return route_map_alist2rmap_rcode (acode);;
    }

  if (IPV6_ADDR_SAME (&ri->attr->mp_nexthop_global, rule))
    return RMAP_MATCH;

  if (ri->attr->mp_nexthop_len == 32 &&
      IPV6_ADDR_SAME (&ri->attr->mp_nexthop_local, rule))
    return RMAP_MATCH;

  return RMAP_NOMATCH;
}

void *
brm_match_ipv6_next_hop_compile (char *arg)
{
  struct pal_in6_addr *address;
  s_int32_t ret;

  if (access_list_reference_validate (arg))
    return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);

  address = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct pal_in6_addr));

  ret = pal_inet_pton (AF_INET6, arg, address);
  if (! ret)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      address = NULL;
    }

  return address;
}

void
brm_match_ipv6_next_hop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd brm_match_ipv6_next_hop_cmd =
{
  "ipv6 next-hop",
  brm_match_ipv6_next_hop,
  brm_match_ipv6_next_hop_compile,
  brm_match_ipv6_next_hop_free
};


/* `match ipv6 address prefix-list PREFIX_LIST' */

route_map_result_t
brm_match_ipv6_address_prefix_list (void *rule, struct prefix *prefix,
                                    struct route_map_rule *type, void *object)
{
  enum prefix_list_type pcode;
  struct bgp_rmap_info *brmi;
  struct prefix_list *plist;

  brmi = (struct bgp_rmap_info *) object;
  pcode = PREFIX_NO_MATCH;

  plist = prefix_list_lookup (BGP_VR.owning_ivr, AFI_IP6, (char *) rule);

  if (! brmi)
    pcode = prefix_list_apply (plist, prefix);
  else switch (brmi->brmi_type)
    {
    case BGP_RMAP_INFO_REGULAR:
      pcode = prefix_list_apply (plist, prefix);
      break;

    case BGP_RMAP_INFO_SYNC_PREFIX:
      pcode = prefix_list_custom_apply (plist,
                                        brm_prefix_synchronize,
                                        object);
      break;
    }

  return route_map_plist2rmap_rcode (pcode);
}

void *
brm_match_ipv6_address_prefix_list_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
brm_match_ipv6_address_prefix_list_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

struct route_map_rule_cmd brm_match_ipv6_address_prefix_list_cmd =
{
  "ipv6 address prefix-list",
  brm_match_ipv6_address_prefix_list,
  brm_match_ipv6_address_prefix_list_compile,
  brm_match_ipv6_address_prefix_list_free
};


/* `set ipv6 nexthop global IP_ADDRESS' */

route_map_result_t
brm_set_ipv6_nexthop_global (void *rule, struct prefix *prefix,
                             struct route_map_rule *type, void *object)
{
  struct pal_in6_addr *address;
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  address = rule;

  /* Set next hop value. */
  ri->attr->mp_nexthop_global = *address;

  /* Set nexthop length. */
  if (! ri->attr->mp_nexthop_len)
    ri->attr->mp_nexthop_len = IPV6_MAX_BYTELEN;

  return RMAP_OKAY;
}

void *
brm_set_ipv6_nexthop_global_compile (char *arg)
{
  struct pal_in6_addr *address;
  s_int32_t ret;

  address = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct pal_in6_addr));

  if (! address)
    return address;

  ret = pal_inet_pton (AF_INET6, arg, address);

  if (! ret)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      address = NULL;
    }

  return address;
}

void
brm_set_ipv6_nexthop_global_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd brm_set_ipv6_nexthop_global_cmd =
{
  "ipv6 next-hop",
  brm_set_ipv6_nexthop_global,
  brm_set_ipv6_nexthop_global_compile,
  brm_set_ipv6_nexthop_global_free
};


/* `set ipv6 nexthop local IP_ADDRESS' */

route_map_result_t
brm_set_ipv6_nexthop_local (void *rule, struct prefix *prefix,
                            struct route_map_rule *type, void *object)
{
  struct pal_in6_addr *address;
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  address = rule;

  /* Set next hop value. */
  ri->attr->mp_nexthop_local = *address;

  /* Set nexthop length. */
  ri->attr->mp_nexthop_len = IPV6_MAX_BYTELEN * 2;

  return RMAP_OKAY;
}

void *
brm_set_ipv6_nexthop_local_compile (char *arg)
{
  int ret;
  struct pal_in6_addr *address;

  address = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct pal_in6_addr));

  ret = pal_inet_pton (AF_INET6, arg, address);

  if (ret == 0)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      return NULL;
    }

  return address;
}

void
brm_set_ipv6_nexthop_local_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Route map commands for ip nexthop set */
struct route_map_rule_cmd brm_set_ipv6_nexthop_local_cmd =
{
  "ipv6 next-hop local",
  brm_set_ipv6_nexthop_local,
  brm_set_ipv6_nexthop_local_compile,
  brm_set_ipv6_nexthop_local_free
};
#endif /* HAVE_IPV6 */


/* `set originator-id' */

route_map_result_t
brm_set_originator_id (void *rule, struct prefix *prefix,
                       struct route_map_rule *type, void *object)
{
  struct pal_in4_addr *address;
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  ri = brmi->brmi_bri;
  address = rule;

  ri->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID);
  ri->attr->originator_id = *address;

  return RMAP_OKAY;
}

void *
brm_set_originator_id_compile (char *arg)
{
  struct pal_in4_addr *address;
  s_int32_t ret;

  address = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct pal_in4_addr));

  if (! address)
    return address;

  ret = pal_inet_pton (AF_INET, arg, address);

  if (! ret)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      address = NULL;
    }

  return address;
}

void
brm_set_originator_id_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Set metric rule structure. */
struct route_map_rule_cmd brm_set_originator_id_cmd =
{
  "originator-id",
  brm_set_originator_id,
  brm_set_originator_id_compile,
  brm_set_originator_id_free,
};


/* `set dampening' */

route_map_result_t
brm_set_damp (void *rule, struct prefix *prefix,
              struct route_map_rule *type, void *object)
{
  struct bgp_rmap_info *brmi;
  struct bgp_info *ri;

  brmi = (struct bgp_rmap_info *) object;

  if (! rule || ! brmi || ! (ri = brmi->brmi_bri) || ! ri->attr)
    return RMAP_ERROR;

  /* 'rule' contains * to 'struct bgp_rfd_cb_cfg_param' */
  ri->attr->rfd_cb_cfg = (struct bgp_rfd_cb_cfg_param *) rule;

  BGP_UNREFERENCED_PARAMETER (prefix);
  BGP_UNREFERENCED_PARAMETER (type);

  return RMAP_OKAY;
}

void *
brm_set_damp_compile (char *arg)
{
  struct bgp_rfd_cb_cfg_param *rfd_cb_cfg;
  s_int32_t ret;

  rfd_cb_cfg = XCALLOC (MTYPE_ROUTE_MAP_COMPILED,
                        sizeof (struct bgp_rfd_cb_cfg_param));
  if (! rfd_cb_cfg)
    return rfd_cb_cfg;

  /* Set the defaults */
  rfd_cb_cfg->rfdc_reach_hlife = BGP_RFD_REACH_HLIFE_DEF_VAL *
                                 ONE_MIN_SECOND;
  rfd_cb_cfg->rfdc_reuse = BGP_RFD_REUSE_DEF_VAL;
  rfd_cb_cfg->rfdc_suppress = BGP_RFD_SUPPRESS_DEF_VAL;
  rfd_cb_cfg->rfdc_max_suppress = BGP_RFD_MAX_SUPPRESS_DEF_VAL *
                                  ONE_MIN_SECOND;
  rfd_cb_cfg->rfdc_unreach_hlife = BGP_RFD_UREACH_HLIFE_DEF_VAL *
                                   ONE_MIN_SECOND;

  if (arg)
    {
      ret = bgp_rfd_str2cfgparams (arg, rfd_cb_cfg);
      if (ret)
        {
          if (BGP_DEBUG (rfd, RFD))
            zlog_info (&BLG, "[DAMP] bgp_route_set_damp_compile():"
                       " Invalid dampening parameters %s", arg);

          if (rfd_cb_cfg)
            {
              XFREE (MTYPE_ROUTE_MAP_COMPILED, rfd_cb_cfg);
              rfd_cb_cfg = NULL;
            }
        }
    }

  return rfd_cb_cfg;
}

void
brm_set_damp_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);

  return;
}

/* Set 'dampening' rule structure. */
struct route_map_rule_cmd brm_set_damp_cmd =
{
  "dampening",
  brm_set_damp,
  brm_set_damp_compile,
  brm_set_damp_free,
};


/* Hook function for updating route_map assignment. */
void
brm_rmap_update (struct ipi_vr *ivr, char *rmap_name)
{
  struct bgp_peer_group *group;
  struct bgp_rfd_cfg *rfd_cfg;
  struct bgp_static *bstatic;
  struct bgp_filter *filter;
  struct listnode *nn, *nm;
  struct bgp_peer *peer;
  u_int8_t *tmp_name;
  struct bgp_node *bn;
  u_int32_t direct;
  struct bgp *bgp;
  u_int32_t baai;
  u_int32_t bsai;
  u_int32_t idx;

  /* Update each peer's route-map in and out.  */
  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    {
      LIST_LOOP (bgp->peer_list, peer, nm)
        {
          for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
            for (bsai = BSAI_UNICAST; bsai < BSAI_MAX ; bsai++)
              {
                filter = &peer->filter[baai][bsai];

                for (direct = FILTER_IN; direct < FILTER_MAX; direct++)
                  {
                    if (filter->map[direct].name)
                      filter->map[direct].map =
                        route_map_lookup_by_name (BGP_VR.owning_ivr,
                                                  filter->map[direct].name);
                    else
                      filter->map[direct].map = NULL;
                  }
                if (filter->usmap.name)
                  filter->usmap.map
                    = route_map_lookup_by_name (BGP_VR.owning_ivr, filter->usmap.name);
                else
                  filter->usmap.map = NULL;
              }
        }
      LIST_LOOP (bgp->group_list, group, nm)
        {
          for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
            for (bsai = BSAI_UNICAST; bsai < BSAI_MAX ; bsai++)
              {
                filter = &group->conf->filter[baai][bsai];

                for (direct = FILTER_IN; direct < FILTER_MAX; direct++)
                  {
                    if (filter->map[direct].name)
                      filter->map[direct].map =
                        route_map_lookup_by_name
                        (BGP_VR.owning_ivr, filter->map[direct].name);
                    else
                      filter->map[direct].map = NULL;
                  }

                if (filter->usmap.name)
                  filter->usmap.map
                    = route_map_lookup_by_name (BGP_VR.owning_ivr, filter->usmap.name);
                else
                  filter->usmap.map = NULL;
              }
        }
    }

  /* For default-originate route-map updates. */
  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    {
      LIST_LOOP (bgp->peer_list, peer, nm)
        {
          for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
            for (bsai = BSAI_UNICAST; bsai < BSAI_MAX ; bsai++)
              {
                if (peer->default_rmap[baai][bsai].name)
                  peer->default_rmap[baai][bsai].map =
                    route_map_lookup_by_name (BGP_VR.owning_ivr,
                                 peer->default_rmap[baai][bsai].name);
                else
                  peer->default_rmap[baai][bsai].map = NULL;
              }
        }
    }

  /* For network route-map updates. */
  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    {
      for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
        for (bsai = BSAI_UNICAST; bsai < BSAI_MAX ; bsai++)
          for (bn = bgp_table_top (bgp->route[baai][bsai]); bn;
               bn = bgp_route_next (bn))
            if ((bstatic = bn->info) != NULL)
              {
                if (bstatic->bs_rmap.name)
                  bstatic->bs_rmap.map =
                    route_map_lookup_by_name (BGP_VR.owning_ivr,
                                              bstatic->bs_rmap.name);
                else
                  bstatic->bs_rmap.map = NULL;
              }
    }

  /* For redistribute route-map updates. */
  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    {
      for (idx = 0; idx < IPI_ROUTE_MAX; idx++)
        {
          if (bgp->rmap [BAAI_IP][idx].name)
            bgp->rmap [BAAI_IP][idx].map =
              route_map_lookup_by_name (BGP_VR.owning_ivr, bgp->rmap [BAAI_IP][idx].name);
#ifdef HAVE_IPV6
          IF_BGP_CAP_HAVE_IPV6
            {
              if (bgp->rmap [BAAI_IP6][idx].name)
                bgp->rmap [BAAI_IP6][idx].map =
                  route_map_lookup_by_name (BGP_VR.owning_ivr, bgp->rmap [BAAI_IP6][idx].name);
            }
#endif /* HAVE_IPV6 */
        }
    }

  /* Update Dampening r-map configuration in all address-families */
  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    {
      for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
        for (bsai = BSAI_UNICAST; bsai < BSAI_MAX ; bsai++)
          {
            rfd_cfg = bgp->rfd_cfg [baai][bsai];
            if (rfd_cfg && rfd_cfg->rfdg_rmap.name)
              {
                tmp_name = XSTRDUP (MTYPE_TMP,
                                    rfd_cfg->rfdg_rmap.name);
                bgp_rfd_cfg_create (bgp, BGP_BAAI2AFI (baai),
                                    BGP_BSAI2SAFI (bsai), NULL,
                                    tmp_name);
                XFREE (MTYPE_TMP, tmp_name);
              }
          }
    }
}

void
brm_route_map_event (struct ipi_vr *vr, route_map_event_t event,
                     char *name)
{

  struct listnode *nn;
  struct bgp *bgp;
  u_int32_t type;

  /* For redistribute route-map updates. */
  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    {
      for (type = 0; type < IPI_ROUTE_MAX; type++)
        {
          if (bgp->redist [BAAI_IP][type]
              && bgp->rmap [BAAI_IP][type].name 
              && pal_strcmp (bgp->rmap[BAAI_IP][type].name, name) == 0)
           {
             bgp->rmap [BAAI_IP][type].map =
               route_map_lookup_by_name (BGP_VR.owning_ivr, 
                                         bgp->rmap [BAAI_IP][type].name);
           }
#ifdef HAVE_IPV6
          IF_BGP_CAP_HAVE_IPV6
            {
              if (bgp->redist [BAAI_IP6][type]
                  && bgp->rmap [BAAI_IP6][type].name
                  && pal_strcmp (bgp->rmap[BAAI_IP6][type].name, name) == 0)
                {
                  bgp->rmap [BAAI_IP6][type].map =
                   route_map_lookup_by_name (BGP_VR.owning_ivr, 
                                             bgp->rmap [BAAI_IP6][type].name);
                }
            } /* IF_BGP_CAP_HAVE_IPV6 */
#endif /* HAVE_IPV6 */
           }  
     } /* LIST_LOOP */
}


s_int32_t
bgp_route_map_init (struct ipi_vr *ivr)
{
  s_int32_t ret;

  ret = 0;

  route_map_add_hook (ivr, brm_rmap_update);
  route_map_delete_hook (ivr, brm_rmap_update);
  route_map_event_hook  (ivr, brm_route_map_event);

  route_map_install_match (ivr, &brm_match_ip_address_cmd);
  route_map_install_match (ivr, &brm_match_ip_next_hop_cmd);
  route_map_install_match (ivr, &brm_match_ip_peer_cmd);
#ifdef HAVE_IPV6
  route_map_install_match (ivr, &brm_match_ipv6_peer_cmd);
#endif /*HAVE_IPV6*/
  route_map_install_match (ivr, &brm_match_ip_address_prefix_list_cmd);
  route_map_install_match (ivr, &brm_match_ip_next_hop_prefix_list_cmd);
  route_map_install_match (ivr, &brm_match_metric_cmd);
  route_map_install_match (ivr, &brm_match_tag_cmd);
  route_map_install_match (ivr, &brm_match_aspath_cmd);
  route_map_install_match (ivr, &brm_match_community_cmd);
  route_map_install_match (ivr, &brm_match_ecommunity_cmd);
  route_map_install_match (ivr, &brm_match_origin_cmd);

  route_map_install_set (ivr, &brm_set_ip_nexthop_cmd);
  route_map_install_set (ivr, &brm_set_ip_peer_cmd);
#ifdef HAVE_IPV6
  route_map_install_set (ivr, &brm_set_ipv6_peer_cmd);
#endif /*HAVE_IPV6*/
  route_map_install_set (ivr, &brm_set_local_pref_cmd);
  route_map_install_set (ivr, &brm_set_weight_cmd);
  route_map_install_set (ivr, &brm_set_metric_cmd);
  route_map_install_set (ivr, &brm_set_aspath_prepend_cmd);
  route_map_install_set (ivr, &brm_set_origin_cmd);
  route_map_install_set (ivr, &brm_set_atomic_aggregate_cmd);
  route_map_install_set (ivr, &brm_set_aggregator_as_cmd);
  route_map_install_set (ivr, &brm_set_community_delete_cmd);
  route_map_install_set (ivr, &brm_set_community_cmd);
  route_map_install_set (ivr, &brm_set_originator_id_cmd);
  route_map_install_set (ivr, &brm_set_ecommunity_rt_cmd);
  route_map_install_set (ivr, &brm_set_ecommunity_soo_cmd);
  route_map_install_set (ivr, &brm_set_damp_cmd);

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      route_map_install_match (ivr, &brm_match_ipv6_address_cmd);
      route_map_install_match (ivr, &brm_match_ipv6_next_hop_cmd);
      route_map_install_match (ivr, &brm_match_ipv6_address_prefix_list_cmd);
      route_map_install_set (ivr, &brm_set_ipv6_nexthop_global_cmd);
      route_map_install_set (ivr, &brm_set_ipv6_nexthop_local_cmd);
    }
#endif /* HAVE_IPV6 */

  return ret;
}
