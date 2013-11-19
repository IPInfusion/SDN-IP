/* Copyright (C) 2003-2011 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

struct message bgp_route_type_msg[] =
{
  { IPI_ROUTE_DEFAULT,  "system" },
  { IPI_ROUTE_KERNEL,   "kernel" },
  { IPI_ROUTE_CONNECT,  "connected" },
  { IPI_ROUTE_STATIC,   "static" },
  { IPI_ROUTE_BGP,      "bgp" },
  { IPI_ROUTE_SDN,      "sdn" },
};

int bgp_route_type_msg_max = IPI_ROUTE_MAX;


/* Utility function function to display route. */
static void
bgp_show_prefix (struct cli *cli, struct prefix *p)
{
  int len = 0;
  u_int32_t destination;

  destination = pal_ntoh32 (p->u.prefix4.s_addr);

  /* When mask is natural, mask is not displayed. */
  if (p->family == AF_INET)
    {
      if ((IN_CLASSC (destination) && p->prefixlen == 24)
          || (IN_CLASSB (destination) && p->prefixlen == 16)
          || (IN_CLASSA (destination) && p->prefixlen == 8))
        len = cli_out (cli, "%r", &p->u.prefix4);
      else
        len = cli_out (cli, "%O", p);
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && p->family == AF_INET6)
    len = cli_out (cli, "%O", p);
#endif /* HAVE_IPV6 */

  /* Prefix area is limited, so when the output is larger than that,
     output newline then format the next place.  */
  len = 17 - len;

  if (len < 1)
    cli_out (cli, "\n                    ");
  else
    cli_out (cli, "%*s", len, " ");
}

void
bgp_show_nexthop (struct cli *cli, struct prefix *p,
                  struct attr *attr, struct bgp_info *ri,
                  safi_t safi)
{
  if (p->family == AF_INET)
    {
      cli_out (cli, "%-16r", &attr->nexthop);
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && p->family == AF_INET6)
    {
      int len = 0;
      if (attr->mp_nexthop_len == IPV6_MAX_BYTELEN)
        len = cli_out (cli, "%R", &attr->mp_nexthop_global);
      else if (attr->mp_nexthop_len == IPV6_MAX_BYTELEN * 2)
        len = cli_out (cli, "%R(%R)",&attr->mp_nexthop_global,
                       &attr->mp_nexthop_local);
      else if (attr->mp_nexthop_len == IPV4_MAX_BYTELEN)
        len = cli_out (cli, "%-16r", &attr->mp_nexthop_global_in);
      else
	 len = cli_out (cli, "%R", &attr->mp_nexthop_global);

      len = 17 - len;

      if (len < 1)
        cli_out (cli, "\n                                     ");
      else
        cli_out (cli, "%*s", len, " ");
    }
#endif /* HAVE_IPV6 */
}

/* Show BGP route in one line.  */
s_int32_t
bgp_show_line (struct cli *cli,
               struct prefix *p,
               struct bgp_info *ri,
               u_int32_t displayed,
               safi_t safi)
{
  char timebuf[BGP_UPTIME_LEN];
  struct attr *attr;
  char flags[5];
  
  pal_mem_set (flags, 0x00, sizeof (flags));

  /* Suppressed or not. */
  if (ri->suppress)
    flags[0] = 's';
  else if (BGP_RFD_RT_STATE_IS_VALID (ri))
    flags[0] = '*';
  else
    flags[0] = ' ';

  /* Selected, flag dampning information.  */
  if (BGP_RFD_RT_STATE_IS_DAMPED (ri))
    flags[1] = 'd';
  else if (BGP_RFD_RT_STATE_IS_HISTORY (ri))
    flags[1] = 'h';
  else if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
    flags[1] = '>';
  else
    flags[1] = ' ';

  /* Internal route. */
  if (ri->peer->as && ri->peer->as == ri->peer->local_as)
    flags[2] = 'i';
  else
    flags[2] = ' ';
  /* Set terminator then output.  */
  flags[4] = '\0';
  cli_out (cli, "%s", flags);

  /* print prefix and mask */
  if (! displayed)
    bgp_show_prefix (cli, p);
  else
    cli_out (cli, "                 ");

  /* Print attribute */
  attr = ri->attr;

  if (attr)
    {
      bgp_show_nexthop (cli, p, attr, ri, safi);

      if (cli->type == bgp_show_type_dampened_paths)
        {
          if (BGP_RFD_RT_STATE_IS_DAMPED (ri))
            {
              cli_out (cli, "      %s",
                       bgp_sec2wdhms_str
                       (BGP_RFD_RT_GET_TIME_TO_REUSE (&BGP_VR, ri),
                        timebuf, BGP_UPTIME_LEN));
              cli_out (cli, " ");
            }
        }
      else if (cli->type == bgp_show_type_flap_statistics)
        {
          if (BGP_RFD_RT_HAS_RECORD (ri))
            {
              cli_out (cli, "%10d ", BGP_RFD_RT_GET_FLAP_COUNT (ri));
              cli_out (cli, " %s ",
                       bgp_time_t2wdhms_str
                       (BGP_RFD_RT_GET_RECORD_DURATION (ri),
                        timebuf, BGP_UPTIME_LEN));
              cli_out (cli, " ");
              if (BGP_RFD_RT_IS_IN_REUSE_LIST (ri))
                cli_out (cli, "%s ",
                         bgp_sec2wdhms_str
                         (BGP_RFD_RT_GET_TIME_TO_REUSE (&BGP_VR, ri),
                          timebuf, BGP_UPTIME_LEN));
              else
                cli_out (cli, "%8s ", "");
              cli_out (cli, " ");
            }
        }
      else
        {
          /* if REMOVE-MED FLAG is enabled, then show "removed" */
          if ((bgp_config_check (ri->peer->bgp, BGP_CFLAG_MED_REMOVE_RCVD))
                  ||(bgp_config_check (ri->peer->bgp, BGP_CFLAG_MED_REMOVE_SEND)))
             cli_out (cli, "removed");
          else
           if (ri->type == IPI_ROUTE_BGP
              && ri->sub_type == BGP_ROUTE_NORMAL)
            cli_out (cli, "%10lu", bgp_med_value (attr, ri->peer->bgp));
          else
            {
              if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
                cli_out (cli, "%10lu", attr->med);
              else
                cli_out (cli, "          ");
            }

          if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
            cli_out (cli, " %6lu", attr->local_pref);
          else
            cli_out (cli, "       ");

          cli_out (cli, " %6lu ", attr->weight);
        }

      /* Print aspath */
#ifndef HAVE_EXT_CAP_ASN
      if (attr->aspath)
        cli_out (cli, "%s", attr->aspath->str);
#else
      if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        {
          if (attr->aspath4B)
            cli_out (cli, "%s", attr->aspath4B->str);
        } 
      else
        {
          if (attr->aspath)
          cli_out (cli, "%s", attr->aspath->str);
        }
#endif /* HAVE_EXT_CAP_ASN */

      /* Print origin */
#ifndef HAVE_EXT_CAP_ASN
      if (pal_strlen (attr->aspath->str) == 0)
        cli_out (cli, "%s", BGP_ORIGIN_STR (attr->origin));
      else
        cli_out (cli, " %s", BGP_ORIGIN_STR (attr->origin));
#else
     if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
       {
         if (attr->aspath4B)
           {  
             if (pal_strlen (attr->aspath4B->str) == 0)
               cli_out (cli, "%s", BGP_ORIGIN_STR (attr->origin));
             else
               cli_out (cli, " %s", BGP_ORIGIN_STR (attr->origin));
           }
       } 
     else
       {
         if (attr->aspath)
           {
             if (pal_strlen (attr->aspath->str) == 0)
               cli_out (cli, "%s", BGP_ORIGIN_STR (attr->origin));
             else
               cli_out (cli, " %s", BGP_ORIGIN_STR (attr->origin));
           }  
       }
#endif /* HAVE_EXT_CAP_ASN */  
   }   
  cli_out (cli, "\n");

  return 0;
}

/* Show BGP route in one line for adjacency information.  */
void
bgp_show_line_adj (struct cli *cli, struct prefix *p,
                   struct bgp_peer *peer, struct attr *attr)
{
  struct bgp_info ri;

  pal_mem_set (&ri, 0, sizeof (struct bgp_info));

  /* Set peer and attribute.  */
  ri.peer = peer;
  ri.attr = attr;

  /* BGP information flag.  */
  ri.suppress = 0;
  ri.flags = 0;
  SET_FLAG (ri.flags, BGP_INFO_SELECTED);

  /* Type is normal.  */
  cli->type = bgp_show_type_normal;

  /* Display route.  */
  bgp_show_line (cli, p, &ri, 0, SAFI_UNICAST);
}

/* Headers.  */
#define BGP_SHOW_HEADER                                                      \
 "   Network          Next Hop            Metric LocPrf Weight Path\n"
#define BGP_SHOW_FLAP_STAT_HEADER                                            \
 "   Network            From                Flaps  Duration  Reuse   Path\n"
#define BGP_SHOW_DAMP_PATH_HEADER                                            \
 "   Network            From                 Reuse   Path\n"

/* Display "show ip bgp" header.  */
void
bgp_show_header (struct cli *cli, struct bgp *bgp, int type,
                 afi_t afi, safi_t safi)
{
  cli_out (cli, "BGP table version is %lu, local router ID is %r\n",
           bgp->table_version [BGP_AFI2BAAI (afi)]
                              [BGP_SAFI2BSAI (safi)],
           &bgp->router_id);
  cli_out (cli, "Status codes: s suppressed, d damped, h history,"
           " * valid, > best, i - internal\n");
  cli_out (cli, "              S Stale\n");
  cli_out (cli, "Origin codes: i - IGP, e - EGP, ? - incomplete\n\n");

  if (type == bgp_show_type_dampened_paths)
    cli_out (cli, BGP_SHOW_DAMP_PATH_HEADER);
  else if (type == bgp_show_type_flap_statistics)
    cli_out (cli, BGP_SHOW_FLAP_STAT_HEADER);
  else
    cli_out (cli, BGP_SHOW_HEADER);

  return;
}

/* Look up value for each type.  */
static void *
bgp_show_val (int type, char *arg, afi_t afi)
{
  switch (type)
    {
    case bgp_show_type_prefix_list:
      return prefix_list_lookup (BGP_VR.owning_ivr, afi, arg);
      break;

    case bgp_show_type_filter_list:
      return as_list_lookup (arg);
      break;

    case bgp_show_type_route_map:
      return route_map_lookup_by_name (BGP_VR.owning_ivr, arg);
      break;

    case bgp_show_type_community_list:
    case bgp_show_type_community_list_exact:
      return community_list_lookup (bgp_clist, arg, COMMUNITY_LIST_AUTO);
      break;

    default:
      break;
    }
  return NULL;
}

/* When "show ip bgp" for the BGP information is suppressed return 1. */
static int
bgp_show_filter (struct bgp_node *rn, struct bgp_info *ri,
                 int type, void *arg, void *val)
{
 struct prefix rnp;

  BGP_GET_PREFIX_FROM_NODE (rn);

  switch (type)
    {
    case bgp_show_type_regexp:
      {
        pal_regex_t *regex = arg;

#ifndef HAVE_EXT_CAP_ASN
        if (bgp_regexec (regex, ri->attr->aspath) == REG_NOMATCH)
          return 1;
#else
        if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
          {
            if (bgp_regexec_aspath4B (regex, ri->attr->aspath4B) == REG_NOMATCH) 
             return 1;
          }
        else if (bgp_regexec (regex, ri->attr->aspath) == REG_NOMATCH)
          return 1;    
#endif /* HAVE_EXT_CAP_ASN */
      } 
      break;

    case bgp_show_type_prefix_list:
      {
        struct prefix_list *plist = val;
        if (prefix_list_apply (plist, &rnp) != PREFIX_PERMIT)
          return 1;
      }
      break;

    case bgp_show_type_filter_list:
      {
        struct as_list *as_list = val;
#ifdef HAVE_EXT_CAP_ASN
        if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
          {
            if (as_list_apply (as_list, ri->attr->aspath4B) != AS_FILTER_PERMIT)
              return 1;
          }
        else
          {
#endif /* HAVE_EXT_CAP_ASN */
            if (as_list_apply (as_list, ri->attr->aspath) != AS_FILTER_PERMIT)
              return 1;
#ifdef HAVE_EXT_CAP_ASN 
          }
#endif /* HAVE_EXT_CAP_ASN */
      }
      break;

    case bgp_show_type_route_map:
      {
        struct bgp_rmap_info brmi;
        struct route_map *rmap;
        route_map_result_t ret;
        struct bgp_info binfo;
        struct attr attr;

        if (! val)
          return 1;

        attr = *ri->attr;
        rmap = val;

        binfo.peer = ri->peer;
        binfo.attr = &attr;

        pal_mem_set (&brmi, 0, sizeof (struct bgp_rmap_info));
        brmi.brmi_type = BGP_RMAP_INFO_REGULAR;
        brmi.brmi_bgp = ri->peer->bgp;
        brmi.brmi_bri = &binfo;

        ret = route_map_apply (rmap, &rnp, &brmi);

        bgp_attr_flush (&attr);

        if (ret == RMAP_DENYMATCH)
          return 1;
      }
      break;

    case bgp_show_type_neighbor:
      {
        union sockunion *su = arg;

        if (ri->peer->su_remote == NULL
            || ! sockunion_same(ri->peer->su_remote, su))
          return 1;
      }
      break;

    case bgp_show_type_cidr_only:
      {
        u_int32_t destination;

        destination = pal_ntoh32 (rnp.u.prefix4.s_addr);
        if (IN_CLASSC (destination) && rnp.prefixlen == 24)
          return 1;
        if (IN_CLASSB (destination) && rnp.prefixlen == 16)
          return 1;
        if (IN_CLASSA (destination) && rnp.prefixlen == 8)
          return 1;
      }
      break;

    case bgp_show_type_prefix_longer:
      {
        struct prefix *p = arg;

        if (! prefix_match (p, &rnp))
          return 1;
      }
      break;

    case bgp_show_type_community_all:
      {
        if (! ri->attr->community)
          return 1;
      }
      break;

    case bgp_show_type_community:
      {
        struct community *com = arg;

        if (! ri->attr->community
            || ! community_match (ri->attr->community, com))
          return 1;
      }
      break;

    case bgp_show_type_community_exact:
      {
        struct community *com = arg;

        if (! ri->attr->community
            || ! community_cmp (ri->attr->community, com))
          return 1;
      }
      break;

    case bgp_show_type_community_list:
      {
        struct community_list *list = val;

        if (community_list_match (ri->attr->community, list)
            != COMMUNITY_PERMIT)
          return 1;
      }
      break;

    case bgp_show_type_community_list_exact:
      {
        struct community_list *list = val;

        if (community_list_exact_match (ri->attr->community, list)
            != COMMUNITY_PERMIT)
          return 1;
      }
      break;

    case bgp_show_type_dampened_paths:
      {
        if (! BGP_RFD_RT_STATE_IS_DAMPED (ri))
          return 1;
      }
      break;

    case bgp_show_type_flap_statistics:
      {
        if (! BGP_RFD_RT_HAS_RECORD (ri))
          return 1;
      }
      break;


    default:
      break;
    }

  return 0;
}

/* "show ip bgp" main function.  This function is called two way.
   First time this function is called from each CLI definition through
   bgp_show_cli().  After that, this function register myself as
   callback function.  So after that this function is called from
   event manager.  */
int
bgp_show_callback (struct cli *cli)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  int header = 0;
  int count = 0;
  int displayed;
  void *val;
  struct prefix rnp;

  /* Fetch current node.  */
  rn = cli->current;

  /* "show" connection is closed. */
  if (cli->status == CLI_CLOSE)
    goto cleanup;

  /* This is first time.  */
  if (cli->status == CLI_NORMAL)
    {
      header = 1;
      cli->count = 0;
    }

  /* Look up argument.  Between callback access-list, community-list
     and route-map may be changed.  So we just keep the value in
     the atomic area.  */
  val = bgp_show_val (cli->type, cli->arg, cli->afi);

  /* Walk BGP table.  */
  for (; rn; rn = bgp_route_next (rn))
   {
      if (rn->info != NULL)
      {
        /* When more than two BGP routes exists for on prefix, only
           first one's prefix should be displayed.  */
        displayed = 0;

        /* Inconsistent AS special check.  */
        if (cli->type == bgp_show_type_inconsistent_as)
          {
            as_t as;
            int inconsistent = 0;

            /* First BGP information.  */
            ri = rn->info;

            /* When this is only one BGP information, skip this
               prefix.  */
            if (! ri->next)
              continue;

            /* Fetch AS path.  */
#ifndef HAVE_EXT_CAP_ASN
            as = aspath_origin (ri->attr->aspath);

            /* Check AS consistency for all of other BGP
               information.  */
            for (ri = ri->next; ri; ri = ri->next)
              {
                if (as != aspath_origin (ri->attr->aspath))
                  {
                    inconsistent = 1;
                    break;
                  }
              }
#else
           if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
             {
               as = as4path_origin (ri->attr->aspath4B);

               /* Check AS consistency for all of other BGP
                 information.  */
               for (ri = ri->next; ri; ri = ri->next)
                 {
                   if (as != as4path_origin (ri->attr->aspath4B))
                     {
                       inconsistent = 1;
                       break;
                     }
                 }
             }
          else
            {
              as = aspath_origin (ri->attr->aspath);

               /* Check AS consistency for all of other BGP
                 information.  */
               for (ri = ri->next; ri; ri = ri->next)
                 {
                   if (as != aspath_origin (ri->attr->aspath))
                     {
                       inconsistent = 1;
                       break;
                     }
                 }
             }       
#endif /* HAVE_EXT_CAP_ASN */
            /* When AS path is not inconsistent (consistent), go to
               next prefix.  */
            if (! inconsistent)
              continue;
          }

        /* Check BGP information.  */
        for (ri = rn->info; ri; ri = ri->next)
          {
            /* Inactive redistribute routes should not be shown */
            if (ri->type != IPI_ROUTE_BGP
                && ! CHECK_FLAG (ri->flags, BGP_INFO_NHOP_VALID))
              continue;

            /* Default route is internal and should not be shown */
            if (ri->type == IPI_ROUTE_BGP
                && ri->sub_type == BGP_ROUTE_DEFAULT)
              continue;

            /* "show ip bgp" optional filtering.  */
            if (bgp_show_filter (rn, ri, cli->type, cli->arg, val))
              continue;

            /* Header treatment.  */
            if (header)
              {
                bgp_show_header (cli, cli->index, cli->type, cli->afi,
                                 cli->safi);
                header = 0;
              }

            /* Display BGP route.  */
            BGP_GET_PREFIX_FROM_NODE (rn);
            bgp_show_line (cli, &rnp, ri, displayed, cli->safi);

            /* Update displayed count.  */
            displayed++;
          }

        if (displayed)
          {
            cli->count++;
            count++;
          }

        /* Remember current pointer then suspend output. */
        if (count >= 25)
          {
            cli->status = CLI_CONTINUE;
            cli->current = bgp_route_next (rn);
            cli->callback = bgp_show_callback;
            return 0;
          }
      } 
   } /* End of Wk BGP */
  /* Total count display. */
  if (cli->count)
    cli_out (cli, "\nTotal number of prefixes %ld\n", cli->count);
  else
    {
      if (cli->type == bgp_show_type_normal)
        cli_out (cli, "\n");
      if (cli->type == bgp_show_type_dampened_paths)
        cli_out (cli, "No BGP dampened prefix exists\n");
      if (cli->type == bgp_show_type_flap_statistics)
        cli_out (cli, "No BGP flapped prefix exists\n");
    }

  /* Clean up.  */
 cleanup:

  /* Unlock the node.  */
  if (rn)
    bgp_unlock_node (rn);

  /* Call clean up routine.  */
  if (cli->cleanup)
    {
      (*cli->cleanup) (cli);
      cli->cleanup = NULL;
      cli->arg = NULL;
    }

  /* Set NULL to callback pointer.  */
  cli->status = CLI_CONTINUE;
  cli->callback = NULL;

  return 0;
}


/* CLI function wrapper for "show ip bgp".  */
int
bgp_show_cli (struct cli *cli, char *name, afi_t afi, safi_t safi,
              enum bgp_show_type type)
{
  struct bgp *bgp;

  if (name)
    {
      /* When name is specified use name to lookup BGP instance */
      bgp = bgp_lookup_by_name (name);
      if (! bgp)
        {
          cli_out (cli, "%% Can't find BGP view %s\n", name);
          return CLI_ERROR;
        }
    }
  else
    {
      /* Otherwise lookup default BGP instance.  */
      bgp = bgp_lookup_default ();
      if (! bgp)
        return CLI_ERROR;
    }

  /*
   * Put BGP structure to cli->index so that it can retrieved
   * when within invoked functions
   */
  cli->index = bgp;

  /* Set top node to current pointer in CLI structure.  */
  cli->afi = afi;
  cli->safi = safi;
  cli->current = bgp_table_top (bgp->rib [BGP_AFI2BAAI (afi)]
                                         [BGP_SAFI2BSAI (safi)]);
  cli->type = type;

  /* Call display function.  */
  bgp_show_callback (cli);

  return 0;
}

/* CLI function wrapper for "show [ip] bgp dampening parameters" */
int
bgp_show_rfd_config (struct cli *cli, char *view_name,
                     afi_t afi, safi_t safi)
{
  struct bgp *bgp;

  if (view_name)
    {
      /* When view name is specified use it to lookup BGP instance */
      bgp = bgp_lookup_by_name (view_name);
      if (! bgp)
        {
          cli_out (cli, "%% Can't find BGP view %s\n", view_name);
          return CLI_ERROR;
        }
    }
  else
    {
      /* Otherwise lookpu default BGP instance.  */
      bgp = bgp_lookup_default ();
      if (! bgp)
        return CLI_ERROR;
    }

  /* Call display function.  */
  bgp_rfd_config_show (cli, bgp, afi, safi);

  return 0;
}

void
ecommunity_cli_out (struct cli *cli, struct ecommunity *ecom)
{
  int i,j;
  u_int8_t *pnt;
  struct ecommunity_as eas;
  struct ecommunity_ip eip;
  struct ecomm_ospf_did eosid;
  struct ecomm_ospf_rtype eos_rtype;
  struct ecomm_ospf_rid eos_rid;
  int encode = 0;
  int type = 0;


  for (i = 0; i < ecom->size; i++)
    {
      pal_mem_set (&eas, 0, sizeof (struct ecommunity_as));
      pal_mem_set (&eip, 0, sizeof (struct ecommunity_ip));

      pnt = ecom->val + (i * 8);

      /* High-order octet of type. */
      if (*pnt == ECOMMUNITY_ENCODE_AS)
        encode = ECOMMUNITY_ENCODE_AS;
      else if (*pnt == ECOMMUNITY_ENCODE_IP)
        encode = ECOMMUNITY_ENCODE_IP;
      else if (*pnt == ECOMMUNITY_ENCODE_AS4)
        encode = ECOMMUNITY_ENCODE_AS4;
      else if (*pnt == ECOMMUNITY_OPAQUE)
        encode = ECOMMUNITY_OPAQUE;
      else if (*pnt == ECOMMUNITY_IANA_BIT)
        encode = ECOMMUNITY_IANA_BIT;
      pnt++;

      /* Low-order octet of type. */
      if (*pnt == ECOMMUNITY_ROUTE_TARGET)
        {
          if (type != ECOMMUNITY_ROUTE_TARGET)
            cli_out (cli, " RT:");
          type = ECOMMUNITY_ROUTE_TARGET;
        }
      else if (*pnt == ECOMMUNITY_SITE_ORIGIN)
        {
          if (type != ECOMMUNITY_SITE_ORIGIN)
            cli_out (cli, " SOO:");
          type = ECOMMUNITY_SITE_ORIGIN;
        }
      else if (*pnt == ECOMMUNITY_OSPF_DOMAIN_ID)
        {
	  if (type != ECOMMUNITY_OSPF_DOMAIN_ID)
            cli_out (cli, " OSPF-Domain-ID:");
          type = ECOMMUNITY_OSPF_DOMAIN_ID;
        }
      else if (*pnt == ECOMMUNITY_OSPF_ROUTE_TYPE)
        {
          if (type != ECOMMUNITY_OSPF_ROUTE_TYPE)
            cli_out (cli, " OSPF-Route-type:");
          type = ECOMMUNITY_OSPF_ROUTE_TYPE;
        }
      else if (*pnt == ECOMMUNITY_OSPF_ROUTER_ID)
        {
          if (type != ECOMMUNITY_OSPF_ROUTER_ID)
            cli_out (cli, " OSPF-Router-ID:");
          type = ECOMMUNITY_OSPF_ROUTER_ID;
        }
      pnt++;

      if (((encode == ECOMMUNITY_ENCODE_AS)
          || (encode == ECOMMUNITY_ENCODE_AS4)
          || (encode == ECOMMUNITY_IANA_BIT))
          && (type == ECOMMUNITY_OSPF_DOMAIN_ID))
        {
          eosid.type = encode;
          eosid.subtype = type;

          for (j =0;j<6;j++)
           {
             eosid.did[j]= *pnt;
             pnt++;
           }
          cli_out (cli, "0x0%x0%x : %#x%x%x%x%x%x ", eosid.type, eosid.subtype,
                        eosid.did[0],eosid.did[1],eosid.did[2],
                        eosid.did[3],eosid.did[4],eosid.did[5]);
        }
      else if (encode == ECOMMUNITY_ENCODE_AS)
        {
          eas.as = (*pnt++ << 8);
          eas.as |= (*pnt++);

          eas.val = (*pnt++ << 24);
          eas.val |= (*pnt++ << 16);
          eas.val |= (*pnt++ << 8);
          eas.val |= (*pnt++);

          cli_out (cli, "%u:%lu ", eas.as, eas.val);
        }
      else if (encode == ECOMMUNITY_ENCODE_AS4)
        {
          eas.as = (*pnt++ << 24);
          eas.as |= (*pnt++ << 16);
          eas.as |= (*pnt++ << 8);
          eas.as |= (*pnt++);

          eas.val |= (*pnt++ << 8);
          eas.val |= (*pnt++);

          cli_out (cli, "%u:%lu ", eas.as, eas.val);
        }
      else if (encode == ECOMMUNITY_OPAQUE)
        {
          if (type == ECOMMUNITY_OSPF_ROUTE_TYPE)
            {
              pal_mem_cpy (&eos_rtype.area_id, pnt, 4);
              pnt += 4;
              eos_rtype.rtype = (*pnt++);
              eos_rtype.option = (*pnt++);

              cli_out (cli, "%r :%d:%d \n",&eos_rtype.area_id,
                             eos_rtype.rtype, eos_rtype.option);
            }
          else
            {
              cli_out (cli, "%#x ", (*pnt++ << 24));
              cli_out (cli, "%#x ", (*pnt++ << 16));
              cli_out (cli, "%#x ", (*pnt++ << 8));
              cli_out (cli, "%#x ", (*pnt++));
              cli_out (cli, "%#x ", (*pnt++ << 8));
              cli_out (cli, "%#x ", (*pnt++));
            }
        }
      else if (encode == ECOMMUNITY_ENCODE_IP)
        {
         if(type == ECOMMUNITY_OSPF_DOMAIN_ID)
           {
             eosid.type = encode;
             eosid.subtype = type;

             for(j=0; j<6; j++)
              {
                eosid.did[j] = *pnt;
                pnt++;
              }
             cli_out (cli, "0x0%x0%x : %#x%x%x%x%x%x", eosid.type, eosid.subtype,
                       eosid.did[0],eosid.did[1],eosid.did[2],
                       eosid.did[3],eosid.did[4],eosid.did[5]);
           }
         else if (type == ECOMMUNITY_OSPF_ROUTER_ID)
           {
             pal_mem_cpy (&eos_rid.router_id, pnt, 4);
             cli_out (cli, "%r", &eos_rid.router_id);
           }
         else
           {
             pal_mem_cpy (&eip.ip, pnt, 4);
             pnt += 4;
             eip.val = (*pnt++ << 8);
             eip.val |= (*pnt++);

             cli_out (cli, "%r:%u ", &eip.ip, eip.val);
           }
        }
    }
}

void
route_vty_out_detail (struct cli *cli,
                      struct prefix *p,
                      struct bgp_info *ri,
                      afi_t afi, safi_t safi)
{
  char timebuf[BGP_UPTIME_LEN];
  char buf[INET6_ADDRSTRLEN];
  struct attr *attr;
  struct bgp *bgp;
  char buf1[BUFSIZ];
  /* int sockunion_vty_out (struct vty *, union sockunion *); */

  bgp = ri->peer->bgp;
  attr = ri->attr;

  if (bgp == NULL)
    return;

  if (attr)
    {
      /* Line1 display AS-path, Aggregator */
#ifndef HAVE_EXT_CAP_ASN
      if (attr->aspath)
        {
          cli_out (cli, "  ");
          if (attr->aspath->length == 0)
            cli_out (cli, "Local");
          else
            cli_out (cli, "%s", attr->aspath->str);
        }
#else
      if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        {
          if (attr->aspath4B)
            {
              cli_out (cli, "  ");
              if (attr->aspath4B->length == 0)
                cli_out (cli, "Local");
              else
                cli_out (cli, "%s", attr->aspath4B->str);
            }
        }
       else if (attr->aspath)
         {
           cli_out (cli, "  ");
           if (attr->aspath->length == 0)
             cli_out (cli, "Local");
           else
             cli_out (cli, "%s", attr->aspath->str);
         }
#endif /* HAVE_EXT_CAP_ASN */

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)
          || CHECK_FLAG (ri->peer->af_flags [BGP_AFI2BAAI (afi)]
                                            [BGP_SAFI2BSAI (safi)],
                          PEER_FLAG_REFLECTOR_CLIENT)
          || BGP_RFD_RT_STATE_IS_HISTORY (ri)
          || BGP_RFD_RT_STATE_IS_DAMPED (ri))
        {
          cli_out (cli, ",");
#ifndef HAVE_EXT_CAP_ASN
          if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))
            cli_out (cli, " (aggregated by %d %r)",
                     attr->aggregator_as, &attr->aggregator_addr);
#else
          if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))
            {
              if (! CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
                 cli_out (cli, " (aggregated by %d %r)",
                          attr->aggregator_as, &attr->aggregator_addr);
              else 
                 cli_out (cli, " (aggregated by %u %r)",
                          attr->aggregator_as4, &attr->aggregator_addr);
            }
#endif /* HAVE_EXT_CAP_ASN */

          if (CHECK_FLAG (ri->peer->af_flags [BGP_AFI2BAAI (afi)]
                                             [BGP_SAFI2BSAI (safi)],
                          PEER_FLAG_REFLECTOR_CLIENT))
            cli_out (cli, " (Received from a RR-client)");
          if (BGP_RFD_RT_STATE_IS_DAMPED (ri))
            cli_out (cli, " (suppressed due to dampening)");
          if (BGP_RFD_RT_STATE_IS_HISTORY (ri))
            cli_out (cli, " (history entry)");
        }
      cli_out (cli, "\n");

      /* Line2 display Next-hop, Neighbor, Router-id */
      if (p->family == AF_INET)
        {
          cli_out (cli, "    %r", &attr->nexthop);
        }
#ifdef HAVE_IPV6
      else if (BGP_CAP_HAVE_IPV6 && p->family == AF_INET6)
        {
	  if (attr->mp_nexthop_len == 16)
            cli_out (cli, "    %R", &attr->mp_nexthop_global);
          else if (attr->mp_nexthop_len == 32)
            cli_out (cli, "    %R(%R)",&attr->mp_nexthop_global,
                     &attr->mp_nexthop_local);
        }
#endif /* HAVE_IPV6 */

      if (ri->peer == bgp->peer_self)
        {
          cli_out (cli, " from %s ",
                   p->family == AF_INET ? "0.0.0.0" : "::");
          cli_out (cli, "(%r)", &bgp->router_id);
        }
      else
        {
          if (! CHECK_FLAG (ri->flags, BGP_INFO_NHOP_VALID))
            cli_out (cli, " (inaccessible)");
          else if (ri->igpmetric)
            cli_out (cli, " (metric %lu)", ri->igpmetric);
          cli_out (cli, " from %s", sockunion2str (&ri->peer->su, buf, SU_ADDRSTRLEN));
          cli_out (cli, " (%r)", &ri->peer->remote_id);
        }
      cli_out (cli, "\n");

#ifdef HAVE_IPV6
      IF_BGP_CAP_HAVE_IPV6
        {
          /* display nexthop local */
          if (attr->mp_nexthop_len == 32)
            cli_out (cli, "    (%R)\n", &attr->mp_nexthop_local);
        }
#endif /* HAVE_IPV6 */

       /* Line 3 display Local Attributes and Status Information */
      cli_out (cli, "      Origin %s", BGP_ORIGIN_LONG_STR (attr->origin));

      /* if REMOVE-MED FLAG is enabled, then show "removed" */
      if (bgp_config_check (ri->peer->bgp, BGP_CFLAG_MED_REMOVE_RCVD) 
            || bgp_config_check (ri->peer->bgp, BGP_CFLAG_MED_REMOVE_SEND))
        cli_out (cli, "removed");
      else
      if (ri->type == IPI_ROUTE_BGP
          && ri->sub_type == BGP_ROUTE_NORMAL)
        cli_out (cli, " metric %lu", bgp_med_value (attr, ri->peer->bgp));
      else
        {
          if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
            cli_out (cli, " metric %lu", attr->med);
        }

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
        cli_out (cli, ", localpref %lu", attr->local_pref);
      else
        cli_out (cli, ", localpref %lu", bgp->default_local_pref);

      if (attr->weight != 0)
        cli_out (cli, ", weight %lu", attr->weight);

      if (BGP_RFD_RT_STATE_IS_VALID (ri))
        cli_out (cli, ", valid");

      if (ri->peer != bgp->peer_self)
        {
          if (ri->peer->as == ri->peer->local_as)
            cli_out (cli, ", internal");
          else
            cli_out (cli, ", %s",
                     (bgp_confederation_peers_check(bgp, ri->peer->as) ?
                     "confed-external" : "external"));
        }
      else if (ri->sub_type == BGP_ROUTE_AGGREGATE)
        cli_out (cli, ", aggregated, local");
      else if (ri->type != IPI_ROUTE_BGP)
        cli_out (cli, ", sourced");
      else
        cli_out (cli, ", sourced, local");

      if (CHECK_FLAG(ri->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE))
	cli_out (cli, ", multipath-candidate");
      if (CHECK_FLAG(ri->flags_misc, BGP_INFO_MULTI_INSTALLED))
	cli_out (cli, ", installed"); 
      if (CHECK_FLAG (ri->flags, BGP_INFO_SYNCHRONIZED))
        cli_out (cli, ", synchronized");
      else if (CHECK_FLAG (ri->flags, BGP_INFO_UNSYNCHRONIZED))
        cli_out (cli, ", not synchronized");

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
        cli_out (cli, ", atomic-aggregate");

      if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
        cli_out (cli, ", best");

      cli_out (cli, "\n");

      /* Line 4 display Community */
      if (attr->community)
        cli_out (cli, "      Community: %s\n", community_str (attr->community));

      /* Line 5 display Extended-community */
      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))
        {
          cli_out (cli, "      Extended Community:");
          ecommunity_cli_out (cli, attr->ecommunity);
          cli_out (cli, "\n");
        }

      /* Line 6 display Originator, Cluster-id */
      if ((attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)) &&
          (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST)))
        {
          cli_out (cli, "      Originator: %r", &attr->originator_id);

          int i;

          cli_out (cli, ", Cluster list: ");
          for (i = 0; i < attr->cluster->length / 4; i++)
            cli_out (cli, "%r ", &attr->cluster->list[i]);
          cli_out (cli, "\n");
        }

      /* Line 7 display BGP dampened information if have. */
      if (BGP_RFD_RT_HAS_RECORD (ri))
        {
          cli_out (cli, "      Dampinfo: penalty %d, flapped %d times in %s",
                   BGP_RFD_RT_GET_PENALTY (ri),
                   BGP_RFD_RT_GET_FLAP_COUNT (ri),
                   bgp_time_t2wdhms_str (BGP_RFD_RT_GET_RECORD_DURATION (ri),
                                       timebuf, BGP_UPTIME_LEN));

          if (BGP_RFD_RT_IS_IN_REUSE_LIST (ri))
            cli_out (cli, ", reuse in %s",
                     bgp_sec2wdhms_str
                     (BGP_RFD_RT_GET_TIME_TO_REUSE (&BGP_VR, ri),
                      timebuf, BGP_UPTIME_LEN));

          cli_out (cli, "\n");
        }

      pal_time_calendar (&ri->bri_uptime, buf1);

      /* Line 8 display Uptime */
      cli_out (cli, "      Last update: %s", buf1);
    }
  cli_out (cli, "\n");
}


/* Display specified route of BGP table. */
int
bgp_show_route (struct cli *cli, char *view_name, char *ip_str,
                afi_t afi, safi_t safi, int prefix_check)
{
  int ret;
  int count = 0;
  int best = 0;
  int suppress = 0;
  int no_export = 0;
  int no_advertise = 0;
  int local_as = 0;
  char buf[INET6_ADDRSTRLEN];
  struct bgp *bgp;
  struct prefix match;
  struct prefix *p;
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_peer *peer;
  struct bgp_peer_group *group;
  struct listnode *nn;
  struct listnode  *nm;
  bool_t nonpeer;
  bool_t peergroup;
  struct prefix rnp;

  nonpeer = PAL_FALSE;
  peergroup = PAL_FALSE;

  pal_mem_set (&match, 0, sizeof (struct prefix));
  /* BGP structure lookup. */
  if (view_name)
    {
      /* When name is specified use name to lookup BGP instance */
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
        {
          cli_out (cli, "Can't find BGP view %s\n", view_name);
          return CLI_ERROR;
        }
    }
  else
    {
      bgp = bgp_lookup_default ();

      if (bgp == NULL)
        {
          cli_out (cli, "No BGP process is configured\n");
          return CLI_ERROR;
        }
    }

  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      cli_out (cli, "address is malformed\n");
      return CLI_ERROR;
    }

  match.family = afi2family (afi);

  /* Lookup route node. */
  rn = bgp_node_match (bgp->rib [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)],
                       &match);
  if (rn == NULL)
    {
      cli_out (cli, "%% Network not in table\n");
      return CLI_ERROR;
    }
  BGP_GET_PREFIX_FROM_NODE (rn);
  p = &rnp;
  if (prefix_check)
    {
      if (p->prefixlen != match.prefixlen)
        {
          cli_out (cli, "%% Network not in table\n");
          return CLI_ERROR;
        }
    }

  /* Header of detailed BGP route information */
  for (ri = rn->info; ri; ri = ri->next)
    {
      count++;
      if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
        {
          best = count;
          if (ri->suppress)
            suppress = 1;
          if (ri->attr->community != NULL)
            {
              if (community_include (ri->attr->community, COMMUNITY_NO_ADVERTISE))
                no_advertise = 1;
              if (community_include (ri->attr->community, COMMUNITY_NO_EXPORT))
                no_export = 1;
              if (community_include (ri->attr->community, COMMUNITY_LOCAL_AS))
                local_as = 1;
            }
        }
    }
  cli_out (cli, "BGP routing table entry for %O\n", p);

  cli_out (cli, "Paths: (%d available", count);
  if (best)
    {
      cli_out (cli, ", best #%d", best);
      cli_out (cli, ", table Default-IP-Routing-Table");
    }
  else
    cli_out (cli, ", no best path");
  if (no_advertise)
    cli_out (cli, ", not advertised to any peer");
  else if (no_export)
    cli_out (cli, ", not advertised to EBGP peer");
  else if (local_as)
    cli_out (cli, ", not advertised outside local AS");
  if (suppress)
    cli_out (cli, ", Advertisements suppressed by an aggregate.");
  cli_out (cli, ")\n");

  /* advertised non peer-group peers */
  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      if (! CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
        if (bgp_adj_out_lookup (peer, rn))
          {
            if (! nonpeer)
              {
                cli_out (cli, "  Advertised to non peer-group peers:\n");
                cli_out (cli, " ");
              }
            cli_out (cli, " %s", sockunion2str (&peer->su, buf, SU_ADDRSTRLEN));
            nonpeer = PAL_TRUE;
          }
    }

  /* advertised peer-groups */
  LIST_LOOP (bgp->group_list, group, nm)
    {
      LIST_LOOP (group->peer_list, peer, nn)
        {
          if (bgp_adj_out_lookup (peer, rn))
            {
              if (! peergroup)
                {
                  if (nonpeer)
                    cli_out (cli, "\n");
                  cli_out (cli, "  Advertised to peer-groups:\n");
                  cli_out (cli, " ");
                }
              cli_out (cli, " %s", group->name);
              peergroup = PAL_TRUE;
              break;
            }
        }
    }
  if (! nonpeer && ! peergroup)
    cli_out (cli, "  Not advertised to any peer");
  cli_out (cli, "\n");

  for (ri = rn->info; ri; ri = ri->next)
    route_vty_out_detail (cli, &rnp, ri, afi, safi);

  bgp_unlock_node (rn);

  return CLI_SUCCESS;
}

/* "show ip bgp"  */

CLI (show_ip_bgp,
     show_ip_bgp_cli,
     "show ip bgp",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR)
{
  return bgp_show_cli (cli, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_normal);
}

CLI (show_ip_bgp_safi,
     show_ip_bgp_safi_cli,
     "show ip bgp ipv4 (unicast|multicast)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR)
{
  return bgp_show_cli (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]),
                       bgp_show_type_normal);
}

/* "show ip bgp A.B.C.D"  */

CLI (show_ip_bgp_route,
     show_ip_bgp_route_cli,
     "show ip bgp A.B.C.D",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "IP prefix <network>, e.g., 35.0.0.0")
{
  return bgp_show_route (cli, NULL, argv[0], AFI_IP, SAFI_UNICAST, 0);
}

CLI (show_ip_bgp_safi_route,
     show_ip_bgp_safi_route_cli,
     "show ip bgp ipv4 (unicast|multicast) A.B.C.D",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "IP prefix <network>, e.g., 35.0.0.0")
{
  return bgp_show_route (cli, NULL, argv[1],
                         AFI_IP, bgp_cli_str2safi (argv[0]), 0);
}

/* "show ip bgp A.B.C.D/M"  */

CLI (show_ip_bgp_prefix,
     show_ip_bgp_prefix_cli,
     "show ip bgp A.B.C.D/M",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8")
{
  return bgp_show_route (cli, NULL, argv[0], AFI_IP, SAFI_UNICAST, 1);
}

CLI (show_ip_bgp_safi_prefix,
     show_ip_bgp_safi_prefix_cli,
     "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8")
{
  return bgp_show_route (cli, NULL, argv[1],
                         AFI_IP, bgp_cli_str2safi (argv[0]), 1);
}

CLI (show_ip_bgp_view,
     show_ip_bgp_view_cli,
     "show ip bgp view WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "BGP view name")
{
  return bgp_show_cli (cli, argv[0], AFI_IP, SAFI_UNICAST, bgp_show_type_normal);
}

CLI (show_ip_bgp_view_route,
     show_ip_bgp_view_route_cli,
     "show ip bgp view WORD A.B.C.D",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "BGP view name",
     "Network in the BGP routing table to display")
{
  return bgp_show_route (cli, argv[0], argv[1], AFI_IP, SAFI_UNICAST, 0);
}

CLI (show_ip_bgp_view_prefix,
     show_ip_bgp_view_prefix_cli,
     "show ip bgp view WORD A.B.C.D/M",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "BGP view name",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8")
{
  return bgp_show_route (cli, argv[0], argv[1], AFI_IP, SAFI_UNICAST, 1);
}

#ifdef HAVE_IPV6
/* IPv6 "show bgp" commands.  */
CLI (show_bgp,
     show_bgp_cli,
     "show bgp",
     CLI_SHOW_STR,
     CLI_BGP_STR)
{
  return bgp_show_cli (cli, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal);
}

ALI (show_bgp,
     show_bgp_ipv6_cli,
     "show bgp (ipv6)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_AF_STR);

CLI (show_bgp_afi_safi,
     show_bgp_afi_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR)
{
  return bgp_show_cli (cli, NULL,
                       bgp_cli_str2afi (argv[0]), bgp_cli_str2safi (argv[1]),
                       bgp_show_type_normal);
}

/* "show bgp X:X::X:X" */
CLI (show_bgp_route,
     show_bgp_route_cli,
     "show bgp X:X::X:X",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "IPv6 prefix <network>, e.g. 2003::")
{
  if (argc == 1)
    return bgp_show_route (cli, NULL, argv[0], AFI_IP6, SAFI_UNICAST, 0);
  else
    return bgp_show_route (cli, NULL, argv[1], AFI_IP6, SAFI_UNICAST, 0);
}

ALI (show_bgp_route,
     show_bgp_ipv6_route_cli,
     "show bgp (ipv6) X:X::X:X",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "IPv6 prefix <network>, e.g. 2003::");

CLI (show_bgp_ipv6_route_safi,
     show_bgp_ipv6_route_safi_cli,
     "show bgp (ipv6) (unicast|multicast) X:X::X:X",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "IPv6 prefix <network>, e.g. 2003::")
{
  return bgp_show_route (cli, NULL, argv[2],
                         AFI_IP6, bgp_cli_str2safi (argv[1]), 0);
}

CLI (show_bgp_ipv4_route_safi,
     show_bgp_ipv4_route_safi_cli,
     "show bgp (ipv4) (unicast|multicast) A.B.C.D",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "IP prefix <network>, e.g., 35.0.0.0")
{
  return bgp_show_route (cli, NULL, argv[2],
                         AFI_IP, bgp_cli_str2safi (argv[1]), 0);
}

/* "show bgp X:X::X:X/M" */
CLI (show_bgp_prefix,
     show_bgp_prefix_cli,
     "show bgp X:X::X:X/M",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "IPv6 prefix <network>/<length>, e.g., 2003::/16")
{
  if (argc == 1)
    return bgp_show_route (cli, NULL, argv[0], AFI_IP6, SAFI_UNICAST, 1);
  else
    return bgp_show_route (cli, NULL, argv[1], AFI_IP6, SAFI_UNICAST, 1);
}

CLI (show_bgp_ipv6_prefix_safi,
     show_bgp_ipv6_prefix_safi_cli,
     "show bgp (ipv6) (unicast|multicast|) X:X::X:X/M",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "IPv6 prefix <network>/<length>, e.g., 2003::/16")
{
  if (argc == 2)
    return bgp_show_route (cli, NULL, argv[1],
                         AFI_IP6, SAFI_UNICAST, 1);
  else
    return bgp_show_route (cli, NULL, argv[2],
                         AFI_IP6, bgp_cli_str2safi (argv[1]), 1);
}

CLI (show_bgp_ipv4_prefix_safi,
     show_bgp_ipv4_prefix_safi_cli,
     "show bgp (ipv4) (unicast|multicast) A.B.C.D/M",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8")
{
  return bgp_show_route (cli, NULL, argv[2],
                         AFI_IP, bgp_cli_str2safi (argv[1]), 1);
}

CLI (show_bgp_ipv6_view,
     show_bgp_ipv6_view_cli,
     "show bgp ipv6 view WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "BGP view",
     "BGP view name")
{
  return bgp_show_cli (cli, argv[1], AFI_IP6, SAFI_UNICAST, bgp_show_type_normal);
}
#endif /* HAVE_IPV6*/

/* "show ip bgp regexp" and "show ip bgp quote-regexp"  */
static int
bgp_show_regexp_clean (struct cli *cli)
{
  bgp_regex_free (cli->arg);
  cli->arg = NULL;
  return 0;
}

static int
bgp_show_regexp (struct cli *cli, char *regstr, afi_t afi, safi_t safi)
{
  pal_regex_t *regex;

  regex = bgp_regcomp (regstr);
  if (! regex)
    {
      cli_out (cli, "%% Can't compile regexp %s\n", regstr);
      return CLI_ERROR;
    }
  cli->arg = regex;
  cli->cleanup = bgp_show_regexp_clean;

  return bgp_show_cli (cli, NULL, afi, safi, bgp_show_type_regexp);
}

static int
bgp_show_quote_regexp (struct cli *cli, char *regstr, afi_t afi, safi_t safi)
{
  pal_regex_t *regex;
  int len;

  if (regstr[0] == '"')
    regstr++;

  len = pal_strlen (regstr) - 1;
  if (regstr[len] == '"')
    regstr[len] = '\0';

  regex = bgp_regcomp (regstr);
  if (! regex)
    {
      cli_out (cli, "%% Can't compile regexp %s\n", regstr);
      return CLI_ERROR;
    }
  cli->arg = regex;
  cli->cleanup = bgp_show_regexp_clean;

  return bgp_show_cli (cli, NULL, afi, safi, bgp_show_type_regexp);
}

CLI (show_ip_bgp_regexp,
     show_ip_bgp_regexp_cli,
     "show ip bgp regexp LINE",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Display routes matching the AS path regular expression",
     "A regular-expression to match the BGP AS paths")
{
  return bgp_show_regexp (cli, argv[0], AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_safi_regexp,
     show_ip_bgp_safi_regexp_cli,
     "show ip bgp ipv4 (unicast|multicast) regexp LINE",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the AS path regular expression",
     "A regular-expression to match the BGP AS paths")
{
  return bgp_show_regexp (cli, argv[1], AFI_IP, bgp_cli_str2safi (argv[0]));
}

#ifdef HAVE_IPV6
CLI (show_bgp_regexp,
     show_bgp_regexp_cli,
     "show bgp regexp LINE",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display routes matching the AS path regular expression",
     "A regular-expression to match the BGP AS paths")
{
  if (argc == 1)
    return bgp_show_regexp (cli, argv[0], AFI_IP6, SAFI_UNICAST);
  else
    return bgp_show_regexp (cli, argv[1], AFI_IP6, SAFI_UNICAST);
}

ALI (show_bgp_regexp,
     show_bgp_ipv6_regexp_cli,
     "show bgp (ipv6) regexp LINE",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     "Display routes matching the AS path regular expression",
     "A regular-expression to match the BGP AS paths");

CLI (show_bgp_afi_regexp_safi,
     show_bgp_afi_regexp_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast) regexp LINE",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the AS path regular expression",
     "A regular-expression to match the BGP AS paths")
{
  return bgp_show_regexp (cli, argv[2],
                          bgp_cli_str2afi (argv[0]), bgp_cli_str2safi (argv[1]));
}
#endif /* HAVE_IPV6 */

CLI (show_ip_bgp_quote_regexp,
     show_ip_bgp_quote_regexp_cli,
     "show ip bgp quote-regexp WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Display routes matching the AS path \"regular expression\"",
     "A regular-expression to match the BGP AS paths")
{
  return bgp_show_quote_regexp (cli, argv[0], AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_safi_quote_regexp,
     show_ip_bgp_safi_quote_regexp_cli,
     "show ip bgp ipv4 (unicast|multicast) quote-regexp WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the AS path \"regular expression\"",
     "A regular-expression to match the BGP AS paths")
{
  return bgp_show_quote_regexp (cli, argv[1], AFI_IP, bgp_cli_str2safi (argv[0]));
}

#ifdef HAVE_IPV6
CLI (show_bgp_quote_regexp,
     show_bgp_quote_regexp_cli,
     "show bgp quote-regexp WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display routes matching the AS path \"regular expression\"",
     "A regular-expression to match the BGP AS paths")
{
  if (argc == 1)
    return bgp_show_quote_regexp (cli, argv[0], AFI_IP6, SAFI_UNICAST);
  else
    return bgp_show_quote_regexp (cli, argv[1], AFI_IP6, SAFI_UNICAST);
}

CLI (show_bgp_afi_quote_regexp_safi,
     show_bgp_afi_quote_regexp_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast|) quote-regexp WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the AS path \"regular expression\"",
     "A regular-expression to match the BGP AS paths")
{
  if (argc == 2)
    return bgp_show_quote_regexp (cli, argv[1],
                                  bgp_cli_str2afi (argv[0]),
                                  SAFI_UNICAST);
  else
    return bgp_show_quote_regexp (cli, argv[2],
                                  bgp_cli_str2afi (argv[0]),
                                  bgp_cli_str2safi (argv[1]));
}
#endif /* HAVE_IPV6 */

static int
bgp_show_prefix_list_clean (struct cli *cli)
{
  XFREE (MTYPE_TMP, cli->arg);
  cli->arg = NULL;
  return 0;
}

int
bgp_show_prefix_list (struct cli *cli, char *prefix_list_str, u_int16_t afi,
                      u_int8_t safi)
{
  cli->arg = XSTRDUP (MTYPE_TMP, prefix_list_str);
  cli->cleanup = bgp_show_prefix_list_clean;

  return bgp_show_cli (cli, NULL, afi, safi, bgp_show_type_prefix_list);
}

CLI (show_ip_bgp_prefix_list,
     show_ip_bgp_prefix_list_cli,
     "show ip bgp prefix-list WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Display routes matching the prefix-list",
     "IP prefix-list name")
{
  return bgp_show_prefix_list (cli, argv[0], AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_safi_prefix_list,
     show_ip_bgp_safi_prefix_list_cli,
     "show ip bgp ipv4 (unicast|multicast) prefix-list WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the prefix-list",
     "IP prefix-list name")
{
  return bgp_show_prefix_list (cli, argv[1], AFI_IP, bgp_cli_str2safi (argv[0]));
}

#ifdef HAVE_IPV6
CLI (show_bgp_prefix_list,
     show_bgp_prefix_list_cli,
     "show bgp prefix-list WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display routes matching the prefix-list",
     "IPv6 prefix-list name")
{
  if (argc == 1)
    return bgp_show_prefix_list (cli, argv[0], AFI_IP6, SAFI_UNICAST);
  else
    return bgp_show_prefix_list (cli, argv[1], AFI_IP6, SAFI_UNICAST);
}

CLI (show_bgp_afi_prefix_list_safi,
     show_bgp_afi_prefix_list_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast|) prefix-list WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the prefix-list",
     "IPv6 prefix-list name")
{
  if (argc == 2)
    return bgp_show_prefix_list (cli, argv[1],
                                 bgp_cli_str2afi (argv[0]),
                                 SAFI_UNICAST);
  else
    return bgp_show_prefix_list (cli, argv[2],
                                 bgp_cli_str2afi (argv[0]),
                                 bgp_cli_str2safi (argv[1]));
}
#endif /* HAVE_IPV6 */

static int
bgp_show_filter_list_clean (struct cli *cli)
{
  XFREE (MTYPE_TMP, cli->arg);
  cli->arg = NULL;
  return 0;
}

int
bgp_show_filter_list (struct cli *cli, char *filter, u_int16_t afi,
                      u_int8_t safi)
{
  cli->arg = XSTRDUP (MTYPE_TMP, filter);
  cli->cleanup = bgp_show_filter_list_clean;

  return bgp_show_cli (cli, NULL, afi, safi, bgp_show_type_filter_list);
}

CLI (show_ip_bgp_filter_list,
     show_ip_bgp_filter_list_cli,
     "show ip bgp filter-list WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Display routes conforming to the filter-list",
     "Regular expression access list name")
{
  return bgp_show_filter_list (cli, argv[0], AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_safi_filter_list,
     show_ip_bgp_safi_filter_list_cli,
     "show ip bgp ipv4 (unicast|multicast) filter-list WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes conforming to the filter-list",
     "Regular expression access list name")
{
  return bgp_show_filter_list (cli, argv[1], AFI_IP, bgp_cli_str2safi (argv[0]));
}

#ifdef HAVE_IPV6
CLI (show_bgp_filter_list,
     show_bgp_filter_list_cli,
     "show bgp filter-list WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display routes conforming to the filter-list",
     "Regular expression access list name")
{
  if (argc == 1)
    return bgp_show_filter_list (cli, argv[0], AFI_IP6, SAFI_UNICAST);
  else
    return bgp_show_filter_list (cli, argv[1], AFI_IP6, SAFI_UNICAST);
}

ALI (show_bgp_filter_list,
     show_bgp_ipv6_filter_list_cli,
     "show bgp (ipv6) filter-list WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Display routes conforming to the filter-list",
     "Regular expression access list name");

CLI (show_bgp_afi_filter_list_safi,
     show_bgp_afi_filter_list_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast) filter-list WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes conforming to the filter-list",
     "Regular expression access list name")
{
  return bgp_show_filter_list (cli, argv[2],
                               bgp_cli_str2afi (argv[0]),
                               bgp_cli_str2safi (argv[1]));
}
#endif /* HAVE_IPV6 */

CLI (show_ip_bgp_cidr_only,
     show_ip_bgp_cidr_only_cli,
     "show ip bgp cidr-only",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Display only routes with non-natural netmasks")
{
  return bgp_show_cli (cli, NULL, AFI_IP, SAFI_UNICAST,
                       bgp_show_type_cidr_only);
}

CLI (show_ip_bgp_safi_cidr_only,
     show_ip_bgp_safi_cidr_only_cli,
     "show ip bgp ipv4 (unicast|multicast) cidr-only",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display only routes with non-natural netmasks")
{
  return bgp_show_cli (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]),
                       bgp_show_type_cidr_only);
}

/* "show ip bgp community"  */

CLI (show_ip_bgp_community,
     show_ip_bgp_community_cli,
     "show ip bgp community",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Display routes matching the communities")
{
  return bgp_show_cli (cli, NULL, AFI_IP, SAFI_UNICAST,
                       bgp_show_type_community_all);
}

CLI (show_ip_bgp_safi_community,
     show_ip_bgp_safi_community_cli,
     "show ip bgp ipv4 (unicast|multicast) community",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the communities")
{
  return bgp_show_cli (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]),
                       bgp_show_type_community_all);
}

#ifdef HAVE_IPV6
CLI (show_bgp_community,
     show_bgp_community_cli,
     "show bgp community",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display routes matching the communities")
{
  return bgp_show_cli (cli, NULL, AFI_IP6, SAFI_UNICAST,
                       bgp_show_type_community_all);
}

ALI (show_bgp_community,
     show_bgp_ipv6_community_cli,
     "show bgp (ipv6) community",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Display routes matching the communities");

CLI (show_bgp_afi_community_safi,
     show_bgp_afi_community_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast) community",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the communities")
{
  return bgp_show_cli (cli, NULL,
                       bgp_cli_str2afi (argv[0]), bgp_cli_str2safi (argv[1]),
                       bgp_show_type_community_all);
}
#endif /* HAVE_IPV6 */

/* "show ip bgp community AA:NN (exact-match|)"  */

static int
bgp_show_community_clean (struct cli *cli)
{
  community_free (cli->arg);
  cli->arg = NULL;
  return 0;
}

int
bgp_show_community (struct cli *cli, int argc, char **argv,
                    afi_t afi, safi_t safi)
{
  int type;
  struct community *com = NULL;
  char *comstr = NULL;

  /* Exact match check. */
  if (pal_strncmp ("exact-match",
                   argv[argc - 1], pal_strlen (argv[argc - 1])) == 0)
    {
      type = bgp_show_type_community_exact;
      argc--;
      argv[argc] = NULL;
    }
  else
    type = bgp_show_type_community;

  /* Compile community string.  */
  comstr = argv_concat (argv, argc, 0);
  if (comstr)
    {
      com = community_str2com (comstr);
      XFREE (MTYPE_TMP, comstr);
    }

  if (! com)
    {
      cli_out (cli, "%% Malformed community value\n");
      return CLI_ERROR;
    }

  cli->arg = com;
  cli->cleanup = bgp_show_community_clean;

  return bgp_show_cli (cli, NULL, afi, safi, type);
}

CLI (show_ip_bgp_community_val,
     show_ip_bgp_community_val_cli,
     "show ip bgp community [AA:NN|local-AS|no-advertise|no-export] (exact-match|)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Display routes matching the communities",
     "community number",
     "Do not send outside local AS (well-known community)",
     "Do not advertise to any peer (well-known community)",
     "Do not export to next AS (well-known community)",
     "Exact match of the communities")
{
  return bgp_show_community (cli, argc, argv, AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_safi_community_val,
     show_ip_bgp_safi_community_val_cli,
     "show ip bgp ipv4 (unicast|multicast) community [AA:NN|local-AS|no-advertise|no-export] (exact-match|)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the communities",
     "community number",
     "Do not send outside local AS (well-known community)",
     "Do not advertise to any peer (well-known community)",
     "Do not export to next AS (well-known community)",
     "Exact match of the communities")
{
  safi_t safi;

  safi = bgp_cli_str2safi (argv[0]);
  argc--;
  argv++;

  return bgp_show_community (cli, argc, argv, AFI_IP, safi);
}

#ifdef HAVE_IPV6
CLI (show_bgp_community_val,
     show_bgp_community_val_cli,
     "show bgp community [AA:NN|local-AS|no-advertise|no-export] (exact-match|)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display routes matching the communities",
     "community number",
     "Do not send outside local AS (well-known community)",
     "Do not advertise to any peer (well-known community)",
     "Do not export to next AS (well-known community)",
     "Exact match of the communities")
{
  if (pal_strncmp ("ipv6", argv[0], 4) == 0)
    {
      argc--;
      argv++;
    }
  return bgp_show_community (cli, argc, argv, AFI_IP6, SAFI_UNICAST);
}

ALI (show_bgp_community_val,
     show_bgp_ipv6_community_val_cli,
     "show bgp (ipv6) community [AA:NN|local-AS|no-advertise|no-export] (exact-match|)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Display routes matching the communities",
     "community number",
     "Do not send outside local AS (well-known community)",
     "Do not advertise to any peer (well-known community)",
     "Do not export to next AS (well-known community)",
     "Exact match of the communities");

CLI (show_bgp_afi_community_val_safi,
     show_bgp_afi_community_val_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast) community [AA:NN|local-AS|no-advertise|no-export] (exact-match|)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the communities",
     "community number",
     "Do not send outside local AS (well-known community)",
     "Do not advertise to any peer (well-known community)",
     "Do not export to next AS (well-known community)",
     "Exact match of the communities")
{
  afi_t afi;
  safi_t safi;

  afi = bgp_cli_str2afi (argv[0]);
  argc--;
  argv++;

  safi = bgp_cli_str2safi (argv[0]);
  argc--;
  argv++;

  return bgp_show_community (cli, argc, argv, afi, safi);
}
#endif /* HAVE_IPV6 */

/* "show ip bgp community-list"  */

static int
bgp_show_community_list_clean (struct cli *cli)
{
  XFREE (MTYPE_TMP, cli->arg);
  cli->arg = NULL;
  return 0;
}

int
bgp_show_community_list (struct cli *cli, char *com, int exact,
                         afi_t afi, safi_t safi)
{
  int type;

  if (exact)
    type = bgp_show_type_community_list_exact;
  else
    type = bgp_show_type_community_list;

  cli->arg = XSTRDUP (MTYPE_TMP, com);
  cli->cleanup = bgp_show_community_list_clean;

  return bgp_show_cli (cli, NULL, afi, safi, type);
}

CLI (show_ip_bgp_community_list,
     show_ip_bgp_community_list_cli,
     "show ip bgp community-list WORD (exact-match|)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Display routes matching the community-list",
     "community-list name",
     "Exact match of the communities")
{
  int exact;

  if (argc == 2)
    exact = 1;
  else
    exact = 0;

  return bgp_show_community_list (cli, argv[0], exact, AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_safi_community_list,
     show_ip_bgp_safi_community_list_cli,
     "show ip bgp ipv4 (unicast|multicast) community-list WORD (exact-match|)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the community-list",
     "community-list name",
     "Exact match of the communities")
{
  int exact;

  if (argc == 3)
    exact = 1;
  else
    exact = 0;

  return bgp_show_community_list (cli, argv[1], exact,
                                  AFI_IP, bgp_cli_str2safi (argv[0]));
}

#ifdef HAVE_IPV6
CLI (show_bgp_community_list,
     show_bgp_community_list_cli,
     "show bgp community-list WORD (exact-match|)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display routes matching the community-list",
     "community-list name",
     "Exact match of the communities")
{
  int exact;

  if (pal_strncmp ("ipv6", argv[0], 4) == 0)
    {
      argc--;
      argv++;
    }
  if (argc == 2)
    exact = 1;
  else
    exact = 0;

  return bgp_show_community_list (cli, argv[0], exact, AFI_IP6, SAFI_UNICAST);
}

ALI (show_bgp_community_list,
     show_bgp_ipv6_community_list_cli,
     "show bgp (ipv6) community-list WORD (exact-match|)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Display routes matching the community-list",
     "community-list name",
     "Exact match of the communities");

CLI (show_bgp_afi_community_list_safi,
     show_bgp_afi_community_list_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast) community-list WORD (exact-match|)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the community-list",
     "community-list name",
     "Exact match of the communities")
{
  int exact;

  if (argc == 4)
    exact = 1;
  else
    exact = 0;

  return bgp_show_community_list (cli, argv[2], exact,
                                  bgp_cli_str2afi (argv[0]),
                                  bgp_cli_str2safi (argv[1]));
}
#endif /* HAVE_IPV6 */

int
bgp_show_prefix_longer_clean (struct cli *cli)
{
  struct prefix *p;

  p = cli->arg;
  prefix_free (p);
  return 0;
}

int
bgp_show_prefix_longer (struct cli *cli, char *prefix, u_int16_t afi,
                        u_int8_t safi)
{
  int ret;
  struct prefix *p;

  p = prefix_new();

  ret = str2prefix (prefix, p);
  if (! ret)
    {
      cli_out (cli, "%% Malformed Prefix\n");
      prefix_free (p);
      return CLI_ERROR;
    }

  cli->arg = p;
  cli->cleanup = bgp_show_prefix_longer_clean;

  return bgp_show_cli (cli, NULL, afi, safi, bgp_show_type_prefix_longer);
}

CLI (show_ip_bgp_prefix_longer,
     show_ip_bgp_prefix_longer_cli,
     "show ip bgp A.B.C.D/M longer-prefixes",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8",
     "Display route and more specific routes")
{
  return bgp_show_prefix_longer (cli, argv[0], AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_safi_prefix_longer,
     show_ip_bgp_safi_prefix_longer_cli,
     "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M longer-prefixes",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8",
     "Display route and more specific routes")
{
  return bgp_show_prefix_longer (cli, argv[1], AFI_IP, bgp_cli_str2safi (argv[0]));
}

#ifdef HAVE_IPV6
CLI (show_bgp_prefix_longer,
     show_bgp_prefix_longer_cli,
     "show bgp X:X::X:X/M longer-prefixes",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "IPv6 prefix <network>/<length>, e.g., 2003::/16",
     "Display route and more specific routes")
{
  if (argc == 1)
    return bgp_show_prefix_longer (cli, argv[0], AFI_IP6, SAFI_UNICAST);
  else
    return bgp_show_prefix_longer (cli, argv[1], AFI_IP6, SAFI_UNICAST);
}

CLI (show_bgp_ipv6_prefix_longer_safi,
     show_bgp_ipv6_prefix_longer_safi_cli,
     "show bgp (ipv6) (unicast|multicast|)" 
     " X:X::X:X/M longer-prefixes",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "IPv6 prefix <network>/<length>, e.g., 2003::/16",
     "Display route and more specific routes")
{
  if (argc == 2)
    return bgp_show_prefix_longer (cli, argv[1],
                                   AFI_IP6, SAFI_UNICAST);
  else
    return bgp_show_prefix_longer (cli, argv[2],
                                   AFI_IP6, bgp_cli_str2safi (argv[1]));
}

CLI (show_bgp_ipv4_prefix_longer_safi,
     show_bgp_ipv4_prefix_longer_safi_cli,
     "show bgp (ipv4) (unicast|multicast) A.B.C.D/M longer-prefixes",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8",
     "Display route and more specific routes")
{
  return bgp_show_prefix_longer (cli, argv[2],
                                 AFI_IP, bgp_cli_str2safi (argv[1]));
}
#endif /* HAVE_IPV6 */

static void
bgp_show_adj_route (struct cli *cli,
                    struct bgp_peer *peer,
                    afi_t afi, safi_t safi,
                    int in)
{
  struct bgp_ptree *table;
  struct bgp_adj_in *ain;
  struct bgp_adj_out *aout;
  struct bgp_adj_out *aouts;
  u_int32_t output_count;
  struct bgp_node *rn;
  struct bgp_node *rns;
  int header1 = 1;
  struct bgp *bgp;
  int header2 = 1;
  struct prefix rnp;
  struct prefix rnps;
  u_int32_t src_addr = PAL_FALSE;
  u_int32_t src_addr1 = PAL_FALSE;
  u_int32_t duplicate_flag = PAL_FALSE;


  bgp = peer->bgp;

  if (bgp == NULL)
    return;

  if (!in && bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
    {
      cli_out (cli, "Adj-out is disabled - unable to show advertised routes\n");
      return;
    }  

  table = bgp->rib[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  output_count = 0;

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    if (in)
      {
        for (ain = rn->adj_in; ain; ain = ain->next)
          if (ain->peer == peer)
            {
              if (header1)
                {
                  cli_out (cli, "BGP table version is %lu,"
                           " local router ID is %r\n",
                           bgp->table_version [BGP_AFI2BAAI (afi)]
                                              [BGP_SAFI2BSAI (safi)],
                           &bgp->router_id);
                  cli_out (cli, "Status codes: s suppressed, d damped,"
                           " h history, * valid, > best, i - internal\n");
                  cli_out (cli, "Origin codes: i - IGP, e - EGP,"
                           " ? - incomplete\n\n");
                  header1 = 0;
                }
              if (header2)
                {
                  cli_out (cli, BGP_SHOW_HEADER);
                  header2 = 0;
                }

              if (ain->attr)
                {
                  BGP_GET_PREFIX_FROM_NODE (rn);
                  bgp_show_line_adj (cli, &rnp, peer, ain->attr);
                  output_count++;
                }
            }
      }
    else
      {
        for (aout = rn->adj_out; aout; aout = aout->next)
          if (aout->peer == peer)
            {
              if (header1)
                {
                  cli_out (cli, "BGP table version is %lu,"
                           " local router ID is %r\n",
                           bgp->table_version [BGP_AFI2BAAI (afi)]
                                              [BGP_SAFI2BSAI (safi)],
                           &bgp->router_id);
                  cli_out (cli, "Status codes: s suppressed, d damped,"
                           " h history, * valid, > best, i - internal\n");
                  cli_out (cli, "Origin codes: i - IGP, e - EGP,"
                           " ? - incomplete\n\n");
                  header1 = 0;
                }

              if (header2)
                {
                  cli_out (cli, BGP_SHOW_HEADER);
                  header2 = 0;

                }
              if (aout->attr)
                {
                  BGP_GET_PREFIX_FROM_NODE (rn);
                  if (bgp_af_config_check (bgp, afi, safi, BGP_AF_CFLAG_AUTO_SUMMARY))
                    {
                      src_addr = pal_ntoh32 (rnp.u.prefix4.s_addr);
                      BGP_SET_PREFIX_LEN (src_addr, rnp.prefixlen);

                      rnp.u.prefix4.s_addr = pal_ntoh32 (src_addr);
                      duplicate_flag = PAL_FALSE;
                      /* Check if there are duplicate routes in the table after auto-summary,
                         if so, they need not be displayed again and must be skipped */
                      for (rns = bgp_table_top (table); rns && rns != rn; rns = bgp_route_next (rns))
                        {
                          for (aouts = rns->adj_out; aouts; aouts = aouts->next)
                            {
                              if (aouts->peer == peer)
                                {
                                  bgp_ptree_get_prefix_from_node (rns, &rnps);
                                  src_addr1 = pal_ntoh32 (rnps.u.prefix4.s_addr);
                                  BGP_SET_PREFIX_LEN (src_addr1, rnps.prefixlen);

                                  if (src_addr1 == src_addr && rnp.prefixlen == rnps.prefixlen)
                                    duplicate_flag = PAL_TRUE;
                                }
                            } /* for aouts */
                          if (duplicate_flag)
                            break;
                        } /* for rns */
                      if (!duplicate_flag)
                        {
                          bgp_show_line_adj (cli, &rnp, peer, aout->attr);
                          output_count++;
                        }
                    }
                  else
                    {
                      /* No auto-summary */
                      bgp_show_line_adj (cli, &rnp, peer, aout->attr);
                      output_count++;
                    }
                }
            }
      }
  if (output_count != 0)
    cli_out (cli, "\nTotal number of prefixes %ld\n", output_count);
}

int
peer_adj_routes (struct cli *cli, char *ip_str, afi_t afi, safi_t safi, int in)
{
  int ret;
  struct bgp_peer *peer;
  union sockunion su;

  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      cli_out (cli, "Malformed address: %s\n", ip_str);
      return CLI_ERROR;
    }
  peer = bgp_peer_search (NULL, &su);
  if (! peer || ! peer->afc[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    {
      cli_out (cli, "%% No such neighbor or address family\n");
      return CLI_ERROR;
    }

  if (in && ! CHECK_FLAG (peer->af_flags[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)], PEER_FLAG_SOFT_RECONFIG))
    {
      cli_out (cli, "%% Inbound soft reconfiguration not enabled\n");
      return CLI_ERROR;
    }

  bgp_show_adj_route (cli, peer, afi, safi, in);

  return CLI_SUCCESS;
}

CLI (show_ip_bgp_neighbor_advertised_route,
     show_ip_bgp_neighbor_advertised_route_cli,
     "show ip bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display the routes advertised to a BGP neighbor")
{
  return peer_adj_routes (cli, argv[0], AFI_IP, SAFI_UNICAST, 0);
}

CLI (show_ip_bgp_safi_neighbor_advertised_route,
     show_ip_bgp_safi_neighbor_advertised_route_cli,
     "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) advertised-routes",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display the routes advertised to a BGP neighbor")
{
  return peer_adj_routes (cli, argv[1], AFI_IP, bgp_cli_str2safi (argv[0]), 0);
}

#ifdef HAVE_IPV6
CLI (show_bgp_neighbor_advertised_route,
     show_bgp_neighbor_advertised_route_cli,
     "show bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display the routes advertised to a BGP neighbor")
{
  if (argc == 1)
    return peer_adj_routes (cli, argv[0], AFI_IP6, SAFI_UNICAST, 0);
  else
    return peer_adj_routes (cli, argv[1], AFI_IP6, SAFI_UNICAST, 0);
}

CLI (show_bgp_afi_neighbor_advertised_route_safi,
     show_bgp_afi_neighbor_advertised_route_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast|) neighbors (A.B.C.D|X:X::X:X) advertised-routes",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display the routes advertised to a BGP neighbor")
{
  if (argc == 2)
    return peer_adj_routes (cli, argv[1], bgp_cli_str2afi (argv[0]),
                            SAFI_UNICAST, 0);
  else
    return peer_adj_routes (cli, argv[2], bgp_cli_str2afi (argv[0]),
                          bgp_cli_str2safi (argv[1]), 0);
}
#endif /* HAVE_IPV6 */

CLI (show_ip_bgp_neighbor_received_routes,
     show_ip_bgp_neighbor_received_routes_cli,
     "show ip bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display the received routes from neighbor")
{
  return peer_adj_routes (cli, argv[0], AFI_IP, SAFI_UNICAST, 1);
}

CLI (show_ip_bgp_safi_neighbor_received_routes,
     show_ip_bgp_safi_neighbor_received_routes_cli,
     "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) received-routes",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display the received routes from neighbor")
{
  return peer_adj_routes (cli, argv[1], AFI_IP, bgp_cli_str2safi (argv[0]), 1);
}

CLI (show_ip_bgp_neighbor_received_prefix_filter,
     show_ip_bgp_neighbor_received_prefix_filter_cli,
     "show ip bgp neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display information received from a BGP neighbor",
     "Display the prefixlist filter")
{
  struct bgp_peer *peer;
  union sockunion *su;
  char name[BUFSIZ];
  int count;

  su = sockunion_str2su (argv[0]);
  if (! su)
    return CLI_ERROR;

  peer = bgp_peer_search (NULL, su);
  if (! peer)
    {
      sockunion_free (su);
      return CLI_ERROR;
    }

  pal_snprintf (name, BUFSIZ,"%s.%d.%d", peer->host, AFI_IP, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (BGP_VR.owning_ivr, NULL, AFI_IP, name);
  if (count)
    {
      cli_out (cli, "Address family: IPv4 Unicast\n");
      prefix_bgp_show_prefix_list (BGP_VR.owning_ivr, cli, AFI_IP, name);
    }

  sockunion_free (su);
  return CLI_SUCCESS;
}

CLI (show_ip_bgp_safi_neighbor_received_prefix_filter,
     show_ip_bgp_safi_neighbor_received_prefix_filter_cli,
     "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display information received from a BGP neighbor",
     "Display the prefixlist filter")
{
  struct bgp_peer *peer;
  union sockunion *su;
  char name[BUFSIZ];
  int count;

  su = sockunion_str2su (argv[1]);
  if (! su)
    return CLI_ERROR;

  peer = bgp_peer_search (NULL, su);
  if (! peer)
    {
      sockunion_free (su);
      return CLI_ERROR;
    }

  if (bgp_cli_str2safi (argv[0]) == SAFI_MULTICAST)
    {
      pal_snprintf (name, BUFSIZ, "%s.%d.%d", peer->host, AFI_IP, SAFI_MULTICAST);
      count =  prefix_bgp_show_prefix_list (BGP_VR.owning_ivr, NULL, AFI_IP, name);
      if (count)
        {
          cli_out (cli, "Address family: IPv4 Multicast\n");
          prefix_bgp_show_prefix_list (BGP_VR.owning_ivr, cli, AFI_IP, name);
        }
    }
  else
    {
      pal_snprintf (name, BUFSIZ,"%s.%d.%d", peer->host, AFI_IP, SAFI_UNICAST);
      count =  prefix_bgp_show_prefix_list (BGP_VR.owning_ivr, NULL, AFI_IP, name);
      if (count)
        {
          cli_out (cli, "Address family: IPv4 Unicast\n");
          prefix_bgp_show_prefix_list (BGP_VR.owning_ivr, cli, AFI_IP, name);
        }
    }

  sockunion_free (su);
  return CLI_SUCCESS;
}


#ifdef HAVE_IPV6
int
bgp_show_prefix_filter (struct cli *cli, char *ip_str,
                        afi_t afi, safi_t safi)
{
  struct bgp_peer *peer;
  union sockunion su;
  char name[BUFSIZ];
  int count;
  int ret;

  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      cli_out (cli, "Malformed address: %s\n", ip_str);
      return CLI_ERROR;
    }
  peer = bgp_peer_search (NULL, &su);
  if (! peer || ! peer->afc[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    {
      cli_out (cli, "%% No such neighbor or address family\n");
      return CLI_ERROR;
    }

  pal_snprintf (name, BUFSIZ, "%s.%d.%d", peer->host, afi, safi);

  count =  prefix_bgp_show_prefix_list (BGP_VR.owning_ivr, NULL, afi, name);
  if (count)
    {
      cli_out (cli, "Address family: %s %s\n",
               afi == AFI_IP ? "IPv4" : "IPv6",
               safi == SAFI_UNICAST ? "Unicast" : "Multicast");
      prefix_bgp_show_prefix_list (BGP_VR.owning_ivr, cli, afi, name);
    }
  return CLI_SUCCESS;
}

CLI (show_bgp_neighbor_received_prefix_filter,
     show_bgp_neighbor_received_prefix_filter_cli,
     "show bgp neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display information received from a BGP neighbor",
     "Display the prefixlist filter")
{
  if (argc == 1)
    return bgp_show_prefix_filter (cli, argv[0], AFI_IP6, SAFI_UNICAST);
  else
    return bgp_show_prefix_filter (cli, argv[1], AFI_IP6, SAFI_UNICAST);
}

CLI (show_bgp_afi_neighbor_received_prefix_filter_safi,
     show_bgp_afi_neighbor_received_prefix_filter_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast|) neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display information received from a BGP neighbor",
     "Display the prefixlist filter")
{
  if (argc == 2)
    return bgp_show_prefix_filter (cli, argv[1],
                                   bgp_cli_str2afi (argv[0]),
                                   SAFI_UNICAST);
  else
    return bgp_show_prefix_filter (cli, argv[2],
                                 bgp_cli_str2afi (argv[0]),
                                 bgp_cli_str2safi (argv[1]));
}

CLI (show_bgp_neighbor_received_routes,
     show_bgp_neighbor_received_routes_cli,
     "show bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display the received routes from neighbor")
{
  if (argc == 1)
    return peer_adj_routes (cli, argv[0], AFI_IP6, SAFI_UNICAST, 1);
  else
    return peer_adj_routes (cli, argv[1], AFI_IP6, SAFI_UNICAST, 1);
}

CLI (show_bgp_afi_neighbor_received_routes_safi,
     show_bgp_afi_neighbor_received_routes_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast|) neighbors (A.B.C.D|X:X::X:X) received-routes",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display the received routes from neighbor")
{
  if (argc == 2)
    return peer_adj_routes (cli, argv[1], bgp_cli_str2afi (argv[0]),
                            SAFI_UNICAST, 1);
  else
    return peer_adj_routes (cli, argv[2], bgp_cli_str2afi (argv[0]),
                          bgp_cli_str2safi (argv[1]), 1);
}
#endif /* HAVE_IPV6 */

int
bgp_show_neighbor_route_clean (struct cli *cli)
{
  union sockunion *su;

  su = cli->arg;
  XFREE (MTYPE_SOCKUNION, su);
  return 0;
}

int
bgp_show_neighbor_route (struct cli *cli, char *ip_str, u_int16_t afi,
                         u_int8_t safi)
{
  union sockunion *su;
  struct bgp_peer *peer;

  su = sockunion_str2su (ip_str);
  if (su == NULL)
    {
      cli_out (cli, "Malformed address: %s\n", ip_str);
      return CLI_ERROR;
    }

  peer = bgp_peer_search (NULL, su);
  if (! peer || ! peer->afc[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    {
      cli_out (cli, "%% No such neighbor or address family\n");
      XFREE (MTYPE_SOCKUNION, su);
      return CLI_ERROR;
    }

  cli->arg = su;
  cli->cleanup = bgp_show_neighbor_route_clean;

  return bgp_show_cli (cli, NULL, afi, safi, bgp_show_type_neighbor);
}

CLI (show_ip_bgp_neighbor_routes,
     show_ip_bgp_neighbor_routes_cli,
     "show ip bgp neighbors (A.B.C.D|X:X::X:X) routes",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display routes learned from neighbor")
{
  return bgp_show_neighbor_route (cli, argv[0], AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_safi_neighbor_routes,
     show_ip_bgp_safi_neighbor_routes_cli,
     "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) routes",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display routes learned from neighbor")
{
  return bgp_show_neighbor_route (cli, argv[1], AFI_IP, bgp_cli_str2safi (argv[0]));
}

#ifdef HAVE_IPV6
CLI (show_bgp_neighbor_routes,
     show_bgp_neighbor_routes_cli,
     "show bgp neighbors (A.B.C.D|X:X::X:X) routes",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display routes learned from neighbor")
{
  if (argc == 1)
    return bgp_show_neighbor_route (cli, argv[0], AFI_IP6, SAFI_UNICAST);
  else
    return bgp_show_neighbor_route (cli, argv[1], AFI_IP6, SAFI_UNICAST);
}

CLI (show_bgp_afi_neighbor_routes_safi,
     show_bgp_afi_neighbor_routes_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast|) neighbors (A.B.C.D|X:X::X:X) routes",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Display routes learned from neighbor")
{
  if (argc == 2)
    return bgp_show_neighbor_route (cli, argv[1],
                                    bgp_cli_str2afi (argv[0]),
                                    SAFI_UNICAST);
  else
    return bgp_show_neighbor_route (cli, argv[2],
                                    bgp_cli_str2afi (argv[0]),
                                    bgp_cli_str2safi (argv[1]));
}
#endif /* HAVE_IPV6 */

CLI (show_ip_bgp_dampened_path,
     show_ip_bgp_dampened_path_cli,
     "show ip bgp dampening dampened-paths",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "BGP Specific commands",
     "Display detailed information about dampening",
     "Display paths suppressed due to dampening")
{
  return bgp_show_cli (cli, NULL, AFI_IP, SAFI_UNICAST,
                       bgp_show_type_dampened_paths);
}

CLI (show_ip_bgp_safi_dampened_path,
     show_ip_bgp_safi_dampened_path_cli,
     "show ip bgp ipv4 (unicast|multicast) dampening dampened-paths",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "BGP Specific commands",
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display detailed information about dampening",
     "Display paths suppressed due to dampening")
{
  return bgp_show_cli (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]),
                       bgp_show_type_dampened_paths);
}

CLI (show_bgp_dampened_path,
     show_bgp_dampened_path_cli,
     "show bgp dampening dampened-paths",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display detailed information about dampening",
     "Display paths suppressed due to dampening")
{
  return bgp_show_cli (cli, NULL, AFI_IP6, SAFI_UNICAST,
                       bgp_show_type_dampened_paths);
}

ALI (show_bgp_dampened_path,
     show_bgp_ipv6_dampened_path_cli,
     "show bgp (ipv6) dampening dampened-paths",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Display detailed information about dampening",
     "Display paths suppressed due to dampening");

CLI (show_bgp_afi_dampened_path_safi,
     show_bgp_afi_dampened_path_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast) dampening dampened-paths",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display detailed information about dampening",
     "Display paths suppressed due to dampening")
{
  return bgp_show_cli (cli, NULL, bgp_cli_str2afi (argv[0]),
                       bgp_cli_str2safi (argv[1]),
                       bgp_show_type_dampened_paths);
}

CLI (show_ip_bgp_flap_statistics,
     show_ip_bgp_flap_statistics_cli,
     "show ip bgp dampening flap-statistics",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "BGP Specific commands",
     "Display detailed information about dampening",
     "Display flap statistics of routes")
{
  return bgp_show_cli (cli, NULL, AFI_IP, SAFI_UNICAST,
                       bgp_show_type_flap_statistics);
}

CLI (show_ip_bgp_safi_flap_statistics,
     show_ip_bgp_safi_flap_statistics_cli,
     "show ip bgp ipv4 (unicast|multicast) dampening flap-statistics",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "BGP Specific commands",
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display detailed information about dampening",
     "Display flap statistics of routes")
{
  return bgp_show_cli (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]),
                       bgp_show_type_flap_statistics);
}

#ifdef HAVE_IPV6
CLI (show_bgp_flap_statistics,
     show_bgp_flap_statistics_cli,
     "show bgp dampening flap-statistics",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display detailed information about dampening",
     "Display flap statistics of routes")
{
  return bgp_show_cli (cli, NULL, AFI_IP6, SAFI_UNICAST,
                       bgp_show_type_flap_statistics);
}

ALI (show_bgp_flap_statistics,
     show_bgp_ipv6_flap_statistics_cli,
     "show bgp (ipv6) dampening flap-statistics",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Display detailed information about dampening",
     "Display flap statistics of routes");

CLI (show_bgp_afi_flap_statistics_safi,
     show_bgp_afi_flap_statistics_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast) dampening flap-statistics",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display detailed information about dampening",
     "Display flap statistics of routes")
{
  return bgp_show_cli (cli, NULL, bgp_cli_str2afi (argv[0]),
                       bgp_cli_str2safi (argv[1]),
                       bgp_show_type_flap_statistics);
}
#endif /* HAVE_IPV6 */

CLI (show_ip_bgp_damp_params,
     show_ip_bgp_damp_params_cli,
     "show ip bgp dampening parameters",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "BGP Specific commands",
     "Display detailed information about dampening",
     "Display details of configured dampening parameters")
{
  return bgp_show_rfd_config (cli, NULL, AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_safi_damp_params,
     show_ip_bgp_safi_damp_params_cli,
     "show ip bgp ipv4 (unicast|multicast) dampening parameters",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "BGP Specific commands",
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display detailed information about dampening",
     "Display details of configured dampening parameters")
{
  return bgp_show_rfd_config (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]));
}

#ifdef HAVE_IPV6
CLI (show_bgp_damp_params,
     show_bgp_damp_params_cli,
     "show bgp dampening parameters",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display detailed information about dampening",
     "Display details of configured dampening parameters")
{
  return bgp_show_rfd_config (cli, NULL, AFI_IP, SAFI_UNICAST);
}

ALI (show_bgp_damp_params,
     show_bgp_ipv6_damp_params_cli,
     "show bgp (ipv6) dampening parameters",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Display detailed information about dampening",
     "Display details of configured dampening parameters");

CLI (show_bgp_afi_damp_params_safi,
     show_bgp_afi_damp_params_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast) dampening parameters",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display detailed information about dampening",
     "Display details of configured dampening parameters")
{
  return bgp_show_rfd_config (cli, NULL, bgp_cli_str2afi (argv[0]),
                              bgp_cli_str2safi (argv[1]));
}
#endif /* HAVE_IPV6 */

CLI (show_ip_bgp_inconsistent_as,
     show_ip_bgp_inconsistent_as_cli,
     "show ip bgp inconsistent-as",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "BGP Specific commands",
     "Display routes with inconsistent AS Paths")
{
  return bgp_show_cli (cli, NULL, AFI_IP, SAFI_UNICAST,
                       bgp_show_type_inconsistent_as);
}

CLI (show_ip_bgp_safi_inconsistent_as,
     show_ip_bgp_safi_inconsistent_as_cli,
     "show ip bgp ipv4 (unicast|multicast) inconsistent-as",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "BGP Specific commands",
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes with inconsistent AS Paths")
{
  return bgp_show_cli (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]),
                       bgp_show_type_inconsistent_as);
}

#ifdef HAVE_IPV6
CLI (show_bgp_inconsistent_as,
     show_bgp_inconsistent_as_cli,
     "show bgp inconsistent-as",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display routes with inconsistent AS Paths")
{
  return bgp_show_cli (cli, NULL, AFI_IP6, SAFI_UNICAST,
                       bgp_show_type_inconsistent_as);
}

ALI (show_bgp_inconsistent_as,
     show_bgp_ipv6_inconsistent_as_cli,
     "show bgp (ipv6) inconsistent-as",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Display routes with inconsistent AS Paths");

CLI (show_bgp_afi_inconsistent_as_safi,
     show_bgp_afi_inconsistent_as_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast) inconsistent-as",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes with inconsistent AS Paths")
{
  return bgp_show_cli (cli, NULL, bgp_cli_str2afi (argv[0]),
                       bgp_cli_str2safi (argv[1]),
                       bgp_show_type_inconsistent_as);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_route_map_clean (struct cli *cli)
{
  XFREE (MTYPE_TMP, cli->arg);
  cli->arg = NULL;
  return 0;
}

int
bgp_show_route_map (struct cli *cli, char *rmap_str, u_int16_t afi,
                    u_int8_t safi)
{
  cli->arg = XSTRDUP (MTYPE_TMP, rmap_str);
  cli->cleanup = bgp_show_route_map_clean;

  return bgp_show_cli (cli, NULL, afi, safi, bgp_show_type_route_map);
}

CLI (show_ip_bgp_route_map,
     show_ip_bgp_route_map_cli,
     "show ip bgp route-map WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "BGP Specific commands",
     "Display routes matching the route-map",
     "A route-map to match on")
{
  return bgp_show_route_map (cli, argv[0], AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_safi_route_map,
     show_ip_bgp_safi_route_map_cli,
     "show ip bgp ipv4 (unicast|multicast) route-map WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "BGP Specific commands",
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the route-map",
     "A route-map to match on")
{
  return bgp_show_route_map (cli, argv[1], AFI_IP, bgp_cli_str2safi (argv[0]));
}

#ifdef HAVE_IPV6
CLI (show_bgp_route_map,
     show_bgp_route_map_cli,
     "show bgp route-map WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Display routes matching the route-map",
     "A route-map to match on")
{
  if (argc == 1)
    return bgp_show_route_map (cli, argv[0], AFI_IP6, SAFI_UNICAST);
  else
    return bgp_show_route_map (cli, argv[1], AFI_IP6, SAFI_UNICAST);
}

ALI (show_bgp_route_map,
     show_bgp_ipv6_route_map_cli,
     "show bgp (ipv6) route-map WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Display routes matching the route-map",
     "A route-map to match on");

CLI (show_bgp_afi_route_map_safi,
     show_bgp_afi_route_map_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast) route-map WORD",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Display routes matching the route-map",
     "A route-map to match on")
{
  return bgp_show_route_map (cli, argv[2],
                             bgp_cli_str2afi (argv[0]),
                             bgp_cli_str2safi (argv[1]));
}
#endif /* HAVE_IPV6 */

/* Show BGP peer's summary information. */
s_int32_t
bgp_show_summary (struct cli *cli, struct bgp *bgp,
                  afi_t afi, safi_t safi,
                  bool_t *disp_rid)
{
  u_int8_t timebuf [BGP_UPTIME_LEN];
  struct bgp_peer *peer;
  struct listnode *nn;
  u_int32_t count;
  u_int32_t len;

  /* Header string for each address family. */
  static char header[] = "Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd";

  count = 0;

  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      if (peer->afc[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
        {
          if (! count)
            {
              if (! disp_rid || *disp_rid == PAL_TRUE)
                {
                  cli_out (cli, "BGP router identifier %r, local AS number %u\n",
                           &bgp->router_id, bgp->as);

                  if (disp_rid)
                    *disp_rid = PAL_FALSE;
                }
              else
                cli_out (cli, "\n");

              cli_out (cli, "BGP table version is %lu\n",
                       bgp->table_version[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)]);
#ifndef HAVE_EXT_CAP_ASN
              cli_out (cli, "%ld BGP AS-PATH entries\n", aspath_count ());
#else
              if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
                 cli_out (cli, "%ld BGP AS-PATH entries\n", aspath4B_count ());
              else
                  cli_out (cli, "%ld BGP AS-PATH entries\n", aspath_count ());
#endif /* HAVE_EXT_CAP_ASN */
              cli_out (cli, "%ld BGP community entries\n", community_count ());
	      if (bgp_config_check(bgp, BGP_CFLAG_ECMP_ENABLE))
		{
		  cli_out (cli, "%ld  Configured ebgp ECMP multipath: Currently set at %ld\n",
                     bgp->cfg_maxpath_ebgp,  bgp->maxpath_ebgp);
		  cli_out (cli, "%ld  Configured ibgp ECMP multipath: Currently set at %ld\n",
		     bgp->cfg_maxpath_ibgp,  bgp->maxpath_ibgp);
		} 
  	       if (bgp->aslocal_count > 1)
                 {
		   cli_out (cli, "As-local-count: Configured %ld\n", bgp->aslocal_count);
	         }

              cli_out (cli, "\n%s\n", header);
            }
          count++;

          cli_out (cli, "%s", peer->host);
          len = pal_strlen (peer->host);
          len = 16 - len;
          if (len < 1)
            cli_out (cli, "%*s", 16, " ");
          else
            cli_out (cli, "%*s", len, " ");

          switch (peer->version)
            {
            case BGP_VERSION_4:
              cli_out (cli, "4 ");
              break;
            default:
              cli_out (cli, "?");
              break;
            }

          cli_out (cli, "%5d %7lu %7lu %8lu %4d %4lu ",
                   peer->as,
                   peer->open_in + peer->update_in + peer->keepalive_in
                   + peer->notify_in + peer->refresh_in + peer->dynamic_cap_in,
                   peer->open_out + peer->update_out + peer->keepalive_out
                   + peer->notify_out + peer->refresh_out
                   + peer->dynamic_cap_out,
                   peer->table_version [BGP_AFI2BAAI (afi)]
                                       [BGP_SAFI2BSAI (safi)],
                   0, 0);

          cli_out (cli, "%8s", (peer->uptime == 0) ? (s_int8_t *) "never" :
                   bgp_time_t2wdhms_str (peer->uptime, timebuf, BGP_UPTIME_LEN));

          if (peer->bpf_state == BPF_STATE_ESTABLISHED)
            cli_out (cli, " %8lu", peer->pcount [BGP_AFI2BAAI (afi)]
                                                [BGP_SAFI2BSAI (safi)]);
          else
            {
              if (CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
                cli_out (cli, " Idle (Admin)");
              else if (CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
                cli_out (cli, " Idle (PfxCt)");
              else
                cli_out (cli, " %-11s",
                         BGP_PEER_FSM_STATE_STR (peer->bpf_state));
            }

          cli_out (cli, "\n");
        }
    }

  if (count)
    cli_out (cli, "\nTotal number of neighbors %d\n", count);

  return CLI_SUCCESS;
}

/* Should be removed after CLI integrattion.  */
s_int32_t
bgp_show_summary_cli (struct cli *cli, u_int8_t *name,
                      afi_t afi, safi_t safi)
{
  struct bgp *bgp;

  /* When name is specified use name to lookup BGP instance */
  if (name)
    {
      bgp = bgp_lookup_by_name (name);

      if (! bgp)
        {
          cli_out (cli, "%% No such BGP instance exists\n");
          return CLI_ERROR;
        }
      bgp_show_summary (cli, bgp, afi, safi, NULL);

      return CLI_SUCCESS;
    }

  bgp = bgp_lookup_default ();

  if (bgp)
    bgp_show_summary (cli, bgp, afi, safi, NULL);

  return CLI_SUCCESS;
}

/* `show ip bgp summary' commands. */
CLI (show_ip_bgp_summary,
     show_ip_bgp_summary_cli,
     "show ip bgp summary",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Summary of BGP neighbor status")
{
  return bgp_show_summary_cli (cli, NULL, AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_instance_summary,
     show_ip_bgp_instance_summary_cli,
     "show ip bgp view WORD summary",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "View name",
     "Summary of BGP neighbor status")
{
  return bgp_show_summary_cli (cli, argv[0], AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_ipv4_summary,
     show_ip_bgp_ipv4_summary_cli,
     "show ip bgp ipv4 (unicast|multicast) summary",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Summary of BGP neighbor status")
{
  if (pal_strncmp (argv[0], "m", 1) == 0)
    return bgp_show_summary_cli (cli, NULL, AFI_IP, SAFI_MULTICAST);

  return bgp_show_summary_cli (cli, NULL, AFI_IP, SAFI_UNICAST);
}

CLI (show_ip_bgp_instance_ipv4_summary,
     show_ip_bgp_instance_ipv4_summary_cli,
     "show ip bgp view WORD ipv4 (unicast|multicast) summary",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "View name",
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Summary of BGP neighbor status")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_show_summary_cli (cli, argv[0], AFI_IP, SAFI_MULTICAST);
  else
    return bgp_show_summary_cli (cli, argv[0], AFI_IP, SAFI_UNICAST);
}

#ifdef HAVE_IPV6
CLI (show_bgp_summary,
     show_bgp_summary_cli,
     "show bgp summary",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Summary of BGP neighbor status")
{
  return bgp_show_summary_cli (cli, NULL, AFI_IP6, SAFI_UNICAST);
}

CLI (show_bgp_afi_summary_safi,
     show_bgp_afi_summary_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast|) summary",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Summary of BGP neighbor status")
{
  if (argc == 1)
    return bgp_show_summary_cli (cli, NULL, bgp_cli_str2afi (argv[0]),
                                 SAFI_UNICAST);
  else
    return bgp_show_summary_cli (cli, NULL, bgp_cli_str2afi (argv[0]),
                                 bgp_cli_str2safi (argv[1]));
}
#endif /* HAVE_IPV6 */

/* Show BGP peer's information. */
enum show_type
  {
    show_all,
    show_peer,
    show_hold_time,
    show_keepalive_interval,
    show_connection_retrytime,
    show_received,
    show_sent,
    show_notification,
    show_update,
    show_open,
    show_keepalive
  };

/* Display BGP capability information.  */
void
bgp_capability_cli_out (struct cli *cli, struct bgp_peer *peer)
{
  struct bgp_capability cap;
  u_int8_t *pnt;
  u_int8_t *end;

  pnt = peer->notify_info->not_err_data;
  end = pnt + peer->notify_info->not_err_dlen;

  while (pnt < end)
    {
      pal_mem_cpy (&cap, pnt, sizeof (struct bgp_capability));

      if (pnt + 2 > end)
        return;
      if (pnt + (cap.cap_len + 2) > end)
        return;

      if (cap.cap_code == BGP_CAPABILITY_CODE_MP)
        {
          cli_out (cli, "  Capability error for: Multi protocol ");

          switch (pal_ntoh16 (cap.cap_mp.afi))
            {
            case AFI_IP:
              cli_out (cli, "AFI IPv4, ");
              break;
            case AFI_IP6:
              cli_out (cli, "AFI IPv6, ");
              break;
            default:
              cli_out (cli, "AFI Unknown %d, ",
                       pal_ntoh16 (cap.cap_mp.afi));
              break;
            }
          switch (cap.cap_mp.safi)
            {
            case SAFI_UNICAST:
              cli_out (cli, "SAFI Unicast");
              break;
            case SAFI_MULTICAST:
              cli_out (cli, "SAFI Multicast");
              break;
            default:
              cli_out (cli, "SAFI Unknown %d ", cap.cap_mp.safi);
              break;
            }
          cli_out (cli, "\n");
        }
      else if (cap.cap_code >= 128)
        cli_out (cli, "  Capability error: vendor specific capability code %d",
                 cap.cap_code);
      else
        cli_out (cli, "  Capability error: unknown capability code %d",
                 cap.cap_code);

      pnt += cap.cap_len + 2;
    }
}

void
bgp_show_peer_afi_orf_cap (struct cli *cli, struct bgp_peer *p,
                           afi_t afi, safi_t safi,
                           u_int16_t adv_smcap, u_int16_t adv_rmcap,
                           u_int16_t rcv_smcap, u_int16_t rcv_rmcap)
{
  u_int32_t baai;
  u_int32_t bsai;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  /* Send-Mode */
  if (CHECK_FLAG (p->af_cap[baai][bsai], adv_smcap)
      || CHECK_FLAG (p->af_cap[baai][bsai], rcv_smcap))
    {
      cli_out (cli, "      Send-mode: ");
      if (CHECK_FLAG (p->af_cap[baai][bsai], adv_smcap))
        cli_out (cli, "advertised");
      if (CHECK_FLAG (p->af_cap[baai][bsai], rcv_smcap))
        cli_out (cli, "%sreceived",
                 CHECK_FLAG (p->af_cap[baai][bsai], adv_smcap) ?
                 ", " : "");
      cli_out (cli, "\n");
    }

  /* Receive-Mode */
  if (CHECK_FLAG (p->af_cap[baai][bsai], adv_rmcap)
      || CHECK_FLAG (p->af_cap[baai][bsai], rcv_rmcap))
    {
      cli_out (cli, "      Receive-mode: ");
      if (CHECK_FLAG (p->af_cap[baai][bsai], adv_rmcap))
        cli_out (cli, "advertised");
      if (CHECK_FLAG (p->af_cap[baai][bsai], rcv_rmcap))
        cli_out (cli, "%sreceived",
                 CHECK_FLAG (p->af_cap[baai][bsai], adv_rmcap) ?
                 ", " : "");
      cli_out (cli, "\n");
    }

  return;
}

void
bgp_show_peer_afi (struct cli *cli,
                   struct bgp_peer *peer,
                   afi_t afi, safi_t safi)
{
  struct bgp_peer_index *index;
  struct bgp_filter *filter;
  char orf_pfx_name[BUFSIZ];
  u_int32_t orf_pfx_count;
  struct bgp_node *rn;
  struct prefix p;
  u_int32_t baai;
  u_int32_t bsai;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  filter = &peer->filter[baai][bsai];
  index = &peer->index[baai][bsai];

  cli_out (cli, " For address family: %s %s\n",
           afi == AFI_IP6 ? "IPv6" :"IPv4",
           safi == SAFI_MULTICAST ? "Multicast" : "Unicast");

  cli_out (cli, "  BGP table version %lu, neighbor version %lu\n",
           peer->bgp->table_version[baai][bsai],
           peer->table_version[baai][bsai]);
  cli_out (cli, "  Index %d, Offset %d, Mask %#x\n",
           index->val, index->offset, index->mask);

  if (peer->af_group [baai][bsai])
    cli_out (cli, "  %s peer-group member\n", peer->group->name);

  if (CHECK_FLAG (peer->af_cap[baai][bsai], PEER_CAP_ORF_PREFIX_SM_ADV)
      || CHECK_FLAG (peer->af_cap[baai][bsai], PEER_CAP_ORF_PREFIX_SM_RCV)
      || CHECK_FLAG (peer->af_cap[baai][bsai], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)
      || CHECK_FLAG (peer->af_cap[baai][bsai], PEER_CAP_ORF_PREFIX_RM_ADV)
      || CHECK_FLAG (peer->af_cap[baai][bsai], PEER_CAP_ORF_PREFIX_RM_RCV)
      || CHECK_FLAG (peer->af_cap[baai][bsai], PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
    cli_out (cli, "  AF-dependant capabilities:\n");

  if (CHECK_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_SM_ADV)
      || CHECK_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_SM_RCV)
      || CHECK_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_RM_ADV)
      || CHECK_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_RM_RCV))
    {
      cli_out (cli, "    Outbound Route Filter (ORF) type (%d) Prefix-list:\n",
               BGP_ORF_TYPE_PREFIX);
      bgp_show_peer_afi_orf_cap (cli, peer, afi, safi,
                                 PEER_CAP_ORF_PREFIX_SM_ADV,
                                 PEER_CAP_ORF_PREFIX_RM_ADV,
                                 PEER_CAP_ORF_PREFIX_SM_RCV,
                                 PEER_CAP_ORF_PREFIX_RM_RCV);
    }
  if (CHECK_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_SM_ADV)
      || CHECK_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)
      || CHECK_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_RM_ADV)
      || CHECK_FLAG (peer->af_cap [baai][bsai], PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
    {
      cli_out (cli, "    Outbound Route Filter (ORF) type (%d) Prefix-list:\n",
               BGP_ORF_TYPE_PREFIX_OLD);
      bgp_show_peer_afi_orf_cap (cli, peer, afi, safi,
                                 PEER_CAP_ORF_PREFIX_SM_ADV,
                                 PEER_CAP_ORF_PREFIX_RM_ADV,
                                 PEER_CAP_ORF_PREFIX_SM_OLD_RCV,
                                 PEER_CAP_ORF_PREFIX_RM_OLD_RCV);
    }

  pal_snprintf (orf_pfx_name, BUFSIZ, "%s.%d.%d", peer->host, afi, safi);
  orf_pfx_count =  prefix_bgp_show_prefix_list (BGP_VR.owning_ivr, NULL, afi, orf_pfx_name);

  if (CHECK_FLAG (peer->af_sflags[baai][bsai], PEER_STATUS_ORF_PREFIX_SEND)
      || orf_pfx_count)
    {
      cli_out (cli, "  Outbound Route Filter (ORF):");
      if (CHECK_FLAG (peer->af_sflags[baai][bsai], PEER_STATUS_ORF_PREFIX_SEND))
        cli_out (cli, " sent;");
      if (orf_pfx_count)
        cli_out (cli, " received (%d entries)", orf_pfx_count);
      cli_out (cli, "\n");
    }
  if (CHECK_FLAG (peer->af_sflags[baai][bsai], PEER_STATUS_ORF_WAIT_REFRESH))
    cli_out (cli, "  First update is deferred until ORF or ROUTE-REFRESH is received\n");

  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_REFLECTOR_CLIENT))
    cli_out (cli, "  Route-Reflector Client\n");
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_RSERVER_CLIENT))
    cli_out (cli, "  Route-Server Client\n");
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_SOFT_RECONFIG))
    cli_out (cli, "  Inbound soft reconfiguration allowed\n");
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_REMOVE_PRIVATE_AS))
    cli_out (cli, "  Private AS number removed from updates to this neighbor\n");
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_NEXTHOP_SELF))
    cli_out (cli, "  NEXT_HOP is always this router\n");
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_AS_PATH_UNCHANGED))
    cli_out (cli, "  AS_PATH is propagated unchanged to this neighbor\n");
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_NEXTHOP_UNCHANGED))
    cli_out (cli, "  NEXT_HOP is propagated unchanged to this neighbor\n");
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_MED_UNCHANGED))
    cli_out (cli, "  MED is propagated unchanged to this neighbor\n");
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_SEND_COMMUNITY)
      || CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_SEND_EXT_COMMUNITY))
    {
      cli_out (cli, "  Community attribute sent to this neighbor");
      if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_SEND_COMMUNITY)
          && CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_SEND_EXT_COMMUNITY))
        cli_out (cli, " (both)\n");
      else if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_SEND_EXT_COMMUNITY))
        cli_out (cli, " (extended)\n");
      else
        cli_out (cli, " (standard)\n");
    }
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_DEFAULT_ORIGINATE))
    {
      pal_mem_set (&p, 0, sizeof (struct prefix));
      if (afi == AFI_IP)
        p.family = AF_INET;
#ifdef HAVE_IPV6
      else if (BGP_CAP_HAVE_IPV6 && afi == AFI_IP6)
        p.family = AF_INET6;
#endif /* HAVE_IPV6 */

      rn = bgp_afi_node_get (peer->bgp, afi, safi, &p, NULL);

      if (! rn)
        return;

      cli_out (cli, "  Default information originate,");

      if (peer->default_rmap[baai][bsai].name)
        cli_out (cli, " default route-map %s%s,",
                 peer->default_rmap[baai][bsai].map ? "*" : "",
                 peer->default_rmap[baai][bsai].name);

      if (bgp_adj_out_lookup (peer, rn))
        cli_out (cli, " default sent\n");
      else
        cli_out (cli, " default not sent\n");

      bgp_unlock_node (rn);
    }
  /* Display the weight only if it is not default weight */
  if (peer->weight[baai][bsai] != BGP_DEFAULT_WEIGHT)
    cli_out (cli, " Weight %lu\n", peer->weight[baai][bsai]);

  if (filter->plist[FILTER_IN].name
      || filter->dlist[FILTER_IN].name
      || filter->aslist[FILTER_IN].name
      || filter->map[FILTER_IN].name)
    cli_out (cli, "  Inbound path policy configured\n");
  if (filter->plist[FILTER_OUT].name
      || filter->dlist[FILTER_OUT].name
      || filter->aslist[FILTER_OUT].name
      || filter->map[FILTER_OUT].name
      || filter->usmap.name)
    cli_out (cli, "  Outbound path policy configured\n");

  /* prefix-list */
  if (filter->plist[FILTER_IN].name)
    cli_out (cli, "  Incoming update prefix filter list is %s%s\n",
             filter->plist[FILTER_IN].plist ? "*" : "",
             filter->plist[FILTER_IN].name);
  if (filter->plist[FILTER_OUT].name)
    cli_out (cli, "  Outgoing update prefix filter list is %s%s\n",
             filter->plist[FILTER_OUT].plist ? "*" : "",
             filter->plist[FILTER_OUT].name);

  /* distribute-list */
  if (filter->dlist[FILTER_IN].name)
    cli_out (cli, "  Incoming update network filter list is %s%s\n",
             filter->dlist[FILTER_IN].alist ? "*" : "",
             filter->dlist[FILTER_IN].name);
  if (filter->dlist[FILTER_OUT].name)
    cli_out (cli, "  Outgoing update network filter list is %s%s\n",
             filter->dlist[FILTER_OUT].alist ? "*" : "",
             filter->dlist[FILTER_OUT].name);

  /* filter-list. */
  if (filter->aslist[FILTER_IN].name)
    cli_out (cli, "  Incoming update AS path filter list is %s%s\n",
             filter->aslist[FILTER_IN].aslist ? "*" : "",
             filter->aslist[FILTER_IN].name);
  if (filter->aslist[FILTER_OUT].name)
    cli_out (cli, "  Outgoing update AS path filter list is %s%s\n",
             filter->aslist[FILTER_OUT].aslist ? "*" : "",
             filter->aslist[FILTER_OUT].name);

  /* route-map. */
  if (filter->map[FILTER_IN].name)
    cli_out (cli, "  Route map for incoming advertisements is %s%s\n",
             filter->map[FILTER_IN].map ? "*" : "",
             filter->map[FILTER_IN].name);
  if (filter->map[FILTER_OUT].name)
    cli_out (cli, "  Route map for outgoing advertisements is %s%s\n",
             filter->map[FILTER_OUT].map ? "*" : "",
             filter->map[FILTER_OUT].name);

  /* unsuppress-map */
  if (filter->usmap.name)
    cli_out (cli, "  Route map for selective unsuppress is %s%s\n",
             filter->usmap.map ? "*" : "",
             filter->usmap.name);

  /* Receive prefix count */
  cli_out (cli, "  %lu accepted prefixes", peer->pcount[baai][bsai]);

  /* Maximum prefix */
  if (peer->pmax[baai][bsai])
    {
      cli_out (cli, ", maximum limit %lu%s\n", peer->pmax[baai][bsai],
               CHECK_FLAG (peer->af_flags[baai][bsai],
                           PEER_FLAG_MAX_PREFIX_WARNING)
               ? " (warning-only)" : "");

      cli_out (cli, "  Threshold for warning message %d(%)",
               peer->threshold [baai][bsai]);
    }
  cli_out (cli, "\n");

  cli_out (cli, "  %lu announced prefixes\n",
           peer->scount [baai][bsai]);

  cli_out (cli, "\n");
}

void
bgp_show_peer (struct cli *cli, struct bgp_peer *p)
{
  u_int8_t timebuf[BGP_UPTIME_LEN];
  u_int8_t buf1 [SU_ADDRSTRLEN];
  u_int8_t *bufp;
  u_int8_t *code_str = NULL;
  u_int8_t *subcode_str = NULL;
  u_int8_t *direct = NULL;

  /* Configured IP address. */
  cli_out (cli, "BGP neighbor is %s, ", p->host);
  cli_out (cli, "remote AS %u, ", p->as);
  cli_out (cli, "local AS %u, ", p->local_as);
  cli_out (cli, "%s link\n",
           p->as == p->local_as ? "internal" : "external");

  /* Description. */
  if (p->desc)
    cli_out (cli, " Description: %s\n", p->desc);

  /* Peer-group */
  if (p->group)
    cli_out (cli, " Member of peer-group %s for session parameters\n",
             p->group->name);

  /* Administrative shutdown. */
  if (CHECK_FLAG (p->flags, PEER_FLAG_SHUTDOWN))
    cli_out (cli, " Administratively shut down\n");

  /* BGP Version. */
  cli_out (cli, "  BGP version 4");
  cli_out (cli, ", remote router ID %r\n", &p->remote_id);

  /* Confederation */
  if (bgp_confederation_peers_check (p->bgp, p->as))
    cli_out (cli, "  Neighbor under common administration\n");

  /* Status. */
  cli_out (cli, "  BGP state = %s",
           BGP_PEER_FSM_STATE_STR (p->bpf_state));

  if (CHECK_FLAG (p->flags, PEER_FLAG_NO_IF_BINDING))
    cli_out (cli, "\n No Interfaces bound to BGP Instance");

  if (p->bpf_state == BPF_STATE_ESTABLISHED)
    cli_out (cli, ", up for %8s",
             bgp_time_t2wdhms_str (p->uptime, timebuf, BGP_UPTIME_LEN));
  cli_out (cli, "\n");

  /* read timer */
  cli_out (cli, "  Last read %s",
           bgp_time_t2wdhms_str (p->uptime, timebuf, BGP_UPTIME_LEN));

  /* Configured timer values. */
  cli_out (cli, ", hold time is %lu, keepalive interval is %lu seconds\n",
           p->v_holdtime, p->v_keepalive);
  if (CHECK_FLAG (p->config, PEER_CONFIG_TIMER))
    {
      cli_out (cli, "  Configured hold time is %lu", p->holdtime);
      cli_out (cli, ", keepalive interval is %lu seconds\n", p->keepalive);
    }
  else if (bgp_config_check (p->bgp, BGP_CFLAG_DEFAULT_TIMER))
    {
      cli_out (cli, "  Configured hold time is %lu", p->holdtime);
      cli_out (cli, ", keepalive interval is %lu seconds\n", p->keepalive);
    }

  /* Capability. */
  if (p->bpf_state == BPF_STATE_ESTABLISHED)
    {
      if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_ADV)
          || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV)
          || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV)
          || CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_ADV)
          || CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_RCV)
          || CHECK_FLAG (p->cap, PEER_CAP_EXTENDED_ASN_ADV)
          || CHECK_FLAG (p->cap, PEER_CAP_EXTENDED_ASN_RCV)
          || p->afc_adv[BAAI_IP][BSAI_UNICAST]
          || p->afc_recv[BAAI_IP][BSAI_UNICAST]
          || p->afc_adv[BAAI_IP][BSAI_MULTICAST]
          || p->afc_recv[BAAI_IP][BSAI_MULTICAST]
#ifdef HAVE_IPV6
          || (BGP_CAP_HAVE_IPV6 && (p->afc_adv [BAAI_IP6][BSAI_UNICAST]
                               || p->afc_recv [BAAI_IP6][BSAI_UNICAST]
                               || p->afc_adv [BAAI_IP6][BSAI_MULTICAST]
                               || p->afc_recv [BAAI_IP6][BSAI_MULTICAST]))
#endif /* HAVE_IPV6 */
	)
        {
          cli_out (cli, "  Neighbor capabilities:\n");

          /* Dynamic */
          if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_RCV)
              || CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_ADV))
            {
              cli_out (cli, "    Dynamic:");
              if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_ADV))
                cli_out (cli, " advertised");
              if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_RCV))
                {
                  if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_ADV))
                    cli_out (cli, " and");
                  cli_out (cli, " received");
                }
              cli_out (cli, "\n");
            }

          /* Route Refresh */
          if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_ADV)
              || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV)
              || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV))
            {
              cli_out (cli, "    Route refresh:");
               if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_ADV))
                cli_out (cli, " advertised");
              if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV)
                  || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV))
                {
                  if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_ADV))
                    cli_out (cli, " and");
                  cli_out (cli, " received");
                  if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV)
                      && CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV))
                    cli_out (cli, " (old and new)");
                  else if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV))
                    cli_out (cli, " (old)");
                  else
                    cli_out (cli, " (new)");
                }
              cli_out (cli, "\n");
            }

         /* Extended ASN Capability handling */
         /* Check local speaker is NBGP */
         if (CHECK_FLAG (BGP_VR.bvr_options,BGP_OPT_EXTENDED_ASN_CAP))
           {
              cli_out (cli, "    4-Octet ASN Capability:");
                  if (CHECK_FLAG (p->cap, PEER_CAP_EXTENDED_ASN_ADV))
                     cli_out (cli, " advertised");
              if (CHECK_FLAG (p->cap, PEER_CAP_EXTENDED_ASN_ADV)
                  && CHECK_FLAG (p->cap, PEER_CAP_EXTENDED_ASN_RCV))
                {                
                    cli_out (cli, " and");
                    cli_out (cli, " received");
                }
               else if(CHECK_FLAG (p->cap, PEER_CAP_EXTENDED_ASN_RCV))
                  cli_out (cli, " received"); 
               cli_out (cli, "\n");  
           }

          /* IPv4 */
          if (p->afc_adv [BAAI_IP][BSAI_UNICAST]
              || p->afc_recv [BAAI_IP][BSAI_UNICAST])
            {
              cli_out (cli, "    Address family IPv4 Unicast:");
              if (p->afc_adv [BAAI_IP][BSAI_UNICAST])
                cli_out (cli, " advertised");
              if (p->afc_recv [BAAI_IP][BSAI_UNICAST])
                {
                  if (p->afc_adv [BAAI_IP][BSAI_UNICAST])
                    cli_out (cli, " and");
                  cli_out (cli, " received");
                }
              cli_out (cli, "\n");
            }
          if (p->afc_adv [BAAI_IP][BSAI_MULTICAST]
              || p->afc_recv [BAAI_IP][BSAI_MULTICAST])
            {
              cli_out (cli, "    Address family IPv4 Multicast:");
              if (p->afc_adv [BAAI_IP][BSAI_MULTICAST])
                cli_out (cli, " advertised");
              if (p->afc_recv [BAAI_IP][BSAI_MULTICAST])
                {
                  if (p->afc_adv [BAAI_IP][BSAI_MULTICAST])
                    cli_out (cli, " and");
                  cli_out (cli, " received");
                }
              cli_out (cli, "\n");
            }
          /* IPv6 */
#ifdef HAVE_IPV6
          IF_BGP_CAP_HAVE_IPV6
            {
              if (p->afc_adv [BAAI_IP6][BSAI_UNICAST]
                  || p->afc_recv [BAAI_IP6][BSAI_UNICAST])
                {
                  cli_out (cli, "    Address family IPv6 Unicast:");
                  if (p->afc_adv [BAAI_IP6][BSAI_UNICAST])
                    cli_out (cli, " advertised");
                  if (p->afc_recv [BAAI_IP6][BSAI_UNICAST])
                    {
                      if (p->afc_adv [BAAI_IP6][BSAI_UNICAST])
                        cli_out (cli, " and");
                      cli_out (cli, " received");
                    }
                  cli_out (cli, "\n");
                }
              if (p->afc_adv [BAAI_IP6][BSAI_MULTICAST]
                  || p->afc_recv [BAAI_IP6][BSAI_MULTICAST])
                {
                  cli_out (cli, "    Address family IPv6 Multicast:");
                  if (p->afc_adv [BAAI_IP6][BSAI_MULTICAST])
                    cli_out (cli, " advertised");
                  if (p->afc_recv [BAAI_IP6][BSAI_MULTICAST])
                    {
                      if (p->afc_adv [BAAI_IP6][BSAI_MULTICAST])
                        cli_out (cli, " and");
                      cli_out (cli, " received");
                    }
                  cli_out (cli, "\n");
                }
            }
#endif /* HAVE_IPV6 */
        }
    }

  /* Packet counts. */
  cli_out(cli, "  Received %lu messages, %lu notifications, %lu in queue\n",
          p->open_in + p->update_in + p->keepalive_in + p->refresh_in
          + p->dynamic_cap_in, p->notify_in, 0);
  cli_out(cli, "  Sent %lu messages, %lu notifications, %lu in queue\n",
          p->open_out + p->update_out + p->keepalive_out + p->refresh_out
          + p->dynamic_cap_out, p->notify_out, 0);
  cli_out(cli, "  Route refresh request: received %lu, sent %lu\n",
          p->refresh_in, p->refresh_out);

  /* advertisement-interval */
  cli_out (cli, "  Minimum time between advertisement runs is %lu seconds\n",
           p->v_routeadv);

  /* Update-source. */
  if (p->update_if || p->update_source)
    {
      cli_out (cli, "  Update source is ");
      if (p->update_if)
        cli_out (cli, "%s", p->update_if);
      else if (p->update_source)
        cli_out (cli, "%s",
                 sockunion2str (p->update_source, buf1, SU_ADDRSTRLEN));
      cli_out (cli, "\n");
    }

  /* Address Family Information */
  if (p->afc [BAAI_IP][BSAI_UNICAST])
    bgp_show_peer_afi (cli, p, AFI_IP, SAFI_UNICAST);
  if (p->afc [BAAI_IP][BSAI_MULTICAST])
    bgp_show_peer_afi (cli, p, AFI_IP, SAFI_MULTICAST);
#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      if (p->afc [BAAI_IP6][BSAI_UNICAST])
        bgp_show_peer_afi (cli, p, AFI_IP6, SAFI_UNICAST);
      if (p->afc [BAAI_IP6][BSAI_MULTICAST])
        bgp_show_peer_afi (cli, p, AFI_IP6, SAFI_MULTICAST);
    }
#endif /* HAVE_IPV6 */

  cli_out (cli, " Connections established %lu; dropped %lu\n",
           p->established, p->dropped);

  if (CHECK_FLAG (p->sflags, PEER_STATUS_PREFIX_OVERFLOW))
    cli_out (cli," Last reset due to Peer has exceeded the maximum prefix configured\n");

  /* EBGP Multihop */
  if (peer_sort (p) == BGP_PEER_EBGP && p->ttl > 1)
    cli_out (cli, "  External BGP neighbor may be up to %d hops away.\n",
             p->ttl);

  /* Local address. */
  if (p->su_local)
    {
      bufp = (u_int8_t *) sockunion2str (p->su_local, buf1, SU_ADDRSTRLEN);

      cli_out (cli, "Local host: %s, Local port: %d\n",
               bufp ? bufp : (u_int8_t *) "",
               pal_ntoh16 (p->su_local->sin.sin_port));
    }

  /* Remote address. */
  if (p->su_remote)
    {
      bufp = (u_int8_t *) sockunion2str (p->su_remote, buf1, SU_ADDRSTRLEN);
      cli_out (cli, "Foreign host: %s, Foreign port: %d\n",
               bufp ? bufp : (u_int8_t *) "",
               pal_ntoh16 (p->su_remote->sin.sin_port));
    }

  /* Nexthop display. */
  if (p->su_local)
    {
      cli_out (cli, "Nexthop: %r\n", &p->nexthop.v4);
#ifdef HAVE_IPV6
      IF_BGP_CAP_HAVE_IPV6
        {
          cli_out (cli, "Nexthop global: %R\n", &p->nexthop.v6_global);
          cli_out (cli, "Nexthop local: %R\n", &p->nexthop.v6_local);
          cli_out (cli, "BGP connection: %s\n",
                   p->shared_network ? "shared network" : "non shared network");
        }
#endif /* HAVE_IPV6 */
    }

  /* Timer information. */
  if (p->t_auto_start)
    cli_out (cli, "Auto restarting due in %ld seconds\n",
	     thread_timer_remain_second (p->t_auto_start));

  if (p->t_connect)
    cli_out (cli, "Next connect timer due in %ld seconds\n",
             thread_timer_remain_second (p->t_connect));

  if (p->notify_info
      && p->notify_info->not_err_code == BGP_NOTIFY_OPEN_ERR
      && p->notify_info->not_err_sub_code == BGP_NOTIFY_OPEN_UNSUP_CAPBL)
    bgp_capability_cli_out (cli, p);
  if ((p->notify_info))
    {
      if (p->notify_info->not_err_dir_sent == PAL_TRUE)
        direct = "sent";
      else
        direct = "received";
      cli_out (cli, "Last Reset: %s, due to BGP Notification %s\n",
               bgp_time_t2wdhms_str (p->last_reset_time, timebuf,
                                     BGP_UPTIME_LEN), direct);

      bgp_get_notify_err_mesg (p->notify_info, &code_str, &subcode_str);
      cli_out(cli,"Notification Error Message: (%s%s)\n", code_str,
              subcode_str);
    }
  cli_out (cli, "\n");
}


void
bgp_show_peer_time (struct cli *cli, struct bgp_peer *p, enum show_type type)
{
  /* Configured timer values. */

  if ( type == show_hold_time )
  {
    if (CHECK_FLAG (p->config, PEER_CONFIG_TIMER))
    {
      cli_out (cli, " Configured hold time is %lu\n", p->holdtime);
      cli_out (cli, " Hold time for this session is %lu seconds\n ", p->v_holdtime);
    }
    else if (bgp_config_check (p->bgp, BGP_CFLAG_DEFAULT_TIMER))
    {
      cli_out (cli, " Hold time is %lu\n", p->holdtime);
      cli_out (cli, " Hold time for this session is %lu seconds\n ", p->v_holdtime);
    }
  }

  else if ( type == show_keepalive_interval )
  {
    if (CHECK_FLAG (p->config, PEER_CONFIG_TIMER))
    {
      cli_out (cli, " Configured keepalive interval is %lu seconds\n", p->keepalive);
      cli_out (cli, " Keepalive interval for this session is %lu seconds\n", p->v_keepalive);
    }
    else if (bgp_config_check (p->bgp, BGP_CFLAG_DEFAULT_TIMER))
    {
      cli_out (cli, " Keepalive interval is %lu seconds\n", p->keepalive);
      cli_out (cli, " Keepalive interval for this session is %lu seconds\n", p->v_keepalive);
    }
  }
  
  else if ( type == show_connection_retrytime )
  {
    if (CHECK_FLAG (p->config,PEER_CONFIG_CONNECT))
     cli_out (cli, "Next connect timer due in %ld seconds\n", p->connect);
  }

}


void
bgp_show_peer_msgcounter(struct cli *cli, struct bgp_peer *p, enum show_type type)
{
  /* Packet counts. */
  if ( type == show_received )
    cli_out(cli, "  Received %lu messages\n",
                  p->open_in + p->update_in + p->keepalive_in + p->refresh_in + p->dynamic_cap_in);
  else if ( type == show_sent )
    cli_out(cli, "  Sent %lu messages\n",
                  p->open_out + p->update_out + p->keepalive_out + p->refresh_out + p->dynamic_cap_out );
  else if ( type == show_notification )
    cli_out(cli, " Received %lu Notification messages and Sent %lu Notification messages \n", p->notify_in, p->notify_out);
  else if ( type == show_update )
    cli_out(cli, " Received %lu UPDATE messages and Sent %lu UPDATE messages \n", p->update_in,  p->update_out);
  else if ( type == show_open )
    cli_out(cli, " Received %lu OPEN messages and Sent %lu OPEN messages \n", p->open_in,  p->open_out);
  else if ( type == show_keepalive )
    cli_out(cli, " Received %lu KEEPALIVE messages and Sent %lu KEEPALIVE messages \n", p->keepalive_in,  p->keepalive_out);
}


s_int32_t
bgp_show_neighbor (struct cli *cli, struct bgp *bgp,
                   enum show_type type, union sockunion *su)
{
  struct bgp_peer *peer;
  struct listnode *nn;

  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      switch (type)
        {
        case show_all:
          bgp_show_peer (cli, peer);
          break;
        case show_peer:
          if (sockunion_same (&peer->su, su))
            {
              bgp_show_peer (cli, peer);
            }
          break;
        case show_hold_time:
        case show_keepalive_interval:
        case show_connection_retrytime:
          if (sockunion_same (&peer->su, su))
            {
              bgp_show_peer_time(cli, peer, type); 
            }
          break;
        case show_received:
        case show_sent:
        case show_notification:
        case show_update:
        case show_open:
        case show_keepalive:
          if (sockunion_same (&peer->su, su))
            {
              bgp_show_peer_msgcounter(cli, peer, type);
            }
          break;
        }
    }
  return 0;
}

s_int32_t
bgp_show_neighbor_vty (struct cli *cli, u_int8_t *name,
                       enum show_type type, u_int8_t *ip_str)
{
  struct listnode *nn;
  union sockunion su;
  struct bgp *bgp;
  s_int32_t ret;

  if (ip_str)
    {
      ret = str2sockunion (ip_str, &su);
      if (ret < 0)
        {
          cli_out (cli, "%% Malformed address: %s\n", ip_str);
          return CLI_ERROR;
        }
    }

  if (name)
    {
      /* When specified, use name to lookup BGP instance */
      bgp = bgp_lookup_by_name (name);

      if (! bgp)
        {
          cli_out (cli, "%% No such BGP instance exist\n");
          return CLI_ERROR;
        }

      bgp_show_neighbor (cli, bgp, type, &su);

      return CLI_SUCCESS;
    }

  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    bgp_show_neighbor (cli, bgp, type, &su);

  return CLI_SUCCESS;
}


/* "show ip bgp neighbors" commands.  */
CLI (show_ip_bgp_neighbors,
     show_ip_bgp_neighbors_cli,
     "show ip bgp neighbors",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections")
{
  return bgp_show_neighbor_vty (cli, NULL, show_all, NULL);
}


CLI (show_ip_bgp_neighbor_peer_time,
     show_ip_bgp_neighbors_peer_time_cli,
     "show ip bgp neighbors (A.B.C.D|X:X::X:X) (hold-time|keepalive-interval|connection-retrytime)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Hold-time",
     "Keepalive-interval",
     "Connection-retrytime")
{
  if ( !pal_strncmp (argv[1], "h", 1))
    return bgp_show_neighbor_vty (cli, NULL, show_hold_time, argv[0]);
  else if ( !pal_strncmp (argv[1], "k", 1))
    return bgp_show_neighbor_vty (cli, NULL, show_keepalive_interval, argv[0]);
  else if ( !pal_strncmp (argv[1], "c", 1))
    return bgp_show_neighbor_vty (cli, NULL, show_connection_retrytime, argv[0]);
  else
    return CLI_ERROR;
}

CLI (show_ip_bgp_neighbor_peer_msgcounter,
     show_ip_bgp_neighbors_peer_msgcounter_cli,
     "show ip bgp neighbors (A.B.C.D|X:X::X:X) (sent-msgs|rcvd-msgs|notification|update|open|keepalive)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about",
     "Sent packets",
     "Received packets",
     "Notification messages",
     "Update messages",
     "Open messages",
     "Keepalive messages")
{
  if ( !pal_strncmp (argv[1], "s", 1) )
    return bgp_show_neighbor_vty (cli, NULL, show_sent, argv[0]);
  else if ( !pal_strncmp (argv[1], "r", 1) )
    return bgp_show_neighbor_vty (cli, NULL, show_received, argv[0]);
  else if ( !pal_strncmp (argv[1], "n", 1) )
    return bgp_show_neighbor_vty (cli, NULL, show_notification, argv[0]);
  else if ( !pal_strncmp (argv[1], "u", 1) )
    return bgp_show_neighbor_vty (cli, NULL, show_update, argv[0]);
  else if ( !pal_strncmp (argv[1], "o", 1) )
    return bgp_show_neighbor_vty (cli, NULL, show_open, argv[0]);
  else if ( !pal_strncmp (argv[1], "k", 1) )
    return bgp_show_neighbor_vty (cli, NULL, show_keepalive, argv[0]);
  else
    return CLI_ERROR;
}


ALI (show_ip_bgp_neighbors,
     show_ip_bgp_ipv4_neighbors_cli,
     "show ip bgp ipv4 (unicast|multicast) neighbors",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections");

ALI (show_ip_bgp_neighbors,
     show_bgp_neighbors_cli,
     "show bgp neighbors",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections");

ALI (show_ip_bgp_neighbors,
     show_bgp_ipv6_neighbors_cli,
     "show bgp (ipv6) neighbors",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Detailed information on TCP and BGP neighbor connections");

ALI (show_ip_bgp_neighbors,
     show_bgp_afi_neighbors_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast|) neighbors",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections");

CLI (show_ip_bgp_neighbors_peer,
     show_ip_bgp_neighbors_peer_cli,
     "show ip bgp neighbors (A.B.C.D|X:X::X:X)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about")
{
  while (argc > 1)
    {
      argc--;
      argv++;
    }
  return bgp_show_neighbor_vty (cli, NULL, show_peer, argv[argc - 1]);
}

ALI (show_ip_bgp_neighbors_peer,
     show_ip_bgp_ipv4_neighbors_peer_cli,
     "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about");

CLI (show_ip_bgp_instance_neighbors,
     show_ip_bgp_instance_neighbors_cli,
     "show ip bgp view WORD neighbors",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "View name",
     "Detailed information on TCP and BGP neighbor connections")
{
  return bgp_show_neighbor_vty (cli, argv[0], show_all, NULL);
}

CLI (show_ip_bgp_instance_neighbors_peer,
     show_ip_bgp_instance_neighbors_peer_cli,
     "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "View name",
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about")
{
  return bgp_show_neighbor_vty (cli, argv[0], show_peer, argv[1]);
}

#ifdef HAVE_IPV6
ALI (show_ip_bgp_neighbors_peer,
     show_bgp_neighbors_peer_cli,
     "show bgp neighbors (A.B.C.D|X:X::X:X)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about");

ALI (show_ip_bgp_neighbors_peer,
     show_bgp_ipv6_neighbors_peer_cli,
     "show bgp (ipv6) neighbors (A.B.C.D|X:X::X:X)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about");

ALI (show_ip_bgp_neighbors_peer,
     show_bgp_afi_neighbors_peer_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast|) neighbors (A.B.C.D|X:X::X:X)",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Detailed information on TCP and BGP neighbor connections",
     "Neighbor to display information about",
     "Neighbor to display information about");
#endif /* HAVE_IPV6 */

/* Show BGP's AS paths internal data.  */
void
aspath_show_iterator (struct hash_backet *backet, struct cli *cli)
{
  struct aspath *as = (struct aspath *) backet->data;

  cli_out (cli, "[%p:%d] (%ld) ", backet, backet->key, as->refcnt);
  cli_out (cli, "%s\n", as->str);
}
#ifdef HAVE_EXT_CAP_ASN
void
as4path_show_iterator (struct hash_backet *backet, struct cli *cli)
{
  struct as4path *as = (struct as4path *) backet->data;

  cli_out (cli, "[%p:%d] (%ld) ", backet, backet->key, as->refcnt);
  cli_out (cli, "%s\n", as->str);
}
#endif /* HAVE_EXT_CAP_ASN */

CLI (show_ip_bgp_paths,
     show_ip_bgp_paths_cli,
     "show ip bgp paths",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Path information")
{
#ifndef HAVE_EXT_CAP_ASN
  cli_out (cli, "Address       Refcnt Path\n");

  hash_iterate (aspath_hash (),
                (void (*) (struct hash_backet *, void *)) aspath_show_iterator,
                cli);
#endif /* HAVE_EXT_CAP_ASN */
#ifdef HAVE_EXT_CAP_ASN
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      cli_out (cli,  "Address       Refcnt Path\n");

      hash_iterate (aspath4B_hash (),
                    (void (*) (struct hash_backet *, void *)) as4path_show_iterator,
                     cli);
     }
   /* Local speaker is OBGP */
   else
     { 
       cli_out (cli,  "Address       Refcnt Path\n");

       hash_iterate (aspath_hash (),
                     (void (*) (struct hash_backet *, void *)) aspath_show_iterator,
                     cli);
     }
#endif /* HAVE_EXT_CAP_ASN */

  return CLI_SUCCESS;
}

ALI (show_ip_bgp_paths,
     show_ip_bgp_ipv4_paths_cli,
     "show ip bgp ipv4 (unicast|multicast) paths",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Path information");

#ifdef HAVE_IPV6
ALI (show_ip_bgp_paths,
     show_bgp_paths_cli,
     "show bgp paths",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     "Path information");

ALI (show_ip_bgp_paths,
     show_bgp_ipv6_paths_cli,
     "show bgp (ipv6) paths",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IPV6_STR,
     "Path information");

ALI (show_ip_bgp_paths,
     show_bgp_afi_paths_safi_cli,
     "show bgp (ipv4|ipv6) (unicast|multicast|) paths",
     CLI_SHOW_STR,
     CLI_BGP_STR,
     CLI_IP_STR,
     CLI_IPV6_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Path information");
#endif /* HAVE_IPV6 */

/* Show BGP's community internal data. */
void
community_show_all_iterator (struct hash_backet *backet, struct cli *cli)
{
  struct community *com;

  com = (struct community *) backet->data;
  cli_out (cli, "[%p] (%ld) %s\n", backet, com->refcnt,
           community_str (com));
}

CLI (show_ip_bgp_community_info,
     show_ip_bgp_community_info_cli,
     "show ip bgp community-info",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "List all bgp community information")
{
  cli_out (cli, "Address Refcnt Community\n");

  hash_iterate (community_hash (),
                (void (*) (struct hash_backet *, void *))
                community_show_all_iterator,
                cli);

  return CLI_SUCCESS;
}

static void
attr_show_iterator (struct hash_backet *backet, struct cli *cli)
{
  struct attr *attr = backet->data;
  cli_out (cli, "attr[%ld] nexthop %r\n", attr->refcnt, &attr->nexthop);
  /* display AS-path*/
  #ifndef HAVE_EXT_CAP_ASN
    if (attr->aspath)
      {
         cli_out (cli, "  ");
         if (attr->aspath->length == 0)
           cli_out (cli, "Local");
         else
           cli_out (cli, "%s", attr->aspath->str);
      }
  #else
    if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
      {
          if (attr->aspath4B)
             {
               cli_out (cli, "  ");
               if (attr->aspath4B->length == 0)
                 cli_out (cli, "Local");
               else
                 cli_out (cli, "%s", attr->aspath4B->str);
             }
       }
     else if (attr->aspath)
       {
            cli_out (cli, "  ");
            if (attr->aspath->length == 0)
              cli_out (cli, "Local");
            else
              cli_out (cli, "%s", attr->aspath->str);
        }
  #endif /* HAVE_EXT_CAP_ASN */
        cli_out (cli, "\n");
         /* display Local Attributes and Status Information */
        cli_out (cli, "      Origin %s", BGP_ORIGIN_LONG_STR (attr->origin));
        if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
          cli_out (cli, ", localpref %lu", attr->local_pref);
        if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
          cli_out (cli, " metric %lu", attr->med);
        cli_out (cli, "\n");
        if (attr->weight != 0)
          cli_out (cli, ", weight %lu", attr->weight);
        if (attr->community)
          cli_out (cli, "      Community: %s\n", community_str (attr->community));
        cli_out (cli, "\n");
        cli_out (cli, "\n");

}

CLI (show_ip_bgp_attr_info,
     show_ip_bgp_attr_info_cli,
     "show ip bgp attribute-info",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "List all bgp attribute information")
{
  hash_iterate (bgp_attr_hash (),
                (void (*)(struct hash_backet *, void *))
                attr_show_iterator,
                cli);
  return CLI_SUCCESS;
}

void
bgp_show_neighbor_info (struct cli *cli, struct bgp_peer *peer,
                        afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  u_int32_t baai, bsai;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  filter = &peer->filter[baai][bsai];

  cli_out (cli, "%-24s", peer->host);

  if (safi == SAFI_UNICAST)
    cli_out (cli, "%-12s", "unicast");
  else if (safi == SAFI_MULTICAST)
    cli_out (cli, "%-12s", "multicast");

  if (filter->aslist[FILTER_IN].name)
    cli_out (cli, "%-8s", filter->aslist[FILTER_IN].name);
  else
    cli_out (cli, "%-8s", "");
  if (filter->aslist[FILTER_OUT].name)
    cli_out (cli, "%-9s", filter->aslist[FILTER_OUT].name);
  else
    cli_out (cli, "%-9s", "");

  if (filter->dlist[FILTER_IN].name)
    cli_out (cli, "%-8s", filter->dlist[FILTER_IN].name);
  else
    cli_out (cli, "%-8s", "");
  if (filter->dlist[FILTER_OUT].name)
    cli_out (cli, "%-9s", filter->dlist[FILTER_OUT].name);
  else
    cli_out (cli, "%-9s", "");

  if (filter->map[FILTER_IN].name)
    cli_out (cli, "%-12s", filter->map[FILTER_IN].name);
  else
    cli_out (cli, "%-12s", "");
  if (filter->map[FILTER_OUT].name)
    cli_out (cli, "%-13s", filter->map[FILTER_OUT].name);
  else
    cli_out (cli, "%-13s", "");

  /* Display the weight only if it is not Default weight */
  if(peer->weight[baai][bsai] != BGP_DEFAULT_WEIGHT)
    cli_out (cli, "%lu\n", peer->weight[baai][bsai]);
  else
    cli_out (cli, "\n");
}


CLI (show_ip_protocols_bgp,
     bgp_show_ip_protocols_cmd,
     "show ip protocols",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "IP routing protocol process parameters and statistics")
{
  struct bgp *bgp;
  struct bgp_peer *peer;
  struct listnode *nn, *nm;
  int type, flag = 0;
  afi_t afi;
  safi_t safi;

  afi = bgp_cli_mode_afi (cli);

  LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
    {
      if (! bgp->as)
        continue;

      cli_out (cli, "Routing Protocol is \"bgp %d\"\n", bgp->as);
      cli_out (cli, "  IGP synchronization is ");
      if (bgp_af_config_check (bgp, AFI_IP, SAFI_UNICAST,
                               BGP_AF_CFLAG_SYNCHRONIZATION))
        cli_out (cli, "enabled\n");
      else
        cli_out (cli, "disabled\n");
      cli_out (cli, "  Automatic route summarization is ");
      if (bgp_af_config_check (bgp, AFI_IP, SAFI_UNICAST,
                               BGP_AF_CFLAG_AUTO_SUMMARY))
        cli_out (cli, "enabled\n");
      else
        cli_out (cli, "disabled\n");
      cli_out (cli,
             "  Default local-preference applied to incoming route is %d\n",
             bgp->default_local_pref);
      /* Show filter by distribute-list */
      cli_out (cli, "  Redistributing: ");
      for (type =0; type < IPI_ROUTE_MAX; type++)
      if (bgp->redist[BGP_AFI2BAAI (afi)][type])
        {
          cli_out (cli, "%s%s", flag ? ", " : "",
                   LOOKUP (bgp_route_type_msg, type));
          flag++;
        }
      cli_out (cli, "\n");

      cli_out (cli, "  Neighbor(s):\n");
      cli_out (cli, "  Address          AddressFamily  FiltIn  FiltOut  DistIn  DistOut  RouteMapIn  RouteMapOut  Weight\n");

      LIST_LOOP (bgp->peer_list, peer, nm)
        {
          if (peer->afc[BAAI_IP][BSAI_UNICAST])
            {
              safi = SAFI_UNICAST;
              bgp_show_neighbor_info (cli, peer, afi, safi);
            }
          if (peer->afc[BAAI_IP][BSAI_MULTICAST])
            {
              safi = SAFI_MULTICAST;
              bgp_show_neighbor_info (cli, peer, afi, safi);
            }
        }

      cli_out (cli, "\n");
    }
  return CLI_SUCCESS;
}

ALI (show_ip_protocols_bgp,
     bgp_show_ip_protocols_bgp_cmd,
     "show ip protocols bgp",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "IP routing protocol process parameters and statistics",
     "Border Gateway Protocol (BGP)");

void
bgp_config_write_filter (struct cli *cli, struct bgp_peer *peer,
                         afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  struct bgp_filter *gfilter = NULL;
  char *addr;
  int in = FILTER_IN;
  int out = FILTER_OUT;
  u_int32_t baai;
  u_int32_t bsai;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  addr = peer->host;
  /* Get the relevant filter as per the bgp instance only if
   * same peer is allowed in multiple-instance */
  if (bgp_option_check(BGP_OPT_MULTI_INS_ALLOW_SAME_PEER)
      && peer->pbgp_node_inctx)
    filter = &peer->pbgp_node_inctx->filter[baai][bsai];
  else
    filter = &peer->filter[baai][bsai];

  if (peer->af_group[baai][bsai])
    gfilter = &peer->group->conf->filter[baai][bsai];

  /* distribute-list. */
  if (filter->dlist[in].name)
    if (! gfilter || ! gfilter->dlist[in].name
        || pal_strcmp (filter->dlist[in].name, gfilter->dlist[in].name) != 0)
      cli_out (cli, " neighbor %s distribute-list %s in\n", addr,
               filter->dlist[in].name);
  if (filter->dlist[out].name && ! gfilter)
    cli_out (cli, " neighbor %s distribute-list %s out\n", addr,
             filter->dlist[out].name);

  /* prefix-list. */
  if (filter->plist[in].name)
    if (! gfilter || ! gfilter->plist[in].name
        || pal_strcmp (filter->plist[in].name, gfilter->plist[in].name) != 0)
      cli_out (cli, " neighbor %s prefix-list %s in\n", addr,
               filter->plist[in].name);
  if (filter->plist[out].name && ! gfilter)
    cli_out (cli, " neighbor %s prefix-list %s out\n", addr,
             filter->plist[out].name);

  /* route-map. */
  if (filter->map[in].name)
    if (! gfilter || ! gfilter->map[in].name
        || pal_strcmp (filter->map[in].name, gfilter->map[in].name) != 0)
      cli_out (cli, " neighbor %s route-map %s in\n", addr,
               filter->map[in].name);
  if (filter->map[out].name && ! gfilter)
    cli_out (cli, " neighbor %s route-map %s out\n", addr,
             filter->map[out].name);

  /* unsuppress-map */
  if (filter->usmap.name && ! gfilter)
    cli_out (cli, " neighbor %s unsuppress-map %s\n", addr,
             filter->usmap.name);

  /* filter-list. */
  if (filter->aslist[in].name)
    if (! gfilter || ! gfilter->aslist[in].name
        || pal_strcmp (filter->aslist[in].name, gfilter->aslist[in].name) != 0)
      cli_out (cli, " neighbor %s filter-list %s in\n", addr,
               filter->aslist[in].name);
  if (filter->aslist[out].name && ! gfilter)
    cli_out (cli, " neighbor %s filter-list %s out\n", addr,
             filter->aslist[out].name);
}

/* BGP peer configuration display function. */
void
bgp_config_write_peer (struct cli *cli,
                       struct bgp *bgp,
                       struct bgp_peer *peer,
                       afi_t afi, safi_t safi)
{
  u_int8_t buf [SU_ADDRSTRLEN];
  struct bgp_peer *g_peer;
  bool_t g_peer_member;
  u_int8_t *addr;
  u_int32_t baai;
  u_int32_t bsai;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  addr = peer->host;

  g_peer = NULL;
  g_peer_member = PAL_FALSE;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      if (peer->group)
        g_peer = peer->group->conf;
      else
        return;

      if (g_peer != peer)
        g_peer_member = PAL_TRUE;
    }

  /* Global to the neighbor i.e. BGP_MODE and IPV4/IPV6 VRF mode */
  if ( (afi == AFI_IP && safi == SAFI_UNICAST)
      ||(afi == AFI_IP6
         && LIB_VRF_GET_VRF_ID (bgp->owning_ivrf) && safi == SAFI_UNICAST) )
    {
      /* remote-as. */
      if (!bgp_peer_group_active (peer))
        {
          if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
            {
              if (!g_peer_member)
                {
                    cli_out (cli, " neighbor %s peer-group\n", addr);
                  
                  if (peer->as)
                    cli_out (cli, " neighbor %s remote-as %u\n",
                             addr, peer->as);

                  if (CHECK_FLAG (peer->config, PEER_FLAG_LOCAL_AS))
                    cli_out (cli, " neighbor %s local-as %u\n",
                             addr, peer->local_as);
                }
            }
          else
            {
              if (peer->as) /* For normal peer */
                 cli_out (cli, " neighbor %s remote-as %u\n",
                          addr, peer->as);

              if (CHECK_FLAG (peer->config, PEER_FLAG_LOCAL_AS))
                 cli_out (cli, " neighbor %s local-as %u\n",
                          addr, peer->local_as);
            }
        }
      else /* For peer-group member */
        {
          if (! g_peer->as)
             cli_out (cli, " neighbor %s remote-as %u\n", addr, peer->as);

          if (CHECK_FLAG (peer->config, PEER_FLAG_LOCAL_AS)
              && !CHECK_FLAG (g_peer->config, PEER_FLAG_LOCAL_AS))
             cli_out (cli, " neighbor %s local-as %u\n",
                      addr, peer->local_as);

          if (peer->af_group[BAAI_IP][BSAI_UNICAST])  
             cli_out (cli, " neighbor %s peer-group %s\n", addr,
                      peer->group->name);

          if (peer->af_group[BAAI_IP6][BSAI_UNICAST])
             cli_out (cli, " neighbor %s peer-group %s\n", addr,
                      peer->group->name);

        }

      /* Description. */
      if (peer->desc)
        cli_out (cli, " neighbor %s description %s\n", addr, peer->desc);

      /* Shutdown. */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! CHECK_FLAG (g_peer->flags, PEER_FLAG_SHUTDOWN))
          cli_out (cli, " neighbor %s shutdown\n", addr);

      /* BGP port. */
      if (peer->sock_port != BGP_PORT_DEFAULT)
        cli_out (cli, " neighbor %s port %d\n",
                 addr, peer->sock_port);

      /* Local interface name. */
      if (peer->ifname)
        cli_out (cli, " neighbor %s interface %s\n", addr, peer->ifname);

      /* Passive. */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_PASSIVE))
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! CHECK_FLAG (g_peer->flags, PEER_FLAG_PASSIVE))
          cli_out (cli, " neighbor %s passive\n", addr);

      /* EBGP multihop.  */
      if (peer_sort (peer) != BGP_PEER_IBGP && peer->ttl != 1)
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || g_peer->ttl != peer->ttl)
          cli_out (cli, " neighbor %s ebgp-multihop %d\n", addr, peer->ttl);

      /* Enforce multihop.  */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_ENFORCE_MULTIHOP))
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! CHECK_FLAG (g_peer->flags, PEER_FLAG_ENFORCE_MULTIHOP))
          cli_out (cli, " neighbor %s enforce-multihop\n", addr);

      /* Update-source. */
      if (peer->update_if)
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! g_peer->update_if
            || pal_strcmp (g_peer->update_if, peer->update_if) != 0)
          cli_out (cli, " neighbor %s update-source %s\n", addr,
                   peer->update_if);
      if (peer->update_source)
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! g_peer->update_source
            || sockunion_cmp (g_peer->update_source,
                              peer->update_source) != 0)
          cli_out (cli, " neighbor %s update-source %s\n", addr,
                   sockunion2str (peer->update_source, buf, SU_ADDRSTRLEN));

#ifdef HAVE_TCP_MD5SIG
      /* Password */
      /* Display the password configuration on a peer only 
         in default VRF mode */ 
      if (CHECK_FLAG (peer->config, PEER_CONFIG_PASSWORD)
          && !LIB_VRF_GET_VRF_ID (bgp->owning_ivrf))
        cli_out (cli, " neighbor %s password %s\n", addr, peer->password);
#endif /* TCP_MD5SIG */

      /* BGP version */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_VERSION_CHECK))
          if (! bgp_peer_group_active (peer) && !g_peer_member)
          cli_out (cli, " neighbor %s version %d\n", addr, peer->version);

     /* AS-Origination-interval */
      if (CHECK_FLAG (peer->config, PEER_CONFIG_ASORIG)
          && (! bgp_peer_group_active (peer) && !g_peer_member))
        cli_out (cli, " neighbor %s as-origination-interval %lu\n",
                 addr, peer->v_asorig);

      /* advertisement-interval */
      if (CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV))
        {
          if (! peer->af_group[baai][bsai] ||
             (g_peer_member && g_peer->v_routeadv != peer->v_routeadv))
        cli_out (cli, " neighbor %s advertisement-interval %lu\n",
                 addr, peer->v_routeadv);
        }

      /* timers. */
      if (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER)
          && (! bgp_peer_group_active (peer) && !g_peer_member))
        cli_out (cli, " neighbor %s timers %lu %lu\n", addr,
                 peer->keepalive, peer->holdtime);

      if (CHECK_FLAG (peer->config, PEER_CONFIG_CONNECT))
        cli_out (cli, " neighbor %s timers connect %lu\n", addr,
                 peer->connect);

      /* disallow-infinite-holdtime */
      if (CHECK_FLAG (peer->flags, PEER_DISALLOW_INFINITE_HOLD_TIME)
          && !LIB_VRF_GET_VRF_ID (bgp->owning_ivrf)
          && (! bgp_peer_group_active (peer) && !g_peer_member))
        cli_out (cli, " neighbor %s disallow-infinite-holdtime\n", addr);

      /* Display the weight only if it is not default weight. */
      if (peer->weight[baai][bsai] != BGP_DEFAULT_WEIGHT)
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || g_peer->weight[baai][bsai] != peer->weight[baai][bsai])
          cli_out (cli, " neighbor %s weight %lu\n", addr, 
		   peer->weight[baai][bsai]);
     
      /* Collide Established */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_COLLIDE_ESTABLISHED))
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! CHECK_FLAG (g_peer->flags, PEER_FLAG_COLLIDE_ESTABLISHED))
          cli_out (cli, " neighbor %s collide-established\n", addr);

      /* Route refresh. */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_NO_ROUTE_REFRESH_CAP))
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! CHECK_FLAG (g_peer->flags, PEER_FLAG_NO_ROUTE_REFRESH_CAP))
          cli_out (cli, " no neighbor %s capability route-refresh\n", addr);

      /* Dynamic capability.  */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_DYNAMIC_CAPABILITY))
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! CHECK_FLAG (g_peer->flags, PEER_FLAG_DYNAMIC_CAPABILITY))
          cli_out (cli, " neighbor %s capability dynamic\n", addr);

      /* dont capability negotiation. */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_DONT_CAPABILITY))
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! CHECK_FLAG (g_peer->flags, PEER_FLAG_DONT_CAPABILITY))
          cli_out (cli, " neighbor %s dont-capability-negotiate\n", addr);

      /* override capability negotiation. */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! CHECK_FLAG (g_peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
          cli_out (cli, " neighbor %s override-capability\n", addr);

      /* strict capability negotiation. */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_STRICT_CAP_MATCH))
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
            || ! CHECK_FLAG (g_peer->flags, PEER_FLAG_STRICT_CAP_MATCH))
          cli_out (cli, " neighbor %s strict-capability-match\n", addr);

      /* In the default VRF display peer's active state*/
      if (!LIB_VRF_GET_VRF_ID (bgp->owning_ivrf))
        {
          if (bgp_config_check (bgp, BGP_CFLAG_NO_DEFAULT_IPV4))
            {
              if (peer->afc[BAAI_IP][BSAI_UNICAST])
                cli_out (cli, " neighbor %s activate\n", addr);
            }
          else
            {
              if (! peer->afc[BAAI_IP][BSAI_UNICAST])
                cli_out (cli, " no neighbor %s activate\n", addr);
            }
        }
      /* In the VRF mode display the peer's active state */
/*      if (LIB_VRF_GET_VRF_ID (bgp->owning_ivrf)) */
      else
        {
          if (peer->afc[baai][BSAI_UNICAST])
            cli_out (cli, " neighbor %s activate\n", addr);
          else 
            cli_out (cli, " no neighbor %s activate\n", addr);
        }
    } /* end of if (afi == AFI_IP) */

  /* Per AF to the neighbor */
  /* Diplay the peer configuration per address-family 
     only in default VRF mode. By default the AFI is IPV4-UNICAST,
     so no need to display address-family for IPV4. But this control
     should get to this block for address-family ipv6 unicast */ 
  if ( !(afi == AFI_IP && safi == SAFI_UNICAST)
      && !(afi == AFI_IP6 && LIB_VRF_GET_VRF_ID (bgp->owning_ivrf)
            && safi == SAFI_UNICAST) )
    {
      if (peer->weight[baai][bsai] != BGP_DEFAULT_WEIGHT)
        if ((! bgp_peer_group_active (peer) && !g_peer_member)
             || (g_peer && g_peer->weight[baai][bsai] != peer->weight[baai][bsai]))
          cli_out (cli, " neighbor %s weight %lu\n", addr, 
		   peer->weight[baai][bsai]);

      if (peer->af_group[baai][bsai])
        cli_out (cli, " neighbor %s peer-group %s\n", addr,
                 peer->group->name);
      else
        {
          cli_out (cli, " neighbor %s activate\n", addr);
       }
    }

  /* ORF capability.  */
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_ORF_PREFIX_SM)
      || CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_ORF_PREFIX_RM))
    if (! peer->af_group[baai][bsai])
      {
        cli_out (cli, " neighbor %s capability orf prefix-list", addr);

        if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_ORF_PREFIX_SM)
            && CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_ORF_PREFIX_RM))
          cli_out (cli, " both");
        else if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_ORF_PREFIX_SM))
          cli_out (cli, " send");
        else
          cli_out (cli, " receive");
        cli_out (cli, "\n");
      }

  /* Route reflector client. */
  if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_REFLECTOR_CLIENT)
      && ! peer->af_group[baai][bsai])
    cli_out (cli, " neighbor %s route-reflector-client\n", addr);

  /* Nexthop self. */
  if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_NEXTHOP_SELF)
      && ! peer->af_group[baai][bsai])
    cli_out (cli, " neighbor %s next-hop-self\n", addr);

  /* Remove private AS. */
  if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS)
      && ! peer->af_group[baai][bsai])
    cli_out (cli, " neighbor %s remove-private-AS\n", addr);

  /* send-community print. */
  if (! peer->af_group[baai][bsai])
    {
      if (bgp_option_check (BGP_OPT_CONFIG_STANDARD))
        {
          if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_SEND_COMMUNITY)
              && peer_af_flag_check (peer, afi, safi, PEER_FLAG_SEND_EXT_COMMUNITY))
            cli_out (cli, " neighbor %s send-community both\n", addr);
          else if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_SEND_EXT_COMMUNITY))        
            cli_out (cli, " neighbor %s send-community extended\n", addr);
          else if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_SEND_COMMUNITY))
            cli_out (cli, " neighbor %s send-community\n", addr);
        }
      else
        {
          if (! peer_af_flag_check (peer, afi, safi, PEER_FLAG_SEND_COMMUNITY)
              && ! peer_af_flag_check (peer, afi, safi, PEER_FLAG_SEND_EXT_COMMUNITY))
            cli_out (cli, " no neighbor %s send-community both\n", addr);
          else if (! peer_af_flag_check (peer, afi, safi, PEER_FLAG_SEND_EXT_COMMUNITY))
            cli_out (cli, " no neighbor %s send-community extended\n", addr);
          else if (! peer_af_flag_check (peer, afi, safi, PEER_FLAG_SEND_COMMUNITY))
            cli_out (cli, " no neighbor %s send-community\n", addr);
        }
    }

  /* Default information */
  if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_DEFAULT_ORIGINATE)
      && ! peer->af_group[baai][bsai])
    {
      cli_out (cli, " neighbor %s default-originate", addr);
      if (peer->default_rmap[baai][bsai].name)
        cli_out (cli, " route-map %s", peer->default_rmap[baai][bsai].name);
      cli_out (cli, "\n");
    }

  /* Soft reconfiguration inbound. */
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_SOFT_RECONFIG))
    if (! peer->af_group[baai][bsai] ||
        ! ( g_peer && CHECK_FLAG (g_peer->af_flags[baai][bsai], PEER_FLAG_SOFT_RECONFIG)))
      cli_out (cli, " neighbor %s soft-reconfiguration inbound\n", addr);

  /* maximum-prefix. */
  if (peer->pmax[baai][bsai])
    if (! peer->af_group[baai][bsai]
        || (g_peer && (g_peer->pmax[baai][bsai] != peer->pmax[baai][bsai]
        || g_peer->threshold[baai][bsai] != peer->threshold[baai][bsai]
        || CHECK_FLAG (g_peer->af_flags[baai][bsai], PEER_FLAG_MAX_PREFIX_WARNING)
        != CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_MAX_PREFIX_WARNING))))
      {
        cli_out (cli, " neighbor %s maximum-prefix %lu",
                 addr, peer->pmax[baai][bsai]);
        if (peer->threshold[baai][bsai] != BGP_DEFAULT_MAX_PREFIX_THRESHOLD)
          cli_out (cli, " %ld", peer->threshold[baai][bsai]);
        if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_MAX_PREFIX_WARNING))
          cli_out (cli, " warning-only");
        cli_out (cli, "\n");
      }

  /* Route server client. */
  if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_RSERVER_CLIENT)
      && ! peer->af_group[baai][bsai])
    cli_out (cli, " neighbor %s route-server-client\n", addr);

  /* Allow AS in.  */
  if (g_peer && peer_af_flag_check (peer, afi, safi, PEER_FLAG_ALLOWAS_IN))
    if (! bgp_peer_group_active (peer)
        || ! peer_af_flag_check (g_peer, afi, safi, PEER_FLAG_ALLOWAS_IN)
        || peer->allowas_in[baai][bsai] != g_peer->allowas_in[baai][bsai])
      {
        if (peer->allowas_in[baai][bsai] == 3)
          cli_out (cli, " neighbor %s allowas-in\n", addr);
        else
          cli_out (cli, " neighbor %s allowas-in %d\n", addr,
                   peer->allowas_in[baai][bsai]);
      }

  /* Filter. */
  if (bgp_option_check(BGP_OPT_MULTI_INS_ALLOW_SAME_PEER)
      && peer->peer_bgp_node_list)
    {
      struct peer_bgp_node *pbgp_node = NULL;
      struct listnode *node = NULL;
      
      LIST_LOOP (peer->peer_bgp_node_list, pbgp_node, node)
        {
          if (pbgp_node->bgp == bgp)
            {
              peer->pbgp_node_inctx = pbgp_node;
              break;
            }
        }
    }
  bgp_config_write_filter (cli, peer, afi, safi);

  if (bgp_option_check(BGP_OPT_MULTI_INS_ALLOW_SAME_PEER)
      && peer->pbgp_node_inctx)
    peer->pbgp_node_inctx = NULL;

  /* atribute-unchanged. */
  if ((CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_AS_PATH_UNCHANGED)
       || CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_NEXTHOP_UNCHANGED)
       || CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_MED_UNCHANGED))
      && ! peer->af_group[baai][bsai])
    {
      if (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_AS_PATH_UNCHANGED)
          && CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_NEXTHOP_UNCHANGED)
          && CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_MED_UNCHANGED))
        cli_out (cli, " neighbor %s attribute-unchanged\n", addr);
      else
        cli_out (cli, " neighbor %s attribute-unchanged%s%s%s\n", addr,
                 (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_AS_PATH_UNCHANGED)) ?
                 " as-path" : "",
                 (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_NEXTHOP_UNCHANGED)) ?
                 " next-hop" : "",
                 (CHECK_FLAG (peer->af_flags[baai][bsai], PEER_FLAG_MED_UNCHANGED)) ?
                 " med" : "");
    }

  return;
}

/* Display "address-family" configuration header. */
void
bgp_config_write_family_header (struct cli *cli,
                                afi_t afi, safi_t safi,
                                u_int32_t *write)
{
  if (*write)
    return;

  if (afi == AFI_IP && safi == SAFI_UNICAST)
    return;

  cli_out (cli, " !\n address-family ");

  if (afi == AFI_IP)
    {
      if (safi == SAFI_MULTICAST)
        cli_out (cli, "ipv4 multicast");
    }
  else if (afi == AFI_IP6)
    {
      cli_out (cli, "ipv6");
    }
  cli_out (cli, "\n");

  *write = 1;
}

/* BGP Synchronization and Auto-summary configuration */
u_int32_t
bgp_config_write_sync_auto_summary (struct cli *cli,
                                    struct bgp *bgp,
                                    afi_t afi,
                                    safi_t safi,
                                    u_int32_t *write)
{
  if (bgp_af_config_check (bgp, afi, safi, BGP_AF_CFLAG_SYNCHRONIZATION))
    {
      /* "address-family" display.  */
      bgp_config_write_family_header (cli, afi, safi, write);

      cli_out (cli, " synchronization\n");
    }

  if (bgp_af_config_check (bgp, afi, safi, BGP_AF_CFLAG_AUTO_SUMMARY))
    {
      /* "address-family" display.  */
      bgp_config_write_family_header (cli, afi, safi, write);

      cli_out (cli, " auto-summary\n");
    }

  return *write;
}

/* BGP Network routes and aggregates configuration */
void
bgp_config_write_network (struct cli *cli, struct bgp *bgp,
                          afi_t afi, safi_t safi, u_int32_t *write)
{
  struct bgp_aggregate *aggregate;
  struct bgp_static *bstatic;
  struct bgp_node *rn;
  struct prefix *p;
  u_int32_t baai;
  u_int32_t bsai;
  struct prefix rnp;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  /* Network Synchronization */
  if (bgp_af_config_check (bgp, afi, safi, BGP_AF_CFLAG_NETWORK_SYNC))
    {
      /* "address-family" display.  */
      bgp_config_write_family_header (cli, afi, safi, write);

      cli_out (cli, " network synchronization\n");
    }

  /* Network configuration. */
  for (rn = bgp_table_top (bgp->route [baai][bsai]); rn;
       rn = bgp_route_next (rn))
    if ((bstatic = rn->info) != NULL)
      {
        BGP_GET_PREFIX_FROM_NODE (rn);
        p = &rnp;

        /* "address-family" display.  */
        bgp_config_write_family_header (cli, afi, safi, write);

        /* "network" configuration display.  */
        if (bgp_option_check (BGP_OPT_CONFIG_STANDARD) && afi == AFI_IP)
          {
            u_int32_t destination;
            struct pal_in4_addr netmask;

            destination = pal_ntoh32 (p->u.prefix4.s_addr);
            masklen2ip (p->prefixlen, &netmask);

            cli_out (cli, " network %r", &p->u.prefix4);

            if ((IN_CLASSC (destination)
                 && p->prefixlen == IN_CLASSC_PREFIXLEN)
                || (IN_CLASSB (destination)
                    && p->prefixlen == IN_CLASSB_PREFIXLEN)
                || (IN_CLASSA (destination)
                    && p->prefixlen == IN_CLASSA_PREFIXLEN)
                || p->u.prefix4.s_addr == 0)
              ; /* Natural mask is not display. */
            else
              cli_out (cli, " mask %r", &netmask);
          }
        else
          cli_out (cli, " network %O", p);

        if (bstatic->bs_rmap.name)
          cli_out (cli, " route-map %s", bstatic->bs_rmap.name);

        if (bstatic->bs_backdoor)
          cli_out (cli, " backdoor");

        cli_out (cli, "\n");
      }

  /* Aggregate-address configuration. */
  for (rn = bgp_table_top (bgp->aggregate [baai][bsai]); rn;
       rn = bgp_route_next (rn))
    if ((aggregate = rn->info) != NULL)
      {
        BGP_GET_PREFIX_FROM_NODE (rn);
        p = &rnp;

        /* "address-family" display.  */
        bgp_config_write_family_header (cli, afi, safi, write);

        cli_out (cli, " aggregate-address %O", p);

        if (aggregate->as_set)
          cli_out (cli, " as-set");

        if (aggregate->summary_only)
          cli_out (cli, " summary-only");

        cli_out (cli, "\n");
      }
}

/* Redistribute configuration */
u_int32_t
bgp_config_write_redistribute (struct cli *cli,
                               struct bgp *bgp,
                               afi_t afi,
                               safi_t safi,
                               u_int32_t *write)
{
  u_int8_t *str[] = { "system", "kernel", "connected",
                      "static", "rip", "rip", "ospf",
                      "ospf", "bgp", "isis", "trill" };
  u_int32_t idx;

  if (safi != SAFI_UNICAST) 
    return 0;

  for (idx = 0; idx < IPI_ROUTE_MAX; idx++)
    {
      if (idx != IPI_ROUTE_BGP
          && bgp->redist [BGP_AFI2BAAI (afi)][idx])
        {
          /* Address family display */
          bgp_config_write_family_header (cli, afi, safi, write);

          cli_out (cli, " redistribute %s", str[idx]);

          if (bgp->rmap[BGP_AFI2BAAI (afi)][idx].name)
            cli_out (cli, " route-map %s",
                     bgp->rmap[BGP_AFI2BAAI (afi)][idx].name);

          cli_out (cli, "\n");
        }
    }
  return *write;
}

/* Address family based configuration */
u_int32_t
bgp_config_write_family (struct cli *cli, struct bgp *bgp,
                         afi_t afi, safi_t safi)
{
  struct bgp_peer_group *group;
  struct bgp_peer *peer;
  struct list *groupl;
  struct listnode *nn;
  u_int32_t write;
  struct peer_bgp_node *pbgp_node = NULL;
  struct listnode *node = NULL;
  u_int32_t baai;
  u_int32_t bsai;

  write = 0;
  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI(safi);

  bgp_config_write_sync_auto_summary (cli, bgp, afi, safi, &write);

  bgp_config_write_network (cli, bgp, afi, safi, &write);

  bgp_config_write_redistribute (cli, bgp, afi, safi, &write);
  
  bgp_config_write_distance (cli, bgp, BGP_AFI2BAAI (afi), 
                             BGP_SAFI2BSAI (safi), &write);

  /* BGP route flap dampening */
  bgp_rfd_config_write (cli, bgp, afi, safi, &write);

  groupl = bgp->group_list;

  LIST_LOOP (groupl, group, nn)
    {
      if (group->conf->afc [baai]
                           [bsai])
        {
          bgp_config_write_family_header (cli, afi, safi, &write);
          bgp_config_write_peer (cli, bgp, group->conf, afi, safi);
        }
    }
  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      /* If same peer is allowed in multiple bgp instances then 
       * display the information relvant to the particular bgp view
      */
      if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER)
          && (peer->peer_bgp_node_list))
        {
          LIST_LOOP (peer->peer_bgp_node_list, pbgp_node, node)
            {
              if (pbgp_node->bgp != bgp)
                continue;

              if (pbgp_node->bgp == bgp
                  && pbgp_node->afc[baai][bsai])
                {
                  bgp_config_write_family_header (cli, afi, safi, &write);
                  bgp_config_write_peer (cli, bgp, peer, afi, safi);
                  break;
                }
            }
        }
      else if (peer->afc[baai][bsai])
        {
          bgp_config_write_family_header (cli, afi, safi, &write);
          bgp_config_write_peer (cli, bgp, peer, afi, safi);
        }
    }

  if (write)
    cli_out (cli, " exit-address-family\n");

  return write;
}

/* Distance configuration. */
s_int32_t
bgp_config_write_distance (struct cli *cli, struct bgp *bgp, afi_t baai, 
			   safi_t bsai, u_int32_t *write)
{
  struct bgp_distance *bdistance;
  struct bgp_node *rn;
  struct prefix rnp;

  /* Write the distance only if ebgp_distance, ibgp_distance and
   * local_distance's are not null and atleast one of them is not
   * a default distance 
   */
  if (bgp->distance_ebgp[baai][bsai]
      && bgp->distance_ibgp[baai][bsai]
      && bgp->distance_local[baai][bsai]
      && (bgp->distance_ebgp[baai][bsai] != IPI_DISTANCE_EBGP
      || bgp->distance_ibgp[baai][bsai] != IPI_DISTANCE_IBGP
      || bgp->distance_local[baai][bsai] != IPI_DISTANCE_IBGP))
    {
      bgp_config_write_family_header (cli, BGP_BAAI2AFI(baai), 
				      BGP_BSAI2SAFI(bsai), write);
      cli_out (cli, " distance bgp %d %d %d\n",
               bgp->distance_ebgp[baai][bsai],
               bgp->distance_ibgp[baai][bsai],
               bgp->distance_local[baai][bsai]);
    }

  /* Currently we support only IPv4 unicast address family for the command
   * 'distance <1-255> A.B.C.D/M'.
   */
  if ((baai != BAAI_IP) || (bsai != BSAI_UNICAST)) 
   return *write;

  for (rn = bgp_table_top (bgp->distance_table); rn;
       rn = bgp_route_next (rn))
    if ((bdistance = rn->info) != NULL)
      {
        BGP_GET_PREFIX_FROM_NODE (rn);
        cli_out (cli, " distance %d %O %s\n",
                 bdistance->distance, &rnp,
                 bdistance->access_list ?
                 bdistance->access_list : (u_int8_t *) "");
      } 

  return *write;
}

s_int32_t
bgp_config_write_bgp_instance (struct cli *cli, struct bgp *bgp)
{
  struct bgp_peer_group *group;
  struct bgp_peer *peer;
  struct listnode *nn;
  u_int32_t write;

  write = 0;

  if (! cli || ! bgp)
    goto EXIT;

  if (! bgp->as)
    goto EXIT;

  if (write)
    cli_out (cli, "!\n");

  /* Router bgp ASN */
  cli_out (cli, "router bgp %u", bgp->as);

  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE) )
    {
      if (bgp->name)
        cli_out (cli, " view %s", bgp->name);
    }
  cli_out (cli, "\n");

  /* BGP fast-external-failover. */
  if (bgp_config_check (bgp, BGP_CFLAG_NO_FAST_EXT_FAILOVER))
    cli_out (cli, " no bgp fast-external-failover\n");

  /* BGP router ID. */
  if (bgp_config_check (bgp, BGP_CFLAG_ROUTER_ID))
    cli_out (cli, " bgp router-id %r\n", &bgp->router_id);

  /* BGP configuration. */
  if (bgp_config_check (bgp, BGP_CFLAG_ALWAYS_COMPARE_MED))
    cli_out (cli, " bgp always-compare-med\n");

  /* BGP default ipv4-unicast. */
  if (bgp_config_check (bgp, BGP_CFLAG_NO_DEFAULT_IPV4))
    cli_out (cli, " no bgp default ipv4-unicast\n");

  /* BGP default local-preference. */
  if (bgp->default_local_pref != BGP_DEFAULT_LOCAL_PREF)
    cli_out (cli, " bgp default local-preference %lu\n",
             bgp->default_local_pref);

  /* BGP client-to-client reflection. */
  if (bgp_config_check (bgp, BGP_CFLAG_NO_CLIENT_TO_CLIENT))
    cli_out (cli, " no bgp client-to-client reflection\n");

  /* BGP cluster ID. */
  if (bgp_config_check (bgp, BGP_CFLAG_CLUSTER_ID))
    {
      if (bgp_config_check (bgp, BGP_CFLAG_CLUSTER_ID_DIGIT))
        cli_out (cli, " bgp cluster-id %u\n",
                 pal_ntoh32 (bgp->cluster_id.s_addr));
      else
        cli_out (cli, " bgp cluster-id %r\n", &bgp->cluster_id);
    }

  /* Confederation Information */
  if (bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION))
    cli_out (cli, " bgp confederation identifier %i\n",
             bgp->confed_id);

  if (bgp->confed_peers_cnt > 0)
    {
      int i;

      cli_out (cli, " bgp confederation peers");

      for (i = 0; i < bgp->confed_peers_cnt; i++)
        {
          cli_out(cli, " ");
          cli_out(cli, "%d", bgp->confed_peers[i]);
        }
      cli_out (cli, "\n");
    }

  /* BGP enforce-first-as. */
  if (bgp_config_check (bgp, BGP_CFLAG_ENFORCE_FIRST_AS))
    cli_out (cli, " bgp enforce-first-as\n");

  /* BGP deterministic-med. */
  if (bgp_config_check (bgp, BGP_CFLAG_DETERMINISTIC_MED))
    cli_out (cli, " bgp deterministic-med\n");

  /* BGP Multipath */
  if (bgp->cfg_maxpath_ebgp > 1)
    cli_out (cli, " max-paths ebgp %d\n", bgp->cfg_maxpath_ebgp);
  if (bgp->cfg_maxpath_ibgp > 1)
    cli_out (cli, " max-paths ibgp %d\n", bgp->cfg_maxpath_ibgp);

  /* as-local-count */
  if (bgp->aslocal_count > 1)
    cli_out (cli, " bgp as-local-count %d\n", bgp->aslocal_count);
  /* BGP bestpath method. */
  if (bgp_config_check (bgp, BGP_CFLAG_ASPATH_IGNORE))
    cli_out (cli, " bgp bestpath as-path ignore\n");
  if (bgp_config_check (bgp, BGP_CFLAG_COMPARE_CONFED_ASPATH))
    cli_out (cli, " bgp bestpath compare-confed-aspath\n");
  if (bgp_config_check (bgp, BGP_CFLAG_COMPARE_ROUTER_ID))
    cli_out (cli, " bgp bestpath compare-routerid\n");
  if (bgp_config_check (bgp, BGP_CFLAG_DONT_COMP_ORIG_ID))
    cli_out (cli, " bgp bestpath dont-compare-originator-id\n");
  if (!bgp_config_check (bgp, BGP_CFLAG_PREFER_OLD_ROUTE))
    cli_out (cli, " no bgp bestpath tie-break-on-age\n");
  if (bgp_config_check (bgp, BGP_CFLAG_MED_REMOVE_RCVD)
      || bgp_config_check (bgp, BGP_CFLAG_MED_REMOVE_SEND)
      || bgp_config_check (bgp, BGP_CFLAG_MED_CONFED)
      || bgp_config_check (bgp, BGP_CFLAG_MED_MISSING_AS_WORST))
    {
      cli_out (cli, " bgp bestpath med");
      if (bgp_config_check (bgp, BGP_CFLAG_MED_CONFED))
        cli_out (cli, " confed");
      if (bgp_config_check (bgp, BGP_CFLAG_MED_MISSING_AS_WORST))
        cli_out (cli, " missing-as-worst");
      if (bgp_config_check (bgp, BGP_CFLAG_MED_REMOVE_RCVD))
        cli_out (cli, " remove-recv-med");
      if (bgp_config_check (bgp, BGP_CFLAG_MED_REMOVE_SEND))
        cli_out (cli, " remove-send-med");
      cli_out (cli, "\n");
    }

  /* BGP log neighbor changes.  */
  if (bgp_config_check (bgp, BGP_CFLAG_LOG_NEIGHBOR_CHANGES))
    cli_out (cli, " bgp log-neighbor-changes\n");

  /* BGP route flap dampening */
  bgp_rfd_config_write (cli, bgp, AFI_IP, SAFI_UNICAST, &write);

  /* BGP Synchronization and Auto-summary */
  bgp_config_write_sync_auto_summary (cli, bgp, AFI_IP,
                                      SAFI_UNICAST, &write);

  /* BGP static network configuration */
  bgp_config_write_network (cli, bgp, AFI_IP, SAFI_UNICAST, &write);

  /* BGP redistribute configuration. */
  bgp_config_write_redistribute (cli, bgp, AFI_IP, SAFI_UNICAST, &write);

  /* BGP timers configuration. */
  if (bgp_config_check (bgp, BGP_CFLAG_DEFAULT_TIMER))
    cli_out (cli, " timers bgp %lu %lu\n",
             bgp->default_keepalive, bgp->default_holdtime);

  /* peer-group */
  LIST_LOOP (bgp->group_list, group, nn)
    bgp_config_write_peer (cli, bgp, group->conf,
                           AFI_IP, SAFI_UNICAST);

  /* Normal neighbor configuration. */
  LIST_LOOP (bgp->peer_list, peer, nn)
    bgp_config_write_peer (cli, bgp, peer,
                           AFI_IP, SAFI_UNICAST);

  /* Distance configuration.  */
  bgp_config_write_distance (cli, bgp, BAAI_IP, BSAI_UNICAST, &write);

  /* IPv4 multicast configuration.  */
  write += bgp_config_write_family (cli, bgp, AFI_IP,
                                    SAFI_MULTICAST);

  /* IPv6 unicast configuration.  */
  write += bgp_config_write_family (cli, bgp, AFI_IP6, SAFI_UNICAST);

  write++;

EXIT:

  return write;
}

s_int32_t
bgp_vr_config_write (struct cli *cli)
{
  s_int32_t write;

  write = 0;

  /*
   * BGP Virtual-router Level Configuration
   */
  
  /* BGP same peer in multiple instance */
  if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
    {
      cli_out (cli, "bgp multiple-instance allow-same-peer\n");
      write++;
    }
  /* BGP Multiple instance.  */
  else if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      cli_out (cli, "bgp multiple-instance\n");
      write++;
    }

  /* BGP Config type. */
  if (bgp_option_check (BGP_OPT_CONFIG_STANDARD))
    {
      cli_out (cli, "bgp config-type standard\n");
      write++;
    }

  /* RFC1771 path selection. */
  if (bgp_option_check (BGP_OPT_RFC1771_PATH_SELECT))
    {
      cli_out (cli, "bgp rfc1771-path-select\n");
      write++;
    }

  /* RFC1771 strict mode. */
  if (bgp_option_check (BGP_OPT_RFC1771_STRICT))
    {
      cli_out (cli, "bgp rfc1771-strict\n");
      write++;
    }

  /* Aggregation with next hop check. */
  if (bgp_option_check (BGP_OPT_AGGREGATE_NEXTHOP_CHECK))
    {
      cli_out (cli, "bgp aggregate-nexthop-check\n");
      write++;
    }

  /* 4-octet ASN extended capability */
  if (bgp_option_check (BGP_OPT_EXTENDED_ASN_CAP))
    {
      cli_out (cli, "bgp extended-asn-cap \n");
      write ++;
    } 
  
  if (bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
    {
      cli_out (cli, "bgp disable-adj-out \n");
      write ++;
    }  

  return write;
}

s_int32_t
bgp_config_write (struct cli *cli)
{
  struct listnode *nn;
  struct bgp *bgp;
  s_int32_t write;
#ifdef HAVE_BGP_SDN
  int i;
#endif /* HAVE_BGP_SDN */

  bgp = NULL;
  write = 0;
  /*
   * BGP Instance Specific Configuration
   */

  bgp = bgp_lookup_default ();

  if (! bgp)
    goto EXIT;

#ifdef HAVE_BGP_SDN
  for (i = 0; i < BGP_MAX_SDN_CLIENT; i++)
    {
      if (bgp_sdn_addr[i]) 
        cli_out (cli, "bgp sdn-engine %d %s %d\n", i+1,
		       bgp_sdn_addr[i], bgp_sdn_port[i]);
    }

  if (bgp_rest_addr)
    cli_out (cli, "bgp rest-server %s %s\n", bgp_rest_addr, bgp_rest_port);
#endif /* HAVE_BGP_SDN */

  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE) )
    {
      LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
        write += bgp_config_write_bgp_instance (cli, bgp);
    }
  else
    {
      write += bgp_config_write_bgp_instance (cli, bgp);
    }

EXIT:

  return write;
}

/* BGP Show Commands Initialization  */
void
bgp_show_init (void)
{
  /* Install BGP configuration function.  */
  cli_install_config (BLG.ctree, BGP_MODE, bgp_config_write);
  cli_install_config (BLG.ctree, VR_MODE, bgp_vr_config_write);

  /* "show ip bgp"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_cli);

  /* "show ip bgp A.B.C.D"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_route_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_route_cli);

  /* "show ip bgp A.B.C.D/M"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_prefix_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_prefix_cli);

  /* XXX */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_view_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_view_route_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_view_prefix_cli);

  /* "show ip bgp regexp LINE"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_regexp_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_regexp_cli);

  /* "show ip bgp quote-regexp WORD"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_quote_regexp_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_quote_regexp_cli);

  /* "show ip bgp prefix-list"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_prefix_list_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_prefix_list_cli);

  /* "show ip bgp filter-list"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_filter_list_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_filter_list_cli);

  /* "show ip bgp route-map WORD"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_route_map_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_route_map_cli);

  /* "show ip bgp cidr-only"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_cidr_only_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_cidr_only_cli);

  /* "show ip bgp community"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_community_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_community_cli);

  /* "show ip bgp community AA:NN (exact-match|)"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_community_val_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_community_val_cli);

  /* "show bgp community-list WORD (exact-match|)"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_community_list_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_community_list_cli);

  /* "show ip bgp A.B.C.D/M longer-prefixes"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_prefix_longer_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_prefix_longer_cli);

  /* "show ip bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_neighbor_advertised_route_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_neighbor_advertised_route_cli);

  /* "show ip bgp neighbors (A.B.C.D|X:X::X:X) received-routes"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_neighbor_received_routes_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_neighbor_received_routes_cli);

  /* "show ip bgp neighbors (A.B.C.D|X:X::X:X) routes"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_neighbor_routes_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_neighbor_routes_cli);

  /* "show ip bgp neighbors (A.B.C.D|X:X::X:X) received prefix-filter"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_neighbor_received_prefix_filter_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_neighbor_received_prefix_filter_cli);

  /* "show ip bgp dampened-paths"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_dampened_path_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_dampened_path_cli);

  /* "show ip bgp flap-statistics"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_flap_statistics_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_flap_statistics_cli);

  /* "show ip bgp dampening parameters"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_damp_params_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_damp_params_cli);

  /* "show ip bgp inconsistent-as"  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_inconsistent_as_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_safi_inconsistent_as_cli);

  /* "show ip bgp summary" commands. */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_summary_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_instance_summary_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_ipv4_summary_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_instance_ipv4_summary_cli);

  /* "show ip bgp neighbors" commands. */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_neighbors_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_ipv4_neighbors_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_neighbors_peer_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_ipv4_neighbors_peer_cli);

/***************************************************************************************/

  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_neighbors_peer_time_cli);
  
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_neighbors_peer_msgcounter_cli);

/***************************************************************************************/

  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_instance_neighbors_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_instance_neighbors_peer_cli);

  /* "show ip bgp paths" commands. */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_paths_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_ipv4_paths_cli);

  /* "show ip bgp community-info" commands. */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_community_info_cli);

  /* "show ip bgp attribute-info" commands. */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_bgp_attr_info_cli);

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      /* IPv6 BGP CLIs.  */

      /* "show bgp" */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_safi_cli);

      /* "show bgp X:X::X:X" */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_route_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_route_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_route_safi_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv4_route_safi_cli);

      /* "show bgp X:X::X:X/M" */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_prefix_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_prefix_safi_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv4_prefix_safi_cli);

      /* "show bgp regexp LINE"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_regexp_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_regexp_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_regexp_safi_cli);

      /* "show bgp quote-regexp WORD"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_quote_regexp_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_quote_regexp_safi_cli);

      /* "show bgp prefix-list"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_prefix_list_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_prefix_list_safi_cli);

      /* "show bgp filter-list"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_filter_list_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_filter_list_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_filter_list_safi_cli);

      /* "show bgp route-map WORD"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_route_map_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_route_map_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_route_map_safi_cli);

      /* "show bgp community"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_community_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_community_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_community_safi_cli);

      /* "show bgp community AA:NN (exact-match|)"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_community_val_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_community_val_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_community_val_safi_cli);

      /* "show bgp community-list WORD (exact-match|)"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_community_list_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_community_list_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_community_list_safi_cli);

      /* "show bgp X:X::X:X/M longer-prefixes"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_prefix_longer_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_prefix_longer_safi_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv4_prefix_longer_safi_cli);

      /* "show bgp dampened-paths"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_dampened_path_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_dampened_path_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_dampened_path_safi_cli);

      /* "show bgp flap-statistics"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_flap_statistics_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_flap_statistics_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_flap_statistics_safi_cli);

      /* "show bgp flap-statistics"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_damp_params_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_damp_params_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_damp_params_safi_cli);

      /* "show bgp inconsistent-as"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_inconsistent_as_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_inconsistent_as_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_inconsistent_as_safi_cli);

      /* "show bgp neighbors (A.B.C.D|X:X::X:X) routes"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_neighbor_routes_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_neighbor_routes_safi_cli);

      /* "show bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_neighbor_advertised_route_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_neighbor_advertised_route_safi_cli);

      /* "show bgp neighbors (A.B.C.D|X:X::X:X) received-routes"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_neighbor_received_routes_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_neighbor_received_routes_safi_cli);

      /* "show bgp neighbors (A.B.C.D|X:X::X:X) received prefix-filter"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_neighbor_received_prefix_filter_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_neighbor_received_prefix_filter_safi_cli);

      /* "show bgp paths" */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_paths_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_paths_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_paths_safi_cli);

      /* "show bgp neighbor"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_neighbors_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_neighbors_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_neighbors_safi_cli);

      /* "show bgp neighbor X:X::X:X"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_neighbors_peer_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_neighbors_peer_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_neighbors_peer_safi_cli);

      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_ipv6_view_cli);
      /* "show bgp summary"  */
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_summary_cli);
      cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                       &show_bgp_afi_summary_safi_cli);
    }
#endif /* HAVE_IPV6 */

  /* "show ip protocols" commands.  */
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_show_ip_protocols_cmd);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_show_ip_protocols_bgp_cmd);

  return;
}
