/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/* Utility function to get AFI from CLI Mode */
afi_t
bgp_cli_mode_afi (struct cli *cli)
{
  if (cli->mode == BGP_IPV6_MODE)
    return AFI_IP6;
  return AFI_IP;
}

/* Utility function to get SAFI from CLI Mode */
safi_t
bgp_cli_mode_safi (struct cli *cli)
{
  if (cli->mode == BGP_IPV4M_MODE)
    return SAFI_MULTICAST;

  return SAFI_UNICAST;
}

/* Utility function to convert String to AFI */
afi_t
bgp_cli_str2afi (u_int8_t *str)
{
  if (pal_strncmp (str, "ipv4", 4) == 0)
    return AFI_IP;
  else
    return AFI_IP6;
}

/* Utility function to convert String to SAFI */
safi_t
bgp_cli_str2safi (u_int8_t *str)
{
  if (pal_strncmp (str, "multicast", 1) == 0)
    return SAFI_MULTICAST;
  else
    return SAFI_UNICAST;
}

bool_t
bgp_peer_address_self_check (struct bgp *bgp, union sockunion *su)
{
  struct interface *ifp;
  struct connected *ifc;

  ifp = NULL;
  ifc = NULL;

  if (su->sa.sa_family == AF_INET)
    {
      ifp = if_lookup_by_ipv4_address
            (LIB_VR_GET_IF_MASTER (BGP_VR.owning_ivr),
             &su->sin.sin_addr);

      if (ifp)
        ifc = if_lookup_ifc_ipv4 (ifp, &su->sin.sin_addr);
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && su->sa.sa_family == AF_INET6)
    {
      ifp = if_lookup_by_ipv6_address
            (LIB_VR_GET_IF_MASTER (BGP_VR.owning_ivr),
             &su->sin6.sin6_addr);

      if (ifp)
        ifc = if_lookup_ifc_ipv6 (ifp, &su->sin6.sin6_addr);
    }
#endif /* HAVE IPV6 */

  return (ifc ? PAL_TRUE : PAL_FALSE);
}

/* Utility function for looking up peer from VTY */
struct bgp_peer *
bgp_peer_lookup_vty (struct cli *cli, u_int8_t *ip_str)
{
  struct bgp_peer *peer;
  union sockunion su;
  struct bgp *bgp;
  s_int32_t ret;

  bgp = cli->index;

  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      cli_out (cli, "%% Malformed address: %s\n", ip_str);
      return NULL;
    }

  if (PAL_TRUE == bgp_peer_address_self_check (bgp, &su))
    {
      cli_out (cli, "%% Cannot configure the local system as neighbor\n");
      return NULL;
    }

  peer = bgp_peer_search (bgp, &su);
  if (! peer)
    {
      cli_out (cli, "%% Specify remote-as or peer-group commands first\n");
      return NULL;
    }

  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE)
      && peer->bgp != bgp)
    {
      cli_out (cli, "%% Peer Configured in another BGP Instance\n");
      return NULL;
    }

  return peer;
}

/* Utility function for looking up peer or peer group.  */
struct bgp_peer *
bgp_peer_and_group_lookup_vty (struct cli *cli,
                               u_int8_t *peer_str)
{
  struct bgp_peer_group *group;
  struct bgp_peer *peer;
  union sockunion su;
  struct bgp *bgp;
  s_int32_t ret;

  bgp = cli->index;

  ret = str2sockunion (peer_str, &su);
  if (! ret)
    {
      if (bgp_peer_address_self_check (bgp, &su))
        {
          cli_out (cli, "%% Cannot configure the local system as neighbor\n");
          return NULL;
        }

      peer = bgp_peer_search (bgp, &su);
      if (peer
          && bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE)
          && !bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER)
          && peer->bgp != bgp)
        {
          cli_out (cli, "%% Peer Configured in another BGP Instance\n");
          return NULL;
        }

      if (peer)
        return peer;
    }
  else
    {
      group = bgp_peer_group_lookup (bgp, peer_str);
      if (group)
        return group->conf;
    }

  cli_out (cli, "%% Specify remote-as or peer-group commands first\n");

  return NULL;
}

s_int32_t
bgp_cli_return (struct cli *cli, s_int32_t ret)
{
  u_int8_t *str = NULL;

  switch (ret)
    {
    case BGP_API_SET_ERR_INVALID_VALUE:
      str = "Invalid value";
      break;
    case BGP_API_SET_ERR_INVALID_FLAG:
      str = "Invalid flag";
      break;
    case BGP_API_SET_ERR_INVALID_BGP:
      str = "Invalid BGP instance";
      break;
    case BGP_API_SET_ERR_PEER_MALFORMED_ADDRESS:
      str = "Malformed address";
      break;
    case BGP_API_SET_ERR_PEER_SELF_ADDRESS:
      str = "Cannot configure the local system as neighbor";
      break;
    case BGP_API_SET_ERR_PEER_UNINITIALIZED:
      str = "Specify remote-as or peer-group commands first";
      break;
    case BGP_API_SET_ERR_PEER_DUPLICATE:
      str = "Peer Configured in another BGP Instance";
      break;
    case BGP_API_SET_ERR_PEER_INACTIVE:
      str = "Activate the neighbor for the address family first";
      break;
    case BGP_API_SET_ERR_INVALID_FOR_PEER_GROUP_MEMBER:
      str = "Invalid command for a peer-group member";
      break;
    case BGP_API_SET_ERR_PEER_GROUP_SHUTDOWN:
      str = "Peer-group has been shutdown. Activate the peer-group first";
      break;
    case BGP_API_SET_ERR_PEER_GROUP_HAS_THE_FLAG:
      str = "This peer is a peer-group member.  Please change peer-group configuration";
      break;
    case BGP_API_SET_ERR_PEER_FLAG_CONFLICT:
      str = "Can't set override-capability and strict-capability-match at the same time";
      break;
    case BGP_API_SET_ERR_PEER_GROUP_MEMBER_EXISTS:
      str = "No activate for peergroup can be given only if peer-group has no members";
      break;
    case BGP_API_SET_ERR_PEER_BELONGS_TO_GROUP:
      str = "No activate for an individual peer-group member is invalid";
      break;
    case BGP_API_SET_ERR_PEER_GROUP_AF_UNCONFIGURED:
      str = "Activate the peer-group for the address family first";
      break;
    case BGP_API_SET_ERR_PEER_GROUP_AF_INVALID:
      str = "Invalid combination of address families for this peer-group";
      break;
    case BGP_API_SET_ERR_PEER_GROUP_NO_REMOTE_AS:
      str = "Specify remote-as or peer-group remote AS first";
      break;
    case BGP_API_SET_ERR_PEER_GROUP_CANT_CHANGE:
      str = "Cannot change the peer-group. Deconfigure first";
      break;
    case BGP_API_SET_ERR_PEER_GROUP_MISMATCH:
      str = "Cannot have different peer-group for the neighbor";
      break;
    case BGP_API_SET_ERR_PEER_FILTER_CONFLICT:
      str = "Prefix/distribute list can not co-exist";
      break;
    case BGP_API_SET_ERR_NOT_INTERNAL_PEER:
      str = "Invalid command. Not an internal neighbor";
      break;
    case BGP_API_SET_ERR_REMOVE_PRIVATE_AS:
      str = "Private AS cannot be removed for IBGP peers";
      break;
    case BGP_API_SET_ERR_INSTANCE_MISMATCH:
      str = "Mismatch AS value of this BGP Instance";
      break;
    case BGP_API_SET_ERR_UNKNOWN_OBJECT:
      str = "Unknown object, configure first";
      break;
    case BGP_API_SET_ERR_REGEXP_COMPILE_FAIL:
      str = "Can't compile regexp";
      break;
    case BGP_API_SET_ERR_MALFORMED_ARG:
      str = "Malformed argument";
      break;
    case BGP_API_SET_ERR_OBJECT_ALREADY_EXIST:
      str = "The same object already exists";
      break;
    case BGP_API_SET_ERR_SET_VALUE_NOT_UNIQUE:
      str = "This set value must be unique";
      break;
    case BGP_API_SET_ERR_CONFIG_CANT_CHANGED:
      str = "Configuration can't be changed";
      break;
    case BGP_API_SET_ERR_OPERATION_CANT_ALLOWED:
      str = "No privilege for this operation";
      break;
    case BGP_API_SET_ERR_CLIST_DEFINE_CONFLICT:
      str = "Community name conflict with previous defined";
      break;
    case BGP_API_SET_ERR_REMOTE_AS_MISMATCH:
      str = "Remote-as value mismatched, but Neighbor was deleted";
      break;
    case BGP_API_SET_ERROR:
      str = "Operation failed";
      break;
    case BGP_API_SET_ERR_AS_MISMATCH:
      str = "AS number mismatch";
      break;
    case BGP_API_SET_ERR_MULTIPLE_INSTANCE_USED:
      str = "Unconfigure all BGP Multiple-Instance configuration";
      break;
    case BGP_API_SET_ERR_PEER_CONFIG_IN_ANOTHER_INST:
      str = "Peer Configured in another BGP Instance";
      break;
    case BGP_API_SET_ERR_MULTIPLE_INSTANCE_NOT_SET:
      cli_out (cli, "Please specify 'bgp multiple-instance' first\n");
      return CLI_ERROR;
    case BGP_API_SET_ERR_MULT_INST_DEL_CONFIG:
      str = "Delete BGP Router before choosing this option";
      break;
    case BGP_API_SET_ERR_INVALID_NETWORK:
      str = "Invalid network address";
      break;
    case BGP_API_SET_ERR_UNSUP_VPNVF_CONF:
      str = "Can't activate VPNV4 family for EBGP peer ";
      break;
    case BGP_API_SET_ERR_INVALID_AF:
      str = "Invalid Address-Family";
      break;
   case BGP_API_SET_ERR_INVALID_MASK:
      str = "Configured mask is invalid";
      break;
   case BGP_API_SET_ERR_INVALID_AS:
      str = "Local member-AS not allowed in confed peer list";
      break;
   case BGP_API_NO_REDIST_RMAP:
      str = "No route-map name specified in redistribute";
      break;
   case BGP_API_IP_NOT_IN_SAME_SUBNET:
      str = "Neighbor IP not in the same subnet as interface";
      break;
   case BGP_API_INVALID_INTERFACE_NAME:
      str = "Invalid interface name";
      break;
#ifdef HAVE_EXT_CAP_ASN
   case BGP_API_SET_ERR_ALREADY_EXTASNCAP:
      str = "Extended asn capability is already enabled";
      break;
   case BGP_API_SET_ERR_NO_EXTASNCAP: 
      str = "Extended asn capability is not enabled";
      break;
   case BGP_API_INVALID_EXTASN:
      str = "Invalid AS Number, 23456 (Reserved)";
      break;
   case BGP_API_SET_ERR_NONMAPPABLE:
      str = "BGP is configured with 4 octet ASN";
      break;
    case BGP_API_SET_ERR_INVALID_REMOTEASN: 
      str = "Invalid Remote AS Number, 23456 (Reserved)";
      break;
#endif /* HAVE_EXT_CAP_ASN */ 
   case BGP_API_SET_ERR_INFINITE_HOLD_TIME_VALUE:
      str = "The configured holdtime 0 is not allowed";
      break;
   case BGP_API_SET_WARN_HOLD_AND_KEEPALIVE_INVALID:  
      str = "The configured holdtime should be at least 3 times the keepalive time";
      break;
   case BGP_API_SET_ERR_INVALID_HOLD_TIME:
      str = "Invalid holdtime. Configured holdtime should be at least 3";
      break;
   case BGP_API_SET_WARN_HOLD_LESS_DEFAULT:
      str = "Configured holdtime is set below the default value";
      break;
   case BGP_API_INVALID_ROUTE_NODE:
      str = "Invalid routing table node";
      break;
   case BGP_API_SET_ERR_AUTO_SUMMARY_ENABLED:
      str = "Auto summary is already enabled";
      break;
   case BGP_API_SET_ERR_AUTO_SUMMARY_DISABLED:
      str = "Auto summary is already disabled";
      break;
   case BGP_API_FEATURE_NOT_ENABLED_SET_ERR:
      str = "The feature is already disabled";
      break;
   case BGP_API_SET_ERR_ALREADY_SET:
      str = "This value or option is already set";
      break; 
   case BGP_API_SET_ERR_ADJ_OUT_DYNAMIC:
      str = "Can not change this option while BGP instance running";
      break;
   case BGP_API_SET_ERR_PEER_NOT_EBGP:
      str = "Please specify EBGP configuration";
      break;
   case BGP_API_SET_ERR_LOCAL_AS_EQUAL_TRUE_AS:
      str = "Local-AS cannot equal the true local AS";
      break;
   case BGP_API_SET_ERR_LOCAL_AS_EQUAL_PEER_AS:
      str = "Local-AS cannot equal peer's AS";
      break;
   case BGP_API_SET_ERR_LOCAL_AS_TO_PEER_GROUP_MEMBER:
      str = "Local-AS cannot be customized for individual peers in a peer group.";
      break;
   case BGP_API_SET_ERR_NOT_SET:
      str = "This value or option is not set "; 
      break;
   case BGP_API_SET_ERR_MEM_ALLOC_FAIL:
      str = "Can not allocate memory";
      break;
   case BGP_API_SET_ERR_NO_CAP_CMD:
      str = "g-shut-capable is not enabled";
      break;
   case BGP_API_SET_ERR_PEER_IBGP:
      str = " G-shut is not allowed on IBGP peer";
      break;
    }
  if (str)
    {
      cli_out (cli, "%% %s\n", str);

      return CLI_ERROR;
    }

  if (ret < 0)
    return CLI_ERROR;
  else
    return CLI_SUCCESS;
}

/* BGP VR Multiple Instance Configuration */
CLI (bgp_multiple_instance_func,
     bgp_multiple_instance_cmd,
     "bgp multiple-instance (allow-same-peer|)",
     CLI_BGP_STR,
     "Enable bgp multiple instance",
     "Allow same peer in multiple instances")
{
  s_int32_t ret;

  if (argc)
    {
      ret = bgp_option_set (BGP_OPT_MULTIPLE_INSTANCE);
      ret = bgp_option_set (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER);
    }
  else
    ret = bgp_option_set (BGP_OPT_MULTIPLE_INSTANCE);

  return bgp_cli_return (cli, ret);
}

CLI (no_bgp_multiple_instance,
     no_bgp_multiple_instance_cmd,
     "no bgp multiple-instance (allow-same-peer|)",
     CLI_NO_STR,
     CLI_BGP_STR,
     "BGP multiple instance",
     "Disable allowing same peer in multiple views"
   )
{
  s_int32_t ret;
 
  if (argc)
    ret = bgp_option_unset(BGP_OPT_MULTI_INS_ALLOW_SAME_PEER);
  else
    {
      ret = bgp_option_unset (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER);
      ret = bgp_option_unset (BGP_OPT_MULTIPLE_INSTANCE);
    }

  return bgp_cli_return (cli, ret);
}

#ifdef HAVE_MULTIPATH

int
bgp_multipath_set(struct cli *cli, bool_t mset, char *bgp_type, char * num_str)
{
    int multipath = 0;
    int btype = 0;
    int retval = 0;

    struct bgp *bgp = cli->index;

    if (!bgp || !bgp->owning_bvr)
      return CLI_ERROR;

    if (bgp_type == NULL)
      {
	cli_out (cli, "%% %s\n",
	  " Please specify BGP type - ebgp or ibgp");
	return CLI_ERROR;
      }
    if (mset && num_str == NULL)
      {
	cli_out (cli, "%% %s\n", "Command syntax: max-paths bgp-type number");
	return CLI_ERROR;
      } 

    if ((bgp_cli_mode_afi(cli) != AFI_IP) || 
	  (bgp_cli_mode_safi(cli) != SAFI_UNICAST))
      return (bgp_cli_return(cli, BGP_API_SET_ERR_INVALID_AF));

    if (num_str)
      CLI_GET_INTEGER_RANGE ("multipath number", multipath, num_str, 2, 64);

    if (pal_strncmp (bgp_type, "e", 1) == 0)
      {
	btype = BGP_PEER_EBGP;
      }
     else
      {
        btype = BGP_PEER_IBGP;
       }
      
     retval = bgp_set_maxpath (mset, bgp, btype, multipath);

     return bgp_cli_return(cli, retval);

}
	
    
/* BGP ECMP : maximum-paths ebgp|ibgp */
CLI (bgp_maximum_paths,
     bgp_maximum_paths_cmd,
     "max-paths (ebgp|ibgp) <2-64>",
     "Set multipath ECMP numbers for BGP",
     "Session EBGP ECMP",
     "Session IBGP ECMP",
     "Supported multipath numbers")
{
  if (argc == 1)
    {
       cli_out (cli, "%% %s\n", "Command syntax: max-paths bgp-type number");
        return CLI_ERROR;
    }
  /* Currently only support maximum 64  multipaths. */
  return bgp_multipath_set (cli, 1, argv[0], argv[1]);
}

CLI (no_bgp_maximum_paths_ebgp,
     no_bgp_maximum_paths_ebgp_cmd,
     "no max-paths ebgp (<2-64>|)",
     CLI_NO_STR,
     "Unset multipath  ebgp",
     "Session EBGP ECMP",
      "Multipath number")
{
    return bgp_multipath_set (cli, 0, "ebgp", argv[0]);

}

CLI (no_bgp_maximum_paths_ibgp,
     no_bgp_maximum_paths_ibgp_cmd,
     "no max-paths ibgp (<2-64>|)",
      CLI_NO_STR,
      "Unset multipath ibgp",
      "Session IBGP ECMP",
      "Multipath number")
{
    return bgp_multipath_set (cli, 0, "ibgp", argv[0]);
}



void
bgp_ecmp_cli_init(struct cli_tree * ctree)
{
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_maximum_paths_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_maximum_paths_ebgp_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_maximum_paths_ibgp_cmd);
}

#endif  /* HAVE_MULTIPATH */

CLI (bgp_config_type,
     bgp_config_type_cmd,
     "bgp config-type (standard|bgpsdn)",
     CLI_BGP_STR,
     "Configuration type",
     "standard",
     "BGP-SDN")
{
  if (pal_strncmp (argv[0], "s", 1) == 0)
    bgp_option_set (BGP_OPT_CONFIG_STANDARD);
  else
    bgp_option_unset (BGP_OPT_CONFIG_STANDARD);

  return CLI_SUCCESS;
}
/* BGP Disable ADJ OUT Configuration */
CLI (bgp_disable_adj_out_func,
     bgp_disable_adj_out_cmd,
     "bgp disable-adj-out",
     CLI_BGP_STR,
     "Disable BGP ADJ_OUT")
{
  s_int32_t ret;

  if (bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
    {
      cli_out (cli, "Adj-out is already enabled\n");
      return CLI_ERROR;
    }

  ret = bgp_option_set (BGP_OPT_DISABLE_ADJ_OUT);

  return bgp_cli_return (cli, ret);
}

CLI (no_bgp_disable_adj_out_func,
     no_bgp_disable_adj_out_cmd,
     "no bgp disable-adj-out",
     CLI_NO_STR,
     CLI_BGP_STR,
     "BGP ADJ_OUT")
{
  s_int32_t ret;

  if (!bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
    {
      cli_out (cli, "Adj-out is already disabled\n");
      return CLI_ERROR;
    }

  ret = bgp_option_unset (BGP_OPT_DISABLE_ADJ_OUT);

  return bgp_cli_return (cli, ret);
}

CLI (no_bgp_config_type,
     no_bgp_config_type_cmd,
     "no bgp config-type",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Display configuration type")
{
  bgp_option_unset (BGP_OPT_CONFIG_STANDARD);
  return CLI_SUCCESS;
}

CLI (bgp_rfc1771_path_select,
     bgp_rfc1771_path_select_cmd,
     "bgp rfc1771-path-select",
     CLI_BGP_STR,
     "RFC1771 path selection mechanism")
{
  bgp_option_set (BGP_OPT_RFC1771_PATH_SELECT);
  return CLI_SUCCESS;
}

CLI (no_bgp_rfc1771_path_select,
     no_bgp_rfc1771_path_select_cmd,
     "no bgp rfc1771-path-select",
     CLI_NO_STR,
     CLI_BGP_STR,
     "RFC1771 path selection mechanism")
{
  bgp_option_unset (BGP_OPT_RFC1771_PATH_SELECT);
  return CLI_SUCCESS;
}

CLI (bgp_rfc1771_strict,
     bgp_rfc1771_strict_cmd,
     "bgp rfc1771-strict",
     CLI_BGP_STR,
     "Strict RFC1771 behavior")
{
  bgp_option_set (BGP_OPT_RFC1771_STRICT);
  return CLI_SUCCESS;
}

CLI (no_bgp_rfc1771_strict,
     no_bgp_rfc1771_strict_cmd,
     "no bgp rfc1771-strict",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Strict RFC1771 behavior")
{
  bgp_option_unset (BGP_OPT_RFC1771_STRICT);
  return CLI_SUCCESS;
}

CLI (bgp_aggregate_nexthop_check,
     bgp_aggregate_nexthop_check_cmd,
     "bgp aggregate-nexthop-check",
     CLI_BGP_STR,
     "Perform aggregation only when next hop is same")
{
  bgp_option_set (BGP_OPT_AGGREGATE_NEXTHOP_CHECK);
  return CLI_SUCCESS;
}

CLI (no_bgp_aggregate_nexthop_check,
     no_bgp_aggregate_nexthop_check_cmd,
     "no bgp aggregate-nexthop-check",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Perform aggregation only when next hop is same")
{
  bgp_option_unset (BGP_OPT_AGGREGATE_NEXTHOP_CHECK);
  return CLI_SUCCESS;
}

#ifdef HAVE_EXT_CAP_ASN
CLI (bgp_extended_asn_cap_check,
     bgp_extended_asn_cap_check_cmd,
     "bgp extended-asn-cap",
     CLI_BGP_STR,
     "Enable the router to send 4-octet ASN capabilities")
{
  struct bgp *bgp = NULL;
  s_int32_t  ret = CLI_SUCCESS;

  bgp = bgp_lookup_default ();
  ret = bgp_conf_ext_asn_cap (bgp, BGP_OPT_EXTENDED_ASN_CAP, PAL_TRUE);
  return bgp_cli_return (cli,ret);
}

CLI (no_bgp_extended_asn_cap_check,
     no_bgp_extended_asn_cap_check_cmd,
     "no bgp extended-asn-cap",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Disable the  router to send 4-octet ASN capabilities")
{
  struct bgp *bgp = NULL;
  s_int32_t  ret = CLI_SUCCESS;

  bgp = bgp_lookup_default();
  ret = bgp_conf_ext_asn_cap (bgp, BGP_OPT_EXTENDED_ASN_CAP, PAL_FALSE);
  return bgp_cli_return (cli,ret);
}
#endif /* HAVE_EXT_CAP_ASN */


/* BGP as-local-count configuration */
CLI (bgp_as_local_count,
     bgp_as_local_count_cmd,
     "bgp as-local-count <2-64>",
     "Adds local AS number to the specified number of times in AS-PATH",
     "Prepends Local-as",
     "Number of times local-as to be prepended")
{
  struct bgp *bgp = cli->index;
  int ret;
  int  count = 0;


  if (bgp != bgp_lookup_default())
    {
      cli_out (cli, "%% %s\n",
         "Only supported on default BGP instance");
      return CLI_ERROR;
    }
  if (argv[0] == NULL)
    {
      cli_out (cli, "%% %s\n",
        "Command syntax: bgp as-local-count number");
      return CLI_ERROR;
    }

  CLI_GET_INTEGER_RANGE ("as loop count", count, argv[0], 2, 64);
  ret = bgp_set_local_as_count(bgp, count);
  return bgp_cli_return (cli, ret);
}

CLI (no_bgp_as_local_count,
     no_bgp_as_local_count_cmd,
     "no bgp as-local-count <2-64>",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Unset prepending additional Local-as",
     "As-local-count")
{
  struct bgp *bgp = cli->index;
  int ret;
  int count;


  if (bgp != bgp_lookup_default())
    {
      cli_out (cli, "%% %s\n",
         "Only supported on default BGP instance");
      return CLI_ERROR;
    }
  CLI_GET_INTEGER_RANGE ("as loop count", count, argv[0], 2, 64);

  ret = bgp_unset_local_as_count(bgp, count);
  return bgp_cli_return (cli, ret);
}


void
bgp_cli_default_init (struct cli_tree *ctree)
{
  /* Install default CLI commands.  */
  cli_install_default (ctree, BGP_MODE);
  cli_install_default_family (ctree, BGP_IPV4_MODE);
  cli_install_default_family (ctree, BGP_IPV4M_MODE);
  cli_install_default_family (ctree, BGP_IPV6_MODE);

  /* "bgp disable adj_out" commands */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_disable_adj_out_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                       &no_bgp_disable_adj_out_cmd);

  /* "bgp multiple-instance" commands */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_multiple_instance_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_multiple_instance_cmd);

  /* "bgp config-type" commands. */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_config_type_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_config_type_cmd);

  /* "bgp rfc1771-path-select" commands.  */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_rfc1771_path_select_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_rfc1771_path_select_cmd);

  /* "bgp rfc1771-strict" commands .  */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_rfc1771_strict_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_rfc1771_strict_cmd);

  /* "bgp aggregate-nexthop-check" commands.  */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_aggregate_nexthop_check_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_aggregate_nexthop_check_cmd);

  /* "bgp as-local-count n" command */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_as_local_count_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_as_local_count_cmd);

#ifdef HAVE_EXT_CAP_ASN  
  /* bgp 4-octet ASN capability commands */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_extended_asn_cap_check_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_extended_asn_cap_check_cmd);
#endif /* HAVE_EXT_CAP_ASN */

  return;
}


/* Address family configuration.  */
CLI (address_family_ipv4,
     address_family_ipv4_cmd,
     "address-family ipv4",
     "Enter Address Family command mode",
     "Address family")
{
  cli->mode = BGP_IPV4_MODE;
  return CLI_SUCCESS;
}

CLI (address_family_ipv4_safi,
     address_family_ipv4_safi_cmd,
     "address-family ipv4 (unicast|multicast)",
     "Enter Address Family command mode",
     "Address family",
     "Address Family modifier",
     "Address Family modifier")
{
  if (pal_strncmp (argv[0], "multicast", 1) == 0)
    cli->mode = BGP_IPV4M_MODE;
  else
    cli->mode = BGP_IPV4_MODE;

  return CLI_SUCCESS;
}

CLI (address_family_ipv6,
     address_family_ipv6_cmd,
     "address-family ipv6 (unicast|)",
     "Enter Address Family command mode",
     "Address family",
     "Address Family modifier")
{
  cli->mode = BGP_IPV6_MODE;
  return CLI_SUCCESS;
}

CLI (exit_address_family,
     exit_address_family_cmd,
     "exit-address-family",
     "Exit from Address Family configuration mode")
{
  if (cli->mode == BGP_IPV4M_MODE
      || cli->mode == BGP_IPV4_MODE
      || cli->mode == BGP_IPV6_MODE)
    cli->mode = BGP_MODE;

  return CLI_SUCCESS;
}

void
bgp_cli_address_family_init (struct cli_tree *ctree)
{
  /* address-family commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &address_family_ipv4_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &address_family_ipv4_safi_cmd);

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
   {
     cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                      &address_family_ipv6_cmd);
   }
#endif /* HAVE_IPV6 */

  /* "exit-address-family" command. */
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &exit_address_family_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &exit_address_family_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &exit_address_family_cmd);
}

/* "router bgp" commands */
#ifndef HAVE_EXT_CAP_ASN
CLI (router_bgp,
     router_bgp_cmd,
     "router bgp <1-65535>",
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR)
#else
CLI (router_bgp,
     router_bgp_cmd,
     "router bgp <1-4294967295>",
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR)
#endif /* HAVE_EXT_CAP_ASN */
{
  u_int32_t tmp_as;
  struct bgp *bgp;
  u_int8_t *name;
  s_int32_t ret;
  as_t as;
#ifndef HAVE_EXT_CAP_ASN
  CLI_GET_INTEGER_RANGE ("AS", tmp_as, argv[0], 1, 65535); 
#else
  CLI_GET_UINT32_RANGE ("AS", tmp_as, argv[0], 1, 4294967295U);
#endif /* HAVE_EXT_CAP_ASN */
  ret = BGP_API_SET_SUCCESS;
#ifndef HAVE_EXT_CAP_ASN
  as = (u_int16_t) tmp_as;
#else
  as = tmp_as;
  if (as == BGP_AS_TRANS)
    return bgp_cli_return (cli, BGP_API_INVALID_EXTASN);
  else if (! BGP_IS_AS4_MAPPABLE(as)
           && ! CHECK_FLAG (BGP_VR.bvr_options,BGP_OPT_EXTENDED_ASN_CAP))
    return bgp_cli_return (cli, BGP_API_SET_ERR_NO_EXTASNCAP); 
#endif /* HAVE_EXT_CAP_ASN */
  name = NULL;

  if (argc == 2)
    name = argv[1];

  ret = bgp_get (&bgp, &as, name);
  switch (ret)
    {
    case BGP_API_SET_SUCCESS:
      break;
    case BGP_API_SET_ERR_MULTIPLE_INSTANCE_NOT_SET:
      cli_out (cli, "Please specify 'bgp multiple-instance' first\n");
      return CLI_ERROR;
      break;
    case BGP_API_SET_ERR_AS_MISMATCH:
      cli_out (cli, "BGP is already running; AS is %d\n", as);
      return CLI_ERROR;
      break;
    case BGP_API_SET_ERR_INSTANCE_MISMATCH:
      cli_out (cli, "BGP view name and AS number mismatch\n");
      cli_out (cli, "BGP instance is already running; AS is %d\n", as);
      return CLI_ERROR;
      break;
    case BGP_API_SET_ERR_DEFAULTINS_FOR_SAMEPEER:
      cli_out (cli, "%% Creation of default instance is not allowed, when allow-same-peer is enabled\n");
      return CLI_ERROR;
      break;
    case BGP_API_SET_ERROR:
    default:
      cli_out (cli, "BGP router creation failed\n");
      return CLI_ERROR;
      break;
    }

  cli->mode = BGP_MODE;
  cli->index = bgp;

  return CLI_SUCCESS;
}

#ifndef HAVE_EXT_CAP_ASN
ALI (router_bgp,
     router_bgp_view_cmd,
     "router bgp <1-65535> view WORD",
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR,
     "BGP view",
     "view name");

/* "no router bgp" commands. */
CLI (no_router_bgp,
     no_router_bgp_cmd,
     "no router bgp <1-65535>",
     CLI_NO_STR,
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR)
#else
ALI (router_bgp,
     router_bgp_view_cmd,
     "router bgp <1-4294967295> view WORD",
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR,
     "BGP view",
     "view name");

/* "no router bgp" commands. */
CLI (no_router_bgp,
     no_router_bgp_cmd,
     "no router bgp <1-4294967295>",
     CLI_NO_STR,
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR)
#endif /* HAVE_EXT_CAP_ASN */
{
  u_int32_t tmp_as;
  struct bgp *bgp;
  u_int8_t *name;
  s_int32_t ret;
  as_t as;
#ifndef HAVE_EXT_CAP_ASN
  CLI_GET_INTEGER_RANGE ("AS", tmp_as, argv[0], 1, 65535);
#else
  CLI_GET_UINT32_RANGE ("AS", tmp_as, argv[0], 1, 4294967295U);
#endif /* HAVE_EXT_CAP_ASN */
  ret = BGP_API_SET_SUCCESS;
#ifndef HAVE_EXT_CAP_ASN
  as = (u_int16_t) tmp_as;
#else
  as = tmp_as;
#endif /* HAVE_EXT_CAP_ASN */
  name = NULL;

  if (argc == 2)
    name = argv[1];

  /* Lookup bgp structure */
  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE) )
    {
      if (name)
        bgp = bgp_lookup_by_name (name);
      else
        bgp = bgp_lookup_default ();

      if (! bgp || bgp->as != as)
        {
          if (! bgp)
            ret = BGP_API_SET_ERR_UNKNOWN_OBJECT;
          else
            ret = BGP_API_SET_ERR_INSTANCE_MISMATCH;

          goto EXIT;
        }
    }
  else
    {
      /* BGP Instance Name is illegal for single instance */
      if (name)
        {
          ret = BGP_API_SET_ERR_MULTIPLE_INSTANCE_NOT_SET;

          goto EXIT;
        }

      /* Get default BGP structure if exists. */
      bgp = bgp_lookup_default ();
      if (! bgp)
        {
          ret = BGP_API_SET_ERROR;

          goto EXIT;
        }

      if (bgp->as != as)
        {
          if (bgp->as)
            ret = BGP_API_SET_ERR_AS_MISMATCH;
          else
            ret = BGP_API_SET_ERR_UNKNOWN_OBJECT;

          goto EXIT;
        }
    }

  bgp_delete (bgp);

 EXIT:

  return bgp_cli_return (cli, ret);
}
#ifndef HAVE_EXT_CAP_ASN
ALI (no_router_bgp,
     no_router_bgp_view_cmd,
     "no router bgp <1-65535> view WORD",
     CLI_NO_STR,
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR,
     "BGP view",
     "view name");
#else
ALI (no_router_bgp,
     no_router_bgp_view_cmd,
     "no router bgp <1-4294967295> view WORD",
     CLI_NO_STR,
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR,
     "BGP view",
     "view name");
#endif /* HAVE_EXT_CAP_ASN */

/* BGP router-id.  */

CLI (bgp_router_id,
     bgp_router_id_cmd,
     "bgp router-id A.B.C.D",
     CLI_BGP_STR,
     "Override current router identifier (peers will reset)",
     "Manually configured router identifier")
{
  struct pal_in4_addr router_id;
  struct listnode *nn;
  struct bgp *bgp;
  s_int32_t ret;

  ret = pal_inet_pton (AF_INET, argv[0], &router_id);
  if (! ret)
    {
      cli_out (cli, "%% Malformed bgp router identifier\n");
      return CLI_ERROR;
    }

  ret = bgp_router_id_validate (&router_id);
  if (ret < 0)
    {
      cli_out (cli, "%%Invalid router-id\n");
      return CLI_ERROR;
    }

  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      bgp = cli->index;

      bgp_router_id_set (bgp, &router_id);
    }
  else
    {
      LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
        bgp_router_id_set (bgp, &router_id);
    }

  return CLI_SUCCESS;
}

CLI (no_bgp_router_id,
     no_bgp_router_id_cmd,
     "no bgp router-id",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Override current router identifier (peers will reset)")
{
  struct pal_in4_addr router_id;
  struct listnode *nn;
  struct bgp *bgp;
  s_int32_t ret;

  if (argc == 1)
    {
      ret = pal_inet_pton (AF_INET, argv[0], &router_id);
      if (! ret)
        {
          cli_out (cli, "%% Malformed BGP router identifier\n");
          return CLI_ERROR;
        }

      ret = bgp_router_id_validate (&router_id);
      if (ret < 0)
        {
          cli_out (cli, "%%Invalid router-id\n");
          return CLI_ERROR;
        }

      if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
        {
          bgp = cli->index;

          if (! IPV4_ADDR_SAME (&bgp->router_id, &router_id))
            {
              cli_out (cli, "%% BGP router-id doesn't match\n");
              return CLI_ERROR;
            }

          bgp_router_id_unset (bgp);
        }
      else
        {
          bgp = bgp_lookup_default ();

          if (bgp && ! IPV4_ADDR_SAME (&bgp->router_id, &router_id))
            {
              cli_out (cli, "%% BGP router-id doesn't match\n");
              return CLI_ERROR;
            }

          LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
            bgp_router_id_unset (bgp);
        }
    }
  else
    {
      if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
        {
          bgp = cli->index;

          bgp_router_id_unset (bgp);
        }
      else
        {
          LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
            bgp_router_id_unset (bgp);
        }
    }

  return CLI_SUCCESS;
}

ALI (no_bgp_router_id,
     no_bgp_router_id_val_cmd,
     "no bgp router-id A.B.C.D",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Override current router identifier (peers will reset)",
     "Manually configured router identifier");

/* BGP Cluster ID.  */

CLI (bgp_cluster_id,
     bgp_cluster_id_cmd,
     "bgp cluster-id A.B.C.D",
     CLI_BGP_STR,
     "Configure Route-Reflector Cluster-id",
     "Route-Reflector Cluster-id in IP address format")
{
  struct pal_in4_addr cluster;
  struct listnode *nn;
  struct bgp *bgp;
  s_int32_t ret;

  ret = pal_inet_pton (AF_INET, argv[0], &cluster);
  if (! ret)
    {
      cli_out (cli, "%% Malformed bgp cluster identifier\n");
      return CLI_ERROR;
    }

  ret = bgp_cluster_id_validate (&cluster);
  if (ret < 0)
    {
      cli_out (cli, "%%Invalid cluster-id\n");
      return CLI_ERROR;
    }

  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      bgp = cli->index;

      bgp_cluster_id_set (bgp, &cluster);
    }
  else
    {
      LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
        bgp_cluster_id_set (bgp, &cluster);
    }

  return CLI_SUCCESS;
}

CLI (bgp_cluster_id_digit,
     bgp_cluster_id_digit_cmd,
     "bgp cluster-id <1-4294967295>",
     CLI_BGP_STR,
     "Configure Route-Reflector Cluster-id",
     "Route-Reflector Cluster-id as 32 bit quantity")
{
  struct listnode *nn;
  u_int32_t cluster;
  struct bgp *bgp;

  bgp = cli->index;

  CLI_GET_INTEGER ("Cluster-id", cluster, argv[0]);

  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      bgp = cli->index;

      bgp_cluster_id_digit_set (bgp, cluster);
    }
  else
    {
      LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
        bgp_cluster_id_digit_set (bgp, cluster);
    }

  return CLI_SUCCESS;
}

CLI (no_bgp_cluster_id,
     no_bgp_cluster_id_cmd,
     "no bgp cluster-id",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Configure Route-Reflector Cluster-id")
{
  struct listnode *nn;
  struct bgp *bgp;

  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      bgp = cli->index;

      bgp_cluster_id_unset (bgp);
    }
  else
    {
      LIST_LOOP (BGP_VR.bgp_list, bgp, nn)
	bgp_cluster_id_unset (bgp);
    }

  return CLI_SUCCESS;
}
CLI (bgp_confederation_identifier,
     bgp_confederation_identifier_cmd,
     "bgp confederation identifier <1-65535>",
     "BGP specific commands",
     "AS confederation parameters",
     "AS number",
     "Set routing domain confederation AS")
{
  struct bgp *bgp;
  as_t as;

  bgp = cli->index;

  CLI_GET_INTEGER ("AS", as, argv[0]);

  bgp_confederation_id_set (bgp, as);

  return CLI_SUCCESS;
}

CLI (no_bgp_confederation_identifier,
     no_bgp_confederation_identifier_cmd,
     "no bgp confederation identifier",
     CLI_NO_STR,
     "BGP specific commands",
     "AS confederation parameters",
     "AS number")
{
  struct bgp *bgp;

  bgp = cli->index;

  bgp_confederation_id_unset (bgp);

  return CLI_SUCCESS;
}

CLI (bgp_confederation_peers,
     bgp_confederation_peers_cmd,
     "bgp confederation peers .<1-65535>",
     "BGP specific commands",
     "AS confederation parameters",
     "Peer ASs in BGP confederation",
     CLI_AS_STR)
{
  u_int32_t tmp_as;
  struct bgp *bgp;
  u_int32_t idx;
  s_int32_t ret;
  s_int32_t temp;
  as_t as;
  ret = temp = BGP_API_SET_SUCCESS;
  bgp = cli->index;

  for (idx = 0; idx < argc; idx++)
    {
      CLI_GET_INTEGER_RANGE ("AS", tmp_as, argv[idx], 1, 65535);
      as = (u_int16_t) tmp_as;

      ret = bgp_confederation_peers_add (bgp, as);

      if (ret)
        temp = ret;
    }

  return bgp_cli_return (cli, temp);
}
CLI (no_bgp_confederation_peers,
     no_bgp_confederation_peers_cmd,
     "no bgp confederation peers .<1-65535>",
     CLI_NO_STR,
     "BGP specific commands",
     "AS confederation parameters",
     "Peer ASs in BGP confederation",
     CLI_AS_STR)
{
  u_int32_t tmp_as;
  struct bgp *bgp;
  u_int32_t idx;
  s_int32_t ret;
  as_t as;

  ret = BGP_API_SET_SUCCESS;
  bgp = cli->index;

  for (idx = 0; idx < argc; idx++)
    {
      CLI_GET_INTEGER_RANGE ("AS", tmp_as, argv[idx], 1, 65535);
      as = (u_int16_t) tmp_as;

      (void) bgp_confederation_peers_remove (bgp, as);
    }

  return bgp_cli_return (cli, ret);
}


#ifdef HAVE_BGP_SDN
#define BGP_SDN_DEFAULT_PORT 8080

CLI (bgp_rest_server,
     bgp_rest_server_cmd,
     "bgp rest-server (WORD|A.B.C.D) <1-65535>",
     CLI_BGP_STR,
     "RESTful API Server Configuration",
     "RESTful API Server Hostname (default: localhost)",
     "RESTful API Server Address",
     "RESTful API Server Port (default: 8080)")
{
  if (bgp_rest_addr)
    XFREE (MTYPE_TMP, bgp_rest_addr);

  bgp_rest_addr = XSTRDUP (MTYPE_TMP, argv[0]);

  if (bgp_rest_port)
    XFREE (MTYPE_TMP, bgp_rest_port);

  bgp_rest_port = XSTRDUP (MTYPE_TMP, argv[1]);

  bgp_onion_stop ();
  bgp_onion_init ();

  return CLI_SUCCESS;
}

CLI (no_bgp_rest_server,
     no_bgp_rest_server_cmd,
     "no bgp rest-server",
     CLI_NO_STR,
     CLI_BGP_STR,
     "RESTful API Server Configuration")
{
  if (bgp_rest_addr)
    XFREE (MTYPE_TMP, bgp_rest_addr);

  bgp_rest_addr = NULL;

  if (bgp_rest_port)
    XFREE (MTYPE_TMP, bgp_rest_port);

  bgp_rest_port = NULL;

  bgp_onion_stop ();
  bgp_onion_init ();

  return CLI_SUCCESS;
}

CLI (bgp_sdn_engine,
     bgp_sdn_engine_cmd,
     "bgp sdn-engine <1-2> (WORD|A.B.C.D) <1-65535>",
     CLI_BGP_STR,
     "SDN-Engine",
     "Index",
     "Hostname of SDN-Engine",
     "IP Address of SDN-Engine",
     "Port number of SDN-Engine")
{
  int idx;
  u_int16_t port;
  s_int32_t ret;

  ret = BGP_API_SET_SUCCESS;

  CLI_GET_INTEGER_RANGE ("Index", idx, argv[0], 1, 2);
  idx--;

  if (bgp_sdn_addr[idx])
    XFREE (MTYPE_TMP, bgp_sdn_addr[idx]);

  bgp_sdn_addr[idx] = XSTRDUP (MTYPE_TMP, argv[1]);
  
  if (argc == 3)
    {
      CLI_GET_INTEGER_RANGE ("PORT", port, argv[2], 1, 65535);

      bgp_sdn_port[idx] = port;
    }
  else
    {
      ret = BGP_API_SET_ERR_MALFORMED_ARG;
    }

  if (! bgp_curlm)
    bgp_curlm = curl_multi_init ();

  return bgp_cli_return (cli, ret);
} 

CLI (no_bgp_sdn_engine,
     no_bgp_sdn_engine_cmd,
     "no bgp sdn-engine <1-2>",
     CLI_NO_STR,
     CLI_BGP_STR,
     "SDN-Engine",
     "Index")
{
  s_int32_t ret;
  int idx;

  ret = BGP_API_SET_SUCCESS;

  CLI_GET_INTEGER_RANGE ("Index", idx, argv[0], 1, 2);
  idx--;

  if (bgp_sdn_addr[idx])
    XFREE (MTYPE_TMP, bgp_sdn_addr[idx]);

  bgp_sdn_addr[idx] = NULL;
  bgp_sdn_port[idx] = 0;

  for (idx = 0; idx < BGP_MAX_SDN_CLIENT; idx++)
    {
      if (bgp_sdn_addr[idx])
  	return bgp_cli_return (cli, ret);
    }

  if (bgp_curlm)
    curl_multi_cleanup (bgp_curlm);

  bgp_curlm = NULL;

  return bgp_cli_return (cli, ret);

}
#endif /* HAVE_BGP_SDN */

/* BGP timers.  */
CLI (bgp_timers,
     bgp_timers_cmd,
     "timers bgp <0-65535> <0-65535>",
     "Adjust routing timers",
     "BGP timers",
     "Keepalive interval",
     "Holdtime")
{
  u_int32_t keepalive;
  u_int32_t holdtime;
  struct bgp *bgp;

  bgp = cli->index;
  keepalive = 0;
  holdtime = 0;

  CLI_GET_UINT32 ("keepalive", keepalive, argv[0]);
  CLI_GET_UINT32 ("holdtime", holdtime, argv[1]);

  /* Holdtime value check. */
  if (holdtime < 3 && holdtime != 0)
    {
      cli_out (cli, "%% hold time value must be either 0 or greater than or equal to 3\n");
      return CLI_ERROR;
    }

  bgp_timers_set (bgp, keepalive, holdtime);

  return CLI_SUCCESS;
}

CLI (no_bgp_timers,
     no_bgp_timers_cmd,
     "no timers bgp",
     CLI_NO_STR,
     "Adjust routing timers",
     "BGP timers")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_timers_unset (bgp);

  return CLI_SUCCESS;
}

ALI (no_bgp_timers,
     no_bgp_timers_arg_cmd,
     "no timers bgp <0-65535> <0-65535>",
     CLI_NO_STR,
     "Adjust routing timers",
     "BGP timers",
     "Keepalive interval",
     "Holdtime");


CLI (bgp_client_to_client_reflection,
     bgp_client_to_client_reflection_cmd,
     "bgp client-to-client reflection",
     "BGP specific commands",
     "Configure client to client route reflection",
     "reflection of routes allowed")
{
  struct bgp *bgp;

  bgp = cli->index;
  if (! bgp_config_check (bgp, BGP_CFLAG_NO_CLIENT_TO_CLIENT))
    return bgp_cli_return (cli, BGP_API_SET_ERR_ALREADY_SET);
  bgp_config_unset (bgp, BGP_CFLAG_NO_CLIENT_TO_CLIENT);
  bgp_reflected_routes_update (bgp);
  return CLI_SUCCESS;
}

CLI (no_bgp_client_to_client_reflection,
     no_bgp_client_to_client_reflection_cmd,
     "no bgp client-to-client reflection",
     CLI_NO_STR,
     "BGP specific commands",
     "Configure client to client route reflection",
     "reflection of routes allowed")
{
  struct bgp *bgp;

  bgp = cli->index;
  if (bgp_config_check (bgp, BGP_CFLAG_NO_CLIENT_TO_CLIENT))
    return bgp_cli_return (cli, BGP_API_SET_ERR_NOT_SET);
  bgp_config_set (bgp, BGP_CFLAG_NO_CLIENT_TO_CLIENT);
  bgp_reflected_routes_update (bgp);
  return CLI_SUCCESS;
}

/* "bgp always-compare-med" configuration. */
CLI (bgp_always_compare_med,
     bgp_always_compare_med_cmd,
     "bgp always-compare-med",
     "BGP specific commands",
     "Allow comparing MED from different neighbors")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_ALWAYS_COMPARE_MED);
  return CLI_SUCCESS;
}

CLI (no_bgp_always_compare_med,
     no_bgp_always_compare_med_cmd,
     "no bgp always-compare-med",
     CLI_NO_STR,
     "BGP specific commands",
     "Allow comparing MED from different neighbors")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_ALWAYS_COMPARE_MED);
  return CLI_SUCCESS;
}

/* "bgp deterministic-med" configuration. */
CLI (bgp_deterministic_med,
     bgp_deterministic_med_cmd,
     "bgp deterministic-med",
     "BGP specific commands",
     "Pick the best-MED path among paths advertised from the neighboring AS")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_DETERMINISTIC_MED);
  return CLI_SUCCESS;
}

CLI (no_bgp_deterministic_med,
     no_bgp_deterministic_med_cmd,
     "no bgp deterministic-med",
     CLI_NO_STR,
     "BGP specific commands",
     "Pick the best-MED path among paths advertised from the neighboring AS")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_DETERMINISTIC_MED);
  return CLI_SUCCESS;
}

/* "bgp fast-external-failover" configuration. */
CLI (bgp_fast_external_failover,
     bgp_fast_external_failover_cmd,
     "bgp fast-external-failover",
     CLI_BGP_STR,
     "Immediately reset session if a link to a directly connected external peer goes down")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_NO_FAST_EXT_FAILOVER);
  return CLI_SUCCESS;
}

CLI (no_bgp_fast_external_failover,
     no_bgp_fast_external_failover_cmd,
     "no bgp fast-external-failover",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Immediately reset session if a link to a directly connected external peer goes down")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_NO_FAST_EXT_FAILOVER);
  return CLI_SUCCESS;
}

/* "bgp enforce-first-as" configuration. */
CLI (bgp_enforce_first_as,
     bgp_enforce_first_as_cmd,
     "bgp enforce-first-as",
     CLI_BGP_STR,
     "Enforce the first AS for EBGP routes")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_ENFORCE_FIRST_AS);
  return CLI_SUCCESS;
}

CLI (no_bgp_enforce_first_as,
     no_bgp_enforce_first_as_cmd,
     "no bgp enforce-first-as",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Enforce the first AS for EBGP routes")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_ENFORCE_FIRST_AS);
  return CLI_SUCCESS;
}

/* "bgp bestpath compare-routerid" configuration.  */
CLI (bgp_bestpath_compare_router_id,
     bgp_bestpath_compare_router_id_cmd,
     "bgp bestpath compare-routerid",
     "BGP specific commands",
     "Change the default bestpath selection",
     "Compare router-id for identical EBGP paths")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_COMPARE_ROUTER_ID);
  return CLI_SUCCESS;
}

CLI (no_bgp_bestpath_compare_router_id,
     no_bgp_bestpath_compare_router_id_cmd,
     "no bgp bestpath compare-routerid",
     CLI_NO_STR,
     "BGP specific commands",
     "Change the default bestpath selection",
     "Compare router-id for identical EBGP paths")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_COMPARE_ROUTER_ID);
  return CLI_SUCCESS;
}

CLI (bgp_bestpath_dont_compare_originator_id,
     bgp_bestpath_dont_compare_originator_id_cmd,
     "bgp bestpath dont-compare-originator-id",
      "BGP specific commands",
      "Change the default bestpath selection",
      "Don't Compare originator-id for BGP")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_DONT_COMP_ORIG_ID);
  return CLI_SUCCESS;
}

CLI (no_bgp_bestpath_dont_compare_originator_id,
     no_bgp_bestpath_dont_compare_originator_id_cmd,
     "no bgp bestpath dont-compare-originator-id",
     CLI_NO_STR,
     "BGP specific commands",
     "Change the default bestpath selection",
     "Don't Compare originator-id for identical EBGP paths")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_DONT_COMP_ORIG_ID);
  return CLI_SUCCESS;

}


/* bgp bestpath tie_break_on_age */
CLI(bgp_bestpath_tie_break_on_age,
    bgp_bestpath_tie_break_on_age_cmd,
    "bgp bestpath tie-break-on-age",
     "BGP specific commands",
     "Change default bestpath selection",
     "Prefer old route when compare-route-id is not set")
{
  struct bgp *bgp;
  
  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_PREFER_OLD_ROUTE);
  return CLI_SUCCESS;
}

CLI(no_bgp_bestpath_tie_break_on_age,
    no_bgp_bestpath_tie_break_on_age_cmd,
    "no bgp bestpath tie-break-on-age",
     "BGP specific commands",
     "Change default bestpath selection",
     "Prefer old route when compare-route-id is not set")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_PREFER_OLD_ROUTE);
  return CLI_SUCCESS;
}
     
/* "bgp bestpath as-path ignore" configuration.  */
CLI (bgp_bestpath_aspath_ignore,
     bgp_bestpath_aspath_ignore_cmd,
     "bgp bestpath as-path ignore",
     "BGP specific commands",
     "Change the default bestpath selection",
     "AS-path attribute",
     "Ignore as-path length in selecting a route")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_ASPATH_IGNORE);
  return CLI_SUCCESS;
}

CLI (no_bgp_bestpath_aspath_ignore,
     no_bgp_bestpath_aspath_ignore_cmd,
     "no bgp bestpath as-path ignore",
     CLI_NO_STR,
     "BGP specific commands",
     "Change the default bestpath selection",
     "AS-path attribute",
     "Ignore as-path length in selecting a route")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_ASPATH_IGNORE);
  return CLI_SUCCESS;
}

/* "bgp bestpath med" configuration. */
CLI (bgp_bestpath_med,
     bgp_bestpath_med_cmd,
     "bgp bestpath med (confed|missing-as-worst|remove-recv-med|remove-send-med )",
     "BGP specific commands",
     "Change the default bestpath selection",
     "MED attribute",
     "Compare MED among confederation paths",
     "Treat missing MED as the least preferred one",
     "To remove rcvd MED attribute",
     "To remove send MED attribute")
{
  struct bgp *bgp;

  bgp = cli->index;

  if(pal_strncmp (argv[0], "remove-recv-med", 9) == 0)
    bgp_config_set (bgp, BGP_CFLAG_MED_REMOVE_RCVD);
  else if(pal_strncmp (argv[0], "remove-send-med", 9) == 0)
    bgp_config_set (bgp, BGP_CFLAG_MED_REMOVE_SEND);
  else if (pal_strncmp (argv[0], "confed", 1) == 0)
    bgp_config_set (bgp, BGP_CFLAG_MED_CONFED);
  else 
    bgp_config_set (bgp, BGP_CFLAG_MED_MISSING_AS_WORST);

  return CLI_SUCCESS;
}

CLI (bgp_bestpath_med2,
     bgp_bestpath_med2_cmd,
     "bgp bestpath med confed missing-as-worst",
     "BGP specific commands",
     "Change the default bestpath selection",
     "MED attribute",
     "Compare MED among confederation paths",
     "Treat missing MED as the least preferred one")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_MED_CONFED);
  bgp_config_set (bgp, BGP_CFLAG_MED_MISSING_AS_WORST);
  return CLI_SUCCESS;
}

ALI (bgp_bestpath_med2,
     bgp_bestpath_med3_cmd,
     "bgp bestpath med missing-as-worst confed",
     "BGP specific commands",
     "Change the default bestpath selection",
     "MED attribute",
     "Treat missing MED as the least preferred one",
     "Compare MED among confederation paths");

CLI (no_bgp_bestpath_med,
     no_bgp_bestpath_med_cmd,
     "no bgp bestpath med (confed|missing-as-worst|remove-recv-med|remove-send-med)",
     CLI_NO_STR,
     "BGP specific commands",
     "Change the default bestpath selection",
     "MED attribute",
     "Compare MED among confederation paths",
     "Treat missing MED as the least preferred one",
     "To remove rcvd MED attribute",
     "To remove send MED attribute")
{
  struct bgp *bgp;

  bgp = cli->index;

  if(pal_strncmp (argv[0], "remove-recv-med", 9) == 0)
    bgp_config_unset (bgp, BGP_CFLAG_MED_REMOVE_RCVD);
  else if(pal_strncmp (argv[0], "remove-send-med", 9) == 0)
    bgp_config_unset (bgp, BGP_CFLAG_MED_REMOVE_SEND);
  else if (pal_strncmp (argv[0], "confed", 1) == 0)
    bgp_config_unset (bgp, BGP_CFLAG_MED_CONFED);
  else 
    bgp_config_unset (bgp, BGP_CFLAG_MED_MISSING_AS_WORST);

  return CLI_SUCCESS;
}

CLI (no_bgp_bestpath_med2,
     no_bgp_bestpath_med2_cmd,
     "no bgp bestpath med confed missing-as-worst",
     CLI_NO_STR,
     "BGP specific commands",
     "Change the default bestpath selection",
     "MED attribute",
     "Compare MED among confederation paths",
     "Treat missing MED as the least preferred one")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_MED_CONFED);
  bgp_config_unset (bgp, BGP_CFLAG_MED_MISSING_AS_WORST);
  return CLI_SUCCESS;
}

ALI (no_bgp_bestpath_med2,
     no_bgp_bestpath_med3_cmd,
     "no bgp bestpath med missing-as-worst confed",
     CLI_NO_STR,
     "BGP specific commands",
     "Change the default bestpath selection",
     "MED attribute",
     "Treat missing MED as the least preferred one",
     "Compare MED among confederation paths");

/* "no bgp default ipv4-unicast". */
CLI (no_bgp_default_ipv4_unicast,
     no_bgp_default_ipv4_unicast_cmd,
     "no bgp default ipv4-unicast",
     CLI_NO_STR,
     "BGP specific commands",
     "Configure BGP defaults",
     "Activate ipv4-unicast for a peer by default")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_NO_DEFAULT_IPV4);
  return CLI_SUCCESS;
}

CLI (bgp_default_ipv4_unicast,
     bgp_default_ipv4_unicast_cmd,
     "bgp default ipv4-unicast",
     "BGP specific commands",
     "Configure BGP defaults",
     "Activate ipv4-unicast for a peer by default")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_NO_DEFAULT_IPV4);
  return CLI_SUCCESS;
}

/* "bgp bestpath compare-confed-aspath" configuration. */
CLI (bgp_bestpath_compare_confed_aspath,
     bgp_bestpath_compare_confed_aspath_cmd,
     "bgp bestpath compare-confed-aspath",
     "BGP specific commands",
     "Change the default bestpath selection",
     "Allow comparing confederation AS path length")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_COMPARE_CONFED_ASPATH);
  return CLI_SUCCESS;
}

CLI (no_bgp_bestpath_compare_confed_aspath,
     no_bgp_bestpath_compare_confed_aspath_cmd,
     "no bgp bestpath compare-confed-aspath",
     CLI_NO_STR,
     "BGP specific commands",
     "Change the default bestpath selection",
     "Allow comparing confederation AS path length")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_COMPARE_CONFED_ASPATH);
  return CLI_SUCCESS;
}

CLI (bgp_default_local_preference,
     bgp_default_local_preference_cmd,
     "bgp default local-preference <0-4294967295>",
     "BGP specific commands",
     "Configure BGP defaults",
     "local preference (higher=more preferred)",
     "Configure default local preference value")
{
  struct bgp *bgp;
  u_int32_t local_pref;

  CLI_GET_UINT32 ("local preference", local_pref, argv[0]);

  bgp = cli->index;
  bgp_default_local_preference_set (bgp, local_pref);
  return CLI_SUCCESS;
}

CLI (no_bgp_default_local_preference,
     no_bgp_default_local_preference_cmd,
     "no bgp default local-preference",
     CLI_NO_STR,
     "BGP specific commands",
     "Configure BGP defaults",
     "local preference (higher=more preferred)")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_default_local_preference_unset (bgp);
  return CLI_SUCCESS;
}

ALI (no_bgp_default_local_preference,
     no_bgp_default_local_preference_val_cmd,
     "no bgp default local-preference <0-4294967295>",
     CLI_NO_STR,
     "BGP specific commands",
     "Configure BGP defaults",
     "local preference (higher=more preferred)",
     "Configure default local preference value");

CLI (bgp_log_neighbor_changes,
     bgp_log_neighbor_changes_cmd,
     "bgp log-neighbor-changes",
     CLI_BGP_STR,
     "Log neighbor up/down and reset reason")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_set (bgp, BGP_CFLAG_LOG_NEIGHBOR_CHANGES);
  return CLI_SUCCESS;
}

CLI (no_bgp_log_neighbor_changes,
     no_bgp_log_neighbor_changes_cmd,
     "no bgp log-neighbor-changes",
     CLI_NO_STR,
     CLI_BGP_STR,
     "Enable the logging changes of BGP neighbor's status")
{
  struct bgp *bgp;

  bgp = cli->index;
  bgp_config_unset (bgp, BGP_CFLAG_LOG_NEIGHBOR_CHANGES);
  return CLI_SUCCESS;
}

void
bgp_cli_router_init (struct cli_tree *ctree)
{
  /* "router bgp" and "no router bgp" commands. */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &router_bgp_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_router_bgp_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &router_bgp_view_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_router_bgp_view_cmd);

  /* "bgp router-id" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_router_id_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_router_id_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_router_id_val_cmd);

  /* "bgp cluster-id" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_cluster_id_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_cluster_id_digit_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_cluster_id_cmd);

  /* "bgp confederation" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_confederation_identifier_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_confederation_identifier_cmd);

  /* "bgp confederation peers" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_confederation_peers_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_confederation_peers_cmd);

  /* "timers bgp" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_timers_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_timers_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_timers_arg_cmd);

  /* "bgp client-to-client reflection" commands */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_client_to_client_reflection_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_client_to_client_reflection_cmd);

  /* "bgp always-compare-med" commands */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_always_compare_med_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_always_compare_med_cmd);

  /* "bgp deterministic-med" commands */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_deterministic_med_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_deterministic_med_cmd);

  /* "bgp fast-external-failover" commands */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_fast_external_failover_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_fast_external_failover_cmd);

  /* "bgp enforce-first-as" commands */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_enforce_first_as_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_enforce_first_as_cmd);

  /* "bgp bestpath compare-routerid" commands */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_bestpath_compare_router_id_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_bestpath_compare_router_id_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_bestpath_dont_compare_originator_id_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_bestpath_dont_compare_originator_id_cmd);

  /* "bgp bestpath tie-break-on-age" commands */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_bestpath_tie_break_on_age_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_bestpath_tie_break_on_age_cmd);
  
  /* "bgp bestpath as-path ignore" commands */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_bestpath_aspath_ignore_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_bestpath_aspath_ignore_cmd);

  /* "bgp bestpath med" commands */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_bestpath_med_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_bestpath_med2_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_bestpath_med3_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_bestpath_med_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_bestpath_med2_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_bestpath_med3_cmd);

  /* "no bgp default ipv4-unicast" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_default_ipv4_unicast_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_default_ipv4_unicast_cmd);

  /* "bgp bestpath compare-confed-aspath" */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_bestpath_compare_confed_aspath_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_bestpath_compare_confed_aspath_cmd);

  /* "bgp default local-preference" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_default_local_preference_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_default_local_preference_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_default_local_preference_val_cmd);

  /* "bgp log-neighbor-changes" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_log_neighbor_changes_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_log_neighbor_changes_cmd);

#ifdef HAVE_BGP_SDN
   cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
  	     	    &bgp_sdn_engine_cmd);
   cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
	     	    &no_bgp_sdn_engine_cmd);

   cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                    &bgp_rest_server_cmd);
   cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                    &no_bgp_rest_server_cmd);
#endif /* HAVE_BGP_SDN */
}

s_int32_t
bgp_peer_remote_as_vty (struct cli *cli, u_int8_t *peer_str,
                        u_int8_t *as_str, afi_t afi, safi_t safi)
{
  union sockunion su;
  u_int32_t tmp_as;
  struct bgp *bgp;
  s_int32_t ret;
  as_t as;


  /* Get AS number.  */
#ifndef HAVE_EXT_CAP_ASN
  CLI_GET_INTEGER_RANGE ("AS", tmp_as, as_str, 1, 65535);
  as = (u_int16_t)tmp_as;
#else
  CLI_GET_UINT32_RANGE ("AS", tmp_as, as_str, 1, 4294967295U);
  as = tmp_as;
  if ( (!BGP_IS_AS4_MAPPABLE (as)) && 
       (!CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)) )
    {
      return bgp_cli_return (cli, BGP_API_SET_ERR_NO_EXTASNCAP);
    }
  /* BGP_AS_TRANS cannot be configured as nbr only in an NBGP router
   * In OBGP router BGP_AS_TRANS can be used for nbr configuration. 
  */
  if ( (as == BGP_AS_TRANS) &&
       (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)) )
    {
      return bgp_cli_return (cli, BGP_API_SET_ERR_INVALID_REMOTEASN);   
    }
#endif /* HAVE_EXT_CAP_ASN */

  bgp = cli->index;

  /* If peer is peer group, call proper function.  */
  ret = str2sockunion (peer_str, &su);
  if (ret < 0)
    {
      ret = bgp_peer_group_remote_as (bgp, peer_str, &as);
      switch (ret)
        {
        case BGP_API_SET_SUCCESS:
          break;
        case BGP_API_SET_ERR_AS_MISMATCH:
          cli_out (cli, "AS number mismatch.\n");
          return CLI_ERROR;
          break;
        case BGP_API_SET_ERROR:
        default:
          cli_out (cli, "%% Create the peer-group first\n");
          return CLI_ERROR;
          break;
        }
      return CLI_SUCCESS;
    }

  if (PAL_TRUE == bgp_peer_address_self_check (bgp, &su))
    {
      cli_out (cli, "%% Cannot configure the local system as neighbor\n");
      return CLI_ERROR;
    }

  ret = bgp_peer_remote_as (bgp, &su, &as, afi, safi);
  switch (ret)
    {
    case BGP_API_SET_SUCCESS:
      break;
    case BGP_API_SET_ERR_PEER_CONFIG_IN_ANOTHER_INST:
      cli_out (cli, "%% Peer Configured in another BGP Instance\n");
      break;
    case BGP_API_SET_ERR_PEER_GROUP_AF_UNCONFIGURED:
      cli_out (cli, "%% Invalid address family\n");
      break;
    case BGP_API_SET_ERR_AS_MISMATCH:
      cli_out (cli, "%% AS number mismatch.\n");
      return CLI_ERROR;
      break;
    case BGP_API_SET_ERR_PEER_GROUP_MEMBER:
      cli_out (cli, "%% Peer-group AS %d. Cannot configure remote-as for member\n", as);
      return CLI_ERROR;
      break;
    case BGP_API_SET_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT:
      cli_out (cli, "%% The AS# can not be changed from %d to %s, peer-group members must be all internal or all external\n", as, as_str);
      return CLI_ERROR;
      break;
    case BGP_API_SET_ERROR:
    default:
      cli_out (cli, "%% Peer creation failed\n");
      return CLI_ERROR;
      break;
    }

  return bgp_cli_return (cli, ret);
}
#ifndef HAVE_EXT_CAP_ASN
CLI (neighbor_remote_as,
     neighbor_remote_as_cmd,
     NEIGHBOR_CMD2 "remote-as <1-65535>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Specify AS number of BGP neighbor",
     CLI_AS_STR)
#else
CLI (neighbor_remote_as,
     neighbor_remote_as_cmd,
     NEIGHBOR_CMD2 "remote-as <1-4294967295>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Specify AS number of BGP neighbor",
     CLI_AS_STR)
#endif /* HAVE_EXT_CAP_ASN */
{
  return bgp_peer_remote_as_vty (cli, argv[0], argv[1],
                                 bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi(cli));
}

#ifndef HAVE_EXT_CAP_ASN
CLI (neighbor_local_as,
     neighbor_local_as_cmd,
     NEIGHBOR_CMD2 "local-as <1-65535>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Specify AS number to use with BGP neighbor",
     CLI_AS_STR)
#else
CLI (neighbor_local_as,
     neighbor_local_as_cmd,
     NEIGHBOR_CMD2 "local-as <1-4294967295>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Specify AS number to use with BGP neighbor",
     CLI_AS_STR)
#endif /* HAVE_EXT_CAP_ASN */
{
  struct bgp_peer *peer;
  s_int32_t ret;

  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  ret = bgp_peer_set_local_as (peer, pal_strtos32 (argv[1], (char **) NULL, 10));

  return bgp_cli_return (cli, ret);  
}

#ifndef HAVE_EXT_CAP_ASN
CLI (no_neighbor_local_as,
     no_neighbor_local_as_cmd,
     NO_NEIGHBOR_CMD2 "local-as <1-65535>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Specify AS number to use with BGP neighbor",
     CLI_AS_STR)
#else
CLI (no_neighbor_local_as,
     no_neighbor_local_as_cmd,
     NO_NEIGHBOR_CMD2 "local-as <1-4294967295>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Specify AS number to use with BGP neighbor",
     CLI_AS_STR)
#endif /* HAVE_EXT_CAP_ASN */
{
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  return (bgp_peer_unset_local_as (peer));
}

CLI (bgp_no_neighbor,
     bgp_no_neighbor_cmd,
     NO_NEIGHBOR_CMD2,
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2)
{
  struct bgp_peer_group *group;
  struct bgp_peer *peer;
  union sockunion su;
  u_int32_t tmp_as;
  s_int32_t ret;
  as_t as;

  ret = BGP_API_SET_SUCCESS;
  tmp_as = 0;
  peer = NULL;

  if (argc > 1)
#ifndef HAVE_EXT_CAP_ASN
  CLI_GET_INTEGER_RANGE ("AS", tmp_as, argv[1], 1, 65535);
  as = (u_int16_t) tmp_as;
#else
  CLI_GET_UINT32_RANGE ("AS", tmp_as, argv[1], 1, 4294967295U);
  as = tmp_as;
#endif /* HAVE_EXT_CAP_ASN */

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      ret = BGP_API_SET_SUCCESS;

      group = bgp_peer_group_lookup (cli->index, argv[0]);
      if (group)
        {
          if (argc > 1 && group->conf->as != as)
            ret = BGP_API_SET_ERR_REMOTE_AS_MISMATCH;

          bgp_peer_group_remote_as_delete (group);
        }
      else
        {
          cli_out (cli, "%% Create the peer-group first\n");
          return CLI_ERROR;
        }
    }
  else
    {
      if (bgp_peer_address_self_check (cli->index, &su))
        {
          cli_out (cli, "%% Cannot configure the local system as neighbor\n");
          return CLI_ERROR;
        }

      ret = BGP_API_SET_SUCCESS;

      peer = bgp_peer_search (cli->index, &su);
      if (peer)
        {
          if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
            {
              if (argc > 1 && peer->as != as)
                {
                  ret = BGP_API_SET_ERR_REMOTE_AS_MISMATCH;
                  goto EXIT;
                }
              bgp_peer_pbgp_node_inctx_get (cli->index, peer);

              if (!peer->pbgp_node_inctx)
                {
                  cli_out (cli, "%% No such Peer in this bgp instance\n");
                  return CLI_ERROR; 
                }

              /* Only delete the pointer from the peer's bgp_node list
               * if this peer is in multiple instances 
               * If the current instance is the only instance in which
               * peer is present then do the normal deletion */ 
              if (peer->refcnt > 1)          
                {
                  if (peer->pbgp_node_inctx->bgp == cli->index)
                    cli_out (cli, "%%Peer need to be deleted from other views"
                              "before deleting from owning view \n");
                  ret = bgp_peer_del_in_multi_ins (cli->index, peer);
                  peer->pbgp_node_inctx = NULL;
                  goto EXIT;
                }
            }
          else if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE)
              && peer->bgp != cli->index)
            {
              ret = BGP_API_SET_ERR_PEER_CONFIG_IN_ANOTHER_INST;
              goto EXIT;
            }

          if (argc > 1 && peer->as != as)
            ret = BGP_API_SET_ERR_REMOTE_AS_MISMATCH;

          bgp_log_neighbor_status_print (peer, PEER_LOG_STATUS_DOWN,
                                         "Neighbor Deleted");
          bgp_peer_config_delete (peer);
        }
    }

 EXIT:

  return bgp_cli_return (cli, ret);
}
#ifndef HAVE_EXT_CAP_ASN
ALI (bgp_no_neighbor,
     no_neighbor_remote_as_cmd,
     NO_NEIGHBOR_CMD2 "remote-as <1-65535>",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Specify a BGP neighbor",
     CLI_AS_STR);
#else
ALI (bgp_no_neighbor,
     no_neighbor_remote_as_cmd,
     NO_NEIGHBOR_CMD2 "remote-as <1-4294967295>",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Specify a BGP neighbor",
     CLI_AS_STR);
#endif /* HAVE_EXT_CAP_ASN */


CLI (neighbor_peer_group,
     neighbor_peer_group_cmd,
     "neighbor WORD peer-group",
     CLI_NEIGHBOR_STR,
     "Neighbor tag",
     "Configure peer-group")
{
  struct bgp *bgp;
  struct bgp_peer_group *group;

  bgp = cli->index;

  group = bgp_peer_group_get (bgp, argv[0]);
  if (! group)
    return bgp_cli_return (cli, BGP_API_SET_ERROR);

  return CLI_SUCCESS;
}

CLI (no_neighbor_peer_group,
     no_neighbor_peer_group_cmd,
     "no neighbor WORD peer-group",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     "Neighbor tag",
     "Configure peer-group")
{
  struct bgp_peer_group *group;
  struct bgp *bgp;

  bgp = cli->index;

  group = bgp_peer_group_lookup (bgp, argv[0]);
  if (group)
    bgp_peer_group_delete (group);
  else
    {
      cli_out (cli, "%% Create the peer-group first\n");
      return CLI_ERROR;
    }
  return CLI_SUCCESS;
}

CLI (neighbor_activate,
     neighbor_activate_cmd,
     NEIGHBOR_CMD2 "activate",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Enable the Address Family for this Neighbor")
{
  struct bgp_peer *peer;
  int ret;

  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  ret = peer_activate (cli->index, peer, bgp_cli_mode_afi (cli),
                       bgp_cli_mode_safi (cli));

  return bgp_cli_return (cli, ret);
}

CLI (no_neighbor_activate,
     no_neighbor_activate_cmd,
     NO_NEIGHBOR_CMD2 "activate",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Enable the Address Family for this Neighbor")
{
  struct bgp_peer_group *group;
  struct bgp_peer *peer1;
  struct bgp_peer *peer;
  struct listnode *nn;
  s_int8_t ret;
  safi_t safi;
  afi_t afi;

  safi = bgp_cli_mode_safi (cli);
  afi = bgp_cli_mode_afi (cli);

  /* Lookup peer. */
  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP))
    {
      group = peer->group;

      if (!group)
        return CLI_ERROR;

      if (peer->group->conf == peer)
        {
          ret = peer_deactivate (peer, afi, safi);

          LIST_LOOP (group->peer_list, peer1, nn)
            if (peer1->af_group [BGP_AFI2BAAI (afi)]
		[BGP_SAFI2BSAI (safi)])
              ret = peer_deactivate (peer1, afi, safi);
        }
      else
        ret = peer_deactivate (peer, afi, safi);
    }
  else
    ret = peer_deactivate (peer, afi, safi);

  return bgp_cli_return (cli, ret);
}

CLI (neighbor_set_peer_group,
     neighbor_set_peer_group_cmd,
     NEIGHBOR_CMD "peer-group WORD",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR,
     "Member of the peer-group",
     "peer-group name")
{
  int ret;
  as_t as;
  union sockunion su;
  struct bgp *bgp;
  struct bgp_peer_group *group;

  bgp = cli->index;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      cli_out (cli, "%% Malformed address: %s\n", argv[0]);
      return CLI_ERROR;
    }

  if (PAL_TRUE == bgp_peer_address_self_check (bgp, &su))
    {
      cli_out (cli, "%% Cannot configure the local system as neighbor\n");
      return CLI_ERROR;
    }

  group = bgp_peer_group_lookup (bgp, argv[1]);
  if (! group)
    {
      cli_out (cli, "%% Configure the peer-group first\n");
      return CLI_ERROR;
    }

  ret = bgp_peer_group_bind (bgp, &su, group,
                             bgp_cli_mode_afi (cli),
                             bgp_cli_mode_safi (cli), &as);

  if (ret == BGP_API_SET_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT)
    {
      cli_out (cli, "%% Peer with AS %d cannot be in this "
               "peer-group, members must be all internal or"
               " all external\n", as);
      return CLI_ERROR;
    }
  else if (ret == BGP_API_SET_ERR_PEER_GROUP_AF_INVALID)
    {
      cli_out (cli, "%% Peer cannot be in this peer-group, "
               "address family mismatch\n");
      return CLI_ERROR;
    }

  return bgp_cli_return (cli, ret);
}

CLI (no_neighbor_set_peer_group,
     no_neighbor_set_peer_group_cmd,
     NO_NEIGHBOR_CMD "peer-group WORD",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR,
     "Member of the peer-group",
     "peer-group name")
{
  int ret;
  struct bgp *bgp;
  struct bgp_peer *peer;
  struct bgp_peer_group *group;

  bgp = cli->index;

  peer = bgp_peer_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  group = bgp_peer_group_lookup (bgp, argv[1]);
  if (! group)
    {
      cli_out (cli, "%% Configure the peer-group first\n");
      return CLI_ERROR;
    }

  ret = bgp_peer_group_unbind (bgp, peer, group,
                               bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli));

  return bgp_cli_return (cli, ret);
}

int
peer_flag_modify_vty (struct cli *cli, char *ip_str, u_int16_t flag, int set)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  if (set)
    ret = peer_flag_set (peer, flag);
  else
    ret = peer_flag_unset (peer, flag);

  return bgp_cli_return (cli, ret);
}

int
peer_flag_set_vty (struct cli *cli, char *ip_str, u_int16_t flag)
{
  return peer_flag_modify_vty (cli, ip_str, flag, 1);
}

int
peer_flag_unset_vty (struct cli *cli, char *ip_str, u_int16_t flag)
{
  return peer_flag_modify_vty (cli, ip_str, flag, 0);
}

/* neighbor passive. */
CLI (neighbor_passive,
     neighbor_passive_cmd,
     NEIGHBOR_CMD2 "passive",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Don't send open messages to this neighbor")
{
  return peer_flag_set_vty (cli, argv[0], PEER_FLAG_PASSIVE);
}

CLI (no_neighbor_passive,
     no_neighbor_passive_cmd,
     NO_NEIGHBOR_CMD2 "passive",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Don't send open messages to this neighbor")
{
  return peer_flag_unset_vty (cli, argv[0], PEER_FLAG_PASSIVE);
}

/* neighbor shutdown. */
CLI (neighbor_shutdown,
     neighbor_shutdown_cmd,
     NEIGHBOR_CMD2 "shutdown",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Administratively shut down this neighbor")
{
  return peer_flag_set_vty (cli, argv[0], PEER_FLAG_SHUTDOWN);
}

CLI (no_neighbor_shutdown,
     no_neighbor_shutdown_cmd,
     NO_NEIGHBOR_CMD2 "shutdown",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Administratively shut down this neighbor")
{
  return peer_flag_unset_vty (cli, argv[0], PEER_FLAG_SHUTDOWN);
}

/* neighbor capability route-refresh. */
CLI (neighbor_capability_route_refresh,
     neighbor_capability_route_refresh_cmd,
     NEIGHBOR_CMD2 "capability route-refresh",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Advertise capability to the peer",
     "Advertise route-refresh capability to this neighbor")
{
  return peer_flag_unset_vty (cli, argv[0], PEER_FLAG_NO_ROUTE_REFRESH_CAP);
}

CLI (no_neighbor_capability_route_refresh,
     no_neighbor_capability_route_refresh_cmd,
     NO_NEIGHBOR_CMD2 "capability route-refresh",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Advertise capability to the peer",
     "Advertise route-refresh capability to this neighbor")
{
  return peer_flag_set_vty (cli, argv[0], PEER_FLAG_NO_ROUTE_REFRESH_CAP);
}

/* neighbor capability dynamic. */
CLI (neighbor_capability_dynamic,
     neighbor_capability_dynamic_cmd,
     NEIGHBOR_CMD2 "capability dynamic",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Advertise capability to the peer",
     "Advertise dynamic capability to this neighbor")
{
  return peer_flag_set_vty (cli, argv[0], PEER_FLAG_DYNAMIC_CAPABILITY);
}

CLI (no_neighbor_capability_dynamic,
     no_neighbor_capability_dynamic_cmd,
     NO_NEIGHBOR_CMD2 "capability dynamic",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Advertise capability to the peer",
     "Advertise dynamic capability to this neighbor")
{
  return peer_flag_unset_vty (cli, argv[0], PEER_FLAG_DYNAMIC_CAPABILITY);
}

/* neighbor dont-capability-negotiate */
CLI (neighbor_dont_capability_negotiate,
     neighbor_dont_capability_negotiate_cmd,
     NEIGHBOR_CMD2 "dont-capability-negotiate",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Do not perform capability negotiation")
{
  return peer_flag_set_vty (cli, argv[0], PEER_FLAG_DONT_CAPABILITY);
}

CLI (no_neighbor_dont_capability_negotiate,
     no_neighbor_dont_capability_negotiate_cmd,
     NO_NEIGHBOR_CMD2 "dont-capability-negotiate",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Do not perform capability negotiation")
{
  return peer_flag_unset_vty (cli, argv[0], PEER_FLAG_DONT_CAPABILITY);
}

int
peer_af_flag_modify_vty (struct cli *cli, char *peer_str, afi_t afi,
                         safi_t safi, u_int32_t flag, int set)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, peer_str);
  if (! peer)
    return CLI_ERROR;

  if (set)
    ret = peer_af_flag_set (peer, afi, safi, flag);
  else
    ret = peer_af_flag_unset (peer, afi, safi, flag);

  return bgp_cli_return (cli, ret);
}

int
peer_af_flag_set_vty (struct cli *cli, char *peer_str, afi_t afi,
                      safi_t safi, u_int32_t flag)
{
  return peer_af_flag_modify_vty (cli, peer_str, afi, safi, flag, 1);
}

int
peer_af_flag_unset_vty (struct cli *cli, char *peer_str, afi_t afi,
                        safi_t safi, u_int32_t flag)
{
  return peer_af_flag_modify_vty (cli, peer_str, afi, safi, flag, 0);
}

/* neighbor capability orf prefix-list. */
CLI (neighbor_capability_orf_prefix,
     neighbor_capability_orf_prefix_cmd,
     NEIGHBOR_CMD2 "capability orf prefix-list (both|receive|send)",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Advertise capability to the peer",
     "Advertise ORF capability to the peer",
     "Advertise prefixlist ORF capability to this neighbor",
     "Capability to SEND and RECEIVE the ORF to/from this neighbor",
     "Capability to RECEIVE the ORF from this neighbor",
     "Capability to SEND the ORF to this neighbor")
{
  u_int16_t flag = 0;

  if (pal_strncmp (argv[1], "s", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_SM;
  else if (pal_strncmp (argv[1], "r", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_RM;
  else if (pal_strncmp (argv[1], "b", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_SM|PEER_FLAG_ORF_PREFIX_RM;
  else
    return CLI_ERROR;

  return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli), flag);
}

CLI (no_neighbor_capability_orf_prefix,
     no_neighbor_capability_orf_prefix_cmd,
     NO_NEIGHBOR_CMD2 "capability orf prefix-list (both|receive|send)",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Advertise capability to the peer",
     "Advertise ORF capability to the peer",
     "Advertise prefixlist ORF capability to this neighbor",
     "Capability to SEND and RECEIVE the ORF to/from this neighbor",
     "Capability to RECEIVE the ORF from this neighbor",
     "Capability to SEND the ORF to this neighbor")
{
  u_int16_t flag = 0;

  if (pal_strncmp (argv[1], "s", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_SM;
  else if (pal_strncmp (argv[1], "r", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_RM;
  else if (pal_strncmp (argv[1], "b", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_SM|PEER_FLAG_ORF_PREFIX_RM;
  else
    return CLI_ERROR;

  return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli), flag);
}

/* neighbor next-hop-self. */
CLI (neighbor_nexthop_self,
     neighbor_nexthop_self_cmd,
     NEIGHBOR_CMD2 "next-hop-self",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Disable the next hop calculation for this neighbor")
{
  return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli), PEER_FLAG_NEXTHOP_SELF);
}

CLI (no_neighbor_nexthop_self,
     no_neighbor_nexthop_self_cmd,
     NO_NEIGHBOR_CMD2 "next-hop-self",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Disable the next hop calculation for this neighbor")
{
  return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli), PEER_FLAG_NEXTHOP_SELF);
}

/* neighbor remove-private-AS. */
CLI (neighbor_remove_private_as,
     neighbor_remove_private_as_cmd,
     NEIGHBOR_CMD2 "remove-private-AS",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Remove private AS number from outbound updates")
{
  return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli),
                               PEER_FLAG_REMOVE_PRIVATE_AS);
}

CLI (no_neighbor_remove_private_as,
     no_neighbor_remove_private_as_cmd,
     NO_NEIGHBOR_CMD2 "remove-private-AS",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Remove private AS number from outbound updates")
{
  return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli),
                                 PEER_FLAG_REMOVE_PRIVATE_AS);
}

/* neighbor send-community. */
CLI (neighbor_send_community,
     neighbor_send_community_cmd,
     NEIGHBOR_CMD2 "send-community",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Send Community attribute to this neighbor")
{
  return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli),
                               PEER_FLAG_SEND_COMMUNITY);
}

CLI (no_neighbor_send_community,
     no_neighbor_send_community_cmd,
     NO_NEIGHBOR_CMD2 "send-community",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Send Community attribute to this neighbor")
{
  return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli),
                                 PEER_FLAG_SEND_COMMUNITY);
}

/* neighbor send-community extended. */
CLI (neighbor_send_community_type,
     neighbor_send_community_type_cmd,
     NEIGHBOR_CMD2 "send-community (both|extended|standard)",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Send Community attribute to this neighbor",
     "Send Standard and Extended Community attributes",
     "Send Extended Community attributes",
     "Send Standard Community attributes")
{
  if (pal_strncmp (argv[1], "s", 1) == 0)
    return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli),
                                 PEER_FLAG_SEND_COMMUNITY);
  if (pal_strncmp (argv[1], "e", 1) == 0)
    return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli),
                                 PEER_FLAG_SEND_EXT_COMMUNITY);

  return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli),
                               (PEER_FLAG_SEND_COMMUNITY|
                                PEER_FLAG_SEND_EXT_COMMUNITY));
}

CLI (no_neighbor_send_community_type,
     no_neighbor_send_community_type_cmd,
     NO_NEIGHBOR_CMD2 "send-community (both|extended|standard)",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Send Community attribute to this neighbor",
     "Send Standard and Extended Community attributes",
     "Send Extended Community attributes",
     "Send Standard Community attributes")
{
  if (pal_strncmp (argv[1], "s", 1) == 0)
    return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                   bgp_cli_mode_safi (cli),
                                   PEER_FLAG_SEND_COMMUNITY);
  if (pal_strncmp (argv[1], "e", 1) == 0)
    return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                   bgp_cli_mode_safi (cli),
                                   PEER_FLAG_SEND_EXT_COMMUNITY);

  return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli),
                                 (PEER_FLAG_SEND_COMMUNITY |
                                  PEER_FLAG_SEND_EXT_COMMUNITY));
}

/* neighbor soft-reconfig. */
CLI (neighbor_soft_reconfiguration,
     neighbor_soft_reconfiguration_cmd,
     NEIGHBOR_CMD2 "soft-reconfiguration inbound",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Per neighbor soft reconfiguration",
     "Allow inbound soft reconfiguration for this neighbor")
{
  return peer_af_flag_set_vty (cli, argv[0],
                               bgp_cli_mode_afi (cli), bgp_cli_mode_safi (cli),
                               PEER_FLAG_SOFT_RECONFIG);
}

CLI (no_neighbor_soft_reconfiguration,
     no_neighbor_soft_reconfiguration_cmd,
     NO_NEIGHBOR_CMD2 "soft-reconfiguration inbound",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Per neighbor soft reconfiguration",
     "Allow inbound soft reconfiguration for this neighbor")
{
  return peer_af_flag_unset_vty (cli, argv[0],
                                 bgp_cli_mode_afi (cli), bgp_cli_mode_safi (cli),
                                 PEER_FLAG_SOFT_RECONFIG);
}

CLI (neighbor_route_reflector_client,
     neighbor_route_reflector_client_cmd,
     NEIGHBOR_CMD2 "route-reflector-client",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Configure a neighbor as Route Reflector client")
{
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli),
                               PEER_FLAG_REFLECTOR_CLIENT);
}

CLI (no_neighbor_route_reflector_client,
     no_neighbor_route_reflector_client_cmd,
     NO_NEIGHBOR_CMD2 "route-reflector-client",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Configure a neighbor as Route Reflector client")
{
  return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli),
                                 PEER_FLAG_REFLECTOR_CLIENT);
}

/* neighbor route-server-client. */
CLI (neighbor_route_server_client,
     neighbor_route_server_client_cmd,
     NEIGHBOR_CMD2 "route-server-client",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Configure a neighbor as Route Server client")
{
  return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli),
                               PEER_FLAG_RSERVER_CLIENT);
}

CLI (no_neighbor_route_server_client,
     no_neighbor_route_server_client_cmd,
     NO_NEIGHBOR_CMD2 "route-server-client",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Configure a neighbor as Route Server client")
{
  return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli),
                                 PEER_FLAG_RSERVER_CLIENT);
}

CLI (neighbor_attr_unchanged,
     neighbor_attr_unchanged_cmd,
     NEIGHBOR_CMD2 "attribute-unchanged ({ as-path|next-hop|med }|)",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP attribute is propagated unchanged to this neighbor",
     "As-path attribute",
     "Next-hop attribute",
     "Med attribute")
{
  u_int16_t flags = 0;
  int i;

  if (argc == 1)
    {
      SET_FLAG (flags, PEER_FLAG_AS_PATH_UNCHANGED);
      SET_FLAG (flags, PEER_FLAG_NEXTHOP_UNCHANGED);
      SET_FLAG (flags, PEER_FLAG_MED_UNCHANGED);
      return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                   bgp_cli_mode_safi (cli), flags);
    }

  for (i = 1; i < argc; i++)
    {
      if (pal_strncmp (argv[i], "a", 1) == 0)
        SET_FLAG (flags, PEER_FLAG_AS_PATH_UNCHANGED);
      else if (pal_strncmp (argv[i], "n", 1) == 0)
        SET_FLAG (flags, PEER_FLAG_NEXTHOP_UNCHANGED);
      else if (pal_strncmp (argv[i], "m", 1) == 0)
        SET_FLAG (flags, PEER_FLAG_MED_UNCHANGED);
    }

  return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli), flags);
}

CLI (no_neighbor_attr_unchanged,
     no_neighbor_attr_unchanged_cmd,
     NO_NEIGHBOR_CMD2 "attribute-unchanged ({ as-path|next-hop|med }|)",
     CLI_NO_STR         ,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP attribute is propagated unchanged to this neighbor",
     "As-path attribute",
     "Next-hop attribute",
     "Med attribute")
{
  u_int16_t flags = 0;
  int i;

  if (argc == 1)
    {
      SET_FLAG (flags, PEER_FLAG_AS_PATH_UNCHANGED);
      SET_FLAG (flags, PEER_FLAG_NEXTHOP_UNCHANGED);
      SET_FLAG (flags, PEER_FLAG_MED_UNCHANGED);
      return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                     bgp_cli_mode_safi (cli), flags);
    }

  for (i = 1; i < argc; i++)
    {
      if (pal_strncmp (argv[i], "a", 1) == 0)
        SET_FLAG (flags, PEER_FLAG_AS_PATH_UNCHANGED);
      else if (pal_strncmp (argv[i], "n", 1) == 0)
        SET_FLAG (flags, PEER_FLAG_NEXTHOP_UNCHANGED);
      else if (pal_strncmp (argv[i], "m", 1) == 0)
        SET_FLAG (flags, PEER_FLAG_MED_UNCHANGED);
    }

  return peer_af_flag_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli), flags);
}

/* For old version BGP-SDN compatibility.  */
CLI (neighbor_transparent_as,
     neighbor_transparent_as_cmd,
     NEIGHBOR_CMD2 "transparent-as",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Do not append my AS number even when peer is EBGP")
{
  return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli),
                               PEER_FLAG_AS_PATH_UNCHANGED);
}

CLI (neighbor_transparent_nexthop,
     neighbor_transparent_nexthop_cmd,
     NEIGHBOR_CMD2 "transparent-nexthop",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Do not change nexthop even when peer is EBGP")
{
  return peer_af_flag_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                               bgp_cli_mode_safi (cli),
                               PEER_FLAG_NEXTHOP_UNCHANGED);
}

/* EBGP multihop configuration. */
int
peer_ebgp_multihop_set_vty (struct cli *cli, char *ip_str, char *ttl_str)
{
  struct bgp_peer *peer;
  int ttl;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  if (! ttl_str)
    ttl = BGP_PEER_TTL_MAX;
  else
    CLI_GET_INTEGER_RANGE ("TTL", ttl, ttl_str, 1, 255);

  peer_ebgp_multihop_set (peer, ttl);

  return CLI_SUCCESS;
}

int
peer_ebgp_multihop_unset_vty (struct cli *cli, char *ip_str)
{
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  peer_ebgp_multihop_unset (peer);

  return CLI_SUCCESS;
}
/* neighbor ebgp-multihop. */
CLI (neighbor_ebgp_multihop,
     neighbor_ebgp_multihop_cmd,
     NEIGHBOR_CMD2 "ebgp-multihop",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Allow EBGP neighbors not on directly connected networks")
{
  return peer_ebgp_multihop_set_vty (cli, argv[0], NULL);
}

CLI (neighbor_ebgp_multihop_ttl,
     neighbor_ebgp_multihop_ttl_cmd,
     NEIGHBOR_CMD2 "ebgp-multihop <1-255>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Allow EBGP neighbors not on directly connected networks",
     "maximum hop count")
{
  return peer_ebgp_multihop_set_vty (cli, argv[0], argv[1]);
}

CLI (no_neighbor_ebgp_multihop,
     no_neighbor_ebgp_multihop_cmd,
     NO_NEIGHBOR_CMD2 "ebgp-multihop",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Allow EBGP neighbors not on directly connected networks")
{
  return peer_ebgp_multihop_unset_vty (cli, argv[0]);
}

ALI (no_neighbor_ebgp_multihop,
     no_neighbor_ebgp_multihop_ttl_cmd,
     NO_NEIGHBOR_CMD2 "ebgp-multihop <1-255>",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Allow EBGP neighbors not on directly connected networks",
     "maximum hop count");

/* Enforce multihop.  */
CLI (neighbor_enforce_multihop,
     neighbor_enforce_multihop_cmd,
     NEIGHBOR_CMD2 "enforce-multihop",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Enforce EBGP neighbors to perform multihop")
{
  return peer_flag_set_vty (cli, argv[0], PEER_FLAG_ENFORCE_MULTIHOP);
}

CLI (no_neighbor_enforce_multihop,
     no_neighbor_enforce_multihop_cmd,
     NO_NEIGHBOR_CMD2 "enforce-multihop",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Enforce EBGP neighbors to perform multihop")
{
  return peer_flag_unset_vty (cli, argv[0], PEER_FLAG_ENFORCE_MULTIHOP);
}

CLI (neighbor_description,
     neighbor_description_cmd,
     NEIGHBOR_CMD2 "description LINE",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Neighbor specific description",
     "Up to 80 characters describing this neighbor")
{
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  if (argc == 1)
    return CLI_SUCCESS;

  /* Make string from buffer.  This function should be provided by
     buffer.c. */
  peer_description_set (peer, argv[1]);

  return CLI_SUCCESS;
}

CLI (no_neighbor_description,
     no_neighbor_description_cmd,
     NO_NEIGHBOR_CMD2 "description",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Neighbor specific description")
{
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  peer_description_unset (peer);

  return CLI_SUCCESS;
}

ALI (no_neighbor_description,
     no_neighbor_description_val_cmd,
     NO_NEIGHBOR_CMD2 "description LINE",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Neighbor specific description",
     "Up to 80 characters describing this neighbor");
/* Neighbor update-source. */
int
peer_update_source_vty (struct cli *cli, char *peer_str, char *source_str)
{
  struct bgp_peer *peer;
  union sockunion *su;

  peer = bgp_peer_and_group_lookup_vty (cli, peer_str);
  if (! peer)
    return CLI_ERROR;

  if (source_str)
    {
      su = sockunion_str2su (source_str);
      if (su)
        {
          peer_update_source_addr_set (peer, su);
          sockunion_free (su);
        }
      else
        peer_update_source_if_set (peer, source_str);
    }
  else
    peer_update_source_unset (peer);

  return CLI_SUCCESS;
}

CLI (neighbor_update_source,
     neighbor_update_source_cmd,
     NEIGHBOR_CMD2 "update-source WORD",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Source of routing updates",
     "Interface name or address")
{
  return peer_update_source_vty (cli, argv[0], argv[1]);
}

CLI (no_neighbor_update_source,
     no_neighbor_update_source_cmd,
     NO_NEIGHBOR_CMD2 "update-source",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Source of routing updates")
{
  return peer_update_source_vty (cli, argv[0], NULL);
}

int
peer_default_originate_set_vty (struct cli *cli, char *peer_str, afi_t afi,
                                safi_t safi, char *rmap, int set)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, peer_str);
  if (! peer)
    return CLI_ERROR;

  if (set)
    ret = peer_default_originate_set (peer, afi, safi, rmap);
  else
    ret = peer_default_originate_unset (peer, afi, safi, PAL_FALSE);

  return bgp_cli_return (cli, ret);
}

/* neighbor default-originate. */
CLI (neighbor_default_originate,
     neighbor_default_originate_cmd,
     NEIGHBOR_CMD2 "default-originate",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Originate default route to this neighbor")
{
  return peer_default_originate_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                         bgp_cli_mode_safi (cli), NULL, 1);
}

CLI (neighbor_default_originate_rmap,
     neighbor_default_originate_rmap_cmd,
     NEIGHBOR_CMD2 "default-originate route-map WORD",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Originate default route to this neighbor",
     "Route-map to specify criteria to originate default",
     "route-map name")
{
  return peer_default_originate_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                         bgp_cli_mode_safi (cli), argv[1], 1);
}

CLI (no_neighbor_default_originate,
     no_neighbor_default_originate_cmd,
     NO_NEIGHBOR_CMD2 "default-originate",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Originate default route to this neighbor")
{
  return peer_default_originate_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                         bgp_cli_mode_safi (cli), NULL, 0);
}

ALI (no_neighbor_default_originate,
     no_neighbor_default_originate_rmap_cmd,
     NO_NEIGHBOR_CMD2 "default-originate route-map WORD",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Originate default route to this neighbor",
     "Route-map to specify criteria to originate default",
     "route-map name");


/* Set neighbor's BGP port.  */
int
peer_port_vty (struct cli *cli, char *ip_str, int afi, char *port_str)
{
  struct bgp_peer *peer;
  u_int16_t port;
  int ret;
  struct pal_servent *sp;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  if (! port_str)
    {
      sp = (struct pal_servent *) pal_getservbyname ("bgp", "tcp");
      port = (sp == NULL)  ? BGP_PORT_DEFAULT : pal_ntoh16 (sp->s_port);
    }
  else
    {
      CLI_GET_INTEGER("port", port, port_str);
    }

  ret = peer_port_set (peer, port);

  return bgp_cli_return(cli,ret);
}

CLI (neighbor_port,
     neighbor_port_cmd,
     NEIGHBOR_CMD2 "port <0-65535>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Neighbor's BGP port",
     "TCP port number")
{
  return peer_port_vty (cli, argv[0], AFI_IP, argv[1]);
}

CLI (no_neighbor_port,
     no_neighbor_port_cmd,
     NO_NEIGHBOR_CMD2 "port",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Neighbor's BGP port")
{
  return peer_port_vty (cli, argv[0], AFI_IP, NULL);
}

ALI (no_neighbor_port,
     no_neighbor_port_val_cmd,
     NO_NEIGHBOR_CMD2 "port <0-65535>",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Neighbor's BGP port",
     "TCP port number");

/* neighbor weight. */
int
peer_weight_set_vty (struct cli *cli, char *ip_str, char *weight_str)
{
  int ret = 0;
  afi_t afi = 0;
  safi_t safi = 0;
  u_int32_t weight = 0;
  struct bgp_peer *peer = NULL;

  afi =  bgp_cli_mode_afi (cli);
  safi = bgp_cli_mode_safi(cli);

  CLI_GET_UINT32_RANGE ("weight", weight, weight_str, 0, 65535);

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  ret = peer_weight_set (peer, weight, afi, safi);

  return bgp_cli_return (cli, ret);
}

int
peer_weight_unset_vty (struct cli *cli, char *ip_str)
{
  int ret = 0;
  afi_t afi = 0;
  safi_t safi = 0;
  struct bgp_peer *peer = NULL;

  afi =  bgp_cli_mode_afi (cli);
  safi = bgp_cli_mode_safi(cli);

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  ret = peer_weight_unset (peer, afi, safi);

  return bgp_cli_return (cli, ret);
}

CLI (neighbor_weight,
     neighbor_weight_cmd,
     NEIGHBOR_CMD2 "weight <0-65535>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Set default weight for routes from this neighbor",
     "default weight")
{
  return peer_weight_set_vty (cli, argv[0], argv[1]);
}

CLI (no_neighbor_weight,
     no_neighbor_weight_cmd,
     NO_NEIGHBOR_CMD2 "weight",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Set default weight for routes from this neighbor")
{
  return peer_weight_unset_vty (cli, argv[0]);
}

ALI (no_neighbor_weight,
     no_neighbor_weight_val_cmd,
     NO_NEIGHBOR_CMD2 "weight <0-65535>",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Set default weight for routes from this neighbor",
     "default weight");


/* Enable Collision Detection to include Peers in ESTABLISHED state */
CLI (neighbor_collide_established,
     neighbor_collide_established_cmd,
     NEIGHBOR_CMD2 "collide-established",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Include Neighbor in Established State for Collision Detection")
{
  return peer_flag_set_vty (cli, argv[0],
                            PEER_FLAG_COLLIDE_ESTABLISHED);
}

CLI (no_neighbor_collide_established,
     no_neighbor_collide_established_cmd,
     NO_NEIGHBOR_CMD2 "collide-established",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Include Neighbor in Established State for Collision Detection")
{
  return peer_flag_unset_vty (cli, argv[0],
                              PEER_FLAG_COLLIDE_ESTABLISHED);
}

/* Override capability negotiation. */
CLI (neighbor_override_capability,
     neighbor_override_capability_cmd,
     NEIGHBOR_CMD2 "override-capability",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Override capability negotiation result")
{
  return peer_flag_set_vty (cli, argv[0], PEER_FLAG_OVERRIDE_CAPABILITY);
}

CLI (no_neighbor_override_capability,
     no_neighbor_override_capability_cmd,
     NO_NEIGHBOR_CMD2 "override-capability",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Override capability negotiation result")
{
  return peer_flag_unset_vty (cli, argv[0], PEER_FLAG_OVERRIDE_CAPABILITY);
}

CLI (neighbor_strict_capability,
     neighbor_strict_capability_cmd,
     NEIGHBOR_CMD2 "strict-capability-match",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Strict capability negotiation match")
{
  return peer_flag_set_vty (cli, argv[0], PEER_FLAG_STRICT_CAP_MATCH);
}

CLI (no_neighbor_strict_capability,
     no_neighbor_strict_capability_cmd,
     NO_NEIGHBOR_CMD2 "strict-capability-match",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Strict capability negotiation match")
{
  return peer_flag_unset_vty (cli, argv[0], PEER_FLAG_STRICT_CAP_MATCH);
}

int
peer_timers_set_vty (struct cli *cli, char *ip_str, char *keep_str,
                     char *hold_str)
{
  int ret;
  struct bgp_peer *peer;
  u_int32_t keepalive;
  u_int32_t holdtime;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  CLI_GET_UINT32_RANGE ("Keepalive", keepalive, keep_str, 0, 65535);
  CLI_GET_UINT32_RANGE ("Holdtime", holdtime, hold_str, 0, 65535);

  ret = peer_timers_set (peer, keepalive, holdtime);

  return bgp_cli_return (cli, ret);
}

int
peer_timers_unset_vty (struct cli *cli, char *ip_str)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  ret = peer_timers_unset (peer);

  return bgp_cli_return (cli, ret);
}

CLI (neighbor_timers,
     neighbor_timers_cmd,
     NEIGHBOR_CMD2 "timers <0-65535> <0-65535>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP per neighbor timers",
     "Keepalive interval",
     "Holdtime")
{
  return peer_timers_set_vty (cli, argv[0], argv[1], argv[2]);
}

CLI (no_neighbor_timers,
     no_neighbor_timers_cmd,
     NO_NEIGHBOR_CMD2 "timers",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP per neighbor timers")
{
  return peer_timers_unset_vty (cli, argv[0]);
}


int
peer_disallow_infinite_hold_timer_set_vty (struct cli *cli, char *ip_str)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  ret = peer_disallow_hold_timer_set (peer);

  return bgp_cli_return (cli, ret);
}

int
peer_disallow_infinite_hold_timer_unset_vty (struct cli *cli, char *ip_str)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  ret = peer_disallow_hold_timer_unset (peer);

  return bgp_cli_return (cli, ret);
}


CLI (neighbor_disallow_infinite_time,
     neighbor_disallow_infinite_timer_cmd,
     NEIGHBOR_CMD2 "disallow-infinite-holdtime",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP per neighbor disallow-infinite-holdtime")
{
  return peer_disallow_infinite_hold_timer_set_vty(cli, argv[0]);
}

CLI (no_neighbor_disallow_infinite_time,
     no_neighbor_disallow_infinite_timer_cmd,
     NO_NEIGHBOR_CMD2 "disallow-infinite-holdtime",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP per neighbor disallow-infinite-holdtime")
{
  return peer_disallow_infinite_hold_timer_unset_vty(cli, argv[0]);
}

int
peer_timers_connect_set_vty (struct cli *cli, char *ip_str, char *time_str)
{
  int ret;
  struct bgp_peer *peer;
  u_int32_t connect;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  CLI_GET_INTEGER_RANGE ("Connect time", connect, time_str, 1, 65535);

  ret = peer_timers_connect_set (peer, connect);

  if (ret == 0)
    return CLI_SUCCESS;
  else
    return CLI_ERROR;
}

int
peer_timers_connect_unset_vty (struct cli *cli, char *ip_str)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  ret = peer_timers_connect_unset (peer);

  if (ret == 0)
    return CLI_SUCCESS;
  else
    return CLI_ERROR;
}

CLI (neighbor_timers_connect,
     neighbor_connection_retry_time_cmd,
     NEIGHBOR_CMD2 "connection-retry-time <1-65535>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP per neighbor timers",
     "BGP connect timer",
     "Connect timer")
{
  return peer_timers_connect_set_vty (cli, argv[0], argv[1]);
}

ALI (neighbor_timers_connect,
     neighbor_timers_connect_cmd,
     NEIGHBOR_CMD2 "timers connect <1-65535>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP per neighbor timers",
     "BGP connect timer",
     "Connect timer");

CLI (no_neighbor_timers_connect,
     no_neighbor_connection_retry_time_cmd,
     NO_NEIGHBOR_CMD2 "connection-retry-time",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP per neighbor timers",
     "BGP connect timer")
{
  return peer_timers_connect_unset_vty (cli, argv[0]);
}

ALI (no_neighbor_timers_connect,
     no_neighbor_timers_connect_cmd,
     NO_NEIGHBOR_CMD2 "timers connect",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP per neighbor timers",
     "BGP connect timer");

ALI (no_neighbor_timers_connect,
     no_neighbor_timers_connect_val_cmd,
     NO_NEIGHBOR_CMD2 "connection-retry-time <1-65535>",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "BGP per neighbor timers",
     "BGP connect timer",
     "Connect timer");

int
peer_asorig_interval_vty (struct cli *cli, char *ip_str, char *time_str, int set)
{
  int ret;
  struct bgp_peer *peer;
  u_int32_t asorig = 0;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  if (time_str)
    CLI_GET_INTEGER_RANGE ("as-origination interval", asorig, time_str, 1, 65535);

  if (set)
    ret = peer_asorig_interval_set (peer, asorig);
  else
    ret = peer_asorig_interval_unset (peer);

  if (ret == 0)
    return CLI_SUCCESS;
  else
    return CLI_ERROR;
}

CLI (neighbor_asorig_interval,
     neighbor_asorig_interval_cmd,
     NEIGHBOR_CMD2 "as-origination-interval <1-65535>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Minimum interval between sending AS-origination routing updates",
     "time in seconds")
{
  return peer_asorig_interval_vty (cli, argv[0], argv[1], 1);
}

CLI (no_neighbor_asorig_interval,
     no_neighbor_asorig_interval_cmd,
     NO_NEIGHBOR_CMD2 "as-origination-interval",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Minimum interval between sending AS-origination routing updates")
{
  return peer_asorig_interval_vty (cli, argv[0], NULL, 0);
}

ALI (no_neighbor_asorig_interval,
     no_neighbor_asorig_interval_val_cmd,
     NO_NEIGHBOR_CMD2 "as-origination-interval <1-65535>",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Minimum interval between sending AS-origination routing updates",
     "time in seconds");

int
peer_advertise_interval_vty (struct cli *cli, char *ip_str, char *time_str,
                             int set)
{
  int ret;
  struct bgp_peer *peer;
  u_int32_t routeadv = 0;
  struct listnode *lnode;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  if (time_str)
    CLI_GET_UINT32_RANGE ("advertise interval", routeadv, time_str, 0, 65535);

  if (set)
    ret = peer_advertise_interval_set (peer, routeadv, PAL_FALSE);
  else
    ret = peer_advertise_interval_unset (peer);

  if (ret != BGP_API_SET_SUCCESS)
  return bgp_cli_return (cli, ret);

  if (CHECK_FLAG (peer->flags, PEER_FLAG_IN_GROUP)
      && !bgp_peer_group_active(peer))
    {
      if (! peer->group)
        return BGP_API_SET_ERROR;

      LIST_LOOP (peer->group->peer_list, peer, lnode)
        {
          if (! CHECK_FLAG (peer->config, PEER_CONFIG_ROUTEADV))
            {
              if (set)
                ret = peer_advertise_interval_set (peer, routeadv, PAL_TRUE);
              else
                ret = peer_advertise_interval_unset (peer);
            }

          if (ret != BGP_API_SET_SUCCESS)
            return bgp_cli_return (cli, ret);
        }
    }

  return BGP_API_SET_SUCCESS;
}

CLI (neighbor_advertise_interval,
     neighbor_advertise_interval_cmd,
     NEIGHBOR_CMD2 "advertisement-interval <0-65535>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Minimum interval between sending BGP routing updates",
     "time in seconds")
{
  return peer_advertise_interval_vty (cli, argv[0], argv[1], 1);
}

CLI (no_neighbor_advertise_interval,
     no_neighbor_advertise_interval_cmd,
     NO_NEIGHBOR_CMD2 "advertisement-interval",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Minimum interval between sending BGP routing updates")
{
  return peer_advertise_interval_vty (cli, argv[0], NULL, 0);
}

ALI (no_neighbor_advertise_interval,
     no_neighbor_advertise_interval_val_cmd,
     NO_NEIGHBOR_CMD2 "advertisement-interval <0-65535>",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Minimum interval between sending BGP routing updates",
     "time in seconds");

int
peer_version_vty (struct cli *cli, char *ip_str, char *str)
{
  int ret;
  struct bgp_peer *peer;
  int version = BGP_VERSION_4;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  /* BGP version string check. */
  if (str)
    {
      if (pal_strcmp (str, "4") == 0)
        version = BGP_VERSION_4;

      ret = peer_version_set (peer, version);
    }
  else
    ret = peer_version_unset (peer);

  return bgp_cli_return (cli, ret);
}

CLI (neighbor_version,
     neighbor_version_cmd,
     NEIGHBOR_CMD2 "version (4)",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Set the BGP version to match a neighbor",
     "Neighbor's BGP version")
{
  return peer_version_vty (cli, argv[0], argv[1]);
}

CLI (no_neighbor_version,
     no_neighbor_version_cmd,
     NO_NEIGHBOR_CMD2 "version",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Set the BGP version to match a neighbor")
{
  return peer_version_vty (cli, argv[0], NULL);
}

/* neighbor interface */
int
peer_interface_vty (struct cli *cli, char *ip_str, char *str, bool_t setflag)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  if (setflag)
    ret = peer_interface_set (peer, ip_str, str);
  else
    ret = peer_interface_unset (peer, str);

  if (ret == 0)
    return CLI_SUCCESS;

  return bgp_cli_return (cli, ret);
}

CLI (neighbor_interface,
     neighbor_interface_cmd,
     NEIGHBOR_CMD "interface WORD",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR,
     "Interface",
     "Interface name")
{
  return peer_interface_vty (cli, argv[0], argv[1], PAL_TRUE);
}

CLI (no_neighbor_interface,
     no_neighbor_interface_cmd,
     NO_NEIGHBOR_CMD "interface WORD",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR,
     "Interface",
     "Interface name")
{
  return peer_interface_vty (cli, argv[0], argv[1], PAL_FALSE);
}

/* Set distribute list to the peer. */
int
peer_distribute_set_vty (struct cli *cli, char *ip_str, afi_t afi, safi_t safi,
                         char *name_str, char *direct_str)
{
  int ret;
  struct bgp_peer *peer;
  int direct = FILTER_IN;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  /* Check filter direction. */
  if (pal_strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (pal_strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_distribute_set (peer, afi, safi, direct, name_str);

  return bgp_cli_return (cli, ret);
}

int
peer_distribute_unset_vty (struct cli *cli, char *ip_str, afi_t afi,
                           safi_t safi, char *direct_str)
{
  int ret;
  struct bgp_peer *peer;
  int direct = FILTER_IN;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  /* Check filter direction. */
  if (pal_strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (pal_strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_distribute_unset (peer, afi, safi, direct);

  return bgp_cli_return (cli, ret);
}

CLI (neighbor_distribute_list,
     neighbor_distribute_list_cmd,
     NEIGHBOR_CMD2 "distribute-list (<1-199>|<1300-2699>|WORD) (in|out)",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Filter updates to/from this neighbor",
     "IP access-list number",
     "IP access-list number (expanded range)",
     "IP Access-list name",
     "Filter incoming updates",
     "Filter outgoing updates")
{
  return peer_distribute_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                  bgp_cli_mode_safi (cli), argv[1], argv[2]);
}

CLI (no_neighbor_distribute_list,
     no_neighbor_distribute_list_cmd,
     NO_NEIGHBOR_CMD2 "distribute-list (<1-199>|<1300-2699>|WORD) (in|out)",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Filter updates to/from this neighbor",
     "IP access-list number",
     "IP access-list number (expanded range)",
     "IP Access-list name",
     "Filter incoming updates",
     "Filter outgoing updates")
{
  return peer_distribute_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                    bgp_cli_mode_safi (cli), argv[2]);
}

/* Set prefix list to the peer. */
int
peer_prefix_list_set_vty (struct cli *cli, char *ip_str, afi_t afi,
                          safi_t safi, char *name_str, char *direct_str)
{
  int ret;
  struct bgp_peer *peer;
  int direct = FILTER_IN;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  /* Check filter direction. */
  if (pal_strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (pal_strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_prefix_list_set (peer, afi, safi, direct, name_str);

  return bgp_cli_return (cli, ret);
}

int
peer_prefix_list_unset_vty (struct cli *cli, char *ip_str, afi_t afi,
                            safi_t safi, char *direct_str)
{
  int ret;
  struct bgp_peer *peer;
  int direct = FILTER_IN;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  /* Check filter direction. */
  if (pal_strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (pal_strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_prefix_list_unset (peer, afi, safi, direct);

  return bgp_cli_return (cli, ret);
}

CLI (neighbor_prefix_list,
     neighbor_prefix_list_cmd,
     NEIGHBOR_CMD2 "prefix-list WORD (in|out)",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Filter updates to/from this neighbor",
     "Name of a prefix list",
     "Filter incoming updates",
     "Filter outgoing updates")
{
  return peer_prefix_list_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                   bgp_cli_mode_safi (cli), argv[1], argv[2]);
}

CLI (no_neighbor_prefix_list,
     no_neighbor_prefix_list_cmd,
     NO_NEIGHBOR_CMD2 "prefix-list WORD (in|out)",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Filter updates to/from this neighbor",
     "Name of a prefix list",
     "Filter incoming updates",
     "Filter outgoing updates")
{
  return peer_prefix_list_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                     bgp_cli_mode_safi (cli), argv[2]);
}

int
peer_aslist_set_vty (struct cli *cli, char *ip_str, afi_t afi, safi_t safi,
                     char *name_str, char *direct_str)
{
  int ret;
  struct bgp_peer *peer;
  int direct = FILTER_IN;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  /* Check filter direction. */
  if (pal_strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (pal_strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_aslist_set (peer, afi, safi, direct, name_str);

  return bgp_cli_return (cli, ret);
}

int
peer_aslist_unset_vty (struct cli *cli, char *ip_str, afi_t afi, safi_t safi,
                       char *direct_str)
{
  int ret;
  struct bgp_peer *peer;
  int direct = FILTER_IN;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  /* Check filter direction. */
  if (pal_strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (pal_strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_aslist_unset (peer, afi, safi, direct);

  return bgp_cli_return (cli, ret);
}

CLI (neighbor_filter_list,
     neighbor_filter_list_cmd,
     NEIGHBOR_CMD2 "filter-list WORD (in|out)",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Establish BGP filters",
     "AS path access-list name",
     "Filter incoming routes",
     "Filter outgoing routes")
{
  return peer_aslist_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                              bgp_cli_mode_safi (cli), argv[1], argv[2]);
}

CLI (no_neighbor_filter_list,
     no_neighbor_filter_list_cmd,
     NO_NEIGHBOR_CMD2 "filter-list WORD (in|out)",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Establish BGP filters",
     "AS path access-list name",
     "Filter incoming routes",
     "Filter outgoing routes")
{
  return peer_aslist_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                bgp_cli_mode_safi (cli), argv[2]);
}

/* Set route-map to the peer. */
int
peer_route_map_set_vty (struct cli *cli, char *ip_str, afi_t afi, safi_t safi,
                        char *name_str, char *direct_str)
{
  int ret;
  struct bgp_peer *peer;
  int direct = FILTER_IN;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  /* Check filter direction. */
  if (pal_strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (pal_strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  /* Get the correct bgp view context for relavant filter information */
  if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
    {
      bgp_peer_pbgp_node_inctx_get (cli->index, peer);

       if (!peer->pbgp_node_inctx)
         ret = BGP_API_SET_ERROR;
       else if (!peer->pbgp_node_inctx->afc[BGP_AFI2BAAI(afi)]
                                 [BGP_SAFI2BSAI(safi)])
         ret = BGP_API_SET_ERR_PEER_INACTIVE;
      else
        {
          peer->bgp = peer->pbgp_node_inctx->bgp;      
          ret = peer_route_map_set (peer, afi, safi, direct, name_str);
        }

      if (peer->pbgp_node_inctx)
        {
          peer->bgp = peer->master_bgp; 
          peer->pbgp_node_inctx = NULL;      
        }
    }
   else
     ret = peer_route_map_set (peer, afi, safi, direct, name_str);

  return bgp_cli_return (cli, ret);
}

int
peer_route_map_unset_vty (struct cli *cli, char *ip_str, afi_t afi,
                          safi_t safi, char *direct_str)
{
  int ret;
  struct bgp_peer *peer;
  int direct = FILTER_IN;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  /* Check filter direction. */
  if (pal_strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (pal_strncmp (direct_str, "o", 1) == 0)

    direct = FILTER_OUT;
   
  /* Get the correct bgp view context for relavant filter information */
  if (bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
    {
      bgp_peer_pbgp_node_inctx_get (cli->index, peer);
    
      if (!peer->pbgp_node_inctx)
        ret = BGP_API_SET_ERROR;
      else if(!peer->pbgp_node_inctx->afc[BGP_AFI2BAAI(afi)]
                                         [BGP_SAFI2BSAI(safi)])
       ret = BGP_API_SET_ERR_PEER_INACTIVE;
      else
       {
         peer->bgp = peer->pbgp_node_inctx->bgp;
         ret = peer_route_map_unset (peer, afi, safi, direct);
       }

      if (peer->pbgp_node_inctx)
        {
          peer->pbgp_node_inctx = NULL;
          peer->bgp = peer->master_bgp;
        }
     }
    else 
       ret = peer_route_map_unset (peer, afi, safi, direct);
  return bgp_cli_return (cli, ret);
}

CLI (neighbor_route_map,
     neighbor_route_map_cmd,
     NEIGHBOR_CMD2 "route-map WORD (in|out)",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Apply route map to neighbor",
     "Name of route map",
     "Apply map to incoming routes",
     "Apply map to outbound routes")
{
  return peer_route_map_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli), argv[1], argv[2]);
}

CLI (no_neighbor_route_map,
     no_neighbor_route_map_cmd,
     NO_NEIGHBOR_CMD2 "route-map WORD (in|out)",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Apply route map to neighbor",
     "Name of route map",
     "Apply map to incoming routes",
     "Apply map to outbound routes")
{
  return peer_route_map_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                   bgp_cli_mode_safi (cli), argv[2]);
}

/* Set unsuppress-map to the peer. */
int
peer_unsuppress_map_set_vty (struct cli *cli, char *ip_str, afi_t afi,
                             safi_t safi, char *name_str)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  ret = peer_unsuppress_map_set (peer, afi, safi, name_str);

  return bgp_cli_return (cli, ret);
}

/* Unset route-map from the peer. */
int
peer_unsuppress_map_unset_vty (struct cli *cli, char *ip_str, afi_t afi,
                               safi_t safi)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  ret = peer_unsuppress_map_unset (peer, afi, safi);

  return bgp_cli_return (cli, ret);
}

CLI (neighbor_unsuppress_map,
     neighbor_unsuppress_map_cmd,
     NEIGHBOR_CMD2 "unsuppress-map WORD",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Route-map to selectively unsuppress suppressed routes",
     "Name of route map")
{
  return peer_unsuppress_map_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                      bgp_cli_mode_safi (cli), argv[1]);
}

CLI (no_neighbor_unsuppress_map,
     no_neighbor_unsuppress_map_cmd,
     NO_NEIGHBOR_CMD2 "unsuppress-map WORD",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Route-map to selectively unsuppress suppressed routes",
     "Name of route map")
{
  return peer_unsuppress_map_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                        bgp_cli_mode_safi (cli));
}

int
peer_maximum_prefix_set_vty (struct cli *cli, char *ip_str,
                             afi_t afi, safi_t safi, char *num_str,
                             char *threshold_str, bool_t warning)
{
  int ret;
  struct bgp_peer *peer;
  u_int32_t max;
  u_int32_t threshold = 0;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  CLI_GET_INTEGER ("maxmum number", max, num_str);

  if (! threshold_str)
    threshold = BGP_DEFAULT_MAX_PREFIX_THRESHOLD;
  else
    CLI_GET_INTEGER ("threshold", threshold, threshold_str);

  ret = peer_maximum_prefix_set (peer, afi, safi, max, threshold, warning);

  return bgp_cli_return (cli, ret);
}

int
peer_maximum_prefix_unset_vty (struct cli *cli, char *ip_str, afi_t afi,
                               safi_t safi)
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, ip_str);
  if (! peer)
    return CLI_ERROR;

  ret = peer_maximum_prefix_unset (peer, afi, safi);

  return bgp_cli_return (cli, ret);
}

/* Maximum number of prefix configuration.  prefix count is different
   for each peer configuration.  So this configuration can be set for
   each peer configuration. */
CLI (neighbor_maximum_prefix,
     neighbor_maximum_prefix_cmd,
     NEIGHBOR_CMD2 "maximum-prefix <1-4294967295>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Maximum number of prefixes accepted from this peer",
     "Maximum number of prefixes")
{
  return peer_maximum_prefix_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                      bgp_cli_mode_safi (cli), argv[1],
                                      NULL, PAL_FALSE);
}

CLI (neighbor_maximum_prefix_warning,
     neighbor_maximum_prefix_warning_cmd,
     NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> warning-only",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Maximum number of prefix accept from this peer",
     "maximum no. of prefix limit",
     "Only give warning message when limit is exceeded")
{
  return peer_maximum_prefix_set_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                      bgp_cli_mode_safi (cli), argv[1],
                                      NULL, PAL_TRUE);
}

CLI (neighbor_maximum_prefix_threshold,
     neighbor_maximum_prefix_threshold_cmd,
     NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Maximum number of prefix accept from this peer",
     "maximum no. of prefix limit",
     "threshold-value, 1 to 100 percent")
{
  return peer_maximum_prefix_set_vty (cli, argv[0], bgp_cli_mode_afi(cli),
				      bgp_cli_mode_safi(cli), argv[1],
				      argv[2], PAL_FALSE);
}

CLI (neighbor_maximum_prefix_threshold_warning,
     neighbor_maximum_prefix_threshold_warning_cmd,
     NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> warning-only",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Maximum number of prefix accept from this peer",
     "maximum no. of prefix limit",
     "threshold-value, 1 to 100 percent",
     "only give warning message when limit is exceeded")
{
  return peer_maximum_prefix_set_vty (cli, argv[0], bgp_cli_mode_afi(cli),
				      bgp_cli_mode_safi (cli), argv[1],
				      argv[2], PAL_TRUE);
}

CLI (no_neighbor_maximum_prefix,
     no_neighbor_maximum_prefix_cmd,
     NO_NEIGHBOR_CMD2 "maximum-prefix",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Maximum number of prefix accept from this peer")
{
  return peer_maximum_prefix_unset_vty (cli, argv[0], bgp_cli_mode_afi (cli),
                                        bgp_cli_mode_safi (cli));
}

ALI (no_neighbor_maximum_prefix,
     no_neighbor_maximum_prefix_val_cmd,
     NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295>",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Maximum number of prefix accept from this peer",
     "maximum no. of prefix limit");

ALI (no_neighbor_maximum_prefix,
     no_neighbor_maximum_prefix_val2_cmd,
     NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> warning-only",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Maximum number of prefix accept from this peer",
     "maximum no. of prefix limit",
     "Only give warning message when limit is exceeded");


/* "neighbor allowas-in" */
CLI (neighbor_allowas_in,
     neighbor_allowas_in_cmd,
     NEIGHBOR_CMD2 "allowas-in",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Accept as-path with my AS present in it")
{
  int ret;
  struct bgp_peer *peer;
  int allow_num;

  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  if (argc == 1)
    allow_num = 3;
  else
    CLI_GET_INTEGER_RANGE ("AS number", allow_num, argv[1], 1, 10);

  ret = peer_allowas_in_set (peer, bgp_cli_mode_afi (cli), bgp_cli_mode_safi (cli),
                             allow_num);

  return bgp_cli_return (cli, ret);
}

ALI (neighbor_allowas_in,
     neighbor_allowas_in_arg_cmd,
     NEIGHBOR_CMD2 "allowas-in <1-10>",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Accept as-path with my AS present in it",
     "Number of occurrences of AS number");

CLI (no_neighbor_allowas_in,
     no_neighbor_allowas_in_cmd,
     NO_NEIGHBOR_CMD2 "allowas-in",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "allow local ASN appears in aspath attribute")
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  ret = peer_allowas_in_unset (peer, bgp_cli_mode_afi (cli), bgp_cli_mode_safi (cli));

  return bgp_cli_return (cli, ret);
}


#ifdef HAVE_TCP_MD5SIG
CLI (neighbor_password,
     neighbor_password_cmd,
     NEIGHBOR_CMD2 "password WORD",
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Set password to the neighbor",
     "The password")
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  ret = peer_password_set (peer, 0, argv[1]); 

  if (ret == 0)
    return CLI_SUCCESS;
  else
    return CLI_ERROR;
}

CLI (no_neighbor_password,
     no_neighbor_password2_cmd,
     NO_NEIGHBOR_CMD2 "password",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Set password to the neighbor\n")
{
  int ret;
  struct bgp_peer *peer;

  peer = bgp_peer_and_group_lookup_vty (cli, argv[0]);
  if (! peer)
    return CLI_ERROR;

  ret = peer_password_unset (peer);

  if (ret == 0)
    return CLI_SUCCESS;
  else
    return CLI_ERROR;
}

ALI (no_neighbor_password,
     no_neighbor_password3_cmd,
     NO_NEIGHBOR_CMD2 "password WORD",
     CLI_NO_STR,
     CLI_NEIGHBOR_STR,
     NEIGHBOR_ADDR_STR2,
     "Set password to the neighbor",
     "The password");
#endif /* TCP_MD5SIG */

void
bgp_cli_neighbor_init (struct cli_tree *ctree)
{
  /* "neighbor remote-as" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_remote_as_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_no_neighbor_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_remote_as_cmd);

  /* "neighbor local-as" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_local_as_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_local_as_cmd);

  /* "neighbor peer-group" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_peer_group_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_peer_group_cmd);

  /* "neighbor activate" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_activate_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_activate_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_activate_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_activate_cmd);

  /* "no neighbor activate" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_activate_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_activate_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_activate_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_activate_cmd);

  /* "neighbor peer-group set" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_set_peer_group_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_set_peer_group_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_set_peer_group_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_set_peer_group_cmd);

  /* "no neighbor peer-group unset" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_set_peer_group_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_set_peer_group_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_set_peer_group_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_set_peer_group_cmd);

  /* "neighbor softreconfiguration inbound" commands.*/
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_soft_reconfiguration_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_soft_reconfiguration_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_soft_reconfiguration_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_soft_reconfiguration_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_soft_reconfiguration_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_soft_reconfiguration_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_soft_reconfiguration_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_soft_reconfiguration_cmd);

  /* "neighbor attribute-unchanged" commands.  */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_attr_unchanged_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_attr_unchanged_cmd);

  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_attr_unchanged_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_attr_unchanged_cmd);

  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_attr_unchanged_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_attr_unchanged_cmd);

  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_attr_unchanged_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_attr_unchanged_cmd);

  /* "transparent-as" and "transparent-nexthop" for old version
     compatibility.  */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_transparent_as_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_transparent_nexthop_cmd);

  /* "neighbor next-hop-self" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_nexthop_self_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_nexthop_self_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_nexthop_self_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_nexthop_self_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_nexthop_self_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_nexthop_self_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_nexthop_self_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_nexthop_self_cmd);

  /* "neighbor remove-private-AS" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_remove_private_as_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_remove_private_as_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_remove_private_as_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_remove_private_as_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_remove_private_as_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_remove_private_as_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_remove_private_as_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_remove_private_as_cmd);

  /* "neighbor send-community" commands.*/
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_send_community_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_send_community_type_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_send_community_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_send_community_type_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_send_community_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_send_community_type_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_send_community_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_send_community_type_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_send_community_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_send_community_type_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_send_community_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_send_community_type_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_send_community_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_send_community_type_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_send_community_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_send_community_type_cmd);

  /* "neighbor route-reflector" commands.*/
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_reflector_client_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_reflector_client_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_reflector_client_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_reflector_client_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_reflector_client_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_reflector_client_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_reflector_client_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_reflector_client_cmd);

  /* "neighbor route-server" commands.*/
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_server_client_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_server_client_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_server_client_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_server_client_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_server_client_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_server_client_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_server_client_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_server_client_cmd);

  /* "neighbor passive" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_passive_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_passive_cmd);

  /* "neighbor shutdown" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_shutdown_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_shutdown_cmd);

  /* "neighbor capability route-refresh" commands.*/
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_capability_route_refresh_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_capability_route_refresh_cmd);

  /* "neighbor capability orf prefix-list" commands.*/
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_capability_orf_prefix_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_capability_orf_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_capability_orf_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_capability_orf_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_capability_orf_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_capability_orf_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_capability_orf_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_capability_orf_prefix_cmd);

  /* "neighbor capability dynamic" commands.*/
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_capability_dynamic_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_capability_dynamic_cmd);

  /* "neighbor dont-capability-negotiate" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_dont_capability_negotiate_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_dont_capability_negotiate_cmd);

  /* "neighbor ebgp-multihop" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_ebgp_multihop_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_ebgp_multihop_ttl_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_ebgp_multihop_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_ebgp_multihop_ttl_cmd);

  /* "neighbor enforce-multihop" commands.  */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_enforce_multihop_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_enforce_multihop_cmd);

  /* "neighbor description" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_description_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_description_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_description_val_cmd);

  /* "neighbor update-source" commands. "*/
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_update_source_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_update_source_cmd);

  /* "neighbor default-originate" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_default_originate_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_default_originate_rmap_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_default_originate_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_default_originate_rmap_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_default_originate_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_default_originate_rmap_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_default_originate_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_default_originate_rmap_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_default_originate_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_default_originate_rmap_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_default_originate_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_default_originate_rmap_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_default_originate_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_default_originate_rmap_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_default_originate_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_default_originate_rmap_cmd);

  /* "neighbor port" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_port_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_port_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_port_val_cmd);

  /* "neighbor weight" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_weight_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_weight_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_weight_val_cmd);

  /* IPV4 Unicast - Default Address Family */
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_weight_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_weight_cmd);

  /* IPV4 Multicast */
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_weight_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_weight_cmd);

  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_weight_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_weight_cmd);

  /* "neighbor collide-established" commands */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_collide_established_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_collide_established_cmd);

  /* "neighbor override-capability" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_override_capability_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_override_capability_cmd);

  /* "neighbor strict-capability-match" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_strict_capability_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_strict_capability_cmd);

  /* "neighbor timers" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_timers_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_timers_cmd);

  /* "neighbor disallow-infinite-holdtime timers" commands. */

  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_disallow_infinite_timer_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_disallow_infinite_timer_cmd);

  /* "neighbor timers connect" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_timers_connect_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_connection_retry_time_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_timers_connect_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_connection_retry_time_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_timers_connect_val_cmd);

  /* "neighbor as-origination-interval" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_asorig_interval_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_asorig_interval_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_asorig_interval_val_cmd);

  /* "neighbor advertisement-interval" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_advertise_interval_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_advertise_interval_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_advertise_interval_val_cmd);

  /* "neighbor version" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_version_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_version_cmd);

  /* "neighbor interface" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_interface_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_interface_cmd);

  /* "neighbor distribute" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_distribute_list_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_distribute_list_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_distribute_list_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_distribute_list_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_distribute_list_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_distribute_list_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_distribute_list_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_distribute_list_cmd);

  /* "neighbor prefix-list" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_prefix_list_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_prefix_list_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_prefix_list_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_prefix_list_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_prefix_list_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_prefix_list_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_prefix_list_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_prefix_list_cmd);

  /* "neighbor filter-list" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_filter_list_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_filter_list_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_filter_list_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_filter_list_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_filter_list_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_filter_list_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_filter_list_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_filter_list_cmd);

  /* "neighbor route-map" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_map_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_route_map_cmd);

  /* "neighbor unsuppress-map" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_unsuppress_map_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_unsuppress_map_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_unsuppress_map_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_unsuppress_map_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_unsuppress_map_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_unsuppress_map_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_unsuppress_map_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_unsuppress_map_cmd);

  /* "neighbor maximum-prefix" commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_warning_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_threshold_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_threshold_warning_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_val_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_val2_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_warning_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_threshold_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_threshold_warning_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_val_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_val2_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_warning_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_threshold_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_threshold_warning_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_val_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_val2_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_warning_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_threshold_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_maximum_prefix_threshold_warning_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_val_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_maximum_prefix_val2_cmd);

  /* "neighbor allowas-in" */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_allowas_in_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_allowas_in_arg_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_allowas_in_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_allowas_in_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_allowas_in_arg_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_allowas_in_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_allowas_in_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_allowas_in_arg_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_allowas_in_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_allowas_in_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_allowas_in_arg_cmd);
  cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_allowas_in_cmd);

#ifdef HAVE_TCP_MD5SIG
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &neighbor_password_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_password2_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_neighbor_password3_cmd);
#endif /* TCP_MD5SIG */
}


void
bgp_clear_vty_error (struct cli *cli,
                     struct bgp_peer *peer,
                     afi_t afi,
                     safi_t safi,
                     s_int32_t error,
                     u_int8_t *arg)
{
  switch (error)
    {
    case BGP_API_SET_ERR_AF_UNCONFIGURED:
      cli_out (cli,
               "%%BGP: Enable %s %s address family for the neighbor %s\n",
               afi == AFI_IP6 ? "IPv6" : "IPv4",
               safi == SAFI_MULTICAST ? "Multicast" : "Unicast",
               peer->host);
      break;
    case BGP_API_SET_ERR_SOFT_RECONFIG_UNCONFIGURED:
      cli_out (cli, "%%BGP: Inbound soft reconfig for %s not possible"
               " as it\n      has neither refresh capability, nor "
               "inbound soft reconfig\n", peer->host);
      break;
    case BGP_API_SET_ERR_UNKNOWN_OBJECT:
      cli_out (cli, "%%BGP: Unknown object - \"%s\"\n", arg);
    default:
      break;
    }

  return;
}

s_int32_t
bgp_clear_rfd_family (struct cli *cli,
                      struct bgp *bgp,
                      afi_t afi,
                      safi_t safi,
                      s_int32_t stype)
{
  struct bgp_rfd_cfg *rfd_cfg;
  struct bgp_rfd_cb *rfd_cb;
  struct listnode *nn;

  rfd_cfg = bgp->rfd_cfg [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (rfd_cfg)
    {
      switch (stype)
        {
          case BGP_CLEAR_RFD_DAMP:
              LIST_LOOP (rfd_cfg->rfdg_rfd_cb_list, rfd_cb, nn)
                bgp_rfd_cb_restart (rfd_cb);
              break;

          case BGP_CLEAR_RFD_FLAP_STAT:
              LIST_LOOP (rfd_cfg->rfdg_rfd_cb_list, rfd_cb, nn)
                bgp_rfd_cb_clear_flap_stats (rfd_cb);
              break;

          default:
              return -1;
        }
    }

  return 0;
}

s_int32_t
bgp_clear_rfd_prefix (struct cli *cli,
                      struct bgp *bgp,
                      afi_t afi,
                      safi_t safi,
                      s_int32_t stype,
                      u_int8_t *arg)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct prefix p;
  s_int32_t ret;
  struct prefix rnp;

  ret = str2prefix (arg, &p);
  if (! ret)
    {
      cli_out (cli, "%% Malformed Prefix\n");
      return CLI_ERROR;
    }

  for (rn = bgp_table_top (bgp->rib [BGP_AFI2BAAI (afi)]
                                    [BGP_SAFI2BSAI (safi)]);
       rn; rn = bgp_route_next (rn))
    {
      BGP_GET_PREFIX_FROM_NODE (rn);
      if (prefix_match (&p, &rnp))
        for (ri = rn->info; ri; ri = ri->next)
          if (BGP_RFD_RT_HAS_RECORD (ri))
            {
              switch (stype)
                {
                  case BGP_CLEAR_RFD_DAMP:
                      bgp_rfd_hinfo_delete (ri->rfd_hinfo);
                      break;

                  case BGP_CLEAR_RFD_FLAP_STAT:
                      bgp_rfd_hinfo_clear_flap_stats
                          (ri->rfd_hinfo);
                      break;

                  default:
                      break;
                }
            }
     }

  return ret;
}

/* `clear [ip] bgp' functions */
s_int32_t
bgp_clear (struct cli *cli,
           struct bgp *bgp,
           afi_t afi,
           safi_t safi,
           enum bgp_clear_type sort,
           s_int32_t stype,
           u_int8_t *arg)
{
  struct bgp_peer *peer;
  struct listnode *nn;
  u_char family;
  s_int32_t ret;
  bool_t router_id_changed;

  family = afi2family (afi);
  ret = 0;
  router_id_changed = PAL_FALSE;

  /* Clear all neighbors. */
  if (sort == clear_all)
    {
      if(!IPV4_ADDR_SAME (&bgp->router_id, &BGP_VR.router_id)
               && stype == BGP_CLEAR_SOFT_NONE
               && (!bgp_config_check (bgp, BGP_SFLAG_NSM_ROUTER_ID)
               && !bgp_config_check (bgp,BGP_CFLAG_ROUTER_ID)))
              {
                 IPV4_ADDR_COPY (&bgp->router_id, &BGP_VR.router_id);
                 router_id_changed = PAL_TRUE;
              }
 
      LIST_LOOP (bgp->peer_list, peer, nn)
        {
          if (afi != 0 && peer->su.sa.sa_family != family)
            continue;

          if (router_id_changed == PAL_TRUE)
              IPV4_ADDR_COPY (&peer->local_id, &bgp->router_id);

          if (stype == BGP_CLEAR_SOFT_NONE)
            ret = bgp_peer_clear (peer);
          else
            ret = peer_clear_soft (peer, afi, safi, stype);

          if (ret < 0)
            bgp_clear_vty_error (cli, peer, afi, safi, ret, NULL );
        }

      /* Reset table version.  */
      if (stype == BGP_CLEAR_SOFT_NONE)
        for (afi = AFI_IP; afi < AFI_MAX; afi++)
          for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
            bgp->table_version [BGP_AFI2BAAI (afi)]
                               [BGP_SAFI2BSAI (safi)] = 1;

      return 0;
    }

  /* Clear specified neighbors. */
  if (sort == clear_peer)
    {
      union sockunion su;

      /* Make sockunion for lookup. */
      ret = str2sockunion (arg, &su);
      if (ret < 0)
        {
          cli_out (cli, "Malformed address: %s\n", arg);
          return -1;
        }
      peer = bgp_peer_search (bgp, &su);
      if (! peer)
        {
          cli_out (cli, "%%BGP: Unknown neighbor - \"%s\"\n", arg);
          return -1;
        }

      if (stype == BGP_CLEAR_SOFT_NONE)
        ret = bgp_peer_clear (peer);
      else
        ret = peer_clear_soft (peer, afi, safi, stype);

      if (ret < 0)
        bgp_clear_vty_error (cli, peer, afi, safi, ret, arg);

      return 0;
    }

  /* Clear all peer-group members. */
  if (sort == clear_group)
    {
      struct bgp_peer_group *group;

      group = bgp_peer_group_lookup (bgp, arg);
      if (! group)
        {
          cli_out (cli, "%%BGP: No such peer-group %s\n", arg);
          return -1;
        }

      LIST_LOOP (group->peer_list, peer, nn)
        {
          if (stype == BGP_CLEAR_SOFT_NONE)
            {
              ret = bgp_peer_clear (peer);
              continue;
            }

          if (! peer->af_group[BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
            continue;

          ret = peer_clear_soft (peer, afi, safi, stype);

          if (ret < 0)
            bgp_clear_vty_error (cli, peer, afi, safi, ret, NULL);
        }
      return 0;
    }

  if (sort == clear_external)
    {
      LIST_LOOP (bgp->peer_list, peer, nn)
        {
          if (peer_sort (peer) == BGP_PEER_IBGP)
            continue;

          if (stype == BGP_CLEAR_SOFT_NONE)
            ret = bgp_peer_clear (peer);
          else
            ret = peer_clear_soft (peer, afi, safi, stype);

          if (ret < 0)
            bgp_clear_vty_error (cli, peer, afi, safi, ret, NULL);
        }
      return 0;
    }

  if (sort == clear_as)
    {
      as_t as;
      u_int32_t as_ul;
      u_int8_t *endptr = NULL;
      u_int32_t find = 0;

      as_ul = pal_strtou32 (arg, (char **)((char *) &endptr), 10);

#ifndef HAVE_EXT_CAP_ASN
      if ((as_ul == ULONG_MAX)
          || (*endptr != '\0')
          || (as_ul > USHRT_MAX))
#else
      if ((as_ul > ULONG_MAX)
          || (*endptr != '\0'))
#endif /* HAVE_EXT_CAP_ASN */
        {
          cli_out (cli, "%% Invalid AS number\n");
          return -1;
        }
      
#ifndef HAVE_EXT_CAP_ASN
      as = (u_int16_t) as_ul;
#else
      as = (as_t) as_ul;
#endif /* HAVE_EXT_CAP_ASN */

      LIST_LOOP (bgp->peer_list, peer, nn)
        {
          if (peer->as != as)
            continue;

          find = 1;
          if (stype == BGP_CLEAR_SOFT_NONE)
            ret = bgp_peer_clear (peer);
          else
            ret = peer_clear_soft (peer, afi, safi, stype);

          if (ret < 0)
            bgp_clear_vty_error (cli, peer, afi, safi, ret, NULL);
        }
      if (! find)
        {
          cli_out (cli, "%%BGP: No peer is configured with AS %s\n", arg);
          return -1;
        }
        return 0;
    }

  if (sort == clear_rfd)
    {
      if (arg)
        ret = bgp_clear_rfd_prefix (cli, bgp, afi, safi, stype, arg);
      else
        ret = bgp_clear_rfd_family (cli, bgp, afi, safi, stype);
    }

  return ret;
}

s_int32_t
bgp_clear_vty (struct cli *cli,
               u_int8_t *name,
               afi_t afi, safi_t safi,
               enum bgp_clear_type sort,
               s_int32_t stype, u_int8_t *arg)
{
  struct bgp *bgp;
  s_int32_t ret;

  /* BGP structure lookup. */
  if (name)
    {
      bgp = bgp_lookup_by_name (name);
      if (bgp == NULL)
        {
          cli_out (cli, "Can't find BGP view %s\n", name);
          return CLI_ERROR;
        }
    }
  else
    {
      bgp = bgp_lookup_default ();
      if (bgp == NULL)
        {
          cli_out (cli, "%% No BGP process is configured\n");
          return CLI_ERROR;
        }
    }
  
   /* Reset the multipath variables in bgp with cfg values */
   bgp->maxpath_ebgp = bgp->cfg_maxpath_ebgp;
   bgp->maxpath_ibgp = bgp->cfg_maxpath_ibgp;

  if (! BGP_API_CHECK_RANGE (stype, CLEAR_SOFT)
      && ! BGP_API_CHECK_RANGE (stype, CLEAR_RFD))
    return BGP_API_SET_ERR_INVALID_VALUE;

  ret = bgp_clear (cli, bgp, afi, safi, sort, stype, arg);
  if (ret < 0)
    return CLI_ERROR;

  return CLI_SUCCESS;
}

CLI (clear_ip_bgp_all,
     clear_ip_bgp_all_cmd,
     "clear ip bgp *",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers")
{
  if (argc == 1)
    return bgp_clear_vty (cli, argv[0], 0, 0, clear_all,
                          BGP_CLEAR_SOFT_NONE, NULL);

  return bgp_clear_vty (cli, NULL, 0, 0, clear_all,
                        BGP_CLEAR_SOFT_NONE, NULL);
}

ALI (clear_ip_bgp_all,
     clear_bgp_all_cmd,
     "clear bgp *",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all peers");

CLI (clear_ip_bgp_all_ipv6,
     clear_bgp_ipv6_all_cmd,
     "clear bgp ipv6 *",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all peers")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, 0, clear_all,
                        BGP_CLEAR_SOFT_NONE, NULL);
}

ALI (clear_ip_bgp_all,
     clear_ip_bgp_instance_all_cmd,
     "clear ip bgp view WORD *",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers");

ALI (clear_ip_bgp_all,
     clear_bgp_instance_all_cmd,
     "clear bgp view WORD *",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers");

CLI (clear_ip_bgp_peer,
     clear_ip_bgp_peer_cmd,
     "clear ip bgp (A.B.C.D|X:X::X:X)",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor IP address to clear",
     "BGP IPv6 neighbor to clear")
{
  return bgp_clear_vty (cli, NULL, 0, 0, clear_peer,
                        BGP_CLEAR_SOFT_NONE, argv[0]);
}

ALI (clear_ip_bgp_peer,
     clear_bgp_peer_cmd,
     "clear bgp (A.B.C.D|X:X::X:X)",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear");

ALI (clear_ip_bgp_peer,
     clear_bgp_ipv6_peer_cmd,
     "clear bgp ipv6 (A.B.C.D|X:X::X:X)",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear");

CLI (clear_ip_bgp_peer_group,
     clear_ip_bgp_peer_group_cmd,
     "clear ip bgp peer-group WORD",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name")
{
  return bgp_clear_vty (cli, NULL, 0, 0, clear_group,
                        BGP_CLEAR_SOFT_NONE, argv[0]);
}

ALI (clear_ip_bgp_peer_group,
     clear_bgp_peer_group_cmd,
     "clear bgp peer-group WORD",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name");

ALI (clear_ip_bgp_peer_group,
     clear_bgp_ipv6_peer_group_cmd,
     "clear bgp ipv6 peer-group WORD",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all members of peer-group",
     "BGP peer-group name");

CLI (clear_ip_bgp_external,
     clear_ip_bgp_external_cmd,
     "clear ip bgp external",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers")
{
  return bgp_clear_vty (cli, NULL, 0, 0, clear_external,
                        BGP_CLEAR_SOFT_NONE, NULL);
}

ALI (clear_ip_bgp_external,
     clear_bgp_external_cmd,
     "clear bgp external",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all external peers");

ALI (clear_ip_bgp_external,
     clear_bgp_ipv6_external_cmd,
     "clear bgp ipv6 external",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all external peers");
#ifndef HAVE_EXT_CAP_ASN
CLI (clear_ip_bgp_as,
     clear_ip_bgp_as_cmd,
     "clear ip bgp <1-65535>",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number")
{
  return bgp_clear_vty (cli, NULL, 0, 0, clear_as,
                        BGP_CLEAR_SOFT_NONE, argv[0]);
}

ALI (clear_ip_bgp_as,
     clear_bgp_as_cmd,
     "clear bgp <1-65535>",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number");

ALI (clear_ip_bgp_as,
     clear_bgp_ipv6_as_cmd,
     "clear bgp ipv6 <1-65535>",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number");
#else
CLI (clear_ip_bgp_as,
     clear_ip_bgp_as_cmd,
     "clear ip bgp <1-4294967295>",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number")
{
  return bgp_clear_vty (cli, NULL, 0, 0, clear_as,
                        BGP_CLEAR_SOFT_NONE, argv[0]);
}

ALI (clear_ip_bgp_as,
     clear_bgp_as_cmd,
     "clear bgp <1-4294967295>",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number");

ALI (clear_ip_bgp_as,
     clear_bgp_ipv6_as_cmd,
     "clear bgp ipv6 <1-4294967295>",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number");

#endif /* HAVE_EXT_CAP_ASN */

/* Outbound soft-reconfiguration */
CLI (clear_ip_bgp_all_soft_out,
     clear_ip_bgp_all_soft_out_cmd,
     "clear ip bgp * soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  s_int32_t ret1, ret2, ret3;

  if (argc == 1)
  {
    ret1 = bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_OUT, NULL);
    ret2 = bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_OUT, NULL);
    ret3 = bgp_clear_vty (cli, argv[0], AFI_IP6, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_OUT, NULL);
  }
  else
  {
    ret1 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_OUT, NULL);
    ret2 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
                        BGP_CLEAR_SOFT_OUT, NULL);
    ret3 = bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_OUT, NULL);
  }
  
  if(ret1 != CLI_SUCCESS)
    return ret1;
  else if(ret2 != CLI_SUCCESS)
    return ret2;
  else if(ret3 != CLI_SUCCESS)
    return ret3;
  else 
    return CLI_SUCCESS;
}

ALI (clear_ip_bgp_all_soft_out,
     clear_ip_bgp_all_out_cmd,
     "clear ip bgp * out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig outbound update");

ALI (clear_ip_bgp_all_soft_out,
     clear_ip_bgp_instance_all_soft_out_cmd,
     "clear ip bgp view WORD * soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers",
     "Soft reconfig",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_all_ipv4_soft_out,
     clear_ip_bgp_all_ipv4_soft_out_cmd,
     "clear ip bgp * ipv4 (unicast|multicast) soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  if (pal_strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_OUT, NULL);
}

ALI (clear_ip_bgp_all_ipv4_soft_out,
     clear_ip_bgp_all_ipv4_out_cmd,
     "clear ip bgp * ipv4 (unicast|multicast) out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_all_ipv6_soft_out,
     clear_ip_bgp_all_ipv6_soft_out_cmd,
     "clear ip bgp * ipv6 unicast soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig outbound update")
{

  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_OUT, NULL);
}

ALI (clear_ip_bgp_all_ipv6_soft_out,
     clear_ip_bgp_all_ipv6_out_cmd,
     "clear ip bgp * ipv6 unicast out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_instance_all_ipv4_soft_out,
     clear_ip_bgp_instance_all_ipv4_soft_out_cmd,
     "clear ip bgp view WORD * ipv4 (unicast|multicast) soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_OUT, NULL);
}

CLI (clear_bgp_all_soft_out,
     clear_bgp_all_soft_out_cmd,
     "clear bgp * soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  if (argc == 1)
    return bgp_clear_vty (cli, argv[0], AFI_IP6, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_OUT, NULL);
}

ALI (clear_bgp_all_soft_out,
     clear_bgp_instance_all_soft_out_cmd,
     "clear bgp view WORD * soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers",
     "Soft reconfig",
     "Soft reconfig outbound update");

ALI (clear_bgp_all_soft_out,
     clear_bgp_all_out_cmd,
     "clear bgp * out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig outbound update");

ALI (clear_bgp_all_soft_out,
     clear_bgp_ipv6_all_soft_out_cmd,
     "clear bgp ipv6 * soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all peers",
     "Soft reconfig",
     "Soft reconfig outbound update");

ALI (clear_bgp_all_soft_out,
     clear_bgp_ipv6_all_out_cmd,
     "clear bgp ipv6 * out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all peers",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_peer_soft_out,
     clear_ip_bgp_peer_soft_out_cmd,
     "clear ip bgp A.B.C.D soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_ip_bgp_peer_soft_out,
     clear_ip_bgp_peer_out_cmd,
     "clear ip bgp A.B.C.D out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig outbound update");

CLI (clear_ipv6_bgp_peer_soft_out,
     clear_ipv6_bgp_peer_soft_out_cmd,
     "clear ip bgp X:X::X:X soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_ipv6_bgp_peer_soft_out,
     clear_ipv6_bgp_peer_out_cmd,
     "clear ip bgp X:X::X:X out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_peer_ipv4_soft_out,
     clear_ip_bgp_peer_ipv4_soft_out_cmd,
     "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_peer,
                          BGP_CLEAR_SOFT_OUT, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_ip_bgp_peer_ipv4_soft_out,
     clear_ip_bgp_peer_ipv4_out_cmd,
     "clear ip bgp A.B.C.D ipv4 (unicast|multicast) out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig outbound update");

CLI (clear_bgp_peer_soft_out,
     clear_bgp_peer_soft_out_cmd,
     "clear bgp X:X::X:X soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST,
                        clear_peer, BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_bgp_peer_soft_out,
     clear_bgp_ipv6_peer_soft_out_cmd,
     "clear bgp ipv6 (A.B.C.D|X:X::X:X) soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig",
     "Soft reconfig outbound update");

ALI (clear_bgp_peer_soft_out,
     clear_bgp_peer_out_cmd,
     "clear bgp (A.B.C.D|X:X::X:X) out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig outbound update");

ALI (clear_bgp_peer_soft_out,
     clear_bgp_ipv6_peer_out_cmd,
     "clear bgp ipv6 (A.B.C.D|X:X::X:X) out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_peer_group_soft_out,
     clear_ip_bgp_peer_group_soft_out_cmd,
     "clear ip bgp peer-group WORD soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_ip_bgp_peer_group_soft_out,
     clear_ip_bgp_peer_group_out_cmd,
     "clear ip bgp peer-group WORD out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_peer_group_ipv4_soft_out,
     clear_ip_bgp_peer_group_ipv4_soft_out_cmd,
     "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_group,
                          BGP_CLEAR_SOFT_OUT, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_ip_bgp_peer_group_ipv4_soft_out,
     clear_ip_bgp_peer_group_ipv4_out_cmd,
     "clear ip bgp peer-group WORD ipv4 (unicast|multicast) out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig outbound update");

CLI (clear_bgp_peer_group_soft_out,
     clear_bgp_peer_group_soft_out_cmd,
     "clear bgp peer-group WORD soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_bgp_peer_group_soft_out,
     clear_bgp_ipv6_peer_group_soft_out_cmd,
     "clear bgp ipv6 peer-group WORD soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig",
     "Soft reconfig outbound update");

ALI (clear_bgp_peer_group_soft_out,
     clear_bgp_peer_group_out_cmd,
     "clear bgp peer-group WORD out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig outbound update");

ALI (clear_bgp_peer_group_soft_out,
     clear_bgp_ipv6_peer_group_out_cmd,
     "clear bgp ipv6 peer-group WORD out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_external_soft_out,
     clear_ip_bgp_external_soft_out_cmd,
     "clear ip bgp external soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_OUT, NULL);
}

ALI (clear_ip_bgp_external_soft_out,
     clear_ip_bgp_external_out_cmd,
     "clear ip bgp external out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_external_ipv4_soft_out,
     clear_ip_bgp_external_ipv4_soft_out_cmd,
     "clear ip bgp external ipv4 (unicast|multicast) soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  if (pal_strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_external,
                          BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_OUT, NULL);
}

ALI (clear_ip_bgp_external_ipv4_soft_out,
     clear_ip_bgp_external_ipv4_out_cmd,
     "clear ip bgp external ipv4 (unicast|multicast) out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig outbound update");

CLI (clear_bgp_external_soft_out,
     clear_bgp_external_soft_out_cmd,
     "clear bgp external soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_OUT, NULL);
}

ALI (clear_bgp_external_soft_out,
     clear_bgp_ipv6_external_soft_out_cmd,
     "clear bgp ipv6 external soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all external peers",
     "Soft reconfig",
     "Soft reconfig outbound update");

ALI (clear_bgp_external_soft_out,
     clear_bgp_external_out_cmd,
     "clear bgp external out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig outbound update");

ALI (clear_bgp_external_soft_out,
     clear_bgp_ipv6_external_out_cmd,
     "clear bgp ipv6 external WORD out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all external peers",
     "Soft reconfig",
     "Soft reconfig outbound update");
#ifndef HAVE_EXT_CAP_ASN
CLI (clear_ip_bgp_as_soft_out,
     clear_ip_bgp_as_soft_out_cmd,
     "clear ip bgp <1-65535> soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  s_int32_t ret1, ret2, ret3;
  
  ret1 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
  ret2 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
  ret3 = bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);

  if(ret1 != CLI_SUCCESS)
    return ret1;
  else if(ret2 != CLI_SUCCESS)
    return ret2;
  else if(ret3 != CLI_SUCCESS)
    return ret3;
  else 
    return CLI_SUCCESS;
}

ALI (clear_ip_bgp_as_soft_out,
     clear_ip_bgp_as_out_cmd,
     "clear ip bgp <1-65535> out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_as_ipv4_soft_out,
     clear_ip_bgp_as_ipv4_soft_out_cmd,
     "clear ip bgp <1-65535> ipv4 (unicast|multicast) soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                          BGP_CLEAR_SOFT_OUT, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_ip_bgp_as_ipv4_soft_out,
     clear_ip_bgp_as_ipv4_out_cmd,
     "clear ip bgp <1-65535> ipv4 (unicast|multicast) out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_as_ipv6_soft_out,
     clear_ip_bgp_as_ipv6_soft_out_cmd,
     "clear ip bgp <1-65535> ipv6 unicast soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig outbound update")
{

  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_ip_bgp_as_ipv6_soft_out,
     clear_ip_bgp_as_ipv6_out_cmd,
     "clear ip bgp <1-65535> ipv6 unicast out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Soft reconfig outbound update");

CLI (clear_bgp_as_soft_out,
     clear_bgp_as_soft_out_cmd,
     "clear bgp <1-65535> soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_bgp_as_soft_out,
     clear_bgp_ipv6_as_soft_out_cmd,
     "clear bgp ipv6 <1-65535> soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig outbound update");

ALI (clear_bgp_as_soft_out,
     clear_bgp_as_out_cmd,
     "clear bgp <1-65535> out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig outbound update");

ALI (clear_bgp_as_soft_out,
     clear_bgp_ipv6_as_out_cmd,
     "clear bgp ipv6 <1-65535> out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig outbound update");

#else
CLI (clear_ip_bgp_as_soft_out,
     clear_ip_bgp_as_soft_out_cmd,
     "clear ip bgp <1-4294967295> soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  s_int32_t ret1, ret2, ret3;
  
  ret1 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
  ret2 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
  ret3 = bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);

  if(ret1 != CLI_SUCCESS)
    return ret1;
  else if(ret2 != CLI_SUCCESS)
    return ret2;
  else if(ret3 != CLI_SUCCESS)
    return ret3;
  else 
    return CLI_SUCCESS;
}

ALI (clear_ip_bgp_as_soft_out,
     clear_ip_bgp_as_out_cmd,
     "clear ip bgp <1-4294967295> out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_as_ipv4_soft_out,
     clear_ip_bgp_as_ipv4_soft_out_cmd,
     "clear ip bgp <1-4294967295> ipv4 (unicast|multicast) soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                          BGP_CLEAR_SOFT_OUT, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_ip_bgp_as_ipv4_soft_out,
     clear_ip_bgp_as_ipv4_out_cmd,
     "clear ip bgp <1-4294967295> ipv4 (unicast|multicast) out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig outbound update");

CLI (clear_ip_bgp_as_ipv6_soft_out,
     clear_ip_bgp_as_ipv6_soft_out_cmd,
     "clear ip bgp <1-4294967295> ipv6 unicast soft out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_ip_bgp_as_ipv6_soft_out,
     clear_ip_bgp_as_ipv6_out_cmd,
     "clear ip bgp <1-4294967295> ipv6 unicast out",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Soft reconfig outbound update");

CLI (clear_bgp_as_soft_out,
     clear_bgp_as_soft_out_cmd,
     "clear bgp <1-4294967295> soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig outbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALI (clear_bgp_as_soft_out,
     clear_bgp_ipv6_as_soft_out_cmd,
     "clear bgp ipv6 <1-4294967295> soft out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig outbound update");

ALI (clear_bgp_as_soft_out,
     clear_bgp_as_out_cmd,
     "clear bgp <1-4294967295> out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig outbound update");

ALI (clear_bgp_as_soft_out,
     clear_bgp_ipv6_as_out_cmd,
     "clear bgp ipv6 <1-4294967295> out",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig outbound update");

#endif /* HAVE_EXT_CAP_ASN */

/* Inbound soft-reconfiguration */
CLI (clear_ip_bgp_all_soft_in,
     clear_ip_bgp_all_soft_in_cmd,
     "clear ip bgp * soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  s_int32_t ret1, ret2, ret3;

  if (argc == 1)
  {
    ret1 = bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_IN, NULL);
    ret2 = bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_IN, NULL);
    ret3 = bgp_clear_vty (cli, argv[0], AFI_IP6, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_IN, NULL);
  }
  else
  {
    ret1 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN, NULL); 
    ret2 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
                        BGP_CLEAR_SOFT_IN, NULL); 
    ret3 = bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN, NULL); 
  }

  if(ret1 != CLI_SUCCESS)
    return ret1;
  else if(ret2 != CLI_SUCCESS)
    return ret2;
  else if(ret3 != CLI_SUCCESS)
    return ret3;
  else
    return CLI_SUCCESS;
}

ALI (clear_ip_bgp_all_soft_in,
     clear_ip_bgp_instance_all_soft_in_cmd,
     "clear ip bgp view WORD * soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers",
     "Soft reconfig",
     "Soft reconfig inbound update");

ALI (clear_ip_bgp_all_soft_in,
     clear_ip_bgp_all_in_cmd,
     "clear ip bgp * in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_all_in_prefix_filter,
     clear_ip_bgp_all_in_prefix_filter_cmd,
     "clear ip bgp * in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  if (argc== 1)
    return bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALI (clear_ip_bgp_all_in_prefix_filter,
     clear_ip_bgp_instance_all_in_prefix_filter_cmd,
     "clear ip bgp view WORD * in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig");

CLI (clear_ip_bgp_all_ipv4_soft_in,
     clear_ip_bgp_all_ipv4_soft_in_cmd,
     "clear ip bgp * ipv4 (unicast|multicast) soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  if (pal_strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN, NULL);
}

ALI (clear_ip_bgp_all_ipv4_soft_in,
     clear_ip_bgp_all_ipv4_in_cmd,
     "clear ip bgp * ipv4 (unicast|multicast) in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_all_ipv6_soft_in,
     clear_ip_bgp_all_ipv6_soft_in_cmd,
     "clear ip bgp * ipv6 unicast soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN, NULL);
}

ALI (clear_ip_bgp_all_ipv6_soft_in,
     clear_ip_bgp_all_ipv6_in_cmd,
     "clear ip bgp * ipv6 unicast in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_instance_all_ipv4_soft_in,
     clear_ip_bgp_instance_all_ipv4_soft_in_cmd,
     "clear ip bgp view WORD * ipv4 (unicast|multicast) soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN, NULL);
}

CLI (clear_ip_bgp_all_ipv4_in_prefix_filter,
     clear_ip_bgp_all_ipv4_in_prefix_filter_cmd,
     "clear ip bgp * ipv4 (unicast|multicast) in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  if (pal_strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

CLI (clear_ip_bgp_instance_all_ipv4_in_prefix_filter,
     clear_ip_bgp_instance_all_ipv4_in_prefix_filter_cmd,
     "clear ip bgp view WORD * ipv4 (unicast|multicast) in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "View",
     "View name",
     "Clear all peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);

  return bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

CLI (clear_bgp_all_soft_in,
     clear_bgp_all_soft_in_cmd,
     "clear bgp * soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  if (argc == 1)
    return bgp_clear_vty (cli, argv[0], AFI_IP6, SAFI_UNICAST,
                          clear_all, BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST,
                        clear_all, BGP_CLEAR_SOFT_IN, NULL);
}

ALI (clear_bgp_all_soft_in,
     clear_bgp_instance_all_soft_in_cmd,
     "clear bgp view WORD * soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers",
     "Soft reconfig",
     "Soft reconfig inbound update");

ALI (clear_bgp_all_soft_in,
     clear_bgp_ipv6_all_soft_in_cmd,
     "clear bgp ipv6 * soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all peers",
     "Soft reconfig",
     "Soft reconfig inbound update");

ALI (clear_bgp_all_soft_in,
     clear_bgp_all_in_cmd,
     "clear bgp * in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig inbound update");

ALI (clear_bgp_all_soft_in,
     clear_bgp_ipv6_all_in_cmd,
     "clear bgp ipv6 * in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all peers",
     "Soft reconfig inbound update");

CLI (clear_bgp_all_in_prefix_filter,
     clear_bgp_all_in_prefix_filter_cmd,
     "clear bgp * in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6,
                        SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALI (clear_bgp_all_in_prefix_filter,
     clear_bgp_ipv6_all_in_prefix_filter_cmd,
     "clear bgp ipv6 * in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all peers",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig");

CLI (clear_ip_bgp_peer_soft_in,
     clear_ip_bgp_peer_soft_in_cmd,
     "clear ip bgp A.B.C.D soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_ip_bgp_peer_soft_in,
     clear_ip_bgp_peer_in_cmd,
     "clear ip bgp A.B.C.D in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig inbound update");

CLI (clear_ipv6_bgp_peer_soft_in,
     clear_ipv6_bgp_peer_soft_in_cmd,
     "clear ip bgp X:X::X:X soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_ipv6_bgp_peer_soft_in,
     clear_ipv6_bgp_peer_in_cmd,
     "clear ip bgp X:X::X:X in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_peer_in_prefix_filter,
     clear_ip_bgp_peer_in_prefix_filter_cmd,
     "clear ip bgp A.B.C.D in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig inbound update",
     "Push out the existing ORF prefix-list")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

CLI (clear_ip_bgp_peer_ipv4_soft_in,
     clear_ip_bgp_peer_ipv4_soft_in_cmd,
     "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_peer,
                          BGP_CLEAR_SOFT_IN, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_ip_bgp_peer_ipv4_soft_in,
     clear_ip_bgp_peer_ipv4_in_cmd,
     "clear ip bgp A.B.C.D ipv4 (unicast|multicast) in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_peer_ipv4_in_prefix_filter,
     clear_ip_bgp_peer_ipv4_in_prefix_filter_cmd,
     "clear ip bgp A.B.C.D ipv4 (unicast|multicast) in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update",
     "Push out the existing ORF prefix-list")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_peer,
                          BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

CLI (clear_bgp_peer_soft_in,
     clear_bgp_peer_soft_in_cmd,
     "clear bgp (A.B.C.D|X:X::X:X) soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_bgp_peer_soft_in,
     clear_bgp_ipv6_peer_soft_in_cmd,
     "clear bgp ipv6 (A.B.C.D|X:X::X:X) soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig",
     "Soft reconfig inbound update");

ALI (clear_bgp_peer_soft_in,
     clear_bgp_peer_in_cmd,
     "clear bgp (A.B.C.D|X:X::X:X) in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig inbound update");

ALI (clear_bgp_peer_soft_in,
     clear_bgp_ipv6_peer_in_cmd,
     "clear bgp ipv6 (A.B.C.D|X:X::X:X) in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig inbound update");

CLI (clear_bgp_peer_in_prefix_filter,
     clear_bgp_peer_in_prefix_filter_cmd,
     "clear bgp (A.B.C.D|X:X::X:X) in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig inbound update",
     "Push out the existing ORF prefix-list")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALI (clear_bgp_peer_in_prefix_filter,
     clear_bgp_ipv6_peer_in_prefix_filter_cmd,
     "clear bgp ipv6 (A.B.C.D|X:X::X:X) in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig inbound update",
     "Push out the existing ORF prefix-list");

CLI (clear_ip_bgp_peer_group_soft_in,
     clear_ip_bgp_peer_group_soft_in_cmd,
     "clear ip bgp peer-group WORD soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_ip_bgp_peer_group_soft_in,
     clear_ip_bgp_peer_group_in_cmd,
     "clear ip bgp peer-group WORD in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_peer_group_in_prefix_filter,
     clear_ip_bgp_peer_group_in_prefix_filter_cmd,
     "clear ip bgp peer-group WORD in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

CLI (clear_ip_bgp_peer_group_ipv4_soft_in,
     clear_ip_bgp_peer_group_ipv4_soft_in_cmd,
     "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_group,
                          BGP_CLEAR_SOFT_IN, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_ip_bgp_peer_group_ipv4_soft_in,
     clear_ip_bgp_peer_group_ipv4_in_cmd,
     "clear ip bgp peer-group WORD ipv4 (unicast|multicast) in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_peer_group_ipv4_in_prefix_filter,
     clear_ip_bgp_peer_group_ipv4_in_prefix_filter_cmd,
     "clear ip bgp peer-group WORD ipv4 (unicast|multicast) in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_group,
                          BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

CLI (clear_bgp_peer_group_soft_in,
     clear_bgp_peer_group_soft_in_cmd,
     "clear bgp peer-group WORD soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_bgp_peer_group_soft_in,
     clear_bgp_ipv6_peer_group_soft_in_cmd,
     "clear bgp ipv6 peer-group WORD soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig",
     "Soft reconfig inbound update");

ALI (clear_bgp_peer_group_soft_in,
     clear_bgp_peer_group_in_cmd,
     "clear bgp peer-group WORD in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig inbound update");

ALI (clear_bgp_peer_group_soft_in,
     clear_bgp_ipv6_peer_group_in_cmd,
     "clear bgp ipv6 peer-group WORD in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig inbound update");

CLI (clear_bgp_peer_group_in_prefix_filter,
     clear_bgp_peer_group_in_prefix_filter_cmd,
     "clear bgp peer-group WORD in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALI (clear_bgp_peer_group_in_prefix_filter,
     clear_bgp_ipv6_peer_group_in_prefix_filter_cmd,
     "clear bgp ipv6 peer-group WORD in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig");

CLI (clear_ip_bgp_external_soft_in,
     clear_ip_bgp_external_soft_in_cmd,
     "clear ip bgp external soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_IN, NULL);
}

ALI (clear_ip_bgp_external_soft_in,
     clear_ip_bgp_external_in_cmd,
     "clear ip bgp external in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_external_in_prefix_filter,
     clear_ip_bgp_external_in_prefix_filter_cmd,
     "clear ip bgp external in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

CLI (clear_ip_bgp_external_ipv4_soft_in,
     clear_ip_bgp_external_ipv4_soft_in_cmd,
     "clear ip bgp external ipv4 (unicast|multicast) soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  if (pal_strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_external,
                          BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_IN, NULL);
}

ALI (clear_ip_bgp_external_ipv4_soft_in,
     clear_ip_bgp_external_ipv4_in_cmd,
     "clear ip bgp external ipv4 (unicast|multicast) in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_external_ipv4_in_prefix_filter,
     clear_ip_bgp_external_ipv4_in_prefix_filter_cmd,
     "clear ip bgp external ipv4 (unicast|multicast) in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  if (pal_strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_external,
                          BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

CLI (clear_bgp_external_soft_in,
     clear_bgp_external_soft_in_cmd,
     "clear bgp external soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_IN, NULL);
}

ALI (clear_bgp_external_soft_in,
     clear_bgp_ipv6_external_soft_in_cmd,
     "clear bgp ipv6 external soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all external peers",
     "Soft reconfig",
     "Soft reconfig inbound update");

ALI (clear_bgp_external_soft_in,
     clear_bgp_external_in_cmd,
     "clear bgp external in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig inbound update");

ALI (clear_bgp_external_soft_in,
     clear_bgp_ipv6_external_in_cmd,
     "clear bgp ipv6 external WORD in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all external peers",
     "Soft reconfig",
     "Soft reconfig inbound update");

CLI (clear_bgp_external_in_prefix_filter,
     clear_bgp_external_in_prefix_filter_cmd,
     "clear bgp external in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALI (clear_bgp_external_in_prefix_filter,
     clear_bgp_ipv6_external_in_prefix_filter_cmd,
     "clear bgp ipv6 external in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all external peers",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig");

#ifndef HAVE_EXT_CAP_ASN
CLI (clear_ip_bgp_as_soft_in,
     clear_ip_bgp_as_soft_in_cmd,
     "clear ip bgp <1-65535> soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  s_int32_t ret1, ret2, ret3;
    
  ret1 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]);
  ret2 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]); 
  ret3 = bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]);

  if(ret1 != CLI_SUCCESS)
    return ret1;
  else if(ret2 != CLI_SUCCESS)
    return ret2;
  else if(ret3 != CLI_SUCCESS)
    return ret3;
  else 
    return CLI_SUCCESS; 
}

ALI (clear_ip_bgp_as_soft_in,
     clear_ip_bgp_as_in_cmd,
     "clear ip bgp <1-65535> in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_as_in_prefix_filter,
     clear_ip_bgp_as_in_prefix_filter_cmd,
     "clear ip bgp <1-65535> in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}
CLI (clear_ip_bgp_as_ipv4_soft_in,
     clear_ip_bgp_as_ipv4_soft_in_cmd,
     "clear ip bgp <1-65535> ipv4 (unicast|multicast) soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                          BGP_CLEAR_SOFT_IN, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_ip_bgp_as_ipv4_soft_in,
     clear_ip_bgp_as_ipv4_in_cmd,
     "clear ip bgp <1-65535> ipv4 (unicast|multicast) in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_as_ipv6_soft_in,
     clear_ip_bgp_as_ipv6_soft_in_cmd,
     "clear ip bgp <1-65535> ipv6 unicast soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_ip_bgp_as_ipv6_soft_in,
     clear_ip_bgp_as_ipv6_in_cmd,
     "clear ip bgp <1-65535> ipv6 unicast in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_as_ipv4_in_prefix_filter,
     clear_ip_bgp_as_ipv4_in_prefix_filter_cmd,
     "clear ip bgp <1-65535> ipv4 (unicast|multicast) in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update",
 "Push out prefix-list ORF and do inbound soft reconfig")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                          BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

CLI (clear_bgp_as_soft_in,
     clear_bgp_as_soft_in_cmd,
     "clear bgp <1-65535> soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_bgp_as_soft_in,
     clear_bgp_ipv6_as_soft_in_cmd,
     "clear bgp ipv6 <1-65535> soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig inbound update");

ALI (clear_bgp_as_soft_in,
     clear_bgp_as_in_cmd,
     "clear bgp <1-65535> in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
 "Soft reconfig inbound update");

ALI (clear_bgp_as_soft_in,
     clear_bgp_ipv6_as_in_cmd,
     "clear bgp ipv6 <1-65535> in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig inbound update");

CLI (clear_bgp_as_in_prefix_filter,
     clear_bgp_as_in_prefix_filter_cmd,
     "clear bgp <1-65535> in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}
ALI (clear_bgp_as_in_prefix_filter,
     clear_bgp_ipv6_as_in_prefix_filter_cmd,
     "clear bgp ipv6 <1-65535> in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig");
#else
CLI (clear_ip_bgp_as_soft_in,
     clear_ip_bgp_as_soft_in_cmd,
     "clear ip bgp <1-4294967295> soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  s_int32_t ret1, ret2, ret3;
  
  ret1 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]);
  ret2 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]); 
  ret3 = bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]);
  
  if(ret1 != CLI_SUCCESS)
    return ret1;
  else if(ret2 != CLI_SUCCESS)
    return ret2;
  else if(ret3 != CLI_SUCCESS)
    return ret3;
  else 
    return CLI_SUCCESS;

}

ALI (clear_ip_bgp_as_soft_in,
     clear_ip_bgp_as_in_cmd,
     "clear ip bgp <1-4294967295> in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_as_in_prefix_filter,
     clear_ip_bgp_as_in_prefix_filter_cmd,
     "clear ip bgp <1-4294967295> in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

CLI (clear_ip_bgp_as_ipv4_soft_in,
     clear_ip_bgp_as_ipv4_soft_in_cmd,
     "clear ip bgp <1-4294967295> ipv4 (unicast|multicast) soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                          BGP_CLEAR_SOFT_IN, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_ip_bgp_as_ipv4_soft_in,
     clear_ip_bgp_as_ipv4_in_cmd,
     "clear ip bgp <1-4294967295> ipv4 (unicast|multicast) in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_as_ipv6_soft_in,
     clear_ip_bgp_as_ipv6_soft_in_cmd,
     "clear ip bgp <1-4294967295> ipv6 unicast soft in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_ip_bgp_as_ipv6_soft_in,
     clear_ip_bgp_as_ipv6_in_cmd,
     "clear ip bgp <1-4294967295> ipv6 unicast in",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Soft reconfig inbound update");

CLI (clear_ip_bgp_as_ipv4_in_prefix_filter,
     clear_ip_bgp_as_ipv4_in_prefix_filter_cmd,
     "clear ip bgp <1-4294967295> ipv4 (unicast|multicast) in prefix-filter",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                          BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

CLI (clear_bgp_as_soft_in,
     clear_bgp_as_soft_in_cmd,
     "clear bgp <1-4294967295> soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig inbound update")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN, argv[0]);
}

ALI (clear_bgp_as_soft_in,
     clear_bgp_ipv6_as_soft_in_cmd,
     "clear bgp ipv6 <1-4294967295> soft in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig",
     "Soft reconfig inbound update");

ALI (clear_bgp_as_soft_in,
     clear_bgp_as_in_cmd,
     "clear bgp <1-4294967295> in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig inbound update");

ALI (clear_bgp_as_soft_in,
     clear_bgp_ipv6_as_in_cmd,
     "clear bgp ipv6 <1-4294967295> in",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig inbound update");

CLI (clear_bgp_as_in_prefix_filter,
     clear_bgp_as_in_prefix_filter_cmd,
     "clear bgp <1-4294967295> in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALI (clear_bgp_as_in_prefix_filter,
     clear_bgp_ipv6_as_in_prefix_filter_cmd,
     "clear bgp ipv6 <1-4294967295> in prefix-filter",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig inbound update",
     "Push out prefix-list ORF and do inbound soft reconfig");
#endif /* HAVE_EXT_CAP_ASN */

/* Both soft-reconfiguration */
CLI (clear_ip_bgp_all_soft,
     clear_ip_bgp_all_soft_cmd,
     "clear ip bgp * soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig")
{
  s_int32_t ret1, ret2, ret3;

  if (argc == 1)
  {
    ret1 =  bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);
    ret2 =  bgp_clear_vty (cli, argv[0], AFI_IP, SAFI_MULTICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);
    ret3 =  bgp_clear_vty (cli, argv[0], AFI_IP6, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);
  }
  else
  {
    ret1 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);
    ret2 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);
    ret3 = bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);
  }
  
  if(ret1 != CLI_SUCCESS)
    return ret1;
  else if(ret2 != CLI_SUCCESS)
    return ret2;
  else if(ret3 != CLI_SUCCESS)
    return ret3;
  else
    return CLI_SUCCESS; 
}

ALI (clear_ip_bgp_all_soft,
     clear_ip_bgp_instance_all_soft_cmd,
     "clear ip bgp view WORD * soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers",
     "Soft reconfig");


CLI (clear_ip_bgp_all_ipv4_soft,
     clear_ip_bgp_all_ipv4_soft_cmd,
     "clear ip bgp * ipv4 (unicast|multicast) soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family Modifier",
     "Address Family Modifier",
     "Soft reconfig")
{
  if (pal_strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_BOTH, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);
}

CLI (clear_ip_bgp_all_ipv6_soft,
     clear_ip_bgp_all_ipv6_soft_cmd,
     "clear ip bgp * ipv6 unicast soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Address family",
     "Address Family Modifier",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);
}

CLI (clear_ip_bgp_instance_all_ipv4_soft,
     clear_ip_bgp_instance_all_ipv4_soft_cmd,
     "clear ip bgp view WORD * ipv4 (unicast|multicast) soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers",
     "Address family",
     "Address Family Modifier",
     "Address Family Modifier",
     "Soft reconfig")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_BOTH, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);
}

CLI (clear_bgp_all_soft,
     clear_bgp_all_soft_cmd,
     "clear bgp * soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all peers",
     "Soft reconfig")
{
  if (argc == 1)
    return bgp_clear_vty (cli, argv[0], AFI_IP6, SAFI_UNICAST, clear_all,
			  BGP_CLEAR_SOFT_BOTH, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALI (clear_bgp_all_soft,
     clear_bgp_instance_all_soft_cmd,
     "clear bgp view WORD * soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP view",
     "view name",
     "Clear all peers",
     "Soft reconfig");

ALI (clear_bgp_all_soft,
     clear_bgp_ipv6_all_soft_cmd,
     "clear bgp ipv6 * soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all peers",
     "Soft reconfig");

CLI (clear_ip_bgp_peer_soft,
     clear_ip_bgp_peer_soft_cmd,
     "clear ip bgp A.B.C.D soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

CLI (clear_ipv6_bgp_peer_soft,
     clear_ipv6_bgp_peer_soft_cmd,
     "clear ip bgp X:X::X:X soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

CLI (clear_ip_bgp_peer_ipv4_soft,
     clear_ip_bgp_peer_ipv4_soft_cmd,
     "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "Address family",
     "Address Family Modifier",
     "Address Family Modifier",
     "Soft reconfig")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_peer,
                          BGP_CLEAR_SOFT_BOTH, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

CLI (clear_bgp_peer_soft,
     clear_bgp_peer_soft_cmd,
     "clear bgp (A.B.C.D|X:X::X:X) soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_peer,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALI (clear_bgp_peer_soft,
     clear_bgp_ipv6_peer_soft_cmd,
     "clear bgp ipv6 (A.B.C.D|X:X::X:X) soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "BGP neighbor address to clear",
     "BGP IPv6 neighbor to clear",
     "Soft reconfig");

CLI (clear_ip_bgp_peer_group_soft,
     clear_ip_bgp_peer_group_soft_cmd,
     "clear ip bgp peer-group WORD soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

CLI (clear_ip_bgp_peer_group_ipv4_soft,
     clear_ip_bgp_peer_group_ipv4_soft_cmd,
     "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_group,
                          BGP_CLEAR_SOFT_BOTH, argv[0]);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

CLI (clear_bgp_peer_group_soft,
     clear_bgp_peer_group_soft_cmd,
     "clear bgp peer-group WORD soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_group,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALI (clear_bgp_peer_group_soft,
     clear_bgp_ipv6_peer_group_soft_cmd,
     "clear bgp ipv6 peer-group WORD soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all members of peer-group",
     "BGP peer-group name",
     "Soft reconfig");

CLI (clear_ip_bgp_external_soft,
     clear_ip_bgp_external_soft_cmd,
     "clear ip bgp external soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_BOTH, NULL);
}

CLI (clear_ip_bgp_external_ipv4_soft,
     clear_ip_bgp_external_ipv4_soft_cmd,
     "clear ip bgp external ipv4 (unicast|multicast) soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Address family",
     "Address Family modifier",
     "Address Family modifier",
     "Soft reconfig")
{
  if (pal_strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_external,
                          BGP_CLEAR_SOFT_BOTH, NULL);

  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_BOTH, NULL);
}

CLI (clear_bgp_external_soft,
     clear_bgp_external_soft_cmd,
     "clear bgp external soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear all external peers",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_external,
                        BGP_CLEAR_SOFT_BOTH, NULL);
}

ALI (clear_bgp_external_soft,
     clear_bgp_ipv6_external_soft_cmd,
     "clear bgp ipv6 external soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear all external peers",
     "Soft reconfig");

#ifndef HAVE_EXT_CAP_ASN
CLI (clear_ip_bgp_as_soft,
     clear_ip_bgp_as_soft_cmd,
     "clear ip bgp <1-65535> soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig")
{
  s_int32_t ret1, ret2, ret3;
   
  ret1 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
  ret2 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
  ret3 = bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
  
  if(ret1 != CLI_SUCCESS)
    return ret1;
  else if(ret2 != CLI_SUCCESS)
    return ret2;
  else if(ret3 != CLI_SUCCESS)
    return ret3;
  else 
    return CLI_SUCCESS;
}

CLI (clear_ip_bgp_as_ipv4_soft,
     clear_ip_bgp_as_ipv4_soft_cmd,
     "clear ip bgp <1-65535> ipv4 (unicast|multicast) soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family Modifier",
     "Address Family Modifier",
     "Soft reconfig")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                          BGP_CLEAR_SOFT_BOTH, argv[0]);

  return bgp_clear_vty (cli, NULL,AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

CLI (clear_ip_bgp_as_ipv6_soft,
     clear_ip_bgp_as_ipv6_soft_cmd,
     "clear ip bgp <1-65535> ipv6 unicast soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family Modifier",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL,AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

CLI (clear_bgp_as_soft,
     clear_bgp_as_soft_cmd,
     "clear bgp <1-65535> soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}
ALI (clear_bgp_as_soft,
     clear_bgp_ipv6_as_soft_cmd,
     "clear bgp ipv6 <1-65535> soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig");

#else
CLI (clear_ip_bgp_as_soft,
     clear_ip_bgp_as_soft_cmd,
     "clear ip bgp <1-4294967295> soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig")
{
  s_int32_t ret1, ret2, ret3;
    
  ret1 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
  ret2 = bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
  ret3 = bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
  
  if(ret1 != CLI_SUCCESS)
    return ret1;
  else if(ret2 != CLI_SUCCESS)
    return ret2;
  else if(ret3 != CLI_SUCCESS)
    return ret3;
  else 
    return CLI_SUCCESS;
}

CLI (clear_ip_bgp_as_ipv4_soft,
     clear_ip_bgp_as_ipv4_soft_cmd,
     "clear ip bgp <1-4294967295> ipv4 (unicast|multicast) soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family Modifier",
     "Address Family Modifier",
     "Soft reconfig")
{
  if (pal_strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
                          BGP_CLEAR_SOFT_BOTH, argv[0]);

  return bgp_clear_vty (cli, NULL,AFI_IP, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

CLI (clear_ip_bgp_as_ipv6_soft,
     clear_ip_bgp_as_ipv6_soft_cmd,
     "clear ip bgp <1-4294967295> ipv6 unicast soft",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Address family",
     "Address Family Modifier",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL,AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

CLI (clear_bgp_as_soft,
     clear_bgp_as_soft_cmd,
     "clear bgp <1-4294967295> soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Clear peers with the AS number",
     "Soft reconfig")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
                        BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALI (clear_bgp_as_soft,
     clear_bgp_ipv6_as_soft_cmd,
     "clear bgp ipv6 <1-4294967295> soft",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     "Address family",
     "Clear peers with the AS number",
     "Soft reconfig");
#endif /* HAVE_EXT_CAP_ASN */


CLI (clear_ip_bgp_dampening,
     clear_ip_bgp_dampening_cmd,
     "clear ip bgp dampening",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear route flap dampening information")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_DAMP, NULL);
}

CLI (clear_ip_bgp_dampening_prefix,
     clear_ip_bgp_dampening_prefix_cmd,
     "clear ip bgp dampening A.B.C.D",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear route flap dampening information",
     "IP prefix <network>, e.g., 35.0.0.0")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_DAMP, argv [0]);
}

ALI (clear_ip_bgp_dampening_prefix,
     clear_ip_bgp_dampening_prefix_len_cmd,
     "clear ip bgp dampening A.B.C.D/M",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear route flap dampening information",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8");

CLI (clear_ip_bgp_ipv4_safi_dampening,
     clear_ip_bgp_ipv4_safi_dampening_cmd,
     "clear ip bgp ipv4 (unicast|multicast) dampening",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, bgp_cli_str2safi (argv [0]),
                        clear_rfd, BGP_CLEAR_RFD_DAMP, NULL);
}

CLI (clear_ip_bgp_ipv4_safi_dampening_prefix,
     clear_ip_bgp_ipv4_safi_dampening_prefix_cmd,
     "clear ip bgp ipv4 (unicast|multicast) dampening A.B.C.D",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information",
     "IP prefix <network>, e.g., 35.0.0.0")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, bgp_cli_str2safi (argv [0]),
                        clear_rfd, BGP_CLEAR_RFD_DAMP, argv [0]);
}

ALI (clear_ip_bgp_ipv4_safi_dampening_prefix,
     clear_ip_bgp_ipv4_safi_dampening_prefix_len_cmd,
     "clear ip bgp ipv4 (unicast|multicast) dampening A.B.C.D/M",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8");

#ifdef HAVE_IPV6
CLI (clear_ip_bgp_ipv6_safi_dampening,
     clear_ip_bgp_ipv6_safi_dampening_cmd,
     "clear ip bgp ipv6 unicast dampening",
     CLI_CLEAR_STR,
     CLI_IPV6_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_DAMP, NULL);
}

CLI (clear_ip_bgp_ipv6_safi_dampening_prefix,
     clear_ip_bgp_ipv6_safi_dampening_prefix_cmd,
     "clear ip bgp ipv6 unicast dampening X:X::X:X",
     CLI_CLEAR_STR,
     CLI_IPV6_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information",
     "IPv6 prefix <network>, e.g., 2003::")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_DAMP, argv [0]);
}

ALI (clear_ip_bgp_ipv6_safi_dampening_prefix,
     clear_ip_bgp_ipv6_safi_dampening_prefix_len_cmd,
     "clear ip bgp ipv6 unicast dampening X:X::X:X/M",
     CLI_CLEAR_STR,
     CLI_IPV6_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information",
     "IPv6 prefix <network>/<length>, e.g., 2003::/16");

CLI (clear_bgp_ipv6_safi_dampening,
     clear_bgp_ipv6_safi_dampening_cmd,
     "clear bgp ipv6 unicast dampening",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_DAMP, NULL);
}

CLI (clear_bgp_ipv6_safi_dampening_prefix,
     clear_bgp_ipv6_safi_dampening_prefix_cmd,
     "clear bgp ipv6 unicast dampening X:X::X:X",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information",
     "IPv6 prefix <network>, e.g., 2003::")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_DAMP, argv [0]);
}

ALI (clear_bgp_ipv6_safi_dampening_prefix,
     clear_bgp_ipv6_safi_dampening_prefix_len_cmd,
     "clear bgp ipv6 unicast dampening X:X::X:X/M",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information",
     "IPv6 prefix <network>/<length>, e.g., 2003::/16");

CLI (clear_bgp_ipv4_safi_dampening,
     clear_bgp_ipv4_safi_dampening_cmd,
     "clear bgp ipv4 (unicast|multicast) dampening",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]),
                        clear_rfd, BGP_CLEAR_RFD_DAMP, NULL);
}

CLI (clear_bgp_ipv4_safi_dampening_prefix,
     clear_bgp_ipv4_safi_dampening_prefix_cmd,
     "clear bgp ipv4 (unicast|multicast) dampening A.B.C.D",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information",
     "IP prefix <network>, e.g., 35.0.0.0")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]),
                        clear_rfd, BGP_CLEAR_RFD_DAMP, argv[1]);
}

ALI (clear_bgp_ipv4_safi_dampening_prefix,
     clear_bgp_ipv4_safi_dampening_prefix_len_cmd,
     "clear bgp ipv4 (unicast|multicast) dampening A.B.C.D/M",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap dampening information",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8");
#endif /* HAVE_IPV6 */


CLI (clear_ip_bgp_flap_statistics,
     clear_ip_bgp_flap_statistics_cmd,
     "clear ip bgp flap-statistics",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear route flap statistics")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_FLAP_STAT, NULL);
}

CLI (clear_ip_bgp_flap_statistics_prefix,
     clear_ip_bgp_flap_statistics_prefix_cmd,
     "clear ip bgp flap-statistics A.B.C.D",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear route flap statistics",
     "IP prefix <network>, e.g., 35.0.0.0")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_FLAP_STAT, argv [0]);
}

ALI (clear_ip_bgp_flap_statistics_prefix,
     clear_ip_bgp_flap_statistics_prefix_len_cmd,
     "clear ip bgp flap-statistics A.B.C.D/M",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     "Clear route flap statistics",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8");

CLI (clear_ip_bgp_ipv4_safi_flap_statistics,
     clear_ip_bgp_ipv4_safi_flap_statistics_cmd,
     "clear ip bgp ipv4 (unicast|multicast) flap-statistics",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap statistics")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, bgp_cli_str2safi (argv [0]),
                        clear_rfd, BGP_CLEAR_RFD_FLAP_STAT, NULL);
}

CLI (clear_ip_bgp_ipv4_safi_flap_statistics_prefix,
     clear_ip_bgp_ipv4_safi_flap_statistics_prefix_cmd,
     "clear ip bgp ipv4 (unicast|multicast) flap-statistics A.B.C.D",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap statistics",
     "IP prefix <network>, e.g., 35.0.0.0")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, bgp_cli_str2safi (argv [0]),
                        clear_rfd, BGP_CLEAR_RFD_FLAP_STAT, argv [0]);
}

ALI (clear_ip_bgp_ipv4_safi_flap_statistics_prefix,
     clear_ip_bgp_ipv4_safi_flap_statistics_prefix_len_cmd,
     "clear ip bgp ipv4 (unicast|multicast) flap-statistics A.B.C.D/M",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap statistics",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8");

#ifdef HAVE_IPV6
CLI (clear_ip_bgp_ipv6_safi_flap_statistics,
     clear_ip_bgp_ipv6_safi_flap_statistics_cmd,
     "clear ip bgp ipv6 unicast flap-statistics",
     CLI_CLEAR_STR,
     CLI_IPV6_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap statistics")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_FLAP_STAT, NULL);
}

CLI (clear_ip_bgp_ipv6_safi_flap_statistics_prefix,
     clear_ip_bgp_ipv6_safi_flap_statistics_prefix_cmd,
     "clear ip bgp ipv6 unicast flap-statistics X:X::X:X",
     CLI_CLEAR_STR,
     CLI_IPV6_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap statistics",
     "IPv6 prefix <network>, e.g., 2003::")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_FLAP_STAT, argv [0]);
}

ALI (clear_ip_bgp_ipv6_safi_flap_statistics_prefix,
     clear_ip_bgp_ipv6_safi_flap_statistics_prefix_len_cmd,
     "clear ip bgp ipv6 unicast flap-statistics X:X::X:X/M",
     CLI_CLEAR_STR,
     CLI_IPV6_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap statistics",
     "IPv6 prefix <network>/<length>, e.g., 2003::/16");

CLI (clear_bgp_ipv6_safi_flap_statistics,
     clear_bgp_ipv6_safi_flap_statistics_cmd,
     "clear bgp ipv6 unicast flap-statistics",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap statistics")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_FLAP_STAT, NULL);
}

CLI (clear_bgp_ipv6_safi_flap_statistics_prefix,
     clear_bgp_ipv6_safi_flap_statistics_prefix_cmd,
     "clear bgp ipv6 unicast flap-statistics X:X::X:X",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap statistics",
     "IPv6 prefix <network>, e.g., 2003::")
{
  return bgp_clear_vty (cli, NULL, AFI_IP6, SAFI_UNICAST,
                        clear_rfd, BGP_CLEAR_RFD_FLAP_STAT, argv [0]);
}

ALI (clear_bgp_ipv6_safi_flap_statistics_prefix,
     clear_bgp_ipv6_safi_flap_statistics_prefix_len_cmd,
     "clear bgp ipv6 unicast flap-statistics X:X::X:X/M",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     "Clear route flap statistics",
     "IPv6 prefix <network>/<length>, e.g., 2003::/16");
#endif /* HAVE_IPV6 */

CLI (clear_bgp_ipv4_safi_flap_statistics,
     clear_bgp_ipv4_safi_flap_statistics_cmd,
     "clear bgp ipv4 (unicast|multicast) flap-statistics",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap statistics")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]),
                        clear_rfd, BGP_CLEAR_RFD_FLAP_STAT, NULL);
}

CLI (clear_bgp_ipv4_safi_flap_statistics_prefix,
     clear_bgp_ipv4_safi_flap_statistics_prefix_cmd,
     "clear bgp ipv4 (unicast|multicast) flap-statistics A.B.C.D",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap statistics",
     "IP prefix <network>, e.g., 35.0.0.0")
{
  return bgp_clear_vty (cli, NULL, AFI_IP, bgp_cli_str2safi (argv[0]),
                        clear_rfd, BGP_CLEAR_RFD_FLAP_STAT, argv[1]);
}

ALI (clear_bgp_ipv4_safi_flap_statistics_prefix,
     clear_bgp_ipv4_safi_flap_statistics_prefix_len_cmd,
     "clear bgp ipv4 (unicast|multicast) flap-statistics A.B.C.D/M",
     CLI_CLEAR_STR,
     CLI_BGP_STR,
     CLI_AF_STR,
     CLI_AFM_STR,
     CLI_AFM_STR,
     "Clear route flap statistics",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8");


void
bgp_cli_clear_init (struct cli_tree *ctree)
{
  /* "clear ip bgp commands" */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_instance_all_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_cmd);
#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_all_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_instance_all_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_all_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_group_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_group_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_external_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_external_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_as_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_as_cmd);
    }
#endif /* HAVE_IPV6 */

  /* "clear ip bgp neighbor soft in" */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_instance_all_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_instance_all_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ipv6_bgp_peer_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ipv6_bgp_peer_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv4_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv6_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_instance_all_ipv4_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv4_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv6_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv4_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_instance_all_ipv4_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_ipv4_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_ipv4_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_ipv4_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_ipv4_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_ipv4_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_ipv4_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_ipv4_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_ipv4_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_ipv4_in_prefix_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv4_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv6_soft_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv4_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv6_in_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv4_in_prefix_filter_cmd);
#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_all_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_instance_all_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_all_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_all_in_prefix_filter_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_in_prefix_filter_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_group_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_group_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_group_in_prefix_filter_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_external_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_external_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_external_in_prefix_filter_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_as_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_as_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_as_in_prefix_filter_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_all_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_all_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_all_in_prefix_filter_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_in_prefix_filter_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_group_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_group_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_group_in_prefix_filter_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_external_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_external_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_external_in_prefix_filter_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_as_soft_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_as_in_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_as_in_prefix_filter_cmd);
    }
#endif /* HAVE_IPV6 */

  /* "clear ip bgp neighbor soft out" */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_instance_all_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ipv6_bgp_peer_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ipv6_bgp_peer_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_out_cmd);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv4_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv6_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_instance_all_ipv4_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv4_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv6_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_ipv4_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_ipv4_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_ipv4_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_ipv4_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_ipv4_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_ipv4_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv4_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv6_soft_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv4_out_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv6_out_cmd);
#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_all_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_instance_all_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_all_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_group_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_group_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_external_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_external_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_as_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_as_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_all_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_all_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_group_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_group_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_external_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_external_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_as_soft_out_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_as_out_cmd);
    }
#endif /* HAVE_IPV6 */

  /* "clear ip bgp neighbor soft" */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_instance_all_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ipv6_bgp_peer_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv4_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_all_ipv6_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_instance_all_ipv4_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_ipv4_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_peer_group_ipv4_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_external_ipv4_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv4_soft_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_as_ipv6_soft_cmd);
#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_all_soft_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_instance_all_soft_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_soft_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_peer_group_soft_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_external_soft_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_as_soft_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_all_soft_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_soft_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_peer_group_soft_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_external_soft_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_as_soft_cmd);
    }
#endif /* HAVE_IPV6 */

  /* "clear [ip] bgp [ipv4|ipv6 [u|m]] dampening [prefix[/length]]" */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_dampening_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_dampening_prefix_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_dampening_prefix_len_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_ipv4_safi_dampening_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_ipv4_safi_dampening_prefix_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_ipv4_safi_dampening_prefix_len_cmd);
#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_ip_bgp_ipv6_safi_dampening_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_ip_bgp_ipv6_safi_dampening_prefix_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_ip_bgp_ipv6_safi_dampening_prefix_len_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_safi_dampening_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_safi_dampening_prefix_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_safi_dampening_prefix_len_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv4_safi_dampening_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv4_safi_dampening_prefix_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv4_safi_dampening_prefix_len_cmd);
    }
#endif /* HAVE_IPV6 */

  /* "clear [ip] bgp [ipv4|ipv6 [u|m]] flap-statistics [prefix[/length]]" */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_flap_statistics_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_flap_statistics_prefix_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_flap_statistics_prefix_len_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_ipv4_safi_flap_statistics_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_ipv4_safi_flap_statistics_prefix_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_bgp_ipv4_safi_flap_statistics_prefix_len_cmd);
#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_ip_bgp_ipv6_safi_flap_statistics_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_ip_bgp_ipv6_safi_flap_statistics_prefix_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_ip_bgp_ipv6_safi_flap_statistics_prefix_len_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_safi_flap_statistics_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_safi_flap_statistics_prefix_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv6_safi_flap_statistics_prefix_len_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv4_safi_flap_statistics_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv4_safi_flap_statistics_prefix_cmd);
      cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                       &clear_bgp_ipv4_safi_flap_statistics_prefix_len_cmd);
    }
#endif /* HAVE_IPV6 */

  return;
}

/* Redistribute commands.  */

#define BGP_REDIST_PROTO_STR " (kernel|connected|static|rip|ospf|isis)"
#define BGP_REDIST_PROTO_HELP_STR \
       "Kernel routes",\
       "Connected",\
       "Static routes",\
       "Routing Information Protocol (RIP)",\
       "Open Shortest Path First (OSPF)",\
       "ISO IS-IS"

s_int32_t
bgp_cli_str2proto (afi_t afi, u_int8_t *str)
{
  if (str == NULL)
    return -1;

  if (pal_strncmp (str, "k", 1) == 0)
    return IPI_ROUTE_KERNEL;
  else if (pal_strncmp (str, "c", 1) == 0)
    return IPI_ROUTE_CONNECT;
  else if (pal_strncmp (str, "s", 1) == 0)
    return IPI_ROUTE_STATIC;
  else
    return -1;
}

/* BGP distance configuration.  */

int
bgp_distance_set (struct cli *cli, char *distance_str, char *ip_str,
                  char *access_list_str)
{
  int ret;
  struct prefix_ipv4 p;
  u_char distance;
  struct bgp_node *rn;
  struct bgp_distance *bdistance;
  struct bgp *bgp = cli->index;

  if (! bgp->distance_table)
    return CLI_SUCCESS;

  ret = str2prefix_ipv4 (ip_str, &p);
  if (ret == 0)
    {
      cli_out (cli, "Malformed prefix\n");
      return CLI_ERROR;
    }

  distance = pal_strtos32 (distance_str, (char **)NULL, 10);

  /* Get BGP distance node. */
  rn = bgp_node_get (bgp->distance_table, (struct prefix *) &p);
  if (NULL == rn)
    return CLI_ERROR;

  if (rn->info)
    {
      bdistance = rn->info;
      bgp_unlock_node (rn);
    }
  else
    {
      bdistance = bgp_distance_new ();
      rn->info = bdistance;
    }

  /* Set distance value. */
  bdistance->distance = distance;

  /* Reset access-list configuration. */
  if (bdistance->access_list)
    {
      XFREE (MTYPE_TMP, bdistance->access_list);
      bdistance->access_list = NULL;
    }
  if (access_list_str)
    bdistance->access_list = XSTRDUP (MTYPE_TMP, access_list_str);

  return CLI_SUCCESS;
}

int
bgp_distance_unset (struct cli *cli, char *distance_str, char *ip_str,
                    char *access_list_str)
{
  int ret;
  struct prefix_ipv4 p;
  struct bgp_node *rn;
  struct bgp_distance *bdistance;
  struct bgp *bgp = cli->index;

  if (! bgp->distance_table)
    return CLI_SUCCESS;

  ret = str2prefix_ipv4 (ip_str, &p);
  if (ret == 0)
    {
      cli_out (cli, "Malformed prefix\n");
      return CLI_ERROR;
    }

  rn = bgp_node_lookup (bgp->distance_table, (struct prefix *)&p);
  if (! rn)
    {
      cli_out (cli, "Can't find specified prefix\n");
      return CLI_ERROR;
    }

  bdistance = rn->info;

  if (bdistance->access_list)
    XFREE (MTYPE_TMP, bdistance->access_list);
  bgp_distance_free (bdistance);

  rn->info = NULL;
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CLI_SUCCESS;
}

CLI (bgp_distance,
     bgp_distance_cmd,
     "distance bgp <1-255> <1-255> <1-255>",
     "Define an administrative distance",
     "BGP distance",
     "Distance for routes external to the AS",
     "Distance for routes internal to the AS",
     "Distance for local routes")
{
  bgp_distance_config_set (cli, argv[0], argv[1], argv[2]);
  return CLI_SUCCESS;
}

CLI (no_bgp_distance,
     no_bgp_distance_cmd,
     "no distance bgp <1-255> <1-255> <1-255>",
     CLI_NO_STR,
     "Define an administrative distance",
     "BGP distance",
     "Distance for routes external to the AS",
     "Distance for routes internal to the AS",
     "Distance for local routes")
{
  u_int32_t ret = 0;
  u_int32_t baai = 0;
  u_int32_t bsai = 0;
  u_int32_t ebgp_distance = 0;
  u_int32_t ibgp_distance = 0;
  u_int32_t local_distance = 0;
  struct bgp *bgp = cli->index; 
  
  baai = BGP_AFI2BAAI (bgp_cli_mode_afi (cli));
  bsai = BGP_SAFI2BSAI (bgp_cli_mode_safi(cli));

  /* Check and return an error if the weight unconfiguration is done even 
   * when the distane is not configured.
   */
  if (! bgp->distance_ebgp[baai][bsai] &&
      ! bgp->distance_ibgp[baai][bsai] &&
      ! bgp->distance_local[baai][bsai])
    {
      cli_out (cli, "%% Distance is not configured \n");
      return CLI_ERROR;
    }
 
  /* if arguments are given with the 'no' command, extract them,
   * else send the distance's with values initialized to ZERO 
   */ 
  if (argc == 3)
    {  
      ebgp_distance = pal_strtos32 (argv[0], (char **) NULL, 10);
      ibgp_distance = pal_strtos32 (argv[1], (char **) NULL, 10);
      local_distance = pal_strtos32 (argv[2], (char **) NULL, 10);
    }
  
  ret = bgp_distance_config_unset (cli , ebgp_distance, ibgp_distance, 
				   local_distance);

  if (ret == CLI_ERROR)
    {
      cli_out (cli, "%% Mismatch of distance-value's \n");
      return CLI_ERROR;
    }
  else
    return CLI_SUCCESS;
}

ALI (no_bgp_distance,
     no_bgp_distance2_cmd,
     "no distance bgp",
     CLI_NO_STR,
     "Define an administrative distance",
     "BGP distance");

CLI (bgp_distance_source,
     bgp_distance_source_cmd,
     "distance <1-255> A.B.C.D/M",
     "Define an administrative distance",
     "Administrative distance",
     "IP source prefix")
{
  bgp_distance_set (cli, argv[0], argv[1], NULL);
  return CLI_SUCCESS;
}

/*
CLI (bgp_memory_test_source,
     bgp_memory_test_cmd,
     "bgp memory test problem",
     "Define an administrative distance",
     "Administrative distance",
     "IP source prefix")
{
  struct prefix p;
  int loop;
  struct bgp_node *ret;
  struct prefix rnp;
  u_char buff [30];
  struct bgp *bgp = cli->index;
  u_char flag =0;
   u_char *prelist[] ={ 
  	"10.10.10.1/24",
  	"10.10.10.2/24",
  	"10.10.10.3/24",
  	"10.10.10.4/24",
  	"10.10.10.5/24",
  	"10.10.10.6/24",
  	"10.10.10.7/24",
  	"10.10.10.8/24",
  	"10.10.10.9/24",
  	"10.10.10.10/24",
  	"10.10.10.11/24"
  	};

  for (loop = 0; loop < 10; loop++)
   {
	str2prefix_ipv4 (prelist[loop], (struct prefix_ipv4 *)&p);
	ret = bgp_node_get (bgp->distance_table, &p);
	if (!ret)
          {
            cli_out(cli, "badri : unsuccessful in getting the node %s \n", prelist[loop]);
	    flag|=(loop+1);
	   }
    }

  if (!flag)
    {
      for (loop = 0; loop < 10; loop++)
         {
           str2prefix_ipv4 (prelist[loop], (struct prefix_ipv4 *)&p);
           ret = bgp_node_get(bgp->distance_table, &p);
           if (ret)
             {
               BGP_GET_PREFIX_FROM_NODE (ret);
               prefix2str (&rnp, buff, (ret->key_len -1));
               cli_out (cli," prefix : %s", buff);
             }
         }
    }

  return CLI_SUCCESS;
}
*/

CLI (no_bgp_distance_source,
     no_bgp_distance_source_cmd,
     "no distance <1-255> A.B.C.D/M",
     CLI_NO_STR,
     "Define an administrative distance",
     "Administrative distance",
     "IP source prefix")
{
  bgp_distance_unset (cli, argv[0], argv[1], NULL);
  return CLI_SUCCESS;
}

CLI (bgp_distance_source_access_list,
     bgp_distance_source_access_list_cmd,
     "distance <1-255> A.B.C.D/M WORD",
     "Define an administrative distance",
     "Administrative distance",
     "IP source prefix",
     "Access list name")
{
  bgp_distance_set (cli, argv[0], argv[1], argv[2]);
  return CLI_SUCCESS;
}

CLI (no_bgp_distance_source_access_list,
     no_bgp_distance_source_access_list_cmd,
     "no distance <1-255> A.B.C.D/M WORD",
     CLI_NO_STR,
     "Define an administrative distance",
     "Administrative distance",
     "IP source prefix",
     "Access list name")
{
  bgp_distance_unset (cli, argv[0], argv[1], argv[2]);
  return CLI_SUCCESS;
}

void
bgp_cli_distance_init (struct cli_tree *ctree)
{
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_distance_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_distance_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_distance2_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_distance_source_cmd);
  /*
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_memory_test_cmd);
  */

  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_distance_source_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_distance_source_access_list_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_distance_source_access_list_cmd);

  /* IPV4 Unicast - Default Address Family */
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_distance_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_distance_cmd);

  /* IPV4 Multicast */
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_distance_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_distance_cmd);
#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      /* IPV6 VRF */
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_distance_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_bgp_distance_cmd);
    }
#endif /* HAVE_IPV6 */
}

/* BGP Route Flap Dampening CLIs. */

CLI (bgp_damp_set,
     bgp_damp_set_cmd,
     "bgp dampening <1-45> <1-20000> <1-20000> <1-255> <1-45>",
     "BGP Specific commands",
     "Enable route-flap dampening",
     "Reachability Half-life time for the penalty(minutes)",
     "Value to start reusing a route",
     "Value to start suppressing a route",
     "Maximum duration to suppress a stable route(minutes)",
     "Un-reachability Half-life time for the penalty(minutes)")
{
  struct bgp_rfd_cb_cfg_param rfd_cb_cfg;
  s_int32_t ret;

  /* Set the defaults */
  rfd_cb_cfg.rfdc_reach_hlife = BGP_RFD_REACH_HLIFE_DEF_VAL *
                                ONE_MIN_SECOND;
  rfd_cb_cfg.rfdc_reuse = BGP_RFD_REUSE_DEF_VAL;
  rfd_cb_cfg.rfdc_suppress = BGP_RFD_SUPPRESS_DEF_VAL;
  rfd_cb_cfg.rfdc_max_suppress = BGP_RFD_MAX_SUPPRESS_DEF_VAL *
                                 ONE_MIN_SECOND;
  rfd_cb_cfg.rfdc_unreach_hlife = BGP_RFD_UREACH_HLIFE_DEF_VAL *
                                  ONE_MIN_SECOND;

  switch (argc)
    {
      case 1:
        rfd_cb_cfg.rfdc_reach_hlife =
                             pal_strtou32(argv[0], (char **)NULL, 10);
        if (rfd_cb_cfg.rfdc_reach_hlife < BGP_RFD_REACH_HLIFE_MIN_VAL
            || rfd_cb_cfg.rfdc_reach_hlife > BGP_RFD_REACH_HLIFE_MAX_VAL)
          {
            ret = -1;
            goto EXIT;
          }
        rfd_cb_cfg.rfdc_reach_hlife *= ONE_MIN_SECOND;
        rfd_cb_cfg.rfdc_max_suppress = rfd_cb_cfg.rfdc_reach_hlife * 4;
        rfd_cb_cfg.rfdc_unreach_hlife = rfd_cb_cfg.rfdc_reach_hlife;
        break;

      case 4:
        rfd_cb_cfg.rfdc_reach_hlife =
                             pal_strtou32(argv[0], (char **)NULL, 10);
        if (rfd_cb_cfg.rfdc_reach_hlife < BGP_RFD_REACH_HLIFE_MIN_VAL
            || rfd_cb_cfg.rfdc_reach_hlife > BGP_RFD_REACH_HLIFE_MAX_VAL)
          {
            ret = -1;
            goto EXIT;
          }
        rfd_cb_cfg.rfdc_reach_hlife *= ONE_MIN_SECOND;
        rfd_cb_cfg.rfdc_reuse =
                             pal_strtos32(argv[1], (char **)NULL, 10);
        if (rfd_cb_cfg.rfdc_reuse < BGP_RFD_REUSE_MIN_VAL
            || rfd_cb_cfg.rfdc_reuse > BGP_RFD_REUSE_MAX_VAL)
          {
            ret = -1;
            goto EXIT;
          }
        rfd_cb_cfg.rfdc_suppress =
                             pal_strtos32(argv[2], (char **)NULL, 10);
        if ((rfd_cb_cfg.rfdc_suppress < BGP_RFD_SUPPRESS_MIN_VAL
             || rfd_cb_cfg.rfdc_suppress > BGP_RFD_SUPPRESS_MAX_VAL)
            || (rfd_cb_cfg.rfdc_suppress < rfd_cb_cfg.rfdc_reuse))
          {
            ret = -1;
            goto EXIT;
          }
        rfd_cb_cfg.rfdc_max_suppress =
                             pal_strtos32(argv[3], (char **)NULL, 10);
        if (rfd_cb_cfg.rfdc_max_suppress < BGP_RFD_MAX_SUPPRESS_MIN_VAL
             || rfd_cb_cfg.rfdc_max_suppress > BGP_RFD_MAX_SUPPRESS_MAX_VAL)
          {
            ret = -1;
            goto EXIT;
          }
        rfd_cb_cfg.rfdc_max_suppress *= ONE_MIN_SECOND;
        if (rfd_cb_cfg.rfdc_max_suppress < rfd_cb_cfg.rfdc_reach_hlife)
          {
            ret = -1;
            goto EXIT;
          }
        rfd_cb_cfg.rfdc_unreach_hlife = rfd_cb_cfg.rfdc_reach_hlife;
        break;

      case 5:
        rfd_cb_cfg.rfdc_reach_hlife =
            pal_strtou32(argv[0], (char **)NULL, 10) * ONE_MIN_SECOND;
        rfd_cb_cfg.rfdc_reuse =
            pal_strtos32(argv[1], (char **)NULL, 10);
        rfd_cb_cfg.rfdc_suppress =
            pal_strtos32(argv[2], (char **)NULL, 10);
        rfd_cb_cfg.rfdc_max_suppress =
                             pal_strtos32(argv[3], (char **)NULL, 10);
        if (rfd_cb_cfg.rfdc_max_suppress < BGP_RFD_MAX_SUPPRESS_MIN_VAL
             || rfd_cb_cfg.rfdc_max_suppress > BGP_RFD_MAX_SUPPRESS_MAX_VAL)
          {
            ret = -1;
            goto EXIT;
          }
        rfd_cb_cfg.rfdc_max_suppress *= ONE_MIN_SECOND;
        if (rfd_cb_cfg.rfdc_max_suppress < rfd_cb_cfg.rfdc_reach_hlife)
          {
            ret = -1;
            goto EXIT;
          }
        rfd_cb_cfg.rfdc_unreach_hlife =
                             pal_strtou32(argv[4], (char **)NULL, 10);
        if (rfd_cb_cfg.rfdc_unreach_hlife < BGP_RFD_UREACH_HLIFE_MIN_VAL
             || rfd_cb_cfg.rfdc_unreach_hlife > BGP_RFD_UREACH_HLIFE_MAX_VAL)
          {
            ret = -1;
            goto EXIT;
          }
        rfd_cb_cfg.rfdc_unreach_hlife *= ONE_MIN_SECOND;
        if ((rfd_cb_cfg.rfdc_unreach_hlife < rfd_cb_cfg.rfdc_reach_hlife)
            || (rfd_cb_cfg.rfdc_max_suppress < rfd_cb_cfg.rfdc_unreach_hlife))
          {
            ret = -1;
            goto EXIT;
          }
        break;
    }

  ret = bgp_rfd_cfg_create (cli->index, bgp_cli_mode_afi (cli),
                            bgp_cli_mode_safi (cli), &rfd_cb_cfg, NULL);

 EXIT:

  ret = ret ? BGP_API_SET_ERR_INVALID_VALUE : BGP_API_SET_SUCCESS;

  return bgp_cli_return (cli, ret);
}

ALI (bgp_damp_set,
     bgp_damp_set2_cmd,
     "bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
     "BGP Specific commands",
     "Enable route-flap dampening",
     "Reachability Half-life time for the penalty(minutes)",
     "Value to start reusing a route",
     "Value to start suppressing a route",
     "Maximum duration to suppress a stable route(minutes)");

ALI (bgp_damp_set,
     bgp_damp_set3_cmd,
     "bgp dampening <1-45>",
     "BGP Specific commands",
     "Enable route-flap dampening",
     "Reachability Half-life time for the penalty(minutes)");

ALI (bgp_damp_set,
     bgp_damp_set4_cmd,
     "bgp dampening",
     "BGP Specific commands",
     "Enable route-flap dampening");

CLI (bgp_damp_unset,
     bgp_damp_unset_cmd,
     "no bgp dampening",
     CLI_NO_STR,
     "BGP Specific commands",
     "Enable route-flap dampening")
{
  s_int32_t ret;

  ret = bgp_rfd_cfg_delete (cli->index, bgp_cli_mode_afi (cli),
                            bgp_cli_mode_safi (cli));

  ret = ret ? BGP_API_SET_ERROR : BGP_API_SET_SUCCESS;

  return bgp_cli_return (cli, ret);
}

ALI (bgp_damp_unset,
     bgp_damp_unset2_cmd,
     "no bgp dampening <1-45> <1-20000> <1-20000> <1-255> <1-45>",
     CLI_NO_STR,
     "BGP Specific commands",
     "Enable route-flap dampening",
     "Reachability Half-life time for the penalty(minutes)",
     "Value to start reusing a route",
     "Value to start suppressing a route",
     "Maximum duration to suppress a stable route(minutes)",
     "Un-reachability Half-life time for the penalty(minutes)");

ALI (bgp_damp_unset,
     bgp_damp_unset3_cmd,
     "no bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
     CLI_NO_STR,
     "BGP Specific commands",
     "Enable route-flap dampening",
     "Reachability Half-life time for the penalty(minutes)",
     "Value to start reusing a route",
     "Value to start suppressing a route",
     "Maximum duration to suppress a stable route(minutes)");

ALI (bgp_damp_unset,
     bgp_damp_unset4_cmd,
     "no bgp dampening <1-45>",
     CLI_NO_STR,
     "BGP Specific commands",
     "Enable route-flap dampening",
     "Reachability Half-life time for the penalty(minutes)");

CLI (bgp_damp_rmap,
     bgp_damp_rmap_cmd,
     "bgp dampening route-map WORD",
     "BGP Specific commands",
     "Enable route-flap dampening",
     "Route-map to specify criteria for dampening",
     "Route-map name")
{
  s_int32_t ret;

  ret = bgp_rfd_cfg_create (cli->index, bgp_cli_mode_afi (cli),
                            bgp_cli_mode_safi (cli), NULL, argv[0]);

  ret = ret ? BGP_API_SET_ERR_INVALID_VALUE : BGP_API_SET_SUCCESS;

  return bgp_cli_return (cli, ret);
}

ALI (bgp_damp_unset,
     no_bgp_damp_rmap_cmd,
     "no bgp dampening route-map",
     CLI_NO_STR,
     "BGP Specific commands",
     "Enable route-flap dampening",
     "Route-map to specify criteria for dampening");

ALI (bgp_damp_unset,
     no_bgp_damp_rmap2_cmd,
     "no bgp dampening route-map WORD",
     CLI_NO_STR,
     "BGP Specific commands",
     "Enable route-flap dampening",
     "Route-map to specify criteria for dampening",
     "route-map name");

s_int32_t
bgp_cli_dampening_init (struct cli_tree *ctree)
{
  s_int32_t ret;

  ret = 0;

  /* IPV4 Unicast - Default Address Family */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set2_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set3_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set4_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset2_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset3_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset4_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_rmap_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_damp_rmap_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_damp_rmap2_cmd);

  /* IPV4 Unicast - Explicitly specified Def Address Family */
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set2_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set3_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set4_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset2_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset3_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset4_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_rmap_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_damp_rmap_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_damp_rmap2_cmd);

  /* IPV4 Multicast */
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set2_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set3_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_set4_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset2_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset3_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_unset4_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_damp_rmap_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_damp_rmap_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_damp_rmap2_cmd);

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      /* IPV6 VRF */
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_damp_set_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_damp_set2_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_damp_set3_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_damp_set4_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_damp_unset_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_damp_unset2_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_damp_unset3_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_damp_unset4_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_damp_rmap_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_bgp_damp_rmap_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_bgp_damp_rmap2_cmd);
    }
#endif /* HAVE_IPV6 */

  return ret;
}

/* BGP Auto-Summarization commands */
CLI (bgp_auto_summary,
     bgp_auto_summary_cmd,
     "auto-summary",
     "Enable automatic network number summarization")
{
  s_int32_t ret;

  ret = bgp_auto_summary_update (cli->index, bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli), PAL_TRUE);

  return bgp_cli_return (cli, ret);
}

CLI (bgp_no_auto_summary,
     bgp_no_auto_summary_cmd,
     "no auto-summary",
     CLI_NO_STR,
     "Enable automatic network number summarization")
{
  s_int32_t ret;

  ret = bgp_auto_summary_update (cli->index, bgp_cli_mode_afi (cli),
                                 bgp_cli_mode_safi (cli), PAL_FALSE);

  return bgp_cli_return (cli, ret);
}

s_int32_t
bgp_cli_auto_summary_init (struct cli_tree *ctree)
{
  s_int32_t ret;

  ret = 0;

  /* IPV4 Unicast - Default Address Family */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_auto_summary_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_no_auto_summary_cmd);

  /* IPV4 Unicast - Explicitly specified Def Address Family */
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_auto_summary_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_no_auto_summary_cmd);

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      /* IPV6 VRF */
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_auto_summary_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_no_auto_summary_cmd);
    }
#endif /* HAVE_IPV6 */

  return ret;
}


/* BGP Static Network Synchronization commands */

CLI (bgp_network_synchronization,
     bgp_network_synchronization_cmd,
     "network synchronization",
     "Specify a network to announce via BGP",
     "Perform IGP synchronization on network routes")
{
  s_int32_t ret;

  ret = bgp_network_sync_set (cli->index, bgp_cli_mode_afi (cli),
                              bgp_cli_mode_safi (cli));

  return bgp_cli_return (cli, ret);
}

CLI (bgp_no_network_synchronization,
     bgp_no_network_synchronization_cmd,
     "no network synchronization",
     CLI_NO_STR,
     "Specify a network to announce via BGP",
     "Perform IGP synchronization on network routes")
{
  s_int32_t ret;

  ret = bgp_network_sync_unset (cli->index, bgp_cli_mode_afi (cli),
                                bgp_cli_mode_safi (cli));

  return bgp_cli_return (cli, ret);
}

s_int32_t
bgp_cli_network_sync_init (struct cli_tree *ctree)
{
  s_int32_t ret;

  ret = 0;

  /* IPV4 Unicast - Default Address Family */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_synchronization_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_no_network_synchronization_cmd);

  /* IPV4 Unicast - Explicitly specified Def Address Family */
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_synchronization_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_no_network_synchronization_cmd);

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      /* IPV6 Unicast */
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_network_synchronization_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_no_network_synchronization_cmd);
    }
#endif /* HAVE_IPV6 */

  return ret;
}

/* BGP Network CLIs.  */

CLI (bgp_network,
     bgp_network_cmd,
     "network A.B.C.D/M (backdoor|)",
     "Specify a network to announce via BGP",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8",
     "Specify a BGP backdoor route")
{
  s_int32_t ret;
  u_int8_t backdoor = 0;

  if (argc == 2)
    backdoor = 1;

  ret = bgp_static_network_set (cli->index, argv[0], AFI_IP,
                                bgp_cli_mode_safi (cli),
                                backdoor, NULL);

  return bgp_cli_return (cli, ret);
}

ALI (bgp_network,
     bgp_network_nomask_cmd,
     "network A.B.C.D (backdoor|)",
     "Specify a network to announce via BGP",
     "IP prefix <network>, e.g., 35.0.0.0",
     "Specify a BGP backdoor route");

CLI (bgp_network_route_map,
     bgp_network_route_map_cmd,
     "network A.B.C.D/M route-map WORD (backdoor|)",
     "Specify a network to announce via BGP",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8",
     "Route-map to modify the attributes",
     "Name of the route map",
     "Specify a BGP backdoor route")
{
  int ret;
  int backdoor = 0;

  if (argc == 3)
    backdoor = 1;

  ret = bgp_static_network_set (cli->index, argv[0], AFI_IP,
                                bgp_cli_mode_safi (cli),
                                backdoor, argv[1]);

  return bgp_cli_return (cli, ret);
}

ALI (bgp_network_route_map,
     bgp_network_nomask_route_map_cmd,
     "network A.B.C.D route-map WORD (backdoor|)",
     "Specify a network to announce via BGP",
     "IP prefix <network>, e.g., 35.0.0.0",
     "Route-map to modify the attributes",
     "Name of the route map",
     "Specify a BGP backdoor route");

CLI (no_bgp_network,
     no_bgp_network_cmd,
     "no network A.B.C.D/M (backdoor|)",
     CLI_NO_STR,
     "Specify a network to announce via BGP",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8",
     "Specify a BGP backdoor route")
{
  int ret;

  ret = bgp_static_network_unset (cli->index, argv[0], AFI_IP,
                                  bgp_cli_mode_safi (cli));

  return bgp_cli_return (cli, ret);
}

ALI (no_bgp_network,
     no_bgp_network_route_map_cmd,
     "no network A.B.C.D/M route-map WORD (backdoor|)",
     CLI_NO_STR,
     "Specify a network to announce via BGP",
     "IP prefix <network>/<length>, e.g., 35.0.0.0/8",
     "Route-map to modify the attributes",
     "Name of the route map",
     "Specify a BGP backdoor route");

ALI (no_bgp_network,
     no_bgp_network_nomask_cmd,
     "no network A.B.C.D (backdoor|)",
     CLI_NO_STR,
     "Specify a network to announce via BGP",
     "IP prefix <network>, e.g., 35.0.0.0",
     "Specify a BGP backdoor route");

ALI (no_bgp_network,
     no_bgp_network_nomask_route_map_cmd,
     "no network A.B.C.D route-map WORD (backdoor|)",
     CLI_NO_STR,
     "Specify a network to announce via BGP",
     "IP prefix <network>, e.g., 35.0.0.0",
     "Route-map to modify the attributes",
     "Name of the route map",
     "Specify a BGP backdoor route");

CLI (bgp_network_mask,
     bgp_network_mask_cmd,
     "network A.B.C.D mask A.B.C.D (backdoor|)",
     "Specify a network to announce via BGP",
     "IP prefix <network>, e.g., 35.0.0.0",
     "Specify network mask",
     "Network mask, e.g., 255.255.0.0",
     "Specify a BGP backdoor route")
{
  int backdoor = 0;
  s_int32_t ret = PAL_TRUE;
  char ip_str[IPV4_PREFIX_STR_MAX_LEN];

  if (! strmask2ipstr (argv[0], argv[1], ip_str))
    ret = BGP_API_SET_ERR_INVALID_MASK;

  if (ret == PAL_TRUE)
    {
      if (argc == 3)
        backdoor = 1;

      ret = bgp_static_network_set (cli->index, ip_str, AFI_IP,
                                    bgp_cli_mode_safi (cli),
                                    backdoor, NULL);
    }
  return bgp_cli_return (cli, ret);
}

CLI (bgp_network_mask_route_map,
     bgp_network_mask_route_map_cmd,
     "network A.B.C.D  mask A.B.C.D route-map WORD (backdoor|)",
     "Specify a network to announce via BGP",
     "IP prefix <network>, e.g., 35.0.0.0",
     "Specify network mask",
     "Network mask, e.g., 255.255.0.0",
     "Route-map to modify the attributes",
     "Name of the route map",
     "Specify a BGP backdoor route")
{
  int backdoor = 0;
  s_int32_t ret = PAL_TRUE;
  char ip_str[IPV4_PREFIX_STR_MAX_LEN];

  if (! strmask2ipstr (argv[0], argv[1], ip_str))
    ret = BGP_API_SET_ERR_INVALID_MASK;

  if (ret == PAL_TRUE)
    {
      if (argc == 4)
        backdoor = 1;

      ret = bgp_static_network_set (cli->index, ip_str, AFI_IP,
                                    bgp_cli_mode_safi (cli),
                                    backdoor, argv[2]);
    }
  return bgp_cli_return (cli, ret);
}

CLI (no_bgp_network_mask,
     no_bgp_network_mask_cmd,
     "no network A.B.C.D mask A.B.C.D (backdoor|)",
     CLI_NO_STR,
     "Specify a network to announce via BGP",
     "IP prefix <network>, e.g., 35.0.0.0",
     "Specify network mask",
     "Network mask, e.g., 255.255.0.0",
     "Specify a BGP backdoor route")
{
  s_int32_t ret = PAL_TRUE;
  char ip_str[IPV4_PREFIX_STR_MAX_LEN];

  if (! strmask2ipstr (argv[0], argv[1], ip_str))
    ret = BGP_API_SET_ERR_INVALID_MASK;

  if (ret == PAL_TRUE)
    ret = bgp_static_network_unset (cli->index, ip_str, AFI_IP,
                                    bgp_cli_mode_safi (cli));

  return bgp_cli_return (cli, ret);
}

ALI (no_bgp_network_mask,
     no_bgp_network_mask_route_map_cmd,
     "no network A.B.C.D mask A.B.C.D route-map WORD (backdoor|)",
     CLI_NO_STR,
     "Specify a network to announce via BGP",
     "IP prefix <network>, e.g., 35.0.0.0",
     "Specify network mask",
     "Network mask, e.g., 255.255.0.0",
     "Route-map to modify the attributes",
     "Name of the route map",
     "Specify a BGP backdoor route");

#ifdef HAVE_IPV6
CLI (bgp_ipv6_network,
     bgp_ipv6_network_cmd,
     "network X:X::X:X/M",
     "Specify a network to announce via BGP",
     "IPv6 prefix <network>/<length>, e.g., 3ffe::/16")
{
  int ret;

  ret = bgp_static_network_set (cli->index, argv[0],
                                AFI_IP6, SAFI_UNICAST, 0, NULL);

  return bgp_cli_return (cli, ret);
}

CLI (bgp_ipv6_network_backdoor,
     bgp_ipv6_network_backdoor_cmd,
     "network X:X::X:X/M backdoor",
     "Specify a network to announce via BGP",
     "IPv6 prefix <network>/<length>, e.g., 3ffe::/16",
     "Specify a BGP backdoor route")
{
  int ret;
  ret = bgp_static_network_set (cli->index, argv[0],
                                AFI_IP6, SAFI_UNICAST, 1, NULL);

  return bgp_cli_return (cli, ret);
}

CLI (bgp_ipv6_network_route_map,
     bgp_ipv6_network_route_map_cmd,
     "network X:X::X:X/M route-map WORD (backdoor|)",
     "Specify a network to announce via BGP",
     "IPv6 prefix <network>/<length>, e.g., 3ffe::/16",
     "Route-map to modify the attributes",
     "Name of the route map",
     "Specify a BGP backdoor route")

{
  int ret;
  int backdoor = 0;

  if (argc == 3)
    backdoor = 1;

  ret = bgp_static_network_set (cli->index, argv[0],
                                AFI_IP6, SAFI_UNICAST, backdoor, argv[1]);

  return bgp_cli_return (cli, ret);
}

CLI (no_ipv6_bgp_network,
     no_ipv6_bgp_network_cmd,
     "no network X:X::X:X/M",
     CLI_NO_STR,
     "Specify a network to announce via BGP",
     "IPv6 prefix <network>/<length>, e.g., 3ffe::/16")
{
  int ret;
  ret = bgp_static_network_unset (cli->index, argv[0], AFI_IP6, SAFI_UNICAST);

  return bgp_cli_return (cli, ret);
}

ALI (no_ipv6_bgp_network,
     no_ipv6_bgp_network_backdoor_cmd,
     "no network X:X::X:X/M backdoor",
     CLI_NO_STR,
     "Specify a network to announce via BGP",
     "IPv6 prefix <network>/<length>, e.g., 3ffe::/16",
     "Specify a BGP backdoor route");

ALI (no_ipv6_bgp_network,
     no_ipv6_bgp_network_route_map_cmd,
     "no network X:X::X:X/M route-map WORD (backdoor|)",
     CLI_NO_STR,
     "Specify a network to announce via BGP",
     "IPv6 prefix <network>/<length>, e.g., 3ffe::/16",
     "Route-map to modify the attributes",
     "Name of the route map",
     "Specify a BGP backdoor route");
#endif /* HAVE_IPV6 */

void
bgp_cli_network_init (struct cli_tree *ctree)
{
  /* IPv4 BGP commands. */
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_nomask_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_nomask_route_map_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_nomask_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_nomask_route_map_cmd);

  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_route_map_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_route_map_cmd);

  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_mask_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_mask_route_map_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_mask_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_mask_route_map_cmd);

  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_nomask_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_nomask_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_nomask_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_nomask_route_map_cmd);

  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_route_map_cmd);

  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_mask_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_mask_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_mask_cmd);
  cli_install_gen (ctree, BGP_IPV4_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_mask_route_map_cmd);

  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_nomask_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_nomask_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_nomask_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_nomask_route_map_cmd);

  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_route_map_cmd);

  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_mask_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_network_mask_route_map_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_mask_cmd);
  cli_install_gen (ctree, BGP_IPV4M_MODE, PRIVILEGE_NORMAL, 0,
                   &no_bgp_network_mask_route_map_cmd);

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      /* IPv6 BGP commands. */
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_ipv6_network_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_ipv6_network_backdoor_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &bgp_ipv6_network_route_map_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_ipv6_bgp_network_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_ipv6_bgp_network_backdoor_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_ipv6_bgp_network_route_map_cmd);
    }
#endif /* HAVE_IPV6 */
}

/* Community list related CLIs.   */

/* Direction value to string conversion.  */
char *
community_direct_str (int direct)
{
  switch (direct)
    {
    case COMMUNITY_DENY:
      return "deny";
      break;
    case COMMUNITY_PERMIT:
      return "permit";
      break;
    default:
      return "unknown";
      break;
    }
}

/* VTY interface for community_set() function.  */
int
community_list_set_vty (struct cli *cli, int argc, char **argv, int style,
                        int reject_all_digit_name)
{
  u_int32_t direct;
  s_int32_t ret;
  char *str;

  /* Check the list type. */
  if (pal_strncmp (argv[1], "p", 1) == 0)
    direct = COMMUNITY_PERMIT;
  else if (pal_strncmp (argv[1], "d", 1) == 0)
    direct = COMMUNITY_DENY;
  else
    {
      cli_out (cli, "%% Matching condition must be permit or deny\n");
      return CLI_ERROR;
    }

  /* All digit name check.  */
  if (reject_all_digit_name && all_digit (argv[0]))
    {
      cli_out (cli, "%% Community name cannot have all digits\n");
      return CLI_ERROR;
    }

  /* Concat community string argument.  */
  if (argc > 1)
    str = argv_concat (argv, argc, 2);
  else
    str = NULL;

  /* When community_list_set() return nevetive value, it means
     malformed community string.  */
  ret = community_list_set (bgp_clist, argv[0], str, direct, style);

  /* Free temporary community list string allocated by
     argv_concat().  */
  if (str)
    XFREE (MTYPE_TMP, str);

  return bgp_cli_return (cli, ret);
}

/* Community-list delete with name.  */
int
community_list_unset_all_vty (struct cli *cli, char *name)
{
  int ret;

  ret = community_list_unset (bgp_clist, name, NULL, 0, COMMUNITY_LIST_AUTO);

  return bgp_cli_return (cli, ret);
}

/* Communiyt-list entry delete.  */
int
community_list_unset_vty (struct cli *cli, int argc, char **argv, int style)
{
  u_int32_t direct;
  s_int32_t ret;
  char *str;

  /* Check the list direct. */
  if (pal_strncmp (argv[1], "p", 1) == 0)
    direct = COMMUNITY_PERMIT;
  else if (pal_strncmp (argv[1], "d", 1) == 0)
    direct = COMMUNITY_DENY;
  else
    {
      cli_out (cli, "%% Matching condition must be permit or deny\n");
      return CLI_ERROR;
    }

  /* Concat community string argument.  */
  str = argv_concat (argv, argc, 2);

  /* Unset community list.  */
  ret = community_list_unset (bgp_clist, argv[0], str, direct, style);

  /* Free temporary community list string allocated by
     argv_concat().  */
  XFREE (MTYPE_TMP, str);

  return bgp_cli_return (cli, ret);
}

/* "community-list" keyword help string.  */
#define COMMUNITY_LIST_STR "Add a community list entry"
#define COMMUNITY_VAL_STR  "[AA:NN|internet|local-AS|no-advertise|no-export]"
#define COMMUNITY_VAL_HELP_STR \
        "Specifies the valid value for community number",\
        "Advertise routes to the internet community",\
        "Specifies routes not to be advertised to external BGP peers",\
        "Specifies routes not to be advertised to other BGP peers",\
        "Specifies routes not to be advertised outside of Autonomous system boundary"

CLI (ip_community_list,
     ip_community_list_cmd,
     "ip community-list WORD (deny|permit)" COMMUNITY_VAL_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Community list name",
     "Specify community to reject",
     "Specify community to accept",
     COMMUNITY_VAL_HELP_STR)
{
  return community_list_set_vty (cli, argc, argv, COMMUNITY_LIST_AUTO, 1);
}

CLI (ip_community_list_standard,
     ip_community_list_standard_cmd,
     "ip community-list <1-99> (deny|permit)" COMMUNITY_VAL_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Community list number (standard)",
     "Specify community to reject",
     "Specify community to accept",
     COMMUNITY_VAL_HELP_STR)
{
  return community_list_set_vty (cli, argc, argv, COMMUNITY_LIST_STANDARD, 0);
}

ALI (ip_community_list_standard,
     ip_community_list_standard2_cmd,
     "ip community-list <1-99> (deny|permit)",
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Community list number (standard)",
     "Specify community to reject",
     "Specify community to accept");

CLI (ip_community_list_expanded,
     ip_community_list_expanded_cmd,
     "ip community-list <100-199> (deny|permit) LINE",
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Community list number (expanded)",
     "Specify community to reject",
     "Specify community to accept",
     "An ordered list as a regular-expression")
{
  return community_list_set_vty (cli, argc, argv, COMMUNITY_LIST_EXPANDED, 0);
}

CLI (ip_community_list_name_standard,
     ip_community_list_name_standard_cmd,
     "ip community-list standard WORD (deny|permit)" COMMUNITY_VAL_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Add a standard community-list entry",
     "Community list name",
     "Specify community to reject",
     "Specify community to accept",
     COMMUNITY_VAL_HELP_STR)
{
  return community_list_set_vty (cli, argc, argv, COMMUNITY_LIST_STANDARD, 1);
}

ALI (ip_community_list_name_standard,
     ip_community_list_name_standard2_cmd,
     "ip community-list standard WORD (deny|permit)",
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Add a standard community-list entry",
     "Community list name",
     "Specify community to reject",
     "Specify community to accept");

CLI (ip_community_list_name_expanded,
     ip_community_list_name_expanded_cmd,
     "ip community-list expanded WORD (deny|permit) LINE",
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Add an expanded community-list entry",
     "Community list name",
     "Specify community to reject",
     "Specify community to accept",
     "An ordered list as a regular-expression")
{
  return community_list_set_vty (cli, argc, argv, COMMUNITY_LIST_EXPANDED, 1);
}

CLI (no_ip_community_list_all,
     no_ip_community_list_all_cmd,
     "no ip community-list (WORD|<1-99>|<100-199>)",
     CLI_NO_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Community list name",
     "Community list number (standard)",
     "Community list number (expanded)")
{
  return community_list_unset_all_vty (cli, argv[0]);
}

CLI (no_ip_community_list_name_all_s,
     no_ip_community_list_name_all_s_cmd,
     "no ip community-list standard WORD",
     CLI_NO_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Add a standard community-list entry",
     "Community list name")
{
  return community_list_unset_all_vty (cli, argv[0]);
}

CLI (no_ip_community_list_name_all_e,
     no_ip_community_list_name_all_e_cmd,
     "no ip community-list expanded WORD",
     CLI_NO_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Add an expanded community-list entry",
     "Community list name")
{
  return community_list_unset_all_vty (cli, argv[0]);
}

CLI (no_ip_community_list,
     no_ip_community_list_cmd,
     "no ip community-list WORD (deny|permit)" COMMUNITY_VAL_STR,
     CLI_NO_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Community list name",
     "Specify community to reject",
     "Specify community to accept",
     COMMUNITY_VAL_HELP_STR)
{
  return community_list_unset_vty (cli, argc, argv, COMMUNITY_LIST_AUTO);
}

CLI (no_ip_community_list_standard,
     no_ip_community_list_standard_cmd,
     "no ip community-list <1-99> (deny|permit)" COMMUNITY_VAL_STR,
     CLI_NO_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Community list number (standard)",
     "Specify community to reject",
     "Specify community to accept",
     COMMUNITY_VAL_HELP_STR)
{
  return community_list_unset_vty (cli, argc, argv, COMMUNITY_LIST_STANDARD);
}

CLI (no_ip_community_list_expanded,
     no_ip_community_list_expanded_cmd,
     "no ip community-list <100-199> (deny|permit) LINE",
     CLI_NO_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Community list number (expanded)",
     "Specify community to reject",
     "Specify community to accept",
     "An ordered list as a regular-expression")
{
  return community_list_unset_vty (cli, argc, argv, COMMUNITY_LIST_EXPANDED);
}

CLI (no_ip_community_list_name_standard,
     no_ip_community_list_name_standard_cmd,
     "no ip community-list standard WORD (deny|permit)" COMMUNITY_VAL_STR,
     CLI_NO_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Specify a standard community-list",
     "Community list name",
     "Specify community to reject",
     "Specify community to accept",
     COMMUNITY_VAL_HELP_STR)
{
  return community_list_unset_vty (cli, argc, argv, COMMUNITY_LIST_STANDARD);
}

CLI (no_ip_community_list_name_expanded,
     no_ip_community_list_name_expanded_cmd,
     "no ip community-list expanded WORD (deny|permit) LINE",
     CLI_NO_STR,
     CLI_IP_STR,
     COMMUNITY_LIST_STR,
     "Specify an expanded community-list",
     "Community list name",
     "Specify community to reject",
     "Specify community to accept",
     "An ordered list as a regular-expression")
{
  return community_list_unset_vty (cli, argc, argv, COMMUNITY_LIST_EXPANDED);
}

void
community_list_show (struct cli *cli, struct community_list *list)
{
  struct community_entry *entry;

  for (entry = list->head; entry; entry = entry->next)
    {
      if (entry == list->head)
        {
          if (all_digit (list->name))
            cli_out (cli, "Community %s list %s\n",
                     entry->style == COMMUNITY_LIST_STANDARD ?
                     "standard" : "(expanded) access",
                     list->name);
          else
            cli_out (cli, "Named Community %s list %s\n",
                     entry->style == COMMUNITY_LIST_STANDARD ?
                     "standard" : "expanded",
                     list->name);
        }
      if (entry->any)
        cli_out (cli, "    %s\n",
                 community_direct_str (entry->direct));
      else
        cli_out (cli, "    %s %s\n",
                 community_direct_str (entry->direct),
                 entry->style == COMMUNITY_LIST_STANDARD
                 ? community_str (entry->u.com) : entry->config);
    }
}

CLI (show_ip_community_list,
     show_ip_community_list_cmd,
     "show ip community-list",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "List community-list")
{
  struct community_list *list;
  struct community_list_master *cm;

  cm = community_list_master_lookup (bgp_clist, COMMUNITY_LIST_AUTO);
  if (! cm)
    return CLI_SUCCESS;

  for (list = cm->num.head; list; list = list->next)
    community_list_show (cli, list);

  for (list = cm->str.head; list; list = list->next)
    community_list_show (cli, list);

  return CLI_SUCCESS;
}

CLI (show_ip_community_list_arg,
     show_ip_community_list_arg_cmd,
     "show ip community-list (<1-199>|WORD)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "List community-list",
     "Community-list number",
     "Community-list name")
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, argv[0], COMMUNITY_LIST_AUTO);
  if (! list)
    {
      cli_out (cli, "%% Can't find community-list\n");
      return CLI_ERROR;
    }

  community_list_show (cli, list);

  return CLI_SUCCESS;
}

/* Extended community list.  */
int
extcommunity_list_set_vty (struct cli *cli, int argc, char **argv, int style,
                           int reject_all_digit_name)
{
  int ret;
  int direct;
  char *str;

  /* Check the list type. */
  if (pal_strncmp (argv[1], "p", 1) == 0)
    direct = COMMUNITY_PERMIT;
  else if (pal_strncmp (argv[1], "d", 1) == 0)
    direct = COMMUNITY_DENY;
  else
    {
      cli_out (cli, "%% Matching condition must be permit or deny\n");
      return CLI_ERROR;
    }

  /* All digit name check.  */
  if (reject_all_digit_name && all_digit (argv[0]))
    {
      cli_out (cli, "%% Community name cannot have all digits\n");
      return CLI_ERROR;
    }

  /* Concat community string argument.  */
  if (argc > 1)
    str = argv_concat (argv, argc, 2);
  else
    str = NULL;

  ret = extcommunity_list_set (bgp_clist, argv[0], str, direct, style);

  /* Free temporary community list string allocated by
     argv_concat().  */
  if (str)
    XFREE (MTYPE_TMP, str);

  return bgp_cli_return (cli, ret);
}

int
extcommunity_list_unset_all_vty (struct cli *cli, char *name)
{
  int ret;

  ret = extcommunity_list_unset (bgp_clist, name, NULL, 0,
                                 EXTCOMMUNITY_LIST_AUTO);

  return bgp_cli_return (cli, ret);
}

int
extcommunity_list_unset_vty (struct cli *cli, int argc, char **argv, int style)
{
  int ret;
  int direct;
  char *str;

  /* Check the list direct. */
  if (pal_strncmp (argv[1], "p", 1) == 0)
    direct = COMMUNITY_PERMIT;
  else if (pal_strncmp (argv[1], "d", 1) == 0)
    direct = COMMUNITY_DENY;
  else
    {
      cli_out (cli, "%% Matching condition must be permit or deny\n");
      return CLI_ERROR;
    }

  /* Concat community string argument.  */
  str = argv_concat (argv, argc, 2);

  /* Unset community list.  */
  ret = extcommunity_list_unset (bgp_clist, argv[0], str, direct, style);

  /* Free temporary community list string allocated by
     argv_concat().  */
  XFREE (MTYPE_TMP, str);

  return bgp_cli_return (cli, ret);
}

/* "extcommunity-list" keyword help string.  */
#define EXTCOMMUNITY_LIST_STR "Add a extended community list entry"
#define EXTCOMMUNITY_VAL_STR  \
    "rt Route Target extended community in aa:nn or IPaddr:nn format OR\
    soo Site-of-Origin extended community in aa:nn or IPaddr:nn format"

CLI (ip_extcommunity_list_standard,
     ip_extcommunity_list_standard_cmd,
     "ip extcommunity-list <1-99> (deny|permit) LINE",
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Extended Community list number (standard)",
     "Specify community to reject",
     "Specify community to accept",
     EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_set_vty (cli, argc, argv, EXTCOMMUNITY_LIST_STANDARD, 0);
}

ALI (ip_extcommunity_list_standard,
     ip_extcommunity_list_standard2_cmd,
     "ip extcommunity-list <1-99> (deny|permit) LINE",
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Extended Community list number (standard)",
     "Specify community to reject",
     "Specify community to accept",
     EXTCOMMUNITY_VAL_STR);

CLI (ip_extcommunity_list_expanded,
     ip_extcommunity_list_expanded_cmd,
     "ip extcommunity-list <100-199> (deny|permit) LINE",
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Extended Community list number (expanded)",
     "Specify community to reject",
     "Specify community to accept",
     "An ordered list as a regular-expression")
{
  return extcommunity_list_set_vty (cli, argc, argv, EXTCOMMUNITY_LIST_EXPANDED, 0);
}

CLI (ip_extcommunity_list_name_standard,
     ip_extcommunity_list_name_standard_cmd,
     "ip extcommunity-list standard WORD (deny|permit) LINE",
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Specify standard extcommunity-list",
     "Extended Community list name",
     "Specify community to reject",
     "Specify community to accept",
     EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_set_vty (cli, argc, argv, EXTCOMMUNITY_LIST_STANDARD, 1);
}

ALI (ip_extcommunity_list_name_standard,
     ip_extcommunity_list_name_standard2_cmd,
     "ip extcommunity-list standard WORD (deny|permit) LINE",
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Specify standard extcommunity-list",
     "Extended Community list name",
     "Specify community to reject",
     "Specify community to accept",
     EXTCOMMUNITY_VAL_STR);

CLI (ip_extcommunity_list_name_expanded,
     ip_extcommunity_list_name_expanded_cmd,
     "ip extcommunity-list expanded WORD (deny|permit) LINE",
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Specify expanded extcommunity-list",
     "Extended Community list name",
     "Specify community to reject",
     "Specify community to accept",
     "An ordered list as a regular-expression")
{
  return extcommunity_list_set_vty (cli, argc, argv, EXTCOMMUNITY_LIST_EXPANDED, 1);
}

CLI (no_ip_extcommunity_list_all,
     no_ip_extcommunity_list_all_cmd,
     "no ip extcommunity-list (<1-99>|<100-199>)",
     CLI_NO_STR,
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Extended Community list number (standard)",
     "Extended Community list number (expanded)")
{
  return extcommunity_list_unset_all_vty (cli, argv[0]);
}

CLI (no_ip_extcommunity_list_name_all_s,
     no_ip_extcommunity_list_name_all_s_cmd,
     "no ip extcommunity-list standard WORD",
     CLI_NO_STR,
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Specify standard extcommunity-list",
     "Extended Community list name")
{
  return extcommunity_list_unset_all_vty (cli, argv[0]);
}

CLI (no_ip_extcommunity_list_name_all_e,
     no_ip_extcommunity_list_name_all_e_cmd,
     "no ip extcommunity-list expanded WORD",
     CLI_NO_STR,
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Specify expanded extcommunity-list",
     "Extended Community list name")
{
  return extcommunity_list_unset_all_vty (cli, argv[0]);
}

CLI (no_ip_extcommunity_list_standard,
     no_ip_extcommunity_list_standard_cmd,
     "no ip extcommunity-list <1-99> (deny|permit) LINE",
     CLI_NO_STR,
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Extended Community list number (standard)",
     "Specify community to reject",
     "Specify community to accept",
     EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_unset_vty (cli, argc, argv, EXTCOMMUNITY_LIST_STANDARD);
}

CLI (no_ip_extcommunity_list_expanded,
     no_ip_extcommunity_list_expanded_cmd,
     "no ip extcommunity-list <100-199> (deny|permit) LINE",
     CLI_NO_STR,
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Extended Community list number (expanded)",
     "Specify community to reject",
     "Specify community to accept",
     "An ordered list as a regular-expression")
{
  return extcommunity_list_unset_vty (cli, argc, argv, EXTCOMMUNITY_LIST_EXPANDED);
}

CLI (no_ip_extcommunity_list_name_standard,
     no_ip_extcommunity_list_name_standard_cmd,
     "no ip extcommunity-list standard WORD (deny|permit) LINE",
     CLI_NO_STR,
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Specify standard extcommunity-list",
     "Extended Community list name",
     "Specify community to reject",
     "Specify community to accept",
     EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_unset_vty (cli, argc, argv, EXTCOMMUNITY_LIST_STANDARD);
}

CLI (no_ip_extcommunity_list_name_expanded,
     no_ip_extcommunity_list_name_expanded_cmd,
     "no ip extcommunity-list expanded WORD (deny|permit) LINE",
     CLI_NO_STR,
     CLI_IP_STR,
     EXTCOMMUNITY_LIST_STR,
     "Specify expanded extcommunity-list",
     "Community list name",
     "Specify community to reject",
     "Specify community to accept",
     "An ordered list as a regular-expression")
{
  return extcommunity_list_unset_vty (cli, argc, argv, EXTCOMMUNITY_LIST_EXPANDED);
}

void
extcommunity_list_show (struct cli *cli, struct community_list *list)
{
  struct community_entry *entry;

  for (entry = list->head; entry; entry = entry->next)
    {
      if (entry == list->head)
        {
          if (all_digit (list->name))
            cli_out (cli, "Extended community %s list %s\n",
                     entry->style == EXTCOMMUNITY_LIST_STANDARD ?
                     "standard" : "(expanded) access",
                     list->name);
          else
            cli_out (cli, "Named extended community %s list %s\n",
                     entry->style == EXTCOMMUNITY_LIST_STANDARD ?
                     "standard" : "expanded",
                     list->name);
        }
      if (entry->any)
        cli_out (cli, "    %s\n",
                 community_direct_str (entry->direct));
      else
        cli_out (cli, "    %s %s\n",
                 community_direct_str (entry->direct),
                 entry->style == EXTCOMMUNITY_LIST_STANDARD ?
                 entry->u.ecom->str : entry->config);
    }
}

CLI (show_ip_extcommunity_list,
     show_ip_extcommunity_list_cmd,
     "show ip extcommunity-list",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "List extended-community list")
{
  struct community_list *list;
  struct community_list_master *cm;

  cm = community_list_master_lookup (bgp_clist, EXTCOMMUNITY_LIST_AUTO);
  if (! cm)
    return CLI_SUCCESS;

  for (list = cm->num.head; list; list = list->next)
    extcommunity_list_show (cli, list);

  for (list = cm->str.head; list; list = list->next)
    extcommunity_list_show (cli, list);

  return CLI_SUCCESS;
}

CLI (show_ip_extcommunity_list_arg,
     show_ip_extcommunity_list_arg_cmd,
     "show ip extcommunity-list (<1-199>|WORD)",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "List extended-community list",
     "Extcommunity-list number",
     "Extcommunity-list name")
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, argv[0], EXTCOMMUNITY_LIST_AUTO);
  if (! list)
    {
      cli_out (cli, "%% Can't find extcommunity-list\n");
      return CLI_ERROR;
    }

  extcommunity_list_show (cli, list);

  return CLI_SUCCESS;
}

/* Return configuration string of community-list entry.  */
static char *
community_list_config_str (struct community_entry *entry)
{
  char *str;

  if (entry->any)
    str = "";
  else
    {
      if (entry->style == COMMUNITY_LIST_STANDARD)
        str = community_str (entry->u.com);
      else
        str = entry->config;
    }
  return str;
}

/* Display community-list and extcommunity-list configuration.  */
int
community_list_config_write (struct cli *cli)
{
  struct community_list *list;
  struct community_entry *entry;
  struct community_list_master *cm;
  int write = 0;

  /* Community-list.  */
  cm = community_list_master_lookup (bgp_clist, COMMUNITY_LIST_AUTO);
  if (!cm)
    return 0;

  for (list = cm->num.head; list; list = list->next)
    for (entry = list->head; entry; entry = entry->next)
      {
        if (pal_strtos32 (list->name, (char **)NULL, 10) < 200)
          cli_out (cli, "ip community-list %s %s %s\n",
                   list->name, community_direct_str (entry->direct),
                   community_list_config_str (entry));
        else
          cli_out (cli, "ip community-list %s %s %s %s\n",
                   entry->style == COMMUNITY_LIST_STANDARD
                   ? "standard" : "expanded",
                   list->name, community_direct_str (entry->direct),
                   community_list_config_str (entry));
        write++;
      }
  for (list = cm->str.head; list; list = list->next)
    for (entry = list->head; entry; entry = entry->next)
      {
        cli_out (cli, "ip community-list %s %s %s %s\n",
                 entry->style == COMMUNITY_LIST_STANDARD
                 ? "standard" : "expanded",
                 list->name, community_direct_str (entry->direct),
                 community_list_config_str (entry));
        write++;
      }

  /* Extcommunity-list.  */
  cm = community_list_master_lookup (bgp_clist, EXTCOMMUNITY_LIST_AUTO);
  if (!cm)
    return 0;

  for (list = cm->num.head; list; list = list->next)
    for (entry = list->head; entry; entry = entry->next)
      {
        if (pal_strtos32 (list->name, (char **)NULL, 10) < 200)
          cli_out (cli, "ip extcommunity-list %s %s %s\n",
                   list->name, community_direct_str (entry->direct),
                   community_list_config_str (entry));
        else
          cli_out (cli, "ip extcommunity-list %s %s %s %s\n",
                   entry->style == EXTCOMMUNITY_LIST_STANDARD
                   ? "standard" : "expanded",
                   list->name, community_direct_str (entry->direct),
                   community_list_config_str (entry));
        write++;
      }
  for (list = cm->str.head; list; list = list->next)
    for (entry = list->head; entry; entry = entry->next)
      {
        cli_out (cli, "ip extcommunity-list %s %s %s %s\n",
                 entry->style == EXTCOMMUNITY_LIST_STANDARD
                 ? "standard" : "expanded",
                 list->name, community_direct_str (entry->direct),
                 community_list_config_str (entry));
        write++;
      }
  return write;
}

/* Community list CLI. */
void
bgp_cli_community_list_init (struct cli_tree *ctree)
{
  /* Configuration function.  */
  cli_install_config (ctree, COMMUNITY_LIST_MODE, community_list_config_write);

  /* Community-list.  */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_community_list_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_community_list_standard_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_community_list_standard2_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_community_list_expanded_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_community_list_name_standard_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_community_list_name_standard2_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_community_list_name_expanded_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_community_list_all_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_community_list_name_all_s_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_community_list_name_all_e_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_community_list_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_community_list_standard_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_community_list_expanded_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_community_list_name_standard_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_community_list_name_expanded_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_community_list_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_community_list_arg_cmd);

  /* Extcommunity-list.  */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_extcommunity_list_standard_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_extcommunity_list_standard2_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_extcommunity_list_expanded_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_extcommunity_list_name_standard_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_extcommunity_list_name_standard2_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_extcommunity_list_name_expanded_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_extcommunity_list_all_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_extcommunity_list_name_all_s_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_extcommunity_list_name_all_e_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_extcommunity_list_standard_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_extcommunity_list_expanded_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_extcommunity_list_name_standard_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_extcommunity_list_name_expanded_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_extcommunity_list_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_extcommunity_list_arg_cmd);
}

#ifdef HAVE_SNMP_RESTART
CLI (snmp_restart_bgp,
     snmp_restart_bgp_cli,
     "snmp restart bgp",
     "snmp",
     "restart",
     "bgp")
{
  bgp_snmp_restart ();
  return CLI_SUCCESS;
}

void
bgp_cli_snmp_init (struct cli_tree *ctree)
{
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, CLI_FLAG_HIDDEN,
                   &snmp_restart_bgp_cli);
}
#endif /* HAVE_SNMP_RESTART */

/* BGP CLI initialization.  */
void
bgp_cli_init (void)
{
  /* BGP default commands */
  bgp_cli_default_init (BLG.ctree);

  /* BGP address family commands */
  bgp_cli_address_family_init (BLG.ctree);

  /* BGP router commands */
  bgp_cli_router_init (BLG.ctree);

  /* BGP neighbor commands */
  bgp_cli_neighbor_init (BLG.ctree);

  /* BGP clear commands */
  bgp_cli_clear_init (BLG.ctree);

  /* BGP distance */
  bgp_cli_distance_init (BLG.ctree);

  /* BGP dampening */
  bgp_cli_dampening_init (BLG.ctree);

  /* BGP auto-summary */
  bgp_cli_auto_summary_init (BLG.ctree);

  /* BGP network synchronization */
  bgp_cli_network_sync_init (BLG.ctree);

  /* BGP network */
  bgp_cli_network_init (BLG.ctree);

  /* BGP Community-list */
  bgp_cli_community_list_init (BLG.ctree);

  /* BGP RIB related CLI commands Initialization */
  bgp_route_cli_init (BLG.ctree);

  /* BGP Debug CLI Commands Initialization */
  bgp_debug_cli_init (BLG.ctree);

#ifdef HAVE_MULTIPATH
  bgp_ecmp_cli_init(BLG.ctree);
#endif

  /* BGP Dump CLI Commands Initialization */
#ifdef HAVE_BGP_DUMP
  bgp_dump_cli_init (BLG.ctree);
#endif /* HAVE_BGP_DUMP */

#ifdef HAVE_SNMP_RESTART
  bgp_cli_snmp_init (BLG.ctree);
#endif /* HAVE_SNMP_RESTART */

  return;
}
