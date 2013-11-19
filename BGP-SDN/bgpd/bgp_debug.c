/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/* message for BGP-4 Notify */
struct message bgp_notify_msg[] =
{
  { 0, "/Unrecognized Error Code" },
  { BGP_NOTIFY_HEADER_ERR, "Message Header Error"},
  { BGP_NOTIFY_OPEN_ERR, "OPEN Message Error"},
  { BGP_NOTIFY_UPDATE_ERR, "UPDATE Message Error"},
  { BGP_NOTIFY_HOLD_ERR, "Hold Timer Expired"},
  { BGP_NOTIFY_FSM_ERR, "Finite State Machine Error"},
  { BGP_NOTIFY_CEASE, "Cease"},
  { BGP_NOTIFY_CAPABILITY_ERR, "CAPABILITY Message Error"},
};
int bgp_notify_msg_max = BGP_NOTIFY_MAX;

struct message bgp_notify_head_msg[] =
{
  { 0, "/Unspecified Error Subcode"},
  { BGP_NOTIFY_HEADER_NOT_SYNC, "/Connection Not Synchronized."},
  { BGP_NOTIFY_HEADER_BAD_MESLEN, "/Bad Message Length."},
  { BGP_NOTIFY_HEADER_BAD_MESTYPE, "/Bad Message Type."}
};
int bgp_notify_head_msg_max = BGP_NOTIFY_HEADER_MAX;

struct message bgp_notify_open_msg[] =
{
  { 0, "/Unspecified Error Subcode" },
  { BGP_NOTIFY_OPEN_UNSUP_VERSION, "/Unsupported Version Number." },
  { BGP_NOTIFY_OPEN_BAD_PEER_AS, "/Bad Peer AS."},
  { BGP_NOTIFY_OPEN_BAD_BGP_IDENT, "/Bad BGP Identifier."},
  { BGP_NOTIFY_OPEN_UNSUP_PARAM, "/Unsupported Optional Parameter."},
  { BGP_NOTIFY_OPEN_AUTH_FAILURE, "/Authentication Failure."},
  { BGP_NOTIFY_OPEN_UNACEP_HOLDTIME, "/Unacceptable Hold Time."},
  { BGP_NOTIFY_OPEN_UNSUP_CAPBL, "/Unsupported Capability."},
};
int bgp_notify_open_msg_max = BGP_NOTIFY_OPEN_MAX;

struct message bgp_notify_update_msg[] =
{
  { 0, "/Unspecified Error Subcode"},
  { BGP_NOTIFY_UPDATE_MAL_ATTR, "/Malformed Attribute List."},
  { BGP_NOTIFY_UPDATE_UNREC_ATTR, "/Unrecognized Well-known Attribute."},
  { BGP_NOTIFY_UPDATE_MISS_ATTR, "/Missing Well-known Attribute."},
  { BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR, "/Attribute Flags Error."},
  { BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, "/Attribute Length Error."},
  { BGP_NOTIFY_UPDATE_INVAL_ORIGIN, "/Invalid ORIGIN Attribute."},
  { BGP_NOTIFY_UPDATE_AS_ROUTE_LOOP, "/AS Routing Loop."},
  { BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP, "/Invalid NEXT_HOP Attribute."},
  { BGP_NOTIFY_UPDATE_OPT_ATTR_ERR, "/Optional Attribute Error."},
  { BGP_NOTIFY_UPDATE_INVAL_NETWORK, "/Invalid Network Field."},
  { BGP_NOTIFY_UPDATE_MAL_AS_PATH, "/Malformed AS_PATH."},
  { BGP_NOTIFY_UPDATE_MAL_AS4_PATH, "/Malformed AS4_PATH."},
};
int bgp_notify_update_msg_max = BGP_NOTIFY_UPDATE_MAX;

struct message bgp_notify_cease_msg[] =
{
  { 0, "/Unspecified Error Subcode"},
  { BGP_NOTIFY_CEASE_MAX_PREFIX, "/Maximum Number of Prefixes Reached."},
  { BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN, "/Administratively Shutdown."},
  { BGP_NOTIFY_CEASE_PEER_UNCONFIG, "/Peer Unconfigured."},
  { BGP_NOTIFY_CEASE_ADMIN_RESET, "/Administratively Reset."},
  { BGP_NOTIFY_CEASE_CONNECT_REJECT, "/Connection Rejected."},
  { BGP_NOTIFY_CEASE_CONFIG_CHANGE, "/Other Configuration Change."},
};
int bgp_notify_cease_msg_max = BGP_NOTIFY_CEASE_MAX;

struct message bgp_notify_capability_msg[] =
{
  { 0, "/Unspecified Error Subcode" },
  { BGP_NOTIFY_CAPABILITY_INVALID_ACTION, "/Invalid Action Value." },
  { BGP_NOTIFY_CAPABILITY_INVALID_LENGTH, "/Invalid Capability Length."},
  { BGP_NOTIFY_CAPABILITY_MALFORMED_CODE, "/Malformed Capability Value."},
};
int bgp_notify_capability_msg_max = BGP_NOTIFY_CAPABILITY_MAX;

/* Dump attribute. */
void
bgp_dump_attr (struct bgp_peer *peer, struct attr *attr, char *buf, size_t size)
{
  if (attr == NULL)
    return;

  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP))
    zsnprintf (buf, size, "nexthop %r", &attr->nexthop);
  else
    zsnprintf (buf, size, "no nexthop");

  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGIN))
    zsnprintf (buf + pal_strlen (buf), size - pal_strlen (buf), ", origin %s",
               BGP_ORIGIN_STR (attr->origin));
  else
    zsnprintf (buf, size, "no origin");

#ifdef HAVE_IPV6
  {
    /* Add MP case. */
    if (attr->mp_nexthop_len == 16 || attr->mp_nexthop_len == 32)
      zsnprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
                    ", mp_nexthop %R", &attr->mp_nexthop_global);

    if (attr->mp_nexthop_len == 32)
      zsnprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
                 "(%R)", &attr->mp_nexthop_local);
  }
#endif /* HAVE_IPV6 */

  if (peer_sort (peer) == BGP_PEER_IBGP)
      pal_snprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
                    ", localpref %u", attr->local_pref);

  if (attr->med)
    pal_snprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
                  ", metric %u", attr->med);

  if (attr->community)
    pal_snprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
                  ", community %s", community_str (attr->community));

  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
    pal_snprintf (buf + pal_strlen (buf), size - pal_strlen (buf), ", atomic-aggregate");
#ifdef HAVE_EXT_CAP_ASN
  if ( CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      if (attr->aggregator_as4)
        zsnprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
                    ", aggregated by %u %r", attr->aggregator_as4,
                    &attr->aggregator_addr);
    }
  else
    {
#endif /* HAVE_EXT_CAP_ASN */
  /* Local Speaker is OBGP */ 
    if (attr->aggregator_as)
    zsnprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
               ", aggregated by %d %r", attr->aggregator_as,
               &attr->aggregator_addr);
#ifdef HAVE_EXT_CAP_ASN
    }
#endif /* HAVE_EXT_CAP_ASN */

  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
      zsnprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
                    ", originator %r", &attr->originator_id);

  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_CLUSTER_LIST))
    {
      int i;

      pal_snprintf (buf + pal_strlen (buf), size - pal_strlen (buf), ", clusterlist ");
      for (i = 0; i < attr->cluster->length / 4; i++)
         zsnprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
                      "%r", &attr->cluster->list[i]);
    }
#ifdef HAVE_EXT_CAP_ASN
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      if (attr->aspath4B)
      pal_snprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
                    ", path %s", as4path_print (attr->aspath4B));
    }
  else
    {
#endif /* HAVE_EXT_CAP_ASN */
  if (attr->aspath)
    pal_snprintf (buf + pal_strlen (buf), size - pal_strlen (buf),
                  ", path %s", aspath_print (attr->aspath));
#ifdef HAVE_EXT_CAP_ASN
    } 
#endif /* HAVE_EXT_CAP_ASN */ 
}

/* Logging the changes of bgp neighbor's status. */
void
bgp_log_neighbor_status_print (struct bgp_peer *peer, int status,
                               char *reason)
{
  if (! peer)
    return;

  if (bgp_config_check (peer->bgp, BGP_CFLAG_LOG_NEIGHBOR_CHANGES))
    zlog_info (&BLG,
               "%BGP-5-ADJCHANGE: neighbor %s %s %s",
               peer ? peer->host : (u_int8_t *) "?",
               status ? "Up" : "Down",
               reason ? reason : "");
}

/* Get the Notification Error Message */
void
bgp_get_notify_err_mesg (struct bgp_peer_notify_info *notify_info,
                         u_int8_t **code_str, u_int8_t **subcode_str)
{

  *code_str = LOOKUP (bgp_notify_msg, notify_info->not_err_code);

  if ((! *code_str) || (pal_strcmp (*code_str, "invalid") == 0))
    *code_str = "Unrecognized Error Code";

  switch (notify_info->not_err_code)
    {
    case BGP_NOTIFY_OPEN_ERR:
      *subcode_str = LOOKUP (bgp_notify_open_msg,
                            notify_info->not_err_sub_code);
      break;

    case BGP_NOTIFY_UPDATE_ERR:
      *subcode_str = LOOKUP (bgp_notify_update_msg,
                            notify_info->not_err_sub_code);
      break;

    case BGP_NOTIFY_HOLD_ERR:
      *subcode_str = "/Unspecified Error Subcode";
      break;

    case BGP_NOTIFY_FSM_ERR:
      *subcode_str = "/Unspecified Error Subcode";
      break;

    case BGP_NOTIFY_CEASE:
      *subcode_str = LOOKUP (bgp_notify_cease_msg,
                            notify_info->not_err_sub_code);
      break;

    case BGP_NOTIFY_CAPABILITY_ERR:
      *subcode_str = LOOKUP (bgp_notify_capability_msg,
                            notify_info->not_err_sub_code);
      break;

    default:
      if ((! *subcode_str) || (pal_strcmp(*subcode_str, "invalid") == 0))
        *subcode_str = "/Unspecified Error Subcode";
      break;
   }
}

/* Log bgp notification information */
void
bgp_log_neighbor_notify_print (struct bgp_peer *peer,
                               struct bgp_peer_notify_info *notify_info,
                               u_int8_t *direct)
{
  u_int8_t *code_str = NULL;
  u_int8_t *subcode_str = NULL;

  bgp_get_notify_err_mesg (notify_info, &code_str, &subcode_str);
  zlog_info (&BLG,
             "%BGP-3-NOTIFICATION: %s %s %d/%d (%s%s) %d data-bytes",
             direct,
             peer->host,
             notify_info->not_err_code,
             notify_info->not_err_sub_code,
             code_str,
             subcode_str,
             notify_info->not_err_dlen);

  return;
}



void
bgp_debug_all_on (struct cli *cli)
{
  if (cli->mode == CONFIG_MODE)
    {
      DEBUG_ON (normal, NORMAL);
      DEBUG_ON (events, EVENTS);
      DEBUG_ON (keepalive, KEEPALIVE);
      DEBUG_ON (update, UPDATE_OUT);
      DEBUG_ON (update, UPDATE_IN);
      DEBUG_ON (fsm, FSM);
      DEBUG_ON (filter, FILTER);
      DEBUG_ON (rfd, RFD);
    }
  else
    {
      TERM_DEBUG_ON (normal, NORMAL);
      TERM_DEBUG_ON (events, EVENTS);
      TERM_DEBUG_ON (keepalive, KEEPALIVE);
      TERM_DEBUG_ON (update, UPDATE_OUT);
      TERM_DEBUG_ON (update, UPDATE_IN);
      TERM_DEBUG_ON (fsm, FSM);
      TERM_DEBUG_ON (filter, FILTER);
      TERM_DEBUG_ON (rfd, RFD);
    }
}

void
bgp_debug_all_off (struct cli *cli)
{
  if (cli->mode == CONFIG_MODE)
    {
      DEBUG_OFF (normal, NORMAL);
      DEBUG_OFF (events, EVENTS);
      DEBUG_OFF (keepalive, KEEPALIVE);
      DEBUG_OFF (update, UPDATE_OUT);
      DEBUG_OFF (update, UPDATE_IN);
      DEBUG_OFF (fsm, FSM);
      DEBUG_OFF (filter, FILTER);
      DEBUG_OFF (rfd, RFD);
   }
 else
   {
     TERM_DEBUG_OFF (normal, NORMAL);
     TERM_DEBUG_OFF (events, EVENTS);
     TERM_DEBUG_OFF (keepalive, KEEPALIVE);
     TERM_DEBUG_OFF (update, UPDATE_OUT);
     TERM_DEBUG_OFF (update, UPDATE_IN);
     TERM_DEBUG_OFF (fsm, FSM);
     TERM_DEBUG_OFF (filter, FILTER);
     TERM_DEBUG_OFF (rfd, RFD);
   }
}

CLI (debug_bgp_fsm,
     debug_bgp_fsm_cmd,
     "debug bgp fsm",
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP Finite State Machine")
{
  if (cli->mode == CONFIG_MODE)
    DEBUG_ON (fsm, FSM);
  else
    {
      TERM_DEBUG_ON (fsm, FSM);
      cli_out (cli, "BGP fsm debugging is on\n");
    }
  return CLI_SUCCESS;
}

CLI (no_debug_bgp_fsm,
     no_debug_bgp_fsm_cmd,
     "no debug bgp fsm",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "Finite State Machine")
{
  if (cli->mode == CONFIG_MODE)
    DEBUG_OFF (fsm, FSM);
  else
    {
      TERM_DEBUG_OFF (fsm, FSM);
      cli_out (cli, "BGP fsm debugging is off\n");
    }
  return CLI_SUCCESS;
}

ALI (no_debug_bgp_fsm,
     undebug_bgp_fsm_cmd,
     "undebug bgp fsm",
     CLI_UNDEBUG_STR,
     CLI_BGP_STR,
     "Finite State Machine");

CLI (debug_bgp_events,
     debug_bgp_events_cmd,
     "debug bgp events",
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP events")
{
  if (cli->mode == CONFIG_MODE)
    DEBUG_ON (events, EVENTS);
  else
    {
      TERM_DEBUG_ON (events, EVENTS);
      cli_out (cli, "BGP events debugging is on\n");
    }
  return CLI_SUCCESS;
}

CLI (no_debug_bgp_events,
     no_debug_bgp_events_cmd,
     "no debug bgp events",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP events")
{
  if (cli->mode == CONFIG_MODE)
    DEBUG_OFF (events, EVENTS);
  else
    {
      TERM_DEBUG_OFF (events, EVENTS);
      cli_out (cli, "BGP events debugging is off\n");
    }
  return CLI_SUCCESS;
}

ALI (no_debug_bgp_events,
     undebug_bgp_events_cmd,
     "undebug bgp events",
     CLI_UNDEBUG_STR,
     CLI_BGP_STR,
     "BGP events");

CLI (debug_bgp_filter,
     debug_bgp_filter_cmd,
     "debug bgp filters",
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP filters")
{
  if (cli->mode == CONFIG_MODE)
    DEBUG_ON (filter, FILTER);
  else
    {
      TERM_DEBUG_ON (filter, FILTER);
      cli_out (cli, "BGP filters debugging is on\n");
    }
  return CLI_SUCCESS;
}

CLI (no_debug_bgp_filter,
     no_debug_bgp_filter_cmd,
     "no debug bgp filters",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP filters")
{
  if (cli->mode == CONFIG_MODE)
    DEBUG_OFF (filter, FILTER);
  else
    {
      TERM_DEBUG_OFF (filter, FILTER);
      cli_out (cli, "BGP filters debugging is off\n");
    }
  return CLI_SUCCESS;
}

ALI (no_debug_bgp_filter,
     undebug_bgp_filter_cmd,
     "undebug bgp filters",
     CLI_UNDEBUG_STR,
     CLI_BGP_STR,
     "BGP filters");

CLI (debug_bgp_keepalive,
     debug_bgp_keepalive_cmd,
     "debug bgp keepalives",
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP keepalives")
{
  if (cli->mode == CONFIG_MODE)
    DEBUG_ON (keepalive, KEEPALIVE);
  else
    {
      TERM_DEBUG_ON (keepalive, KEEPALIVE);
      cli_out (cli, "BGP keepalives debugging is on\n");
    }
  return CLI_SUCCESS;
}

CLI (no_debug_bgp_keepalive,
     no_debug_bgp_keepalive_cmd,
     "no debug bgp keepalives",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP keepalives")
{
  if (cli->mode == CONFIG_MODE)
    DEBUG_OFF (keepalive, KEEPALIVE);
  else
    {
      TERM_DEBUG_OFF (keepalive, KEEPALIVE);
      cli_out (cli, "BGP keepalives debugging is off\n");
    }
  return CLI_SUCCESS;
}

ALI (no_debug_bgp_keepalive,
     undebug_bgp_keepalive_cmd,
     "undebug bgp keepalives",
     CLI_UNDEBUG_STR,
     CLI_BGP_STR,
     "BGP keepalives");

CLI (debug_bgp_update,
     debug_bgp_update_cmd,
     "debug bgp updates",
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP updates")
{
  if (cli->mode == CONFIG_MODE)
    {
      DEBUG_ON (update, UPDATE_IN);
      DEBUG_ON (update, UPDATE_OUT);
    }
  else
    {
      TERM_DEBUG_ON (update, UPDATE_IN);
      TERM_DEBUG_ON (update, UPDATE_OUT);
      cli_out (cli, "BGP updates debugging is on\n");
    }
  return CLI_SUCCESS;
}

CLI (debug_bgp_update_direct,
     debug_bgp_update_direct_cmd,
     "debug bgp updates (in|out)",
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP updates",
     "Inbound updates",
     "Outbound updates")
{
  if (cli->mode == CONFIG_MODE)
    {
      if (pal_strncmp ("i", argv[0], 1) == 0)
        {
          DEBUG_OFF (update, UPDATE_OUT);
          DEBUG_ON (update, UPDATE_IN);
        }
      else
        {
          DEBUG_OFF (update, UPDATE_IN);
          DEBUG_ON (update, UPDATE_OUT);
        }
    }
  else
    {
      if (pal_strncmp ("i", argv[0], 1) == 0)
        {
          TERM_DEBUG_OFF (update, UPDATE_OUT);
          TERM_DEBUG_ON (update, UPDATE_IN);
          cli_out (cli, "BGP updates debugging is on (inbound)\n");
        }
      else
        {
          TERM_DEBUG_OFF (update, UPDATE_IN);
          TERM_DEBUG_ON (update, UPDATE_OUT);
          cli_out (cli, "BGP updates debugging is on (outbound)\n");
        }
    }
  return CLI_SUCCESS;
}

CLI (no_debug_bgp_update,
     no_debug_bgp_update_cmd,
     "no debug bgp updates",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP updates")
{
  if (cli->mode == CONFIG_MODE)
    {
      DEBUG_OFF (update, UPDATE_IN);
      DEBUG_OFF (update, UPDATE_OUT);
    }
  else
    {
      TERM_DEBUG_OFF (update, UPDATE_IN);
      TERM_DEBUG_OFF (update, UPDATE_OUT);
      cli_out (cli, "BGP updates debugging is off\n");
    }
  return CLI_SUCCESS;
}

ALI (no_debug_bgp_update,
     undebug_bgp_update_cmd,
     "undebug bgp updates",
     CLI_UNDEBUG_STR,
     CLI_BGP_STR,
     "BGP updates");

CLI (debug_bgp_rfd,
     debug_bgp_rfd_cmd,
     "debug bgp dampening",
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP Dampening")
{
  if (cli->mode == CONFIG_MODE)
    DEBUG_ON (rfd, RFD);
  else
    {
      TERM_DEBUG_ON (rfd, RFD);
      cli_out (cli, "BGP Route Flap Dampening debugging is on\n");
    }
  return CLI_SUCCESS;
}

CLI (no_debug_bgp_rfd,
     no_debug_bgp_rfd_cmd,
     "no debug bgp dampening",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "BGP Dampening")
{
  if (cli->mode == CONFIG_MODE)
    DEBUG_OFF (rfd, RFD);
  else
    {
      TERM_DEBUG_OFF (rfd, RFD);
      cli_out (cli, "BGP Route Flap Dampening debugging is off\n");
    }
  return CLI_SUCCESS;
}

ALI (no_debug_bgp_rfd,
     undebug_bgp_rfd_cmd,
     "undebug bgp dampening",
     CLI_UNDEBUG_STR,
     CLI_BGP_STR,
     "BGP Dampening");

CLI (debug_bgp_all,
     debug_bgp_all_cmd,
     "debug bgp (all|)",
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "all debugging")
{
  bgp_debug_all_on (cli);
  if (cli->mode != CONFIG_MODE)
    cli_out (cli, "All possible debugging options have been turned on\n");

  return CLI_SUCCESS;
}

CLI (no_debug_bgp_all,
     no_debug_bgp_all_cmd,
     "no debug bgp (all|)",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     CLI_BGP_STR,
     "all debugging")
{
  bgp_debug_all_off (cli);
  if (cli->mode != CONFIG_MODE)
    cli_out (cli, "All possible debugging options have been turned off\n");

  return CLI_SUCCESS;
}

ALI (no_debug_bgp_all,
     undebug_bgp_all_cmd,
     "undebug bgp (all|)",
     CLI_UNDEBUG_STR,
     CLI_BGP_STR,
     "all debugging");

ALI (no_debug_bgp_all,
     no_debug_all_bgp_cmd,
     "no debug all bgp",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     "all debugging",
     CLI_BGP_STR);

ALI (no_debug_bgp_all,
     undebug_all_bgp_cmd,
     "undebug all bgp",
     CLI_UNDEBUG_STR,
     "all debugging",
     CLI_BGP_STR);

CLI (no_bgp_debug_all,
     bgp_no_debug_all_cmd,
     "no debug all",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     "all debugging")
{
  bgp_debug_all_off (cli);
  return CLI_SUCCESS;
}

ALI (no_bgp_debug_all,
     bgp_undebug_all_cmd,
     "undebug all",
     CLI_UNDEBUG_STR,
     "all debugging");

/* Show debugging information.  */
CLI (show_debugging_bgp,
     show_debugging_bgp_cmd,
     "show debugging bgp",
     CLI_SHOW_STR,
     CLI_DEBUG_STR,
     CLI_BGP_STR)
{
  cli_out (cli, "BGP debugging status:\n");

  if (BGP_DEBUG (normal, NORMAL))
    cli_out (cli, "  BGP debugging is on\n");
  if (BGP_DEBUG (events, EVENTS))
    cli_out (cli, "  BGP events debugging is on\n");
  if (BGP_DEBUG (keepalive, KEEPALIVE))
    cli_out (cli, "  BGP keepalives debugging is on\n");
  if (BGP_DEBUG (update, UPDATE_IN) && BGP_DEBUG (update, UPDATE_OUT))
    cli_out (cli, "  BGP updates debugging is on\n");
  else if (BGP_DEBUG (update, UPDATE_IN))
    cli_out (cli, "  BGP updates debugging is on (inbound)\n");
  else if (BGP_DEBUG (update, UPDATE_OUT))
    cli_out (cli, "  BGP updates debugging is on (outbound)\n");
  if (BGP_DEBUG (fsm, FSM))
    cli_out (cli, "  BGP fsm debugging is on\n");
  if (BGP_DEBUG (filter, FILTER))
    cli_out (cli, "  BGP filter debugging is on\n");
  if (BGP_DEBUG (rfd, RFD))
    cli_out (cli, "  BGP Route Flap Dampening debugging is on\n");
  cli_out (cli, "\n");
  return CLI_SUCCESS;
}

int
bgp_config_write_debug (struct cli *cli)
{
  int write = 0;

  if (CONF_BGP_DEBUG (normal, NORMAL))
    {
      cli_out (cli, "debug bgp\n");
      write++;
    }

  if (CONF_BGP_DEBUG (events, EVENTS))
    {
      cli_out (cli, "debug bgp events\n");
      write++;
    }

  if (CONF_BGP_DEBUG (keepalive, KEEPALIVE))
    {
      cli_out (cli, "debug bgp keepalives\n");
      write++;
    }

  if (CONF_BGP_DEBUG (update, UPDATE_IN) && CONF_BGP_DEBUG (update, UPDATE_OUT))
    {
      cli_out (cli, "debug bgp updates\n");
      write++;
    }
  else if (CONF_BGP_DEBUG (update, UPDATE_IN))
    {
      cli_out (cli, "debug bgp updates in\n");
      write++;
    }
  else if (CONF_BGP_DEBUG (update, UPDATE_OUT))
    {
      cli_out (cli, "debug bgp updates out\n");
      write++;
    }

  if (CONF_BGP_DEBUG (fsm, FSM))
    {
      cli_out (cli, "debug bgp fsm\n");
      write++;
    }

  if (CONF_BGP_DEBUG (filter, FILTER))
    {
      cli_out (cli, "debug bgp filters\n");
      write++;
    }

  if (CONF_BGP_DEBUG (rfd, RFD))
    {
      cli_out (cli, "debug bgp dampening\n");
      write++;
    }

  return write;
}

/* BGP Debug CLI Commands Initialization */
void
bgp_debug_cli_init (struct cli_tree *ctree)
{
  cli_install_config (ctree, DEBUG_MODE, bgp_config_write_debug);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_debugging_bgp_cmd);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_fsm_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_fsm_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_events_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_events_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_filter_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_keepalive_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_keepalive_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_update_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_update_direct_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_update_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_update_direct_cmd);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_fsm_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &undebug_bgp_fsm_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_fsm_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_events_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &undebug_bgp_events_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_events_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &undebug_bgp_filter_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_filter_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_keepalive_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &undebug_bgp_keepalive_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_keepalive_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_update_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &undebug_bgp_update_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_update_cmd);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_rfd_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_rfd_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_rfd_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &undebug_bgp_rfd_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_rfd_cmd);

  /* "debug bgp all" commands. */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_all_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &debug_bgp_all_cmd);

  /* "no debug bgp all" commands. */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_all_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &undebug_bgp_all_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_all_bgp_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &undebug_all_bgp_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_bgp_all_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_debug_all_bgp_cmd);

  /* "no debug all" commands. */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_no_debug_all_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_undebug_all_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &bgp_no_debug_all_cmd);

  return;
}
