/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

#ifdef HAVE_SNMP

/* Declare static local variables for convenience. */
static s_int32_t bgp_int_val;
static struct pal_in4_addr bgp_in_addr_val;

/* BGP-MIB instances. */
oid bgp_oid [] = { BGP4MIB };
oid bgpd_oid [] = { BGPDMIB };
oid bgp_snmp_notify_oid [] = { BGP4MIB, 0 };

/* Hook functions. */
static u_char *bgpVersion ();
static u_char *bgpLocalAs ();
static u_char *bgpPeerTable ();
static u_char *bgpRcvdPathAttrTable ();
static u_char *bgpIdentifier ();
static u_char *bgp4PathAttrTable ();

struct variable bgp_variables[] =
{
  /* BGP version. */
  {BGPVERSION,                OCTET_STRING, RONLY, bgpVersion,
   1, {1}},
  /* BGP local AS. */
  {BGPLOCALAS,                INTEGER32, RONLY, bgpLocalAs,
   1, {2}},
  /* BGP peer table. */
  {BGPPEERIDENTIFIER,         IPADDRESS, RONLY, bgpPeerTable,
   3, {3, 1, 1}},
  {BGPPEERSTATE,              INTEGER, RONLY, bgpPeerTable,
   3, {3, 1, 2}},
  {BGPPEERADMINSTATUS,        INTEGER, RWRITE, bgpPeerTable,
   3, {3, 1, 3}},
  {BGPPEERNEGOTIATEDVERSION,  INTEGER32, RONLY, bgpPeerTable,
   3, {3, 1, 4}},
  {BGPPEERLOCALADDR,          IPADDRESS, RONLY, bgpPeerTable,
   3, {3, 1, 5}},
  {BGPPEERLOCALPORT,          INTEGER32, RONLY, bgpPeerTable,
   3, {3, 1, 6}},
  {BGPPEERREMOTEADDR,         IPADDRESS, RONLY, bgpPeerTable,
   3, {3, 1, 7}},
  {BGPPEERREMOTEPORT,         INTEGER32, RONLY, bgpPeerTable,
   3, {3, 1, 8}},
  {BGPPEERREMOTEAS,           INTEGER32, RONLY, bgpPeerTable,
   3, {3, 1, 9}},
  {BGPPEERINUPDATES,          COUNTER32, RONLY, bgpPeerTable,
   3, {3, 1, 10}},
  {BGPPEEROUTUPDATES,         COUNTER32, RONLY, bgpPeerTable,
   3, {3, 1, 11}},
  {BGPPEERINTOTALMESSAGES,    COUNTER32, RONLY, bgpPeerTable,
   3, {3, 1, 12}},
  {BGPPEEROUTTOTALMESSAGES,   COUNTER32, RONLY, bgpPeerTable,
   3, {3, 1, 13}},
  {BGPPEERLASTERROR,          OCTET_STRING, RONLY, bgpPeerTable,
   3, {3, 1, 14}},
  {BGPPEERFSMESTABLISHEDTRANSITIONS, COUNTER32, RONLY, bgpPeerTable,
   3, {3, 1, 15}},
  {BGPPEERFSMESTABLISHEDTIME, GAUGE32, RONLY, bgpPeerTable,
   3, {3, 1, 16}},
  {BGPPEERCONNECTRETRYINTERVAL, INTEGER32, RWRITE, bgpPeerTable,
   3, {3, 1, 17}},
  {BGPPEERHOLDTIME,           INTEGER32, RONLY, bgpPeerTable,
   3, {3, 1, 18}},
  {BGPPEERKEEPALIVE,          INTEGER32, RONLY, bgpPeerTable,
   3, {3, 1, 19}},
  {BGPPEERHOLDTIMECONFIGURED, INTEGER32, RWRITE, bgpPeerTable,
   3, {3, 1, 20}},
  {BGPPEERKEEPALIVECONFIGURED, INTEGER32, RWRITE, bgpPeerTable,
   3, {3, 1, 21}},
  {BGPPEERMINASORIGINATIONINTERVAL, INTEGER32, RWRITE, bgpPeerTable,
   3, {3, 1, 22}},
  {BGPPEERMINROUTEADVERTISEMENTINTERVAL, INTEGER32, RWRITE, bgpPeerTable,
   3, {3, 1, 23}},
  {BGPPEERINUPDATEELAPSEDTIME, GAUGE32, RONLY, bgpPeerTable,
   3, {3, 1, 24}},
  /* BGP identifier. */
  {BGPIDENTIFIER,             IPADDRESS, RONLY, bgpIdentifier,
   1, {4}},
  /* BGP received path attribute table. */
  {BGPPATHATTRPEER,           IPADDRESS, RONLY, bgpRcvdPathAttrTable,
   3, {5, 1, 1}},
  {BGPPATHATTRDESTNETWORK,    IPADDRESS, RONLY, bgpRcvdPathAttrTable,
   3, {5, 1, 2}},
  {BGPPATHATTRORIGIN,         INTEGER, RONLY, bgpRcvdPathAttrTable,
   3, {5, 1, 3}},
  {BGPPATHATTRASPATH,         OCTET_STRING, RONLY, bgpRcvdPathAttrTable,
   3, {5, 1, 4}},
  {BGPPATHATTRNEXTHOP,        IPADDRESS, RONLY, bgpRcvdPathAttrTable,
   3, {5, 1, 5}},
  {BGPPATHATTRINTERASMETRIC,  INTEGER32, RONLY, bgpRcvdPathAttrTable,
   3, {5, 1, 6}},
  /* BGP-4 received path attribute table. */
  {BGP4PATHATTRPEER, IPADDRESS, RONLY, bgp4PathAttrTable,
   3, {6, 1, 1}},
  {BGP4PATHATTRIPADDRPREFIXLEN, INTEGER32, RONLY, bgp4PathAttrTable,
   3, {6, 1, 2}},
  {BGP4PATHATTRIPADDRPREFIX,  IPADDRESS, RONLY, bgp4PathAttrTable,
   3, {6, 1, 3}},
  {BGP4PATHATTRORIGIN,        INTEGER32, RONLY, bgp4PathAttrTable,
   3, {6, 1, 4}},
  {BGP4PATHATTRASPATHSEGMENT, OCTET_STRING, RONLY, bgp4PathAttrTable,
   3, {6, 1, 5}},
  {BGP4PATHATTRNEXTHOP,       IPADDRESS, RONLY, bgp4PathAttrTable,
   3, {6, 1, 6}},
  {BGP4PATHATTRMULTIEXITDISC, INTEGER32, RONLY, bgp4PathAttrTable,
   3, {6, 1, 7}},
  {BGP4PATHATTRLOCALPREF,     INTEGER32, RONLY, bgp4PathAttrTable,
   3, {6, 1, 8}},
  {BGP4PATHATTRATOMICAGGREGATE, INTEGER, RONLY, bgp4PathAttrTable,
   3, {6, 1, 9}},
  {BGP4PATHATTRAGGREGATORAS,  INTEGER32, RONLY, bgp4PathAttrTable,
   3, {6, 1, 10}},
  {BGP4PATHATTRAGGREGATORADDR, IPADDRESS, RONLY, bgp4PathAttrTable,
   3, {6, 1, 11}},
  {BGP4PATHATTRCALCLOCALPREF, INTEGER32, RONLY, bgp4PathAttrTable,
   3, {6, 1, 12}},
  {BGP4PATHATTRBEST,          INTEGER, RONLY, bgp4PathAttrTable,
   3, {6, 1, 13}},
  {BGP4PATHATTRUNKNOWN,       OCTET_STRING, RONLY, bgp4PathAttrTable,
   3, {6, 1, 14}},
};

/* BGP SMUX SNMP Notification function */
void
bgp_snmp_smux_notification (oid *notify_oid, size_t notify_oid_len,
                    oid spec_notify_val, u_int32_t uptime,
                    struct snmp_trap_object *obj, size_t obj_len)
{
  snmp_trap2 (&BLG, notify_oid, notify_oid_len, spec_notify_val,
                  bgp_oid, sizeof (bgp_oid) / sizeof (oid),
                  (struct trap_object2 *) obj, obj_len, uptime);
}


/* Entry function for bgpVersion object.  */
static u_char *
bgpVersion (struct variable *v, oid *name, size_t *length, int exact,
            size_t *var_len, WriteMethod **write_method,
            u_int32_t vr_id)
{
  static u_char version;
  int proc_id = BGP_PROCESS_ID_ANY;

  if (snmp_header_generic(v, name, length, exact, var_len, write_method)
      == MATCH_FAILED)
    return NULL;

  if (BGP_SNMP_GET (version, &version, vr_id))
    {
      *var_len = 1;
      BGP_SNMP_RETURN_OCTETSTRING (&version);
    }
  return NULL;
}

/* Entry function for bgpLocalAs object.  */
static u_char *
bgpLocalAs (struct variable *v, oid *name, size_t *length, int exact,
            size_t *var_len, WriteMethod **write_method,
            u_int32_t vr_id)
{
  int as;
  int proc_id = BGP_PROCESS_ID_ANY;

  if (snmp_header_generic(v, name, length, exact, var_len, write_method)
      == MATCH_FAILED)
    return NULL;

  if (BGP_SNMP_GET (local_as, &as, vr_id))
    BGP_SNMP_RETURN_INTEGER (as);

  return NULL;
}

/* Utility function to get bgpPeerRemoteAddr index.  */
int
bgp_snmp_index_get (struct variable *v, oid *name,
                    size_t *length, struct pal_in4_addr *addr,
                    int exact)
{
  int len;

  pal_mem_set (addr, 0, IN_ADDR_SIZE);

  if (exact)
    {
      /* Index length must be IPv4 addr length.  */
      if (*length - v->namelen != IN_ADDR_SIZE)
        return -1;

      oid2in_addr (name + v->namelen, IN_ADDR_SIZE, addr);
      return 0;
    }
  else
    {
      len = *length - v->namelen;
      if (len > IN_ADDR_SIZE)
        len = IN_ADDR_SIZE;

      oid2in_addr (name + v->namelen, len, addr);
      return 0;
    }
}

/* Utility function to set bgpPeerRemoteAddr index.  */
void
bgp_snmp_index_set (struct variable *v, oid *name,
                    size_t *length, struct pal_in4_addr *addr)
{
  oid_copy_addr (name + v->namelen, addr, IN_ADDR_SIZE);
  *length = IN_ADDR_SIZE + v->namelen;
}

/* Write method for bgpPeerTable.  */
int
write_bgpPeerTable (int action, u_char *var_val,
                    u_char var_val_type, size_t var_val_len,
                    u_char *statP, oid *name, size_t length,
                    struct variable *v,
                    u_int32_t vr_id)
{
  struct pal_in4_addr addr;
  s_int32_t intval;
  int  ret;
  int proc_id = BGP_PROCESS_ID_ANY;

  if (var_val_type != ASN_INTEGER)
    return SNMP_ERR_WRONGTYPE;

  if (var_val_len != sizeof (s_int32_t))
    return SNMP_ERR_WRONGLENGTH;

  pal_mem_cpy(&intval,var_val,4);

  ret = bgp_snmp_index_get (v, name, &length, &addr, 1);
  if (ret < 0)
    return SNMP_ERR_NOSUCHNAME;

  switch (v->magic)
    {
    case BGPPEERADMINSTATUS:
      if (bgp_set_peer_admin_status (vr_id, proc_id, &addr, intval)
          != BGP_API_SET_SUCCESS)
        return SNMP_ERR_GENERR;
      break;
    case BGPPEERCONNECTRETRYINTERVAL:
      if (intval < BGPPEERCONNECTRETRYMIN || intval > BGPPEERCONNECTRETRYMAX)
        return SNMP_ERR_BADVALUE;
      if (bgp_set_peer_connect_retry_interval (vr_id, proc_id, &addr, intval)
          != BGP_API_SET_SUCCESS)
        return SNMP_ERR_GENERR;
      break;
    case BGPPEERHOLDTIMECONFIGURED:
      if (intval != BGPZEROTIMER)
        if (intval < BGPHOLDTIMEMIN || intval > BGPHOLDTIMEMAX) 
          return SNMP_ERR_BADVALUE;
      if (bgp_set_peer_hold_time_configured (vr_id, proc_id, &addr, intval)
          != BGP_API_SET_SUCCESS)
        return SNMP_ERR_GENERR;
      break;
    case BGPPEERKEEPALIVECONFIGURED:
      if (intval < BGPZEROTIMER || intval > BGPKEEPALIVEMAX)
        return SNMP_ERR_BADVALUE;
      if (bgp_set_peer_keep_alive_configured (vr_id, proc_id, &addr, intval)
          != BGP_API_SET_SUCCESS)
        return SNMP_ERR_GENERR;
      break;
    case BGPPEERMINASORIGINATIONINTERVAL:
      if (intval < BGPPEERMINASORIGINATEMIN
          || intval > BGPPEERMINASORIGINATEMAX)
        return SNMP_ERR_BADVALUE;
      if (bgp_set_peer_min_as_origination_interval (vr_id, proc_id, &addr,
                                                    intval)
          != BGP_API_SET_SUCCESS)
        return SNMP_ERR_GENERR;
      break;
    case BGPPEERMINROUTEADVERTISEMENTINTERVAL:
      if (intval < BGPMINROUTEADVMIN || intval > BGPMINROUTEADVMAX)
        return SNMP_ERR_BADVALUE;
      if (bgp_set_peer_min_route_advertisement_interval (vr_id, proc_id, &addr,
                                                         intval)
          != BGP_API_SET_SUCCESS)
        return SNMP_ERR_GENERR;
      break;
    default:
      break;
    }
  return SNMP_ERR_NOERROR;
}

/* Entry function for bgpPeerTable object.  */
u_char *
bgpPeerTable (struct variable *v, oid *name, size_t *length, int exact,
              size_t *var_len, WriteMethod **write_method,
              u_int32_t vr_id)
{
  int ret;
  int proc_id = BGP_PROCESS_ID_ANY;
  static struct pal_in4_addr addr;
  static struct pal_in4_addr outaddr;
  static u_char lasterror[2];
  int time;
  int output;

  pal_mem_set (lasterror,0,sizeof (lasterror));
  *write_method = NULL;

  ret = bgp_snmp_index_get (v, name, length, &addr, exact);
  if (ret < 0)
    return NULL;

  switch (v->magic)
    {
    case BGPPEERIDENTIFIER:
      if (BGP_SNMP_GET_NEXT (peer_identifier, &addr, &outaddr, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_IPADDRESS (outaddr);
        }
      break;
    case BGPPEERSTATE:
      if (BGP_SNMP_GET_NEXT (peer_state, &addr, &output, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEERADMINSTATUS:
      *write_method = write_bgpPeerTable;
      if (BGP_SNMP_GET_NEXT (peer_admin_status, &addr, &output, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEERNEGOTIATEDVERSION:
      if (BGP_SNMP_GET_NEXT (peer_negotiated_version, &addr, &output, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEERLOCALADDR:
      if (BGP_SNMP_GET_NEXT (peer_local_addr, &addr, &outaddr, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_IPADDRESS (outaddr);
        }
      break;
    case BGPPEERLOCALPORT:
      if (BGP_SNMP_GET_NEXT (peer_local_port, &addr, &output, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEERREMOTEADDR:
      if (BGP_SNMP_GET_NEXT (peer_remote_addr, &addr, &outaddr, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_IPADDRESS (outaddr);
        }
      break;
    case BGPPEERREMOTEPORT:
      if (BGP_SNMP_GET_NEXT (peer_remote_port, &addr, &output, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEERREMOTEAS:
      if (BGP_SNMP_GET_NEXT (peer_remote_as, &addr, &output, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEERINUPDATES:
      if (BGP_SNMP_GET_NEXT (peer_in_updates, &addr, &output, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEEROUTUPDATES:
      if (BGP_SNMP_GET_NEXT (peer_out_updates, &addr, &output, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEERINTOTALMESSAGES:
      if (BGP_SNMP_GET_NEXT (peer_in_total_messages, &addr, &output, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEEROUTTOTALMESSAGES:
      if (BGP_SNMP_GET_NEXT (peer_out_total_messages, &addr, &output, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEERLASTERROR:
      if (BGP_SNMP_GET_NEXT (peer_last_error, &addr, lasterror, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          *var_len = 2;
          BGP_SNMP_RETURN_OCTETSTRING (lasterror);
        }
      break;
    case BGPPEERFSMESTABLISHEDTRANSITIONS:
      if (BGP_SNMP_GET_NEXT (peer_fsm_established_transitions, &addr, &output,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (output);
        }
      break;
    case BGPPEERFSMESTABLISHEDTIME:
      if (BGP_SNMP_GET_NEXT (peer_fsm_established_time, &addr, &time, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (time);
        }
      break;
    case BGPPEERCONNECTRETRYINTERVAL:
      *write_method = write_bgpPeerTable;
      if (BGP_SNMP_GET_NEXT (peer_connect_retry_interval, &addr, &time, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (time);
        }
      break;
    case BGPPEERHOLDTIME:
      if (BGP_SNMP_GET_NEXT (peer_hold_time, &addr, &time, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (time);
        }
      break;
    case BGPPEERKEEPALIVE:
      if (BGP_SNMP_GET_NEXT (peer_keep_alive, &addr, &time, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (time);
        }
      break;
    case BGPPEERHOLDTIMECONFIGURED:
      *write_method = write_bgpPeerTable;
      if (BGP_SNMP_GET_NEXT (peer_hold_time_configured, &addr, &time, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (time);
        }
      break;
    case BGPPEERKEEPALIVECONFIGURED:
      *write_method = write_bgpPeerTable;
      if (BGP_SNMP_GET_NEXT (peer_keep_alive_configured, &addr, &time, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (time);
        }
      break;
    case BGPPEERMINASORIGINATIONINTERVAL:
      *write_method = write_bgpPeerTable;
      if (BGP_SNMP_GET_NEXT (peer_min_as_origination_interval, &addr, &time,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (time);
        }
      break;
    case BGPPEERMINROUTEADVERTISEMENTINTERVAL:
      *write_method = write_bgpPeerTable;
      if (BGP_SNMP_GET_NEXT (peer_min_route_advertisement_interval, &addr,
                             &time, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (time);
        }
      break;
    case BGPPEERINUPDATEELAPSEDTIME:
      if (BGP_SNMP_GET_NEXT (peer_in_update_elapsed_time, &addr, &time, vr_id))
        {
          if (! exact)
            bgp_snmp_index_set (v, name, length, &addr);
          BGP_SNMP_RETURN_INTEGER (time);
        }
      break;
    default:
      return NULL;
    }
  return NULL;
}

/* Entry function for bgpIdentifier object.  */
u_char *
bgpIdentifier (struct variable *v, oid *name, size_t *length,
               int exact, size_t *var_len, WriteMethod **write_method,
               u_int32_t vr_id)
{
  struct pal_in4_addr addr;
  int proc_id = BGP_PROCESS_ID_ANY;

  if (snmp_header_generic(v, name, length, exact, var_len, write_method)
      == MATCH_FAILED)
    return NULL;

  if (BGP_SNMP_GET (identifier, &addr, vr_id))
    BGP_SNMP_RETURN_IPADDRESS (addr);

  return  NULL;
}

/* Entry function for obsolete bgpRcvdPathAttrTable object.  */
u_char *
bgpRcvdPathAttrTable (struct variable *v, oid *name, size_t *length,
                      int exact, size_t *var_len, WriteMethod **write_method,
                      u_int32_t vr_id)
{
  /* Received Path Attribute Table.  This table contains, one entry
     per path to a network, path attributes received from all peers
     running BGP version 3 or less.  This table is obsolete, having
     been replaced in functionality with the bgp4PathAttrTable.  */
  return NULL;
}

int
bgp_snmp_path_index_get (struct variable *v, oid *name, size_t *length,
                         struct prefix_ipv4 *addr, union sockunion *su,
                         int exact)
{
  oid *offset;
  int offsetlen;
  int len;
  struct bgp *bgp = NULL;

#define BGP_PATHATTR_ENTRY_OFFSET \
          (IN_ADDR_SIZE + 1 + IN_ADDR_SIZE)

  bgp = bgp_lookup_default ();
  if (! bgp)
    return -1;

  su->sin.sin_family = AF_INET;

  if (exact)
    {
      if (*length - v->namelen != BGP_PATHATTR_ENTRY_OFFSET)
        return -1;

      /* Set OID offset for prefix. */
      offset = name + v->namelen;
      oid2in_addr (offset, IN_ADDR_SIZE, &addr->prefix);
      offset += IN_ADDR_SIZE;

      /* Prefix length. */
      addr->prefixlen = *offset;
      offset++;

      /* Peer address. */
      su->sin.sin_family = AF_INET;
      oid2in_addr (offset, IN_ADDR_SIZE, &su->sin.sin_addr);
    }
  else
    {
      offset = name + v->namelen;
      offsetlen = *length - v->namelen;
      len = offsetlen;

      if (offsetlen != 0)
        {
          if (len > IN_ADDR_SIZE)
            len = IN_ADDR_SIZE;

          oid2in_addr (offset, len, &addr->prefix);

          offset += IN_ADDR_SIZE;
          offsetlen -= IN_ADDR_SIZE;

          if (offsetlen > 0)
            addr->prefixlen = *offset;
          else
            addr->prefixlen = len * 8;

          offset++;
          offsetlen--;
        }

      if (offsetlen > 0)
        {
          len = offsetlen;
          if (len > IN_ADDR_SIZE)
            len = IN_ADDR_SIZE;

          oid2in_addr (offset, IN_ADDR_SIZE, &su->sin.sin_addr);
        }
    }
  return 0;
}

void
bgp_snmp_path_index_set (struct variable *v, oid *name, size_t *length,
                         struct prefix_ipv4 *addr, union sockunion *su)
{
  oid_copy_addr (name + v->namelen, &addr->prefix, IN_ADDR_SIZE);
  name[v->namelen + IN_ADDR_SIZE] = addr->prefixlen;
  oid_copy_addr (name + v->namelen + IN_ADDR_SIZE + 1, &su->sin.sin_addr,
                 IN_ADDR_SIZE);
  *length = v->namelen + BGP_PATHATTR_ENTRY_OFFSET;
}

/* Entry function for bgp4PathAttrTable object.  */
u_char *
bgp4PathAttrTable (struct variable *v, oid *name, size_t *length,
                   int exact, size_t *var_len, WriteMethod **write_method,
                   u_int32_t vr_id)
{
  int ret = 0;
  struct prefix_ipv4 addr;
  struct pal_in4_addr outaddr;
  static u_char *pnt;
  int  out;
  int offsetlen;
  int proc_id = BGP_PROCESS_ID_ANY;
  union sockunion su;

  pal_mem_set (&addr, 0, sizeof (struct prefix_ipv4));
  pal_mem_set (&su, 0, sizeof (union sockunion));

  ret = bgp_snmp_path_index_get (v, name, length, &addr, &su, exact);
  if (ret < 0)
    return NULL;

  offsetlen = *length - v->namelen;

  switch (v->magic)
    {
    case BGP4PATHATTRPEER:        /* 1 */
      if (BGP_SNMP_GET2NEXT (path_attr_peer, &addr, &su, offsetlen, &outaddr,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_IPADDRESS (outaddr);
        }
      break;
    case BGP4PATHATTRIPADDRPREFIXLEN: /* 2 */
      if (BGP_SNMP_GET2NEXT (path_attr_ip_addr_prefix_len,
                             &addr, &su, offsetlen, &out,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_INTEGER (out);
        }
      break;
    case BGP4PATHATTRIPADDRPREFIX: /* 3 */
      if (BGP_SNMP_GET2NEXT (path_attr_ip_addr_prefix,
                             &addr, &su, offsetlen, &outaddr,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_IPADDRESS (outaddr);
        }
      break;
    case BGP4PATHATTRORIGIN:        /* 4 */
      if (BGP_SNMP_GET2NEXT (path_attr_origin,
                             &addr, &su, offsetlen, &out,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_INTEGER (out);
        }
      break;
    case BGP4PATHATTRASPATHSEGMENT: /* 5 */
      if (BGP_SNMP_GET3NEXT (path_attr_as_path_segment,
                             &addr, &su, offsetlen, &pnt, var_len,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_OCTETSTRING (pnt);
        }
      break;
    case BGP4PATHATTRNEXTHOP:        /* 6 */
      if (BGP_SNMP_GET2NEXT (path_attr_next_hop,
                             &addr, &su, offsetlen, &outaddr,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_IPADDRESS (outaddr);
        }
      break;
    case BGP4PATHATTRMULTIEXITDISC: /* 7 */
      if (BGP_SNMP_GET2NEXT (path_attr_multi_exit_disc,
                             &addr, &su, offsetlen, &out,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_INTEGER (out);
        }
      break;
    case BGP4PATHATTRLOCALPREF:        /* 8 */
      if (BGP_SNMP_GET2NEXT (path_attr_local_pref,
                             &addr, &su, offsetlen, &out,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_INTEGER (out);
        }
      break;
    case BGP4PATHATTRATOMICAGGREGATE: /* 9 */
      if (BGP_SNMP_GET2NEXT (path_attr_atomic_aggregate,
                             &addr, &su, offsetlen, &out,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_INTEGER (out);
        }
      break;
    case BGP4PATHATTRAGGREGATORAS: /* 10 */
      if (BGP_SNMP_GET2NEXT (path_attr_aggregator_as,
                             &addr, &su, offsetlen, &out,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_INTEGER (out);
        }
      break;
    case BGP4PATHATTRAGGREGATORADDR: /* 11 */
      if (BGP_SNMP_GET2NEXT (path_attr_aggregator_addr,
                             &addr, &su, offsetlen, &outaddr,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_IPADDRESS (outaddr);
        }
      break;
    case BGP4PATHATTRCALCLOCALPREF: /* 12 */
      if (BGP_SNMP_GET2NEXT (path_attr_calc_local_pref,
                             &addr, &su, offsetlen, &out,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_INTEGER (out);
        }
      break;
    case BGP4PATHATTRBEST:        /* 13 */
      if (BGP_SNMP_GET2NEXT (path_attr_best, &addr, &su, offsetlen, &out,
                             vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_INTEGER (out);
        }
      break;
    case BGP4PATHATTRUNKNOWN:        /* 14 */
      if (BGP_SNMP_GET3NEXT (path_attr_unknown,
                             &addr, &su, offsetlen, &pnt, var_len, vr_id))
        {
          if (! exact)
            bgp_snmp_path_index_set (v, name, length, &addr, &su);

          BGP_SNMP_RETURN_OCTETSTRING (pnt);
        }
      break;
    }
  return NULL;
}

/* BGP Traps. */
struct trap_object bgpSnmpNotifyList[] =
{
  {bgpPeerTable, 3, {3, 1, BGPPEERREMOTEADDR}},
  {bgpPeerTable, 3, {3, 1, BGPPEERLASTERROR}},
  {bgpPeerTable, 3, {3, 1, BGPPEERSTATE}}
};

void
bgpSnmpNotifyEstablished (struct bgp_peer *peer)
{
  oid *ptr;
  static u_char error[2];
  int i, ret, state, exact, proc_id;
  struct trap_object2 obj[3];
  struct pal_in4_addr addr, peer_remote_addr;
  size_t name_len;
  u_int32_t vr_id = 0;
  SNMP_TRAP_CALLBACK func;

  ret = pal_inet_pton (AF_INET, peer->host, &addr);
  if (ret == 0)
    return;

  name_len = sizeof bgp_oid / sizeof (oid);
  proc_id = BGP_PROCESS_ID_ANY;
  exact = 1;

  /* Get bgpPeerRemoteAddr. */
  BGP_SNMP_GET_NEXT (peer_remote_addr, &addr, &peer_remote_addr, vr_id);
  ptr = obj[0].name;
  OID_COPY (ptr, bgp_oid, name_len);
  OID_SET_ARG3 (ptr, 3, 1, 7);
  OID_SET_IP_ADDR (ptr, &addr);
  OID_SET_VAL (obj[0], ptr - obj[0].name, IPADDRESS,
               sizeof (struct pal_in4_addr), &peer_remote_addr);

  /* Get bgpPeerLastError. */
  BGP_SNMP_GET_NEXT (peer_last_error, &addr, error, vr_id);
  ptr = obj[1].name;
  OID_COPY (ptr, bgp_oid, name_len);
  OID_SET_ARG3 (ptr, 3, 1, 14);
  OID_SET_IP_ADDR (ptr, &addr);
  OID_SET_VAL (obj[1], ptr - obj[1].name, OCTET_STRING, sizeof(int), error);

  /* Get bgpPeerState. */
  BGP_SNMP_GET_NEXT (peer_state, &addr, &state, vr_id);
  ptr = obj[2].name;
  OID_COPY (ptr, bgp_oid, name_len);
  OID_SET_ARG3 (ptr, 3, 1, 2);
  OID_SET_IP_ADDR (ptr, &addr);
  OID_SET_VAL (obj[2], ptr - obj[2].name, INTEGER, sizeof(int), &state);

  /* Call registered snmp notification callbacks. */
  for (i = 0; i < vector_max (BGP_VR.snmp_notifications[BGPESTABLISHED - 1]); i++)
    if ((func = vector_slot (BGP_VR.snmp_notifications[BGPESTABLISHED - 1], i)))
      (*func) (bgp_snmp_notify_oid, sizeof (bgp_snmp_notify_oid) / sizeof (oid),
               BGPESTABLISHED, pal_time_current (NULL) - BGP_VR.start_time,
               (struct snmp_trap_object *) obj,
               sizeof (obj) / sizeof (struct snmp_trap_object));
}

void
bgpSnmpNotifyBackwardTransition (struct bgp_peer *peer)
{
  oid *ptr;
  static u_char error[2];
  int i, ret, state, exact, proc_id;
  struct trap_object2 obj[3];
  struct pal_in4_addr addr, peer_remote_addr;
  size_t name_len;
  u_int32_t vr_id = 0;
  SNMP_TRAP_CALLBACK func;

  ret = pal_inet_pton (AF_INET, peer->host, &addr);
  if (ret == 0)
    return;

  name_len = sizeof bgp_oid / sizeof (oid);
  proc_id = BGP_PROCESS_ID_ANY;
  exact = 1;

  /* Get bgpPeerRemoteAddr. */
  BGP_SNMP_GET_NEXT (peer_remote_addr, &addr, &peer_remote_addr, vr_id);
  ptr = obj[0].name;
  OID_COPY (ptr, bgp_oid, name_len);
  OID_SET_ARG3 (ptr, 3, 1, 7);
  OID_SET_IP_ADDR (ptr, &addr);
  OID_SET_VAL (obj[0], ptr - obj[0].name, IPADDRESS,
               sizeof (struct pal_in4_addr), &peer_remote_addr);

  /* Get bgpPeerLastError. */
  BGP_SNMP_GET_NEXT (peer_last_error, &addr, error, vr_id);
  ptr = obj[1].name;
  OID_COPY (ptr, bgp_oid, name_len);
  OID_SET_ARG3 (ptr, 3, 1, 14);
  OID_SET_IP_ADDR (ptr, &addr);
  OID_SET_VAL (obj[1], ptr - obj[1].name, OCTET_STRING, sizeof(int), error);

  /* Get bgpPeerState. */
  BGP_SNMP_GET_NEXT (peer_state, &addr, &state, vr_id);
  ptr = obj[2].name;
  OID_COPY (ptr, bgp_oid, name_len);
  OID_SET_ARG3 (ptr, 3, 1, 2);
  OID_SET_IP_ADDR (ptr, &addr);
  OID_SET_VAL (obj[2], ptr - obj[2].name, INTEGER, sizeof(int), &state);

  /* Call registered snmp notifications callbacks. */
  for (i = 0; i < vector_max (BGP_VR.snmp_notifications[BGPBACKWARDTRANSITION - 1]); i++)
    if ((func = vector_slot (BGP_VR.snmp_notifications[BGPBACKWARDTRANSITION - 1], i)))
      (*func) (bgp_snmp_notify_oid, sizeof (bgp_snmp_notify_oid) / sizeof (oid),
               BGPBACKWARDTRANSITION, BGP_VR.start_time - pal_time_current (NULL),
               (struct snmp_trap_object *) obj,
               sizeof (obj) / sizeof (struct snmp_trap_object));

}

/* Register BGP4-MIB. */
void
bgp_snmp_init (void)
{
  snmp_init (&BLG, bgpd_oid, sizeof bgpd_oid / sizeof (oid));
  REGISTER_MIB(&BLG, "mibII/bgp", bgp_variables, variable, bgp_oid);

  snmp_start (&BLG);

  return;
}

#ifdef HAVE_SNMP_RESTART
void
bgp_snmp_restart ()
{
  snmp_restart (&BLG);
}
#endif /* HAVE_SNMP_RESTART */
#endif /* HAVE_SNMP */
