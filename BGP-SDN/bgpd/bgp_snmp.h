/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_SNMP_H
#define _BGPSDN_BGP_SNMP_H

/* BGP4-MIB described in RFC1657. */
#define BGP4MIB 1,3,6,1,2,1,15

/* BGP-SDN enterprise BGP MIB.  This variable is used for register
   BGP MIB to SNMP agent under SMUX protocol.  */
#define BGPDMIB 1,3,6,1,4,1,3317,1,2,2

/* BGP MIB bgpVersion. */
#define BGPVERSION                            0

/* BGP MIB bgpLocalAs. */
#define BGPLOCALAS                            0

/* BGP MIB bgpPeerTable. */
#define BGPPEERIDENTIFIER                     1
#define BGPPEERSTATE                          2
#define BGPPEERADMINSTATUS                    3
#define BGPPEERNEGOTIATEDVERSION              4
#define BGPPEERLOCALADDR                      5
#define BGPPEERLOCALPORT                      6
#define BGPPEERREMOTEADDR                     7
#define BGPPEERREMOTEPORT                     8
#define BGPPEERREMOTEAS                       9
#define BGPPEERINUPDATES                     10
#define BGPPEEROUTUPDATES                    11
#define BGPPEERINTOTALMESSAGES               12
#define BGPPEEROUTTOTALMESSAGES              13
#define BGPPEERLASTERROR                     14
#define BGPPEERFSMESTABLISHEDTRANSITIONS     15
#define BGPPEERFSMESTABLISHEDTIME            16
#define BGPPEERCONNECTRETRYINTERVAL          17
#define BGPPEERHOLDTIME                      18
#define BGPPEERKEEPALIVE                     19
#define BGPPEERHOLDTIMECONFIGURED            20
#define BGPPEERKEEPALIVECONFIGURED           21
#define BGPPEERMINASORIGINATIONINTERVAL      22
#define BGPPEERMINROUTEADVERTISEMENTINTERVAL 23
#define BGPPEERINUPDATEELAPSEDTIME           24

/* BGP MIB bgpIdentifier. */
#define BGPIDENTIFIER                         0

/* BGP MIB bgpRcvdPathAttrTable */
#define BGPPATHATTRPEER                       1
#define BGPPATHATTRDESTNETWORK                2
#define BGPPATHATTRORIGIN                     3
#define BGPPATHATTRASPATH                     4
#define BGPPATHATTRNEXTHOP                    5
#define BGPPATHATTRINTERASMETRIC              6

/* BGP MIB bgp4PathAttrTable. */
#define BGP4PATHATTRPEER                      1
#define BGP4PATHATTRIPADDRPREFIXLEN           2
#define BGP4PATHATTRIPADDRPREFIX              3
#define BGP4PATHATTRORIGIN                    4
#define BGP4PATHATTRASPATHSEGMENT             5
#define BGP4PATHATTRNEXTHOP                   6
#define BGP4PATHATTRMULTIEXITDISC             7
#define BGP4PATHATTRLOCALPREF                 8
#define BGP4PATHATTRATOMICAGGREGATE           9
#define BGP4PATHATTRAGGREGATORAS             10
#define BGP4PATHATTRAGGREGATORADDR           11
#define BGP4PATHATTRCALCLOCALPREF            12
#define BGP4PATHATTRBEST                     13
#define BGP4PATHATTRUNKNOWN                  14

/* BGP Traps. */
#define BGPESTABLISHED                        1
#define BGPBACKWARDTRANSITION                 2

/* BGP Peer Connect Retry Interval Limits */
#define BGPPEERCONNECTRETRYMIN                1
#define BGPPEERCONNECTRETRYMAX            65535

/* Any BGP Timer with a Zero configured value */
#define BGPZEROTIMER                          0
 
/* BGP Peer Hold Time Configured Limits */ 
#define BGPHOLDTIMEMIN                        3 
#define BGPHOLDTIMEMAX                    65535 

/* BGP Peer Keep Alive Configured Limits */
#define BGPKEEPALIVEMAX                   21845

/* BGP Peer Min ASOrigination Interval Limits */
#define BGPPEERMINASORIGINATEMIN              1
#define BGPPEERMINASORIGINATEMAX          65535

/* BGP Peer Min Route Advertisement Interval Limits */
#define BGPMINROUTEADVMIN                     1
#define BGPMINROUTEADVMAX                 65535

/* SNMP value hack. */
#define INTEGER ASN_INTEGER
#define INTEGER32 ASN_INTEGER
#define COUNTER32 ASN_COUNTER
#define OCTET_STRING ASN_OCTET_STR
#define IPADDRESS ASN_IPADDRESS
#define GAUGE32 ASN_UNSIGNED

#define EMPTY_STRING                   ""

/* SNMP Get and GetNext related macros.
   These macros implicitly use `proc_id'. */
#define BGP_SNMP_GET(F, V, I) \
  ((bgp_get_ ## F (I, proc_id, (V))) == BGP_API_GET_SUCCESS)

#define BGP_SNMP_GET_NEXT(F, A, V, I) \
  ((exact ? \
     bgp_get_ ## F (I, proc_id, (A), (V)) : \
     bgp_get_next_ ## F (I, proc_id, (A), (V))) \
   == BGP_API_GET_SUCCESS)

#define BGP_SNMP_GET2NEXT(F, A, B, L, V, I) \
  ((exact ? \
     bgp4_get_ ## F (I, proc_id, (A), (B), (V)) : \
     bgp4_get_next_ ## F (I, proc_id, (A), (B), (L), (V))) \
   == BGP_API_GET_SUCCESS)

#define BGP_SNMP_GET3NEXT(F, A, B, L, V, X, I) \
  ((exact ? \
     bgp4_get_ ## F (I, proc_id, (A), (B), (V), (X)) : \
     bgp4_get_next_ ## F (I, proc_id, (A), (B), (L), (V), (X))) \
   == BGP_API_GET_SUCCESS)

#define BGP_SNMP_RETURN_INTEGER(V) \
  do { \
    *var_len = sizeof (s_int32_t); \
    bgp_int_val = V; \
    return (u_char *) &bgp_int_val; \
  } while (0)

#define BGP_SNMP_RETURN_IPADDRESS(V) \
  do { \
    *var_len = sizeof (struct pal_in4_addr); \
    bgp_in_addr_val = V; \
    return (u_char *) &bgp_in_addr_val; \
  } while (0)

#define BGP_SNMP_RETURN_OCTETSTRING(V) \
  do { \
    if (*var_len ==  0) \
      return EMPTY_STRING; \
    else \
      return (u_char *) (V); \
  } while (0)

/* Prototype. */
void
bgpSnmpNotifyEstablished (struct bgp_peer *);
void
bgpSnmpNotifyBackwardTransition (struct bgp_peer *);
void
bgp_snmp_smux_notification (oid *, size_t, oid, u_int32_t,
                            struct snmp_trap_object *, size_t);
void
bgp_snmp_init (void);
#ifdef HAVE_SNMP_RESTART
void bgp_snmp_restart ();
#endif /* HAVE_SNMP_RESTART */
#endif /* _BGPSDN_BGP_SNMP_H */
