/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_INCL_H
#define _BGPSDN_BGP_INCL_H

/*********************************************************************/
/* FILE       : bgp_incl.h                                           */
/* PURPOSE    : This file contains ALL the Include Header files      */
/*              needed for *.c files WITHIN the 'bgpd/' directory.   */
/*                                                                   */
/* SPECIAL NOTE : THIS FILE SHOULD NOT BE INCLUDED IN ANY FILE       */
/*                OUTSIDE OF 'bgpd/' DIRECTORY.                      */
/*********************************************************************/

/*********************************************************************/
/* PAL and Library Include Files                                     */
/*********************************************************************/
#include "pal.h"
#include "lib.h"
#include "thread.h"
#include "sockunion.h"
#include "log.h"
#include "if.h"
#include "hash.h"
#include "cli.h"
#include "show.h"
#include "log.h"
#include "prefix.h"
#include "vty.h"
#include "vector.h"
#include "bgpsdn_version.h"
#include "linklist.h"
#include "sockunion.h"
#include "snprintf.h"
#include "network.h"
#include "nexthop.h"
#include "cqueue.h"
#include "table.h"
#include "sock_cb.h"
#include "pal_assert.h"
#include "timeutil.h"
#include "plist.h"
#ifdef HAVE_BGP_DUMP
#include "stream.h"
#endif /* HAVE_BGP_DUMP */
#ifdef HAVE_SNMP
#include "snmp.h"
#include "asn1.h"
#endif /* HAVE_SNMP */

/*********************************************************************/
/* BGP Include Files                                                 */
/*********************************************************************/
#include "bgpd/bgpd.h"
#include "bgpd/bgp_api.h"
#include "bgpd/bgp_message.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_ptree.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_encode.h"
#include "bgpd/bgp_decode.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_nexthop.h"
#ifdef HAVE_EXT_CAP_ASN
#include "bgpd/bgp_as4path.h"
#endif /* HAVE_EXT_CAP_ASN */
#include "bgpd/bgp_filter.h"
#ifdef HAVE_SNMP
#include "bgpd/bgp_snmp.h"
#endif /* HAVE_SNMP */
#ifdef HAVE_BGP_DUMP
#include "bgpd/bgp_dump.h"
#endif /* HAVE_BGP_DUMP */
#ifdef HAVE_TCP_MD5SIG
#include "bgpd/bgp_md5.h"
#endif /* TCP_MD5SIG */

#endif /* _BGPSDN_BGP_INCL_H */
