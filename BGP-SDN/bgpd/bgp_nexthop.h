/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_NEXTHOP_H
#define _BGPSDN_BGP_NEXTHOP_H

/*
 *  Prototyping
 */
s_int32_t bnh_network_scan_afi (struct bgp *, afi_t);
s_int32_t bnh_network_scan (struct thread *);
s_int32_t bnh_scan_init (struct bgp *);
s_int32_t bnh_scan_uninit (struct bgp *);

#endif /* _BGPSDN_BGP_NEXTHOP_H */
