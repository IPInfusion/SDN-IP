/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */
                                                                           
#ifndef _PAL_IF_DEFAULT_H
#define _PAL_IF_DEFAULT_H
                                                                           
#define IF_ETHER_DEFAULT_MTU    1500
#define IF_PPP_DEFAULT_MTU      1500
#define IF_HDLC_DEFAULT_MTU     1500
#define IF_LO_DEFAULT_MTU       16436  
#define IF_ATM_DEFAULT_MTU      4470

#ifdef HAVE_TUNNEL
#define IF_TUNNEL_DEFAULT_MTU      1476 /*Based on def kernel set for tunnel*/
#endif

#endif /* _PAL_IF_DEFAULT_H */
