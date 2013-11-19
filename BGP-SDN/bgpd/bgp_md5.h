/* Copyright (C) 2003-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_MD5_H
#define _BGPSDN_BGP_MD5_H

int bgp_md5_set (pal_sock_handle_t sock, struct pal_in4_addr *addr,
                 char *md5_key);
int bgp_md5_unset (pal_sock_handle_t sock, struct pal_in4_addr *addr,
                   char *md5_key);

int bgp_md5_set_server (struct bgp *bgp, pal_sock_handle_t sock);
int bgp_md5_unset_server (struct bgp *bgp, pal_sock_handle_t sock);

#endif /* _BGPSDN_BGP_MD5_H */
