/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_NETWORK_H
#define _BGPSDN_BGP_NETWORK_H

void
bpn_sock_cb_status_hdlr (struct stream_sock_cb *, s_int32_t,
                         struct lib_globals *);
void
bpn_sock_cb_connect (struct bgp_peer *);
void
bpn_sock_cb_disconnect (struct bgp_peer *);
void
bpn_sock_cb_reset (struct bgp_peer *);
void
bpn_sock_cb_get_id (struct bgp_peer *);
s_int32_t
bpn_sock_bind_address (struct bgp_peer *, pal_sock_handle_t);
s_int32_t
bpn_sock_set_opt_nodelay (struct bgp_peer *);
s_int32_t
bpn_sock_set_opt (struct bgp_peer *, pal_sock_handle_t, bool_t);
s_int32_t
bpn_sock_accept (struct thread *);
s_int32_t
bpn_sock_listen (struct bgp *, u_int16_t);
s_int32_t
bpn_sock_listen_uninit (struct bgp *);
u_int16_t
bpn_get_sock_port (s_int32_t sock, u_int16_t * ip_ver);
#endif /* _BGPSDN_BGP_NETWORK_H */
