/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_OPEN_H
#define _BGPSDN_BGP_OPEN_H

void
bgp_peer_send_keepalive (struct bgp_peer *);
void
bgp_peer_send_open (struct bgp_peer *);
void
bgp_peer_send_update (struct bgp_peer *, bool_t);
bool_t
bgp_peer_send_update_adv_list (struct bgp_peer *,
                               struct bgp_peer_adv_list *,
                               afi_t, safi_t, bool_t);
void
bgp_peer_send_notify (struct bgp_peer *);
void
bgp_peer_send_route_refresh (struct bgp_peer *, afi_t, safi_t, u_int8_t,
                             u_int8_t, u_int32_t);
void
bgp_peer_send_dyna_cap (struct bgp_peer *, afi_t, safi_t, u_int8_t,
                        u_int8_t);
s_int32_t
bpe_msg_hdr (struct cqueue_buffer *, struct bgp_peer *, u_int8_t,
             u_int16_t);
s_int32_t
bpe_msg_open (struct cqueue_buffer *, struct bgp_peer *);
bool_t
bpe_msg_update (struct cqueue_buffer *, struct bgp_peer *,
                struct bgp_peer_adv_list *,
                afi_t, safi_t, bool_t);
s_int32_t
bpe_msg_notify (struct cqueue_buffer *, struct bgp_peer *);
s_int32_t
bpe_msg_route_refresh (struct cqueue_buffer *, struct bgp_peer *,
                       afi_t, safi_t, u_int8_t, u_int8_t, u_int32_t);
s_int32_t
bpe_msg_dyna_cap (struct cqueue_buffer *, struct bgp_peer *, afi_t,
                  safi_t, u_int8_t, u_int8_t);
void
bpe_msg_open_cap (struct cqueue_buffer *, struct bgp_peer *);
bool_t
bpe_msg_update_endofrib (struct cqueue_buffer *, struct bgp_peer *);
bool_t
bpe_msg_update_withdrawn (struct cqueue_buffer *, struct bgp_peer *,
                          struct fifo *, bool_t);
int
bpe_msg_encode_extnd_attr (struct cqueue_buffer *, struct bgp_peer *, struct attr *);
bool_t
bpe_msg_attr_ip (struct cqueue_buffer *, struct bgp_peer *,
                 struct bgp_peer *, struct attr *);
bool_t
bpe_msg_attr_mp (struct cqueue_buffer *, struct bgp_peer *,
                 struct bgp_peer *, struct attr *, afi_t, safi_t);
bool_t
bpe_msg_update_nlri (struct cqueue_buffer *, struct bgp_peer *, 
                     struct fifo *, bool_t);
bool_t
bpe_msg_attr_mp_endofrib (struct cqueue_buffer *, struct bgp_peer *,
                          afi_t, safi_t);
bool_t
bpe_msg_attr_mp_unreach (struct cqueue_buffer *, struct bgp_peer *,
                         afi_t, safi_t, struct fifo *);
bool_t
bpe_msg_attr_mp_reach (struct cqueue_buffer *, struct bgp_peer *,
                       struct attr *, afi_t, safi_t, struct fifo *);
void
bpe_msg_open_cap_orf (struct cqueue_buffer *, struct bgp_peer *,
                      afi_t, safi_t, u_int8_t);
void
bpe_msg_attr_aspath (struct cqueue_buffer *, struct bgp_peer *,
                     struct bgp_peer *, struct attr *, afi_t, safi_t);

#ifdef HAVE_EXT_CAP_ASN
void
bpe_msg_attr_new_aspath (struct cqueue_buffer *, struct bgp_peer *,
                     struct bgp_peer *, struct attr *, afi_t, safi_t);
void bge_msg_ext_asn_aggregator (struct cqueue_buffer *, struct bgp_peer *,
                     struct bgp_peer *, struct attr *);
#endif /* HAVE_EXT_CAP_ASN */
bool_t
bpe_msg_update_nlri_prefix (struct cqueue_buffer *, struct bgp_node *,
                            struct bgp_info *, afi_t, safi_t, bool_t, bool_t);
#endif /* _BGPSDN_BGP_OPEN_H */
