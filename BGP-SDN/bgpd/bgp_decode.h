/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_PACKET_H
#define _BGPSDN_BGP_PACKET_H

enum ssock_error
bpd_msg_hdr (struct stream_sock_cb *, u_int32_t,
             struct lib_globals *);
enum ssock_error
bpd_msg_open (struct stream_sock_cb *, u_int32_t,
              struct lib_globals *);
enum ssock_error
bpd_msg_update (struct stream_sock_cb *, u_int32_t,
                struct lib_globals *);
enum ssock_error
bpd_msg_notify (struct stream_sock_cb *, u_int32_t,
                struct lib_globals *);
enum ssock_error
bpd_msg_keepalive (struct stream_sock_cb *, u_int32_t,
                   struct lib_globals *);
enum ssock_error
bpd_msg_route_refresh (struct stream_sock_cb *, u_int32_t,
                       struct lib_globals *);
enum ssock_error
bpd_msg_dyna_cap (struct stream_sock_cb *, u_int32_t,
                  struct lib_globals *);
enum ssock_error
bpd_msg_open_opt (struct cqueue_buffer *, struct bgp_peer *,
                  u_int32_t);
enum ssock_error
bpd_msg_update_attr (struct cqueue_buffer *, struct bgp_peer *,
                     u_int32_t, struct attr *,
                     struct bgp_nlri_snap_shot *);
enum ssock_error
bpd_msg_open_cap (struct cqueue_buffer *, struct bgp_peer *,
                  u_int32_t, u_int8_t **);
enum ssock_error
bpd_msg_attr_origin (struct cqueue_buffer *, struct bgp_peer *,
                     u_int8_t, u_int8_t, u_int16_t, struct attr *);
#ifndef HAVE_EXT_CAP_ASN
enum ssock_error
bpd_msg_attr_aspath (struct cqueue_buffer *, struct bgp_peer *,
                     u_int8_t, u_int8_t, u_int16_t, struct attr *);
#endif /* HAVE_EXT_CAP_ASN */
#ifdef HAVE_EXT_CAP_ASN
enum ssock_error
bpd_msg_attr_new_aspath (struct cqueue_buffer *, struct bgp_peer *,
                         u_int8_t, u_int8_t, u_int16_t, struct attr *);
enum ssock_error
bpd_msg_attr_as4path (struct cqueue_buffer *, struct bgp_peer *,
                      u_int8_t, u_int8_t, u_int16_t, struct attr *);
#endif /* HAVE_EXT_CAP_ASN */
enum ssock_error
bpd_msg_attr_nhop (struct cqueue_buffer *, struct bgp_peer *,
                   u_int8_t, u_int8_t, u_int16_t, struct attr *);
enum ssock_error
bpd_msg_attr_med (struct cqueue_buffer *, struct bgp_peer *,
                  u_int8_t, u_int8_t, u_int16_t, struct attr *);
enum ssock_error
bpd_msg_attr_locpref (struct cqueue_buffer *, struct bgp_peer *,
                      u_int8_t, u_int8_t, u_int16_t, struct attr *);
enum ssock_error
bpd_msg_attr_atomic (struct cqueue_buffer *, struct bgp_peer *,
                     u_int8_t, u_int8_t, u_int16_t, struct attr *);
#ifndef HAVE_EXT_CAP_ASN
enum ssock_error
bpd_msg_attr_aggregator (struct cqueue_buffer *, struct bgp_peer *,
                         u_int8_t, u_int8_t, u_int16_t, struct attr *);
#else
enum ssock_error
bpd_msg_attr_new_aggregator (struct cqueue_buffer *, struct bgp_peer *,
                         u_int8_t, u_int8_t, u_int16_t, struct attr *);
enum ssock_error
bpd_msg_attr_as4_aggregator (struct cqueue_buffer *, struct bgp_peer *,
                         u_int8_t, u_int8_t, u_int16_t, struct attr *);
#endif /* HAVE_EXT_CAP_ASN */
enum ssock_error
bpd_msg_attr_comm (struct cqueue_buffer *, struct bgp_peer *,
                   u_int8_t, u_int8_t, u_int16_t, struct attr *);
enum ssock_error
bpd_msg_attr_ecomm (struct cqueue_buffer *, struct bgp_peer *,
                    u_int8_t, u_int8_t, u_int16_t, struct attr *);
enum ssock_error
bpd_msg_attr_orig_id (struct cqueue_buffer *, struct bgp_peer *,
                      u_int8_t, u_int8_t, u_int16_t, struct attr *);
enum ssock_error
bpd_msg_attr_cluster (struct cqueue_buffer *, struct bgp_peer *,
                      u_int8_t, u_int8_t, u_int16_t, struct attr *);
enum ssock_error
bpd_msg_attr_mp_reach (struct cqueue_buffer *, struct bgp_peer *,
                       u_int8_t, u_int8_t, u_int16_t, struct attr *,
                       struct bgp_nlri_snap_shot *);
enum ssock_error
bpd_msg_attr_mp_unreach (struct cqueue_buffer *, struct bgp_peer *,
                         u_int8_t, u_int8_t, u_int16_t, struct attr *,
                         struct bgp_nlri_snap_shot *);
enum ssock_error
bpd_msg_attr_unknown (struct cqueue_buffer *, struct bgp_peer *,
                      u_int8_t, u_int8_t, u_int16_t, struct attr *);

enum ssock_error
   bpd_msg_open_cap_code_dynamic (struct cqueue_buffer *, struct bgp_peer *,
                                  struct bgp_capability *, u_int32_t *,
                                  u_int8_t **);
enum ssock_error
bpd_msg_open_cap_mp (struct cqueue_buffer *, struct bgp_peer *,
                     struct bgp_capability *, u_int32_t *,
                     u_int8_t **);
enum ssock_error
bpd_msg_open_cap_gr (struct cqueue_buffer *, struct bgp_peer *,
                     u_int8_t, struct bgp_capability *, u_int32_t *,
                     bool_t);
enum ssock_error
bpd_msg_open_cap_orf (struct cqueue_buffer *, struct bgp_peer *,
                      struct bgp_capability *, u_int32_t *);
enum ssock_error
bpd_msg_update_nlri_validate (struct cqueue_buffer *, struct bgp_peer *,
                              afi_t, safi_t, u_int16_t);
s_int32_t
bpd_msg_update_nhop_validate (struct bgp_peer *, struct pal_in4_addr *);

#ifdef HAVE_EXT_CAP_ASN
enum ssock_error
bpd_msg_open_cap_extasn (struct cqueue_buffer *, struct bgp_peer *,
                         struct bgp_capability *, u_int32_t *,
                         u_int8_t **);
#endif /* HAVE_EXT_CAP_ASN */
#endif /* _BGPSDN_BGP_PACKET_H */
