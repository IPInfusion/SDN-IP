/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_FSM_H
#define _BGPSDN_BGP_FSM_H

/* Macro to register an event to BGP Peer FSM */
#define BGP_PEER_FSM_EVENT_ADD(LIB_GLOB, PEER, EVENT)                 \
  thread_add_event ((LIB_GLOB), bpf_process_event, (PEER), (EVENT))

/* Macro to de-register an event of BGP Peer FSM */
#define BGP_PEER_FSM_EVENT_DELETE(LIB_GLOB, PEER)                     \
  thread_cancel_event ((LIB_GLOB), (PEER))

/* Macro to register a low-priority event to BGP Peer FSM */
#define BGP_PEER_FSM_EVENT_LOW_ADD(LIB_GLOB, PEER, EVENT)             \
  thread_add_event_low ((LIB_GLOB), bpf_process_event, (PEER), (EVENT))

/* Macro to de-register a low-priority event of BGP Peer FSM */
#define BGP_PEER_FSM_EVENT_LOW_DELETE(LIB_GLOB, PEER)                 \
  thread_cancel_event_low ((LIB_GLOB), (PEER))


/* Macro to convert BGP Peer FSM State value to string */
#define BGP_PEER_FSM_STATE_STR(STATE)                                 \
    ((STATE) == BPF_STATE_IDLE ? "Idle" :                             \
     (STATE) == BPF_STATE_CONNECT ? "Connect" :                       \
     (STATE) == BPF_STATE_ACTIVE ? "Active" :                         \
     (STATE) == BPF_STATE_OPEN_SENT ? "OpenSent" :                    \
     (STATE) == BPF_STATE_OPEN_CFM ? "OpenConfirm" :                  \
     (STATE) == BPF_STATE_ESTABLISHED ? "Established" : "Invalid")

/*
 * Function Prototype Declarations
 */
s_int32_t
bpf_process_event (struct thread *);
s_int32_t
bpf_action_invalid (struct bgp_peer *, u_int32_t);
s_int32_t
bpf_action_idle (struct bgp_peer *, u_int32_t);
s_int32_t
bpf_action_connect (struct bgp_peer *, u_int32_t);
s_int32_t
bpf_action_active (struct bgp_peer *, u_int32_t);
s_int32_t
bpf_action_open_sent (struct bgp_peer *, u_int32_t);
s_int32_t
bpf_action_open_cfm (struct bgp_peer *, u_int32_t);
s_int32_t
bpf_action_established (struct bgp_peer *, u_int32_t);
void
bpf_change_state (struct bgp_peer *, u_int32_t);
void
bpf_transform_incoming2real_peer (struct bgp_peer **);
u_int32_t
bpf_timer_generate_jitter (u_int32_t);
s_int32_t
bpf_timer_auto_start (struct thread *);
s_int32_t
bpf_timer_conn_retry (struct thread *);
s_int32_t
bpf_timer_holdtime (struct thread *);
s_int32_t
bpf_timer_keepalive (struct thread *);
s_int32_t
bpf_timer_asorig (struct thread *);
s_int32_t
bpf_timer_routeadv (struct thread *);
s_int32_t
bpf_collision_detect_check (struct bgp_peer *, struct pal_in4_addr);
s_int32_t
bpf_collision_detect (struct bgp_peer *);
s_int32_t
bpf_process_open (struct bgp_peer *);
s_int32_t
bpf_process_update (struct bgp_peer *);
s_int32_t
bpf_process_notification (struct bgp_peer *);
s_int32_t
bpf_process_route_refresh (struct bgp_peer *);
s_int32_t
bpf_process_dyna_cap (struct bgp_peer *);
s_int32_t
bpf_process_inconn_req (struct bgp_peer *, enum bgp_peer_icr_act);
s_int32_t
bpf_process_manual_reset (struct bgp_peer *);
s_int32_t
bpf_register_notify (struct bgp_peer *, u_int32_t, u_int32_t,
                     u_int8_t *, u_int32_t);
s_int32_t
bpf_event_notify (struct bgp_peer *, u_int32_t, u_int32_t, u_int32_t,
                  u_int8_t *, u_int32_t);
s_int32_t
bpf_event_notify_attr (struct cqueue_buffer *, struct bgp_peer *,
                       u_int8_t, u_int8_t, u_int16_t, u_int16_t,
                       u_int16_t, u_int32_t, u_int32_t);
s_int32_t
bpf_event_notify_cap (struct cqueue_buffer *, struct bgp_peer *,
                      u_int32_t, u_int8_t, u_int8_t, u_int8_t,
                      u_int8_t, u_int8_t, u_int32_t, u_int32_t);
s_int32_t
bpf_g_shut_timer (struct thread *);

#endif /* _BGPSDN_BGP_FSM_H */
