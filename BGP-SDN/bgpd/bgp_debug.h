/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_DEBUG_H
#define _BGPSDN_BGP_DEBUG_H

/* sort of packet direction */
#define DUMP_ON        1
#define DUMP_SEND      2
#define DUMP_RECV      4

/* for dump_update */
#define DUMP_WITHDRAW  8
#define DUMP_NLRI     16

/* dump detail */
#define DUMP_DETAIL   32

extern int dump_open;
extern int dump_update;
extern int dump_keepalive;
extern int dump_notify;

extern int Debug_Event;
extern int Debug_Keepalive;
extern int Debug_Update;
extern int Debug_Radix;

#define NLRI     1
#define WITHDRAW 2
#define NO_OPT   3
#define SEND     4
#define RECV     5
#define DETAIL   6

/* Prototypes. */
void bgp_debug_cli_init (struct cli_tree *);
int debug (unsigned int option);

#define CONF_DEBUG_ON(a, b) (BGP_VR.conf_bgp_debug_flags |= (BGP_DEBUG_ ## b))
#define CONF_DEBUG_OFF(a, b)(BGP_VR.conf_bgp_debug_flags &= ~(BGP_DEBUG_ ## b))

#define TERM_DEBUG_ON(a, b) (BGP_VR.term_bgp_debug_flags |= (BGP_DEBUG_ ## b))
#define TERM_DEBUG_OFF(a, b)(BGP_VR.term_bgp_debug_flags &= ~(BGP_DEBUG_ ## b))

#define DEBUG_ON(a, b) \
    do { \
        CONF_DEBUG_ON(a, b); \
        TERM_DEBUG_ON(a, b); \
    } while (0)
#define DEBUG_OFF(a, b) \
    do { \
        CONF_DEBUG_OFF(a, b); \
        TERM_DEBUG_OFF(a, b); \
    } while (0)

/* The argument 'a' is not used in this Macro */
#define BGP_DEBUG(a, b)      (BGP_VR.term_bgp_debug_flags & BGP_DEBUG_ ## b)
#define CONF_BGP_DEBUG(a, b) (BGP_VR.conf_bgp_debug_flags & BGP_DEBUG_ ## b)

void bgp_dump_attr (struct bgp_peer *, struct attr *, char *, size_t);
void bgp_log_neighbor_status_print (struct bgp_peer *, int, char *);
void bgp_log_neighbor_notify_print (struct bgp_peer *,
                                    struct bgp_peer_notify_info *,
                                    u_int8_t *);
void bgp_get_notify_err_mesg (struct bgp_peer_notify_info *,
                              u_int8_t **, u_int8_t **);

#endif /* _BGPSDN_BGP_DEBUG_H */
