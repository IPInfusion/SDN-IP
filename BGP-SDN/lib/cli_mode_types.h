/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved.  */

#ifndef _BGPSDN_CLI_MODE_TYPES_H
#define _BGPSDN_CLI_MODE_TYPES_H

/* CLI modes.  */

#define LOGIN_MODE              0
#define AUTH_MODE               1
#define AUTH_ENABLE_MODE        2
#define SERVICE_MODE            3
#define EXEC_MODE               4
#define CONFIG_MODE             5
#define LINE_MODE               6
#define DEBUG_MODE              11
    /* Keychain configuration.  */
#define KEYCHAIN_MODE           12
#define KEYCHAIN_KEY_MODE       13
    /* VR. */
#define VR_MODE                 14
    /* Interface.  */
#define INTERFACE_MODE          16
#define INTERFACE_MANAGE_MODE   21
    /* Router ID/Hostname node. */
#define ROUTER_MODE             25
#define BGP_MODE                26
#define BGP_IPV4_MODE           27
#define BGP_IPV4M_MODE          28
#define BGP_IPV6_MODE           30
    /* Community list.  */
#define COMMUNITY_LIST_MODE     55
    /* Access list and prefix list.  */
#define PREFIX_MODE             56
#define ACCESS_MODE             57
    /* IPv6 access list and prefix list.  */
#define ACCESS_IPV6_MODE        60
#define PREFIX_IPV6_MODE        61
    /* AS path access list.  */
#define AS_LIST_MODE            62
    /* Route-map.  */
#define RMAP_MODE               63
    /* BGP dump mode. */
#define DUMP_MODE               65
    /* VTY */
#define VTY_MODE                76
    /* Fake modes used for config-write. */
#define SMUX_MODE               77
    /* Below is special modes.  */
#define EXEC_PRIV_MODE          78   /* Fake mode.  Same as EXEC_MODE.   */
                                    /* Do not change value for EXEC_PRIV_MODE */
#define MODIFIER_MODE           80  /* Output modifier node.  */

/* MAX Mode for the CLI's. All new modes should have less than this value*/
#define MAX_MODE                177

#endif /* _BGPSDN_CLI_MODE_TYPES_H */
