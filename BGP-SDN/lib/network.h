/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_NETWORK_H
#define _BGPSDN_NETWORK_H

#include "pal.h"

s_int32_t readn (pal_sock_handle_t, u_char *, s_int32_t);
s_int32_t writen (pal_sock_handle_t, u_char *, s_int32_t);

#endif /* _BGPSDN_NETWORK_H */
