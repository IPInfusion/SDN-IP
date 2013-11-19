/*=============================================================================
**
** Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.
**
** pal.h -- BGP-SDN PAL common definitions
**          for Linux
*/
#ifndef _PAL_H
#define _PAL_H

/*-----------------------------------------------------------------------------
**
** Include files
*/

/* System configuration */
#ifndef APS_TOOLKIT
#include "config.h"
#include "plat_incl.h"
#include "pal_types.h"
#include "pal_if_default.h"
#include "pal_posix.h"
#include "pal_assert.h"
#include "pal_memory.h"
#include "pal_file.h"
#include "pal_daemon.h"
#include "pal_debug.h"
#include "pal_stdlib.h"
#include "pal_memory.h"
#include "pal_string.h"
#include "pal_log.h"
#include "pal_time.h"
#include "pal_math.h"
#include "pal_regex.h"
#include "pal_socket.h"
#include "pal_sock_ll.h"
#include "pal_inet.h"
#include "pal_signal.h"
#include "pal_kernel.h"
#include "pal_sysctl.h"

#else  /* For APS Toolkit customer user. */
#include "plat_incl.h"
#include "pal_types.h"
#include "pal_time.h"
#endif /* APS_TOOLKIT */

#ifndef SPEED_10000
#define SPEED_10000 10000
#endif /* ! SPEED_10000 */
/*-----------------------------------------------------------------------------
**
** Constants and enumerations
*/

/*-----------------------------------------------------------------------------
**
** Types
*/
typedef unsigned long int u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

/*-----------------------------------------------------------------------------
**
** Functions
*/

/*-----------------------------------------------------------------------------
**
** Done
*/
#endif /* _PAL_H */
