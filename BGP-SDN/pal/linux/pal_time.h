/*
**
** Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.
**
** pal_time.h -- BGP-SDN PAL time operations definitions
**               for Linux
*/
#ifndef _PAL_TIME_H
#define _PAL_TIME_H

/*
**
** Include files
*/
#include "pal.h"

#include <time.h>
#include <sys/time.h>

/*
**
** Constants and enumerations
*/

/*
** Number of tics per second on this platform
*/
#define TICS_PER_SECOND 100
#define PAL_TIME_MAX_TV_SEC 0x7fffffff
#define PAL_TIME_MAX_TV_USEC 0x7fffffff

/*
** Number of tv_usec per second.  Some systems actually purport to prefer
** nanosecond values for the tv_usec field.  Somehow, this probably isn't
** quite accurate yet...
*/
#define TV_USEC_PER_SEC 1000000

/*
**
** Types
*/

/*
** Time value in tics
*/
typedef time_t pal_time_t;

/*
** Clock value
*/
typedef clock_t pal_clock_t;

/*
** A time in seconds and microseconds
*/
#define pal_timeval timeval

/*
** Time zone information
*/
#define pal_tzval timezone

/*
** A structure with the elements of time disassembled
*/
#define pal_tm tm

struct lib_globals;

/*
**
** Functions
*/

#include "pal_time.def"

#undef pal_time_clock
#define pal_time_clock clock

#undef pal_time_sys_current
#define pal_time_sys_current(z) time(z)

#undef pal_time_mk
#define pal_time_mk mktime

#undef pal_time_strf
#define pal_time_strf strftime

pal_time_t
pal_time_since_boot ();
/*
**
** Done
*/
#endif /* def _PAL_TIME_H */
