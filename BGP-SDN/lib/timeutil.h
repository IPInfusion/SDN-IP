/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_TIMEUTIL_H
#define _BGPSDN_TIMEUTIL_H

#define ONE_WEEK_SECOND     (60*60*24*7)
#define ONE_DAY_SECOND      (60*60*24)
#define ONE_HOUR_SECOND     (60*60)
#define ONE_MIN_SECOND      (60)
#define ONE_SEC_DECISECOND  (10)
#define ONE_SEC_CENTISECOND (100)
#define ONE_SEC_MILLISECOND (1000)
#define ONE_SEC_MICROSECOND (1000000)
#define MILLISEC_TO_DECISEC (100)
#define DECISEC_TO_MILLISEC (100)
#define HALFSEC_MILLISEC    (500)
#define MILLISEC_TO_MICROSEC      (1000)
#define ONE_SEC_TENTHS_OF_SECOND  (10)

#define TV_ADJUST(A)        timeval_adjust (A)
#define TV_CEIL(A)          timeval_ceil ((A))
#define TV_FLOOR(A)         timeval_floor ((A))
#define TV_ADD(A,B)         timeval_add ((A), (B))
#define TV_SUB(A,B)         timeval_sub ((A), (B))
#define TV_CMP(A,B)         timeval_cmp ((A), (B))
#define INT2TV(A)           timeutil_int2tv ((A))
#define MSEC2TV(A)          timeutil_msec2tv ((A))
#define MSEC2SECROUND(A)    timeutil_msec2secround ((A))

/* Time related utility function prototypes  */

char *
timeutil_uptime (char *, u_int32_t, pal_time_t);
char *
timeval_uptime (char *, u_int32_t, struct pal_timeval);
struct pal_timeval
timeval_adjust (struct pal_timeval);
struct pal_timeval
timeval_subtract (struct pal_timeval, struct pal_timeval);
int
timeval_ceil (struct pal_timeval);
int
timeval_floor (struct pal_timeval);
struct pal_timeval
timeval_add (struct pal_timeval, struct pal_timeval);
struct pal_timeval
timeval_sub (struct pal_timeval, struct pal_timeval);
int
timeval_cmp (struct pal_timeval, struct pal_timeval);
struct pal_timeval
timeutil_int2tv (u_int32_t);
struct pal_timeval
timeutil_msec2tv (u_int32_t);
u_int32_t
timeutil_msec2secround (u_int32_t);
#endif /* _BGPSDN_TIMEUTIL_H */
