/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#include "lib.h"
#include "timeutil.h"

/* Uptime string.  */
char *
timeutil_uptime (char *timebuf,
                 u_int32_t bufsiz,
                 pal_time_t uptime)
{
  struct pal_tm tm;

  /* Get current time. */
  pal_time_gmt (&uptime, &tm);

  /* Making formatted timer string. */
  if (uptime < ONE_DAY_SECOND)
    pal_snprintf (timebuf, bufsiz, "%02d:%02d:%02d",
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
  else if (uptime < ONE_WEEK_SECOND)
    pal_snprintf (timebuf, bufsiz, "%02dd%02dh%02dm",
                  tm.tm_yday, tm.tm_hour, tm.tm_min);
  else
    pal_snprintf (timebuf, bufsiz, "%02dw%02dd%02dh",
                  tm.tm_yday/7, tm.tm_yday - ((tm.tm_yday/7) * 7), tm.tm_hour);

  return timebuf;
}

/* Uptime string.  */
char *
timeval_uptime (char *timebuf,
                u_int32_t bufsiz,
                struct pal_timeval uptime)
{
  /* Making formatted timer string. */
  if (uptime.tv_sec < ONE_DAY_SECOND)
    pal_snprintf (timebuf, bufsiz, "%02ld:%02ld:%02ld",
                  uptime.tv_sec / ONE_HOUR_SECOND,
                  (uptime.tv_sec % ONE_HOUR_SECOND) / ONE_MIN_SECOND,
                  uptime.tv_sec % ONE_MIN_SECOND);
  else if (uptime.tv_sec < ONE_WEEK_SECOND)
    pal_snprintf (timebuf, bufsiz, "%02ldd%02ldh%02ldm",
                  uptime.tv_sec / ONE_DAY_SECOND,
                  (uptime.tv_sec % ONE_DAY_SECOND) / ONE_HOUR_SECOND,
                  (uptime.tv_sec % ONE_HOUR_SECOND) / ONE_MIN_SECOND);
  else
    pal_snprintf (timebuf, bufsiz, "%02ldw%02ldd%02ldh",
                  uptime.tv_sec / ONE_WEEK_SECOND,
                  (uptime.tv_sec % ONE_WEEK_SECOND) / ONE_DAY_SECOND,
                  (uptime.tv_sec % ONE_DAY_SECOND) / ONE_HOUR_SECOND);

  return timebuf;
}

struct pal_timeval
timeval_adjust (struct pal_timeval a)
{
  while (a.tv_usec >= TV_USEC_PER_SEC)
    {
      a.tv_usec -= TV_USEC_PER_SEC;
      a.tv_sec++;
    }

  while (a.tv_usec < 0)
    {
      a.tv_usec += TV_USEC_PER_SEC;
      a.tv_sec--;
    }

  if (a.tv_sec < 0)
    {
      a.tv_sec = 0;
      a.tv_usec = 10;
    }

  if (a.tv_sec > TV_USEC_PER_SEC)
    a.tv_sec = TV_USEC_PER_SEC;

  return a;
}

struct pal_timeval
timeval_subtract (struct pal_timeval a, struct pal_timeval b)
{
  struct pal_timeval ret;

  ret.tv_usec = a.tv_usec - b.tv_usec;
  ret.tv_sec = a.tv_sec - b.tv_sec;

  return timeval_adjust (ret);
}

int
timeval_ceil (struct pal_timeval a)
{
  a = timeval_adjust (a);

  return (a.tv_usec ? a.tv_sec + 1 : a.tv_sec);
}

int
timeval_floor (struct pal_timeval a)
{
  a = timeval_adjust (a);

  return a.tv_sec;
}

struct pal_timeval
timeval_add (struct pal_timeval a, struct pal_timeval b)
{
  struct pal_timeval ret;

  ret.tv_sec = a.tv_sec + b.tv_sec;
  ret.tv_usec = a.tv_usec + b.tv_usec;

  return timeval_adjust (ret);
}

struct pal_timeval
timeval_sub (struct pal_timeval a, struct pal_timeval b)
{
  struct pal_timeval ret;

  ret.tv_sec = a.tv_sec - b.tv_sec;
  ret.tv_usec = a.tv_usec - b.tv_usec;

  return timeval_adjust (ret);
}

int
timeval_cmp (struct pal_timeval a, struct pal_timeval b)
{
  return (a.tv_sec == b.tv_sec ?
          a.tv_usec - b.tv_usec : a.tv_sec - b.tv_sec);
}

struct pal_timeval
timeutil_int2tv (u_int32_t a)
{
  struct pal_timeval ret;

  ret.tv_sec = a;
  ret.tv_usec = 0;

  return ret;
}

struct pal_timeval
timeutil_msec2tv (u_int32_t a)
{
  struct pal_timeval ret;

  ret.tv_sec = a / ONE_SEC_MILLISECOND;
  ret.tv_usec = (a % ONE_SEC_MILLISECOND) * ONE_SEC_MILLISECOND;

  return ret;
}

u_int32_t
timeutil_msec2secround (u_int32_t a)
{
  if ((a % ONE_SEC_MILLISECOND) > HALFSEC_MILLISEC)
    return ((a / ONE_SEC_MILLISECOND) + 1);
  else
    return (a / ONE_SEC_MILLISECOND);
}
