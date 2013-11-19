/*
**
** Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.
**
** pal_time.c -- BGP-SDN PAL time operations definitions
**               for Linux
*/

/*
**
** Include files
*/
#include "pal.h"

/*
**
** Constants and enumerations
*/

/*
**
** Types
*/

/*
**
** Functions
*/

pal_handle_t
pal_time_start (struct lib_globals *lib_node)
{
  return (pal_handle_t) 1;
}

extern result_t
pal_time_stop (struct lib_globals *lib_node)
{
  return RESULT_OK;
}

#define WRAPAROUND_VALUE (0xffffffffUL / HZ + 1) /* HZ = frequency of ticks
                                                    per second. */

/* Static function to get current sec and usec.  */
static int
system_uptime (struct pal_timeval *tv, struct pal_tzval *tz)
{
  struct sysinfo info;
  static unsigned long prev = 0;
  static unsigned long wraparound_count = 0;
  unsigned long uptime;
  static long base = 0;
  static long offset = 0;
  long leap;
  long diff;
  
  /* Get sysinfo.  */
  if (sysinfo (&info) < 0)
    return RESULT_ERROR;

  /* Check for wraparound. */
  if (prev > info.uptime)
    wraparound_count++;
  
  /* System uptime.  */
  uptime = wraparound_count * WRAPAROUND_VALUE + info.uptime;
  prev = info.uptime;      
  
  /* Get tv_sec and tv_usec.  */
  gettimeofday (tv, tz);

  /* Deffernce between gettimeofday sec and uptime.  */
  leap = tv->tv_sec - uptime;

  /* Basically we use gettimeofday's return value because it is the
     only way to get required granularity.  But when diff is very
     different we adjust the value using base value.  */
  diff = (leap - base) + offset;

  /* When system time go forward than 2 sec.  */
  if (diff > 2 || diff < -2)
    offset -= diff;

  /* Adjust second.  */
  tv->tv_sec += offset;

  return RESULT_OK;
}

/*!
** Return current time.
**
** Parameters
**   OUT pal_time_t *tp : A pointer to pal_time_t
**
** Results
**   -1 for error or pal_time_t.
*/
pal_time_t
pal_time_current (pal_time_t *tp)
{
  struct pal_timeval tv;
  int ret;

  /* Get current time i.e. time since reboot. */
  ret = system_uptime (&tv, NULL);
  if (ret != RESULT_OK)
    return -1;

  /* When argument is specified copy value.  */
  if (tp)
    *tp = (pal_time_t) tv.tv_sec;

  return tv.tv_sec;
}

pal_time_t
pal_time_since_boot ()
{
    
  struct sysinfo info;
  static unsigned long prev = 0;
  static unsigned long wraparound_count = 0;
    
  /* Get sysinfo.  */
  if (sysinfo (&info) < 0)
    return RESULT_ERROR;
    
  /* Check for wraparound. */
  if (prev > info.uptime)
    wraparound_count++;
    
  /* System uptime.  */
  prev = info.uptime;
    
  return info.uptime;
}

/*!
** Return current time based on timezone. 
**  NOTE: timezone is not supported. Pass this as NULL.
**
** Parameters
**   OUT struct pal_timeval *tv : A pointer to the timeval structure.
**   OUT struct pal_tzval *tz   : A pointer to timezone value.
**
** Results
**   
*/

/* There is a case that system time is changed.  */
void
pal_time_tzcurrent (struct pal_timeval *tv,
                    struct pal_tzval *tz)
{
  system_uptime (tv, tz);
  return;
}

/*!
** Take a local time and convert it to GMT (UTC), in expanded form.
**
** replaces gmtime()
**
** Parameters
**   IN  pal_time_t *tp         : A pointer to the time to convert
**   OUT struct pal_tm *gmt     : A pointer to where to put the expanded GMT
**
** Results
**   RESULT_OK for success, else the error which occurred
*/
result_t
pal_time_gmt (pal_time_t * tp, struct pal_tm *gmt)
{
  struct pal_tm *tmp;

  tmp = gmtime (tp);
  if (tmp)
    {
      pal_mem_cpy (gmt, tmp, sizeof (struct pal_tm));
    }
  return (tmp ? RESULT_OK : EAGAIN);
}

/*!
** Take a local time and convert it into expanded form.
**
** replaces localtime()
**
** Parameters
**   IN  pal_time_t *tp         : A pointer to the time to convert
**   OUT struct pal_tm *loc     : A pointer to where to put the expanded form
**
** Results
**   RESULT_OK for success, else the error which occurred
*/
result_t
pal_time_loc (pal_time_t * tp, struct pal_tm *loc)
{
  struct pal_tm *tmp;
  /*
  ** This isn't thread safe, but Linux doesn't matter since the
  ** threads are run by our own scheduler and each daemon uses
  ** different memory space.  RTOS can't assume so.
  */
  tmp = localtime (tp);
  if (tmp)
    {
      pal_mem_cpy (loc, tmp, sizeof (struct pal_tm));
    }
  return (tmp ? RESULT_OK : EAGAIN);
};

/*!
** Convert the calendar time into string form. The calendar time is often
** obtained through a call to pal_time_current ();
** This function is used to replaced ctime();
**
** Parameters
**   IN  const pal_time_t *tp    :  A pointer to the time_t to use
**   OUT char *buf             :  pointer to character buffer
**
** Results
**   RESULT_OK on success. 
*/
result_t 
pal_time_calendar (const pal_time_t *tp,
                   char *buf) {
  strcpy (buf, ctime (tp));
  return RESULT_OK;
}

/*!
** Delay a process; delay units are in microseconds
**
** replaces usleep ()
**
** Parameters
**   IN  pal_time_t t_usec   : Number of microseconds to delay process
**
** Results
**   RESULT_OK for success, else the error which occurred
*/
result_t
pal_delay (pal_time_t t_usec)
{
  result_t ret;

  ret = RESULT_OK;

  if (! t_usec)
    ret = usleep (1);
  else if (t_usec > TV_USEC_PER_SEC)
    ret = sleep (t_usec / TV_USEC_PER_SEC);
  else
    ret = usleep (t_usec);

  return (ret);
}

result_t
pal_set_time (struct pal_timeval *set_time)
{
  return settimeofday(set_time, NULL);
}

result_t
pal_get_time (struct pal_timeval *get_time)
{
  return gettimeofday(get_time, NULL);
}
/*-----------------------------------------------------------------------------
**
** Done
*/
