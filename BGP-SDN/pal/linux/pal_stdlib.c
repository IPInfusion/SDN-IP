/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.*/

/*
**
** pal_stdlib.c -- BGP-SDN PAL standard library calls definitions
**                 for Linux
*/

#include "pal.h"
#include "pal_stdlib.h"
#include "snprintf.h"
#include <crypt.h>

pal_handle_t
pal_stdlib_start (struct lib_globals *lib_node)
{
  return (pal_handle_t) 1;
}

result_t
pal_stdlib_stop (struct lib_globals * lib_node)
{
  return RESULT_OK;
}

/*
** Encrypt at most eight character from key using salt to perturb DES.
** Provided buffer must be at least 14 characters.
**
** Parameters
**   IN  const char *key
**   IN  const char *salt
**   OUT char *buf
**
** Results
**   Encrypts data into buf and returns buf.
*/
char *
pal_crypt (const char * key, const char * salt, char * buf)
{
  char *tmp;

  /* not safe on RTOS : needs semaphore or similar protection */
  tmp = (char *) crypt ((const char *) key, (const char *) salt);
  pal_mem_cpy (buf, tmp, (size_t) 14);
  return buf;
}

/*
** Return length of entire IP packet (based on IP header information).
**
** Parameters
**   IN  pal_in4_header iphdr
**
** Results
**   Length of IP packet.
*/
extern u_int16_t pal_in4_header_length (struct pal_in4_header *iph)
{
#ifdef GNU_LINUX
  return pal_ntoh16 (iph->ip_len);
#else
  return iph->ip_len + (iph->ip_hl << 2);
#endif /* GNU_LINUX */
}

void
pal_system_err (const char *format, ...)
{
  char buf[ZLOG_BUF_MAXLEN];
  va_list args;

  va_start (args, format); 
  zvsnprintf (buf, sizeof(buf), format, args);
  fprintf (stderr, "%s\n", buf);
  va_end (args); 

  return; 
} 

void
pal_console_err (const char *format, ...)
{
  FILE *fp;
  va_list args;
  char buf[ZLOG_BUF_MAXLEN];

  fp = fopen (PAL_CONSOLE_PATH, PAL_OPEN_RW);
  if (fp == NULL)
    return;

  va_start (args, format);
  vsnprintf (buf, sizeof buf, format, args);
  fprintf (fp, "%s\n", buf);
  va_end (args);

  fclose (fp);
}

void
pal_reboot ()
{
  (void) system ("reboot");
}

char *pal_get_sys_name ()
{
  static struct pal_utsname names;

  pal_uname (&names);

#if _UTSNAME_DOMAIN_LENGTH - 0
# ifdef __USE_GNU
    return (names.domainname);
# else
    return (names.__domainname);
# endif
#else
  return 0;
#endif

}

