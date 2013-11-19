/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"


pid_t
pal_syslog_getpid (void)
{
  FILE *fp;
  char buf[10];
  pid_t pid = 0;

  fp = fopen (SYSLOG_PIDFILE, PAL_OPEN_RO);
  if (fp == NULL)
    return pid;

  if ((fgets (buf, sizeof buf, fp) != NULL))
    pid = atoi (buf);

  fclose (fp);

  return pid;
}

void
pal_syslog_restart (void)
{
  pid_t pid;

  pid = pal_syslog_getpid ();
  if (pid > 0)
    kill (pid, SIGHUP);
}
