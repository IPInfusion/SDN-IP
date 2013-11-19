/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */

#include "pal.h"
#include "sys/syslog.h"

#include "pal_log.h"
#include "memory.h"

#ifdef HAVE_SPLAT
#define ZLOG_PATH_SPLAT "/var/opt/OPSEC/ipinfusion/BGP-SDN-SRS/log"
#endif /* HAVE_SPLAT */

static void
log_print (FILE *fp, char *pristr, const char *protostr, char *msgstr)
{
  char buf[TIME_BUF];
  time_t now;
  int ret;
  struct tm *tm;

  time (&now);
  tm = localtime (&now);
  ret = strftime (buf, TIME_BUF, "%Y/%m/%d %H:%M:%S", tm);

  if (! pristr || ! strlen (pristr))
    fprintf (fp, "%s %s: %s\n", ret ? buf : "(incomplete)",
             protostr, msgstr);
  else
    fprintf (fp, "%s %s: %s: %s\n", ret ? buf : "(incomplete)",
             pristr, protostr, msgstr);
  fflush (fp);
}

void *
pal_log_open (struct lib_globals *zg, struct zlog *zl, 
              enum log_destination dest)
{
  struct pal_log_data *plog;

  if (zl == NULL)
    return NULL;

  /* Close syslog connection. */
  closelog ();

  plog = XCALLOC (MTYPE_TMP, sizeof(struct pal_log_data));
  if (! plog)
    return NULL;

  plog->fp = NULL;

  /* Open syslog. */
  openlog (modname_strl (zg->protocol), LOG_CONS | LOG_NDELAY | LOG_PID, LOG_USER);
  
  return plog; 
}

void
pal_log_close (struct lib_globals *zg, struct zlog *zl)
{
  struct pal_log_data *plog;

  /* Close syslog. */
  closelog ();

  plog = zl->pal_log_data;
  if (plog)
    {
      if (plog->fp)
        {
          fclose (plog->fp);
          plog->fp = NULL;
        }

      XFREE (MTYPE_TMP, plog);
      plog = NULL;
    }
  return;
}

static u_int32_t
pal_log_get_priority (char *priority_str)
{
  if (priority_str)
    {
      if (! strcmp (priority_str, "emergencies"))
        return LOG_EMERG;
      if (! strcmp (priority_str, "alerts"))
        return LOG_ALERT;
      if (! strcmp (priority_str, "critical"))
        return LOG_CRIT;
      if (! strcmp (priority_str, "errors"))
        return LOG_ERR;
      if (! strcmp (priority_str, "warnings"))
        return LOG_WARNING;
      if (! strcmp (priority_str, "notifications"))
        return LOG_NOTICE;
      if (! strcmp (priority_str, "informational"))
        return LOG_INFO;
      if (! strcmp (priority_str, "debugging"))
        return LOG_DEBUG;
      return LOG_DEBUG;
    }

  return LOG_DEBUG;
}

void
pal_log_output (struct lib_globals *zg, struct zlog *zl,
                char *priority_str, char *mod_str, char *buf)
{
  if (zl == NULL)
    zl = zg->log_default;

  if (zl->flags & ZLOG_SYSTEM)
    {
      if (zl->record_priority)
        syslog (pal_log_get_priority(priority_str), "%s %s: %s", 
                                     priority_str, mod_str, buf);
      else
        syslog (pal_log_get_priority(priority_str), "%s: %s", mod_str, buf);
    }

  if (!zl->record_priority)
    priority_str = "";

  if (zl->flags & ZLOG_STDOUT)
    log_print (stdout, priority_str, mod_str, buf);

  if (zl->flags & ZLOG_STDERR)
    log_print (stderr, priority_str, mod_str, buf);

  if (zl->flags & ZLOG_FILE)
    {
      struct pal_log_data *plog;

      plog = (struct pal_log_data *)zl->pal_log_data;
      if (plog && plog->fp)
        log_print (plog->fp, priority_str, mod_str, buf);
    }

  return;
}

int
pal_log_rotate (struct zlog *zl)
{
  FILE *fp;
  struct pal_log_data *plog;

  pal_assert (zl != NULL);

  plog = (struct pal_log_data *)zl->pal_log_data;
  if (! plog)
    return -1;

  if (plog->fp)
    {
      fclose (plog->fp);
      plog->fp = NULL;
    }

  if (zl->logfile)
    {
      fp = fopen (zl->logfile, "w+");
      if (fp == NULL)
        return -1;
 
      plog->fp = fp;
    }

  return 0;
}

int
pal_log_set_file (struct zlog *zl, char *logfile, u_int32_t size)
{
  struct pal_log_data *plog;
  char *fullpath = NULL;
  char *cp;
  int i;
  int len, len1;
  char *cwd = NULL;

  pal_assert (zl != NULL);
  pal_assert (logfile != NULL);

  plog = (struct pal_log_data *)zl->pal_log_data;

  /* Close previous file. */
  if (zl->logfile)
    {
      if (plog->fp)
        {
          fclose (plog->fp);
          plog->fp = NULL;
        }

      zl->log_maxsize = 0;

      XFREE (MTYPE_CONFIG, zl->logfile);
      zl->logfile = NULL;
    }  

  /* Path detection. */
#ifndef HAVE_SPLAT
  if (! IS_DIRECTORY_SEP(logfile[0]))
    {
      cwd = getcwd (NULL, MAXPATHLEN + 1);

      len1 = strlen (logfile) + 1;
      zl->logfile = XMALLOC (MTYPE_CONFIG, len1);
      snprintf (zl->logfile, len1, "%s", logfile);

      len = strlen (cwd) + len1 + 1;
      fullpath = XMALLOC (MTYPE_CONFIG, len);
      if (!fullpath)
      {
        zl->log_maxsize = 0;

        XFREE (MTYPE_CONFIG, zl->logfile);
        zl->logfile = NULL;  
        if(cwd)
        {
          free(cwd);
          cwd = NULL;
        }
        return -1;
      }
      if (! strcmp (cwd, "/"))
        snprintf (fullpath, len, "%s%s", cwd, logfile);
      else
        snprintf (fullpath, len, "%s/%s", cwd, logfile);
    }
  else
    {
      fullpath = XSTRDUP (MTYPE_CONFIG, logfile);
      if (!fullpath)
        return -1;

      zl->logfile = XSTRDUP (MTYPE_CONFIG, logfile);
    }
#else /* HAVE_SPLAT */
  if (! IS_DIRECTORY_SEP(logfile[0]))
    {
      len1 = strlen(logfile) + 1;
      len = strlen (ZLOG_PATH_SPLAT) + strlen(logfile) + 2;

      zl->logfile = XMALLOC (MTYPE_CONFIG, len1);
      snprintf (zl->logfile, len1, "%s", logfile);

      fullpath = XMALLOC (MTYPE_CONFIG, len);
      if (!fullpath)
      {
        zl->log_maxsize = 0;

        XFREE (MTYPE_CONFIG, zl->logfile);
        zl->logfile = NULL;

        return -1;
      }
      snprintf (fullpath, len, "%s/%s", ZLOG_PATH_SPLAT, logfile);
    }
  else
    return -1;
#endif /* HAVE_SPLAT */

  /* Recursive mkdir. Skip leading '/' */
  len = strlen (fullpath);
  cp = fullpath;
  for (i = 1; i < len; i++)
    {
      if (cp[i] == DIR_CHAR)
        {
          cp[i] = '\0';
          mkdir (cp, 00750);
          cp[i] = DIR_CHAR;
        }
    }

  /* Open file. */
  plog->fp = fopen (fullpath, "a+");
  if (plog->fp == NULL)
    {
      if (zl->logfile)
        {
          XFREE (MTYPE_CONFIG, zl->logfile);
          zl->logfile = NULL;
        }

      if (fullpath)
        {
          XFREE (MTYPE_CONFIG, fullpath);
          fullpath = NULL;
        }

      if(cwd)
        {
          free(cwd);
          cwd = NULL;
        }
      return -1;
    }

  zl->log_maxsize = size;

  if (fullpath)
    {
      XFREE (MTYPE_CONFIG, fullpath);
      fullpath = NULL;
    }

  if (cwd)
    {
      free(cwd);
      cwd = NULL;
    } 

  return 0;
}

int
pal_log_unset_file (struct zlog *zl, char *logfile)
{
  pal_assert (zl != NULL);

  /* Path detection. */
#ifdef HAVE_SPLAT
  if (logfile && IS_DIRECTORY_SEP(logfile[0]))
    return -1;
#endif /* HAVE_SPLAT */

  if ((! logfile) || (zl->logfile && !strcmp (zl->logfile, logfile)))
    {
      if (zl->logfile)
        {
          struct pal_log_data *plog;

          plog = (struct pal_log_data *)zl->pal_log_data;
          if (plog->fp)
            {
              fclose (plog->fp);
              plog->fp = NULL;
            }

          XFREE (MTYPE_CONFIG, zl->logfile);
          zl->logfile = NULL;
        }
       else
        {
          return -1;
        }

      return 0;
    }
   else
    {
      return -1;
    }

  return 0;
}

/* Start log system. */
int
pal_log_start (struct lib_globals *zg)
{
  return 0;
}

/* Stop log system. */
int
pal_log_stop (struct lib_globals *zg)
{
  return 0;
}
