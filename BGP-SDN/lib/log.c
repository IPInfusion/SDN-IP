/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */

#include "pal.h"
#include "log.h"
#include "snprintf.h"
#include "cli.h"
#include "vty.h"
#include "thread.h"

char *zlog_priority[] =
{
  "emergencies",
  "alerts",
  "critical",
  "errors",
  "warnings",
  "notifications",
  "informational",
  "debugging",
  NULL
};

char *
zlog_get_priority_str(s_int8_t prio)
{
  if (prio < ZLOG_EMERGENCY || prio > ZLOG_DEBUG)
    return "";
  else
    return zlog_priority[prio];
}

struct zlog *
zlog_new ()
{
  struct zlog *zl;

  zl = XCALLOC (MTYPE_ZLOG, sizeof(struct zlog));

  return zl;
}

void
zlog_free (struct zlog **zl)
{
  pal_assert (*zl != NULL);

  XFREE (MTYPE_ZLOG, *zl);
  *zl = NULL;

  return;
}

/* Set flag. */
static void
zlog_set_flag (struct lib_globals *zg, struct zlog *zl, u_char flags)
{
  if (zl == NULL)
    zl = zg->log_default;

  zl->flags |= flags;
}

/* Unset flags. */
static void
zlog_unset_flag (struct lib_globals *zg, struct zlog *zl, u_char flags)
{
  if (zl == NULL)
    zl = zg->log_default;

  zl->flags &= ~flags;
}

/* Open a particular log. */
struct zlog *
openzlog (struct lib_globals *zg, u_int32_t instance, module_id_t protocol,
          enum log_destination dest)
{
  struct zlog *zl = NULL;
  void *pal_log_data;

  zl = zlog_new ();
  if (zl)
    {
      zl->instance = instance;
      zl->protocol = protocol;
      zl->maskpri = ZLOG_DEBUG;
      zl->record_priority = 0;
      zl->dest = dest;

      pal_log_data = pal_log_open (zg, zl, dest);
      if (! pal_log_data)
        {
          zlog_free (&zl);
          return NULL;
        }

      /* PAL specific data. */
      zl->pal_log_data = pal_log_data;

      return zl;
    }

  return NULL;
}

/* Close log. */
void
closezlog (struct lib_globals *zg, struct zlog *zl)
{
  pal_assert ((zg != NULL) && (zl != NULL));

  if (zl)
    {
      pal_log_close (zg, zl);

      if(zl->logfile)
      {
        XFREE (MTYPE_CONFIG, zl->logfile);
        zl->logfile = NULL;
      }

      zlog_free (&zl);
    }

  return;
}

static void
vzlog (struct lib_globals *zg, struct zlog *zl, u_int32_t priority,
       const char *format, va_list args)
{
  char buf[ZLOG_BUF_MAXLEN];
  char *protostr;

  if (! zl)
    zl = zg->log_default;
  /* First prepare output string. */
  (void) zvsnprintf (buf, sizeof(buf), format, args);
  if (zl == NULL)
    {
      struct zlog tzl;

      pal_mem_set (&tzl, 0, sizeof(struct zlog));

      /* Use stderr. */
      zlog_set_flag (zg, &tzl, ZLOG_STDERR);

      pal_log_output (zg, &tzl, "", "", buf);
      return;
    }

  /* Log this information only if it has not been masked out. */
  if (priority > zl->maskpri)
    return;

  /* Protocol string. */
  protostr = modname_strl (zg->protocol);

  /* Always try to send syslog, stderr, stdout. */
  pal_log_output (zg, zl, zlog_priority[priority], protostr, buf);

  /* Log to log devices and Terminal monitor. */
  if (zl->record_priority)
    {
      vty_log (zg, zlog_priority[priority], protostr, buf);
    }
  else
    {
      vty_log (zg, "", protostr, buf);
    }
}

void
zlog (struct lib_globals *zg, struct zlog *zl, int priority,
      const char *format, ...)
{
  va_list args;

  va_start (args, format);
  vzlog (zg, zl, priority, format, args);
  va_end (args);
}

/* Log error. */
void
zlog_err (struct lib_globals *zg, const char *format, ...)
{
  va_list args;
  struct zlog *zl;

  if (zg->log)
    zl = zg->log;
  else
    zl = zg->log_default;

  va_start (args, format);
  vzlog (zg, zl, ZLOG_ERROR, format, args);
  va_end (args);
}

/* Log warning. */
void
zlog_warn (struct lib_globals *zg, const char *format, ...)
{
  va_list args;
  struct zlog *zl;

  if (zg->log)
    zl = zg->log;
  else
    zl = zg->log_default;

  va_start (args, format);
  vzlog (zg, zl, ZLOG_WARN, format, args);
  va_end (args);
}

/* Log informational. */
void
zlog_info (struct lib_globals *zg, const char *format, ...)
{
  va_list args;
  struct zlog *zl;

  if (zg->log)
    zl = zg->log;
  else
    zl = zg->log_default;

  va_start (args, format);
  vzlog (zg, zl, ZLOG_INFO, format, args);
  va_end (args);
}

/* Log debug. */
void
zlog_debug (struct lib_globals *zg, const char *format, ...)
{
  va_list args;
  struct zlog *zl;

  if (zg->log)
    zl = zg->log;
  else
    zl = zg->log_default;

  va_start (args, format);
  vzlog (zg, zl, ZLOG_INFO, format, args);
  va_end (args);
}

/* Log error to specific log destination. */
void
plog_err (struct lib_globals *zg, struct zlog *zl, const char *format, ...)
{
  va_list args;

  va_start (args, format);
  vzlog (zg, zl, ZLOG_ERROR, format, args);
  va_end (args);
}

/* Log informational to specific log destination. */
void
plog_info (struct lib_globals *zg, struct zlog *zl, const char *format, ...)
{
  va_list args;

  va_start (args, format);
  vzlog (zg, zl, ZLOG_INFO, format, args);
  va_end (args);
}

/* Rotate logs. */
void
zlog_rotate (struct lib_globals *zg, struct zlog *zl)
{
  if (zl == NULL)
    zl = zg->log_default;

  if (zl == NULL)
    return;

  pal_log_rotate (zl);
}

#ifdef PAL_LOG_STDOUT
CLI (config_log_stdout,
     config_log_stdout_cli,
     "log stdout",
     "Logging control",
     "Logging goes to stdout")
{
  struct lib_globals *zg = cli->zg;

  zlog_set_flag (zg, zg->log, ZLOG_STDOUT);

  return CLI_SUCCESS;
}

CLI (no_config_log_stdout,
     no_config_log_stdout_cli,
     "no log stdout",
     CLI_NO_STR,
     "Logging control",
     "Cancel logging to stdout")
{
  struct lib_globals *zg = cli->zg;

  zlog_unset_flag (zg, zg->log, ZLOG_STDOUT);

  return CLI_SUCCESS;
}

#endif /* PAL_LOG_STDOUT. */

#ifdef PAL_LOG_FILESYS

/* Set file params. */
static int
zlog_set_file (struct lib_globals *zg, struct zlog *zl,
               char *filename, u_int32_t size)
{
  int ret;

  if (zl == NULL)
    zl = zg->log_default;

  if (zl == NULL)
    return -1;

  zlog_set_flag (zg, zl, ZLOG_FILE);

  ret = pal_log_set_file (zl, filename, size);

  if (ret < 0)
    {
      zlog_unset_flag (zg,zl,ZLOG_FILE);
    }

  return ret;
}

/* Unset file params. */
static int
zlog_unset_file (struct lib_globals *zg, struct zlog *zl,
                 char *filename)
{
  int ret;

  if (zl == NULL)
    zl = zg->log_default;

  if (zl == NULL)
    return -1;

  if (! (zl->flags & ZLOG_FILE))
    return -1;

  ret = pal_log_unset_file (zl, filename);
  if (ret < 0)
    {
      /* Filename not matched. */
      return -1;
    }

  zl->logfile = NULL;
  zl->log_maxsize = 0;

  zlog_unset_flag (zg, zl, ZLOG_FILE);

  return 0;
}


CLI (config_log_file,
     config_log_file_cli,
     "log file FILENAME",
     "Logging control",
     "Logging to file",
     "Logging filename")
{
  struct lib_globals *zg = cli->zg;
  u_int32_t size = 0;
  int ret = 0;

  ret = zlog_set_file (zg, zg->log, argv[0], size);

  if (ret < 0)
    {
      cli_out (cli, "Specified log file %s is not set.\n", argv[0]);
      return CLI_ERROR;
    }
  return CLI_SUCCESS;
}

CLI (no_config_log_file,
     no_config_log_file_cli,
     "no log file (|FILENAME)",
     CLI_NO_STR,
     "Logging control",
     "Cancel logging to file",
     "Logging file name")
{
  struct lib_globals *zg = cli->zg;
  int ret;

  if (argc == 1)
    ret = zlog_unset_file (zg, zg->log, argv[0]);
  else
    ret = zlog_unset_file (zg, zg->log, NULL);
  if (ret < 0)
    {
      if (argc == 1)
        cli_out (cli, "Specified log file %s is not set.\n", argv[0]);
      else
        cli_out (cli, "No log file configured.\n");
      return CLI_ERROR;
    }

  return CLI_SUCCESS;
}

#endif /* PAL_LOG_FILESYS */

#ifdef PAL_LOG_SYSTEM
CLI (config_log_syslog,
     config_log_syslog_cli,
     "log syslog",
     "Logging control",
     "Logging goes to syslog")
{
  struct lib_globals *zg = cli->zg;

  zlog_set_flag (zg, zg->log, ZLOG_SYSTEM);

  return CLI_SUCCESS;
}

CLI (no_config_log_syslog,
     no_config_log_syslog_cli,
     "no log syslog",
     CLI_NO_STR,
     "Logging control",
     "Cancel logging to syslog")
{
  struct lib_globals *zg = cli->zg;

  zlog_unset_flag (zg, zg->log, ZLOG_SYSTEM);

  return CLI_SUCCESS;
}
#endif /* PAL_LOG_SYSTEM. */

CLI (config_log_trap,
     config_log_trap_cli,
     "log trap (emergencies|alerts|critical|errors|warnings|notifications|informational|debugging)",
     "Logging control",
     "Limit logging to specified level",
     "Emergencies",
     "Alerts",
     "Critical",
     "Errors",
     "Warnings",
     "Notifications",
     "Informational",
     "Debugging")
{
  int new_level ;
  struct lib_globals *zg = cli->zg;
  struct zlog *zl;

  if (! zg->log)
    zl = zg->log_default;
  else
    zl = zg->log;

  for (new_level = 0; zlog_priority[new_level] != NULL; new_level ++)
    {
      /* Find new logging level */
      if (! pal_strcmp (argv[0], zlog_priority[new_level]))
        {
          zl->maskpri = new_level;
          return CLI_SUCCESS;
        }
    }
  return CLI_ERROR;
}

CLI (no_config_log_trap,
     no_config_log_trap_cli,
     "no log trap",
     CLI_NO_STR,
     "Logging control",
     "Permit all logging information")
{
  struct lib_globals *zg = cli->zg;
  struct zlog *zl;

  if (! zg->log)
    zl = zg->log_default;
  else
    zl = zg->log;

  zl->maskpri = ZLOG_DEBUG;

  return CLI_SUCCESS;
}

CLI (config_log_record_priority,
     config_log_record_priority_cli,
     "log record-priority",
     "Logging control",
     "Log the priority of the message within the message")
{
  struct lib_globals *zg = cli->zg;
  struct zlog *zl;

  if (! zg->log)
    zl = zg->log_default;
  else
    zl = zg->log;

  zl->record_priority = 1 ;

  return CLI_SUCCESS;
}

CLI (no_config_log_record_priority,
     no_config_log_record_priority_cli,
     "no log record-priority",
     CLI_NO_STR,
     "Logging control",
     "Do not log the priority of the message within the message")
{
  struct lib_globals *zg = cli->zg;
  struct zlog *zl;

  if (! zg->log)
    zl = zg->log_default;
  else
    zl = zg->log;

  zl->record_priority = 0 ;

  return CLI_SUCCESS;
}

/* Message lookup function.  */
char *
lookup (struct message *mes, s_int32_t key)
{
  struct message *pnt;

  for (pnt = mes; pnt->key != 0; pnt++)
    {
      if (pnt->key == key)
        {
          return pnt->str;
        }
    }
  return "";
}

/* Message lookup function.  Still partly used in bgpd and ospfd. */
char *
mes_lookup (struct message *meslist, s_int32_t max, s_int32_t index)
{
  if (index < 0 || index >= max)
    return "invalid";

  return meslist[index].str;
}

void
zlog_cli_init (struct cli_tree *ctree)
{
#ifdef PAL_LOG_STDOUT
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, 0,
                   &config_log_stdout_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, 0,
                   &no_config_log_stdout_cli);
#endif /* PAL_LOG_STDOUT. */

#ifdef PAL_LOG_FILESYS
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, 0,
                   &config_log_file_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, 0,
                   &no_config_log_file_cli);
#endif /* PAL_LOG_FILESYS. */

#ifdef PAL_LOG_SYSTEM
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, 0,
                   &config_log_syslog_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, 0,
                   &no_config_log_syslog_cli);
#endif /* PAL_LOG_SYSTEM. */

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, 0,
                   &config_log_trap_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, 0,
                   &no_config_log_trap_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, 0,
                   &config_log_record_priority_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_MAX, 0,
                   &no_config_log_record_priority_cli);
}

/* Encode zlog config into vector of strings. */
int
zlog_config_encode(struct lib_globals *zg, cfg_vect_t *cv)
{
  struct zlog *zl;

  pal_assert (zg != NULL);

  if (zg->log == NULL)
    zl = zg->log_default;
  else
    zl = zg->log;

  pal_assert (zl != NULL);

#ifdef PAL_LOG_STDOUT
  if (zl->flags & ZLOG_STDOUT)
    cfg_vect_add_cmd (cv, "log stdout\n");
#endif /* PAL_LOG_STDOUT. */

#if defined(PAL_LOG_SYSTEM)
  if (zl->flags & ZLOG_SYSTEM)
    cfg_vect_add_cmd (cv, "log syslog\n");
#endif /* PAL_LOG_SYSTEM */

#ifdef PAL_LOG_FILESYS
  if (zl->flags & ZLOG_FILE)
    cfg_vect_add_cmd (cv, "log file %s\n", zl->logfile);
#endif /* PAL_LOG_FILESYS. */

  if (zl->maskpri != ZLOG_DEBUG)
    cfg_vect_add_cmd (cv, "log trap %s\n", zlog_priority[zl->maskpri]);

  if (zl->record_priority)
    cfg_vect_add_cmd (cv, "log record-priority\n");

  return 0;
}

/* Log config-write. */
int
zlog_config_write (struct cli *cli)
{
  struct lib_globals *zg = cli->zg;

  /* Currently only PVR support logging. */
  if (cli->vr->id != 0)
    return 0;
  pal_assert (zg != NULL);

  cli->cv = cfg_vect_init(cli->cv);
  zlog_config_encode(zg, cli->cv);
  cfg_vect_out(cli->cv, (cfg_vect_out_fun_t)cli->out_func, cli->out_val);
  return 0;
}

