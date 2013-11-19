/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <pal.h>

#include "bgpsdn_version.h"
#include "host.h"
#include "cli.h"
#include "show.h"
#include "line.h"
#include "log.h"
#include "thread.h"
#include "snprintf.h"
#include "imi_client.h"


struct host_user *
host_user_new (char *name)
{
  struct host_user *new;

  new = XCALLOC (MTYPE_TMP, sizeof (struct host_user));
  new->name = XSTRDUP (MTYPE_TMP, name);

  return new;
}

void
host_user_free (struct host *host, struct host_user *user)
{
  if (user->name)
    XFREE (MTYPE_TMP, user->name);
  if (user->password)
    XFREE (MTYPE_CONFIG_PASSWORD, user->password);
  if (user->password_encrypt)
    XFREE (MTYPE_CONFIG_PASSWORD, user->password_encrypt);

  listnode_delete (host->users, user);

  XFREE (MTYPE_TMP, user);
}

struct host_user *
host_user_lookup (struct host *host, char *name)
{
  struct host_user *user;
  struct listnode *node;

  LIST_LOOP (host->users, user, node)
    if (pal_strcmp (user->name, name) == 0)
      return user;

  return NULL;
}

struct host_user *
host_user_get (struct host *host, char *name)
{
  struct host_user *user;

  user = host_user_lookup (host, name);
  if (user != NULL)
    return user;

  user = host_user_new (name);
  user->privilege = 1;
  listnode_add (host->users, user);

  if (host->vr->zg->user_callback[USER_CALLBACK_UPDATE])
    (*host->vr->zg->user_callback[USER_CALLBACK_UPDATE]) (host->vr, user);

  return user;
}

void
host_user_delete (struct host *host, char *name)
{
  struct host_user *user;

  user = host_user_lookup (host, name);
  if (user != NULL)
    {
      if (host->vr->zg->user_callback[USER_CALLBACK_DELETE])
        (*host->vr->zg->user_callback[USER_CALLBACK_DELETE]) (host->vr, user);

      host_user_free (host, user);
    }
}

void
host_user_update (struct host *host, char *name, int privilege,
                  char *password, char *password_encrypt)
{
  struct host_user *user = NULL;
  if (name)
    user = host_user_lookup (host, name);
  if (user != NULL)
    {
      /* Reset passwords. */
      if (user->password)
        {
          XFREE (MTYPE_CONFIG_PASSWORD, user->password);
          user->password = NULL;
        }
      if (user->password_encrypt)
        {
          XFREE (MTYPE_CONFIG_PASSWORD, user->password_encrypt);
          user->password_encrypt = NULL;
        }

      /* Set new values. */
      if (privilege >= 0)
        user->privilege = privilege;

      if (password != NULL)
        user->password = XSTRDUP (MTYPE_CONFIG_PASSWORD, password);

      if (password_encrypt != NULL)
        user->password_encrypt = XSTRDUP (MTYPE_CONFIG_PASSWORD,
                                          password_encrypt);

      if (host->vr->zg->user_callback[USER_CALLBACK_UPDATE])
        (*host->vr->zg->user_callback[USER_CALLBACK_UPDATE]) (host->vr, user);
    }
}

void
host_user_add_callback (struct lib_globals *zg, enum user_callback_type type,
                        int (*func) (struct ipi_vr *, struct host_user *))
{
  if (type < 0 || type >= USER_CALLBACK_MAX)
    return;

  zg->user_callback[type] = func;
}


/* Allocate a new host structure.  */
struct host *
host_new (struct ipi_vr *vr)
{
  struct host *host;

  host = XCALLOC (MTYPE_HOST, sizeof (struct host));
  host->vr = vr;
  host->motd = vr->zg->motd;
  host->lines = -1;
  host->config_lock = NULL;
  host->users = list_new ();
  SET_FLAG (host->flags, HOST_ADVANCED_VTY);
#ifndef HAVE_IMISH
  host->timeout = VTY_TIMEOUT_DEFAULT;
  SET_FLAG (host->flags, HOST_LOGIN);
#endif /* HAVE_IMISH */

#ifdef HAVE_VRX
  host->localifindex = -1;
#endif /* HAVE_VRX */
#ifdef HAVE_NO_STORAGE_DEV
  UNSET_FLAG (host->flags, HOST_LOGIN);
#endif

  return host;
}

void
host_free (struct host *host)
{
  struct listnode *node, *next;

  for (node = LISTHEAD (host->users); node; node = next)
    {
      next = node->next;
      if (node->data)
        host_user_free (host, node->data);
    }
  list_delete (host->users);

#ifndef HAVE_IMISH
  if (host->aclass_ipv4)
    XFREE (MTYPE_VTY, host->aclass_ipv4);
#ifdef HAVE_IPV6
  if (host->aclass_ipv6)
    XFREE (MTYPE_VTY, host->aclass_ipv6);
#endif /* HAVE_IPV6 */
#endif /* HAVE_IMISH */

  /* Free the configuration file.  */
  if (host->config_file != NULL)
    XFREE (MTYPE_CONFIG, host->config_file);

  XFREE (MTYPE_HOST, host);
}

/* Generic function to lock configuration.  */
int
host_config_lock (struct host *host, void *locker)
{
#ifndef HAVE_MULTI_CONF_SES
  if (host)
    {
      if (host->config_lock)
        return -1;
      host->config_lock = locker;
    }
#endif
  return 0;
}

/* Generic function to unlock configuration.  */
int
host_config_unlock (struct host *host, void *locker)
{
#ifndef HAVE_MULTI_CONF_SES
  if (host)
    {
      if (host->config_lock != locker)
        return -1;
      host->config_lock = NULL;
    }
#endif
  return 0;
}

void
host_config_file_set (struct ipi_vr *vr)
{
  char *path;
  char buf[MAXPATHLEN];
  char file[MAXPATHLEN];
  struct host *host = vr->host;

  if (host->config_file)
    XFREE (MTYPE_CONFIG, host->config_file);

  /* Get the configuration file name.  */
  if (vr->zg->protocol == IPI_PROTO_IMI)
    zsnprintf (file, sizeof file, "BGP-SDN.%s", PAL_FILE_SUFFIX);
  else
    zsnprintf (file, sizeof file, "%s.%s",
               modname_strs (vr->zg->protocol), PAL_FILE_SUFFIX);

  /* Get the path name.  */
  if (vr->name)
    {
      zsnprintf (buf, sizeof buf, "%s%c%s",
                 vr->zg->cwd, PAL_FILE_SEPARATOR, vr->name);
      path = buf;
    }
  else
    path = vr->zg->cwd;

  /* Make sure the path existence.  */
  pal_mkdir (path, PAL_DIR_MODE);

  /* Create a configuration file name.  */
  zsnprintf (buf, sizeof buf, "%s%c%s", path, PAL_FILE_SEPARATOR, file);

  host->config_file = XSTRDUP (MTYPE_CONFIG, buf);
}

void
host_startup_config_file_set (struct ipi_vr *vr, char *config_file)
{
  int i;
  FILE *fp;
  char *path, *old_cwd;
  char buf[MAXPATHLEN];
  char file[MAXPATHLEN];
  struct host *host = vr->host;

  if (host->config_file)
    XFREE (MTYPE_CONFIG, host->config_file);

  if (config_file == NULL)
    {
      /* Get the configuration file name.  */
#ifdef HAVE_IMI
        zsnprintf (file, sizeof file, "BGP-SDN.%s", PAL_FILE_SUFFIX);
#else
        zsnprintf (file, sizeof file, "%s.%s",
                   modname_strs (vr->zg->protocol), PAL_FILE_SUFFIX);
#endif /* HAVE_IMI */
      config_file = file;

      /* Check if the configuration file exists
         on the current working directory in PVR case.  */
      zsnprintf (buf, sizeof buf, "%s%c%s",
                 vr->zg->cwd, PAL_FILE_SEPARATOR, config_file);

      fp = pal_fopen (buf, PAL_OPEN_RO);
      if (fp != NULL)
        pal_fclose (fp);
      else
        {
          /* If not, use global path.  */
          XFREE (MTYPE_CONFIG, vr->zg->cwd);
          vr->zg->cwd = XSTRDUP (MTYPE_CONFIG, PATH_SYSCONFDIR);
        }
    }
  else
    {
      /* Update the current working directory by the specified path.  */
      for (i = pal_strlen (config_file); i > 0; i--)
        if (config_file[i] == PAL_FILE_SEPARATOR)
          {
            config_file[i] = '\0';
            old_cwd = vr->zg->cwd;
            if (config_file[0] == PAL_FILE_SEPARATOR)
              vr->zg->cwd = XSTRDUP (MTYPE_CONFIG, config_file);
            else
              {
                zsnprintf (buf, sizeof buf, "%s%c%s", vr->zg->cwd,
                           PAL_FILE_SEPARATOR, config_file);
                vr->zg->cwd = XSTRDUP (MTYPE_CONFIG, buf);
              }
            XFREE (MTYPE_CONFIG, old_cwd);

            /* Get the configuration file name.  */
            config_file = &config_file[i + 1];
            break;
          }
    }

  /* Get the path name.  */
  if (vr->name)
    {
      zsnprintf (buf, sizeof buf, "%s%c%s",
                 vr->zg->cwd, PAL_FILE_SEPARATOR, vr->name);
      path = buf;
    }
  else
    path = vr->zg->cwd;

  /* Make sure the path existence.  */
  pal_mkdir (path, PAL_DIR_MODE);

  /* Create a configuration file name.  */
  zsnprintf (buf, sizeof buf, "%s%c%s", path, PAL_FILE_SEPARATOR, config_file);

  host->config_file = XSTRDUP (MTYPE_CONFIG, buf);
}

int
host_config_read (struct ipi_vr *vr)
{
  int ret;
  FILE *fp;
  int length;
  char buf[BUFSIZ];
  struct vty *vty;
  struct cli cli;
  struct cli_node *node;
  struct cli_tree *ctree = vr->zg->ctree;

  fp = pal_fopen (vr->host->config_file, PAL_OPEN_RO);
  if (fp == NULL)
    return -1;

  /* Create pseudo vty structure.  */
  vty = vty_new (vr->zg);
  vty->server = vr->zg->vty_master;

  /* Prepare CLI structure.  */
  cli.zg = vr->zg;
  cli.vr = vr;
  cli.line = vty;
  cli.mode = CONFIG_MODE;
  cli.source = CLI_SOURCE_FILE;
  cli.out_val = vr->zg;
  cli.out_func = (CLI_OUT_FUNC) zlog_info;
  cli.index = NULL;

  while (pal_fgets (buf, BUFSIZ, fp))
    {
      /* New line should be removed.  */
      length = pal_strlen (buf);
      if (length-- > 0)
        buf[length] = '\0';

      ret = cli_parse (ctree, cli.mode, PRIVILEGE_MAX, buf, 1, 0);

      switch (ret)
        {
        case CLI_PARSE_EMPTY_LINE:
          /* Simply ignore empty line.  */
          break;
        case CLI_PARSE_SUCCESS:
          node = ctree->exec_node;

          if (node->cel->func)
            ret = (*node->cel->func) (&cli, ctree->argc, ctree->argv);

          break;
        case CLI_PARSE_INCOMPLETE:
        case CLI_PARSE_INCOMPLETE_PIPE:
        case CLI_PARSE_AMBIGUOUS:
        case CLI_PARSE_NO_MATCH:
        case CLI_PARSE_NO_MODE:
        case CLI_PARSE_ARGV_TOO_LONG:
          /* Second try.  */

          /* Free the previous arguments.  */
          cli_free_arguments (ctree);

          cli.mode = CONFIG_MODE;

          ret = cli_parse (ctree, cli.mode, PRIVILEGE_MAX, buf, 1, 0);

          switch (ret)
            {
            case CLI_PARSE_SUCCESS:
              node = ctree->exec_node;

              if (node->cel->func)
                ret = (*node->cel->func) (&cli, ctree->argc, ctree->argv);

              break;
            default:
              break;
            }

          break;
        default:
          break;
        }

      /* Free arguments.  */
      cli_free_arguments (ctree);
    }

  vty_close (vty);

  /* Close the configuration file.  */
  pal_fclose (fp);

  SET_FLAG (vr->host->flags, HOST_CONFIG_READ_DONE);

  return 0;
}

int
host_config_read_event (struct thread *thread)
{
  struct ipi_vr *vr = THREAD_ARG (thread);

  vr->t_config = NULL;

  LIB_GLOB_SET_VR_CONTEXT (vr->zg, vr);

  if (vr->zg->vr_callback[VR_CALLBACK_CONFIG_READ])
    (*vr->zg->vr_callback[VR_CALLBACK_CONFIG_READ]) (vr);

  return 0;
}

/* Write configuration to a particular file.  */
int
host_config_out (FILE *fp, const char *format, ...)
{
  va_list args;
  char buf[BUFSIZ];

  va_start (args, format);
  zvsnprintf (buf, sizeof (buf), format, args);
  va_end (args);

  return pal_fputs (buf, fp);
}

int
host_config_write_file (struct cli *cli, struct ipi_vr *vr)
{
  int i;
  FILE *fp;
  char buf[BUFSIZ];
  pal_time_t curtime;
  struct pal_tm exptime;
  CLI_CONFIG_FUNC func;
  struct cli cliout;
  struct cli_tree *ctree = vr->zg->ctree;
  char tmp_buf[80];

  fp = pal_fopen (vr->host->config_file, PAL_OPEN_RW);
  if (fp == NULL)
    return -1;

  curtime = pal_time_sys_current (NULL);
  pal_time_loc (&curtime, &exptime);
  pal_time_strf (buf, BUFSIZ, "%Y/%m/%d %H:%M:%S", &exptime);

  ctree = vr->zg->ctree;
  cliout = *cli;
  cliout.out_func = (CLI_OUT_FUNC) host_config_out;
  cliout.out_val = fp;

  cli_out (&cliout, "!\n! Config for BGP-SDN%s\n!\n",
           bgpsdn_copyright (tmp_buf, 80));

  for (i = 0; i < vector_max (ctree->config_write); i++)
    if ((func = vector_slot (ctree->config_write, i)))
      if ((*func) (&cliout))
        cli_out (&cliout, "!\n");

  cli_out (&cliout, "end\n\n");

  pal_fclose (fp);

  return 0;
}


/* Shell prompt.  */
char *
host_prompt (struct host *host, struct cli *cli)
{
  struct pal_utsname names;
  static char prompt[MAX_HOSTNAME_LEN];
  char sign = '>';
  char *hostname = "router";

  if (cli->mode == LOGIN_MODE)
    return "Username: ";

  if (cli->mode == AUTH_MODE || cli->mode == AUTH_ENABLE_MODE)
    return "Password:";

  if ((host) && (host->name))
    hostname = host->name;

  if (! hostname)
    {
      pal_uname (&names);
      hostname = names.nodename;
    }

  if (cli->privilege >= PRIVILEGE_ENABLE (cli->vr))
    sign = '#';

  zsnprintf (prompt, MAX_HOSTNAME_LEN, "%s%s%c", hostname,
             cli_prompt_str (cli->mode), sign);

  return prompt;
}

int
host_hostname_set (struct ipi_vr *vr, char *hostname)
{
  struct host *host = vr->host;

#ifdef HAVE_HOSTNAME_CHANGE
  if (sethostname (hostname, pal_strlen (hostname) + 1) < 0)
    {
      return errno;
    }
#endif /* HAVE_HOSTNAME_CHANGE */

  if (host->name)
    XFREE (MTYPE_CONFIG, host->name);

  host->name = XSTRDUP (MTYPE_CONFIG, hostname);

  if (host->hostname_callback)
    (*host->hostname_callback) (vr);

  return HOST_NAME_SUCCESS;
}

int
host_hostname_unset (struct ipi_vr *vr, char *hostname)
{
  struct host *host = vr->host;

#ifdef HAVE_HOSTNAME_CHANGE
  if (sethostname ("Router", pal_strlen ("Router") + 1) < 0)
    {
      return errno;
    }
#endif /* HAVE_HOSTNAME_CHANGE */

  if (host->name)
    {
      if (hostname)
        if(pal_strcmp (host->name, hostname))
          return HOST_NAME_NOT_FOUND;

      XFREE (MTYPE_CONFIG, host->name);
      host->name = NULL;
    }
  else
    return HOST_NAME_NOT_CONFIGURED;

  if (host->hostname_callback)
    (*host->hostname_callback) (vr);

  return HOST_NAME_SUCCESS;
}

int
host_hostname_set_callback (struct ipi_vr *vr, HOST_CALLBACK func)
{
  if (vr->host == NULL)
    return 0;

  vr->host->hostname_callback = func;

  return 1;
}


/* CLIs.  */
CLI (host_enable,
     host_enable_cli,
     "enable",
     "Turn on privileged mode command")
{
  struct host *host = cli->vr->host;

  if (cli->privilege == PRIVILEGE_ENABLE (cli->vr))
    return CLI_SUCCESS;

  /* If enable password is NULL, change to ENABLE_NODE */
  if (host->enable == NULL && host->enable_encrypt == NULL)
    cli->privilege = PRIVILEGE_ENABLE (cli->vr);
  else
    cli->mode = AUTH_ENABLE_MODE;

  return CLI_SUCCESS;
}

/* Disable command */
CLI (host_disable,
     host_disable_cli,
     "disable",
     "Turn off privileged mode command")
{
  cli->privilege = PRIVILEGE_NORMAL;
  return CLI_SUCCESS;
}

/* Show version.  */
CLI (show_version,
     show_version_cli,
     "show version",
     CLI_SHOW_STR,
     "Display BGP-SDN version")
{
  char buf1[50], buf2[50];
  char *str = PLATFORM;

  cli_out (cli, "BGP-SDN version %s%s%s %s\n",
           bgpsdn_version (buf1, 50),
           pal_strlen (str) ? " " : "", str,
           BUILDDATE);
  cli_out (cli, " Build # is %s on host %s\n",
           bgpsdn_buildno (buf2, 50),
           host_name);
  cli_out (cli, " %s\n", IPI_COPYRIGHT);

#ifdef IPNET
  cli_out (cli, " %s\n", "" );
#endif

#ifdef HAVE_LICENSE_MGR
  cli_out (cli, " %s\n",THIRD_PARTY_SOFTWARE_COPYRIGHT);
#endif /* HAVE_LICENSE_MGR */

  return CLI_SUCCESS;
}

/* Show startup configuration file. */
CLI (host_show_startup_config,
     host_show_startup_config_cli,
     "show startup-config",
     CLI_SHOW_STR,
     "Contents of startup configuration")
{
  FILE *fp;
  char buf[BUFSIZ];
  struct ipi_vr *vr = cli->vr;

  /* Open the file. */
  fp = pal_fopen (vr->host->config_file, PAL_OPEN_RO);
  if (fp == NULL)
    {
      cli_out (cli, "%% Can't open startup-config\n");
      return CLI_ERROR;
    }

  while (pal_fgets (buf, BUFSIZ, fp))
    cli_out (cli, "%s", buf);

  pal_fclose (fp);

  return CLI_SUCCESS;
}

/* Configration from terminal.  */
CLI (config_terminal,
     config_terminal_cli,
     "configure terminal",
     "Enter configuration mode",
     "Configure from the terminal")
{
  if (cli->vr->host)
    if (host_config_lock (cli->vr->host, cli) < 0)
      {
        cli_out (cli, "VTY configuration is locked by other VTY\n");
        return CLI_ERROR;
      }

  cli->mode = CONFIG_MODE;

  return CLI_SUCCESS;
}

/* Hostname configuration.  */
CLI (host_hostname,
     host_hostname_cli,
     "hostname WORD",
     "Set system's network name",
     "This system's network name")
{
  s_int32_t ret = 0;
  ret = host_hostname_set (cli->vr, argv[0]);

  if (ret == HOST_NAME_SUCCESS)
    return CLI_SUCCESS;
#ifdef HAVE_HOSTNAME_CHANGE
  else
    cli_out (cli, "%% %s\n", pal_strerror (ret));
#endif /* HAVE_HOSTNAME_CHANGE */
  return CLI_ERROR;

}

CLI (no_host_hostname,
     no_host_hostname_cli,
     "no hostname (WORD|)",
     CLI_NO_STR,
     "Reset system's network name",
     "This system's network name")
{
  s_int32_t ret = 0;
  if (argc)
    ret = host_hostname_unset (cli->vr, argv[0]);
  else
    ret = host_hostname_unset (cli->vr, NULL);

  if (ret == HOST_NAME_SUCCESS)
    return CLI_SUCCESS;
  else if (ret == HOST_NAME_NOT_FOUND)
    cli_out (cli, "%% Hostname not found.\n");
  else if (ret == HOST_NAME_NOT_CONFIGURED)
    cli_out (cli, "%% Default Hostname cannot be removed.\n");
#ifdef HAVE_HOSTNAME_CHANGE
  else
    cli_out (cli, "%% %s", pal_strerror (ret));
#endif /* HAVE_HOSTNAME_CHANGE */
  return CLI_ERROR;
}

/* Banner configuration.  */
CLI (banner_motd_custom,
     banner_motd_custom_cli,
     "banner motd LINE",
     "Define a login banner",
     "Set Message of the Day banner",
     "Custom string")
{
  struct host *host = cli->vr->host;

  if (host->motd != cli->zg->motd && host->motd != NULL)
    XFREE (MTYPE_TMP, host->motd);

  host->motd = XSTRDUP (MTYPE_TMP, argv[0]);

  return CLI_SUCCESS;
}

CLI (banner_motd_default,
     banner_motd_default_cli,
     "banner motd default",
     "Define a login banner",
     "Set Message of the Day banner",
     "Default string")
{
  struct host *host = cli->vr->host;

  if (host->motd != cli->zg->motd && host->motd != NULL)
    XFREE (MTYPE_TMP, host->motd);
  host->motd = cli->zg->motd;
  return CLI_SUCCESS;
}

CLI (no_banner_motd,
     no_banner_motd_cli,
     "no banner motd",
     CLI_NO_STR,
     "Define a login banner",
     "Set Message of the Day banner")
{
  struct host *host = cli->vr->host;

  if (host->motd != cli->zg->motd && host->motd != NULL)
    XFREE (MTYPE_TMP, host->motd);

  host->motd = NULL;

  return CLI_SUCCESS;
}


static const u_char itoa64[] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void
to64 (char * s, long v, int n)
{
  while (--n >= 0)
    {
      *s++ = itoa64[v & 0x3f];
      v >>= 6;
    }
}

static char *
zencrypt (char * passwd, char * buf)
{
  char salt[6];
  struct pal_timeval tv;

  pal_time_tzcurrent (&tv, 0);

  to64 (&salt[0], pal_rand (), 3);
  to64 (&salt[3], tv.tv_usec, 3);
  salt[5] = '\0';

  pal_crypt (passwd, salt, buf);
  return buf;
}

/* VTY interface to set password. */
CLI (host_password,
     host_password_cli,
     "password (8|) LINE",
     "Assign the terminal connection password",
     "Specifies a HIDDEN password will follow",
     "The HIDDEN line password string")
{
  struct host *host = cli->vr->host;
  char cryptbuf[16];

  if (argc == 2)
    {
      if (*argv[0] == '8')
        {
          if (host->password)
            XFREE (MTYPE_CONFIG_PASSWORD, host->password);
          host->password = NULL;

          if (host->password_encrypt)
            XFREE (MTYPE_CONFIG_PASSWORD, host->password_encrypt);

          host->password_encrypt = XSTRDUP (MTYPE_CONFIG_PASSWORD, argv[1]);

          return CLI_SUCCESS;
        }
      else
        {
          cli_out (cli, "%% Unknown encryption type.\n");
          return CLI_ERROR;
        }
    }

  if (! pal_char_isalnum ((int) *argv[0]))
    {
      cli_out (cli, "%% Please specify string starting with alphanumeric\n");
      return CLI_ERROR;
    }

  if (host->password)
    XFREE (MTYPE_CONFIG_PASSWORD, host->password);
  host->password = NULL;

  if (host->password_encrypt)
    XFREE (MTYPE_CONFIG_PASSWORD, host->password_encrypt);
  host->password_encrypt = NULL;

  if (CHECK_FLAG (host->flags, HOST_PASSWORD_ENCRYPT))
    host->password_encrypt = XSTRDUP (MTYPE_CONFIG_PASSWORD,
                                      zencrypt (argv[0], cryptbuf));
  else
    host->password = XSTRDUP (MTYPE_CONFIG_PASSWORD, argv[0]);

  return CLI_SUCCESS;
}

/* Remove enable password. */
CLI (no_host_password,
     no_host_password_cli,
     "no password",
     CLI_NO_STR,
     "Assign the terminal connection password")
{
  struct host *host = cli->vr->host;

  if (host->password)
    XFREE (MTYPE_CONFIG_PASSWORD, host->password);
  host->password = NULL;

  if (host->password_encrypt)
    XFREE (MTYPE_CONFIG_PASSWORD, host->password_encrypt);
  host->password_encrypt = NULL;

  return CLI_SUCCESS;
}

/* Enable password.  */
CLI (host_enable_password,
     host_enable_password_cli,
     "enable password (8|) LINE",
     "Modify enable password parameters",
     "Assign the privileged level password",
     "Specifies a HIDDEN password will follow",
     "The HIDDEN 'enable' password string")
{
  struct host *host = cli->vr->host;
  char cryptbuf[16];

  /* Argument check. */
  if (argc == 0)
    {
      cli_out (cli, "Please specify password.\n");
      return CLI_ERROR;
    }

  /* Crypt type is specified. */
  if (argc == 2)
    {
      if (*argv[0] == '8')
        {
          if (host->enable)
            XFREE (MTYPE_CONFIG_PASSWORD, host->enable);
          host->enable = NULL;

          if (host->enable_encrypt)
            XFREE (MTYPE_CONFIG_PASSWORD, host->enable_encrypt);
          host->enable_encrypt = XSTRDUP (MTYPE_CONFIG_PASSWORD, argv[1]);

          return CLI_SUCCESS;
        }
      else
        {
          cli_out (cli, "%% Unknown encryption type.\n");
          return CLI_ERROR;
        }
    }

  if (!pal_char_isalnum ((int) * argv[0]))
    {
      cli_out (cli, "Please specify string starting with alphanumeric\n");
      return CLI_ERROR;
    }

  if (pal_strlen (argv[0]) > HOST_MAX_PASSWD_LEN)
    {
      /* Limiting the password since DES-based encryption crypt() will
         encrypt only first 8 characters */
      cli_out (cli, "Password exceeds Max of 8 characters\n");
      return CLI_ERROR;
    }

  if (host->enable)
    XFREE (MTYPE_CONFIG_PASSWORD, host->enable);
  host->enable = NULL;

  if (host->enable_encrypt)
    XFREE (MTYPE_CONFIG_PASSWORD, host->enable_encrypt);
  host->enable_encrypt = NULL;

  /* Plain password input. */
  if (CHECK_FLAG (host->flags, HOST_PASSWORD_ENCRYPT))
    host->enable_encrypt = XSTRDUP (MTYPE_CONFIG_PASSWORD,
                                    zencrypt (argv[0], cryptbuf));
  else
    host->enable = XSTRDUP (MTYPE_CONFIG_PASSWORD, argv[0]);

  return CLI_SUCCESS;
}

/* Remove enable password. */
CLI (no_host_enable_password,
     no_host_enable_password_cli,
     "no enable password",
     CLI_NO_STR,
     "Modify enable password parameters",
     "Assign the privileged level password")
{
  struct host *host = cli->vr->host;

  if (host->enable)
    XFREE (MTYPE_CONFIG_PASSWORD, host->enable);
  host->enable = NULL;

  if (host->enable_encrypt)
    XFREE (MTYPE_CONFIG_PASSWORD, host->enable_encrypt);
  host->enable_encrypt = NULL;

  return CLI_SUCCESS;
}

ALI (no_host_enable_password,
     no_host_enable_password_arg_cli,
     "no enable password LINE",
     CLI_NO_STR,
     "Modify enable password parameters",
     "Assign the privileged level password",
     "Password string");

/* Service password encryption.  */
CLI (service_password_encrypt,
     service_password_encrypt_cli,
     "service password-encryption",
     "Modify use of network based services",
     "Encrypt system passwords")
{
  struct host *host = cli->vr->host;
  char cryptbuf[16];

  if (CHECK_FLAG (host->flags, HOST_PASSWORD_ENCRYPT))
    return CLI_SUCCESS;

  SET_FLAG (host->flags, HOST_PASSWORD_ENCRYPT);

  if (host->password)
    {
      if (host->password_encrypt)
        XFREE (MTYPE_CONFIG_PASSWORD, host->password_encrypt);
      host->password_encrypt = XSTRDUP (MTYPE_CONFIG_PASSWORD,
                                        zencrypt (host->password, cryptbuf));

      XFREE (MTYPE_CONFIG_PASSWORD, host->password);
      host->password = NULL;
    }
  if (host->enable)
    {
      if (host->enable_encrypt)
        XFREE (MTYPE_CONFIG_PASSWORD, host->enable_encrypt);
      host->enable_encrypt = XSTRDUP (MTYPE_CONFIG_PASSWORD,
                                      zencrypt (host->enable, cryptbuf));

      XFREE (MTYPE_CONFIG_PASSWORD, host->enable);
      host->enable = NULL;
    }
  return CLI_SUCCESS;
}

CLI (no_service_password_encrypt,
     no_service_password_encrypt_cli,
     "no service password-encryption",
     CLI_NO_STR,
     "Set up miscellaneous service",
     "Enable encrypted passwords")
{
  struct host *host = cli->vr->host;


  if (! CHECK_FLAG (host->flags, HOST_PASSWORD_ENCRYPT))
    return CLI_SUCCESS;

  UNSET_FLAG (host->flags, HOST_PASSWORD_ENCRYPT);

  return CLI_SUCCESS;
}


/* Service terminal length.  */
CLI (service_terminal_length,
     service_terminal_length_cli,
     "service terminal-length <0-512>",
     "Set up miscellaneous service",
     "System wide terminal length configuration",
     "Number of lines of VTY (0 means no line control)")
{
  int lines;
  struct host *host = cli->vr->host;

  CLI_GET_INTEGER_RANGE("length", lines, argv[0], 0, 512);
  host->lines = lines;

  return CLI_SUCCESS;
}

CLI (no_service_terminal_length,
     no_service_terminal_length_cli,
     "no service terminal-length (<0-512>|)",
     CLI_NO_STR,
     "Set up miscellaneous service",
     "System wide terminal length configuration",
     "Number of lines of VTY (0 means no line control)")
{
  struct host *host = cli->vr->host;
  host->lines = -1;
  return CLI_SUCCESS;
}


/* "show running-config" for protocol module.  IMI has it's own
   version of this.*/

CLI (host_show_running_config,
     host_show_running_config_cli,
     "show running-config",
     "Show running system information",
     "Current Operating configuration")
{
  struct cli_tree *ctree = cli->ctree;
  CLI_CONFIG_FUNC func;
  int i;

  cli_out (cli, "\nCurrent configuration:\n!\n");

  if (ctree)
    for (i = 0; i < vector_max (ctree->config_write); i++)
      if ((func = (CLI_CONFIG_FUNC)vector_slot (ctree->config_write, i)))
        if ((*func) (cli))
          cli_out (cli, "!\n");

  cli_out (cli, "end\n\n");

  return CLI_SUCCESS;
}

ALI (host_show_running_config,
     host_write_terminal_pm_cli,
     "write terminal",
     CLI_WRITE_STR,
     "Write to terminal");

CLI (host_show_running_config_pm,
     host_show_running_config_pm_cli,
     "show running-config pm",
     "Show running system information",
     "Current Operating configuration",
     "Protocol Module configuration")
{
  struct cli_tree *ctree = cli->ctree;
  CLI_CONFIG_FUNC func;
  int i;
  int cli_cv_is_null = 0;

  if (cli->cv == NULL)
    cli_cv_is_null = 1;

  cli->cv = cfg_vect_init(cli->cv);

  if (ctree)
    for (i = 0; i < vector_max (ctree->config_write); i++)
      if (i != VTY_MODE && i != SERVICE_MODE && i != CONFIG_MODE)
        if ((func = (CLI_CONFIG_FUNC)vector_slot (ctree->config_write, i)))
          if ((*func) (cli))
            cli_out (cli, "!\n");

  if (cli_cv_is_null && cli->cv)
    {
      cfg_vect_del(cli->cv);
      cli->cv = NULL;
    }

  return CLI_SUCCESS;
}

CLI (host_show_running_config_instance,
     host_show_running_config_instance_cli,
     "show running-config instance",
     "Show running system information",
     "Current Operating configuration",
     "Instance configuration")
{
  struct cli_tree *ctree = cli->ctree;
  CLI_CONFIG_FUNC func;
  int mode;

  /* Get the Mode from Module ID.  */
  mode = MODULE_ID2MODE (cli->zg->protocol);
  if (mode ==  PAL_FALSE)
    return CLI_ERROR;

  if (ctree)
    if ((func = (CLI_CONFIG_FUNC)vector_slot (ctree->config_write, mode)))
      if ((*func) (cli))
        cli_out (cli, "!\n");

  return CLI_SUCCESS;
}

CLI (host_show_running_config_interface,
     host_show_running_config_interface_cli,
     "show running-config interface",
     "Show running system information",
     "Current Operating configuration",
     "Interface configuration")
{
  struct cli_tree *ctree = cli->ctree;
  int mode = INTERFACE_MODE;
  CLI_CONFIG_FUNC func;

  if (ctree)
    if ((func = (CLI_CONFIG_FUNC)vector_slot (ctree->config_write, mode)))
      if ((*func) (cli))
        cli_out (cli, "!\n");

  return CLI_SUCCESS;
}


CLI (host_write,
     host_write_cli,
     "write (file|)",
     CLI_WRITE_STR,
     "Write to file")
{
  struct ipi_vr *vr = cli->vr;
  struct host *host = vr->host;
  int ret;

  ret = host_config_write_file (cli, vr);

  if (ret < 0)
    cli_out (cli, "Error writing configuration to %s\n", host->config_file);
  else
    cli_out (cli, "Configuration saved to %s\n", host->config_file);

  return CLI_SUCCESS;
}

ALI (host_write,
     host_write_memory_cli,
     "write memory",
     CLI_WRITE_STR,
     "Write to NV memory");

ALI (host_write,
     host_copy_runconfig_startconfig_cli,
     "copy running-config startup-config",
     "Copy from one file to another",
     "Copy from current system configuration",
     "Copy to startup configuration");


CLI (service_advanced_vty,
     service_advanced_vty_cli,
     "service advanced-vty",
     "Set up miscellaneous service",
     "Enable advanced mode vty interface")
{
  struct host *host = cli->vr->host;

  SET_FLAG (host->flags, HOST_ADVANCED_VTY);

  return CLI_SUCCESS;
}

CLI (no_service_advanced_vty,
     no_service_advanced_vty_cli,
     "no service advanced-vty",
     CLI_NO_STR,
     "Set up miscellaneous service",
     "Enable advanced mode vty interface")
{
  struct host *host = cli->vr->host;

  UNSET_FLAG (host->flags, HOST_ADVANCED_VTY);

  return CLI_SUCCESS;
}

int
host_username_set (struct cli *cli, char *name, int privilege,
                   char *password, char *password_encrypt)
{
  struct ipi_vr *vr;
  struct host *host;
  struct host_user *user;
  char cryptbuf[16];
  u_char flags = 0;

  if (password)
    if (pal_strlen (password) > HOST_MAX_PASSWD_LEN)
      {
        cli_out (cli, "Password exceeds Max of 8 characters\n");
        return CLI_ERROR;
      }

  if (cli->mode == VR_MODE)
    {
      vr = cli->index;

      if (cli->vr->id == 0)
        SET_FLAG (flags, HOST_USER_FLAG_PRIVILEGED);
    }
  else
    vr = cli->vr;

  host = vr->host;

  user = host_user_lookup (host, name);
  if (user != NULL)
    {
      if (CHECK_FLAG (user->flags, HOST_USER_FLAG_PRIVILEGED)
          && !CHECK_FLAG (flags, HOST_USER_FLAG_PRIVILEGED))
        {
          cli_out (cli, "%% `%s' already exists\n", name);
          return CLI_ERROR;
        }

      if (!CHECK_FLAG (user->flags, HOST_USER_FLAG_PRIVILEGED)
          && CHECK_FLAG (flags, HOST_USER_FLAG_PRIVILEGED))
        {
          cli_out (cli, "%% `%s' already exists\n", name);
          return CLI_ERROR;
        }
    }
  else
    {
      user = host_user_get (host, name);
      user->flags = flags;
    }

  if (privilege >= 0)
    user->privilege = privilege;

  if (password)
    {
      if (CHECK_FLAG (host->flags, HOST_PASSWORD_ENCRYPT))
        host_user_update (host, name, privilege, NULL,
                          zencrypt (password, cryptbuf));
      else
        host_user_update (host, name, privilege, password, NULL);
    }

  if (password_encrypt)
    host_user_update (host, name, privilege, NULL, password_encrypt);

  return CLI_SUCCESS;
}

int
host_username_unset (struct cli *cli, char *name)
{
  struct ipi_vr *vr;
  struct host *host;
  struct host_user *user;

  if (cli->mode == VR_MODE)
    vr = cli->index;
  else
    vr = cli->vr;

  host = vr->host;

  user = host_user_lookup (host, name);
  if (user != NULL)
    {
      if (vr == cli->vr)
        {
          if (CHECK_FLAG (user->flags, HOST_USER_FLAG_PRIVILEGED))
            return CLI_ERROR;
        }
      else
        {
          if (!CHECK_FLAG (user->flags, HOST_USER_FLAG_PRIVILEGED))
            return CLI_ERROR;
        }
    }

  host_user_delete (host, name);

  return CLI_SUCCESS;
}

CLI (username,
     username_cmd,
     "username WORD",
     "Establish User Name Authentication",
     "User name")
{
  int privilege = -1;
  char *password = NULL;
  char *password_encrypt = NULL;

  if (argc > 2)
    password_encrypt = argv[2];
  else if (argc > 1)
    password = argv[1];

  return host_username_set (cli, argv[0], privilege,
                            password, password_encrypt);
}

ALI (username,
     username_password_cmd,
     "username WORD password (8|) LINE",
     "Establish User Name Authentication",
     "User name",
     "Specify the password for the user",
     "Specifies a HIDDEN password will follow",
     "User password string");

CLI (username_privilege,
     username_privilege_cmd,
     "username WORD privilege <0-15>",
     "Establish User Name Authentication",
     "User name",
     "Set user privilege level",
     "User privilege level")
{
  int privilege;
  char *password = NULL;
  char *password_encrypt = NULL;

  CLI_GET_INTEGER_RANGE ("privilege", privilege, argv[1], 0, 15);

  if (argc > 3)
    password_encrypt = argv[3];
  else if (argc > 2)
    password = argv[2];

  return host_username_set (cli, argv[0], privilege,
                            password, password_encrypt);
}

ALI (username_privilege,
     username_privilege_password_cmd,
     "username WORD privilege <0-15> password (8|) LINE",
     "Establish User Name Authentication",
     "User name",
     "Set user privilege level",
     "User privilege level",
     "Specify the password for the user",
     "Specifies a HIDDEN password will follow",
     "User password string");

CLI (no_username,
     no_username_cmd,
     "no username WORD",
     CLI_NO_STR,
     "Establish User Name Authentication",
     "User name")
{
  host_username_unset (cli, argv[0]);

  return CLI_SUCCESS;
}


/* Check enable password.  */
int
host_password_check (char *passwd, char *encrypt, char *input)
{
  char cryptbuf[16];
  char *str;
  int ret;

  /* Get enable password.  */
  if (encrypt)
    str = encrypt;
  else
    str = passwd;

  if (input == NULL)
    {
      /* Just check password is set or not.  */
      if (str == NULL)
        return 1;
    }
  else
    {
      if (str != NULL)
        {
          if (encrypt)
            ret = pal_strcmp (pal_crypt (input, str, cryptbuf), str);
          else
            ret = pal_strcmp (str, input);

          if (ret == 0)
            return 1;
        }
    }
  return 0;
}

/*-------------------------------------------------------------
 * host_service_encode
 * host_service_write
 *-------------------------------------------------------------
 */
int
host_service_encode (struct host *host, cfg_vect_t *cv)
{
  if (! CHECK_FLAG (host->flags, HOST_ADVANCED_VTY))
    {
    cfg_vect_add_cmd (cv, "no service advanced-vty\n");
  }
  if (CHECK_FLAG (host->flags, HOST_ADVANCED_VTYSH))
    {
    cfg_vect_add_cmd (cv, "service advanced-vty\n");
  }
#ifdef VTYSH
  if (CHECK_FLAG (host->flags, HOST_PASSWORD_ENCRYPT))
    {
    cfg_vect_add_cmd (cv, "service password-encryption\n");
  }
#else /* VTYSH */
  if (CHECK_FLAG (host->flags, HOST_PASSWORD_ENCRYPT))
    {
    cfg_vect_add_cmd (cv, "service password-encryption\n");
  }
  else
    {
    cfg_vect_add_cmd (cv, "no service password-encryption\n");
  }
#endif /* VTYSH */
  if (host->lines >= 0)
    {
    cfg_vect_add_cmd (cv, "service terminal-length %d\n", host->lines);
  }

  if (cfg_vect_count(cv))
  {
    cfg_vect_add_cmd (cv, "!\n");
  }
  return 0;
}

int
host_service_write (struct cli *cli)
{
  struct host *host = cli->vr->host;

  if (! host)
    return 0;

  cli->cv = cfg_vect_init(cli->cv);
  host_service_encode(host, cli->cv);
  cfg_vect_out(cli->cv, (cfg_vect_out_fun_t)cli->out_func, cli->out_val);
  return 0;
}

/*-------------------------------------------------------------
 * host_config_encode_user
 * host_config_write_user
 *-------------------------------------------------------------
 */
int
host_config_encode_user (struct host_user *user, cfg_vect_t *cv)
{
  cfg_vect_add_cmd (cv, "username %s", user->name);
  if (user->privilege != 1)
  {
    cfg_vect_add_cmd (cv, " privilege %d", user->privilege);
  }
  if (user->password)
  {
    cfg_vect_add_cmd (cv, " password %s", user->password);
  }
  if (user->password_encrypt)
  {
    cfg_vect_add_cmd (cv, " password 8 %s", user->password_encrypt);
  }
  cfg_vect_add_cmd (cv, "\n");
  return 0;

}

int
host_config_write_user (struct cli *cli, struct host_user *user)
{
  int write = 0;

  cli->cv = cfg_vect_init(cli->cv);
  host_config_encode_user(user, cli->cv);
  write = cfg_vect_count(cli->cv);
  cfg_vect_out(cli->cv, (cfg_vect_out_fun_t)cli->out_func, cli->out_val);
  return write;
}

/*-------------------------------------------------------------
 * host_config_encode_user_all
 * host_config_write_user_all
 *-------------------------------------------------------------
 */
int
host_config_encode_user_all (struct host *host, cfg_vect_t *cv)
{
  struct host_user *user;
  struct listnode *node;

  LIST_LOOP (host->users, user, node)
    if (!CHECK_FLAG (user->flags, HOST_USER_FLAG_PRIVILEGED))
      host_config_encode_user (user, cv);
  return 0;
}

int
host_config_write_user_all (struct cli *cli, struct host *host)
{
  int write = 0;

  cli->cv = cfg_vect_init(cli->cv);
  host_config_encode_user_all(host, cli->cv);
  write = cfg_vect_count(cli->cv);
  cfg_vect_out(cli->cv, (cfg_vect_out_fun_t)cli->out_func, cli->out_val);
  return write;
}

#ifdef HAVE_VR
int
host_config_encode_user_all_vr (struct host *host, cfg_vect_t *cv)
{
  struct host_user *user;
  struct listnode *node;
  int write = 0;

  LIST_LOOP (host->users, user, node)
    if (CHECK_FLAG (user->flags, HOST_USER_FLAG_PRIVILEGED))
      {
        cfg_vect_add_cmd (cv, " ");
        write += host_config_encode_user (user, cv);
      }
  return write;
}

int
host_config_write_user_all_vr (struct cli *cli, struct host *host)
{
  int write = 0;

  cli->cv = cfg_vect_init(cli->cv);
  host_config_encode_user_all_vr(host, cli->cv);
  write = cfg_vect_count(cli->cv);
  cfg_vect_out(cli->cv, (cfg_vect_out_fun_t)cli->out_func, cli->out_val);
  return write;
}
#endif /* HAVE_VR */


/*-------------------------------------------------------------
 * host_config_encode
 * host_config_write
 *-------------------------------------------------------------
 */
int
host_config_encode (struct host *host, cfg_vect_t *cv)
{
  struct lib_globals *zg = host->vr->zg;
  int cnt = cfg_vect_count(cv);

  if (host->name)
    {
    cfg_vect_add_cmd (cv, "hostname %s\n", host->name);
    cfg_vect_add_cmd (cv, "!\n");
  }
  if (host->password_encrypt)
    {
    cfg_vect_add_cmd (cv, "password 8 %s\n", host->password_encrypt);
  }
  else if (host->password)
    {
    cfg_vect_add_cmd (cv, "password %s\n", host->password);
  }

  if (host->enable_encrypt)
    {
    cfg_vect_add_cmd (cv, "enable password 8 %s\n", host->enable_encrypt);
  }
  else if (host->enable)
    {
    cfg_vect_add_cmd (cv, "enable password %s\n", host->enable);
  }

  /* Host log config write. */
  zlog_config_encode (zg, cv);

  if (! host->motd)
    {
    cfg_vect_add_cmd (cv, "no banner motd\n");
  }
  else if (host->motd != zg->motd)
  {
    cfg_vect_add_cmd (cv, "banner motd %s\n", host->motd);
  }
  if (cnt < cfg_vect_count(cv))
  {
    cfg_vect_add_cmd (cv, "!\n");
  }
  cnt = cfg_vect_count(cv);
  host_config_encode_user_all (host, cv);
  if (cnt < cfg_vect_count(cv))
  {
    cfg_vect_add_cmd (cv, "!\n");
  }
  return 0;
}

int
host_config_write (struct cli *cli)
{
  struct host *host = cli->vr->host;
  int write = 0;

  if (! host)
    return 0;

  cli->cv = cfg_vect_init(cli->cv);
  host_config_encode(host, cli->cv);
  write = cfg_vect_count(cli->cv);
  cfg_vect_out(cli->cv, (cfg_vect_out_fun_t)cli->out_func, cli->out_val);
  return write;
}

/* Default host CLIs.  */
void
host_default_cli_init (struct cli_tree *ctree)
{
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_version_cli);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &config_terminal_cli);

#ifndef HAVE_IMISH
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &host_password_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_host_password_cli);
#endif /* !HAVE_IMISH */
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &host_enable_password_cli);
  cli_set_imi_cmd (&banner_motd_custom_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_host_enable_password_cli);
  cli_set_imi_cmd (&no_host_enable_password_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_host_enable_password_arg_cli);
  cli_set_imi_cmd (&no_host_enable_password_arg_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST);

  cli_install_gen (ctree, CONFIG_MODE,PRIVILEGE_NORMAL, 0,
                   &service_password_encrypt_cli);
  cli_set_imi_cmd (&service_password_encrypt_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST_SERVICE );

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_service_password_encrypt_cli);
  cli_set_imi_cmd (&no_service_password_encrypt_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST_SERVICE );


  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &banner_motd_custom_cli);
  cli_set_imi_cmd (&banner_motd_custom_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &banner_motd_default_cli);
  cli_set_imi_cmd (&banner_motd_default_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST );

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_banner_motd_cli);
  cli_set_imi_cmd (&no_banner_motd_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST );


  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &service_terminal_length_cli);
  cli_set_imi_cmd (&service_terminal_length_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST_SERVICE );

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_service_terminal_length_cli);
  cli_set_imi_cmd (&no_service_terminal_length_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST_SERVICE );

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &service_advanced_vty_cli);
  cli_set_imi_cmd (&service_advanced_vty_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST_SERVICE );

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_service_advanced_vty_cli);
  cli_set_imi_cmd (&no_service_advanced_vty_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST_SERVICE );

  /* "show startup-config" CLI.  */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &host_show_startup_config_cli);
}

void
host_user_cli_init (struct cli_tree *ctree)
{
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &username_cmd);
  cli_set_imi_cmd (&username_cmd, CONFIG_MODE, CFG_DTYP_IMI_HOST );

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &username_password_cmd);
  cli_set_imi_cmd (&username_password_cmd, CONFIG_MODE, CFG_DTYP_IMI_HOST );

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &username_privilege_cmd);
  cli_set_imi_cmd (&username_privilege_cmd, CONFIG_MODE, CFG_DTYP_IMI_HOST );

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &username_privilege_password_cmd);
  cli_set_imi_cmd (&username_privilege_password_cmd, CONFIG_MODE, CFG_DTYP_IMI_HOST );

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_username_cmd);
  cli_set_imi_cmd (&no_username_cmd, CONFIG_MODE, CFG_DTYP_IMI_HOST );
}

#ifdef VTYSH
void
host_vtysh_cli_init (struct cli_tree *ctree)
{
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &host_hostname_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_host_hostname_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &host_enable_password_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_host_enable_password_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_host_enable_password_arg_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &service_password_encrypt_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_service_password_encrypt_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &banner_motd_custom_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &banner_motd_default_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_banner_motd_cli);
}
#endif /* VTYSH */

void
host_running_config_init (struct cli_tree *ctree)
{
  int i;

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &host_show_running_config_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &host_write_terminal_pm_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, CLI_FLAG_HIDDEN,
                   &host_show_running_config_pm_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_VR_MAX, CLI_FLAG_HIDDEN,
                   &host_show_running_config_pm_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, CLI_FLAG_HIDDEN,
                   &host_show_running_config_instance_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_VR_MAX, CLI_FLAG_HIDDEN,
                   &host_show_running_config_instance_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, CLI_FLAG_HIDDEN,
                   &host_show_running_config_interface_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_VR_MAX, CLI_FLAG_HIDDEN,
                   &host_show_running_config_interface_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &host_write_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &host_write_memory_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &host_copy_runconfig_startconfig_cli);

  for (i = 0; i < MAX_MODE; i++)
    if (i != EXEC_MODE && i != EXEC_PRIV_MODE)
      cli_install_gen (ctree, i, PRIVILEGE_NORMAL, CLI_FLAG_HIDDEN,
                       &host_write_memory_cli);
}

void
host_cli_init (struct lib_globals *zg, struct cli_tree *ctree)
{
  /* Default host CLIs.  */
  host_default_cli_init (ctree);

  /* VTY movement CLIs. */
  cli_install_config (ctree, SERVICE_MODE, host_service_write);
  cli_install_config (ctree, CONFIG_MODE, host_config_write);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &host_enable_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &host_disable_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &host_hostname_cli);
  cli_set_imi_cmd (&host_hostname_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_host_hostname_cli);
  cli_set_imi_cmd (&no_host_hostname_cli, CONFIG_MODE, CFG_DTYP_IMI_HOST);

  /* Install logging CLIs. */
  if (zg->protocol != IPI_PROTO_IMI)
    zlog_cli_init (ctree);
}

void
host_vr_cli_init (struct cli_tree *ctree)
{
  cli_install_gen (ctree, VR_MODE, PRIVILEGE_NORMAL, 0,
                   &username_cmd);
  cli_set_imi_cmd (&username_cmd, VR_MODE, CFG_DTYP_IMI_VR);

  cli_install_gen (ctree, VR_MODE, PRIVILEGE_NORMAL, 0,
                   &username_password_cmd);
  cli_set_imi_cmd (&username_password_cmd, VR_MODE, CFG_DTYP_IMI_VR);

  cli_install_gen (ctree, VR_MODE, PRIVILEGE_NORMAL, 0,
                   &username_privilege_cmd);
  cli_set_imi_cmd (&username_privilege_cmd, VR_MODE, CFG_DTYP_IMI_VR);

  cli_install_gen (ctree, VR_MODE, PRIVILEGE_NORMAL, 0,
                   &username_privilege_password_cmd);
  cli_set_imi_cmd (&username_privilege_password_cmd, VR_MODE, CFG_DTYP_IMI_VR);

  cli_install_gen (ctree, VR_MODE, PRIVILEGE_NORMAL, 0,
                   &no_username_cmd);
  cli_set_imi_cmd (&no_username_cmd, VR_MODE, CFG_DTYP_IMI_VR);
}


void
host_vty_init (struct lib_globals *zg)
{
  zg->vty_master = vty_server_new (zg->ctree);
  if (zg->vty_master == NULL)
    return;

  zg->ss = show_server_init (zg);
  if (zg->ss == NULL)
    return;

  cli_install_default (zg->ctree, EXEC_MODE);
  cli_install_default (zg->ctree, CONFIG_MODE);

  host_cli_init (zg, zg->ctree);

  host_running_config_init (zg->ctree);
}

/* Start the configuration.  */
int
host_config_start (struct lib_globals *zg,
                   char *config_file, u_int16_t vty_port)
{
  /* Sort all installed commands. */
  cli_sort (zg->ctree);

  /* Start the configuration management.  */
#if !defined(HAVE_NO_STORAGE_DEV) || defined(HAVE_IMI)
  HOST_CONFIG_START (zg, config_file, IPI_VTY_PORT (zg, vty_port));
#else
  vty_serv_sock (zg, IPI_VTY_PORT (zg, vty_port));
#endif /* !HAVE_NO_STORAGE_DEV || HAVE_IMI */

 /* If there is no storage device mark as startup config complete. */
#ifdef HAVE_NO_STORAGE_DEV
  SET_FLAG ((ipi_vr_get_privileged (zg))->host->flags, HOST_CONFIG_READ_DONE);
#endif /* HAVE_NO_STORAGE_DEV */

  return 0;
}
