/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#include "lib.h"
#include "cli.h"
#include "buffer.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "bgpsdn_version.h"
#include "thread.h"
#include "prefix.h"
#include "filter.h"
#include "snprintf.h"

/* VTY events. */
enum event
{
  VTY_SERV,
  VTY_READ,
  VTY_WRITE,
  VTY_TIMEOUT_RESET,
  VTY_MAX
};

/* Character definition.  */
static char telnet_backward_char = 0x08;
static char telnet_space_char = ' ';

void vty_event (struct lib_globals *, enum event, pal_sock_handle_t, void *);
int cli_config_exit (struct cli *, int, char **);


/* Allocate a new VTY server.  */
struct vty_server *
vty_server_new (struct cli_tree *ctree)
{
  struct vty_server *vty_server;

  vty_server = XCALLOC (MTYPE_VTY_MASTER, sizeof (struct vty_server));

  /* Initialize vector for vty's. */
  vty_server->vtyvec = vector_init (VECTOR_MIN_SIZE);

  /* Initialize server thread vector. */
  vty_server->Vvty_serv_thread = vector_init (VECTOR_MIN_SIZE);

  /* Register ctee.  */
  vty_server->ctree = ctree;

  vty_cmd_init (ctree);

  return vty_server;
}

void
vty_master_free (struct vty_server **vty_master)
{
  if (*vty_master)
    {
      /* Free vector of vty's. */
      vector_free ((*vty_master)->vtyvec);

      /* Free server thread vector. */
      vector_free ((*vty_master)->Vvty_serv_thread);

      /* Free vty master strucuture. */
      XFREE (MTYPE_VTY_MASTER, *vty_master);
      *vty_master = NULL;
    }
}

/* Change "\n" to "\r\n" from src to dst. */
static void
vty_add_linefeeds (char *src, char *dst)
{
  char *cp1, *cp2;

  for (cp1 = src, cp2 = dst; *cp1 != '\0'; cp1++)
    {
      if (*cp1 == '\n')
        {
          *cp2++ = '\r';
          *cp2++ = '\n';
        }
      else
        *cp2++ = *cp1;
    }
  *cp2 = '\0';

  return;
}

/* Display formatted output to the vty.  */
int
vty_out (struct vty *vty, const char *format, ...)
{
  va_list args;
  int len = 0;
  u_int32_t size = 1024;
  char buf[1024];
  char out[2048];
  char *p = NULL;
  char *q = NULL;
  bool_t mem_allocation = 0;

  va_start (args, format);

  len = zvsnprintf (buf, size, format, args);

  va_end (args);

  if (len < 0 || (len >= size))
    {
      p = XCALLOC (MTYPE_VTY_OUT_BUF, len + 1);
      if (p == NULL)
        return -1;
      q = XCALLOC (MTYPE_VTY_OUT_BUF, (len + 1) * 2);
      if (q == NULL)
        {
          XFREE (MTYPE_VTY_OUT_BUF, p);
          return -1;
        }
 
      mem_allocation = 1;

      va_start (args, format);
      len = zvsnprintf (p, len, format, args);
      va_end (args);
    }
  else
    {
      p = buf;
      q = out;
    }

  /* Change "\n" to "\r\n". */
  vty_add_linefeeds (p, q);
  len = pal_strlen (q);

  if (vty_shell_serv (vty) || vty_monitor_output (vty))
    {
      if (vty->sock >= 0)
        (void) pal_sock_write (vty->sock, q, len);
    }
  else if (vty_shell (vty))
    {
      if (0 <= vty->sock)
        {
          (void) pal_sock_write (vty->sock, q, len);
        }
    }
  else
    buffer_write (vty->obuf, q, len);

  if (mem_allocation)
    {
      XFREE (MTYPE_VTY_OUT_BUF, p);
      XFREE (MTYPE_VTY_OUT_BUF, q);
      p = q = NULL;
    }

  return len;
}

/* Output current time to the vty.  */
void
vty_time_print (struct vty *vty, int cr)
{
  pal_time_t clock;
  struct pal_tm tm;
  char buf[TIME_BUF];
  int ret;

  pal_time_sys_current (&clock);
  pal_time_loc (&clock, &tm);
  ret = pal_time_strf (buf, TIME_BUF, "%Y/%m/%d %H:%M:%S", &tm);

  if (0 == ret)
    zlog_info (vty->zg, "pal_time_strf error");
  else if (cr)
    vty_out (vty, "%s\n", buf);
  else
    vty_out (vty, "%s ", buf);
}

/* Put out prompt and wait input from user.  */
void
vty_prompt (struct vty *vty)
{
  struct host *host;

  host = vty->cli.vr->host;

  if (vty->type != VTY_TERM)
    return;

  vty_out (vty, "%s", host_prompt (host, &vty->cli));
}

/* Send WILL TELOPT_ECHO to remote server.  */
void
vty_will_echo (struct vty *vty)
{
  u_char cmd[] = { IAC, WILL, TELOPT_ECHO, '\0' };
  vty_out (vty, "%s", cmd);
}

/* Make suppress Go-Ahead telnet option.  */
void
vty_will_suppress_go_ahead (struct vty *vty)
{
  u_char cmd[] = { IAC, WILL, TELOPT_SGA, '\0' };
  vty_out (vty, "%s", cmd);
}

/* Make don't use linemode over telnet.  */
void
vty_dont_linemode (struct vty *vty)
{
  u_char cmd[] = { IAC, DONT, TELOPT_LINEMODE, '\0' };
  vty_out (vty, "%s", cmd);
}

/* Use window size. */
void
vty_do_window_size (struct vty *vty)
{
  u_char cmd[] = { IAC, DO, TELOPT_NAWS, '\0' };
  vty_out (vty, "%s", cmd);
}

/* Allocate new vty struct.  */
struct vty *
vty_new (struct lib_globals *zg)
{
  struct vty *new = XCALLOC (MTYPE_VTY, sizeof (struct vty));

  new->obuf = (struct buffer *) buffer_new (1024);
  new->buf = XCALLOC (MTYPE_VTY, VTY_BUFSIZ);
  new->max = VTY_BUFSIZ;
  new->sb_buffer = NULL;
  new->zg = zg;
  new->history = PAL_TRUE;
  new->sock = -1; /* initialize to -1, s >= 0 is valid socket value */
  return new;
}

/* Authentication of vty.  */
void
vty_auth (struct vty *vty, char *buf)
{
  char *passwd = NULL;
  int privilege = PRIVILEGE_NORMAL;
  int fail;
  char crypt_buf[BUFSIZ];
  struct host *host = vty->cli.vr->host;

  switch (vty->cli.mode)
    {
    case AUTH_MODE:
      if (CHECK_FLAG (host->flags, HOST_PASSWORD_ENCRYPT))
        passwd = host->password_encrypt;
      else
        passwd = host->password;
      break;
    case AUTH_ENABLE_MODE:
      if (CHECK_FLAG (host->flags, HOST_PASSWORD_ENCRYPT))
        passwd = host->enable_encrypt;
      else
        passwd = host->enable;
      privilege = PRIVILEGE_ENABLE (vty->cli.vr);
      break;
    }

  if (passwd)
    {
      if (CHECK_FLAG (host->flags, HOST_PASSWORD_ENCRYPT))
        fail = pal_strcmp (pal_crypt (buf, passwd, crypt_buf), passwd);
      else
        fail = pal_strcmp (buf, passwd);
    }
  else
    fail = 1;

  if (! fail)
    {
      /* Success!.  */
      vty->fail = 0;
      vty->cli.mode = EXEC_MODE;
      vty->cli.privilege = privilege;
    }
  else
    {
      vty->fail++;
      if (vty->fail >= 3)
        {
          if (vty->cli.mode == AUTH_MODE)
            {
              vty_out (vty, "%% Bad passwords, too many failures!\n");
              vty->cli.status = CLI_CLOSE;
            }
          else
            {
              /* AUTH_ENABLE_MODE */
              vty->fail = 0;
              vty_out (vty, "%% Bad enable passwords, too many failures!\n");
              vty->cli.mode = EXEC_MODE;
            }
        }
    }
}

/* Command execution over the vty interface.  */
int
vty_command (struct vty *vty, char *buf)
{
  struct vty_server *server = vty->server;
  struct cli_tree *ctree = server->ctree;
  struct cli_node *node;
  struct cli *cli;
  int ret;

  cli = &vty->cli;

  ret = cli_parse (ctree, cli->mode, cli->privilege, buf, 1, 0);

  switch (ret)
    {
    case CLI_PARSE_NO_MODE:
      /* Ignore no mode line.  */
      break;
    case CLI_PARSE_EMPTY_LINE:
      /* Ignore empty line.  */
      break;
    case CLI_PARSE_SUCCESS:
      node = ctree->exec_node;

      /* This command is only used by WMI (Web Management Interface).  */
      if (CHECK_FLAG (node->cel->flags, CLI_FLAG_WMI))
        {
          vty_out (vty, "%% No such command (only used for Web Management Interface).\n");
          ret = CLI_ERROR;
          break;
        }

      cli->zg = vty->zg;
      cli->vr = vty->cli.vr;
      cli->line = vty;
      cli->out_func = (CLI_OUT_FUNC) vty_out;
      cli->out_val = vty;
      cli->ctree = ctree;
      cli->status = CLI_NORMAL;
      vty->lp = 0;
      vty->lineno = 0;

      LIB_GLOB_SET_VR_CONTEXT (cli->zg, cli->vr);

      ret = (*node->cel->func) (cli, ctree->argc, ctree->argv);
      break;

    case CLI_PARSE_AMBIGUOUS:
      vty_out (vty, "%% Ambiguous command:  \"%s\"\n", buf);
      break;

    case CLI_PARSE_INCOMPLETE:
      /* In case of hidden command we do not want to give the user
         any hint that such command may exist.
       */
      if (ctree->exec_node != NULL )
        if (CHECK_FLAG(ctree->exec_node->flags, CLI_FLAG_HIDDEN))
          {
            vty_out (vty, "%*c^\n",
                     pal_strlen (host_prompt (cli->vr->host, &vty->cli))
                     + (ctree->invalid - buf), ' ');
            vty_out (vty, "%% Invalid input detected at '^' marker.\n\n");
            break;
        }
      vty_out (vty, "%% Incomplete command.\n\n");
      break;

    case CLI_PARSE_INCOMPLETE_PIPE:
      vty_out (vty, "%% Incomplete command before pipe.\n\n");
      break;

    case CLI_PARSE_NO_MATCH:
      if (ctree->invalid)
        {
          vty_out (vty, "%*c^\n",
                   pal_strlen (host_prompt (cli->vr->host, &vty->cli))
                   + (ctree->invalid - buf), ' ');
          vty_out (vty, "%% Invalid input detected at '^' marker.\n\n");
        }
      else
        vty_out (vty, "%% Unrecognized command\n");
      break;

    default:
      vty_out (vty, "%% Parser error\n");
      ret = CLI_ERROR;
      break;
    }

  /* Free arguments. */
  cli_free_arguments (ctree);

  return ret;
}

/* Basic function to write buffer to vty.  */
static void
vty_write (struct vty *vty, const char *buf, size_t nbytes)
{
  if (vty->cli.mode != AUTH_MODE && vty->cli.mode != AUTH_ENABLE_MODE)
    buffer_write (vty->obuf, buf, nbytes);
}

/* Ensure length of input buffer.  Is buffer is short, double it. */
static void
vty_ensure (struct vty *vty, int length)
{
  if (vty->max <= length)
    {
      vty->max *= 2;
      vty->buf = XREALLOC (MTYPE_VTY, vty->buf, vty->max);
    }
}

/* Basic function to insert character int vty. */
void
vty_self_insert (struct vty *vty, char c)
{
  int i;
  int length;

  vty_ensure (vty, vty->length + 1);
  length = vty->length - vty->cp;
  pal_mem_move (&vty->buf[vty->cp + 1], &vty->buf[vty->cp], length);
  vty->buf[vty->cp] = c;

  vty_write (vty, &vty->buf[vty->cp], length + 1);
  for (i = 0; i < length; i++)
    vty_write (vty, &telnet_backward_char, 1);

  vty->cp++;
  vty->length++;
}

/* Self insert character 'c' in overwrite mode. */
static void
vty_self_insert_overwrite (struct vty *vty, char c)
{
  vty_ensure (vty, vty->length + 1);
  vty->buf[vty->cp++] = c;

  if (vty->cp > vty->length)
    vty->length++;

  if ((vty->cli.mode == AUTH_MODE) || (vty->cli.mode == AUTH_ENABLE_MODE))
    return;

  vty_write (vty, &c, 1);
}

/* Insert a word into vty interface with overwrite mode. */
void
vty_insert_word_overwrite (struct vty *vty, char *str)
{
  int len = pal_strlen (str);
  vty_write (vty, str, len);
  pal_strcpy (&vty->buf[vty->cp], str);
  vty->cp += len;
  vty->length = vty->cp;
}

/* Forward character. */
static void
vty_forward_char (struct vty *vty)
{
  if (vty->cp < vty->length)
    {
      vty_write (vty, &vty->buf[vty->cp], 1);
      vty->cp++;
    }
}

/* Backward character. */
static void
vty_backward_char (struct vty *vty)
{
  if (vty->cp > 0)
    {
      vty->cp--;
      vty_write (vty, &telnet_backward_char, 1);
    }
}

/* Move to the beginning of the line. */
static void
vty_beginning_of_line (struct vty *vty)
{
  while (vty->cp)
    vty_backward_char (vty);
}

/* Move to the end of the line. */
static void
vty_end_of_line (struct vty *vty)
{
  while (vty->cp < vty->length)
    vty_forward_char (vty);
}

static void vty_kill_line_from_beginning (struct vty *);
void vty_redraw_line (struct vty *);

/* Print command line history.  This function is called from
   vty_next_line and vty_previous_line. */
static void
vty_history_print (struct vty *vty)
{
  int length;

  vty_kill_line_from_beginning (vty);

  /* Get previous line from history buffer */
  length = pal_strlen (vty->hist[vty->hp]);
  pal_mem_cpy (vty->buf, vty->hist[vty->hp], length);
  vty->cp = vty->length = length;

  /* Redraw current line */
  vty_redraw_line (vty);
}

/* Show next command line history.  */
void
vty_next_line (struct vty *vty)
{
  int try_index;

  if (vty->hp == vty->hindex)
    return;

  /* Try is there history exist or not. */
  try_index = vty->hp;
  if (try_index == (VTY_MAXHIST - 1))
    try_index = 0;
  else
    try_index++;

  /* If there is not history return. */
  if (vty->hist[try_index] == NULL)
    return;
  else
    vty->hp = try_index;

  vty_history_print (vty);
}

/* Show previous command line history. */
void
vty_previous_line (struct vty *vty)
{
  int try_index;

  try_index = vty->hp;
  if (try_index == 0)
    try_index = VTY_MAXHIST - 1;
  else
    try_index--;

  if (vty->hist[try_index] == NULL)
    return;
  else
    vty->hp = try_index;

  vty_history_print (vty);
}

/* This function redraw all of the command line character. */
void
vty_redraw_line (struct vty *vty)
{
  vty_write (vty, vty->buf, vty->length);
  vty->cp = vty->length;
}

/* Forward word. */
static void
vty_forward_word (struct vty *vty)
{
  while (vty->cp != vty->length && vty->buf[vty->cp] != ' ')
    vty_forward_char (vty);

  while (vty->cp != vty->length && vty->buf[vty->cp] == ' ')
    vty_forward_char (vty);
}

/* Backward word without skipping trailing space. */
int
vty_backward_pure_word (struct vty *vty)
{
  int i = 0;

  while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
    {
      i++;
      vty_backward_char (vty);
    }
  return i;
}

/* Backward word. */
static void
vty_backward_word (struct vty *vty)
{
  while (vty->cp > 0 && vty->buf[vty->cp - 1] == ' ')
    vty_backward_char (vty);

  while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
    vty_backward_char (vty);
}

/* When '^D' is typed at the beginning of the line we move to the down
   level. */
static void
vty_down_level (struct vty *vty)
{
  vty_out (vty, "\n");
  cli_mode_exit (&vty->cli);
  if (vty->cli.status == CLI_CLOSE)
    vty->cli.status = CLI_CLOSE;
  vty_prompt (vty);
  vty->cp = 0;
}

void
vty_clear_buf (struct vty *vty)
{
  vty->cp = 0;
  vty->length = 0;
  pal_mem_set (vty->buf, 0, vty->max);
}

/* When '^Z' is received from vty, move down to the enable mode. */
void
vty_end_config (struct vty *vty)
{
  vty_out (vty, "\n");

  switch (vty->cli.mode)
    {
    case EXEC_MODE:
      /* Nothing to do. */
      break;
    case CONFIG_MODE:
    case INTERFACE_MODE:
    case BGP_MODE:
    case BGP_IPV4_MODE:
    case BGP_IPV4M_MODE:
    case BGP_IPV6_MODE:
    case RMAP_MODE:
    case KEYCHAIN_MODE:
    case KEYCHAIN_KEY_MODE:
    case VTY_MODE:
      vty_config_unlock (vty);
      vty->cli.mode = EXEC_MODE;
      break;
    default:
      /* Unknown node, we shold ignore it. */
      break;
    }
  vty_clear_buf (vty);
  vty_prompt (vty);
}

/* Delete a charcter at the current point. */
static void
vty_delete_char (struct vty *vty)
{
  int i;
  int size;

  if (vty->cli.mode == AUTH_MODE ||  vty->cli.mode == AUTH_ENABLE_MODE)
    return;

  if (vty->length == 0)
    {
      vty_down_level (vty);
      return;
    }

  if (vty->cp == vty->length)
    return;                     /* completion need here? */

  size = vty->length - vty->cp;

  vty->length--;
  pal_mem_move (&vty->buf[vty->cp], &vty->buf[vty->cp + 1], size - 1);
  vty->buf[vty->length] = '\0';

  vty_write (vty, &vty->buf[vty->cp], size - 1);
  vty_write (vty, &telnet_space_char, 1);

  for (i = 0; i < size; i++)
    vty_write (vty, &telnet_backward_char, 1);
}

/* Delete a character before the point. */
static void
vty_delete_backward_char (struct vty *vty)
{
  if (vty->cp == 0)
    return;

  vty_backward_char (vty);
  vty_delete_char (vty);
}

/* Kill rest of line from current point. */
static void
vty_kill_line (struct vty *vty)
{
  int i;
  int size;

  size = vty->length - vty->cp;

  if (size == 0)
    return;

  for (i = 0; i < size; i++)
    vty_write (vty, &telnet_space_char, 1);
  for (i = 0; i < size; i++)
    vty_write (vty, &telnet_backward_char, 1);

  pal_mem_set (&vty->buf[vty->cp], 0, size);
  vty->length = vty->cp;
}

/* Kill line from the beginning. */
static void
vty_kill_line_from_beginning (struct vty *vty)
{
  vty_beginning_of_line (vty);
  vty_kill_line (vty);
}

/* Delete a word before the point. */
static void
vty_forward_kill_word (struct vty *vty)
{
  while (vty->cp != vty->length && vty->buf[vty->cp] == ' ')
    vty_delete_char (vty);
  while (vty->cp != vty->length && vty->buf[vty->cp] != ' ')
    vty_delete_char (vty);
}

/* Delete a word before the point. */
static void
vty_backward_kill_word (struct vty *vty)
{
  while (vty->cp > 0 && vty->buf[vty->cp - 1] == ' ')
    vty_delete_backward_char (vty);
  while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
    vty_delete_backward_char (vty);
}

/* Transpose chars before or at the point. */
static void
vty_transpose_chars (struct vty *vty)
{
  char c1, c2;

  /* If length is short or point is near by the beginning of line then
     return. */
  if (vty->length < 2 || vty->cp < 1)
    return;

  /* In case of point is located at the end of the line. */
  if (vty->cp == vty->length)
    {
      c1 = vty->buf[vty->cp - 1];
      c2 = vty->buf[vty->cp - 2];

      vty_backward_char (vty);
      vty_backward_char (vty);
      vty_self_insert_overwrite (vty, c1);
      vty_self_insert_overwrite (vty, c2);
    }
  else
    {
      c1 = vty->buf[vty->cp];
      c2 = vty->buf[vty->cp - 1];

      vty_backward_char (vty);
      vty_self_insert_overwrite (vty, c1);
      vty_self_insert_overwrite (vty, c2);
    }
}

/* Check LCD of matched command. */
int
vty_lcd (char **matched)
{
  int i;
  int j;
  int lcd = -1;
  char *s1, *s2;
  char c1, c2;

  if (matched[0] == NULL || matched[1] == NULL)
    return 0;

  for (i = 1; matched[i] != NULL; i++)
    {
      s1 = matched[i - 1];
      s2 = matched[i];

      for (j = 0; (c1 = s1[j]) && (c2 = s2[j]); j++)
        if (c1 != c2)
          break;

      if (lcd < 0)
        lcd = j;
      else
        {
          if (lcd > j)
            lcd = j;
        }
    }
  return lcd;
}

/* Do completion at vty interface. */
static void
vty_complete_command (struct vty *vty)
{
  struct vty_server *server = vty->server;
  char **matched = NULL;
  int i;
  int lcd = 0;
  int backword = 0;
  char c;

  matched = cli_complete (server->ctree, vty->cli.mode,
                          vty->cli.privilege, vty->buf);

  if (matched)
    {
      if (matched[0] && matched[1] == NULL)
        {
          vty_out (vty, "\n");
          vty_prompt (vty);
          vty_redraw_line (vty);
          vty_backward_pure_word (vty);
          vty_insert_word_overwrite (vty, matched[0]);
          vty_self_insert (vty, ' ');
          XFREE (MTYPE_TMP, matched[0]);
        }
      else
        {
          /* Check LCD.  */
          lcd = vty_lcd (matched);

          if (lcd)
            {
              c = matched[0][lcd];
              matched[0][lcd] = '\0';
              vty_out (vty, "\n");
              vty_prompt (vty);
              vty_redraw_line (vty);
              backword = vty_backward_pure_word (vty);
              vty_insert_word_overwrite (vty, matched[0]);
              matched[0][lcd] = c;
            }

          if (lcd == backword)
            {
              vty_out (vty, "\n");
              for (i = 0; matched[i] != NULL; i++)
                {
                  if (i != 0 && ((i % 6) == 0))
                    vty_out (vty, "\n");
                  vty_out (vty, "%-10s ", matched[i]);
                }
              vty_out (vty, "\n");
              vty_prompt (vty);
              vty_redraw_line (vty);
            }

          /* Free allocated memory.  */
          for (i = 0; matched[i] != NULL; i++)
            XFREE (MTYPE_TMP, matched[i]);
        }

      XFREE (MTYPE_TMP, matched);
    }

  return;
}

/* Describe matched command function. */
static void
vty_describe_command (struct vty *vty)
{
  struct cli *cli;

  cli = &vty->cli;
  cli->zg = vty->zg;
  cli->out_func = (CLI_OUT_FUNC) vty_out;
  cli->out_val = vty;

  cli_describe (cli, vty->server->ctree, cli->mode,
                cli->privilege, vty->buf, vty->width);

  vty_prompt (vty);
  vty_redraw_line (vty);
}

/* ^C stop current input and do not add command line to the history. */
static void
vty_stop_input (struct vty *vty)
{
  /* goto enable mode. */
  vty_end_config (vty);

  /* Set history pointer to the latest one. */
  vty->hp = vty->hindex;
}

/* Add current command line to the history buffer. */
void
vty_hist_add (struct vty *vty)
{
  int index;

  if (vty->history != PAL_TRUE)
    return;
  if (vty->length == 0)
    return;

  index = vty->hindex ? vty->hindex - 1 : VTY_MAXHIST - 1;

  /* Ignore the same string as previous one. */
  if (vty->hist[index])
    if (pal_strcmp (vty->buf, vty->hist[index]) == 0)
      {
        vty->hp = vty->hindex;
        return;
      }

  /* Insert history entry. */
  if (vty->hist[vty->hindex])
    XFREE (MTYPE_VTY_HIST, vty->hist[vty->hindex]);
  vty->hist[vty->hindex] = XSTRDUP (MTYPE_VTY_HIST, vty->buf);

  /* History index rotation. */
  vty->hindex++;
  if (vty->hindex == VTY_MAXHIST)
    vty->hindex = 0;

  vty->hp = vty->hindex;
}

/* Get telnet window size. */
static int
vty_telnet_option (struct vty *vty, unsigned char *buf, int nbytes)
{
#ifdef TELNET_OPTION_DEBUG
  int i;

  for (i = 0; i < nbytes; i++)
    {
      switch (buf[i])
        {
        case IAC:
          vty_out (vty, "IAC ");
          break;
        case WILL:
          vty_out (vty, "WILL ");
          break;
        case WONT:
          vty_out (vty, "WONT ");
          break;
        case DO:
          vty_out (vty, "DO ");
          break;
        case DONT:
          vty_out (vty, "DONT ");
          break;
        case SB:
          vty_out (vty, "SB ");
          break;
        case SE:
          vty_out (vty, "SE ");
          break;
        case TELOPT_ECHO:
          vty_out (vty, "TELOPT_ECHO \n");
          break;
        case TELOPT_SGA:
          vty_out (vty, "TELOPT_SGA \n");
          break;
        case TELOPT_NAWS:
          vty_out (vty, "TELOPT_NAWS \n");
          break;
        default:
          vty_out (vty, "%x ", buf[i]);
          break;
        }
    }
  vty_out (vty, "\n");

#endif /* TELNET_OPTION_DEBUG */

  switch (buf[0])
    {
    case SB:
      buffer_reset (vty->sb_buffer);
      vty->iac_sb_in_progress = 1;
      return 0;
      break;
    case SE:
      {
        char *buffer = (char *) vty->sb_buffer->head->data;
        int length = vty->sb_buffer->length;

        if (buffer == NULL)
          return 0;

        if (!vty->iac_sb_in_progress)
          return 0;

        if (buffer[0] == '\0')
          {
            vty->iac_sb_in_progress = 0;
            return 0;
          }
        switch (buffer[0])
          {
          case TELOPT_NAWS:
            if (length < 5)
              break;
            vty->width = buffer[2];
            vty->height = vty->lines >= 0 ? vty->lines : buffer[4];
            break;
          }
        vty->iac_sb_in_progress = 0;
        return 0;
        break;
      }
    default:
      break;
    }
  return 1;
}

static int
vty_auth_username (struct vty *vty, char *buf)
{
  struct host *host = vty->cli.vr->host;
  struct host_user *user;

  if (host != NULL)
    {
      user = host_user_lookup (host, buf);
      if (user != NULL)
        {
          vty->login_fail = 0;
          vty->cli.index = user;
          vty->cli.mode = AUTH_MODE;
          return 1;
        }
    }
  vty->login_fail = 1;
  vty->cli.index = NULL;
  vty->cli.mode = AUTH_MODE;

  return 0;
}

static int
vty_auth_user_password (struct vty *vty, char *buf)
{
  int privilege = 1;
  int permit;
  struct host_user *user;

  /* Did login pass? */
  if (vty->login_fail)
    {
      user = NULL;
      permit = 0;
    }
  else
    {
      user = vty->cli.index;
      permit = host_password_check (user->password,
                                    user->password_encrypt, buf);
    }

  /* Is this user authenticated? */
  if (permit)
    {
      vty->fail = 0;
      vty->cli.mode = EXEC_MODE;
      vty->cli.privilege = privilege;   /* XXX */
    }
  else
    {
      vty->fail++;
      vty->login_fail = 0;
      if (vty->fail >= 3)
        {
          if (vty->cli.mode == AUTH_MODE)
            {
              vty_out (vty, "%% Bad passwords, too many failures!\n");
              vty->cli.status = CLI_CLOSE;
            }
        }
      vty->cli.mode = LOGIN_MODE;
    }

  return 1;
}

static int
vty_auth_local (struct vty *vty, char *buf)
{
  switch (vty->cli.mode)
    {
    case LOGIN_MODE:
      vty_auth_username (vty, buf);
      break;
    case AUTH_MODE:
      vty_auth_user_password (vty, buf);
      break;
    }
  return 1;
}

/* Execute current command line. */
int
vty_execute (struct vty *vty)
{
  struct host *host = vty->cli.vr->host;
  int ret;

  ret = CLI_SUCCESS;

  switch (vty->cli.mode)
    {
    case LOGIN_MODE:
    case AUTH_MODE:
      if (CHECK_FLAG (host->flags, HOST_LOGIN))
        vty_auth (vty, vty->buf);
      else if (CHECK_FLAG (host->flags, HOST_LOGIN_LOCAL))
        vty_auth_local (vty, vty->buf);
      break;
    case AUTH_ENABLE_MODE:
      vty_auth (vty, vty->buf);
      break;
    default:
      if (vty->type == VTY_TERM)
        vty_hist_add (vty);
      ret = vty_command (vty, vty->buf);
      break;
    }

  /* Clear command line buffer. */
  vty_clear_buf (vty);

  if (vty->cli.status != CLI_CLOSE && vty->cli.status != CLI_CONTINUE &&
      vty->cli.status != CLI_MORE_CONTINUE)
    vty_prompt (vty);

  return ret;
}

#define CONTROL(X)  ((X) - '@')
#define CLI_NORMAL     0
#define VTY_PRE_ESCAPE 1
#define VTY_ESCAPE     2

/* Escape character command map. */
static void
vty_escape_map (char c, struct vty *vty)
{
  switch (c)
    {
    case ('A'):
      vty_previous_line (vty);
      break;
    case ('B'):
      vty_next_line (vty);
      break;
    case ('C'):
      vty_forward_char (vty);
      break;
    case ('D'):
      vty_backward_char (vty);
      break;
    default:
      break;
    }

  /* Go back to normal mode. */
  vty->escape = CLI_NORMAL;
}

/* Quit print out to the buffer. */
static void
vty_buffer_reset (struct vty *vty)
{
  buffer_reset (vty->obuf);
  if (vty->cli.status == CLI_MORE)
    vty_prompt (vty);
  vty_redraw_line (vty);
}

/* Read data via vty socket. */
static int
vty_read (struct thread *t)
{
  int i;
  int ret;
  int nbytes;
  u_char buf[VTY_BUFSIZ];
  pal_sock_handle_t sock;
  struct vty *vty;
  struct lib_globals *g;
  struct cli *cli;

  sock = THREAD_FD (t);
  vty = THREAD_ARG (t);
  g = THREAD_GLOB (t);
  vty->t_read = NULL;
  cli = &vty->cli;

  /* Read data from socket or file */
  nbytes = pal_sock_read (vty->sock, buf, VTY_BUFSIZ);

  if (nbytes <= 0)
    vty->cli.status = CLI_CLOSE;

  for (i = 0; i < nbytes; i++)
    {
      /* Receipt of two consequetive newline characters prevents login
        to vr-cli.  Problem discovered when porting VR to OSE/IPNET.
        Also needed for Windows.  */
      if (nbytes > 1)
        if ((buf[i] == '\r' && buf[i+1] == '\n')
            || (buf[i] == '\n' && buf[i+1] == '\r'))
          i++;

      if (buf[i] == IAC)
        {
          if (!vty->iac)
            {
              vty->iac = 1;
              continue;
            }
          else
            vty->iac = 0;
        }

      if (vty->iac_sb_in_progress && !vty->iac)
        {
          buffer_putc (vty->sb_buffer, buf[i]);
          continue;
        }

      if (vty->iac)
        {
          /* In case of telnet command */
          ret = vty_telnet_option (vty, buf + i, nbytes - i);
          vty->iac = 0;
          i += ret;
          continue;
        }

      if (cli->status == CLI_MORE || cli->status == CLI_MORE_CONTINUE)
        {
          switch (buf[i])
            {
            case CONTROL ('C'):
            case 'q':
            case 'Q':
              {
                int status = cli->status;

                if (cli->callback)
                  {
                    cli->status = CLI_CLOSE;
                    (*cli->callback) (cli);
                  }
                cli->status = status;
                vty_buffer_reset (vty);
              }
              break;
            default:
              break;
            }
          continue;
        }

      /* Escape character. */
      if (vty->escape == VTY_ESCAPE)
        {
          vty_escape_map (buf[i], vty);
          continue;
        }

      /* Pre-escape status. */
      if (vty->escape == VTY_PRE_ESCAPE)
        {
          switch (buf[i])
            {
            case '[':
              vty->escape = VTY_ESCAPE;
              break;
            case 'b':
              vty_backward_word (vty);
              vty->escape = CLI_NORMAL;
              break;
            case 'f':
              vty_forward_word (vty);
              vty->escape = CLI_NORMAL;
              break;
            case 'd':
              vty_forward_kill_word (vty);
              vty->escape = CLI_NORMAL;
              break;
            case CONTROL ('H'):
            case 0x7f:
              vty_backward_kill_word (vty);
              vty->escape = CLI_NORMAL;
              break;
            default:
              vty->escape = CLI_NORMAL;
              break;
            }
          continue;
        }

      switch (buf[i])
        {
        case CONTROL ('A'):
          vty_beginning_of_line (vty);
          break;
        case CONTROL ('B'):
          vty_backward_char (vty);
          break;
        case CONTROL ('C'):
          vty_stop_input (vty);
          break;
        case CONTROL ('D'):
          vty_delete_char (vty);
          break;
        case CONTROL ('E'):
          vty_end_of_line (vty);
          break;
        case CONTROL ('F'):
          vty_forward_char (vty);
          break;
        case CONTROL ('H'):
        case 0x7f:
          vty_delete_backward_char (vty);
          break;
        case CONTROL ('K'):
          vty_kill_line (vty);
          break;
        case CONTROL ('N'):
          vty_next_line (vty);
          break;
        case CONTROL ('P'):
          vty_previous_line (vty);
          break;
        case CONTROL ('T'):
          vty_transpose_chars (vty);
          break;
        case CONTROL ('U'):
          vty_kill_line_from_beginning (vty);
          break;
        case CONTROL ('W'):
          vty_backward_kill_word (vty);
          break;
        case CONTROL ('Z'):
          vty_end_config (vty);
          break;
        case '\n':
        case '\r':
          vty_out (vty, "\n");
          vty_execute (vty);
          break;
        case '\t':
          vty_complete_command (vty);
          break;
        case '?':
          if (vty->cli.mode == LOGIN_MODE
              || vty->cli.mode == AUTH_MODE
              || vty->cli.mode == AUTH_ENABLE_MODE)
            vty_self_insert (vty, buf[i]);
          else
            vty_describe_command (vty);
          break;
        case '\033':
          if (i + 1 < nbytes && buf[i + 1] == '[')
            {
              vty->escape = VTY_ESCAPE;
              i++;
            }
          else
            vty->escape = VTY_PRE_ESCAPE;
          break;
        default:
          if (buf[i] > 31 && buf[i] < 127)
            vty_self_insert (vty, buf[i]);
          break;
        }
    }

  /* Check status. */
  if (vty->cli.status == CLI_CLOSE)
    vty_close (vty);
  else
    {
      vty_event (g, VTY_WRITE, sock, vty);
      vty_event (g, VTY_READ, sock, vty);
    }

  return 0;
}

/* Flush buffer to the vty. */
static int
vty_flush (struct thread *thread)
{
  struct lib_globals *zg = THREAD_GLOB (thread);
  struct vty *vty = THREAD_ARG (thread);
  struct cli *cli;
  pal_sock_handle_t vty_sock = THREAD_FD (thread);
  int ret;
  int erase;

  vty->t_write = NULL;
  cli = &vty->cli;

  /* Temporary disable read thread. */
  if (vty->lines == 0)
    THREAD_OFF (vty->t_read);

  /* Function execution continue. */
  if (cli->status == CLI_MORE || cli->status == CLI_MORE_CONTINUE)
    erase = 1;
  else
    erase = 0;

  /* Write buffer.  */
  if (vty->lines == 0)
    ret = buffer_flush_window (vty, vty->obuf, vty->sock, vty->width,
                               vty->lines, 0, 1);
  else
    ret = buffer_flush_window (vty, vty->obuf, vty->sock, vty->width,
                               vty->lines >= 0 ? vty->lines : vty->height,
                               erase, 0);

  /* Close status check. */
  if (cli->status == CLI_CLOSE)
    {
      vty_close (vty);
      return 0;
    }

  /* All of buffer is flushed out.  */
  if (! buffer_empty (vty->obuf) || ret == 1)
    {
      if (vty->cli.status == CLI_CONTINUE)
        vty->cli.status = CLI_MORE_CONTINUE;
      else
        vty->cli.status = CLI_MORE;
    }
  else
    {
      if (cli->callback)
        {
          if (cli->callback)
            (*cli->callback) (cli);

          vty_event (zg, VTY_WRITE, vty_sock, vty);
        }
      else
        {
          if (cli->status == CLI_CONTINUE || cli->status == CLI_MORE_CONTINUE)
            {
              vty_prompt (vty);
              vty_event (zg, VTY_WRITE, vty_sock, vty);
            }
          vty->cli.status = CLI_NORMAL;
        }
    }

  if (vty->lines == 0)
    vty_event (zg, VTY_READ, vty_sock, vty);

  return 0;
}

/* Create new vty structure. */
struct vty *
vty_create (struct lib_globals *zg, struct ipi_vr *vr,
            struct vty_server *server, pal_sock_handle_t vty_sock,
            struct prefix *local, struct prefix *remote)
{
  struct vty *vty;
  struct host *host = vr->host;
  vector vtyvec = server->vtyvec;

  /* Allocate new vty structure and set up default values. */
  vty = vty_new (zg);

  vty->sock = vty_sock;
  vty->type = VTY_TERM;
  vty->server = server;
  vty->local = local;
  vty->remote = remote;

  /* CLI structure.  */
  vty->cli.vr = vr;
  vty->cli.privilege = PRIVILEGE_NORMAL;

  /* Password check? */
  if (CHECK_FLAG (host->flags, HOST_LOGIN))
    vty->cli.mode = AUTH_MODE;
  else if (CHECK_FLAG (host->flags, HOST_LOGIN_LOCAL))
    vty->cli.mode = LOGIN_MODE;
  else
    {
      vty->cli.mode = EXEC_MODE;
      vty->cli.privilege = PRIVILEGE_ENABLE (vr);
    }

  vty->fail = 0;
  vty_clear_buf (vty);
  pal_mem_set (vty->hist, 0, sizeof (vty->hist));
  vty->hp = 0;
  vty->hindex = 0;
  vector_set_index (vtyvec, vty_sock, vty);
  vty->cli.status = CLI_NORMAL;
  vty->v_timeout = host->timeout;

  if (host->lines >= 0)
    vty->lines = host->lines;
  else
    vty->lines = -1;

  vty->iac = 0;
  vty->iac_sb_in_progress = 0;
  vty->sb_buffer = buffer_new (1024);

  /* We perform this check later on for VR. */
  if (CHECK_FLAG (host->flags, HOST_LOGIN))
    {
      /* Vty is not available if password isn't set. */
      if (host->password == NULL && host->password_encrypt == NULL)
        {
          vty_out (vty, "Vty password is not set.\n");
          vty->cli.status = CLI_CLOSE;
          vty_close (vty);
          return NULL;
        }
    }

  /* Display motd. */
  if (host->motd)
    vty_out (vty, "%s\n", host->motd);

  if (CHECK_FLAG (host->flags, HOST_LOGIN)
      || CHECK_FLAG (host->flags, HOST_LOGIN_LOCAL))
    vty_out (vty, "\nUser Access Verification\n\n");

  /* Setting up terminal. */
  vty_will_echo (vty);
  vty_will_suppress_go_ahead (vty);

  vty_dont_linemode (vty);
  vty_do_window_size (vty);
  /* vty_dont_lflow_ahead (vty); */

  vty_prompt (vty);

  /* Add read/write thread. */
  vty_event (zg, VTY_WRITE, vty_sock, vty);
  vty_event (zg, VTY_READ, vty_sock, vty);

  return vty;
}

/* VTY's accesslist apply. */
int
vty_accept_access_list_apply (struct vty_server *server,
                              struct ipi_vr *vr, struct prefix *p)
{
  struct access_list *acl;
  struct host *host = vr->host;

  /* Allow the connection if the address does not exist.  */
  if (p == NULL)
    return 1;

  if (p->family == AF_INET
      && host->aclass_ipv4 != NULL)
    {
      acl = access_list_lookup (vr, AFI_IP, host->aclass_ipv4);
      if (acl != NULL)
        if ((access_list_apply (acl, p)) == FILTER_DENY)
          return 0;
    }
#ifdef HAVE_IPV6
  else if (p->family == AF_INET6
           && host->aclass_ipv6 != NULL)
    {
      acl = access_list_lookup (vr, AFI_IP6, host->aclass_ipv6);
      if (acl != NULL)
        if ((access_list_apply (acl, p)) == FILTER_DENY)
          return 0;
    }
#endif /* HAVE_IPV6 */

  return 1;
}

/* Accept connection from the network. */
static int
vty_accept (struct thread *thread)
{
  struct lib_globals *zg = THREAD_GLOB (thread);
  struct ipi_vr *vr = NULL;
  struct prefix *local = NULL;
  struct prefix *remote;
  struct interface *ifp;
  struct vty_server *server;
  union sockunion su;
  union sockunion *su_local;
  pal_sock_handle_t vty_sock;
  pal_sock_handle_t accept_sock;
  int ret;

  accept_sock = THREAD_FD (thread);
  server = THREAD_ARG (thread);

  /* We continue hearing vty socket. */
  vty_event (zg, VTY_SERV, accept_sock, server);

  pal_mem_set (&su, 0, sizeof (union sockunion));

  /* We can handle IPv4 or IPv6 socket. */
  vty_sock = sockunion_accept (zg, accept_sock, &su);
  if (vty_sock < 0)
    return -1;

  /* Determine VR context from local address. */
  su_local = sockunion_getsockname (zg, vty_sock);
  if (su_local)
    {
      local = sockunion2hostprefix (su_local);
      if (local != NULL)
        {
          ifp = ifg_lookup_by_prefix (&zg->ifg, local);
          if (ifp != NULL)
            vr = ifp->vr;
        }
      sockunion_free (su_local);
    }

  /* If there is no VR context fount, fallback to PVR. */
  if (vr == NULL)
    vr = ipi_vr_get_privileged (zg);

  remote = sockunion2hostprefix (&su);
  if (!vty_accept_access_list_apply (server, vr, remote))
    {
      /* Access denied.  */
      pal_sock_close (zg, vty_sock);
      if (remote != NULL)
        prefix_free (remote);

      if (local != NULL)
         prefix_free (local);

      return 0;
    }

  ret = pal_sock_set_tcp_nodelay (vty_sock, PAL_TRUE);
  if (ret < 0)
    zlog_info (zg, "can't set sockopt to vty_sock : %s", pal_strerror (errno));

  vty_create (zg, vr, server, vty_sock, local, remote);

  return 0;
}

int
vty_vr_close (struct ipi_vr *vr)
{
  int i;
  struct vty *vty;
  struct vty_server *server = vr->zg->vty_master;

  for (i = 0; i < vector_max (server->vtyvec); i++)
    if ((vty = vector_slot (server->vtyvec, i)))
      if (vty->cli.vr->id == vr->id)
        {
          /* Clear buffer */
          buffer_reset (vty->obuf);
          vty_out (vty, "\nVR session has been closed.\n");

          /* Close connection. */
          vty->cli.status = CLI_CLOSE;
          vty_close (vty);
        }

  return 0;
}

int
vty_vr_unbind (struct ipi_vr *vr)
{
  int i;
  struct vty *vty;
  struct vty_server *server = vr->zg->vty_master;

  for (i = 0; i < vector_max (server->vtyvec); i++)
    if ((vty = vector_slot (server->vtyvec, i)))
      if (vty->cli.vr->id == vr->id)
        if (vty->cli.mode == INTERFACE_MODE)
          {
            /* Clear buffer */
            buffer_reset (vty->obuf);
            vty_out (vty, "\n");

            vty->cli.mode = CONFIG_MODE;
            vty_prompt (vty);

            buffer_flush_all (vty->obuf, vty->sock);
          }

  return 0;
}

int
vty_session_close (struct connected *ifc)
{
  struct vty_server *server = ifc->ifp->vr->zg->vty_master;
  struct vty *vty;
  int i;

  for (i = 0; i < vector_max (server->vtyvec); i++)
    if ((vty = vector_slot (server->vtyvec, i)))
      if (prefix_addr_same (vty->local, ifc->address))
        vty_close (vty);

  return 0;
}

#if defined(HAVE_IPV6) && defined(HAVE_GETADDRINFO)
/* In case of IPv6 use getaddrinfo() to get server socket.  */
int
vty_serv_sock_addrinfo (struct lib_globals *zg, struct vty_server *server,
                        u_int16_t port)
{
  int ret;
  struct pal_addrinfo req;
  struct pal_addrinfo *ainfo;
  struct pal_addrinfo *ainfo_save;
  pal_sock_handle_t sock = 0;
  char port_str[BUFSIZ];

  pal_mem_set (&req, 0, sizeof (struct pal_addrinfo));
  req.ai_flags = AI_PASSIVE;
  req.ai_family = AF_UNSPEC;
  req.ai_socktype = SOCK_STREAM;
  zsnprintf (port_str, sizeof (port_str), "%d", port);
  port_str[sizeof (port_str) - 1] = '\0';

  ret = pal_sock_getaddrinfo (NULL, port_str, &req, &ainfo);

  if (ret != 0)
    {
      zlog_err (zg, "getaddrinfo failed: %s\n", pal_strerror (ret));
      return ret;
    }

  ainfo_save = ainfo;

  do
    {
      if (ainfo->ai_family != AF_INET && ainfo->ai_family != AF_INET6)
        continue;

      sock =
        pal_sock (zg, ainfo->ai_family, ainfo->ai_socktype,
                  ainfo->ai_protocol);
      if (sock < 0)
        continue;

      pal_sock_set_reuseaddr (sock, PAL_TRUE);
      pal_sock_set_reuseport (sock, PAL_TRUE);

      ret = pal_sock_bind (sock, ainfo->ai_addr, ainfo->ai_addrlen);
      if (ret < 0)
        {
          pal_sock_close (zg, sock);
          continue;
        }

      ret = pal_sock_listen (sock, 3);
      if (ret < 0)
        {
          pal_sock_close (zg, sock);
          continue;
        }

      /* Add vty server event. */
      vty_event (zg, VTY_SERV, sock, server);
    }
  while ((ainfo = ainfo->ai_next) != NULL);

  pal_sock_freeaddrinfo (ainfo_save);

  return 0;
}
#endif /* (defined(HAVE_IPV6) && defined(HAVE_GETADDRINFO)) */
/* Make vty server socket. */
int
vty_serv_sock_family (struct lib_globals *zg, struct vty_server *server,
                      u_int16_t port, int family)
{
  int ret;
  union sockunion su;
  pal_sock_handle_t accept_sock;

  pal_mem_set (&su, 0, sizeof (union sockunion));
  su.sa.sa_family = family;

  /* Make new socket. */
  accept_sock = sockunion_stream_socket (zg, &su);
  if (accept_sock < 0)
    return accept_sock;

  /* This is server, so reuse address. */
  pal_sock_set_reuseaddr (accept_sock, PAL_TRUE);
  pal_sock_set_reuseport (accept_sock, PAL_TRUE);

  /* Bind socket to universal address and given port. */
  ret = sockunion_bind (zg, accept_sock, &su, port, NULL);
  if (ret < 0)
    {
      pal_sock_close (zg, accept_sock); /* Avoid sd leak. */
      return ret;
    }

  /* Listen socket under queue 3. */
  ret = pal_sock_listen (accept_sock, 3);
  if (ret < 0)
    {
      zlog_warn (zg, "can't listen socket");

      pal_sock_close (zg, accept_sock); /* Avoid sd leak. */
      return ret;
    }

  /* Add vty server event. */
  vty_event (zg, VTY_SERV, accept_sock, server);

  return 0;
}

/* Determine address family to bind. */
int
vty_serv_sock (struct lib_globals *zg, u_int16_t port)
{
  struct vty_server *server;
  int ret;

  /* Initialize vty master. */
  server = zg->vty_master;

  /* If port is set to 0, do not listen on TCP/IP at all! */
  if (port)
    {
#if defined(HAVE_IPV6) && defined(HAVE_GETADDRINFO)
      ret = vty_serv_sock_addrinfo (zg, server, port);
      if (ret < 0)
        return ret;
#else /* ! (defined(HAVE_IPV6) && defined(HAVE_GETADDRINFO)) */
      ret = vty_serv_sock_family (zg, server, port, AF_INET);
      if (ret < 0)
        return ret;
#endif /* defined(HAVE_IPV6) && defined(HAVE_GETADDRINFO) */
    }

  /* Set VR connection close callback function.  */
  ipi_vr_add_callback (zg, VR_CALLBACK_CLOSE, vty_vr_close);

  /* Set VR unbind callback function.  */
  ipi_vr_add_callback (zg, VR_CALLBACK_UNBIND, vty_vr_unbind);

  /* Set VTY session close callback function.  */
  ifc_add_hook (&zg->ifg, IFC_CALLBACK_SESSION_CLOSE, vty_session_close);

  return 0;
}

/* Close vty interface. */
void
vty_close (struct vty *vty)
{
  struct vty_server *server = vty->server;
  vector vtyvec = server->vtyvec;
  int i;

  /* Cancel threads. */
  if (vty->t_read)
    THREAD_OFF (vty->t_read);
  if (vty->t_write)
    THREAD_OFF (vty->t_write);
  if (vty->t_timeout)
    THREAD_OFF (vty->t_timeout);
  if (vty->t_output)
    THREAD_OFF (vty->t_output);

  /* Flush buffer. */
  if (! buffer_empty (vty->obuf))
    buffer_flush_all (vty->obuf, vty->sock);

  /* Free input buffer. */
  buffer_free (vty->obuf);

  /* Free SB buffer. */
  if (vty->sb_buffer)
    buffer_free (vty->sb_buffer);

  /* Free command history. */
  for (i = 0; i < VTY_MAXHIST; i++)
    if (vty->hist[i])
      XFREE (MTYPE_VTY_HIST, vty->hist[i]);

  /* Unset vector. */
  vector_unset (vtyvec, vty->sock);

  /* Close socket. */
  switch (vty->type)
    {
    case VTY_TERM:
    case VTY_SHELL:
    case VTY_SHELL_SERV:
      if (vty->sock >= 0) {
        pal_sock_close (vty->zg, vty->sock);
      }
      break;
    default:
      break;
    }

  if (vty->local)
    prefix_free (vty->local);
  if (vty->remote)
    prefix_free (vty->remote);
  if (vty->buf)
    XFREE (MTYPE_VTY, vty->buf);

  /* Check configure. */
  vty_config_unlock (vty);

  /* OK free vty. */
  XFREE (MTYPE_VTY, vty);
}

/* When time out occur output message then close connection. */
int
vty_timeout (struct thread *thread)
{
  struct vty *vty;

  vty = THREAD_ARG (thread);
  vty->t_timeout = NULL;
  vty->v_timeout = 0;

  /* Clear buffer */
  buffer_reset (vty->obuf);
  vty_out (vty, "\nVty connection is timed out.\n");

  /* Close connection. */
  vty->cli.status = CLI_CLOSE;
  vty_close (vty);

  return 0;
}

/* Small utility function which output logging to the VTY. */
void
vty_log (struct lib_globals *zg, const char *pristr,
         const char *proto_str, const char *buf)
{
  struct vty_server *vty_master = zg->vty_master;
  struct vty *vty;
  vector vtyvec;
  u_int32_t i;

  if (vty_master == NULL)
    return;

  /* Just discard if vtyvec is not initialized. */
  vtyvec = vty_master->vtyvec;
  if (vtyvec == NULL)
    return;

  for (i = 0; i < vector_max (vtyvec); i++)
    if ((vty = vector_slot (vtyvec, i)) != NULL)
      if (CHECK_FLAG (vty->monitor, VTY_MONITOR_CONFIG))
        {
          SET_FLAG (vty->monitor, VTY_MONITOR_OUTPUT);
          vty_time_print (vty, 0);
          if (! pristr || ! pal_strcmp (pristr, ""))
            vty_out (vty, "%s: %s\r\n", proto_str, buf);
          else
            vty_out (vty, "%s: %s: %s\r\n", pristr, proto_str, buf);
          UNSET_FLAG (vty->monitor, VTY_MONITOR_OUTPUT);
        }
}

int
vty_config_unlock (struct vty *vty)
{
  struct ipi_vr *vr = vty->cli.vr;

  if (vr != NULL)
    return host_config_unlock (vr->host, &vty->cli);

  return 0;
}

/* VTY event manager.  */
void
vty_event (struct lib_globals *zg, enum event event,
           pal_sock_handle_t sock, void *val)
{
  struct thread *t_accept;
  struct vty *vty = val;

  switch (event)
    {
    case VTY_SERV:
      {
        struct vty_server *server = val;
        /* Server accept.  */
        t_accept = thread_add_read_high (zg, vty_accept,
                                         (struct vty_server *)vty, sock);
        vector_set_index (server->Vvty_serv_thread, sock, t_accept);
      }
      break;

    case VTY_READ:
      vty->t_read = thread_add_read_high (zg, vty_read, vty, sock);

      /* Time out treatment. */
      if (vty->v_timeout)
        {
          if (vty->t_timeout)
            thread_cancel (vty->t_timeout);
          vty->t_timeout = thread_add_timer (zg, vty_timeout, vty,
                                             vty->v_timeout);
        }
      break;
    case VTY_WRITE:
      if (!vty->t_write)
        vty->t_write = thread_add_write (zg, vty_flush, vty, sock);
      break;
    case VTY_TIMEOUT_RESET:
      if (vty->t_timeout)
        {
          THREAD_OFF (vty->t_timeout);
        }
      if (vty->v_timeout > 0)
        {
          vty->t_timeout =
            thread_add_timer (zg, vty_timeout, vty, vty->v_timeout);
        }
      break;
    default:
      break;
    }
}


CLI (config_who,
     config_who_cmd,
     "who",
     "Display who is on vty")
{
  struct vty *vty = cli->line;
  struct vty *v;
  int i;

  for (i = 0; i < vector_max (vty->server->vtyvec); i++)
    if ((v = vector_slot (vty->server->vtyvec, i)) != NULL)
      {
        vty_out (vty, "%svty[%d] connected from ", v->config ? "*" : " ", i);
        if (v->remote->family == AF_INET)
          vty_out (vty, "%r\n", &v->remote->u.prefix4);
#ifdef HAVE_IPV6
        else if (v->remote->family == AF_INET6)
          vty_out (vty, "%R\n", &v->remote->u.prefix6);
#endif /* HAVE_IPV6 */
        else
          vty_out (vty, "\n");
      }

  return CLI_SUCCESS;
}

CLI (show_privilege,
     show_privilege_cmd,
     "show privilege",
     "Show running system information",
     "Show current privilege level")
{
  cli_out (cli, "Current privilege level is %d\n", cli->privilege);
  return CLI_SUCCESS;
}

/* Move to vty configuration mode. */
CLI (line_vty,
     line_vty_cmd,
     "line vty",
     "Configure a terminal line",
     "Virtual terminal")
{
  cli->mode = VTY_MODE;
  return CLI_SUCCESS;
}

/* Set time out value. */
int
exec_timeout (struct ipi_vr *vr, struct vty *vty, char *min_str, char *sec_str)
{
  struct lib_globals *zg = vty->zg;
  u_int32_t timeout = 0;

  /* min_str and sec_str are already checked by parser.  So it must be
     all digit string. */
  if (min_str)
    {
      timeout = pal_strtou32 (min_str, NULL, 10);
      timeout *= 60;
    }
  if (sec_str)
    timeout += pal_strtou32 (sec_str, NULL, 10);

  vr->host->timeout = timeout;
  vty->v_timeout = timeout;
  vty_event (zg, VTY_TIMEOUT_RESET, 0, vty);

  return CLI_SUCCESS;
}

CLI (exec_timeout_min,
     exec_timeout_min_cmd,
     "exec-timeout <0-35791>",
     "Set timeout value",
     "Timeout value in minutes")
{
  struct vty *vty = cli->line;
  return exec_timeout (cli->vr, vty, argv[0], NULL);
}

CLI (exec_timeout_sec,
     exec_timeout_sec_cmd,
     "exec-timeout <0-35791> <0-2147483>",
     "Set the EXEC timeout",
     "Timeout in minutes",
     "Timeout in seconds")
{
  struct vty *vty = cli->line;
  return exec_timeout (cli->vr, vty, argv[0], argv[1]);
}

CLI (no_exec_timeout,
     no_exec_timeout_cmd,
     "no exec-timeout",
     CLI_NO_STR,
     "Set the EXEC timeout")
{
  struct vty *vty = cli->line;
  return exec_timeout (cli->vr, vty, NULL, NULL);
}

/* Set vty access class. */
CLI (vty_access_class,
     vty_access_class_cmd,
     "access-class WORD",
     "Filter connections based on an IP access list",
     "IP access list")
{
  struct host *host = cli->vr->host;

  if (host->aclass_ipv4)
    XFREE (MTYPE_VTY, host->aclass_ipv4);

  host->aclass_ipv4 = XSTRDUP (MTYPE_VTY, argv[0]);

  return CLI_SUCCESS;
}

CLI (no_vty_access_class,
     no_vty_access_class_cmd,
     "no access-class (WORD|)",
     CLI_NO_STR,
     "Filter connections based on an IP access list",
     "IP access list")
{
  struct host *host = cli->vr->host;
  struct vty *vty = cli->line;

  if (host->aclass_ipv4 == NULL)
    {
      vty_out (vty, "%% Access-class is not currently applied to VTY\n");
      return CLI_ERROR;
    }

  if (argc > 0)
    if (pal_strcmp (host->aclass_ipv4, argv[0]) != 0)
      {
        vty_out (vty, "%% access-list %s is not applied to VTY\n", argv[0]);
        return CLI_ERROR;
      }

  XFREE (MTYPE_VTY, host->aclass_ipv4);
  host->aclass_ipv4 = NULL;

  return CLI_SUCCESS;
}

#ifdef HAVE_IPV6
/* Set vty access class. */
CLI (vty_ipv6_access_class,
     vty_ipv6_access_class_cmd,
     "ipv6 access-class WORD",
     CLI_IPV6_STR,
     "Filter connections based on an IP access list",
     "IPv6 access list")
{
  struct host *host = cli->vr->host;

  if (host->aclass_ipv6)
    XFREE (MTYPE_VTY, host->aclass_ipv6);

  host->aclass_ipv6 = XSTRDUP (MTYPE_VTY, argv[0]);

  return CLI_SUCCESS;
}

/* Clear vty access class. */
CLI (no_vty_ipv6_access_class,
     no_vty_ipv6_access_class_cmd,
     "no ipv6 access-class [WORD]",
     CLI_NO_STR,
     CLI_IPV6_STR,
     "Filter connections based on an IP access list",
     "IPv6 access list")
{
  struct host *host = cli->vr->host;
  struct vty *vty = cli->line;

  if (host->aclass_ipv6 == NULL)
    {
      vty_out (vty, "%% IPv6 Access-class is not currently applied to VTY\n");
      return CLI_ERROR;
    }

  if (argc > 0)
    if (pal_strcmp (host->aclass_ipv6, argv[0]) != 0)
      {
        vty_out (vty, "%% IPv6 access-list %s is not applied to VTY\n",
                 argv[0]);
        return CLI_ERROR;
      }

  XFREE (MTYPE_VTY, host->aclass_ipv6);
  host->aclass_ipv6 = NULL;

  return CLI_SUCCESS;
}
#endif /* HAVE_IPV6 */

/* vty login. */
CLI (vty_login,
     vty_login_cmd,
     "login",
     "Enable password checking")
{
  struct host *host = cli->vr->host;

  SET_FLAG (host->flags, HOST_LOGIN);
  UNSET_FLAG (host->flags, HOST_LOGIN_LOCAL);

  return CLI_SUCCESS;
}

CLI (no_vty_login,
     no_vty_login_cmd,
     "no login",
     CLI_NO_STR,
     "Enable password checking")
{
  struct host *host = cli->vr->host;

  UNSET_FLAG (host->flags, HOST_LOGIN);
  UNSET_FLAG (host->flags, HOST_LOGIN_LOCAL);

  return CLI_SUCCESS;
}

CLI (vty_login_local,
     vty_login_local_cmd,
     "login local",
     "Enable password checking",
     "Local password checking")
{
  struct host *host = cli->vr->host;

  UNSET_FLAG (host->flags, HOST_LOGIN);
  SET_FLAG (host->flags, HOST_LOGIN_LOCAL);

  return CLI_SUCCESS;
}

CLI (terminal_monitor,
     terminal_monitor_cmd,
     "terminal monitor",
     "Set terminal line parameters",
     "Copy debug output to the current terminal line")
{
  struct vty *vty = cli->line;

  SET_FLAG (vty->monitor, VTY_MONITOR_CONFIG);

  return CLI_SUCCESS;
}

CLI (terminal_no_monitor,
     terminal_no_monitor_cmd,
     "terminal no monitor",
     "Set terminal line parameters",
     CLI_NO_STR,
     "Copy debug output to the current terminal line")
{
  struct vty *vty = cli->line;

  UNSET_FLAG (vty->monitor, VTY_MONITOR_CONFIG);

  return CLI_SUCCESS;
}

CLI (show_history,
     show_history_cmd,
     "show history",
     CLI_SHOW_STR,
     "Display the session command history")
{
  struct vty *vty = cli->line;
  int index;

  /* Tag 1. Please donot delete. */
  for (index = vty->hindex + 1; index != vty->hindex;)
    {
      if (index == VTY_MAXHIST)
        {
          index = 0;
          continue;
        }

      if (vty->hist[index] != NULL)
        cli_out (cli, "  %s\r\n", vty->hist[index]);

      index++;
    }
  return CLI_SUCCESS;
}

/* Terminal length set up.  */
CLI (config_terminal_length,
     config_terminal_length_cli,
     "terminal length <0-512>",
     "Set terminal line parameters",
     "Set number of lines on a screen",
     "Number of lines on screen (0 for no pausing)")
{
  int lines;
  struct vty *vty = cli->line;

  CLI_GET_INTEGER_RANGE("length", lines, argv[0], 0, 512);
  vty->lines = lines;

  return CLI_SUCCESS;
}

CLI (config_terminal_no_length,
     config_terminal_no_length_cli,
     "terminal no length",
     "Set terminal line parameters",
     CLI_NO_STR,
      "Set number of lines on a screen")
{
  struct vty *vty = cli->line;
  vty->lines = -1;
  return CLI_SUCCESS;
}

#ifdef HAVE_VR
CLI (login_virtual_router,
     login_virtual_router_cli,
     "login virtual-router WORD",
     "Login as a particular user",
     "Login to a particular VR context",
     CLI_VR_NAME_STR)
{
  struct vty *vty = cli->line;
  struct ipi_vr *vr;

  vr = ipi_vr_lookup_by_name (cli->vr->zg, argv[0]);
  if (vr == NULL)
    {
      cli_out (cli, "%% No such VR\n");
      return CLI_ERROR;
    }

  vty->cli.vr = vr;
  vty->cli.privilege = PRIVILEGE_VR_MAX;
  SET_FLAG (vty->cli.flags, CLI_FROM_PVR);

  return CLI_SUCCESS;
}

ALI (login_virtual_router,
     configure_virtual_router_cli,
     "configure virtual-router WORD",
     "Enter configuration mode",
     CLI_VR_STR,
     CLI_VR_NAME_STR);

CLI (exit_virtual_router,
     exit_virtual_router_cli,
     "exit virtual-router",
     "End current mode and down to previous mode",
     CLI_VR_STR)
{
  cli_config_exit (cli, argc, argv);
  return CLI_SUCCESS;
}
#endif /* HAVE_VR */

/* Display current configuration. */
int
vty_config_write (struct cli *cli)
{
  struct vty *vty = cli->line;
  struct host *host = cli->vr->host;

  if (! vty || ! vty->server)
    return 0;

  cli_out (cli, "line vty\n");

  /* "access-class". */
  if (host->aclass_ipv4 != NULL)
    cli_out (cli, " access-class %s\n", host->aclass_ipv4);
#ifdef HAVE_IPV6
  if (host->aclass_ipv6 != NULL)
    cli_out (cli, " ipv6 access-class %s\n", host->aclass_ipv6);
#endif /* HAVE_IPV6 */

  /* "exec-timeout". */
  if (host->timeout != VTY_TIMEOUT_DEFAULT)
    cli_out (cli, " exec-timeout %ld %ld\n",
             host->timeout / 60, host->timeout % 60);

  /* "login". */
  if (!CHECK_FLAG (host->flags, HOST_LOGIN)
      && !CHECK_FLAG (host->flags, HOST_LOGIN_LOCAL))
    cli_out (cli, " no login\n");
  else if (CHECK_FLAG (host->flags, HOST_LOGIN))
    cli_out (cli, " login\n");
  else if (CHECK_FLAG (host->flags, HOST_LOGIN_LOCAL))
    cli_out (cli, " login local\n");

  cli_out (cli, "!\n");

  return CLI_SUCCESS;
}

char *
vty_get_cwd (struct lib_globals *zg)
{
  struct vty_server *vty_master = zg->vty_master;
  return vty_master->vty_cwd;
}

int
vty_shell (struct vty * vty)
{
  return vty->type == VTY_SHELL ? 1 : 0;
}

int
vty_shell_serv (struct vty * vty)
{
  return vty->type == VTY_SHELL_SERV ? 1 : 0;
}

int
vty_monitor_output (struct vty *vty)
{
  return CHECK_FLAG (vty->monitor, VTY_MONITOR_OUTPUT);
}

/* Install vty's own commands like `who' command. */
void
vty_cmd_init (struct cli_tree *ctree)
{
  cli_install_config (ctree, VTY_MODE, vty_config_write);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &terminal_monitor_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &terminal_no_monitor_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &config_terminal_length_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &config_terminal_no_length_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_history_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &show_history_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &config_who_cmd);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_privilege_cmd);

  /* VTY_MODE commands. */
  cli_install_default (ctree, VTY_MODE);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &line_vty_cmd);
  cli_install_gen (ctree, VTY_MODE, PRIVILEGE_NORMAL, 0,
                   &exec_timeout_min_cmd);
  cli_install_gen (ctree, VTY_MODE, PRIVILEGE_NORMAL, 0,
                   &exec_timeout_sec_cmd);
  cli_install_gen (ctree, VTY_MODE, PRIVILEGE_NORMAL, 0,
                   &no_exec_timeout_cmd);
  cli_install_gen (ctree, VTY_MODE, PRIVILEGE_NORMAL, 0,
                   &vty_access_class_cmd);
  cli_install_gen (ctree, VTY_MODE, PRIVILEGE_NORMAL, 0,
                   &no_vty_access_class_cmd);
  cli_install_gen (ctree, VTY_MODE, PRIVILEGE_NORMAL, 0,
                   &vty_login_cmd);
  cli_install_gen (ctree, VTY_MODE, PRIVILEGE_NORMAL, 0,
                   &no_vty_login_cmd);
  cli_install_gen (ctree, VTY_MODE, PRIVILEGE_NORMAL, 0,
                   &vty_login_local_cmd);
#ifdef HAVE_IPV6
  cli_install_gen (ctree, VTY_MODE, PRIVILEGE_NORMAL, 0,
                   &vty_ipv6_access_class_cmd);
  cli_install_gen (ctree, VTY_MODE, PRIVILEGE_NORMAL, 0,
                   &no_vty_ipv6_access_class_cmd);
#endif /* HAVE_IPV6 */

#ifdef HAVE_VR
  /* VR commands. */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_PVR_MAX, 0,
                   &login_virtual_router_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, CLI_FLAG_HIDDEN,
                      &configure_virtual_router_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_NORMAL, CLI_FLAG_HIDDEN,
                      &exit_virtual_router_cli);
#endif /* HAVE_VR */
}
