/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <pal.h>

#include "show.h"
#include "thread.h"
#include "snprintf.h"
#include "modbmap.h"
#include "network.h"
#include "cli.h"
#include "log.h"
#include "tlv.h"

/* All of "show" commands are installed in EXEC_MODE.  One exception
   is "show running-config", it will be installed into all modes for
   user convenience.  */

/* General function for "show" command.  So typical way of defining
   "show" command is like this:

   ALI (imish_show_func,
   show_ip_dns_domain_name_cli,
   "show ip domain-name",
   CLI_SHOW_STR,
   CLI_IP_STR,
   "Default domain for DNS")

   cli_install_imi (ctree, EXEC_MODE, IMISH_IMI, &show_ip_dns_domain_name_cli);

   This parse the user input string, then execute imish_show_func().
   imish_show_func() take care of sending user input to proper process
   and show the result.  */


/* Utility function to write the line to IMI.  */
int
show_line_write (struct lib_globals *glob, pal_sock_handle_t sock,
                 char *buf, u_int16_t length, u_int32_t vr_id)
{
  int nbytes;
  u_char buf_id[4];

  /* Check socket.  */
  if (sock < 0)
    {
      zlog_err (glob, "Show connection to protocol is gone\n");
      return -1;
    }

  /* Encode VR ID and send it. */
  buf_id[0] = (vr_id >> 24) & 0xFF;
  buf_id[1] = (vr_id >> 16) & 0xFF;
  buf_id[2] = (vr_id >> 8) & 0xFF;
  buf_id[3] = vr_id & 0xFF;

  nbytes = writen (sock, buf_id, 4);
  if (nbytes <= 0)
    {
      zlog_err (glob, "Show socket is closed!\n");
      return -1;
    }

  /* Send the message. */
  nbytes = writen (sock, buf, length);
  if (nbytes <= 0)
    {
      zlog_err (glob, "Show socket is closed!\n");
      return -1;
    }

  /* Check written value. */
  if (nbytes != length)
    {
      zlog_err (glob, "Show socket write was partial!\n");
      return -1;
    }
  return nbytes;
}

CLI (generic_show_func,
     generic_show_func_cli,
     "Internal_function",
     "Internal_function")
{
  struct cli_element *cel;
  module_id_t module_id;
  static char buf[BUFSIZ];
  int nbytes;
  int sock;

  cel = cli->cel;

  for (module_id = IPI_PROTO_IMI; module_id < IPI_PROTO_MAX; module_id++)
    {
      if (module_id == IPI_PROTO_IMI)
        continue;

      if (MODBMAP_ISSET (cel->module, module_id))
        {
          /* Open socket. */
          sock = show_client_socket (cli->zg, module_id);
          if (sock < 0)
            {
              /* The module daemon is not running.
               */
              continue;
            }

          /* Send command.  */
          show_line_write (cli->zg, sock, cli->str,
                           pal_strlen (cli->str), cli->vr->id);

          /* Print output to stdout.  */
          while (1)
            {
              nbytes = pal_sock_read (sock, buf, BUFSIZ - 1);
              if (nbytes <= 0)
                break;
              buf[nbytes] = '\0';
              cli_out (cli, "%s", buf);
            }
          cli_out(cli, "\n");
          /* Close socket.  */
          pal_sock_close (cli->zg, sock);
        }
    }

  return CLI_SUCCESS;
}
