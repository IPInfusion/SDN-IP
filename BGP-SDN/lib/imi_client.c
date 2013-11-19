/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "network.h"

#include "lib.h"
#include "thread.h"
#include "line.h"
#include "message.h"
#include "imi_client.h"
#include "snprintf.h"


/* Send error message.  */
void
imi_client_set_error (struct imi_client *ic, const char *format, ...)
{
  va_list args;

  ic->line.code = LINE_CODE_ERROR;

  va_start (args, format);
  zvsnprintf (ic->line.str, LINE_BODY_LEN, format, args);
  va_end (args);
}

int
imi_client_send_reply (struct imi_client *ic)
{
  int length;

  line_header_encode (&ic->line);

  length = writen (ic->line.sock, (u_char *)ic->line.buf, ic->line.length);
  if (length != ic->line.length)
    return -1;

  return 0;
}

int imi_client_reconnect_start (struct imi_client *);

/* Start IMI client.  */
int
imi_client_start (struct imi_client *ic)
{
  int ret;

  if ((ret = message_client_start (ic->mc)) < 0)
    if (ic->t_reconnect == NULL)
      return imi_client_reconnect_start (ic);

  return ret;
}

/* Reconnect thread.  */
int
imi_client_reconnect (struct thread *thread)
{
  struct imi_client *ic;

  ic = THREAD_ARG (thread);
  ic->t_reconnect = NULL;

  imi_client_start (ic);

  return 1;
}

/* Reconnect to IMI.  */
int
imi_client_reconnect_start (struct imi_client *ic)
{
  struct message_handler *mc = ic->mc;

  /* Start reconnect timer.  */
  ic->t_reconnect = thread_add_timer (mc->zg, imi_client_reconnect,
                                      ic, ic->reconnect_interval);
  if (ic->t_reconnect == NULL)
    return 0;

  return 1;
}

/* Client connection is established.  Client send service description
   message to the server.  */
int
imi_client_connect (struct message_handler *mc,
                    struct message_entry *me, pal_sock_handle_t sock)
{
  int ret;
  struct imi_client *ic = mc->info;
  struct line *line = &ic->line;

  /* Make the client socket blocking. */
  pal_sock_set_nonblocking (sock, PAL_FALSE);

  /* Prepare line header info.  */
  line->zg = mc->zg;
  line->sock = sock;
  line->module = modbmap_id2bit (mc->zg->protocol);
  line->code = LINE_CODE_CONNECT;
  line->str = NULL;
  line->pid = 0;
  line->vr_id = 0;
  line->vr  = ipi_vr_get_privileged(mc->zg);

  /* Encode line header.  */
  line_header_encode (line);

  /* Send protocol module ID to IMI server.  */
  ret = writen (mc->sock, (u_char *)line->buf, line->length);
  if (ret != line->length)
    return -1;

  /* Register read thread.  */
  message_client_read_register (mc);

  ic->ic_connected = PAL_TRUE;

  return 0;
}

int
imi_client_disconnect (struct message_handler *mc,
                       struct message_entry *me, pal_sock_handle_t sock)
{
  struct imi_client *ic = mc->info;

  /* Stop message client.  */
  message_client_stop (mc);

  /* Remove all configuration sessions from the database */
  imi_confses_db_empty(&ic->confses_db);

  /* Dispatch disconnect notification callback, if registered.
     Only if we switch from "connected" state.
   */
  if (ic->ic_connected && ic->ic_event_ntf_cbs[IMI_CLT_NTF_SRV_DISCON])
      (ic->ic_event_ntf_cbs[IMI_CLT_NTF_SRV_DISCON])(mc->zg);

  ic->ic_connected = PAL_FALSE;

  /* Go back to the privileged VR context. */
  ic->line.vr_id = 0;
  ic->line.vr = ipi_vr_get_privileged(mc->zg);

  /* Forget about the last config session. */
  ic->line.pid = 0;

  /* Start reconnect thread.  */
  imi_client_reconnect_start (ic);

  return 0;
}

/* Read IMI line CLI.  */
int
imi_client_read (struct message_handler *mc,
                 struct message_entry *me, pal_sock_handle_t sock)
{
  int ret;
  int nbytes, length;
  struct imi_client *ic = mc->info;
  struct imi_confses *confses;
  char *cmd_str;

  /* Read IMI line header.  */
  nbytes = pal_sock_read (sock, ic->line.buf, LINE_HEADER_LEN);
  if (nbytes != LINE_HEADER_LEN)
    return -1;

  /* Decode line header.  */
  line_header_decode (&ic->line);

  if (ic->line.length < LINE_HEADER_LEN || ic->line.length > LINE_MESSAGE_MAX)
    return -1;

  length = ic->line.length - LINE_HEADER_LEN;

  if ((length != 0) && (pal_sock_read (sock, ic->line.str, length) != length))
    return -1;

/*  printf("%d->%s\n", ic->line.code, ic->line.str); */


  /* Check the module ID.  */
  if (! MODBMAP_ISSET (ic->line.module, mc->zg->protocol))
    return -1;

  /* Check VR.  */
  ic->line.vr = ipi_vr_lookup_by_id (mc->zg, ic->line.vr_id);

  if (ic->line.vr == NULL)
  {
    /* VR has been already deleted. Remove the config session */
    imi_confses_del(&ic->confses_db, ic->line.pid);

    /* We have a choice to send an error or success... Hm... */
    ic->line.code = LINE_CODE_SUCCESS;
    return imi_client_send_reply (ic);
  }

  switch (ic->line.code) {

  case LINE_CODE_COMMAND:
    {
      u_int32_t sid;
/*
      zlog_debug (mc->zg, "CLI CMD: Vr:%s/%d Cmd:\"%s\"",
                  ic->line.vr->name ?  ic->line.vr->name : "PVR",
                  ic->line.vr_id,
                  ic->line.str);
*/
      cmd_str = ic->line.str;
      cmd_str = cli_skip_white_space(cmd_str);

      if ((pal_strncasecmp("no ", cmd_str, 3) == 0) ||
          (pal_strncasecmp("n ", cmd_str, 2) == 0))
      {
        /* Check any session on this VR in a nested config mode
           and reject "no ... " command to prevent collision
        */
        int sid = imi_confses_check(&ic->confses_db, ic->line.pid,
                                    ic->line.vr_id);
        if (sid > 0)
        {
            imi_client_set_error (ic,
                                "%% IMISH (pid:%d) in nested config mode"
                                  " - \"no ...\" commands are disabled\n",
                                  sid);
            ret = imi_client_send_reply (ic);
            break;
        }
      }
    /* Retrieve the CLI session state */
      if ((confses=imi_confses_get(&ic->confses_db,
                                   ic->line.pid,
                                   ic->line.vr_id)) == NULL) {
      imi_client_set_error (ic, "%% Cannot retrieve/install config session state\n");
        ret = imi_client_send_reply(ic);
        break;
      }
      /* Execute the command */
      line_parser (&ic->line, confses);

      /* Save the session state in any case.
         NOTE:It will be removed if the index is NULL.
      */
      ret = imi_confses_save(&ic->confses_db, confses, &sid);

      /* Return an error only if the parser returned success */
      if (ret<0 && ic->line.code == LINE_CODE_SUCCESS)
      {
        if (ret == -1)
          imi_client_set_error (ic, "%% Cannot save config session state\n");
        else if (ret == -2)
          imi_client_set_error(ic,"%% Interfering with VTY session"
                               " - socket:%d\n",sid);
        else
          imi_client_set_error(ic, "%% Cannot save config session state\n");
      }
      ret = imi_client_send_reply(ic);
    }
    break;

  case LINE_CODE_CONFIG_END:
    {
      SET_FLAG (ic->line.vr->host->flags, HOST_CONFIG_READ_DONE);

      /* Remove the IMI server session state. */
      imi_confses_del(&ic->confses_db, ic->line.pid);

    ret = 0;

    /* Dispatch config done notification callback, if registered. */
    if (ic->ic_event_ntf_cbs[IMI_CLT_NTF_CONFIG_DONE])
      (ic->ic_event_ntf_cbs[IMI_CLT_NTF_CONFIG_DONE])(mc->zg);
  }
    break;

  case LINE_CODE_CONFSES_CLR:
    {
    imi_confses_del(&ic->confses_db, ic->line.pid);
    ret = 0;
  }
    break;

  default:
    imi_client_set_error (ic, "%% Invalid input\n");
    ret = imi_client_send_reply (ic);
  }
  return ret;
}

int
imi_client_start_timer_trill (struct thread *thread)
{
  struct imi_client *ic;
  ic = THREAD_ARG (thread);

  imi_client_start (ic);

  return 0;
}

/* Start IMI client.  */
int
imi_client_create (struct lib_globals *zg, int now)
{
  struct imi_client *ic;
  struct message_handler *mc;
  int type = MESSAGE_TYPE_ASYNC;

  ic = XCALLOC (MTYPE_IMI_CLIENT, sizeof (struct imi_client));
  if (ic == NULL)
    return -1;

  /* Create async message client.  */
  mc = message_client_create (zg, type);
  if (mc == NULL)
    return -1;

#ifdef HAVE_TCP_MESSAGE
  message_client_set_style_tcp (mc, IMI_LINE_PORT);
#else
  message_client_set_style_domain (mc, IMI_LINE_PATH);
#endif /* HAVE_TCP_MESSAGE */

  /* Initiate connection using IMI connection manager.  */
  message_client_set_callback (mc, MESSAGE_EVENT_CONNECT,
                               imi_client_connect);
  message_client_set_callback (mc, MESSAGE_EVENT_DISCONNECT,
                               imi_client_disconnect);
  message_client_set_callback (mc, MESSAGE_EVENT_READ_MESSAGE,
                               imi_client_read);

  /* Link each other.  */
  zg->imh = mc;
  mc->info = ic;
  ic->mc = mc;

  /* Set reconnect interval.  */
  ic->reconnect_interval = IMI_CLIENT_RECONNECT_INTERVAL;

  /* Keep the global pointer and the socket in the line structure.  */
  ic->line.zg = zg;

  /* Create a DB of all active CLI sesions states */
  if (imi_confses_db_init(&ic->confses_db)!=0)
    return -1;

  /* As per BGP-SDN Architecture, while reading from the config file,
   * IMI executes the config before NSM, which causes Bridge not found
   * error occasionally. 
   * To delay the notification to IMI in order to recv 
   * Bridge Add MSG from NSM First, adding a small delay.
   * To verify if this is OK
   */
  imi_client_start (ic);

  return 0;
}

/* Stop IMI client.  */
int
imi_client_delete (struct lib_globals *zg)
{
  struct message_handler *mc = zg->imh;
  struct imi_client *ic;

  if (mc == NULL || (ic = mc->info) == NULL)
    return -1;

  /* Cancel reconnect thread.  */
  if (ic->t_reconnect)
    THREAD_OFF (ic->t_reconnect);

  /* Free the message handler.  */
  message_client_delete (mc);

  /* Delete the configuration sessions database */
  imi_confses_db_delete(&ic->confses_db);

  XFREE (MTYPE_IMI_CLIENT, ic);

  zg->imh = NULL;

  return 0;
}

int
imi_client_send_config_request (struct ipi_vr *vr)
{
  struct lib_globals *zg = vr->zg;
  struct message_handler *mc = zg->imh;
  struct imi_client *ic = mc->info;
  struct line *line = &ic->line;
  int ret;

  line->zg = zg;
  line->code = LINE_CODE_CONFIG_REQUEST;
  line->str = NULL;
  line->vr_id = vr->id;

  /* Encode line header. */
  line_header_encode (line);

  /* Send config request to IMI server. */
  ret = writen (mc->sock, (u_char *)line->buf, line->length);
  if (ret != line->length)
    return -1;

  return 0;
}

ZRESULT
imi_client_register_event_ntf_cb (struct lib_globals      *zg,
                                  IMI_CLIENT_EVENT_NTF_TYPE ntf_type,
                                  IMI_CLIENT_EVENT_NTF_CB   ntf_cb)
{
  struct message_handler *mc = NULL;
  struct imi_client *ic = NULL;

  if (ntf_type < IMI_CLT_NTF_CONFIG_DONE || ntf_type >= IMI_CLT_NTF_MAX)
    return ZRES_ERR;

  if (ntf_cb == NULL)
    return ZRES_ERR;

  mc = zg->imh;
  if (!mc)
    return ZRES_ERR;

  ic = mc->info;
  if (!ic)
    return ZRES_ERR;

  ic->ic_event_ntf_cbs [ntf_type] = ntf_cb;
  return ZRES_OK;
}


