/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_IMI_CLIENT_H
#define _BGPSDN_IMI_CLIENT_H

#include "line.h"

typedef void (*IMI_CLIENT_EVENT_NTF_CB)(struct lib_globals *zg);

typedef enum _imi_client_event_ntf_type
{
  IMI_CLT_NTF_CONFIG_DONE = 0,
  IMI_CLT_NTF_SRV_DISCON  = 1,
  IMI_CLT_NTF_MAX
} IMI_CLIENT_EVENT_NTF_TYPE;


/* IMI client structure.  */
struct imi_client
{
  /* Message handler.  */
  struct message_handler *mc;

  /* Reconnect thread. */
  struct thread *t_reconnect;

  /* Reconnect interval in seconds. */
  int reconnect_interval;

  /* Debug message flag. */
  int debug;

  /* Line info.  */
  struct line line;

  struct imi_confses_db confses_db;

  /* Only when this flag is set we call "disconnect"
     notification callback.
   */
  bool_t                  ic_connected;

  IMI_CLIENT_EVENT_NTF_CB ic_event_ntf_cbs[IMI_CLT_NTF_MAX];

};

#define IMI_CLIENT_RECONNECT_INTERVAL   5

#define NSM_DONE_FILE               "/var/run/nsm_done"

int imi_client_create (struct lib_globals *, int);
int imi_client_delete (struct lib_globals *);
int imi_client_send_config_request (struct ipi_vr *);

ZRESULT imi_client_register_event_ntf_cb (struct lib_globals      *zg,
                                          IMI_CLIENT_EVENT_NTF_TYPE ntf_type,
                                          IMI_CLIENT_EVENT_NTF_CB   ntf_cb);

#endif /* _BGPSDN_IMI_CLIENT_H */
