/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

/*------------------------------------------------------------------------
 *  NOTE:
 *  This is a registry of module stop callbacks.
 *  Different callbakcs might need to be registered for different platforms.
 *  One callback is registered per module.
 *  At the time of departure, the module calls mod_stop() and the callback
 *  is executed.
 *  Callbacks must be registered from "platform" subdirectory.
 *------------------------------------------------------------------------
*/

#include "pal.h"
#include "mod_stop.h"

struct mod_stop_info
{
  mod_stop_cb_t stop_cb;
};

/* We assume global variables are zeroed during start time. */

static struct mod_stop_info mod_stop_info_tab[IPI_PROTO_MAX];

/* To register a function to stop module from software. */
ZRESULT
mod_stop_reg_cb(u_int16_t mod_id, mod_stop_cb_t stop_cb)
{
  if (mod_id <= IPI_PROTO_UNSPEC || mod_id >= IPI_PROTO_MAX)
  {
    return ZRES_ERR;
  }
  mod_stop_info_tab[mod_id].stop_cb = stop_cb;
  return ZRES_OK;
}

/* To unregister a function to stop module from software. */
ZRESULT
mod_stop_unreg_cb(u_int16_t mod_id)
{
  if (mod_id <= IPI_PROTO_UNSPEC || mod_id >= IPI_PROTO_MAX)
  {
    return ZRES_ERR;
  }
  mod_stop_info_tab[mod_id].stop_cb = NULL;
  return ZRES_OK;
}

/* To stop the module with a grace. */
void
mod_stop(u_int16_t mod_id, mod_stop_cause_t cause)
{
  if (mod_id <= IPI_PROTO_UNSPEC || mod_id >= IPI_PROTO_MAX)
    return;

  if (mod_stop_info_tab[mod_id].stop_cb != NULL)
    mod_stop_info_tab[mod_id].stop_cb(cause);
}

