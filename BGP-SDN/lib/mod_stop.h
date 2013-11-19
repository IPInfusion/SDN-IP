/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef MOD_STOP_H
#define MOD_STOP_H

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

typedef enum mod_stop_cause
{
  MOD_STOP_CAUSE_NO_STOP = 0,
  MOD_STOP_CAUSE_USER_KILL,
  MOD_STOP_CAUSE_GRACE_RST,
  MOD_STOP_CAUSE_MAX,
} mod_stop_cause_t;

typedef void (* mod_stop_cb_t)(mod_stop_cause_t);

ZRESULT mod_stop_reg_cb(u_int16_t mod_id, mod_stop_cb_t stop_cb);
ZRESULT mod_stop_unreg_cb(u_int16_t mod_id);

void mod_stop(u_int16_t mod_id, mod_stop_cause_t cause);

#endif

