/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "lib.h"
#include "memory.h"
#include "cfg_util.h"
#include "snprintf.h"


cfg_vect_t *
cfg_vect_init(cfg_vect_t *cv)
{
  if (cv != NULL) {
    cfg_vect_reset(cv);
  }
  else {
    cv = XCALLOC(MTYPE_IMI_CFG_CMD, sizeof(cfg_vect_t));
    if (! cv) {
      return NULL;
    }
    cv->cv_v = vector_init(100);
  }
  return cv;
}

void 
cfg_vect_del(cfg_vect_t *cv)
{
  cfg_vect_reset(cv);
  vector_free(cv->cv_v);
  XFREE(MTYPE_IMI_CFG_CMD, cv);
}

void
cfg_vect_add_cmd(cfg_vect_t *cv, const char *fmt, ...)
{
  va_list args;
  char tmp[512];
  char *cmd;
  int tlen;
  
  va_start (args, fmt);
  zvsnprintf (tmp, sizeof(tmp), fmt, args);
  tlen = strlen(tmp);
  if (!tlen) {
    va_end (args);
    return;
  }
  if (cv->cv_last_len == 0) {
    /* New command. */
    cmd = XSTRDUP(MTYPE_IMI_CFG_CMD, tmp);  
    cv->cv_last_ix = vector_set(cv->cv_v, cmd);
  }
  else {
    /* Next part of the same command string */
    cmd = vector_lookup_index (cv->cv_v, cv->cv_last_ix);
    cmd = XREALLOC(MTYPE_IMI_CFG_CMD, cmd, cv->cv_last_len + tlen+1);
    pal_strncpy(&cmd[cv->cv_last_len], tmp, tlen+1);
    vector_set_index (cv->cv_v, cv->cv_last_ix, cmd);
  }
  if (tmp[tlen-1] == '\n') {
    /* Last part of the command */
    cv->cv_last_len = 0;
  }
  else {
    /* Yet, another part of the same command string. */
    cv->cv_last_len += tlen;
  }
  va_end (args);
}


/*-----------------------------------------------------------------
 * Write the all commands to CLI - free cmd buffer memory - init entry.
 *-----------------------------------------------------------------
 */
void
cfg_vect_out(cfg_vect_t *cv, cfg_vect_out_fun_t out_fun, void *out_writer)
{
  int   ix; 
  char *cmd;

  VECTOR_LOOP(cv->cv_v, cmd, ix)
  {
    out_fun (out_writer, "%s", cmd);
    vector_unset(cv->cv_v, ix);
    XFREE(MTYPE_IMI_CFG_CMD, cmd);
  }
}

/* Free all vector elements */
void
cfg_vect_reset(cfg_vect_t *cv)
{
  int   ix; 
  char *cmd;

  VECTOR_LOOP(cv->cv_v, cmd, ix)
  {
    vector_unset(cv->cv_v, ix);
    XFREE(MTYPE_IMI_CFG_CMD, cmd);
  }
  cv->cv_last_len = 0;
}

int cfg_vect_count(cfg_vect_t *cv)
{
  return vector_count(cv->cv_v);
}
