/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _CFG_UTIL_H
#define _CFG_UTIL_H

#include "vector.h"

/*-------------------------------------------------------------------------
 * cfg_vect_t - Used to encode commands at the time of configuring 
 *              PM during startup.
 *-------------------------------------------------------------------------
 */
typedef struct cfg_vect
{
  vector    cv_v;
  u_int16_t cv_last_len;   /* length of the last stored incomplete command */
  u_int32_t   cv_last_ix;    /* vector index of the last stored incomplete command;
                              valid only if cv_last_len is > 0                    
                           */
} cfg_vect_t;

typedef int (*cfg_vect_out_fun_t) (void *, const char *, ...);

cfg_vect_t  *cfg_vect_init (cfg_vect_t *cv);
void cfg_vect_del (cfg_vect_t *cv);
void cfg_vect_add_cmd (cfg_vect_t *cv, const char *fmt, ...);
void cfg_vect_out(cfg_vect_t *cv, cfg_vect_out_fun_t out_fun, void *out_writer);
void cfg_vect_reset (cfg_vect_t *cv);
int cfg_vect_count(cfg_vect_t *cv);

#endif /* _CFG_UTIL_H */

