/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */
#ifndef _BGPSDN_LOG_H
#define _BGPSDN_LOG_H

/* Forward declaration. */
#include "cfg_util.h"

struct cli;
struct cli_tree;

#define ZLOG_NOLOG                 0x0
#ifdef PAL_LOG_STDOUT
#define ZLOG_STDOUT                0x1
#endif /* PAL_LOG_STDOUT */
#ifdef PAL_LOG_STDERR
#define ZLOG_STDERR                0x2
#endif /* PAL_LOG_STDERR */
#ifdef PAL_LOG_SYSTEM
#define ZLOG_SYSTEM                0x4
#endif /* PAL_LOG_SYSTEM */
#ifdef PAL_LOG_FILESYS
#define ZLOG_FILE                  0x8
#endif /* PAL_LOG_FILESYS */

#define ZLOG_BUF_MAXLEN              1024
#define ZLOG_PRIORITY_STR_MAXLEN       17

enum log_severity
{
  ZLOG_EMERGENCY,     /* Emergency. */
  ZLOG_ALERT,         /* Alert. */
  ZLOG_CRITICAL,      /* Critical. */
  ZLOG_ERROR,         /* Error. */
  ZLOG_WARN,          /* Warning. */
  ZLOG_NOTIFY,        /* Notification. */
  ZLOG_INFO,          /* Informational. */
  ZLOG_DEBUG          /* Debugging. */
};

enum log_destination
{
  LOGDEST_DEFAULT,
  LOGDEST_MAIN
};

struct zlog
{
  /* Log destination. */
  enum log_destination dest;

  /* Instance. */
  u_int32_t instance;

  /* Protocol ID */
  module_id_t protocol;

  /* Mask priority. */
  u_int32_t maskpri;

  /* Priority. */
  u_int32_t record_priority;

  /* Flags. */
  u_char flags;

#ifdef PAL_LOG_FILESYS
  /* Log filename. */
  char *logfile;
  u_int32_t log_maxsize;
#endif /* PAL_LOG_FILESYS */

  /* Platform specific data. */
  void *pal_log_data;
};

/* Message structure. */
struct message
{
  s_int32_t key;
  char *str;
};

/* For hackey massage lookup and check */
#define LOOKUP(X,Y)     mes_lookup(X, X ## _max, Y)

char *lookup (struct message *, s_int32_t);
char *mes_lookup (struct message *, s_int32_t, s_int32_t);

struct zlog *openzlog (struct lib_globals *, u_int32_t, module_id_t,
                       enum log_destination);
void closezlog (struct lib_globals *, struct zlog *);
void zlog (struct lib_globals *, struct zlog *, int, const char *, ...);
void zlog_err (struct lib_globals *, const char *, ...);
void zlog_warn (struct lib_globals *, const char *, ...);
void zlog_info (struct lib_globals *, const char *, ...);
void zlog_debug (struct lib_globals *, const char *, ...);
void plog_err (struct lib_globals *, struct zlog *, const char *, ...);
void plog_info (struct lib_globals *, struct zlog *, const char *, ...);
void zlog_rotate (struct lib_globals *, struct zlog *);
int zlog_config_write (struct cli *);
char * zlog_get_priority_str(s_int8_t prio);

int zlog_config_encode(struct lib_globals *zg, cfg_vect_t *cv);
void zlog_cli_init (struct cli_tree *);

#endif /* _BGPSDN_LOG_H */
