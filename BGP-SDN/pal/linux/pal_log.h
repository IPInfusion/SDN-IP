/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */

#ifndef _PAL_LOG_H
#define _PAL_LOG_H

/* Configuration for BGP-SDN logging. */
#define PAL_LOG_STDOUT
#define PAL_LOG_STDERR
#define PAL_LOG_SYSTEM
#define PAL_LOG_FILESYS

/* Defines. */
#define DIR_CHAR       '/'
#define IS_DIRECTORY_SEP(c) ((c) == DIR_CHAR)

#define TIME_BUF            27
#define PATHNAME_BUF        1024

struct pal_log_data
{
  FILE *fp;
};

#include "log.h"
#include "pal_log.def"

#endif /* _PAL_LOG_H */
