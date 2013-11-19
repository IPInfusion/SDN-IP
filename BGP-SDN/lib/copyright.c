/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "copyright.h"
#include "bgpsdn_version.h"
#include "snprintf.h"

/* Pass TRUE is '\n' is required at the end of the string. */
const char *
bgpsdn_copyright (char *buf, int len)
{
  char tmp[50];
  zsnprintf (buf, len, " version %s %s %s",
             bgpsdn_version (tmp, 50),
             PLATFORM,
             BUILDDATE);
  return buf;
}
