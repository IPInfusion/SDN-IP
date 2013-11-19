/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_VERSION_H
#define _BGPSDN_VERSION_H

#include "pal.h"
#include "copyright.h"

#define BGPSDN_MAJOR_RELEASE    "1"
#define BGPSDN_MINOR_RELEASE    "0"
#define BGPSDN_POINT_RELEASE    "0"
#define BGPSDN_PATCH_RELEASE    "0"

#ifndef BGPSDN_PLATFORM
#define PLATFORM               "IPISDNRouter"
#else
#define PLATFORM               BGPSDN_PLATFORM
#endif

#ifndef BGPSDN_PLATFORM_ACRONYM
#define PLATFORM_ACRONYM       "IPI"
#else
#define PLATFORM_ACRONYM       BGPSDN_PLATFORM_ACRONYM
#endif

#ifndef BGPSDN_CURR_RELEASE
#define CURR_RELEASE           ""
#else
#define CURR_RELEASE           BGPSDN_CURR_RELEASE
#endif

#define BGPSDN_BUG_ADDRESS      "support@ipinfusion.com"

extern const char *host_name;

/* Check if current version is FCS or GA. */
#define CURR_VERSION_IS_FCS(c)                                             \
        ((pal_strcasecmp (c, "FCS") == 0 || pal_strcasecmp (c, "GA") == 0) \
         ? PAL_TRUE : PAL_FALSE)

/* Prototypes. */
const char *bgpsdn_version (char *, int);
const char *bgpsdn_buildno (char *, int);
void print_version (char *);

#endif /* _BGPSDN_VERSION_H */
