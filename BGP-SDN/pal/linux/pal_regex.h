/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _PAL_REGEX_H
#define _PAL_REGEX_H

/*
  pal_regex.h -- BGP-SDN PAL regular expression functions
*/
#include "pal.h"
#include "regex.h"

#define pal_regex_t regex_t
#define pal_regmatch_t regmatch_t

#include "pal_regex.def"

#undef pal_regcomp
#define pal_regcomp regcomp

#undef pal_regexec
#define pal_regexec regexec

#undef pal_regerror
#define pal_regerror regerror

#undef pal_regfree
#define pal_regfree regfree

#endif /* _PAL_REGEX_H */
