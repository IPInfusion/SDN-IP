/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_REGEX_H
#define _BGPSDN_BGP_REGEX_H



#include "pal_regex.h"

void bgp_regex_free (pal_regex_t *regex);
pal_regex_t *bgp_regcomp (char *str);
int bgp_regexec (pal_regex_t *regex, struct aspath *aspath);
#ifdef HAVE_EXT_CAP_ASN
int bgp_regexec_aspath4B (pal_regex_t *regex, struct as4path *as4path);
#endif /* HAVE_EXT_CAP_ASN */
#endif /* _BGPSDN_BGP_REGEX_H */
