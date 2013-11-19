/*  Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved. */

/*
**
** pal_string.c -- BGP-SDN PAL definitions for string management
*/

#include "pal.h"
#include "pal_string.h"

pal_handle_t 
pal_strstart(struct lib_globals *lib_node) 
{
  return (pal_handle_t) 1;
}

result_t 
pal_strstop(struct lib_globals *lib_node) 
{
  return RESULT_OK;
}

