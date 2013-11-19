/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "lib.h"

#include "zffs.h"

/* When system has ffs() for finding first bit set in word, use it.
   Otherwise use zffs().  */

#ifndef HAVE_FFS
int
zffs (u_int32_t mask)
{
  register int bit;

  if (mask == 0)
    return 0;

  for (bit = 1; ! (mask & 1); bit++)
    mask >>= 1;

  return bit;
}
#endif /* ! HAVE_FFS */
