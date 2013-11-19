/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _PAL_MATH_H
#define _PAL_MATH_H

/*
  pal_math.h -- BGP-SDN PAL math functions
*/
#include "math.h"

#include "pal_math.def"

#undef pal_ceil
#define pal_ceil ceil

#undef pal_logarithm
#define pal_logarithm log

#undef pal_log10
#define pal_log10 log10

#undef pal_exponential
#define pal_exponential exp

#undef pal_power
#define pal_power pow

#undef pal_modf
#define pal_modf modf

#undef pal_isnan
#define pal_isnan isnan

#endif /* PAL_MATH_H */
