/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */
#include "pal.h"

void ntohf(float* val)
{
  union {
    u_int32_t val_32;
    float     val_f;
  } conv;

  conv.val_f = *val;
  conv.val_32 = pal_ntoh32 (conv.val_32);
  pal_mem_cpy(val, &conv.val_32, 4);
}

void htonf(float* val)
{
  union {
    u_int32_t val_32;
    float     val_f;
  } conv;

  conv.val_f = *val;
  conv.val_32 = pal_hton32 (conv.val_32);
  pal_mem_cpy(val, &conv.val_32, 4);
}

