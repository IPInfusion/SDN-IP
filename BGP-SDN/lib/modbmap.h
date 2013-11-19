/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved. */

#ifndef _MODBMAP_H_
#define _MODBMAP_H_

#include "pal.h"

/* Module bitmap Word Size. */
/* MODBMAP_WORD_BITS  should be derived from __WORDSIZE */
#define MODBMAP_WORD_BITS (32)

/* Module bitmap Size in bytes. */
#define MODBMAP_MAX_WORDS (2)

/* Module bitmap Size in bits. */
#define MODBMAP_MAX_BITS  ((MODBMAP_WORD_BITS) * (MODBMAP_MAX_WORDS))

/* Make sure the size of bit map is big enough to hold all modules. */
#if ((MODBMAP_MAX_BITS) < (IPI_PROTO_MAX))
#error **** lib/modbmap.h: Increase MODBMAP_MAX_WORDS ****
#endif

/* Module bitmap structure */
typedef struct modbmap
{
  u_int32_t mbm_arr[MODBMAP_MAX_WORDS];
} modbmap_t;

/* Macro to set Module bitmap. */
#define MODBMAP_SET(mbm, bit) \
  (mbm).mbm_arr[(bit) / MODBMAP_WORD_BITS] |= (1<< ((bit) % MODBMAP_WORD_BITS))

/* Macro to unset Module bitmap. */
#define MODBMAP_UNSET(mbm, bit) \
  (mbm).mbm_arr[(bit) / MODBMAP_WORD_BITS] &= ~(1<< ((bit) % MODBMAP_WORD_BITS))

/* Macro to check whether the Module bitmap is set or not for a given bit. */
#define MODBMAP_ISSET(mbm, bit)                             \
  ((((mbm).mbm_arr[(bit) / MODBMAP_WORD_BITS] &             \
   (1<< ((bit) % MODBMAP_WORD_BITS))) != 0)? PAL_TRUE: PAL_FALSE)

modbmap_t modbmap_or (modbmap_t mbm1, modbmap_t mbm2);
modbmap_t modbmap_and (modbmap_t mbm1, modbmap_t mbm2);
modbmap_t modbmap_sub (modbmap_t mbm1, modbmap_t mbm2);
modbmap_t modbmap_vor (u_int8_t cnt, modbmap_t *mbm, ...);
modbmap_t modbmap_id2bit (u_int8_t bit_num);
bool_t modbmap_isempty (modbmap_t mbm);
bool_t modbmap_check (modbmap_t mbm1, modbmap_t mbm2);
void modbmap_printvalue (modbmap_t mbm);
void modbmap_init_all ();
u_int8_t modbmap_bit2id (modbmap_t mbm);

extern modbmap_t PM_EMPTY;
extern modbmap_t PM_BGP;
extern modbmap_t PM_IMI;

extern modbmap_t PM_UCAST;
extern modbmap_t PM_ALL;
extern modbmap_t PM_VR;
extern modbmap_t PM_VRF;
extern modbmap_t PM_ACCESS;
extern modbmap_t PM_PREFIX;
extern modbmap_t PM_RMAP;
extern modbmap_t PM_LOG;
extern modbmap_t PM_SNMP_DBG;
#endif

