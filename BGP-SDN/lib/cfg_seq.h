/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved.  */

#ifndef _CFG_SEQ_H
#define _CFG_SEQ_H

#include "cfg_data_types.h"


#define CFG_STORE_IMI 1
#define CFG_STORE_PM  2

typedef struct cfgDataSeq
{
  cfgDataType_e cfgDataType;      /* Conifguration data type */
  int           cfgStoreType;     /* Conifg data storage type: IMI, PM or both */
  int           cfgConfigMode;
} cfgDataSeq_t;


typedef void (* cfgSeqWalkCb_t)(intptr_t, intptr_t,
                                int, cfgDataType_e, int);

void cfg_seq_walk(intptr_t ref1, intptr_t ref2, cfgSeqWalkCb_t walk_cb);

bool_t        cfg_seq_is_imi_dtype (int seq_ix);
cfgDataType_e cfg_seq_get_dtype (int seq_ix);
int           cfg_seq_get_index (cfgDataType_e dtype);

#endif

