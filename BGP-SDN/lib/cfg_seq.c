/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved.  */

/*-------------------------------------------------------------
 * cfgDataSeq - Defines sequence of configuration data in the
 *              BGP-SDN config file.
 *--------------------------------------------------------------
 */
#include "pal.h"
#include "lib.h"
#include "cfg_data_types.h"
#include "cfg_seq.h"

#define __IMI_LOCAL (-1)


cfgDataSeq_t cfgDataSeq[] =
{
  { CFG_DTYP_DEBUG,               CFG_STORE_PM , DEBUG_MODE },
  { CFG_DTYP_IMI_VR,              CFG_STORE_IMI, __IMI_LOCAL }, /* imi_vr_config_write */
  { CFG_DTYP_KEYCHAIN,            CFG_STORE_IMI, __IMI_LOCAL }, /* keychain_config_write */
  { CFG_DTYP_EXEC,                CFG_STORE_PM , EXEC_MODE },
  { CFG_DTYP_CONFIG,              CFG_STORE_PM , CONFIG_MODE },
  { CFG_DTYP_ACCESS_IPV4,         CFG_STORE_IMI, __IMI_LOCAL }, /* config_write_access_ipv4 */
#ifdef HAVE_IPV6
  { CFG_DTYP_ACCESS_IPV6,         CFG_STORE_IMI, __IMI_LOCAL }, /* config_write_access_ipv6 */
#endif /*HAVE_IPV6*/
  { CFG_DTYP_VR,                  CFG_STORE_PM , VR_MODE },
  { CFG_DTYP_BGP,                 CFG_STORE_PM , BGP_MODE },
  { CFG_DTYP_COMMUNITY_LIST,      CFG_STORE_PM , COMMUNITY_LIST_MODE },
  { CFG_DTYP_AS_LIST,             CFG_STORE_PM , AS_LIST_MODE },
  { CFG_DTYP_PREFIX_IPV4,         CFG_STORE_IMI, __IMI_LOCAL }, /* config_write_prefix_ipv4 */
#ifdef HAVE_IPV6
  { CFG_DTYP_PREFIX_IPV6,         CFG_STORE_IMI, __IMI_LOCAL }, /* config_write_prefix_ipv6 */
#endif
  { CFG_DTYP_RMAP,                CFG_STORE_IMI, __IMI_LOCAL }, /* route_map_config_write */
};

void
cfg_seq_walk(intptr_t ref1, intptr_t ref2, cfgSeqWalkCb_t walk_cb)
{
  int seq_ix;
  cfgDataSeq_t *seq_entry;

  if (walk_cb == NULL)
    return;

  for (seq_ix=0; seq_ix<sizeof(cfgDataSeq)/sizeof(cfgDataSeq_t); seq_ix++)
    {
      seq_entry = &cfgDataSeq[seq_ix];
      walk_cb(ref1, ref2,
              seq_entry->cfgStoreType,
              seq_entry->cfgDataType,
              seq_entry->cfgConfigMode);
    }
}

bool_t
cfg_seq_is_imi_dtype (int seq_ix)
{
  if (seq_ix >= sizeof(cfgDataSeq)/sizeof(cfgDataSeq_t)) {
    return PAL_FALSE;
  }
  return (cfgDataSeq[seq_ix].cfgStoreType == CFG_STORE_IMI);
}

cfgDataType_e
cfg_seq_get_dtype (int seq_ix)
{
  if (seq_ix >= sizeof(cfgDataSeq)/sizeof(cfgDataSeq_t)) {
    return CFG_DTYP_MAX;
  }
  return (cfgDataSeq[seq_ix].cfgDataType);
}

int
cfg_seq_get_index (cfgDataType_e dtype)
{
  int seq_ix;

  for (seq_ix=0; seq_ix<sizeof(cfgDataSeq)/sizeof(cfgDataSeq_t); seq_ix++) {
    if (cfgDataSeq[seq_ix].cfgDataType == dtype) {
      return seq_ix;
    }
  }
  return (-1);
}

