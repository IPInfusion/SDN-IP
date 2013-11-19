/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved.  */

#ifndef _CFG_DATA_TYPES_H
#define _CFG_DATA_TYPES_H

/*-------------------------------------------------------------
 * cfgDataTypes_e - enumeration type consists identifiers for
 *                  all aggregate data types.
 * The list consists of two parts:
 * 1. Contains data types as the result of direct
 *    mapping to CLI modes.
 * 2. Contains data types that are configured
 *    in the CONFIG_MODE and/or are local to IMI.
 *    These are not mapped to CLI modes.
 * The data types are used to identify configuration data coming
 * to the IMI at the time of parsing the CLI command before it is
 * executed by the CLI command handler.
 *--------------------------------------------------------------
 */
typedef enum cfgDataType
{
  /* Data types mapping directly into cli_mode_types.h. */
  CFG_DTYP_LOGIN              = 0,
  CFG_DTYP_AUTH               = 1,
  CFG_DTYP_AUTH_ENABLE        = 2,
  CFG_DTYP_EXEC               = 4,
  CFG_DTYP_CONFIG             = 5,
  CFG_DTYP_LINE               = 6,
  CFG_DTYP_DEBUG              = 11,
  CFG_DTYP_KEYCHAIN           = 12,
  CFG_DTYP_KEYCHAIN_KEY       = 13,
  CFG_DTYP_VR                 = 14,
  CFG_DTYP_INTERFACE          = 16,
  CFG_DTYP_INTERFACE_MANAGE   = 21,
  CFG_DTYP_ROUTER             = 25,
  CFG_DTYP_BGP                = 26,
  CFG_DTYP_BGP_IPV4           = 27,
  CFG_DTYP_BGP_IPV4M          = 28,
  CFG_DTYP_BGP_IPV6           = 30,
  CFG_DTYP_IP                 = 54,
  CFG_DTYP_COMMUNITY_LIST     = 55,
  CFG_DTYP_PREFIX_IPV4        = 56,
  CFG_DTYP_ACCESS_IPV4        = 57,
  CFG_DTYP_IPV6               = 59,
  CFG_DTYP_ACCESS_IPV6        = 60,
  CFG_DTYP_PREFIX_IPV6        = 61,
  CFG_DTYP_AS_LIST            = 62,
  CFG_DTYP_RMAP               = 63,
  CFG_DTYP_USER               = 64,
  CFG_DTYP_DUMP               = 65,
  CFG_DTYP_SMUX               = 77,
  CFG_DTYP_EXEC_PRIV          = 78,   /* Fake mode.  Same as EXEC.   */
  CFG_DTYP_MODIFIER           = 80,   /* Output modifier node.  */

  /* Local IMI defined data types. */
  CFG_DTYP_IMI_HOST_SERVICE         = 201,
  CFG_DTYP_IMI_HOST                 = 203,
  CFG_DTYP_IMI_VR                   = 209,
  CFG_DTYP_MAX                      = 249
} cfgDataType_e;

#endif /* _CFG_DATA_TYPES_H */
