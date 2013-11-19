/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */
#include "pal.h"

/* Physical Class */
#define CLASS_OTHER                 1
#define CLASS_NOT_KNOWN             2
#define CLASS_CHASSIS               3
#define CLASS_BACKPLANE             4
#define CLASS_CONTAINER             5
#define CLASS_POWERSUPPLY           6
#define CLASS_FAN                   7
#define CLASS_SENSOR                8
#define CLASS_MODULE                9
#define CLASS_PORT                  10
#define CLASS_STACK                 11

#define ADMIN_STRING_MAX_LENGTH     255

struct entPhysicalEntry 
{
  u_int32_t entPhysicalIndex;
  char *entPhysicalDescr;
  u_int32_t entPhysicalContainedIn;
  u_int32_t entPhysicalClass;
  u_int32_t entPhysicalParentRelPos;
  char *entPhysicalName;
  char entPhysicalSoftwareRev [ADMIN_STRING_MAX_LENGTH];
  char entPhysicalVendorType [ADMIN_STRING_MAX_LENGTH];
  char entPhysicalHardwareRev [ADMIN_STRING_MAX_LENGTH];
  char entPhysicalFirmwareRev [ADMIN_STRING_MAX_LENGTH];
  char entPhysicalSerialNum [ADMIN_STRING_MAX_LENGTH];
  char entPhysicalMfgName [ADMIN_STRING_MAX_LENGTH];
  char entPhysicalModelName [ADMIN_STRING_MAX_LENGTH];
  char entPhysicalAlias [ADMIN_STRING_MAX_LENGTH];
  char entPhysicalAssetID [ADMIN_STRING_MAX_LENGTH];
  u_int32_t entPhysicalIsFRU;
};

void snmp_community_event_hook (struct ipi_vr *,
                                void (*func) (struct ipi_vr *, char *));

void snmp_community_init (struct ipi_vr *);

void snmp_community_cli_init (struct lib_globals *);

