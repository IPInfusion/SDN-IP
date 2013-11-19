/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "lib.h"

#define SNMP_STRING "Snmp information"

void
snmp_community_event_hook (struct ipi_vr *vr, void (*func) (struct ipi_vr *, 
                                                            char *))
{
  vr->snmp_community.event_hook = func;
}

/* CLIs. */
CLI (snmp_community,
     snmp_communitiy_cmd,
     "snmp community WORD",
     SNMP_STRING,
     "SNMP Community",
     "Community Name")
{
  struct ipi_vr *vr = ipi_vr_get_privileged (cli->zg);

  if (vr == NULL)
    return CLI_ERROR;

  if (vr)
    vr->snmp_community.current_community = argv[0];

  if (vr->snmp_community.event_hook)
    (*vr->snmp_community.event_hook) (vr, vr->snmp_community.current_community);

  return CLI_SUCCESS; 
}

/* Configuration write function. */
int
snmp_community_config_write (struct cli *cli)
{
  return 0;
}

void
snmp_community_init (struct ipi_vr *vr)
{
  return; 
}

void
snmp_community_cli_init (struct lib_globals *zg)
{
  struct cli_tree *ctree = zg->ctree;
  /* Install CLIs. */
  cli_install (ctree, CONFIG_MODE, 
                   &snmp_communitiy_cmd);
}
