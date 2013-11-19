/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved.  */

/* Common mode functions.  This library is only for IMI and IMI shell
   not needed in protocol module.  */

#include <pal.h>

#include "cli.h"
#include "modbmap.h"

/* Static utility function to change mode.  */
static void
cli_mode_change (struct cli *cli, int mode)
{
  cli->mode = mode;
}

#ifdef HAVE_VR
CLI (mode_virtual_router,
     mode_virtual_router_cli,
     "virtual-router WORD",
     CLI_VR_STR,
     CLI_VR_NAME_STR)
{
  cli_mode_change (cli, VR_MODE);
  return CLI_SUCCESS;
}
#endif /* HAVE_VR */

#ifdef HAVE_BGPD
#ifndef HAVE_EXT_CAP_ASN
CLI (mode_router_bgp,
     mode_router_bgp_cli,
     "router bgp <1-65535>",
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR)
#else
CLI (mode_router_bgp,
     mode_router_bgp_cli,
     "router bgp <1-4294967295>",
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR)
#endif
{
  cli_mode_change (cli, BGP_MODE);
  return CLI_SUCCESS;
}
#ifndef HAVE_EXT_CAP_ASN
ALI (mode_router_bgp,
     mode_router_bgp_view_cli,
     "router bgp <1-65535> view WORD",
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR,
     "BGP view",
     "view name");
#else
ALI (mode_router_bgp,
     mode_router_bgp_view_cli,
     "router bgp <1-4294967295> view WORD",
     CLI_ROUTER_STR,
     "Border Gateway Protocol (BGP)",
     CLI_AS_STR,
     "BGP view",
     "view name");
#endif /* HAVE_EXT_CAP_ASN */
CLI (mode_bgp_af_ipv4,
     mode_bgp_af_ipv4_cli,
     "address-family ipv4",
     "Enter Address Family command mode",
     "Address family")
{
  cli_mode_change (cli, BGP_IPV4_MODE);
  return CLI_SUCCESS;
}

CLI (mode_bgp_af_ipv4_unicast,
     mode_bgp_af_ipv4_unicast_cli,
     "address-family ipv4 unicast",
     "Enter Address Family command mode",
     "Address family",
     "Address Family modifier")
{
  cli_mode_change (cli, BGP_IPV4_MODE);
  return CLI_SUCCESS;
}

CLI (mode_bgp_af_ipv4_multicast,
     mode_bgp_af_ipv4_multicast_cli,
     "address-family ipv4 multicast",
     "Enter Address Family command mode",
     "Address family",
     "Address Family modifier")
{
  cli_mode_change (cli, BGP_IPV4M_MODE);
  return CLI_SUCCESS;
}

#ifdef HAVE_IPV6
CLI (mode_bgp_af_ipv6,
     mode_bgp_af_ipv6_cli,
     "address-family ipv6 (unicast|)",
     "Enter Address Family command mode",
     "Address family",
     "Address Family modifier")
{
  cli_mode_change (cli, BGP_IPV6_MODE);
  return CLI_SUCCESS;
}
#endif /* HAVE_IPV6 */

CLI (mode_bgp_exit_af,
     mode_bgp_exit_af_cli,
     "exit-address-family",
     "Exit from Address Family configuration mode")
{
  cli_mode_change (cli, BGP_MODE);
  return CLI_SUCCESS;
}
#endif /* HAVE_BGPD */

void
cli_mode_init (struct cli_tree *ctree)
{
  /* EXEC mode.  */
  cli_install_default (ctree, EXEC_MODE);

  /* CONFIGURE mode.  */
  cli_install_default (ctree, CONFIG_MODE);

#ifdef HAVE_VR
  /* VR. */
  cli_install_default (ctree, VR_MODE);
  cli_install_imi (ctree, CONFIG_MODE, PM_NSM, PRIVILEGE_PVR_MAX, 0,
                   &mode_virtual_router_cli);
  cli_set_imi_cmd (&mode_virtual_router_cli, VR_MODE, CFG_DTYP_VR);
#endif /* HAVE_VR */

  /* BGP.  */
#ifdef HAVE_BGPD
  cli_install_default (ctree, BGP_MODE);
  cli_install_default_family (ctree, BGP_IPV4_MODE);
  cli_install_default_family (ctree, BGP_IPV4M_MODE);

  cli_install_imi (ctree, CONFIG_MODE, PM_BGP, PRIVILEGE_VR_MAX, 0,
                   &mode_router_bgp_cli);
  cli_set_imi_cmd (&mode_router_bgp_cli, BGP_MODE, CFG_DTYP_BGP);
  cli_install_imi (ctree, CONFIG_MODE, PM_BGP, PRIVILEGE_VR_MAX, 0,
                   &mode_router_bgp_view_cli);
  cli_set_imi_cmd (&mode_router_bgp_view_cli, BGP_MODE, CFG_DTYP_BGP);
  cli_install_imi (ctree, BGP_MODE, PM_BGP, PRIVILEGE_VR_MAX, 0,
                   &mode_bgp_af_ipv4_cli);
  cli_set_imi_cmd (&mode_bgp_af_ipv4_cli, BGP_IPV4_MODE, CFG_DTYP_BGP);
  cli_install_imi (ctree, BGP_MODE, PM_BGP, PRIVILEGE_VR_MAX, 0,
                   &mode_bgp_af_ipv4_unicast_cli);
  cli_set_imi_cmd (&mode_bgp_af_ipv4_unicast_cli, BGP_IPV4_MODE, CFG_DTYP_BGP);
  cli_install_imi (ctree, BGP_MODE, PM_BGP, PRIVILEGE_VR_MAX, 0,
                   &mode_bgp_af_ipv4_multicast_cli);
  cli_set_imi_cmd (&mode_bgp_af_ipv4_multicast_cli, BGP_IPV4M_MODE, CFG_DTYP_BGP);

  cli_install_imi (ctree, BGP_IPV4_MODE, PM_BGP, PRIVILEGE_VR_MAX, 0,
                   &mode_bgp_exit_af_cli);
  cli_set_imi_cmd (&mode_bgp_exit_af_cli, BGP_MODE, CFG_DTYP_BGP);
  cli_install_imi (ctree, BGP_IPV4M_MODE, PM_BGP, PRIVILEGE_VR_MAX, 0,
                   &mode_bgp_exit_af_cli);
  cli_set_imi_cmd (&mode_bgp_exit_af_cli, BGP_MODE, CFG_DTYP_BGP);

#ifdef HAVE_IPV6
  cli_install_default_family (ctree, BGP_IPV6_MODE);
  cli_install_imi (ctree, BGP_MODE, PM_BGP, PRIVILEGE_VR_MAX, 0,
                   &mode_bgp_af_ipv6_cli);
  cli_set_imi_cmd (&mode_bgp_af_ipv6_cli, BGP_IPV6_MODE, CFG_DTYP_BGP);

  cli_install_imi (ctree, BGP_IPV6_MODE, PM_BGP, PRIVILEGE_VR_MAX, 0,
                   &mode_bgp_exit_af_cli);
  cli_set_imi_cmd (&mode_bgp_exit_af_cli, BGP_MODE, CFG_DTYP_BGP);

#endif /* HAVE_IPV6 */
#endif /* HAVE_BGPD */
}

