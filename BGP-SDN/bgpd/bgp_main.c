/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/* Library Global Variables Container */
struct lib_globals *BGP_LIB_GLOBAL_VAR;

/* BGP Capability check. */
void
bgp_feature_capability_check (void)
{
#ifdef HAVE_IPV6
  bgp_cap_have_ipv6 = 1;
#endif /* HAVE_IPV6 */

  return;
}

/* BGP Libraries CLI Initialization */
void
bgp_lib_cli_init (void)
{
  /* BGP CLI Initialization */
  host_vty_init (&BLG);

  /* BGP Access Lists Library CLI Initialization */
  access_list_init (&BLG);

#ifdef MEMMGR
  /* Memory-Manager Library CLI Initialization */
  memmgr_cli_init (&BLG);
#endif /* MEMMGR */

  /* BGP Route-map Library CLI Initialization */
  route_map_cli_init (&BLG);

  /* BGP Prefix List Library CLI Initialization */
  prefix_list_init (&BLG);

  /* BGP Filter List Library CLI Initialization */
  bgp_filter_cli_init ();

  return;
}

/* Main routine of BGP process ('bgpd') */
int
bgp_start (u_int16_t daemon_mode, u_int8_t *config_file, u_int16_t vty_port,
           u_int16_t bgp_port, u_int32_t no_fib, u_int8_t *progname)
{
  struct thread thread;
  u_int8_t buf [50];
  s_int32_t ret;

  ret = 0;

  /* BGP Process Random Seed Initilization */
  pal_srand (pal_time_current (NULL));

  /* BGP Memory Initialization */
  memory_init (IPI_PROTO_BGP);

  /* Allocate Library Global variable container */
  BGP_LIB_GLOBAL = lib_create (progname);
  if (! BGP_LIB_GLOBAL)
    {
      ret = -1;
      goto EXIT;
    }


  ret = lib_start (BGP_LIB_GLOBAL);
  if (ret < 0)
    {
      ret = -1;
      goto EXIT;
    }

  /* Initialize Logging functionality */
  BLG.protocol = IPI_PROTO_BGP;
  BLG.log = openzlog (&BLG, BLG.vr_instance,
                      IPI_PROTO_BGP, LOGDEST_MAIN);

  /* CQueue Buffer Free List Initialization */
  cqueue_buf_free_list_alloc (&BLG);

  /* Stream Socket-CB Zombie List Initialization */
  stream_sock_cb_zombie_list_alloc (&BLG);

  /* BGP Global Variables Container Initialization */
  ret = bgp_global_init ();
  if (ret < 0)
    {
      ret = -1;
      goto EXIT;
    }

  /* BGP Feature Capability check */
  bgp_feature_capability_check ();

  /* BGP Privileged-VR initialization */
  bgp_vr_create (ipi_vr_get_privileged (&BLG));

  /* BGP CLI Library Initialization */
  bgp_lib_cli_init ();

  /* BGP CLI Config Commands Initialization  */
  bgp_cli_init ();

  /* BGP CLI Show Commands Initialization */
  bgp_show_init ();

  /* BGP SNMP Interface Initialization */
#ifdef HAVE_SNMP
  bgp_snmp_init ();
#endif /* HAVE_SNMP */

  /* No FIB option.  */
  if (no_fib)
    bgp_option_set (BGP_OPT_NO_FIB);

  /* Turn into daemon if daemon_mode is set. */
  if (daemon_mode)
    pal_daemonize (0, 0);

#ifdef HAVE_PID
  PID_REGISTER (PATH_BGPD_PID);
#endif /* HAVE_PID */

  /* Start the configuration management.  */
  host_config_start (&BLG, config_file, vty_port);

  /* Print banner. */
  zlog_info (&BLG, "BGPd %s starting: vty@%d, bgp@%d",
             bgpsdn_version (buf, 50), vty_port, BGP_PORT_DEFAULT);

  /* Start processing pseudo-threads */
  while (thread_fetch (&BLG, &thread))
    thread_call (&thread);

EXIT:

  return ret;
}

void
bgp_stop (mod_stop_cause_t cause)
{
  /* Mark lib in shutdown for HA */
  SET_LIB_IN_SHUTDOWN (&BLG);
  SET_LIB_STOP_CAUSE(&BLG, cause);

  /* Terminate BGP.  */
//  bgp_terminate ();
  bgp_global_delete ();

#ifdef HAVE_PID
  PID_REMOVE (PATH_BGPD_PID);
#endif /* HAVE_PID */

  /* Stop the system. */
  lib_stop (&BLG);
}
