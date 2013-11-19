/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/stat.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif /* HAVE_GETOPT_H */

#include "lib.h"
#include "thread.h"
#include "bgpsdn_version.h"
#include "prefix.h"
#include "log.h"
#include "sockunion.h"
#include "cqueue.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_attr.h"

#ifdef HAVE_GETOPT_H
/* bgpd options, we use GNU getopt library. */
struct option longopts[] =
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "bgp_port",    required_argument, NULL, 'p'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "no_kernel",   no_argument,       NULL, 'n'},
  { "version",     no_argument,       NULL, 'v'},
  { "help",        no_argument,       NULL, 'h'},
  { 0 }
};
#endif /* HAVE_GETOPT_H */

/* Manually specified configuration file name.  */
char *config_file_l = NULL;

/* VTY port number.  */
int vty_port_l = BGP_VTY_PORT;

int bgp_start (u_int16_t, char *, u_int16_t, int, int, char *);
void bgp_stop (mod_stop_cause_t);

/* Help information display. */
static void
usage (int status, char *progname)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {
      printf ("Usage : %s [OPTION...]\n\n\
Daemon which manages kernel routing table management and \
redistribution between different routing protocols.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-p, --bgp_port     Set bgp protocol's port number\n\
-P, --vty_port     Set vty's port number\n\
-n, --no_kernel    Do not install route to kernel.\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, BGPSDN_BUG_ADDRESS);
    }

  exit (status);
}

/* SIGHUP handler. */
void
sighup (int sig)
{
  zlog (&BLG, NULL, ZLOG_INFO, "SIGHUP received");
}

/* SIGINT handler. */
void
sigint (int sig)
{
  zlog (&BLG, NULL, ZLOG_INFO, "Terminating on signal");

  /* Stop BGP module.  */
  bgp_stop (MOD_STOP_CAUSE_USER_KILL);

  exit (0);
}

/* SIGUSR1 handler. */
void
sigusr1 (int sig)
{
  zlog_rotate (&BLG, BLG.log);
}

/* Initialization of signal handles.  */
void
signal_init ()
{
  pal_signal_init ();
  pal_signal_set (SIGHUP, sighup);
  pal_signal_set (SIGINT, sigint);
  pal_signal_set (SIGTERM, sigint);
  pal_signal_set (SIGUSR1, sigusr1);
}

/* Main routine of bgpd. Treatment of argument and start bgp finite
   state machine is handled at here. */
int
main (int argc, char **argv)
{
  result_t ret;
  char *p;
  int daemon_mode_l = 0;
  int bgp_port_l = BGP_PORT_DEFAULT;
  int no_fib_l = 0;
  char *progname_l;

  /* Set umask before anything for security */
  umask (0027);

#ifdef VTYSH
  /* Unlink vtysh domain socket. */
  unlink (BGP_VTYSH_PATH);
#endif /* VTYSH */

  /* Preserve name of myself. */
  progname_l = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* Command line argument treatment. */
  while (1)
    {
      int opt;

#ifdef HAVE_GETOPT_H
      opt = getopt_long (argc, argv, "df:hp:P:rnv", longopts, 0);
#else
      opt = getopt (argc, argv, "df:hp:P:rnv");
#endif /* HAVE_GETOPT_H */

      if (opt == EOF)
        break;

      switch (opt)
        {
        case 0:
          break;
        case 'd':
          daemon_mode_l = 1;
          break;
        case 'f':
          config_file_l = optarg;
          break;
        case 'p':
          bgp_port_l = atoi (optarg);
          break;
        case 'P':
          vty_port_l = atoi (optarg);
          break;
        case 'n':
          no_fib_l = 1;
          break;
        case 'v':
          print_version (progname_l);
          exit (0);
        case 'h':
          usage (0, progname_l);
          break;
        default:
          usage (1, progname_l);
          break;
        }
    }

  /* Initializations. */
  srand (time (NULL));

  /* Initialize signal.  */
  signal_init ();

  mod_stop_reg_cb(IPI_PROTO_BGP, bgp_stop);

  /* Start BGP module.  */
  ret = bgp_start (daemon_mode_l, config_file_l, vty_port_l,
                   bgp_port_l, no_fib_l, progname_l);
  if (ret != 0)
    fprintf (stderr, "Error loading BGP-SDN... Aborting...\n");

  /* Not reached... */
  exit (0);
}


