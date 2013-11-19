/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */

#include "pal.h"

/* Signale wrapper. */
RETSIGTYPE *
pal_signal_set (int signo, void (*func) (int))
{
  int ret;
  struct sigaction sig;
  struct sigaction osig;

  sig.sa_handler = func;
  sigemptyset (&sig.sa_mask);
  sig.sa_flags = 0;
#ifdef SA_RESTART
  sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */

  ret = sigaction (signo, &sig, &osig);

  if (ret < 0)
    return (SIG_ERR);
  else
    return (osig.sa_handler);
}

/* SIGXCPU handler.  */
void
pal_sigxcpu (int sig)
{
  pal_console_err ("CPU limit exceeded");

  /* Ignore subsequent error message generation.  */
  pal_signal_set (sig, SIG_IGN);
}

/* SIGXFSZ handler.  */
void
pal_sigxfsz (int sig)
{
  pal_console_err ("File size limit exceeded");

  /* Ignore subsequent error message generation.  */
  pal_signal_set (sig, SIG_IGN);
}

/* Initialization of the default signal handles.  */
void
pal_signal_init (void)
{
  pal_signal_set (SIGHUP, SIG_IGN);
  pal_signal_set (SIGUSR1, SIG_IGN);
  pal_signal_set (SIGUSR2, SIG_IGN);
  pal_signal_set (SIGPIPE, SIG_IGN);
#ifdef SIGTSTP
  pal_signal_set (SIGTSTP, SIG_IGN);
#endif /* SIGTSTP */
#ifdef SIGTTIN
  pal_signal_set (SIGTTIN, SIG_IGN);
#endif /* SIGTTIN */
#ifdef SIGTTOU
  pal_signal_set (SIGTTOU, SIG_IGN);
#endif /* SIGTTOU */
  pal_signal_set (SIGXCPU, pal_sigxcpu);
  pal_signal_set (SIGXFSZ, pal_sigxfsz);
}
