/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_VTY_H
#define _BGPSDN_VTY_H

#include <pal.h>

#include "vector.h"
#include "cli.h"

/* Forward declaration. */
struct vty;

/* VTY server structure. */
struct vty_server
{
  /* Vector of vty's */
  vector vtyvec;

  /* Server thread vector. */
  vector Vvty_serv_thread;

  /* Current working directory. */
  char *vty_cwd;

  /* Command tree. */
  struct cli_tree *ctree;
};

/* VTY struct. */
struct vty
{
  /* CLI parameters.  */
  struct cli cli;

  /* VTY master pointer.  */
  struct vty_server *server;

  /* file descriptor of this vty */
  int fd;

  /* lib_globals. */
  struct lib_globals *zg;

  /* output handle for this vty */
  pal_sock_handle_t sock;

  /* Is this vty connect to file or not */
  enum
    {
      VTY_TERM,
      VTY_SHELL,
      VTY_SHELL_SERV
    } type;

  /* Mode status of this vty */
  int mode;

  /* Local and remote IPv4/v6 address for the VTY connection.  */
  struct prefix *local;
  struct prefix *remote;

  /* Failure count */
  int fail;
  int login_fail;

  /* Output buffer. */
  struct buffer *obuf;

  /* Command input buffer */
  char *buf;

  /* Command cursor point */
  int cp;

  /* Command length */
  int length;

  /* Command max length. */
  int max;

  /* Histry of command */
#define VTY_MAXHIST 20
  char *hist[VTY_MAXHIST];

  /* History lookup current point */
  int hp;

  /* History insert end point */
  int hindex;

  /* For current referencing point of interface, route-map,
     access-list etc... */
  void *index;

  /* For multiple level index treatment such as key chain and key. */
  void *index_sub;

  /* For escape character. */
  char escape;

  /* IAC handling */
  char iac;

  /* IAC SB handling */
  char iac_sb_in_progress;
  struct buffer *sb_buffer;

  /* Window width/height. */
  int width;
  int height;

  /* Configure lines. */
  int lines;

  /* Current executing function pointer. */
  int (*func) (struct vty *, void *arg);

  /* Terminal monitor. */
  int monitor;
#define VTY_MONITOR_CONFIG      (1 << 0)
#define VTY_MONITOR_OUTPUT      (1 << 1)

  /* In configure mode. */
  int config;

  /* Read and write thread. */
  struct thread *t_read;
  struct thread *t_write;

  /* Timeout seconds and thread. */
  u_int32_t v_timeout;
  struct thread *t_timeout;

  /* Thread output function. */
  struct thread *t_output;

  /* Should the command be added to history. */
  char history;

  /* For vty buffer.  */
  int lp;
  int lineno;
};

/* VTY default buffer size.  */
#define VTY_BUFSIZ         8192

/* Default time out value.  */
#define VTY_TIMEOUT_DEFAULT 600

/* Directory separator. */
#ifndef DIRECTORY_SEP
#define DIRECTORY_SEP '/'
#endif /* DIRECTORY_SEP */

#ifndef IS_DIRECTORY_SEP
#define IS_DIRECTORY_SEP(c) ((c) == DIRECTORY_SEP)
#endif

/* VTY port number.  */
#define BGP_VTY_PORT                    2605

#define IPI_VTY_PORT(Z, P)                                                    \
    ((P) ? (P) :                                                              \
     (Z)->protocol == IPI_PROTO_BGP       ? BGP_VTY_PORT :                    \
     -1)

/* VTY shell path.  */
#define BGP_VTYSH_PATH                  "/tmp/.bgpd"

/* Prototypes. */
int vty_serv_sock (struct lib_globals *, u_int16_t);
int vty_out (struct vty *, const char *, ...);
struct vty *vty_new (struct lib_globals *);
void vty_time_print (struct vty *, int);
void vty_close (struct vty *);
int vty_config_write (struct cli *);
char *vty_get_cwd (struct lib_globals *);
void vty_log (struct lib_globals *, const char *, const char *, const char *);
int vty_config_lock (struct vty *);
int vty_config_unlock (struct vty *);
int vty_shell (struct vty *);
int vty_shell_serv (struct vty *);
int vty_monitor_output (struct vty *);
void vty_prompt (struct vty*);
void vty_auth (struct vty *, char *);
int vty_execute (struct vty *);

struct vty_server *vty_server_new ();
void vty_master_free (struct vty_server **vty_master);
void vty_register_ctree (struct vty_server *, struct cli_tree *);
struct vty_server *vty_get_master (struct vty *vty);
void vty_cmd_init (struct cli_tree *ctree);
void vty_hist_add (struct vty *vty);
void vty_clear_buf (struct vty *vty);

#endif /* _BGPSDN_VTY_H */
