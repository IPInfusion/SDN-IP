/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_SHOW_H
#define _BGPSDN_SHOW_H

#include "cli.h"

/* This is a buffer between producer and consumer.  Producer store
   information into the output buffer.  The buffer is built by page.
   Each page can have SHOW_PAGE_SIZE information.  */

#define SHOW_PAGE_SIZE                          4096
#define SHOW_LINE_SIZE                          256

/* Page for output information.  */
struct show_page
{
  /* Simple single linked list.  */
  struct show_page *next;

  /* Data.  Last 1 character is for '\0' termination when it is
     there.  */
  char buf[SHOW_PAGE_SIZE];

  /* First position of the data.  */
  int sp;

  /* Last position of the data.  */
  int cp;
};

/* This is a connection manager for "show" command.  */
struct show
{
  /* Read thread for commands.  */
  struct thread *t_read;

  /* Write thread for output.  */
  struct thread *t_write;

  /* First page.  */
  struct show_page *first_page;

  /* Last page.  */
  struct show_page *last_page;

  /* Storage.  */
  struct show_server *server;

  /* Socket for the connection.  */
  pal_sock_handle_t sock;

  /* Input line buffer.  */
  char buf[SHOW_LINE_SIZE];

  /* Struct CLI. */
  struct cli cli;
};

/* Storage for unused page.  */
struct show_server
{
  /* Globals pointer for thread.  */
  struct lib_globals *zg;

  /* Accept sock.  */
  pal_sock_handle_t sock;

  /* Threads for read, write and accept.  */
  struct thread *t_accept;

  /* Unused page handling.  */
  struct show_page *page_unuse;
  u_int32_t page_unuse_count;
  u_int32_t page_unuse_max;
#define SHOW_PAGE_UNUSE_MAX                     100

  /* CLI tree.  */
  struct cli_tree *ctree;

  /* Protocol running configuration function. */
  s_int32_t (*show_func) (struct cli *);

  /* Host information. */
  struct host *host;
};

#ifdef HAVE_TCP_MESSAGE
/* Each protocol module's show port. */
#define SHOW_PORT_BASE            4000
#define SHOW_PORT_BASE_N(n)       (SHOW_PORT_BASE + (n))
#define BGP_SHOW_PORT             SHOW_PORT_BASE_N(3)

#define SHOW_PORT_GET(P)                                                      \
    ((P) == IPI_PROTO_BGP       ? BGP_SHOW_PORT :                             \
     (P) == IPI_PROTO_UNSPEC    ? -1 : -1)

#else /* HAVE_TCP_MESSAGE */
/* Each protocol module's "show" path.  */
#ifdef HAVE_SPLAT
#define SHOW_PATH_PREFIX          "/var/opt/OPSEC/ipinfusion"
#else /* HAVE_SPLAT */
#define SHOW_PATH_PREFIX
#endif /* HAVE_SPLAT */
#define BGP_SHOW_PATH             SHOW_PATH_PREFIX "/tmp/.bgp_show"

#define SHOW_PATH_GET(P)                                                      \
    ((P) == IPI_PROTO_BGP       ? BGP_SHOW_PATH :                             \
     (P) == IPI_PROTO_UNSPEC    ? NULL : NULL)

#endif /* HAVE_TCP_MESSAGE */

/* Init and shutdown function.  */
int show_client_socket (struct lib_globals *, module_id_t);
struct show_server *show_server_init (struct lib_globals *);
void show_server_finish (struct lib_globals *);

int show_out (struct show *, const char *, ...);
int show_line_write (struct lib_globals *, pal_sock_handle_t,
                     char *, u_int16_t, u_int32_t);
void show_server_show_func (struct show_server *show,
                            int (*func) (struct cli *));


#endif /* _BGPSDN_SHOW_H */
