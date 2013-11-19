/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <pal.h>

#include "line.h"
#include "show.h"
#include "thread.h"
#include "snprintf.h"
#include "cli.h"
#include "log.h"
#include "tlv.h"
#include "imi_client.h"

struct show_page *
show_page_new (void)
{
  return XMALLOC (MTYPE_SHOW_PAGE, sizeof (struct show_page));
}

void
show_page_free (struct show_page *page)
{
  XFREE (MTYPE_SHOW_PAGE, page);
}

/* Allocate a new show connection.  */
struct show *
show_new (void)
{
  return XCALLOC (MTYPE_SHOW, sizeof (struct show));
}

void
show_free (struct show *show)
{
  XFREE (MTYPE_SHOW, show);
}

struct show_server *
show_server_new (struct lib_globals *zg)
{
  struct show_server *new;

  new = XCALLOC (MTYPE_SHOW_SERVER, sizeof (struct show_server));
  if (new != NULL)
    new->zg = zg;

  return new;
}

void
show_server_free (struct lib_globals *zg)
{
  if (zg->ss != NULL)
    XFREE (MTYPE_SHOW_SERVER, zg->ss);

  /* Set the NULL pointer.  */
  zg->ss = NULL;
}

void
show_page_unused_add (struct show_server *ss, struct show_page *page)
{
  if (ss->page_unuse_count >= ss->page_unuse_max)
    show_page_free (page);
  else
    {
      page->cp = page->sp = 0;
      page->next = ss->page_unuse;
      ss->page_unuse = page;
      ss->page_unuse_count++;
    }
}

void
show_page_unused_clear (struct show_server *ss)
{
  struct show_page *page;

  while ((page = ss->page_unuse))
    {
      ss->page_unuse = page->next;
      show_page_free (page);
    }
  ss->page_unuse_count = 0;
}

struct show_page *
show_page_get (struct show *show)
{
  struct show_page *page;

  /* Check unused page first.  */
  if (show->server->page_unuse)
    {
      page = show->server->page_unuse;
      show->server->page_unuse = page->next;
      show->server->page_unuse_count--;
    }
  else
    {
      page = show_page_new ();
      if (page == NULL)
        return NULL;
    }

  /* Reset values.  */
  page->cp = page->sp = 0;
  page->next = NULL;

  return page;
}

/* Return last page.  */
struct show_page *
show_last_page (struct show *show)
{
  struct show_page *page;

  /* Pick up last page.  */
  if (show->last_page && show->last_page->cp != SHOW_PAGE_SIZE)
    return show->last_page;

  /* Get the page.  */
  page = show_page_get (show);
  if (page == NULL)
    return NULL;

  /* When no first page is there, this is the one.  */
  if (show->first_page == NULL)
    show->first_page = page;

  /* Link to the last page.  */
  if (show->last_page)
    show->last_page->next = page;
  show->last_page = page;

  return page;
}

/* Move first page to unused page.  */
void
show_remove_first (struct show *show)
{
  struct show_page *page;

  if (show->first_page)
    {
      page = show->first_page;
      show->first_page = page->next;
      if (show->first_page == NULL)
        show->last_page = NULL;
      show_page_unused_add (show->server, page);
    }
}

void
show_close (struct show *show)
{
  if (show->cli.callback)
    {
      show->cli.status = CLI_CLOSE;
      (*(show->cli.callback)) (&show->cli);
    }

  while (show->first_page)
    show_remove_first (show);

  THREAD_READ_OFF (show->t_read);
  THREAD_WRITE_OFF (show->t_write);

  pal_sock_close (show->server->zg, show->sock);

  show_free (show);
}

/* Write the information to the socket.  */
int
show_write (struct thread *t)
{
  struct show *show;
  struct show_page *page;
  struct lib_globals *zg;
  pal_sock_handle_t sock;
  int written;
  int to_be_written;

  show = THREAD_ARG (t);
  sock = THREAD_FD (t);
  zg = THREAD_GLOB (t);
  show->t_write = NULL;

   if (show->cli.status == CLI_WAIT)
    {
      /* Callback function.  */
      if (show->cli.callback)
        {
         (*(show->cli.callback)) (&show->cli);

          THREAD_WRITE_ON (zg, show->t_write, show_write, show, show->sock);
        }
      else
        show_close (show);

      return 0;
    }


  /* Pick up first page to write. */
  page = show->first_page;
  if (page == NULL) 
    {
      show_close (show);
      return 0;
    }

  to_be_written = page->cp - page->sp;
  if (page->buf[page->cp - 1] == '\0')
    to_be_written--;

  if (to_be_written <= 0)
    {
      show_close (show);
      return 0;
    }

  /* Write the information to the socket.  */
  written = pal_sock_write (sock, page->buf + page->sp, to_be_written);

  if (written <= 0)
    {
      show_close (show);
      return 0;
    }

  page->sp += written;

  /* Write is partial.  */
  if (written != to_be_written)
    {
      THREAD_WRITE_ON (zg, show->t_write, show_write, show, show->sock);
      return 0;
    }
 

  /* Page is flushed out.  Reset last_page and first_page pointer.  */
  show_remove_first (show);

  /* When everything is flushed out, */
  if (show->first_page)
    THREAD_WRITE_ON (zg, show->t_write, show_write, show, show->sock);
  else
    {
      /* Callback function.  */
      if (show->cli.callback)
        {
          show->cli.status = CLI_CONTINUE;
          (*(show->cli.callback)) (&show->cli);

          THREAD_WRITE_ON (zg, show->t_write, show_write, show, show->sock);
        }
      else
        show_close (show);
    }

  return 0;
}

/* Store output to page directly.  This mechanism reduce copying of
   the output.  When the output does not fit into the page, fill
   the output to the each page.  */
int
show_out (struct show *show, const char *format, ...)
{
  va_list args;
  int available;
  int to_be_written;
  struct show_page *page;
  struct show_page *buffer_page = NULL;
  char *buf;
  char *top = NULL;
  int ret;

  /* Pick up last page to write.  */
  page = show_last_page (show);
  if (page == NULL)
    return -1;

  /* Remaining buffer length.  */
  available = SHOW_PAGE_SIZE - page->cp;

  if (show->cli.status == CLI_WAIT)
    {
      /* Register write thread.  */
      THREAD_WRITE_ON (show->server->zg, show->t_write, show_write, show,
                      show->sock);
      return 0;
    }

  /* To reduce the copy operation, write the data to the page
     directly.  */
  va_start (args, format);
  to_be_written = zvsnprintf (page->buf + page->cp, available, format, args);
  va_end (args);

  /* If an output error is encountered a negative value  is  returned, or
     Until glibc 2.0.6 they would return -1 when the output was truncated. */
  if (to_be_written <= 0)
    return -1;

  ret = to_be_written;

  /* When all of the data is written.  */
  if (to_be_written < available)
    {
      page->cp += to_be_written;
      THREAD_WRITE_ON (show->server->zg, show->t_write, show_write, show,
                       show->sock);
      return ret;
    }
  
  /* This page is filled.  Set SHOW_PAGE_SIZE to page->cp.  Add one to
     to_be_written for trailing '\0' space.  */
  page->cp = SHOW_PAGE_SIZE;
  to_be_written++;

  /* Prepare temporary space.  */
  if (to_be_written <= SHOW_PAGE_SIZE)
    {
      /* Get the page.  */
      buffer_page = show_page_get (show);
      if (buffer_page == NULL)
        return -1;
      buf = buffer_page->buf;
    }
  else
    {
      /* Too big output to use page, allocate a temporary buffer.  */
      buf = top = XMALLOC (MTYPE_TMP, to_be_written);
      if (buf == NULL)
        return -1;
    }

  /* Put all of data to the buffer.  */
  va_start (args, format);
  zvsnprintf (buf, to_be_written, format, args);
  va_end (args);

  /* Available is printed length plus trailing '\0'.  So adjust
     to_be_written by the value.  After that we don't need trailing
     '\0' so decrement available by one.  */
  to_be_written -= available;
  available--;
  buf += available;

  while (to_be_written)
    {
      /* Until all of the data is put into the buffer.  */
      page = show_last_page (show);
      if (page == NULL)
        return -1;

      /* Calculate available length.  */
      available = SHOW_PAGE_SIZE - page->cp;

      if (available > to_be_written)
        available = to_be_written;

      /* Copy the data.  */
      pal_mem_cpy (page->buf, buf, available);

      /* Update pointers.  */
      to_be_written -= available;
      buf += available;
      page->cp += available;
    }

  /* If buffer is allocated free it.  */
  if (top)
    XFREE (MTYPE_TMP, top);
  else
    show_page_unused_add (show->server, buffer_page);

  /* Register write thread.  */
  THREAD_WRITE_ON (show->server->zg, show->t_write, show_write, show,
                   show->sock);

  return ret;
}

/* Read from the line.  */
int
show_read (struct thread *t)
{
  int ret;
  int nbytes;
  struct lib_globals *zg;
  pal_sock_handle_t sock;
  struct show *show;
  struct cli_tree *ctree;
  struct cli_node *node;
  struct cli *cli;
  char *buf;
  u_int32_t vr_id;
  u_char buf_id[4];
  struct ipi_vr *vr;
  struct imi_client *ic;
  u_int32_t mode;

  /* Fetch socket and IMI line information.  */
  zg = THREAD_GLOB (t);
  sock = THREAD_FD (t);
  show = THREAD_ARG (t);
  show->t_read = NULL;
  ctree = show->server->ctree;
  cli = &show->cli;
  cli->ctree = ctree;

  if(zg->imh != NULL)
  {
     ic = (struct imi_client *)zg->imh->info;
  }
  else
  {
     return 0;
  }
  
  if(ic != NULL)
  {
     mode = ic->line.cli.mode;
  }
  
  else
  {
     return 0;
  }

  /* Decode VR ID. */
  nbytes = pal_sock_read (sock, buf_id, 4);
  /* Socket is closed.  */
  if (nbytes == 0)
    {
      show_close (show);
      return 0;
    }

  /* Error occur.  */
  if (nbytes < 0)
    {
      show_close (show);
      return 0;
    }

  vr_id = (buf_id[0] << 24) | (buf_id[1] << 16) | (buf_id[2] << 8) | buf_id[3];

  nbytes = pal_sock_read (sock, show->buf, SHOW_LINE_SIZE);

  /* Socket is closed.  */
  if (nbytes == 0)
    {
      show_close (show);
      return 0;
    }

  /* Error occur.  */
  if (nbytes < 0)
    {
      show_close (show);
      return 0;
    }

  /* Check VR.  */
  vr = ipi_vr_lookup_by_id (zg, vr_id);
  if (vr == NULL)
    {
      show_close (show);
      return 0;
    }

  buf = show->buf;

  /* Parser is needed.  */
  ret = cli_parse (ctree, EXEC_MODE, PRIVILEGE_MAX, buf, 1, 0);
   if(ret != CLI_PARSE_SUCCESS)
      ret = cli_parse (ctree, mode, PRIVILEGE_MAX, buf, 1, 0);
  switch (ret)
    {
    case CLI_PARSE_SUCCESS:
      node = ctree->exec_node;
      cli->zg = zg;
      cli->vr = vr;
      cli->out_func = (int (*) (void *, char *, ...)) show_out;
      cli->out_val = show;
      cli->show_func = show->server->show_func;
      cli->status = CLI_NORMAL;
      cli->str = buf;
      cli->cel = node->cel;

      LIB_GLOB_SET_VR_CONTEXT (cli->zg, cli->vr);

      (*node->cel->func) (cli, ctree->argc, ctree->argv);
      if (show->t_write == NULL)
        show_close (show);
      break;
    case CLI_PARSE_INCOMPLETE:
      show_close (show);
      break;
    case CLI_PARSE_INCOMPLETE_PIPE:
      show_close (show);
      break;
    case CLI_PARSE_EMPTY_LINE:
      show_close (show);
      break;
    case CLI_PARSE_AMBIGUOUS:
      show_close (show);
      break;
    case CLI_PARSE_NO_MATCH:
      show_close (show);
      break;
    case CLI_PARSE_NO_MODE:
      show_close (show);
      break;
    case CLI_PARSE_ARGV_TOO_LONG:
      show_close (show);
      break;
    default:
      show_close (show);
      break;
    }

  /* Free arguments.  */
  cli_free_arguments (ctree);

  return 0;
}

/* Accept IMI line connection.  */
static int
show_accept (struct thread *t)
{
  pal_sock_handle_t asock;
  pal_sock_handle_t csock;
  struct pal_sockaddr_un sockun;
  int len;
  struct show *show;
  struct show_server *server;
  struct lib_globals *zg;

  /* Fetch socket and set thread information.  */
  asock = THREAD_FD (t);
  server = THREAD_ARG (t);
  server->t_accept = NULL;
  zg = THREAD_GLOB (t);

  /* Prepare sockaddr_un.  */
  pal_mem_set (&sockun, 0, sizeof (struct pal_sockaddr_un));
  len = sizeof (struct pal_sockaddr_un);

  /* Register accept thread.  */
  THREAD_READ_ON (zg, server->t_accept, show_accept, server, asock);

  /* Accept client connection.  */
  csock = pal_sock_accept (zg, asock, (struct pal_sockaddr *) &sockun, &len);
  if (csock < 0)
    {
      return -1;
    }

  /* Allocate a new line to the socket.  */
  show = show_new ();
  show->sock = csock;
  show->server = server;

  /* Register read thread.  */
  THREAD_READ_ON (zg, show->t_read, show_read, show, csock);

  return 0;
}

#ifdef HAVE_TCP_MESSAGE

/* Create "show" client socket. */
int
show_client_socket (struct lib_globals *zg, module_id_t proto)
{
  pal_sock_handle_t sock;
  struct pal_sockaddr_in4 addr;
  int len = sizeof (struct pal_sockaddr_in4);

  sock = pal_sock (zg, AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return -1;


  /* Prepare TCP client connection. */
  pal_mem_set (&addr, 0, sizeof (struct pal_sockaddr_in4));
  addr.sin_family = AF_INET;
  addr.sin_port = pal_hton16 (SHOW_PORT_GET (proto));
  addr.sin_addr.s_addr = pal_hton32 (INADDR_LOOPBACK);
#ifdef HAVE_SIN_LEN
  addr.sin_len = len;
#endif /* HAVE_SIN_LEN. */

  /* Connect to the server. */
  if (pal_sock_connect (sock, (struct pal_sockaddr *) &addr, len) < 0)
    {
      pal_sock_close (zg, sock);
      return -1;
    }

  return sock;
}

/* Create "show" server socket. */
int
show_server_socket (struct lib_globals *zg)
{
  int ret;
  int sock;
  int port;
  struct pal_sockaddr_in4 addr;
  int len = sizeof (struct pal_sockaddr_in4);
  int state = 1; /* on */

  /* Port check. */
  port = SHOW_PORT_GET (zg->protocol);
  if (port < 0)
    return -1;

  /* IPNET TCP code has some issues with below code. So commenting it out
   * for now.
   */
#ifndef HAVE_IPNET
  /* Check if the socket is already opened. */
  sock = show_client_socket (zg, zg->protocol);
  if (sock >= 0)
    {
      pal_sock_close (zg, sock);

      pal_system_err ("Other %s may be running. Please check it",
                      modname_strs (zg->protocol));

      /* Doesn't allow multiple daemons to run. */
      pal_exit (0);
    }
#endif /* HAVE_IPNET */

  /* Create show server socket. */
  sock = pal_sock (zg, AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return -1;

  /* Prepare accept socket. */
  pal_mem_set (&addr, 0, sizeof (struct pal_sockaddr_in4));
  addr.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
  addr.sin_len = len;
#endif /* HAVE_SIN_LEN. */
  addr.sin_port = pal_hton16 (port);
  addr.sin_addr.s_addr = pal_hton32 (INADDR_LOOPBACK);

  pal_sock_set_reuseaddr (sock, state);
  pal_sock_set_reuseport (sock, state);
 
  /* Bind socket. */
  if (pal_sock_bind (sock, (struct pal_sockaddr *) &addr, len) < 0)
    {
      pal_sock_close (zg, sock);
      return -1;
    } 
  
  /* Listen to the socket.  */
  ret = pal_sock_listen (sock, 5);
  if (ret < 0)
    {
      pal_sock_close (zg, sock);
      return -1;
    }

  return sock;
}
#else /* HAVE_TCP_MESSAGE */

/* Create "show" client socket. */
int
show_client_socket (struct lib_globals *zg, module_id_t proto)
{
  int ret;
  char *path;
  pal_sock_handle_t sock;
  struct pal_sockaddr_un sockun;
  socklen_t len;

  if ((path = SHOW_PATH_GET (proto)) == NULL)
    return -1;

  /* Check socket status.  */
  ret = pal_sock_check (path);
  if (ret < 0)
    return ret;

  /* Make UNIX domain socket.  */
  sock = pal_sock (zg, AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    return -1;

  /* Prepare sockaddr_un.  */
  pal_mem_set (&sockun, 0, sizeof (struct pal_sockaddr_un));
  sockun.sun_family = AF_UNIX;
  pal_strncpy (sockun.sun_path, path, pal_strlen (path));
#ifdef HAVE_SUN_LEN
  len = sockun.sun_len = SUN_LEN (&sockun);
#else
  len = sizeof (sockun.sun_family) + pal_strlen (sockun.sun_path);
#endif /* HAVE_SUN_LEN */

  /* Connect to the socket.  */
  ret = pal_sock_connect (sock, (struct pal_sockaddr *) &sockun, len);
  if (ret < 0)
    {
      pal_sock_close (zg, sock);
      return -1;
    }
  return sock;
}

/* Create "show" server socket. */
int
show_server_socket (struct lib_globals *zg)
{
  int ret;
  int sock;
  char *path;
  struct pal_sockaddr_un serv;
  socklen_t len;

  /* Path check. */
  path = SHOW_PATH_GET (zg->protocol);
  if (path == NULL)
    return -1;

  /* Check if the socket is already opened. */
  sock = show_client_socket (zg, zg->protocol);
  if (sock >= 0)
    {
      pal_sock_close (zg, sock);

      pal_system_err ("Other %s may be running. Please check it",
                      modname_strs (zg->protocol));

      /* Doesn't allow multiple daemons to run. */
      pal_exit (0);
    }

  /* Open UNIX domain socket.  */
  sock = pal_sock (zg, AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    return -1;

  /* Unlink. */
  pal_unlink (path);

  /* Make server socket.  */
  pal_mem_set (&serv, 0, sizeof (struct pal_sockaddr_un));
  serv.sun_family = AF_UNIX;
  pal_strncpy (serv.sun_path, path, pal_strlen (path));
#ifdef HAVE_SUN_LEN
  len = serv.sun_len = SUN_LEN (&serv);
#else
  len = sizeof (serv.sun_family) + pal_strlen (serv.sun_path);
#endif /* HAVE_SUN_LEN */

  /* Bind the socket.  */
  ret = pal_sock_bind (sock, (struct pal_sockaddr *) &serv, len);
  if (ret < 0)
    {
      pal_sock_close (zg, sock);
      return -1;
    }

  /* Listen to the socket.  */
  ret = pal_sock_listen (sock, 5);
  if (ret < 0)
    {
      pal_sock_close (zg, sock);
      return -1;
    }

  /* Set owner and mode of the UNIX domain socket file.  */

  return sock;
}
#endif /* HAVE_TCP_MESSAGE */

/* Initialize "show" server.  */
struct show_server *
show_server_init (struct lib_globals *zg)
{
  pal_sock_handle_t sock;

  /* Create show server socket. */
  sock = show_server_socket (zg);
  if (sock < 0)
    return NULL;

  /* Allocate server memory.  */
  zg->ss = show_server_new (zg);
  if (zg->ss == NULL)
    return NULL;

  /* Unused page counters.  */
  zg->ss->page_unuse_count = 0;
  zg->ss->page_unuse_max = SHOW_PAGE_UNUSE_MAX;

  /* Set CLI tree.  */
  zg->ss->ctree = zg->ctree;
  zg->ss->sock = sock;
  zg->ss->show_func = NULL;

  /* Start accept thread.  */
  THREAD_READ_ON (zg, zg->ss->t_accept, show_accept, zg->ss, sock);

  return zg->ss;
}

/* Initialize running configuration callback. */
void
show_server_show_func (struct show_server *show,
                            int (*func) (struct cli *))
{
  show->show_func = func;
}

void
show_server_finish (struct lib_globals *zg)
{
  /* Close the socket.  */
  if (zg->ss->sock >= 0)
    pal_sock_close (zg, zg->ss->sock);

  zg->ss->sock = -1;

  /* Cancel the thread.  */
  THREAD_READ_OFF (zg->ss->t_accept);

  /* Clear the unused pages.  */
  show_page_unused_clear (zg->ss);

  /* Free the memory.  */
  show_server_free (zg);
}
