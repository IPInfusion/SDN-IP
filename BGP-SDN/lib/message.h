/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_MESSAGE_H
#define _BGPSDN_MESSAGE_H

/* Generic message handling library.  Two connection type UNIX domain
   socket and TCP socket is supported.  */

#define MSG_CINDEX_SIZE                 32
typedef u_int32_t  cindex_t;

/* Message library event types.  */
#define MESSAGE_EVENT_CONNECT           0
#define MESSAGE_EVENT_DISCONNECT        1
#define MESSAGE_EVENT_READ_HEADER       2
#define MESSAGE_EVENT_READ_MESSAGE      3
#define MESSAGE_EVENT_MAX               4

/* Message client socket type. */
#define MESSAGE_CLIENT_BLOCKING         0
#define MESSAGE_CLIENT_NON_BLOCKING     1

#define MESSAGE_SYNC_CLIENT_REGISTER    0
#define MESSAGE_ASYNC_CLIENT_REGISTER   1

#define MESSAGE_HDR_SIZE                14
#define MESSAGE_REGMSG_SIZE             4
#define MESSAGE_MAX_SIZE                4096   
#define MESSAGE_ERR_PKT_TOO_SMALL       -1 

/* Message library callback function typedef.  */
struct message_handler;
struct message_entry;

typedef int (*MESSAGE_CALLBACK) (struct message_handler *,
                                 struct message_entry *, pal_sock_handle_t);

/* Message handler structure.  This structure is common both server
   and client side.  */
struct message_handler
{
  struct lib_globals *zg;

  /* Socket to accept or connect.  */
  pal_sock_handle_t sock;

  /* Style of the connection.  */
  int style;
#define MESSAGE_STYLE_UNIX_DOMAIN   0
#define MESSAGE_STYLE_TCP           1

  /* Type of the connection.  Async or sync.  */
  int type;
#define MESSAGE_TYPE_ASYNC          0
#define MESSAGE_TYPE_SYNC           1

  /* Port for TCP socket.  */
  u_int16_t port;

  /* Path for UNIX domain socket.  */
  char *path;

  /* Call back handers.  */
  MESSAGE_CALLBACK callback[MESSAGE_EVENT_MAX];

  /* Connection read thread.  */
  struct thread *t_read;

  /* Connect thread. */
  struct thread *t_connect;

  /* Vector to manage client.  */
  vector clist;

  /* Information pointer.  */
  void *info;

  /* Status of connection. */
  int status;
#define MESSAGE_HANDLER_DISCONNECTED      0
#define MESSAGE_HANDLER_CONNECTED         1
};

/* This structure is used at server side for managing client
   connection.  */
struct message_entry
{
  struct lib_globals *zg;

  /* Pointer to message server structure.  */
  struct message_handler *ms;

  /* Socket to client.  */
  pal_sock_handle_t sock;

  /* Information to user specific data.  */
  void *info;

  /* Read thread.  */
  struct thread *t_read;
};

/* Message send queue.  */
struct message_queue_entry
{
  struct message_queue *next;
  struct message_queue *prev;

  u_char *buf;
  u_int16_t length;
  u_int16_t written;
};

/* Message send queue master*/
struct message_queue
{
  struct lib_globals *zg;
  struct fifo fifo;
  struct thread *t_write;
};

/* Protocol client header */
struct pmsghdr
{
  u_int32_t len;  /* Length of the header. */
  u_int16_t type; /* Client Name */
};

/* Client message for registration with HSL server */
struct preg_msg
{
  u_int16_t len;
  u_int16_t value;
};

#define MSG_DECODE_TLV_HEADER(TH)                                             \
    do {                                                                      \
      TLV_DECODE_GETW ((TH).type);                                            \
      TLV_DECODE_GETW ((TH).length);                                          \
      (TH).length -= BFD_TLV_HEADER_SIZE;                                     \
    } while (0)

#define MSG_CHECK_CTYPE(F,C)        (CHECK_FLAG (F, (1 << C)))
#define MSG_SET_CTYPE(F,C)          (SET_FLAG (F, (1 << C)))
#define MSG_UNSET_CTYPE(F,C)        (UNSET_FLAG (F, (1 << C)))

/* Message server functions.  */
void message_entry_free (struct message_entry *);
struct message_handler *message_server_create (struct lib_globals *);
int message_server_delete (struct message_handler *);
void message_server_set_style_domain (struct message_handler *, char *);
void message_server_set_style_tcp (struct message_handler *, u_int16_t);
void message_server_set_callback (struct message_handler *, int,
                                  MESSAGE_CALLBACK);
int message_server_start (struct message_handler *);
int message_server_stop (struct message_handler *);
void message_server_disconnect (struct message_handler *ms,
                           struct message_entry *me, pal_sock_handle_t sock);

/* Message client functions.  */
struct message_handler *message_client_create (struct lib_globals *, int);
int message_client_delete (struct message_handler *);
void message_client_set_style_domain (struct message_handler *, char *);
void message_client_set_style_tcp (struct message_handler *, u_int16_t);
void message_client_set_callback (struct message_handler *, int,
                                  MESSAGE_CALLBACK);
int message_client_start (struct message_handler *);
int message_client_stop (struct message_handler *);
int message_client_connect (struct thread *t);
void message_client_disconnect (struct message_handler *, pal_sock_handle_t);
int message_client_read (struct thread *t);
void message_client_read_register (struct message_handler *);
void message_client_read_reregister (struct message_handler *);
void message_queue_init (struct lib_globals *, struct message_queue *);
struct message_queue_entry *message_queue_top (struct message_queue *);
void message_queue_clear (struct message_queue *);
void message_queue_entry_set (struct message_queue *, pal_sock_handle_t,
                              u_char *, u_int16_t, u_int16_t);

#endif /* _BGPSDN_MESSAGE_H */
