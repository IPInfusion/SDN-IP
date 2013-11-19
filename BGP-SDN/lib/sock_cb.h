/* $Id: sock_cb.h,v 1.10 2012/02/23 00:25:24 bob.macgill Exp $ */
/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_SOCK_IF_H
#define _BGPSDN_SOCK_IF_H

#define SSOCK_BUF_MAX_SIZE                  (1024)

/* Enumeration of Stream Socket Errors */
enum ssock_error
{
  SSOCK_ERR_NONE = 0,
  SSOCK_ERR_INVALID = -1,
  SSOCK_ERR_CLOSE = -2,
  SSOCK_ERR_READ_LOOP = -3
};

/* Enumeration of Stream Socket CB FSM States */
enum ssock_cb_state
{
  SSOCK_STATE_IDLE = 1,
  SSOCK_STATE_ACTIVE = 2,
  SSOCK_STATE_CONNECTED = 3,
  SSOCK_STATE_WRITING = 4,
  SSOCK_STATE_CLOSING = 5,
  SSOCK_STATE_ZOMBIE = 6
};

/* Stream Socket Control Block */
struct stream_sock_cb
{
  /* Stream Socket Read Thread */
  struct thread *t_ssock_read;

  /* Stream Socket Write Thread */
  struct thread *t_ssock_write;

  /* Stream Socket FD */
  pal_sock_handle_t ssock_fd;

  /* Stream Socket Local-ID */
  union sockunion ssock_su_local;

  /* Stream Socket Remote-ID */
  union sockunion ssock_su_remote;

  /* Stream Socket Queue Buffer Size */
  u_int32_t ssock_buf_size;

  /* Stream Socket Incoming Queue Buffer */
  struct cqueue_buffer *ssock_ibuf;

  /* Stream Socket Outgoing Queue Buffer */
  struct cqueue_buf_list *ssock_obuf_list;

  /* Stream Socket CB FSM State */
  enum ssock_cb_state ssock_state;

  /* Stream Socket CB owning data structure */
  void *ssock_cb_owner;

  /* Stream Socket CB Read Error Function Pointer */
  void (*ssock_status_func) (struct stream_sock_cb *, s_int32_t,
                             struct lib_globals *);

  /* Stream Socket CB Read Function Pointer */
  enum ssock_error (*ssock_read_func) (struct stream_sock_cb *,
                                       u_int32_t, struct lib_globals *);

  /* Stream Socket CB Read Function Argument */
  u_int32_t ssock_read_func_arg;
};

/* Socket-CB Status Function Type */
typedef void (*ssock_cb_status_func_t) (struct stream_sock_cb *,
                                        s_int32_t,
                                        struct lib_globals *);

/* Socket-CB Read Function Type */
typedef enum ssock_error (*ssock_cb_read_func_t) (struct stream_sock_cb *,
                                                  u_int32_t,
                                                  struct lib_globals *);

/* Macro for Starting Steam Socket Read Thread */
#define SSOCK_CB_READ_ON(LIB_GLOB, THREAD, THREAD_ARG,                \
                         THREAD_FUNC, SOCK_FD)                        \
do {                                                                  \
  if (! (THREAD))                                                     \
    (THREAD) = thread_add_read ((LIB_GLOB), (THREAD_FUNC),            \
                                (THREAD_ARG), (SOCK_FD));             \
} while (0)

/* Macro to close a Stream Socket Descriptor */
#define SSOCK_FD_CLOSE(LIB_GLOB, SOCK_FD)                             \
  do {                                                                \
    u_int8_t drain_bin [SSOCK_BUF_MAX_SIZE];                          \
                                                                      \
    if ((SOCK_FD) >= 0)                                               \
      {                                                               \
        pal_sock_set_nonblocking ((SOCK_FD), PAL_TRUE);               \
        pal_sock_shutdown ((SOCK_FD), PAL_SHUT_WR);                   \
        while (pal_sock_read ((SOCK_FD), &drain_bin [0],              \
                              SSOCK_BUF_MAX_SIZE) > 0);               \
        pal_sock_shutdown ((SOCK_FD), PAL_SHUT_RD);                   \
        pal_sock_close ((LIB_GLOB), (SOCK_FD));                       \
      }                                                               \
    (SOCK_FD) = -1;                                                   \
  } while (0)

/* Macro for Stopping Steam Socket Read Thread */
#define SSOCK_CB_READ_OFF(LIB_GLOB, THREAD)                           \
do {                                                                  \
  if (THREAD)                                                         \
    {                                                                 \
      thread_cancel ((THREAD));                                       \
      (THREAD) = NULL;                                                \
    }                                                                 \
} while (0)

/* Macro for Starting Steam Socket Write Thread */
#define SSOCK_CB_WRITE_ON(LIB_GLOB, THREAD, THREAD_ARG,               \
                          THREAD_FUNC, SOCK_FD)                       \
do {                                                                  \
  if (! (THREAD))                                                     \
    (THREAD) = thread_add_write ((LIB_GLOB), (THREAD_FUNC),           \
                                 (THREAD_ARG), (SOCK_FD));            \
} while (0)

/* Macro for Stopping Steam Socket Write Thread */
#define SSOCK_CB_WRITE_OFF(LIB_GLOB, THREAD)                          \
do {                                                                  \
  if (THREAD)                                                         \
    {                                                                 \
      thread_cancel ((THREAD));                                       \
      (THREAD) = NULL;                                                \
    }                                                                 \
} while (0)

/* Macro to get Read Cir-Queue Buffer */
#define SSOCK_CB_GET_READ_CQ_BUF(SSOCK_CB, LIB_GLOB)                  \
  ((SSOCK_CB)->ssock_ibuf)

/* Macro to get Write Cir-Queue Buffer */
#define SSOCK_CB_GET_WRITE_CQ_BUF(SSOCK_CB, BUF_SIZE, LIB_GLOB)       \
  stream_sock_cb_get_write_cq_buf ((SSOCK_CB), (BUF_SIZE), (LIB_GLOB))

/* Macro to get pointer to owning structure */
#define SSOCK_CB_GET_OWNER(SSOCK_CB) ((SSOCK_CB)->ssock_cb_owner)

/* Macro to set pointer to owning structure */
#define SSOCK_CB_SET_OWNER(SSOCK_CB, OWNER)                           \
  ((SSOCK_CB)->ssock_cb_owner = (OWNER))

/* Macro to get pointer to Socket Local-Address structure */
#define SSOCK_CB_GET_SU_LOCAL(SSOCK_CB) (&(SSOCK_CB)->ssock_su_local)

/* Macro to get pointer to Socket Remote-Address structure */
#define SSOCK_CB_GET_SU_REMOTE(SSOCK_CB) (&(SSOCK_CB)->ssock_su_remote)

/* Macro to set SOCK-CB status-func */
#define SSOCK_CB_SET_STATUS_FUNC(SSOCK_CB, STATUS_FUNC)               \
  (((SSOCK_CB)->ssock_status_func) = (STATUS_FUNC))

/* Macro to set SOCK-CB read-func */
#define SSOCK_CB_SET_READ_FUNC(SSOCK_CB, READ_FUNC)                   \
  (((SSOCK_CB)->ssock_read_func) = (READ_FUNC))

/* Macro to set argument to read-func */
#define SSOCK_CB_SET_READ_FUNC_ARG(SSOCK_CB, READ_FUNC_ARG)           \
  (((SSOCK_CB)->ssock_read_func_arg) = (READ_FUNC_ARG))

/* Macro to get SOCK-CB ssock_fd */
#define SSOCK_CB_GET_SSOCK_FD(SSOCK_CB)                               \
  ((SSOCK_CB) ? ((SSOCK_CB)->ssock_fd) : -1)

/* Macro to get Sock-CB Zombies List from Lib-Globals */
#define SSOCK_CB_GET_ZOMBIE_LIST(LIB_GLOB)                            \
  ((LIB_GLOB)->ssock_cb_zombie_list)

/* Macro to convert Sock-CB FSM State value to string */
#define SSOCK_CB_FSM_STATE_STR(STATE)                                 \
    ((STATE) == SSOCK_STATE_IDLE ? "Idle" :                           \
     (STATE) == SSOCK_STATE_ACTIVE ? "Active" :                       \
     (STATE) == SSOCK_STATE_WRITING ? "Writing" :                     \
     (STATE) == SSOCK_STATE_CLOSING ? "Closing" :                     \
     (STATE) == SSOCK_STATE_ZOMBIE ? "Zombie" : "Invalid")

/*
 * Function Prototype declarations
 */
/*
 * NOTE : Following are the Socket-CB API functions
 */
s_int32_t
stream_sock_cb_zombie_list_alloc (struct lib_globals *);
s_int32_t
stream_sock_cb_zombie_list_free (struct lib_globals *);
struct stream_sock_cb *
stream_sock_cb_alloc (void *, u_int32_t, ssock_cb_status_func_t,
                      struct lib_globals *);
pal_sock_handle_t
stream_sock_cb_get_fd (struct stream_sock_cb *,
                       union sockunion *,
                       struct lib_globals *);
s_int32_t
stream_sock_cb_connect (struct stream_sock_cb *,
                        union sockunion *,
                        struct lib_globals *);
s_int32_t
stream_sock_cb_accept (struct stream_sock_cb *,
                       pal_sock_handle_t,
                       struct lib_globals *);
struct cqueue_buffer *
stream_sock_cb_get_write_cq_buf (struct stream_sock_cb *, u_int32_t,
                                 struct lib_globals *);
s_int32_t
stream_sock_cb_purge_unsent_bufs (struct stream_sock_cb *,
                                  struct lib_globals *);
s_int32_t
stream_sock_cb_write_mesg (struct stream_sock_cb *,
                           struct lib_globals *);
s_int32_t
stream_sock_cb_close (struct stream_sock_cb *, struct lib_globals *);
void
stream_sock_cb_free (struct stream_sock_cb *, struct lib_globals *);
s_int32_t
stream_sock_cb_idle (struct stream_sock_cb *, struct lib_globals *);

#endif /* _BGPSDN_SOCK_IF_H */
