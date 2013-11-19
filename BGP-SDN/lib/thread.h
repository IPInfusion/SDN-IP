/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_THREAD_H
#define _BGPSDN_THREAD_H

#include "pal.h"

/* Linked list of thread. */
struct thread_list
{
  struct thread *head;
  struct thread *tail;
  u_int32_t count;
};

/* Master of the theads. */
struct thread_master
{
  /* Priority based queue.  */
  struct thread_list queue_high;
  struct thread_list queue_middle;
  struct thread_list queue_low;

  /* Timer */
#define THREAD_TIMER_SLOT           4
  int index;
  struct thread_list timer[THREAD_TIMER_SLOT];

  /* Thread to be executed.  */
  struct thread_list read_pend;
  struct thread_list read_high;
  struct thread_list read;
  struct thread_list write;
  struct thread_list event;
  struct thread_list event_low;
  struct thread_list unuse;
  pal_sock_set_t readfd;
  pal_sock_set_t writefd;
  pal_sock_set_t exceptfd;
  int max_fd;
  u_int32_t alloc;
};

/* Thread structure. */
struct thread
{
  /* Linked list.  */
  struct thread *next;
  struct thread *prev;

  /* Pointer to the struct thread_master.  */
  struct thread_master *master;

  /* Pointer to the struct lib_globals. */
  struct lib_globals *zg;

 /* Event function.  */
  int (*func) (struct thread *);

  /* Event argument.  */
  void *arg;

  /* Thread type.  */
  char type;

  /* Priority.  */
  char priority;
#define THREAD_PRIORITY_HIGH         0
#define THREAD_PRIORITY_MIDDLE       1
#define THREAD_PRIORITY_LOW          2

  /* Thread timer index.  */
  char index;

  /* Arguments.  */
  union 
  {
    /* Second argument of the event.  */
    int val;

    /* File descriptor in case of read/write.  */
    int fd;

    /* Rest of time sands value.  */
    struct pal_timeval sands;
  } u;
};

/* Thread types.  */
#define THREAD_READ             0
#define THREAD_WRITE            1
#define THREAD_TIMER            2
#define THREAD_EVENT            3
#define THREAD_QUEUE            4
#define THREAD_UNUSED           5
#define THREAD_READ_HIGH        6
#define THREAD_READ_PEND        7
#define THREAD_EVENT_LOW        8

/* Macros.  */
#define THREAD_ARG(X)           ((X)->arg)
#define THREAD_FD(X)            ((X)->u.fd)
#define THREAD_VAL(X)           ((X)->u.val)
#define THREAD_TIME_VAL(X)      ((X)->u.sands)
#define THREAD_GLOB(X)          ((X)->zg)

#define THREAD_READ_ON(global,thread,func,arg,sock) \
  do { \
    if (! thread) \
      thread = thread_add_read (global, func, arg, sock); \
  } while (0)

#define THREAD_WRITE_ON(global,thread,func,arg,sock) \
  do { \
    if (! thread) \
      thread = thread_add_write (global, func, arg, sock); \
  } while (0)

#define THREAD_TIMER_ON(global,thread,func,arg,time) \
  do { \
    if (! thread) \
      thread = thread_add_timer (global, func, arg, time); \
  } while (0)

#define THREAD_OFF(thread) \
  do { \
    if (thread) \
      { \
        thread_cancel (thread); \
        thread = NULL; \
      } \
  } while (0)

#define THREAD_READ_OFF(thread)   THREAD_OFF(thread)
#define THREAD_WRITE_OFF(thread)  THREAD_OFF(thread)
#define THREAD_TIMER_OFF(thread)  THREAD_OFF(thread)

/* Prototypes.  */
struct thread_master *thread_master_create ();
void thread_master_finish (struct thread_master *);

void thread_list_add (struct thread_list *, struct thread *);
void thread_list_execute (struct lib_globals *, struct thread_list *);
void thread_list_clear (struct lib_globals *, struct thread_list *);

struct thread *thread_get (struct lib_globals *, char,
                           int (*) (struct thread *), void *);

struct thread *thread_add_read (struct lib_globals *,
                                int (*)(struct thread *), void *,
                                int);
struct thread *thread_add_read_high (struct lib_globals *,
                                     int (*)(struct thread *), void *,
                                     int);
struct thread *thread_add_write (struct lib_globals *,
                                 int (*)(struct thread *), void *,
                                 int);
struct thread *thread_add_timer (struct lib_globals *,
                                 int (*)(struct thread *), void *, long);
struct thread *thread_add_timer_timeval (struct lib_globals *,
                                         int (*)(struct thread *),
                                         void *, struct pal_timeval);
struct thread *thread_add_event (struct lib_globals *,
                                 int (*)(struct thread *), void *,
                                 int);
struct thread *thread_add_event_low (struct lib_globals *,
                                     int (*)(struct thread *), void *,
                                     int);
struct thread *thread_add_read_pend (struct lib_globals *zg, 
                                     int (*func) (struct thread *), void *arg,
                                     int val);
void thread_cancel (struct thread *);
void thread_cancel_event (struct lib_globals *, void *);
void thread_cancel_event_low (struct lib_globals *, void *);
void thread_cancel_timer (struct lib_globals *, void *);
void thread_cancel_write (struct lib_globals *, void *);
void thread_cancel_read (struct lib_globals *, void *);
struct thread *thread_fetch (struct lib_globals *, struct thread *);
struct thread *thread_execute (struct lib_globals *,
                               int (*)(struct thread *), void *,
                               int);
void thread_call (struct thread *);
u_int32_t thread_timer_remain_second (struct thread *);

#endif /* _BGPSDN_THREAD_H */
