/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */
#ifndef _FIFO_H
#define _FIFO_H

/* FIFO macros */
struct fifo
{
  struct fifo *next;
  struct fifo *prev;
};

#define FIFO_INIT(F)                                  \
  do {                                                \
    struct fifo *Xfifo = (struct fifo *)(F);          \
    Xfifo->next = Xfifo->prev = Xfifo;                \
  } while (0)

#define FIFO_ADD(F,N)                                 \
  do {                                                \
    struct fifo *Xfifo = (struct fifo *)(F);          \
    struct fifo *Xnode = (struct fifo *)(N);          \
    Xnode->next = Xfifo;                              \
    Xnode->prev = Xfifo->prev;                        \
    Xfifo->prev = Xfifo->prev->next = Xnode;          \
  } while (0)

#define FIFO_DEL(N)                                   \
  do {                                                \
    struct fifo *Xnode = (struct fifo *)(N);          \
    Xnode->prev->next = Xnode->next;                  \
    Xnode->next->prev = Xnode->prev;                  \
  } while (0)

#define FIFO_LOOP(F,N)                                \
  for ((N) = (F)->next;                               \
       (struct fifo *)(N) != (struct fifo *)(F);      \
       (N) = (N)->next)

#define FIFO_EMPTY(F)                                 \
  (((struct fifo *)(F))->next == (struct fifo *)(F))

#define FIFO_TOP(F)                                   \
  (FIFO_EMPTY(F) ? NULL : ((struct fifo *)(F))->next)

#define FIFO_HEAD(F)                                  \
  ((((struct fifo *)(F))->next == (struct fifo *)(F)) \
   ? NULL : ((struct fifo *)(F))->next)

#define FIFO_NODE_NEXT(F,N)                             \
  ((((struct fifo *)(N)) == (struct fifo *)(F)          \
    || ((struct fifo *)(N))->next == (struct fifo *)(F))\
   ? NULL : ((struct fifo *)(N))->next)

#endif /* _FIFO_H */
