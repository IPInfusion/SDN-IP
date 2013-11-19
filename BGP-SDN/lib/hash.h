/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_HASH_H
#define _BGPSDN_HASH_H

/* Default hash table size.  */ 
#define HASHTABSIZE     1024

struct hash_backet
{
  /* Linked list.  */
  struct hash_backet *next;

  /* Hash key. */
  u_int32_t key;

  /* Data.  */
  void *data;
};

struct hash
{
  /* Hash backet. */
  struct hash_backet **index;

  /* Hash table size. */
  u_int32_t size;

  /* Key make function. */
  u_int32_t (*hash_key) ();

  /* Data compare function. */
  bool_t (*hash_cmp) ();

  /* Backet alloc. */
  u_int32_t count;
};

struct hash *hash_create (u_int32_t (*) (), bool_t (*) ());
struct hash *hash_create_size (u_int32_t,
                               u_int32_t (*) (), bool_t (*) ());

void *hash_get (struct hash *, void *, void * (*) ());
void *hash_alloc_intern (void *);
void *hash_lookup (struct hash *, void *);
void *hash_release (struct hash *, void *);

void hash_iterate (struct hash *,
                   void (*) (struct hash_backet *, void *), void *);
void hash_iterate2 (struct hash *,
                    void (*) (struct hash_backet *, void *, void *),
                    void *, void *);
void hash_iterate3 (struct hash *,
                    void (*) (struct hash_backet *, void *, void *, void *),
                    void *, void *, void *);

void hash_clean (struct hash *, void (*) (void *));
void hash_free (struct hash *);

void hash_iterate_delete (struct hash *,
                          void (*) (struct hash_backet *, void *), void *);

void hash_iterate_delete2 (struct hash *,
                           void (*) (struct hash_backet *, void *, void *),
                           void *, void *);
void hash_iterate_delete3 (struct hash *hash,
                      void (*) (struct hash_backet *, void *, void *, void *),
                           void *, void *, void *);
void *hash_set (struct hash *, void *, void *);

u_int32_t hash_key_make (char *);
#endif /* _BGPSDN_HASH_H */
