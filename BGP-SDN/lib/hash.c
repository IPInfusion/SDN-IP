/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "hash.h"

/* Allocate a new hash.  */
struct hash *
hash_create_size (u_int32_t size, 
                  u_int32_t (*hash_key) (), bool_t (*hash_cmp) ())
{
  struct hash *hash;

  hash = XMALLOC (MTYPE_HASH, sizeof (struct hash));
  hash->index = XCALLOC (MTYPE_HASH_INDEX, 
                         sizeof (struct hash_backet *) * size);
  hash->size = size;
  hash->hash_key = hash_key;
  hash->hash_cmp = hash_cmp;
  hash->count = 0;

  return hash;
}

/* Allocate a new hash with default hash size.  */
struct hash *
hash_create (u_int32_t (*hash_key) (), bool_t (*hash_cmp) ())
{
  return hash_create_size (HASHTABSIZE, hash_key, hash_cmp);
}

/* Utility function for hash_get().  When this function is specified
   as alloc_func, return arugment as it is.  This function is used for
   intern already allocated value.  */
void *
hash_alloc_intern (void *arg)
{
  return arg;
}

/* Lookup and return hash backet in hash.  If there is no
   corresponding hash backet and alloc_func is specified, create new
   hash backet.  */
void *
hash_get (struct hash *hash, void *data, void * (*alloc_func) ())
{
  u_int32_t key;
  u_int32_t index;
  void *newdata;
  struct hash_backet *backet;

  key = (*hash->hash_key) (data);
  index = key % hash->size;

  for (backet = hash->index[index]; backet != NULL; backet = backet->next) 
    if (backet->key == key
        && (*hash->hash_cmp) (backet->data, data) == PAL_TRUE)
      return backet->data;

  if (alloc_func)
    {
      newdata = (*alloc_func) (data);
      if (newdata == NULL)
        return NULL;

      backet = XMALLOC (MTYPE_HASH_BUCKET, sizeof (struct hash_backet));
      backet->data = newdata;
      backet->key = key;
      backet->next = hash->index[index];
      hash->index[index] = backet;
      hash->count++;
      return backet->data;
    }
  return NULL;
}

/* Hash lookup.  */
void *
hash_lookup (struct hash *hash, void *data)
{
  return hash_get (hash, data, NULL);
}

/* This function release registered value from specified hash.  When
   release is successfully finished, return the data pointer in the
   hash backet.  */
void *
hash_release (struct hash *hash, void *data)
{
  void *ret;
  u_int32_t key;
  u_int32_t index;
  struct hash_backet *backet;
  struct hash_backet *pp;

  key = (*hash->hash_key) (data);
  index = key % hash->size;

  for (backet = pp = hash->index[index]; backet; backet = backet->next)
    {
      if (backet->key == key
          && (*hash->hash_cmp) (backet->data, data) == PAL_TRUE)
        {
          if (backet == pp) 
            hash->index[index] = backet->next;
          else 
            pp->next = backet->next;

          ret = backet->data;
          XFREE (MTYPE_HASH_BUCKET, backet);
          hash->count--;
          return ret;
        }
      pp = backet;
    }
  return NULL;
}

/* Iterator function for hash.  */
void
hash_iterate (struct hash *hash,
              void (*func) (struct hash_backet *, void *), void *arg)
{
  struct hash_backet *hb;
  int i;

  for (i = 0; i < hash->size; i++)
    for (hb = hash->index[i]; hb; hb = hb->next)
      (*func) (hb, arg);
}

/* Iterator function for hash with 2 args  */
void
hash_iterate2 (struct hash *hash,
               void (*func) (struct hash_backet *, void *, void *),
               void *arg1, void *arg2)
{
  struct hash_backet *hb;
  struct hash_backet *hb_next;
  int i;

  for (i = 0; i < hash->size; i++)
    for (hb = hash->index[i]; hb; hb = hb_next)
      {
        hb_next = hb->next;
        (*func) (hb, arg1, arg2);
      }
}

/* Iterator function for hash with 3 args  */
void
hash_iterate3 (struct hash *hash,
               void (*func) (struct hash_backet *, void *, void *, void *),
               void *arg1, void *arg2, void *arg3)
{
  struct hash_backet *hb;
  int i;

  for (i = 0; i < hash->size; i++)
    for (hb = hash->index[i]; hb; hb = hb->next)
      (*func) (hb, arg1, arg2, arg3);
}

/* Clean up hash.  */
void
hash_clean (struct hash *hash, void (*free_func) (void *))
{
  int i;
  struct hash_backet *hb;
  struct hash_backet *next;

  for (i = 0; i < hash->size; i++)
    {
      for (hb = hash->index[i]; hb; hb = next)
        {
          next = hb->next;
              
          if (free_func)
            (*free_func) (hb->data);

          XFREE (MTYPE_HASH_BUCKET, hb);
          hash->count--;
        }
      hash->index[i] = NULL;
    }
}

/* Free hash memory.  You may call hash_clean before call this
   function.  */
void
hash_free (struct hash *hash)
{
  XFREE (MTYPE_HASH_INDEX, hash->index);
  XFREE (MTYPE_HASH, hash);
}

/* Iterator function for hash entry delete.  */
void
hash_iterate_delete (struct hash *hash,
                     void (*func) (struct hash_backet *, void *), void *arg)
{
  struct hash_backet *next = NULL;
  struct hash_backet *hb = NULL;
  int i;

  for (i = 0; i < hash->size; i++)
    for (hb = hash->index[i]; hb; hb = next)
      {
        next = hb->next;
        (*func) (hb, arg);
      }
}

/* Iterator function for hash entry delete with 2 args  */
void
hash_iterate_delete2 (struct hash *hash,
                      void (*func) (struct hash_backet *, void *, void *),
                      void *arg1, void *arg2)
{
  struct hash_backet *next = NULL;
  struct hash_backet *hb = NULL;
  int i;

  for (i = 0; i < hash->size; i++)
    for (hb = hash->index[i]; hb; hb = next)
      {
        next = hb->next;
        (*func) (hb, arg1, arg2);
      }
}

/* Iterator function for hash entry delete with 3 args  */
void
hash_iterate_delete3 (struct hash *hash,
                      void (*func) (struct hash_backet *, \
                                    void *, void *, void *),
                      void *arg1, void *arg2, void *arg3)
{
  struct hash_backet *next = NULL;
  struct hash_backet *hb = NULL;
  int i;

  for (i = 0; i < hash->size; i++)
    for (hb = hash->index[i]; hb; hb = next)
      {
        next = hb->next;
        (*func) (hb, arg1, arg2, arg3);
      }
}

/* This function takes key and bucket data as input */
void *
hash_set (struct hash *hash, void *data, void *newdata)
{
  u_int32_t key;
  u_int32_t index;
  struct hash_backet *backet;

  if (! data || ! newdata)
    return NULL;

  key = (*hash->hash_key) (data);
  index = key % hash->size;

  for (backet = hash->index[index]; backet != NULL; backet = backet->next)
    if (backet->key == key
        && (*hash->hash_cmp) (backet->data, data) == PAL_TRUE)
      return backet->data;


   backet = XMALLOC (MTYPE_HASH_BUCKET, sizeof (struct hash_backet));
   if (! backet)
     return NULL;

   backet->data = newdata;
   backet->key = key;
   backet->next = hash->index[index];
   hash->index[index] = backet;
   hash->count++;
   return backet->data;
}

u_int32_t
hash_key_make (char *name)
{
  int i, len;
  u_int32_t key;

  if (name)
    {
      key = 0;
      len = pal_strlen (name);
      for (i = 1; i <= len; i++)
        key += (name[i] * i);

      return key;
    }
  return 0;
}
