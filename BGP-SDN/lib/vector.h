/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_VECTOR_H
#define _BGPSDN_VECTOR_H

/* Vector structure. */
struct _vector
{
  /* Max number of used slot.  */
  u_int32_t max;

  /* Number of allocated slot.  */
  u_int32_t alloced;

  /* Index to data.  */
  void **index;
};

/* Typedef it.  */
typedef struct _vector *vector;

#define VECTOR_MIN_SIZE 8

/* Macros.  */
#define vector_slot(V,I)         ((V)->index[(I)])
#define vector_max(V)            ((V)->max)
#define vector_size(V)           ((V)->alloced)
#define vector_reset(V)          ((V)->max = 0)
#define vector_swap(A,B) \
  do {                   \
    vector _v;           \
    _v = A;              \
    A = B;               \
    B = _v;              \
  } while (0)

#define VECTOR_LOOP(V, D, I)                                          \
  for ((I) = 0; (I) < vector_max (V); (I)++)                          \
    if (((D) = vector_slot ((V), (I))))

/* Prototypes. */
vector vector_init (u_int32_t size);
bool_t vector_ensure (vector v, u_int32_t num);
u_int32_t vector_empty_slot (vector v);
u_int32_t vector_set (vector v, void *val);
u_int32_t vector_set_index (vector v, u_int32_t i, void *val);
void *vector_lookup_index (vector v, u_int32_t i);
void vector_unset (vector v, u_int32_t i);
u_int32_t vector_count (vector v);
void vector_only_wrapper_free (vector v);
void vector_free (vector v);
vector vector_copy (vector v);
void vector_add (vector dest, vector src);
void vector_dup (vector dest, vector src);
u_int32_t vector_cmp(vector v1, vector v2);

typedef ZRESULT (* VECTOR_WALK_CB)(void *val, intptr_t user_ref);
ZRESULT vector_walk(vector v, VECTOR_WALK_CB user_cb, intptr_t user_ref);

#endif /* _BGPSDN_VECTOR_H */
