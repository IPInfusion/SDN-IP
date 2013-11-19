/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved. */

#include "pal.h"
#include "memory.h"  

/* Preallocate memory. */
void *
pal_mem_prealloc (size_t size)
{
   void *mem;

   mem = calloc (1, size);
   if (mem)
     return mem;

   return NULL; 
}

/* Initialize memory for memory type. */
int
pal_mem_type_init (enum memory_type type)
{
  return 0;
}

/* Deinitialize memory for memory type. */
int 
pal_mem_type_deinit (enum memory_type type)
{
  return 0;
}

/* Allocate memory. */
void *
pal_mem_malloc (enum memory_type type, size_t size)
{
   void *mem;

   mem = malloc (size);
   if (mem)
     return mem;

   return NULL; 
}

/* Allocate memory and initialize it to zero. */
void *
pal_mem_calloc (enum memory_type type, size_t size)
{
   void *mem;

   mem = calloc (1, size);
   if (mem)
     return mem;

   return NULL; 
}

/* Free memory. */
void
pal_mem_free (enum memory_type type, void *ptr)
{
   free (ptr);

   return;
}

/* Reallocate memory. */
void *
pal_mem_realloc (enum memory_type type, void *ptr, size_t size)
{
  void *mem;

  mem = realloc (ptr, size);
  if (mem)
    return mem;

  return NULL;
}

/* Duplicate string. */
char *
pal_strdup (enum memory_type type, const char *s)
{
  return strdup(s);
}
