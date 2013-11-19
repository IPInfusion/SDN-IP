/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_COMMUNITY_H
#define _BGPSDN_BGP_COMMUNITY_H

/* Communities attribute.  */
struct community 
{
  /* Reference count of communities value.  */
  u_int32_t refcnt;

  /* Communities value size.  */
  u_int32_t size;

  /* Communities value.  */
  u_int32_t *val;

  /* String of community attribute.  This string is used by vty output
     and expanded community-list for regular expression match.  */
  u_int8_t *str;
};

/* Community pre-defined values definition. */
#define COMMUNITY_INTERNET              0x0
#define COMMUNITY_NO_EXPORT             0xFFFFFF01
#define COMMUNITY_NO_ADVERTISE          0xFFFFFF02
#define COMMUNITY_NO_EXPORT_SUBCONFED   0xFFFFFF03
#define COMMUNITY_LOCAL_AS              0xFFFFFF03
#define COMMUNITY_G_SHUT                0xFFFF

/* Macros of community attribute. */
#define com_length(X)    ((X)->size * 4)
#define com_lastval(X)   ((X)->val + (X)->size - 1)
#define com_nthval(X,n)  ((X)->val + (n))

/* Prototypes of community attribute functions. */
struct community *
community_new (void);
void
community_init ();
void
community_free (struct community *);
struct community *
community_uniq_sort (struct community *);
struct community *
community_parse (u_char *, u_int16_t);
struct community *
community_intern (struct community *);
void
community_unintern (struct community *);
u_int32_t
community_hash_make (void *);
struct community *
community_str2com (u_int8_t *);
bool_t
community_match (struct community *, struct community *);
bool_t
community_cmp (void *, void *);
struct community *
community_merge (struct community *, struct community *);
struct community *
community_delete (struct community *, struct community *);
struct community *
community_dup (struct community *);
bool_t
community_include (struct community *, u_int32_t);
u_int32_t
community_count (void);
u_int8_t *
community_str (struct community *);
struct hash *
community_hash ();
void
community_del_val (struct community *, u_int32_t *);
void
community_add_val (struct community *com, u_int32_t val);

#endif /* _BGPSDN_BGP_COMMUNITY_H */
