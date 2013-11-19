/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

struct community *
community_new ()
{
  struct community *new;

  new = XMALLOC (MTYPE_COMMUNITY, sizeof (struct community));
  pal_mem_set (new, 0, sizeof (struct community));
  return new;
}

void
community_free (struct community *com)
{
  if (! com)
    return;

  if (com->val)
    XFREE (MTYPE_COMMUNITY_VAL, com->val);
  if (com->str)
    XFREE (MTYPE_COMMUNITY_STR, com->str);
  XFREE (MTYPE_COMMUNITY, com);
}

/* Add one community value to the community. */
void
community_add_val (struct community *com, u_int32_t val)
{
  com->size++;
  if (com->val)
    com->val = XREALLOC (MTYPE_COMMUNITY_VAL, com->val, com_length (com));
  else
    com->val = XMALLOC (MTYPE_COMMUNITY_VAL, com_length (com));

  val = pal_hton32 (val);
  pal_mem_cpy (com_lastval (com), &val, sizeof (u_int32_t));
}

/* Delete one community. */
void
community_del_val (struct community *com, u_int32_t *val)
{
  int i = 0;
  int c = 0;

  if (! com->val)
    return;

  while (i < com->size)
    {
      if (pal_mem_cmp (com->val + i, val, sizeof (u_int32_t)) == 0)
        {
          c = com->size -i -1;

          if (c > 0)
            pal_mem_cpy (com->val + i, com->val + (i + 1), c * sizeof (u_int32_t));

          com->size--;

          if (com->size > 0)
            com->val = XREALLOC (MTYPE_COMMUNITY_VAL, com->val,
                                 com_length (com));
          else
            {
              XFREE (MTYPE_COMMUNITY_VAL, com->val);
              com->val = NULL;
            }
          return;
        }
      i++;
    }
}

/* Delete all communities listed in com2 from com1 */
struct community *
community_delete (struct community *com1, struct community *com2)
{
  int i = 0;

  while (i < com2->size)
    {
      community_del_val (com1, com2->val + i);
      i++;
    }

  return com1;
}

/* Compare the community value. If a2 presents in a1 return 1 */
int
community_compare (const void *a1, const void *a2)
{
  u_int32_t v1;
  u_int32_t v2;

  pal_mem_cpy (&v1, a1, sizeof (u_int32_t));
  pal_mem_cpy (&v2, a2, sizeof (u_int32_t));
  v1 = pal_ntoh32 (v1);
  v2 = pal_ntoh32 (v2);

  if (v1 < v2)
    return -1;
  if (v1 > v2)
    return 1;
  return 0;
}

bool_t
community_include (struct community *com, u_int32_t val)
{
  int i;

  val = pal_hton32 (val);

  for (i = 0; i < com->size; i++)
    {
      if (pal_mem_cmp (&val, com_nthval (com, i), sizeof (u_int32_t)) == 0)
        return 1;
    }
  return 0;
}

u_int32_t
community_val_get (struct community *com, int i)
{
  u_int8_t *p;
  u_int32_t val;

  p = (u_int8_t *) com->val;
  p += (i * 4);

  pal_mem_cpy (&val, p, sizeof (u_int32_t));

  return pal_ntoh32 (val);
}

/* Sort and uniq given community. */
struct community *
community_uniq_sort (struct community *com)
{
  int i;
  struct community *new;
  u_int32_t val;

  new = community_new ();

  for (i = 0; i < com->size; i++)
    {
      val = community_val_get (com, i);

      if (! community_include (new, val))
        community_add_val (new, val);
    }

  pal_qsort (new->val, new->size, sizeof (u_int32_t), community_compare);

  return new;
}

/* Convert communities attribute to string.

   For Well-known communities value, below keyword is used.

   0x0             "internet"
   0xFFFFFF01      "no-export"
   0xFFFFFF02      "no-advertise"
   0xFFFFFF03      "local-AS"

   For other values, "AS:VAL" format is used.  */
static char *
community_com2str  (struct community *com)
{
  int i;
  char *str;
  char *pnt;
  int len;
  int first;
  u_int32_t comval;
  u_int16_t as;
  u_int16_t val;

  /* When communities attribute is empty.  */
  if (com->size == 0)
    {
      str = XMALLOC (MTYPE_COMMUNITY_STR, 1);
      str[0] = '\0';
      return str;
    }

  /* Memory allocation is time consuming work.  So we calculate
     required string length first.  */
  len = 0;

  for (i = 0; i < com->size; i++)
    {
      pal_mem_cpy (&comval, com_nthval (com, i), sizeof (u_int32_t));
      comval = pal_ntoh32 (comval);

      switch (comval)
        {
        case COMMUNITY_INTERNET:
          len += pal_strlen (" internet");
          break;
        case COMMUNITY_NO_EXPORT:
          len += pal_strlen (" no-export");
          break;
        case COMMUNITY_NO_ADVERTISE:
          len += pal_strlen (" no-advertise");
          break;
        case COMMUNITY_LOCAL_AS:
          len += pal_strlen (" local-AS");
          break;
        default:
          len += pal_strlen (" 65536:65535");
          break;
        }
    }

  /* Allocate memory.  */
  str = pnt = XMALLOC (MTYPE_COMMUNITY_STR, len);
  first = 1;

  /* Fill in string.  */
  for (i = 0; i < com->size; i++)
    {
      pal_mem_cpy (&comval, com_nthval (com, i), sizeof (u_int32_t));
      comval = pal_ntoh32 (comval);

      if (first)
        first = 0;
      else
        *pnt++ = ' ';

      switch (comval)
        {
        case COMMUNITY_INTERNET:
          pal_strcpy (pnt, "internet");
          pnt += pal_strlen ("internet");
          break;
        case COMMUNITY_NO_EXPORT:
          pal_strcpy (pnt, "no-export");
          pnt += pal_strlen ("no-export");
          break;
        case COMMUNITY_NO_ADVERTISE:
          pal_strcpy (pnt, "no-advertise");
          pnt += pal_strlen ("no-advertise");
          break;
        case COMMUNITY_LOCAL_AS:
          pal_strcpy (pnt, "local-AS");
          pnt += pal_strlen ("local-AS");
          break;
        default:
          as = (comval >> 16) & 0xFFFF;
          val = comval & 0xFFFF;
          pal_snprintf (pnt, (str+len) - pnt,"%d:%d", as, val);
          pnt += pal_strlen (pnt);
          break;
        }
    }
  *pnt = '\0';

  return str;
}

/* Intern communities attribute.  */
struct community *
community_intern (struct community *com)
{
  struct community *find;

  /* Assert this community structure is not interned. */
  pal_assert (com->refcnt == 0);

  /* Lookup community hash. */
  find = (struct community *) hash_get (bgp_comhash_tab, com, hash_alloc_intern);

  /* Arguemnt com is allocated temporary.  So when it is not used in
     hash, it should be freed.  */
  if (find != com)
    community_free (com);

  /* Increment refrence counter.  */
  find->refcnt++;

  /* Make string.  */
  if (! find->str)
    find->str = community_com2str (find);

  return find;
}

/* Free community attribute. */
void
community_unintern (struct community *com)
{
  if (com->refcnt)
    com->refcnt--;

  if (com->refcnt == 0)
    {
      struct community *ret;

      /* Community value com must exist in hash. */
      ret = (struct community *) hash_release (bgp_comhash_tab, com);
      pal_assert (ret != NULL);

      community_free (com);
    }
}


/* Create new community attribute. */
struct community *
community_parse (u_int8_t *pnt, unsigned short length)
{
  struct community tmp;
  struct community *new;

  /* If length is malformed return NULL. */
  if (length % 4)
    return NULL;

  /* Make temporary community for hash look up. */
  tmp.size = length / 4;
  tmp.val = (u_int32_t *) pnt;

  new = community_uniq_sort (&tmp);

  return community_intern (new);
}

struct community *
community_dup (struct community *com)
{
  struct community *new;

  new = XMALLOC (MTYPE_COMMUNITY, sizeof (struct community));
  pal_mem_set (new, 0, sizeof (struct community));
  new->size = com->size;
  if (new->size)
    {
      new->val = XMALLOC (MTYPE_COMMUNITY_VAL, com->size * 4);
      pal_mem_cpy (new->val, com->val, com->size * 4);
    }
  else
    new->val = NULL;
  return new;
}

/* Retrun string representation of communities attribute. */
u_int8_t *
community_str (struct community *com)
{
  if (! com->str)
    com->str = community_com2str (com);
  return com->str;
}

/* Make hash value of community attribute. This function is used by
   hash package.*/
u_int32_t
community_hash_make (void *arg)
{
  struct community *com;
  u_int8_t  *pnt;
  u_int32_t key;
  u_int32_t c;

  com = (struct community *) arg;
  pnt = (u_int8_t *)com->val;
  key = 0;

  for(c = 0; c < com->size * 4; c++)
    key += pnt[c];

  return key;
}

bool_t
community_match (struct community *com1, struct community *com2)
{
  int i = 0;
  int j = 0;

  if (com1 == NULL && com2 == NULL)
    return 1;

  if (com1 == NULL || com2 == NULL)
    return 0;

  if (com1->size < com2->size)
    return 0;

  /* Every community on com2 needs to be on com1 for this to match */
  while (i < com1->size && j < com2->size)
    {
      if (pal_mem_cmp (com1->val + i, com2->val + j, sizeof (u_int32_t)) == 0)
        j++;
      i++;
    }

  if (j == com2->size)
    return 1;
  else
    return 0;
}

/* If two community have same value then return 1 else return 0. */ 
bool_t
community_cmp (void *arg1, void *arg2)
{
  struct community *com1;
  struct community *com2;

  com1 = (struct community *) arg1;
  com2 = (struct community *) arg2;

  if (com1 == NULL && com2 == NULL)
    return 1;
  if (com1 == NULL || com2 == NULL)
    return 0;

  if (com1->size == com2->size)
    if (pal_mem_cmp (com1->val, com2->val, com1->size * 4) == 0)
      return 1;
  return 0;
}

/* Add com2 to the end of com1. */
struct community *
community_merge (struct community *com1, struct community *com2)
{
  if (com1->val)
    com1->val = XREALLOC (MTYPE_COMMUNITY_VAL, com1->val,
                          (com1->size + com2->size) * 4);
  else
    com1->val = XMALLOC (MTYPE_COMMUNITY_VAL, (com1->size + com2->size) * 4);

  pal_mem_cpy (com1->val + com1->size, com2->val, com2->size * 4);
  com1->size += com2->size;

  return com1;
}

/* Community token enum. */
enum community_token
{
  community_token_val,
  community_token_no_export,
  community_token_no_advertise,
  community_token_local_as,
  community_token_unknown
};

/* Get next community token from string. */
char *
community_gettoken (char *buf, enum community_token *token, u_int32_t *val)
{
  char *p = buf;

  /* Skip white space. */
  while (pal_char_isspace ((int) *p))
    p++;

  /* Check the end of the line. */
  if (*p == '\0')
    return NULL;

  /* Well known community string check. */
  if (pal_char_isalpha ((int) *p))
    {
      if (pal_strncmp (p, "internet", pal_strlen ("internet")) == 0)
        {
          *val = COMMUNITY_INTERNET;
          *token = community_token_no_export;
          p += pal_strlen ("internet");
          return p;
        }
      if (pal_strncmp (p, "no-export", pal_strlen ("no-export")) == 0)
        {
          *val = COMMUNITY_NO_EXPORT;
          *token = community_token_no_export;
          p += pal_strlen ("no-export");
          return p;
        }
      if (pal_strncmp (p, "no-advertise", pal_strlen ("no-advertise")) == 0)
        {
          *val = COMMUNITY_NO_ADVERTISE;
          *token = community_token_no_advertise;
          p += pal_strlen ("no-advertise");
          return p;
        }
      if (pal_strncmp (p, "local-AS", pal_strlen ("local-AS")) == 0)
        {
          *val = COMMUNITY_LOCAL_AS;
          *token = community_token_local_as;
          p += pal_strlen ("local-AS");
          return p;
        }

      /* Unknown string. */
      *token = community_token_unknown;
      return p;
    }

  /* Community value. */
  if (pal_char_isdigit ((int) *p))
    {
      int separator = 0;
      int digit = 0;
      u_int32_t community_low = 0;
      u_int32_t community_high = 0;

      while (pal_char_isdigit ((int) *p) || *p == ':')
        {
          if (*p == ':')
            {
              if (separator)
                {
                  *token = community_token_unknown;
                  return p;
                }
              else
                {
                  separator = 1;
                  digit = 0;

                  if (community_low > BGP_AS_MAX || community_low < BGP_AS_MIN)
                    {
                      *token = community_token_unknown;
                      return p;
                    }

                  community_high = community_low << 16;
                  community_low = 0;
                }
            }
          else
            {
              digit = 1;
              community_low *= 10;
              community_low += (*p - '0');
            }
          p++;
        }

      if (! digit)
        {
          *token = community_token_unknown;
          return p;
        }

      if (community_low > BGP_AS_MAX || community_low < BGP_AS_MIN)
        {
          *token = community_token_unknown;
          return p;
        }

      *val = community_high + community_low;
      *token = community_token_val;
      return p;
    }

  *token = community_token_unknown;
  return p;
}

/* convert string to community structure */
struct community *
community_str2com (u_int8_t *str)
{
  struct community *com = NULL;
  struct community *com_sort = NULL;
  enum community_token token;
  u_int32_t val;

  while ((str = community_gettoken (str, &token, &val)))
    {
      switch (token)
        {
        case community_token_val:
        case community_token_no_export:
        case community_token_no_advertise:
        case community_token_local_as:
          if (com == NULL)
            com = community_new();
          community_add_val (com, val);
          break;
        case community_token_unknown:
        default:
          if (com)
            community_free (com);
          return NULL;
          break;
        }
    }

  if (! com)
    return NULL;

  com_sort = community_uniq_sort (com);
  community_free (com);

  return com_sort;
}

u_int32_t
community_count (void)
{
  return bgp_comhash_tab->count;
}

/* Return communities hash.  */
struct hash *
community_hash (void)
{
  return bgp_comhash_tab;
}


/* Initialize comminity related hash. */
void
community_init ()
{
  bgp_comhash_tab = hash_create (community_hash_make, community_cmp);
}
