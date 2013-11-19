/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

struct aspath *
aspath_new ()
{
  struct aspath *aspath;

  aspath = XCALLOC (MTYPE_AS_PATH, sizeof (struct aspath));
  return aspath;
}

/* Free AS path structure. */
void
aspath_free (struct aspath *aspath)
{
  if (!aspath)
    return;
  if (aspath->data)
    XFREE (MTYPE_AS_SEG, aspath->data);
  if (aspath->str)
    XFREE (MTYPE_AS_STR, aspath->str);
  XFREE (MTYPE_AS_PATH, aspath);
}

/* Unintern aspath from AS path bucket. */
void
aspath_unintern (struct aspath *aspath)
{
  struct aspath *ret;

  if (aspath->refcnt)
    aspath->refcnt--;

  if (aspath->refcnt == 0)
    {

      /* This aspath must exist in aspath hash table. */
      ret = hash_release (bgp_ashash_tab, aspath);
 
      pal_assert (ret != NULL);
      aspath_free (aspath);
    }
}

/* Return the start or end delimiters for a particular Segment type */
static char
aspath_delimiter_char (u_int8_t type, u_int8_t which)
{
  int i;
  struct
  {
    int type;
    char start;
    char end;
  } aspath_delim_char [] =
    {
      { BGP_AS_SET,             '{', '}' },
      { BGP_AS_SEQUENCE,        ' ', ' ' },
      { BGP_AS_CONFED_SET,      '[', ']' },
      { BGP_AS_CONFED_SEQUENCE, '(', ')' },
      { 0 }
    };

  for (i = 0; aspath_delim_char[i].type != 0; i++)
    {
      if (aspath_delim_char[i].type == type)
        {
          if (which == AS_SEG_START)
            return aspath_delim_char[i].start;
          else if (which == AS_SEG_END)
            return aspath_delim_char[i].end;
        }
    }
  return ' ';
}

/* Convert aspath structure to string expression. */
char *
aspath_make_str_count (struct aspath *as)
{
  int space;
  u_int8_t type;
  u_int8_t *pnt;
  u_int8_t *end;
  struct assegment *assegment;
  int str_size = BGP_ASPATH_STR_DEFAULT_LEN;
  int str_pnt;
  char *str_buf;
  u_int16_t count = 0;
  u_int16_t count_confed = 0;

  /* Empty aspath. */
  if (as->length == 0)
    {
      str_buf = XCALLOC (MTYPE_AS_STR, 1);
      str_buf[0] = '\0';
      as->count = 0;
      as->count_confed = 0;
      return str_buf;
    }

  /* Set default value. */
  space = 0;
  type = BGP_AS_SEQUENCE;

  /* Set initial pointer. */
  pnt = as->data;
  end = pnt + as->length;

  str_buf = XCALLOC (MTYPE_AS_STR, str_size);
  str_pnt = 0;

  assegment = (struct assegment *) pnt;

  while (pnt < end)
    {
      int i;
      int estimate_len;

      /* For fetch value. */
      assegment = (struct assegment *) pnt;

      /* Check AS type validity. */
      if ((assegment->type != BGP_AS_SET) &&
          (assegment->type != BGP_AS_SEQUENCE) &&
          (assegment->type != BGP_AS_CONFED_SET) &&
          (assegment->type != BGP_AS_CONFED_SEQUENCE))
        {
          XFREE (MTYPE_AS_STR, str_buf);
          return NULL;
        }

      /* Check AS length. */
      if ((pnt + (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE) > end)
        {
          XFREE (MTYPE_AS_STR, str_buf);
          return NULL;
        }

      /* Buffer length check. */
      estimate_len = ((assegment->length * 6) + 4);

      /* String length check. */
      while (str_pnt + estimate_len >= str_size)
        {
          str_size *= 2;
          str_buf = XREALLOC (MTYPE_AS_STR, str_buf, str_size);
        }

      /* If assegment type is changed, print previous type's end
         character. */
      if (type != BGP_AS_SEQUENCE)
        str_buf[str_pnt++] = aspath_delimiter_char (type, AS_SEG_END);
      if (space)
        str_buf[str_pnt++] = ' ';

      if (assegment->type != BGP_AS_SEQUENCE)
        str_buf[str_pnt++] = aspath_delimiter_char (assegment->type, AS_SEG_START);

      space = 0;

      /* Increment count.  */
      switch (assegment->type)
        {
        case BGP_AS_SEQUENCE:
          count += assegment->length;
          break;
        case BGP_AS_SET:
          count++;
          break;
        case BGP_AS_CONFED_SEQUENCE:
          count_confed += assegment->length;
          break;
        case BGP_AS_CONFED_SET:
          count_confed++;
          break;
        default:
          break;
        }

      for (i = 0; i < assegment->length; i++)
        {
          int len;

          if (space)
            {
              if (assegment->type == BGP_AS_SET
                  || assegment->type == BGP_AS_CONFED_SET)
                str_buf[str_pnt++] = ',';
              else
                str_buf[str_pnt++] = ' ';
            }
          else
            space = 1;

          len = pal_snprintf (str_buf + str_pnt, str_size - str_pnt,
                               "%d", pal_ntoh16 (assegment->asval[i]));
          str_pnt += len;
        }

      type = assegment->type;
      pnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }

  if (assegment->type != BGP_AS_SEQUENCE)
    str_buf[str_pnt++] = aspath_delimiter_char (assegment->type, AS_SEG_END);

  str_buf[str_pnt] = '\0';

  as->count = count;
  as->count_confed = count + count_confed;

  return str_buf;
}

/* Intern allocated AS path. */
struct aspath *
aspath_intern (struct aspath *aspath)
{
  struct aspath *find;

  /* Assert this AS path structure is not interned. */
  pal_assert ( aspath->refcnt == 0);
  pal_assert (! aspath->str);

  /* Check AS path hash. */
  find = hash_get (bgp_ashash_tab, aspath, hash_alloc_intern);

  if (find != aspath)
    aspath_free (aspath);

  find->refcnt++;

  if (! find->str)
    find->str = aspath_make_str_count (find);

  return find;
}

/* Duplicate aspath structure.  Created same aspath structure but
   reference count and AS path string is cleared. */
struct aspath *
aspath_dup (struct aspath *aspath)
{
  struct aspath *new;

  new = XCALLOC (MTYPE_AS_PATH, sizeof (struct aspath));

  new->length = aspath->length;

  if (new->length)
    {
      new->data = XCALLOC (MTYPE_AS_SEG, aspath->length);
      pal_mem_cpy (new->data, aspath->data, aspath->length);
    }
  else
    new->data = NULL;

  /* new->str = aspath_make_str_count (aspath); */

  return new;
}

struct aspath *
aspath_new_or_dup (struct aspath *existing)
{
  struct aspath *new;

  if (existing)
     new = aspath_dup (existing);
  else
     new = aspath_new();

  return (new);
}


void *
aspath_hash_alloc (void *arg)
{
  struct aspath *aspath_in;
  struct aspath *aspath;

  aspath_in = (struct aspath *) arg;

  /* New aspath strucutre is needed. */
  aspath = XCALLOC (MTYPE_AS_PATH, sizeof (struct aspath));
  pal_mem_set ((void *) aspath, 0, sizeof (struct aspath));
  aspath->length = aspath_in->length;

  /* In case of IBGP connection aspath's length can be zero. */
  if (aspath_in->length)
    {
      aspath->data = XCALLOC (MTYPE_AS_SEG, aspath_in->length);
      pal_mem_cpy (aspath->data, aspath_in->data, aspath_in->length);
    }
  else
    aspath->data = NULL;

  /* Make AS path string. */
  aspath->str = aspath_make_str_count (aspath);

  /* Malformed AS path value. */
  if (! aspath->str)
    {
      aspath_free (aspath);
      return NULL;
    }

  return (void *) aspath;
}

/* AS path parse function.  pnt is a pointer to byte stream and length
   is length of byte stream.  If there is same AS path in the the AS
   path hash then return it else make new AS path structure. */
struct aspath *
aspath_parse (u_int8_t *pnt, int length, struct bgp_peer *peer)
{
  struct aspath as, *tmp_as;
  struct aspath *find;

  /* If length is odd it's malformed AS path. */
  if (length % 2)
    return NULL;

  /* pnt is a pointer to byte stream. length is length of byte stream. */
  as.data = pnt;               
  as.length = length;          

  /*
   * If this AS path was received from a peer with whom we have 
   * a configured Local-AS that AS must be prepended to the AS path
   * as if the message had passed through that AS. Otherwise, simply
   * look for the received AS path. In both cases, if the AS path is
   * not present in the hash table it will be created. 
   */
  if (peer && CHECK_FLAG (peer->config, PEER_FLAG_LOCAL_AS))
    {
      tmp_as = aspath_dup(&as);
      tmp_as = aspath_add_seq (tmp_as, peer->local_as);
      find = hash_get (bgp_ashash_tab, tmp_as, aspath_hash_alloc);
      aspath_free(tmp_as);
    }
  else 
    {
      find = hash_get (bgp_ashash_tab, &as, aspath_hash_alloc);
    }

  /* If already same aspath exist then return it. */
  if (! find)
    return NULL;
  find->refcnt++;

  return find;
}

struct aspath *
aspath_aggregate_segment_copy (struct aspath *aspath, struct assegment *seg,
                               int i)
{
  struct assegment *newseg;

  if (! aspath->data)
    {
      aspath->data = XCALLOC (MTYPE_AS_SEG, ASSEGMENT_SIZE (i));
      newseg = (struct assegment *) aspath->data;
      aspath->length = ASSEGMENT_SIZE (i);
    }
  else
    {
      aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data,
                               aspath->length + ASSEGMENT_SIZE (i));
      newseg = (struct assegment *) (aspath->data + aspath->length);
      aspath->length += ASSEGMENT_SIZE (i);
    }

  newseg->type = seg->type;
  newseg->length = i;
  pal_mem_cpy (newseg->asval, seg->asval, (i * AS_VALUE_SIZE));

  return aspath;
}

struct assegment *
aspath_aggregate_as_set_add (struct aspath *aspath, struct assegment *asset,
                             u_int16_t as, u_int8_t type)
{
  struct assegment *seg;
  int i;

  /* If this is first AS set member, create new as-set segment. */
  if (asset == NULL)
    {
      if (! aspath->data)
        {
          aspath->data = XCALLOC (MTYPE_AS_SEG,
                                  ASSEGMENT_SIZE (ASSEGMENT_LEN_MIN));
          asset = (struct assegment *) aspath->data;
          aspath->length = ASSEGMENT_SIZE (ASSEGMENT_LEN_MIN);
        }
      else
        {
          aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data,
                                   aspath->length
                                   + ASSEGMENT_SIZE (ASSEGMENT_LEN_MIN));
          asset = (struct assegment *) (aspath->data + aspath->length);
          aspath->length += ASSEGMENT_SIZE (ASSEGMENT_LEN_MIN);
        }
      asset->type = type;
      asset->length = ASSEGMENT_LEN_MIN;
      asset->asval[0] = as;
    }
  else
    {
      size_t offset;

      /* Check this AS value already exists or not. */
      for (i = 0; i < asset->length; i++)
        if (asset->asval[i] == as)
          return asset;

      offset = (u_int8_t *) asset - (u_int8_t *) aspath->data;

      if (asset->length < ASSEGMENT_LEN_MAX)
        {
          aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data,
                                   aspath->length + AS_VALUE_SIZE);

          asset = (struct assegment *) (aspath->data + offset);
          aspath->length += AS_VALUE_SIZE;
          asset->asval[asset->length] = as;
          asset->length++;
        }
      else
        {
          aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data,
                                   aspath->length
                                   + ASSEGMENT_SIZE (ASSEGMENT_LEN_MIN));
          asset = (struct assegment *) (aspath->data + offset);
          seg = (struct assegment *) (aspath->data + offset + aspath->length);
          aspath->length += ASSEGMENT_SIZE (ASSEGMENT_LEN_MIN);
          seg->asval[0] = as;
          seg->type = type;
          seg->length = ASSEGMENT_LEN_MIN;
        }
    }

  return asset;
}

/* Modify as1 using as2 for aggregation. */
struct aspath *
aspath_aggregate (struct aspath *as1, struct aspath *as2,
                  u_int8_t asset_type)
{
  int i;
  int minlen;
  int match;
  int match1;
  int match2;
  u_int8_t *cp1;
  u_int8_t *cp2;
  u_int8_t *end1;
  u_int8_t *end2;
  u_int8_t type, type_other;
  struct assegment *seg1;
  struct assegment *seg2;
  struct aspath *aspath;
  struct assegment *asset1, *asset2;

  match = 0;
  minlen = 0;
  aspath = NULL;
  asset1 = NULL;
  asset2 = NULL;
  cp1 = as1->data;
  end1 = as1->data + as1->length;
  cp2 = as2->data;
  end2 = as2->data + as2->length;

  seg1 = (struct assegment *) cp1;
  seg2 = (struct assegment *) cp2;

  /* First of all check common leading sequence. */
  while ((cp1 < end1) && (cp2 < end2))
    {
      /* Check segment type. */
      if (seg1->type != seg2->type)
        break;

      /* Minimum segment length. */
      minlen = BGP_MIN (seg1->length, seg2->length);

      for (match = 0; match < minlen; match++)
        if (seg1->asval[match] != seg2->asval[match])
          break;

      if (match)
        {
          if (! aspath)
            aspath = aspath_new();
          aspath = aspath_aggregate_segment_copy (aspath, seg1, match);
        }

      if (match != minlen || match != seg1->length
          || seg1->length != seg2->length)
        break;

      cp1 += ((seg1->length * AS_VALUE_SIZE) + AS_HEADER_SIZE);
      cp2 += ((seg2->length * AS_VALUE_SIZE) + AS_HEADER_SIZE);

      seg1 = (struct assegment *) cp1;
      seg2 = (struct assegment *) cp2;

      match = 0;
    }

  if (! aspath)
    aspath = aspath_new();

  if (asset_type == BGP_AS_SET)
    {
      type = BGP_AS_SEQUENCE;
      type_other = BGP_AS_CONFED_SET;
    }
  else if (asset_type == BGP_AS_CONFED_SET)
    {
      type =  BGP_AS_CONFED_SET;
      type_other = BGP_AS_SET;
    }
  else
    {
      type = BGP_AS_CONFED_SEQUENCE;
      type_other = BGP_AS_SET;
    }

  /* Make as-set using rest of all information. */
  match1 = match;
  while (cp1 < end1)
    {
      seg1 = (struct assegment *) cp1;

      if (seg1->type == asset_type || seg1->type == type)
        for (i = match1; i < seg1->length; i++)
          asset1 = aspath_aggregate_as_set_add (aspath, asset1, seg1->asval[i],
                                                asset_type);
      else
        for (i = match1; i < seg1->length; i++)
          asset2 = aspath_aggregate_as_set_add (aspath, asset2, seg1->asval[i],
                                                type_other);

      match1 = 0;
      cp1 += ((seg1->length * AS_VALUE_SIZE) + AS_HEADER_SIZE);
    }

  match2 = match;
  while (cp2 < end2)
    {
      seg2 = (struct assegment *) cp2;

      if (seg2->type == asset_type || seg2->type == type)
      for (i = match2; i < seg2->length; i++)
        asset1 = aspath_aggregate_as_set_add (aspath, asset1, seg2->asval[i],
                                              asset_type);
      else
      for (i = match2; i < seg2->length; i++)
        asset2 = aspath_aggregate_as_set_add (aspath, asset2, seg2->asval[i],
                                              type_other);

      match2 = 0;
      cp2 += ((seg2->length * AS_VALUE_SIZE) + AS_HEADER_SIZE);
    }


  return aspath;
}

/* When a BGP router receives an UPDATE with an MP_REACH_NLRI
   attribute, check the leftmost AS number in the AS_PATH attribute is
   or not the peer's AS number. */
int
aspath_firstas_check (struct aspath *aspath, u_int16_t asno)
{
  u_int8_t *pnt;
  struct assegment *assegment;

  if (aspath == NULL)
    return BGP_ASPATH_RET_FAILURE;

  pnt = aspath->data;
  assegment = (struct assegment *) pnt;

  if (assegment
      && assegment->type == BGP_AS_SEQUENCE
      && assegment->asval[0] == pal_hton16 (asno))
    return BGP_ASPATH_RET_ASSEQUENCE;
/* RFC 4271,  Aggregation section 9.2.2.2
   If the aggregated route has an AS_SET as the first element in its
   AS_PATH attribute, then the router that originates the route SHOULD
   NOT advertise the MULTI_EXIT_DISC attribute with this route. */
  else if (assegment
          && assegment->type == BGP_AS_SET)
    return BGP_ASPATH_RET_ASSET;

  return BGP_ASPATH_RET_FAILURE;
}

/* Return 1 if 'aspath' contains segment(s) of type BGP_AS_CONFED_SET
   or AS_CONFED_SEQ */
int
aspath_confed_seg_check (struct aspath *aspath)
{
  u_int8_t *pnt;
  u_int8_t *end;
  struct assegment *assegment;

  if (aspath == NULL)
    return 0;

  pnt = aspath->data;
  end = aspath->data + aspath->length;

  while (pnt < end)
    {
      assegment = (struct assegment *) pnt;

      if (assegment->type == BGP_AS_CONFED_SEQUENCE
          || assegment->type == BGP_AS_CONFED_SET)
          return 1;

      pnt += ASSEGMENT_SIZE(assegment->length);
    }

  return 0;
}

/* Return 1 if 'aspath' contains segment(s) of type BGP_AS_CONFED_SET
   or AS_CONFED_SEQ as the first AS SEGMENT */
int
aspath_confed_first_seg_check (struct aspath *aspath)
{
  u_int8_t *pnt;
  struct assegment *assegment;

  if (aspath == NULL || aspath->length == 0)
    return 1;

  pnt = aspath->data;

  assegment = (struct assegment *) pnt;

  if (assegment->type == BGP_AS_CONFED_SEQUENCE
      || assegment->type == BGP_AS_CONFED_SET)
    return 1;
  else
    return 0;
}

/* AS path loop check.  If aspath contains asno then return 1. */
int
aspath_loop_check (struct aspath *aspath, u_int16_t asno)
{
  u_int8_t *pnt;
  u_int8_t *end;
  struct assegment *assegment;
  int count = 0;

  if (aspath == NULL)
    return 0;

  pnt = aspath->data;
  end = aspath->data + aspath->length;

  while (pnt < end)
    {
      int i;
      assegment = (struct assegment *) pnt;

      for (i = 0; i < assegment->length; i++)
        if (assegment->asval[i] == pal_hton16 (asno))
          count++;

      pnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }
  return count;
}

/* When all of AS path is private AS return 1.  */
int
aspath_private_as_check (struct aspath *aspath)
{
  struct assegment *assegment;
  s_int32_t tmp_asval;
  u_int8_t *pnt;
  u_int8_t *end;

  if (aspath == NULL)
    return 0;

  if (aspath->length == 0)
    return 0;

  pnt = aspath->data;
  end = aspath->data + aspath->length;

  while (pnt < end)
    {
      int i;
      assegment = (struct assegment *) pnt;

      for (i = 0; i < assegment->length; i++)
        {
          tmp_asval = (s_int32_t) pal_ntoh16 (assegment->asval[i]);

          if (tmp_asval < BGP_PRIVATE_AS_MIN
              || tmp_asval > BGP_PRIVATE_AS_MAX)
            return 0;
        }
      pnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }
  return 1;
}

/* When all of AS path is in range <1-65535> return 1.  */
int
aspath_as_value_check (struct aspath *aspath)
{
  struct assegment *assegment;
  s_int32_t tmp_asval;
  u_int8_t *pnt;
  u_int8_t *end;

  if (aspath == NULL)
    return 0;

  if (aspath->length == 0)
    return 0;

  pnt = aspath->data;
  end = aspath->data + aspath->length;

  while (pnt < end)
    {
      int i;
      assegment = (struct assegment *) pnt;
      for (i = 0; i < assegment->length; i++)
        {
          tmp_asval = (s_int32_t) pal_ntoh16 (assegment->asval[i]);
          if (tmp_asval < BGP_AS_MIN || tmp_asval > BGP_AS_MAX)
            return 0;
        }
      pnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }
    return 1;
}
#ifdef HAVE_EXT_CAP_ASN
/* Returns the Number of  AS_TRANS in AS Path.  */
int
aspath_as_value_astrans_check (struct aspath *aspath)
{
  struct assegment *assegment;
  s_int32_t tmp_asval;
  u_int8_t *pnt;
  u_int8_t *end;
  int astranscount;
  

  if (aspath == NULL)
    return 0;

  if (aspath->length == 0)
    return 0;

  pnt = aspath->data;
  end = aspath->data + aspath->length;
  astranscount = 0;

  while (pnt < end)
    {
      int i;
      assegment = (struct assegment *) pnt;
      for (i = 0; i < assegment->length; i++)
        {
          tmp_asval = (s_int32_t) pal_ntoh16 (assegment->asval[i]);
          if (tmp_asval == BGP_AS_TRANS)
            astranscount++;
        }
      pnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }
    return astranscount;
}

/* Return the number of entries in the aspath */
int
aspath_as_count (struct aspath *aspath)
{
  struct assegment *assegment;
  s_int32_t tmp_asval;
  u_int8_t *pnt;
  u_int8_t *end;
  int ascount;


  if (aspath == NULL)
    return 0;

  if (aspath->length == 0)
    return 0;

  pnt = aspath->data;
  end = aspath->data + aspath->length;
  ascount = 0;

  while (pnt < end)
    {
 
      int i;
      assegment = (struct assegment *) pnt;
      for (i = 0; i < assegment->length; i++)
        {
          tmp_asval = (s_int32_t) pal_ntoh16 (assegment->asval[i]);
          if (tmp_asval < BGP_AS_MIN || tmp_asval > BGP_AS_MAX)
            return 0;
          else
            ascount++;           
        }
      pnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }
    return ascount;
}
#endif /* HAVE_EXT_CAP_ASN */

/* Merge as1 to as2.  as2 should be uninterned aspath. */
struct aspath *
aspath_merge (struct aspath *as1, struct aspath *as2)
{
  u_int8_t *data;

  if (! as1 || ! as2)
    return NULL;

  data = XCALLOC (MTYPE_AS_SEG, as1->length + as2->length);
  pal_mem_cpy (data, as1->data, as1->length);
  pal_mem_cpy (data + as1->length, as2->data, as2->length);

  XFREE (MTYPE_AS_SEG, as2->data);
  as2->data = data;
  as2->length += as1->length;
  as2->count += as1->count;
  return as2;
}

/* Prepend as1 to as2.  as2 should be uninterned aspath. */
struct aspath *
aspath_prepend (struct aspath *as1, struct aspath *as2)
{
  u_int8_t *pnt;
  u_int8_t *end;
  int segment_length = 0; 
  struct assegment *seg1 = NULL;
  struct assegment *seg2 = NULL;

  if (! as1 || ! as2)
    return NULL;

  seg2 = (struct assegment *) as2->data;

  /* In case of as2 is empty AS. */
  if (seg2 == NULL)
    {
      as2->length = as1->length;
      as2->data = XCALLOC (MTYPE_AS_SEG, as1->length);
      as2->count = as1->count;
      pal_mem_cpy (as2->data, as1->data, as1->length);
      return as2;
    }

  /* assegment points last segment of as1. */
  pnt = as1->data;
  end = as1->data + as1->length;
  while (pnt < end)
    {
      seg1 = (struct assegment *) pnt;
      pnt += (seg1->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }

  /* In case of as1 is empty AS. */
  if (seg1 == NULL)
    return as2;

  /* Compare last segment type of as1 and first segment type of as2. */
  if (seg1->type != seg2->type)
    return aspath_merge (as1, as2);

  if (seg1->type == BGP_AS_SEQUENCE)
    {
      u_int8_t *newdata;
      struct assegment *seg = NULL;

      segment_length = seg1->length + seg2->length; 

      if ( segment_length <= ASSEGMENT_LEN_MAX)  
        {
          newdata = XCALLOC (MTYPE_AS_SEG,
                             as1->length + as2->length - AS_HEADER_SIZE);
          pal_mem_cpy (newdata, as1->data, as1->length);
          seg = (struct assegment *) (newdata + ((u_int8_t *)seg1 - as1->data));
          seg->length += seg2->length;
          pal_mem_cpy (newdata + as1->length, as2->data + AS_HEADER_SIZE,
                       as2->length - AS_HEADER_SIZE);

          XFREE (MTYPE_AS_SEG, as2->data);
          as2->data = newdata;
          as2->length += (as1->length - AS_HEADER_SIZE);
          as2->count += as1->count;

          return as2;
        }
      /* If the segment length is greater than 255, create a new segment 
       * and update the extra elements into the new segment and append the 
       * remaining elements.
       */ 
      else  
        {
          int i;
          int diff = 0;
          unsigned int tmp_asval = 0;
          struct assegment *segment1 = NULL;
          struct assegment *newsegment1 = NULL;
          struct assegment *newsegment2 = NULL;
          
          newdata = XCALLOC (MTYPE_AS_SEG, as1->length + as2->length);

          diff = segment_length - ASSEGMENT_LEN_MAX;
           
          /* Update the newsegment with the type, length and data. */
          newsegment1 = (struct assegment *) newdata;
          newsegment1->type = BGP_AS_SEQUENCE;
          newsegment1->length = diff; 
          
          segment1 = (struct assegment *) as1->data;
          
	  /* Copy the segment1 (as1->data) into the newsegment, this newsegment
           * contains only the diff number of elements and these elements are
           * from as1.
	   */
          for (i = 0; i < diff; i++) 
            {
              tmp_asval = pal_ntoh16 (segment1->asval[i]);
              newsegment1->asval[i] = pal_hton16 (tmp_asval);
            }
          
          newsegment2 = (struct assegment *) (newdata + 
                                   (AS_HEADER_SIZE + (diff * AS_VALUE_SIZE)));

          /* Fill the second header*/
          newsegment2->type = BGP_AS_SEQUENCE;
          newsegment2->length = ASSEGMENT_LEN_MAX;

	  /* Copy the remaining data present in the as1->data
           * to new data. Here since AS_HEADER is made in the above
           * step no need to copy the header again, so moving the pointer
           * of as1->data to the exact point from where the ASN values
           * need to copied to newdata. 
	   */
	  pal_mem_cpy (newdata + AS_HEADER_SIZE + 
                         (AS_VALUE_SIZE * diff) + AS_HEADER_SIZE,
                       as1->data + AS_HEADER_SIZE + (AS_VALUE_SIZE * diff),
                       as1->length - AS_HEADER_SIZE - (AS_VALUE_SIZE * diff));

       	  /* Now copy the data present in as2 to newdata.
           * Here the AS_HEADER of as2 data need not be copied as
           * the AS_HEADER has already been made in the above step.
           * So just copy the data after the AS_HEADER in as2->data. 
	   */
          pal_mem_cpy (newdata + AS_HEADER_SIZE + as1->length , 
		       as2->data + AS_HEADER_SIZE,
                       as2->length - AS_HEADER_SIZE);

          XFREE (MTYPE_AS_SEG, as2->data);
          as2->data = newdata;
          as2->length += as1->length; 
          as2->count += as1->count; 
     
          return as2;
        }
    }
  else
    {
      /* BGP_AS_SET merge code is needed at here. */
      return aspath_merge (as1, as2);
    }

  /* Not reached */
}

/* Add specified AS to the leftmost of aspath. */
static struct aspath *
aspath_add_one_as (struct aspath *aspath, u_int16_t asno, u_int8_t type)
{

  struct assegment *assegment;

  assegment = (struct assegment *) aspath->data;

  /* In case of empty aspath. */
  if (assegment == NULL || assegment->length == 0)
    {
      aspath->length = AS_HEADER_SIZE + AS_VALUE_SIZE;

      if (assegment)
        aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data, aspath->length);
      else
        aspath->data = XCALLOC (MTYPE_AS_SEG, aspath->length);

      assegment = (struct assegment *) aspath->data;
      assegment->type = type;
      assegment->length = 1;
      assegment->asval[0] = pal_hton16 (asno);

      return aspath;
    }
  /* Assegment length exceeds 255 create new as-segment */
  if (assegment->type == type && assegment->length < 255)
    {
      u_int8_t *newdata;
      struct assegment *newsegment;

      newdata = XCALLOC (MTYPE_AS_SEG, aspath->length + AS_VALUE_SIZE);
      newsegment = (struct assegment *) newdata;

      newsegment->type = type;
      newsegment->length = assegment->length + 1;
      newsegment->asval[0] = pal_hton16 (asno);

      pal_mem_cpy (newdata + AS_HEADER_SIZE + AS_VALUE_SIZE,
              aspath->data + AS_HEADER_SIZE,
              aspath->length - AS_HEADER_SIZE);

      XFREE (MTYPE_AS_SEG, aspath->data);

      aspath->data = newdata;
      aspath->length += AS_VALUE_SIZE;
    }
  else
    {
      u_int8_t *newdata;
      struct assegment *newsegment;

      newdata = XCALLOC (MTYPE_AS_SEG, aspath->length + AS_VALUE_SIZE + AS_HEADER_SIZE);
      newsegment = (struct assegment *) newdata;

      newsegment->type = type;
      newsegment->length = 1;
      newsegment->asval[0] = pal_hton16 (asno);

      pal_mem_cpy (newdata + AS_HEADER_SIZE + AS_VALUE_SIZE,
              aspath->data,
              aspath->length);

      XFREE (MTYPE_AS_SEG, aspath->data);

      aspath->data = newdata;
      aspath->length += AS_HEADER_SIZE + AS_VALUE_SIZE;
    }

  return aspath;
}

/* Add specified AS to the leftmost of aspath. */
struct aspath *
aspath_add_seq (struct aspath *aspath, u_int16_t asno)
{
  return aspath_add_one_as (aspath, asno, BGP_AS_SEQUENCE);
}

/* Return origin AS value.  When AS path is empty return 0.  */
u_int16_t
aspath_origin (struct aspath *aspath)
{
  u_int8_t *pnt;
  u_int8_t *end;
  struct assegment *assegment = NULL;

  if (! aspath)
    return 0;

  if (! aspath->length)
    return 0;

  pnt = aspath->data;
  end = aspath->data + aspath->length;

  while (pnt < end)
    {
      assegment = (struct assegment *) pnt;
      pnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }

  if (! assegment || assegment->length == 0)
    return 0;

  if (assegment->type != BGP_AS_SEQUENCE
      && assegment->type != BGP_AS_CONFED_SEQUENCE)
    return 0;

  return pal_hton16 (assegment->asval[assegment->length - 1]);
}

/* Compare leftmost AS value for MED check.  If as1's leftmost AS and
   as2's leftmost AS is same return 1. */
int
aspath_cmp_left (struct aspath *aspath1, struct aspath *aspath2)
{
  struct assegment *seg1;
  struct assegment *seg2;
  u_int16_t as1;
  u_int16_t as2;
  u_int16_t cnt1;
  u_int16_t cnt2;
 
  if (aspath1 == NULL || aspath2 == NULL)
    return 0;
 
  cnt1 = aspath1->count_confed;
  cnt2 = aspath2->count_confed;
 
  if (cnt1 == 0 || cnt2 == 0)
    return 0;

  seg1 = (struct assegment *) aspath1->data;
  seg2 = (struct assegment *) aspath2->data;

  while (seg1 && seg1->length && --cnt1
         && (seg1->type == BGP_AS_CONFED_SEQUENCE || seg1->type == BGP_AS_CONFED_SET))
    seg1 = (struct assegment *) ((u_int8_t *) seg1 + ASSEGMENT_LEN (seg1));
  while (seg2 && seg2->length && --cnt2 
         && (seg2->type == BGP_AS_CONFED_SEQUENCE || seg2->type == BGP_AS_CONFED_SET))
    seg2 = (struct assegment *) ((u_int8_t *) seg2 + ASSEGMENT_LEN (seg2));

  /* Check as1's */
  if (seg1 == NULL || seg1->length == 0 || seg1->type != BGP_AS_SEQUENCE)
    return 0;
  as1 = seg1->asval[0];

  if (seg2 == NULL || seg2->length == 0 || seg2->type != BGP_AS_SEQUENCE)
    return 0;
  as2 = seg2->asval[0];

  if (as1 == as2)
    return 1;

  return 0;
}

/* Compare leftmost AS value for MED check.  If as1's leftmost AS and
   as2's leftmost AS is same return 1. (confederation as-path
   only).  */
int
aspath_cmp_left_confed (struct aspath *aspath1, struct aspath *aspath2)
{
  struct assegment *seg1;
  struct assegment *seg2;
  u_int16_t as1;
  u_int16_t as2;

  if (aspath1->count || aspath2->count)
    return 0;

  seg1 = (struct assegment *) aspath1->data;
  seg2 = (struct assegment *) aspath2->data;

  /* Check as1's */
  if (seg1 == NULL || seg1->length == 0 || seg1->type != BGP_AS_CONFED_SEQUENCE)
    return 0;
  as1 = seg1->asval[0];

  /* Check as2's */
  if (seg2 == NULL || seg2->length == 0 || seg2->type != BGP_AS_CONFED_SEQUENCE)
    return 0;
  as2 = seg2->asval[0];

  if (as1 == as2)
    return 1;

  return 0;
}

/* Delete first sequential BGP_AS_CONFED_SEQUENCE from aspath and any
   immediately following segments of the type of BGP_AS_CONFED_SET from
   AS_PATH attribute.  */
struct aspath *
aspath_delete_confed_seq (struct aspath *aspath)
{
  int seglen;
  struct assegment *assegment;

  if (! aspath)
    return aspath;

  assegment = (struct assegment *) aspath->data;

  while (assegment)
    {
      if (assegment->type != BGP_AS_CONFED_SEQUENCE
          && assegment->type != BGP_AS_CONFED_SET)
        return aspath;

      seglen = ASSEGMENT_LEN (assegment);

      if (seglen == aspath->length)
        {
          XFREE (MTYPE_AS_SEG, aspath->data);
          aspath->data = NULL;
          aspath->length = 0;
        }
      else
        {
          pal_mem_cpy (aspath->data, aspath->data + seglen,
                  aspath->length - seglen);
          aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data,
                                   aspath->length - seglen);
          aspath->length -= seglen;
        }

      assegment = (struct assegment *) aspath->data;
    }
  return aspath;
}

/* Add new AS number to the leftmost part of the aspath as
   BGP_AS_CONFED_SEQUENCE.  */
struct aspath*
aspath_add_confed_seq (struct aspath *aspath, u_int16_t asno)
{
  return aspath_add_one_as (aspath, asno, BGP_AS_CONFED_SEQUENCE);
}

/* Add new as value to as path structure. */
void
aspath_as_add (struct aspath *as, u_int16_t asno)
{
  struct assegment *assegment;
  u_int8_t *pnt;
  u_int8_t *end;

  /* Increase as->data for new as value. */
  as->data = XREALLOC (MTYPE_AS_SEG, as->data, as->length + 2);
  as->length += 2;

  pnt = as->data;
  end = as->data + as->length;
  assegment = (struct assegment *) pnt;

  /* Last segment search procedure. */
  while (pnt + 2 < end)
    {
      assegment = (struct assegment *) pnt;

      /* We add 2 for segment_type and segment_length and segment
         value assegment->length * 2. */
      pnt += (AS_HEADER_SIZE + (assegment->length * AS_VALUE_SIZE));
    }

  assegment->asval[assegment->length] = pal_hton16 (asno);
  assegment->length++;

  return;
}

/* Add new as segment to the as path. */
void
aspath_segment_add (struct aspath *as, int type)
{
  struct assegment *assegment;

  if (as->data == NULL)
    {
      as->data = XCALLOC (MTYPE_AS_SEG, 2);
      assegment = (struct assegment *) as->data;
      as->length = 2;
    }
  else
    {
      as->data = XREALLOC (MTYPE_AS_SEG, as->data, as->length + 2);
      assegment = (struct assegment *) (as->data + as->length);
      as->length += 2;
    }

  assegment->type = type;
  assegment->length = 0;

  return;
}

struct aspath *
aspath_empty ()
{
  return aspath_parse (NULL, 0, NULL);
}

struct aspath *
aspath_empty_get ()
{
  struct aspath *aspath;

  aspath = aspath_new ();
  return aspath_intern (aspath);
}

unsigned long
aspath_count ()
{
  return bgp_ashash_tab->count;
}

/*
   Theoretically, one as path can have:

   One BGP packet size should be less than 4096.
   One BGP attribute size should be less than 4096 - BGP header size.
   One BGP aspath size should be less than 4096 - BGP header size -
       BGP mandantry attribute size.
*/

/* AS path string lexical token enum. */
enum as_token
{
  as_token_asval,
  as_token_set_start,
  as_token_set_end,
  as_token_confed_start,
  as_token_confed_end,
  as_token_unknown
};

/* Return next token and point for string parse. */
char *
aspath_gettoken (char *buf, enum as_token *token, unsigned short *asno)
{
  char *p = buf;

  /* Skip space. */
  while (pal_char_isspace ((int) *p))
    p++;

  /* Check the end of the string and type specify characters
     (e.g. {}()). */
  switch (*p)
    {
    case '\0':
      return NULL;
      break;
    case '{':
      *token = as_token_set_start;
      p++;
      return p;
      break;
    case '}':
      *token = as_token_set_end;
      p++;
      return p;
      break;
    case '(':
      *token = as_token_confed_start;
      p++;
      return p;
      break;
    case ')':
      *token = as_token_confed_end;
      p++;
      return p;
      break;
    }

  /* Check actual AS value. */
  if (pal_char_isdigit ((int) *p))
    {
      unsigned short asval;

      *token = as_token_asval;
      asval = (*p - '0');
      p++;
      while (pal_char_isdigit ((int) *p))
        {
          asval *= 10;
          asval += (*p - '0');
          p++;
        }
      *asno = asval;
      return p;
    }

  /* There is no match then return unknown token. */
  *token = as_token_unknown;
  return  p++;
}

struct aspath *
aspath_str2aspath (char *str)
{
  enum as_token token;
  unsigned short as_type;
  unsigned short asno;
  struct aspath *aspath;
  int needtype;

  aspath = aspath_new ();

  /* We start default type as BGP_AS_SEQUENCE. */
  as_type = BGP_AS_SEQUENCE;
  needtype = 1;

  while ((str = aspath_gettoken (str, &token, &asno)) != NULL)
    {
      switch (token)
        {
        case as_token_asval:
          if (needtype)
            {
              aspath_segment_add (aspath, as_type);
              needtype = 0;
            }
          aspath_as_add (aspath, asno);
          break;
        case as_token_set_start:
          as_type = BGP_AS_SET;
          aspath_segment_add (aspath, as_type);
          needtype = 0;
          break;
        case as_token_set_end:
          as_type = BGP_AS_SEQUENCE;
          needtype = 1;
          break;
        case as_token_confed_start:
          as_type = BGP_AS_CONFED_SEQUENCE;
          aspath_segment_add (aspath, as_type);
          needtype = 0;
          break;
        case as_token_confed_end:
          as_type = BGP_AS_SEQUENCE;
          needtype = 1;
          break;
        case as_token_unknown:
        default:
          if (aspath)
            aspath_free (aspath);
          return NULL;
          break;
        }
    }

  aspath->str = aspath_make_str_count (aspath);

  return aspath;
}

/* Make hash value by raw aspath data. */
u_int32_t
aspath_key_make (void *arg)
{
  struct aspath *aspath;
  u_int32_t length;
  u_int32_t key;
  u_int8_t *pnt;

  aspath = (struct aspath *) arg;
  key = 0;

  length = aspath->length;
  pnt = aspath->data;

  while (length)
    key += pnt[--length];

  return key;
}

/* If two aspath have same value then return 1 else return 0 */
bool_t
aspath_cmp (void *arg1, void *arg2)
{
  struct aspath *as1;
  struct aspath *as2;

  as1 = (struct aspath *) arg1;
  as2 = (struct aspath *) arg2;

  if (as1 == NULL && as2 == NULL)
    return 1;
  if (as1 == NULL || as2 == NULL)
    return 0;

  if (as1->length == as2->length
      && !pal_mem_cmp (as1->data, as2->data, as1->length))
    return 1;
  else
    return 0;
}

#ifdef HAVE_EXT_CAP_ASN

/*
 * Function name: aspath_copy_aspath4B_to_aspath ()
 * Input        : 4Byte aspath4B, 2Byte aspath
 * Output       : returns the 2 byte aspath structure
 * Purpose      : convert 4Byte aspath4B to 2byte aspath. This is required
                  for sending AS_PATH attribute from an NBGP to OBGP 
*/


struct aspath *
aspath_copy_aspath4B_to_aspath (struct as4path *aspath4B, struct aspath *aspath)
{
   struct as4segment *assegment_4b;
   struct assegment *assegment;
   int i;
   unsigned int tmp_asval;
   unsigned short tmp_asval_2b;
   struct aspath *new;
   unsigned char *aspnt_4b;
   unsigned char *asend_4b;
   unsigned char *aspnt;

   assegment_4b = NULL;
   assegment = NULL;
   i = 0;
   tmp_asval = 0;
   tmp_asval_2b = 0; 
   new = aspath;
   new->length = 0;
   aspnt_4b = aspath4B->data;
   asend_4b = aspath4B->data + aspath4B->length;

   /* Calculate Number of Bytes required for 2 byte aspath */
   /* Find the Number of Segments and the number of AS in it */
   while (aspnt_4b < asend_4b)
    { 
      assegment_4b = (struct as4segment *)aspnt_4b;
      new->length += (assegment_4b->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
      aspnt_4b += (assegment_4b->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE; 
    }
    new->data = XCALLOC (MTYPE_AS_SEG, new->length);

    aspnt = new->data;
   
    aspnt_4b = aspath4B->data;
    asend_4b = aspath4B->data + aspath4B->length;
    
    /* Copy Each segments */
    
     while(aspnt_4b < asend_4b)
       {
         assegment  = (struct assegment *) aspnt;
         assegment_4b = (struct as4segment *) aspnt_4b;
         /* Copy Type and length */
         assegment->type = assegment_4b->type;
         assegment->length = assegment_4b->length;
 
         /* Copy  all the ASs in each Segments */
         for(i=0; i<assegment_4b->length; i++)
           {
             tmp_asval = pal_ntoh32 (assegment_4b->asval[i]);
             if (BGP_IS_AS4_MAPPABLE(tmp_asval))
               {
                 tmp_asval_2b = (unsigned short) tmp_asval;
                 assegment->asval[i] = pal_hton16 (tmp_asval_2b);
               }
             else
               {
                 assegment->asval[i] = pal_hton16 (BGP_AS_TRANS);
               } 
           }

         aspnt_4b += (assegment_4b->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
         aspnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
       }

    return new;
} 
#endif /* HAVE_EXT_CAP_ASN */

/* AS path hash initialize. */
void
aspath_init (void)
{
  bgp_ashash_tab = hash_create (aspath_key_make, aspath_cmp);
}

/* return and as path value */
u_int8_t *
aspath_print (struct aspath *as)
{
  return as->str;
}

struct hash *
aspath_hash (void)
{
  return bgp_ashash_tab;
}
