/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>
#ifdef HAVE_EXT_CAP_ASN
struct as4path *
as4path_new ()
{
  struct as4path *as4path;

  as4path = XCALLOC (MTYPE_AS4_PATH, sizeof (struct as4path));
  return as4path;
}

/* Free AS path structure. */
void
as4path_free (struct as4path *as4path)
{
  if (!as4path)
    return;
  if (as4path->data)
    XFREE (MTYPE_AS4_SEG, as4path->data);
  if (as4path->str)
    XFREE (MTYPE_AS4_STR, as4path->str);
  XFREE (MTYPE_AS4_PATH, as4path);
}

/* Unintern as4path from AS4 path bucket. */
void
as4path_unintern (struct as4path *as4path)
{
  struct as4path *ret;

  if (as4path->refcnt)
    as4path->refcnt--;

  if (as4path->refcnt == 0)
    {
      ret = hash_release (bgp_as4hash_tab, as4path);
      pal_assert (ret != NULL);
      as4path_free (as4path);
    }
}

void
aspath4B_unintern (struct as4path *aspath4B)
{
  struct as4path *ret;

  if (aspath4B->refcnt)
    aspath4B->refcnt--;

  if (aspath4B->refcnt == 0)
    {
      /* This aspath4B must exist in as4path hash table. */
      ret = hash_release (bgp_aspath4Bhash_tab, aspath4B);
      pal_assert (ret != NULL);
      as4path_free (aspath4B);
    }
}

/* Return the start or end delimiters for a particular Segment type */
static char
as4path_delimiter_char (u_int8_t type, u_int8_t which)
{
  int i;
  struct
  {
    int type;
    char start;
    char end;
  } as4path_delim_char [] =
    {
      { BGP_AS_SET,             '{', '}' },
      { BGP_AS_SEQUENCE,        ' ', ' ' },
      { BGP_AS_CONFED_SET,      '[', ']' },
      { BGP_AS_CONFED_SEQUENCE, '(', ')' },
      { 0 }
    };

  for (i = 0; as4path_delim_char[i].type != 0; i++)
    {
      if (as4path_delim_char[i].type == type)
        {
          if (which == AS4_SEG_START)
            return as4path_delim_char[i].start;
          else if (which == AS4_SEG_END)
            return as4path_delim_char[i].end;
        }
    }
  return ' ';
}

/* Convert as4path structure to string expression. */
char *
as4path_make_str_count (struct as4path *as)
{
  int space;
  u_int8_t type;
  u_int8_t *pnt;
  u_int8_t *end;
  struct as4segment *as4segment;
  int str_size = BGP_AS4PATH_STR_DEFAULT_LEN;
  int str_pnt;
  char *str_buf;
  u_int32_t count = 0;
  u_int32_t count_confed = 0;

  /* Empty as4path. */
  if (as->length == 0)
    {
      str_buf = XCALLOC (MTYPE_AS4_STR, 1);
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

  str_buf = XCALLOC (MTYPE_AS4_STR, str_size);
  str_pnt = 0;

  as4segment = (struct as4segment *) pnt;

  while (pnt < end)
    {
      int i;
      int estimate_len;

      /* For fetch value. */
      as4segment = (struct as4segment *) pnt;

      /* Check AS type validity. */
      if ((as4segment->type != BGP_AS_SET) &&
          (as4segment->type != BGP_AS_SEQUENCE) &&
          (as4segment->type != BGP_AS_CONFED_SET) &&
          (as4segment->type != BGP_AS_CONFED_SEQUENCE))
        {
          XFREE (MTYPE_AS4_STR, str_buf);
          return NULL;
        }

      /* Check AS length. */
      if ((pnt + (as4segment->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE) > end)
        {
          XFREE (MTYPE_AS4_STR, str_buf);
          return NULL;
        }

      /* Buffer length check. */
      estimate_len = ((as4segment->length * 8) + 4);

      /* String length check. */
      while (str_pnt + estimate_len >= str_size)
        {
          str_size *= 2;
          str_buf = XREALLOC (MTYPE_AS4_STR, str_buf, str_size);
        }

      /* If as4segment type is changed, print previous type's end
         character. */
      if (type != BGP_AS_SEQUENCE)
        str_buf[str_pnt++] = as4path_delimiter_char (type, AS4_SEG_END);
      if (space)
        str_buf[str_pnt++] = ' ';

      if (as4segment->type != BGP_AS_SEQUENCE)
        str_buf[str_pnt++] = as4path_delimiter_char (as4segment->type, AS4_SEG_START);

      space = 0;

      /* Increment count.  */
      switch (as4segment->type)
        {
        case BGP_AS_SEQUENCE:
          count += as4segment->length;
          break;
        case BGP_AS_SET:
          count++;
          break;
        case BGP_AS_CONFED_SEQUENCE:
          count_confed += as4segment->length;
          break;
        case BGP_AS_CONFED_SET:
          count_confed++;
          break;
        default:
          break;
        }

      for (i = 0; i < as4segment->length; i++)
        {
          int len;

          if (space)
            {
              if (as4segment->type == BGP_AS_SET
                  || as4segment->type == BGP_AS_CONFED_SET)
                str_buf[str_pnt++] = ',';
              else
                str_buf[str_pnt++] = ' ';
            }
          else
            space = 1;

          len = pal_snprintf (str_buf + str_pnt, str_size - str_pnt,
                               "%u", pal_ntoh32 (as4segment->asval[i]));
          str_pnt += len;
        }

      type = as4segment->type;
      pnt += (as4segment->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
    }

  if (as4segment->type != BGP_AS_SEQUENCE)
    str_buf[str_pnt++] = as4path_delimiter_char (as4segment->type, AS4_SEG_END);

  str_buf[str_pnt] = '\0';

  as->count = count;
  as->count_confed = count + count_confed;

  return str_buf;
}


/* Intern allocated AS path. */
struct as4path *
as4path_intern (struct as4path *as4path)
{
  struct as4path *find;

  /* Assert this AS path structure is not interned. */
  pal_assert ( as4path->refcnt == 0);
  pal_assert (! as4path->str);

  /* Check AS path hash. */
  find = hash_get (bgp_as4hash_tab, as4path, hash_alloc_intern);
  if (find != as4path)
    as4path_free (as4path);

  find->refcnt++;

  if (! find->str)
    find->str = as4path_make_str_count (find);

  return find;
}

/* Intern allocated AS path. */
struct as4path *
aspath4B_intern (struct as4path *aspath4B)
{
  struct as4path *find;

  /* Assert this AS path structure is not interned. */
  pal_assert ( aspath4B->refcnt == 0);
  pal_assert (! aspath4B->str);


  /* Check AS path hash. */
  find = hash_get (bgp_aspath4Bhash_tab, aspath4B, hash_alloc_intern);
  if (find != aspath4B)
    as4path_free (aspath4B);

  find->refcnt++;

  if (! find->str)
    find->str = as4path_make_str_count (find);

  return find;
}


/* Duplicate as4path structure.  Created same as4path structure but
   reference count and AS path string is cleared. */
struct as4path *
as4path_dup (struct as4path *as4path)
{
  struct as4path *new;

  new = XCALLOC (MTYPE_AS4_PATH, sizeof (struct as4path));

  new->length = as4path->length;

  if (new->length)
    {
      new->data = XCALLOC (MTYPE_AS4_SEG, as4path->length);
      pal_mem_cpy (new->data, as4path->data, as4path->length);
    }
  else
    new->data = NULL;

  /* new->str = as4path_make_str_count (as4path); */

  return new;
}

struct as4path *
as4path_new_or_dup (struct as4path *existing)
{
  struct as4path *new;

  if (existing)
     new = as4path_dup (existing);
  else
     new = as4path_new();

  return (new);
}


void *
as4path_hash_alloc (void *arg)
{
  struct as4path *as4path_in;
  struct as4path *as4path;

  as4path_in = (struct as4path *) arg;

  /* New as4path strucutre is needed. */
  as4path = XCALLOC (MTYPE_AS4_PATH, sizeof (struct as4path));
  pal_mem_set ((void *) as4path, 0, sizeof (struct as4path));
  as4path->length = as4path_in->length;

  /* In case of IBGP connection as4path's length can be zero. */
  if (as4path_in->length)
    {
      as4path->data = XCALLOC (MTYPE_AS4_SEG, as4path_in->length);
      pal_mem_cpy (as4path->data, as4path_in->data, as4path_in->length);
    }
  else
    as4path->data = NULL;

  /* Make AS path string. */
  as4path->str = as4path_make_str_count (as4path);

  /* Malformed AS path value. */
  if (! as4path->str)
    {
      as4path_free (as4path);
      return NULL;
    } 

  return (void *) as4path;
}

/* AS path parse function.  pnt is a pointer to byte stream and length
   is length of byte stream.  If there is same AS path in the the AS
   path hash then return it else make new AS path structure. */

struct as4path *
as4path_parse (u_int8_t *pnt, int length, struct bgp_peer *peer)
{
  struct as4path as, *tmp_as;
  struct as4path *find;

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
      tmp_as = as4path_dup(&as);
      tmp_as = as4path_add_seq (tmp_as, peer->local_as);
      find = hash_get (bgp_as4hash_tab, tmp_as, as4path_hash_alloc);
      as4path_free(tmp_as);
    }                 
  else
   {       
     find = hash_get (bgp_as4hash_tab, &as, as4path_hash_alloc);
   }       

  if (! find)
    return NULL;
  find->refcnt++;

  return find;
}


/* AS path parse function.  pnt is a pointer to byte stream and length
   is length of byte stream.  If there is same AS path in the the AS
   path hash then return it else make new AS path structure. */

struct as4path *
aspath4B_parse (u_int8_t *pnt, int length)
{
  struct as4path as;
  struct as4path *find;

  /* If length is odd it's malformed AS path. */
  if (length % 2)
    return NULL;

  /* Looking up as4path hash entry. */
  as.data = pnt;
  as.length = length;

  /* If already same as4path exist then return it. */
  find = hash_get (bgp_aspath4Bhash_tab, &as, as4path_hash_alloc);
  if (! find)
    return NULL;
  find->refcnt++;

  return find;
}

struct as4path *
as4path_aggregate_segment_copy (struct as4path *as4path, struct as4segment *seg,
                               int i)
{
  struct as4segment *newseg;

  if (! as4path->data)
    {
      as4path->data = XCALLOC (MTYPE_AS4_SEG, AS4SEGMENT_SIZE (i));
      newseg = (struct as4segment *) as4path->data;
      as4path->length = AS4SEGMENT_SIZE (i);
    }
  else
    {
      as4path->data = XREALLOC (MTYPE_AS4_SEG, as4path->data,
                               as4path->length + AS4SEGMENT_SIZE (i));
      newseg = (struct as4segment *) (as4path->data + as4path->length);
      as4path->length += AS4SEGMENT_SIZE (i);
    }

  newseg->type = seg->type;
  newseg->length = i;
  pal_mem_cpy (newseg->asval, seg->asval, (i * AS4_VALUE_SIZE));

  return as4path;
}

/*
 * Function name: as4path_copy_aspath_to_aspath4B()
 * Input        : 2Byte aspath, 4Byte aspath4b structures
 * Output       : returns the 4 byte aspath4B structure 
 * Purpose      : convert 2 byte AS Path to 4 Byte AS Path. This function will
                  be called when an NBGP recevies an Update Mesage from an OBGP
                  carries 2 Byte AS Path
*/

struct as4path *
as4path_copy_aspath_to_aspath4B (struct aspath *aspath, struct as4path *aspath4B)
{
   struct as4segment *assegment_4b;
   struct assegment *assegment;
   int i;
   unsigned int tmp_asval;
   struct as4path *new_aspath4B;
   unsigned char *aspnt;
   unsigned char *asend;
   unsigned char *aspnt_4b;

   assegment_4b = NULL;
   assegment = NULL;
   new_aspath4B = aspath4B;
   new_aspath4B->length = 0;
   aspnt = aspath->data;
   asend = aspath->data + aspath->length;
   i = 0;
   tmp_asval = 0;

   /* Calculate Number of Bytes required for 4 byte aspath */
   /* Find the Number of Segments and the number of AS in it */

   while (aspnt < asend)
    {
      assegment = (struct assegment *)aspnt;
      new_aspath4B->length += (assegment->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
      aspnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
    }  

   new_aspath4B->data = XCALLOC (MTYPE_AS4_SEG, new_aspath4B->length);
   assegment_4b = (struct as4segment *)new_aspath4B->data;

   aspnt_4b = new_aspath4B->data;
   aspnt = aspath->data;
   asend = aspath->data + aspath->length;

   /* Copy Each segments */
   while(aspnt < asend)
    {
      assegment = (struct assegment *)aspnt;
      assegment_4b = (struct as4segment *) aspnt_4b;
      /* Copy Type and length */
      assegment_4b->type = assegment->type;
      assegment_4b->length = assegment->length;
      /* Copy  all the ASs in each Segments */
      for(i=0; i<assegment->length; i++)
        {
          tmp_asval = (unsigned int) pal_ntoh16 (assegment->asval[i]);         
          assegment_4b->asval[i] = pal_hton32(tmp_asval);
        } 
        
      aspnt += (assegment->length * AS_VALUE_SIZE) + AS_HEADER_SIZE;
      aspnt_4b += (assegment_4b->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
    }

   return new_aspath4B;
}

/*
 * Function name: construct_as4path_from_aspath4B()
 * Input        : 4Byte aspath4B, 4Byte as4path structures
 * Output       : returns the 4 byte as4path structure
 * Purpose      : construct 4 Byte as4path structure from 4 byte aspath4B
                  structure. Only Unmappable ASs will copy from aspath4B to
                  as4path. This is required when NBGP communicates with OBGP
*/ 

struct as4path *
construct_as4path_from_aspath4B (struct as4path *aspath4B, struct as4path *as4path)
{
   struct as4segment *assegment_4b;
   struct as4segment *as4segment;
   int i;
   int j;
   unsigned int tmp_asval;
   struct as4path *new_as4path;
   unsigned char *aspnt_4b;
   unsigned char *asend_4b;
   unsigned char *as4pnt;
   u_int8_t as4_len;
  
   assegment_4b = NULL;
   as4segment = NULL;
   i = 0;
   j = 0;
   as4_len = 0;
   tmp_asval = 0;
   new_as4path = as4path;
   new_as4path->length = 0;
   aspnt_4b = aspath4B->data;
   asend_4b = aspath4B->data + aspath4B->length;

   /* Calculate Number of Bytes required for 4 byte as4path */
   new_as4path->length = bgp_as4path_get_num_of_bytes_from_4bas (aspnt_4b, asend_4b);
   /* Allocate required number of bytes */
   new_as4path->data = XCALLOC (MTYPE_AS4_SEG, new_as4path->length);
   as4segment = (struct as4segment *)new_as4path->data;

   as4pnt = new_as4path->data;

   aspnt_4b = aspath4B->data;
   asend_4b = aspath4B->data + aspath4B->length;

   /* Copy Each segments */
   while(aspnt_4b < asend_4b)
    {
      as4segment  = (struct as4segment *) as4pnt;
      assegment_4b = (struct as4segment *) aspnt_4b;
      as4_len = 0;
      j = 0;
      for(i=0; i<assegment_4b->length; i++)
        {
          tmp_asval = pal_ntoh32 (assegment_4b->asval[i]);
          if (! BGP_IS_AS4_MAPPABLE(tmp_asval))
            {
              as4_len++;
              as4segment->asval[j] = pal_hton32(tmp_asval);
              j++;
            }
        }
      if (j)
        {
          as4segment->length =  as4_len;
          as4segment->type = assegment_4b->type;
        }
      as4pnt += AS4SEGMENT_LEN (as4segment);
      aspnt_4b += AS4SEGMENT_LEN (assegment_4b);
    }

   return new_as4path;
}


/*
 * Function name: as4path_reconstruct_aspath4B()
 * Input        : aspath4B, as4path
 * Output       : returns the 4 byte reconstructed aspath4B 
 * Purpose      : The reconstructed aspath4B ( replaced AS_TRANS with 
                  correspoing entry in the as4path 
*/

struct as4path * 
as4path_reconstruct_aspath4B (struct as4path *aspath4B,
                               struct as4path *as4path)
{
   struct as4segment *assegment_4b;
   struct as4segment *as4segment;
   struct as4segment *assegment_4b_recon;
   unsigned char *as4pnt;
   unsigned char *aspnt_4b;
   unsigned char *asend_4b;
   struct as4path *aspath4B_recon;
   unsigned char *aspnt_4b_recon;
   unsigned char *asend_4b_recon;
   u_int32_t tmp_asval;
   int i,j;

   assegment_4b = NULL;
   as4segment = NULL;
   assegment_4b_recon = NULL;
   aspath4B_recon = NULL;
   i = 0;
   j = 0;
   aspath4B_recon = as4path_new();
   aspath4B_recon->length = 0;
   as4pnt = as4path->data;
   aspnt_4b = aspath4B->data;
   asend_4b = aspath4B->data + aspath4B->length;

   /* construct aspath4B_recon from aspath4B. This is required to avoid incorrect reference
      while calculating the key for accessing from the hash table (The  mapping between
      the key and actual data stored should be correct */
  
   /* calculate required number of bytes */
   aspath4B_recon->length = bgp_as4path_get_num_of_bytes (aspnt_4b,asend_4b);
   /* allocate required number of bytes */
   aspath4B_recon->data = XCALLOC (MTYPE_AS4_SEG, aspath4B_recon->length);
   
   aspnt_4b = aspath4B->data;
   aspnt_4b_recon = aspath4B_recon->data;

   /* copy each bytes so that aspath4B_recon will be exactly same as aspath4B*/
   while(aspnt_4b < asend_4b)
    {
      assegment_4b = (struct as4segment *) aspnt_4b;
      assegment_4b_recon = (struct as4segment *) aspnt_4b_recon;

      /* copy type, length and as values */
      assegment_4b_recon->type = assegment_4b->type;
      assegment_4b_recon->length = assegment_4b->length;
 
       /* Copy  all the ASs in each Segments */
      for(i=0; i<assegment_4b->length; i++)
        assegment_4b_recon->asval[i] =  assegment_4b->asval[i];

      aspnt_4b += AS4SEGMENT_SIZE (assegment_4b->length);
      aspnt_4b_recon += AS4SEGMENT_SIZE (assegment_4b_recon->length); 
    }
   
   /* Reassign the pointers to the initial value */ 
   aspnt_4b_recon = aspath4B_recon->data;
   asend_4b_recon = aspath4B_recon->data + aspath4B_recon->length; 
   j = 0;
    
   /* Reconstruct the path by comparing each as value in each segments */
   while (aspnt_4b_recon < asend_4b_recon)
    {
      assegment_4b_recon = (struct as4segment *) aspnt_4b_recon;
      as4segment = (struct as4segment *) as4pnt;

      for (i=0; i<assegment_4b_recon->length; i++)
       {
         tmp_asval = (u_int32_t) pal_ntoh32 (assegment_4b_recon->asval[i]);
         if (tmp_asval == BGP_AS_TRANS)
           {
             assegment_4b_recon->asval[i] = as4segment->asval[j];
             j++;
           }
       }

       if (j >= as4segment->length)
         {
           j = 0;
           as4pnt += AS4SEGMENT_SIZE (as4segment->length);
         }
       aspnt_4b_recon += AS4SEGMENT_SIZE (assegment_4b_recon->length);
     }

   return aspath4B_recon;
}


/*
 * Function name: bgp_as4path_get_num_of_bytes_from_4bas()
 * Input        : aspnt_4b, asend_4b 
 * Output       : returns the number of bytes required for storing 4 byte 
                  Non-mappable ASs in as4path
 * Purpose      : for constructing as4path from aspath4B 
*/

u_int32_t
bgp_as4path_get_num_of_bytes_from_4bas (unsigned char *aspnt_4b, unsigned char *asend_4b)
{
  struct as4segment *assegment_4b;
  int unmap_as4_cnt;
  u_int32_t as4_len = 0;
  u_int32_t tmp_asval;
  int i;
  
  /* Calculate Number of Bytes required for 4 byte as4path */
   while (aspnt_4b < asend_4b)
    {
      unmap_as4_cnt = 0;
      assegment_4b = (struct as4segment *)aspnt_4b;
      for (i=0; i<assegment_4b->length; i++)
        {
         tmp_asval = (u_int32_t) pal_ntoh32 (assegment_4b->asval[i]);
         if (! BGP_IS_AS4_MAPPABLE(tmp_asval))
            unmap_as4_cnt++;
        }
      as4_len += AS4SEGMENT_SIZE (unmap_as4_cnt);
      aspnt_4b += AS4SEGMENT_LEN (assegment_4b);
    }
  return as4_len;
}


/*
 * Function name: bgp_as4path_get_num_of_bytes()
 * Input        : aspnt_4b, asend_4b (pointers to start and end segments) 
 * Output       : returns the number of bytes required for storing the reconstructed aspath4B
 * Purpose      : for reconstructing aspath4B from as4path
*/

u_int32_t
bgp_as4path_get_num_of_bytes (unsigned char *aspnt_4b, unsigned char *asend_4b)
{
  struct as4segment *assegment_4b;
  u_int32_t as4_recon_len = 0;
  while (aspnt_4b < asend_4b)
    {
      assegment_4b = (struct as4segment *) aspnt_4b;
      as4_recon_len += AS4SEGMENT_LEN (assegment_4b);
      aspnt_4b += AS4SEGMENT_SIZE (assegment_4b->length);
    } 
  return as4_recon_len; 
}

struct as4segment *
as4path_aggregate_as_set_add (struct as4path *as4path, struct as4segment *asset,
                             as_t as, u_int8_t type)
{
  struct as4segment *seg;
  int i;

  /* If this is first AS set member, create new as-set segment. */
  if (asset == NULL)
    {
      if (! as4path->data)
        {
          as4path->data = XCALLOC (MTYPE_AS4_SEG,
                                  AS4SEGMENT_SIZE (AS4SEGMENT_LEN_MIN));
          asset = (struct as4segment *) as4path->data;
          as4path->length = AS4SEGMENT_SIZE (AS4SEGMENT_LEN_MIN);
        }
      else
        {
          as4path->data = XREALLOC (MTYPE_AS4_SEG, as4path->data,
                                   as4path->length
                                   + AS4SEGMENT_SIZE (AS4SEGMENT_LEN_MIN));
          asset = (struct as4segment *) (as4path->data + as4path->length);
          as4path->length += AS4SEGMENT_SIZE (AS4SEGMENT_LEN_MIN);
        }
      asset->type = type;
      asset->length = AS4SEGMENT_LEN_MIN;
      asset->asval[0] = as;
    }
  else
    {
      size_t offset;

      /* Check this AS value already exists or not. */
      for (i = 0; i < asset->length; i++)
        if (asset->asval[i] == as)
          return asset;

      offset = (u_int8_t *) asset - (u_int8_t *) as4path->data;

      if (asset->length < AS4SEGMENT_LEN_MAX)
        {
          as4path->data = XREALLOC (MTYPE_AS4_SEG, as4path->data,
                                   as4path->length + AS4_VALUE_SIZE);

          asset = (struct as4segment *) (as4path->data + offset);
          as4path->length += AS4_VALUE_SIZE;
          asset->asval[asset->length] = as;
          asset->length++;
        }
      else
        {
          as4path->data = XREALLOC (MTYPE_AS4_SEG, as4path->data,
                                   as4path->length
                                   + AS4SEGMENT_SIZE (AS4SEGMENT_LEN_MIN));
          asset = (struct as4segment *) (as4path->data + offset);
          seg = (struct as4segment *) (as4path->data + offset + as4path->length);
          as4path->length += AS4SEGMENT_SIZE (AS4SEGMENT_LEN_MIN);
          seg->asval[0] = as;
          seg->type = type;
          seg->length = AS4SEGMENT_LEN_MIN;
        }
    }

  return asset;
}

/* Modify as1 using as2 for aggregation. */
struct as4path *
as4path_aggregate (struct as4path *as1, struct as4path *as2,
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
  struct as4segment *seg1;
  struct as4segment *seg2;
  struct as4path *as4path;
  struct as4segment *asset1, *asset2;

  match = 0;
  minlen = 0;
  as4path = NULL;
  asset1 = NULL;
  asset2 = NULL;
  cp1 = as1->data;
  end1 = as1->data + as1->length;
  cp2 = as2->data;
  end2 = as2->data + as2->length;

  seg1 = (struct as4segment *) cp1;
  seg2 = (struct as4segment *) cp2;

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
          if (! as4path)
            as4path = as4path_new();
          as4path = as4path_aggregate_segment_copy (as4path, seg1, match);
        }

      if (match != minlen || match != seg1->length
          || seg1->length != seg2->length)
        break;

      cp1 += ((seg1->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE);
      cp2 += ((seg2->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE);

      seg1 = (struct as4segment *) cp1;
      seg2 = (struct as4segment *) cp2;

      match = 0;
    }

  if (! as4path)
    as4path = as4path_new();

  if (asset_type == BGP_AS_SET)
    {
      type = BGP_AS_SEQUENCE;
      type_other = BGP_AS_CONFED_SET;
    }
  if (asset_type == BGP_AS_CONFED_SET)
    {
      type = BGP_AS_CONFED_SET;
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
      seg1 = (struct as4segment *) cp1;

      if (seg1->type == asset_type || seg1->type == type)
        for (i = match1; i < seg1->length; i++)
          asset1 = as4path_aggregate_as_set_add (as4path, asset1, seg1->asval[i],
                                                asset_type);
      else
        for (i = match1; i < seg1->length; i++)
          asset2 = as4path_aggregate_as_set_add (as4path, asset2, seg1->asval[i],
                                                type_other);

      match1 = 0;
      cp1 += ((seg1->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE);
    }

  match2 = match;
  while (cp2 < end2)
    {
      seg2 = (struct as4segment *) cp2;

      if (seg2->type == asset_type || seg2->type == type)
      for (i = match2; i < seg2->length; i++)
        asset1 = as4path_aggregate_as_set_add (as4path, asset1, seg2->asval[i],
                                              asset_type);
      else
      for (i = match2; i < seg2->length; i++)
        asset2 = as4path_aggregate_as_set_add (as4path, asset2, seg2->asval[i],
                                              type_other);

      match2 = 0;
      cp2 += ((seg2->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE);
    }


  return as4path;
}

/* When a BGP router receives an UPDATE with an MP_REACH_NLRI
   attribute, check the leftmost AS number in the AS_PATH attribute is
   or not the peer's AS number. */
int
as4path_firstas_check (struct as4path *as4path, as_t asno)
{
  u_int8_t *pnt;
  struct as4segment *as4segment;

  if (as4path == NULL)
    return 0;

  pnt = as4path->data;
  as4segment = (struct as4segment *) pnt;

  if (as4segment
      && as4segment->type == BGP_AS_SEQUENCE
      && as4segment->asval[0] == pal_hton32 (asno))
    return 1;

  return 0;
}

/* Return 1 if 'as4path' contains segment(s) of type BGP_AS_CONFED_SET
   or AS_CONFED_SEQ */
int
as4path_confed_seg_check (struct as4path *as4path)
{
  u_int8_t *pnt;
  u_int8_t *end;
  struct as4segment *as4segment;

  if (as4path == NULL)
    return 0;

  pnt = as4path->data;
  end = as4path->data + as4path->length;

  while (pnt < end)
    {
      as4segment = (struct as4segment *) pnt;

      if (as4segment->type == BGP_AS_CONFED_SEQUENCE
          || as4segment->type == BGP_AS_CONFED_SET)
          return 1;

      pnt += AS4SEGMENT_SIZE(as4segment->length);
    }

  return 0;
}

/* Return 1 if 'aspath' contains segment(s) of type BGP_AS_CONFED_SET
   or AS_CONFED_SEQ as the first AS SEGMENT */
int
as4path_confed_first_seg_check (struct as4path *aspath4B)
{
  u_int8_t *pnt;
  struct as4segment *as4segment;

  if (aspath4B == NULL || aspath4B->length == 0)
    return 1;

  pnt = aspath4B->data;

  as4segment = (struct as4segment *) pnt;

  if (as4segment->type == BGP_AS_CONFED_SEQUENCE
      || as4segment->type == BGP_AS_CONFED_SET)
    return 1;
  else
    return 0;
}

/* AS path loop check.  If as4path contains asno then return 1. */
int
as4path_loop_check (struct as4path *as4path, as_t asno)
{
  u_int8_t *pnt;
  u_int8_t *end;
  struct as4segment *as4segment;
  int count = 0;

  if (as4path == NULL)
    return 0;

  pnt = as4path->data;
  end = as4path->data + as4path->length;

  while (pnt < end)
    {
      int i;
      as4segment = (struct as4segment *) pnt;

      for (i = 0; i < as4segment->length; i++)
        if (as4segment->asval[i] == pal_hton32 (asno))
          count++;

      pnt += (as4segment->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
    }
  return count;
}

/* When all of AS path is private AS return 1.  */
int
as4path_private_as_check (struct as4path *as4path)
{
  struct as4segment *as4segment;
  u_int32_t tmp_asval;
  u_int8_t *pnt;
  u_int8_t *end;

  if (as4path == NULL)
    return 0;

  if (as4path->length == 0)
    return 0;

  pnt = as4path->data;
  end = as4path->data + as4path->length;

  while (pnt < end)
    {
      int i;
      as4segment = (struct as4segment *) pnt;

      for (i = 0; i < as4segment->length; i++)
        {
          tmp_asval = (u_int32_t) pal_ntoh32 (as4segment->asval[i]);

          if (tmp_asval < BGP_PRIVATE_AS_MIN
              || tmp_asval > BGP_PRIVATE_AS_MAX)
            return 0;
        }
      pnt += (as4segment->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
    }
  return 1;
}

/* When all of AS4 path is in range <1-4294967295> return 1.  */
int
as4path_as_value_check (struct as4path *as4path)
{
  struct as4segment *as4segment;
  u_int32_t tmp_asval;
  u_int8_t *pnt;
  u_int8_t *end;

  if (as4path == NULL)
    return 0;

  if (as4path->length == 0)
    return 0;

  pnt = as4path->data;
  end = as4path->data + as4path->length;

  while (pnt < end)
    {
      int i;
      as4segment = (struct as4segment *) pnt;
      for (i = 0; i < as4segment->length; i++)
       {
          tmp_asval = (u_int32_t) pal_ntoh32 (as4segment->asval[i]);
          if (tmp_asval < BGP_AS4_MIN || tmp_asval > BGP_AS4_MAX)
              return 0;
        }
      pnt += (as4segment->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
    }
    return 1;
}

/* Count the Number of ASs in the AS4 PATH */
unsigned int
as4path_as4_count (struct as4path *as4path)
{
  struct as4segment *as4segment;
  u_int32_t tmp_asval;
  u_int8_t *pnt;
  u_int8_t *end;
  unsigned int as4pathcount;

  if (as4path == NULL)
    return 0;

  if (as4path->length == 0)
    return 0;
  pnt = as4path->data;
  end = as4path->data + as4path->length;
  as4pathcount = 0;

  while (pnt < end)
    {
      int i;
      as4segment = (struct as4segment *) pnt;
      for (i = 0; i < as4segment->length; i++)
        {
          tmp_asval = (u_int32_t) pal_ntoh32 (as4segment->asval[i]);
          if (tmp_asval < BGP_AS4_MIN || tmp_asval > BGP_AS4_MAX)
            return 0;
          else
            as4pathcount++; 
        }
      pnt += (as4segment->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
    }
    return as4pathcount;
}

/* Count the Number of Non Mappable ASs in the AS PATH (4B) */
unsigned int
aspath4B_nonmappable_count (struct as4path *aspath4B)
{
  struct as4segment *assegment_4b;
  u_int32_t tmp_asval;
  u_int8_t *pnt;
  u_int8_t *end;
  unsigned int nonmappable_count;

  if (aspath4B == NULL)
    return 0;

  if (aspath4B->length == 0)
    return 0;
  pnt = aspath4B->data;
  end = aspath4B->data + aspath4B->length;
  nonmappable_count = 0;

  while (pnt < end)
    {
      int i;
      assegment_4b = (struct as4segment *) pnt;
      for (i = 0; i < assegment_4b->length; i++)
        {
          tmp_asval = (u_int32_t) pal_ntoh32 (assegment_4b->asval[i]);
          if (tmp_asval < BGP_AS4_MIN || tmp_asval > BGP_AS4_MAX)
            return 0;
          else
            {
              if (! BGP_IS_AS4_MAPPABLE(tmp_asval)) 
                nonmappable_count++;
            }
        }
      pnt += (assegment_4b->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
    }
    return nonmappable_count;
}


/* Merge as1 to as2.  as2 should be uninterned as4path. */
struct as4path *
as4path_merge (struct as4path *as1, struct as4path *as2)
{
  u_int8_t *data;

  if (! as1 || ! as2)
    return NULL;

  data = XCALLOC (MTYPE_AS4_SEG, as1->length + as2->length);
  pal_mem_cpy (data, as1->data, as1->length);
  pal_mem_cpy (data + as1->length, as2->data, as2->length);

  XFREE (MTYPE_AS4_SEG, as2->data);
  as2->data = data;
  as2->length += as1->length;
  as2->count += as1->count;
  return as2;
}

/* Prepend as1 to as2.  as2 should be uninterned as4path. */
struct as4path *
as4path_prepend (struct as4path *as1, struct as4path *as2)
{
  u_int8_t *pnt;
  u_int8_t *end;
  struct as4segment *seg1 = NULL;
  struct as4segment *seg2 = NULL;

  if (! as1 || ! as2)
    return NULL;

  seg2 = (struct as4segment *) as2->data;

  /* In case of as2 is empty AS. */
  if (seg2 == NULL)
    {
      as2->length = as1->length;
      as2->data = XCALLOC (MTYPE_AS4_SEG, as1->length);
      as2->count = as1->count;
      pal_mem_cpy (as2->data, as1->data, as1->length);
      return as2;
    }

  /* as4segment points last segment of as1. */
  pnt = as1->data;
  end = as1->data + as1->length;
  while (pnt < end)
    {
      seg1 = (struct as4segment *) pnt;
      pnt += (seg1->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
    }

  /* In case of as1 is empty AS. */
  if (seg1 == NULL)
    return as2;

  /* Compare last segment type of as1 and first segment type of as2. */
  if (seg1->type != seg2->type)
    return as4path_merge (as1, as2);

  if (seg1->type == BGP_AS_SEQUENCE)
    {
      u_int8_t *newdata;
      struct as4segment *seg = NULL;

      newdata = XCALLOC (MTYPE_AS4_SEG,
                         as1->length + as2->length - AS4_HEADER_SIZE);
      pal_mem_cpy (newdata, as1->data, as1->length);
      seg = (struct as4segment *) (newdata + ((u_int8_t *)seg1 - as1->data));
      seg->length += seg2->length;
      pal_mem_cpy (newdata + as1->length, as2->data + AS4_HEADER_SIZE,
              as2->length - AS4_HEADER_SIZE);

      XFREE (MTYPE_AS4_SEG, as2->data);
      as2->data = newdata;
      as2->length += (as1->length - AS4_HEADER_SIZE);
      as2->count += as1->count;

      return as2;
    }
  else
    {
      /* BGP_AS_SET merge code is needed at here. */
      return as4path_merge (as1, as2);
    }

  /* Not reached */
}

/* Add specified AS to the leftmost of as4path. */
static struct as4path *
as4path_add_one_as (struct as4path *as4path, as_t asno, u_int8_t type)
{
  struct as4segment *as4segment;

  if (!as4path)
    return NULL;

  as4segment = (struct as4segment *) as4path->data;

  /* In case of empty as4path. */
  if (as4segment == NULL || as4segment->length == 0)
    {
      as4path->length = AS4_HEADER_SIZE + AS4_VALUE_SIZE;

      if (as4segment)
        as4path->data = XREALLOC (MTYPE_AS4_SEG, as4path->data, as4path->length);
      else
        as4path->data = XCALLOC (MTYPE_AS4_SEG, as4path->length);

      as4segment = (struct as4segment *) as4path->data;
      as4segment->type = type;
      as4segment->length = 1;
      as4segment->asval[0] = pal_hton32 (asno); 

      return as4path;
    }

  if (as4segment->type == type)
    {
      u_int8_t *newdata;
      struct as4segment *newsegment;

      newdata = XCALLOC (MTYPE_AS4_SEG, as4path->length + AS4_VALUE_SIZE);
      newsegment = (struct as4segment *) newdata;

      newsegment->type = type;
      newsegment->length = as4segment->length + 1;
      newsegment->asval[0] = pal_hton32 (asno);

      pal_mem_cpy (newdata + AS4_HEADER_SIZE + AS4_VALUE_SIZE,
              as4path->data + AS4_HEADER_SIZE,
              as4path->length - AS4_HEADER_SIZE);

      XFREE (MTYPE_AS4_SEG, as4path->data);

      as4path->data = newdata;
      as4path->length += AS4_VALUE_SIZE;
    }
  else
    {
      u_int8_t *newdata;
      struct as4segment *newsegment;

      newdata = XCALLOC (MTYPE_AS4_SEG, as4path->length + AS4_VALUE_SIZE + AS4_HEADER_SIZE);
      newsegment = (struct as4segment *) newdata;

      newsegment->type = type;
      newsegment->length = 1;
      newsegment->asval[0] = pal_hton32 (asno);

      pal_mem_cpy (newdata + AS4_HEADER_SIZE + AS4_VALUE_SIZE,
              as4path->data,
              as4path->length);

      XFREE (MTYPE_AS4_SEG, as4path->data);

      as4path->data = newdata;
      as4path->length += AS4_HEADER_SIZE + AS4_VALUE_SIZE;
    }

  return as4path;
}

/* Add specified AS to the leftmost of as4path. */
struct as4path *
as4path_add_seq (struct as4path *as4path, as_t asno)
{
  return as4path_add_one_as (as4path, asno, BGP_AS_SEQUENCE);
}

/* Return origin AS value.  When AS path is empty return 0.  */
as_t
as4path_origin (struct as4path *as4path)
{
  u_int8_t *pnt;
  u_int8_t *end;
  struct as4segment *as4segment = NULL;

  if (! as4path)
    return 0;

  if (! as4path->length)
    return 0;

  pnt = as4path->data;
  end = as4path->data + as4path->length;

  while (pnt < end)
    {
      as4segment = (struct as4segment *) pnt;
      pnt += (as4segment->length * AS4_VALUE_SIZE) + AS4_HEADER_SIZE;
    }

  if (! as4segment || as4segment->length == 0)
    return 0;

  if (as4segment->type != BGP_AS_SEQUENCE
      && as4segment->type != BGP_AS_CONFED_SEQUENCE)
    return 0;

  return pal_hton32 (as4segment->asval[as4segment->length - 1]);
}

/* Compare leftmost AS value for MED check.  If as1's leftmost AS and
   as2's leftmost AS is same return 1. */
int
as4path_cmp_left (struct as4path *as4path1, struct as4path *as4path2)
{
  struct as4segment *seg1;
  struct as4segment *seg2;
  as_t as1;
  as_t as2;

  if (!as4path1 || !as4path2)
    return 0;

  seg1 = (struct as4segment *) as4path1->data;
  seg2 = (struct as4segment *) as4path2->data;

  while (seg1 && seg1->length
         && (seg1->type == BGP_AS_CONFED_SEQUENCE || seg1->type == BGP_AS_CONFED_SET))
    seg1 = (struct as4segment *) ((u_int8_t *) seg1 + AS4SEGMENT_LEN (seg1));
  while (seg2 && seg2->length
         && (seg2->type == BGP_AS_CONFED_SEQUENCE || seg2->type == BGP_AS_CONFED_SET))
    seg2 = (struct as4segment *) ((u_int8_t *) seg2 + AS4SEGMENT_LEN (seg2));

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
as4path_cmp_left_confed (struct as4path *as4path1, struct as4path *as4path2)
{
  struct as4segment *seg1;
  struct as4segment *seg2;

  as_t as1;
  as_t as2;

 if (!as4path1 || !as4path2)
    return 0;

  if (as4path1->count || as4path2->count)
    return 0;

  seg1 = (struct as4segment *) as4path1->data;
  seg2 = (struct as4segment *) as4path2->data;

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

/* Delete first sequential BGP_AS_CONFED_SEQUENCE from as4path and any
   immediately following segments of the type of BGP_AS_CONFED_SET from
   AS_PATH attribute.  */
struct as4path *
as4path_delete_confed_seq (struct as4path *as4path)
{
  int seglen;
  struct as4segment *as4segment;

  if (! as4path)
    return as4path;

  as4segment = (struct as4segment *) as4path->data;

  while (as4segment)
    {
      if (as4segment->type != BGP_AS_CONFED_SEQUENCE
          && as4segment->type != BGP_AS_CONFED_SET)
        return as4path;

      seglen = AS4SEGMENT_LEN (as4segment);

      if (seglen == as4path->length)
        {
          XFREE (MTYPE_AS4_SEG, as4path->data);
          as4path->data = NULL;
          as4path->length = 0;
        }
      else
        {
          pal_mem_cpy (as4path->data, as4path->data + seglen,
                  as4path->length - seglen);
          as4path->data = XREALLOC (MTYPE_AS4_SEG, as4path->data,
                                   as4path->length - seglen);
          as4path->length -= seglen;
        }

      as4segment = (struct as4segment *) as4path->data;
    }
  return as4path;
}

/* Add new AS number to the leftmost part of the as4path as
   BGP_AS_CONFED_SEQUENCE.  */
struct as4path*
as4path_add_confed_seq (struct as4path *as4path, as_t asno)
{
  return as4path_add_one_as (as4path, asno, BGP_AS_CONFED_SEQUENCE);
}

/* Add new as value to as path structure. */
void
as4path_as_add (struct as4path *as, as_t asno)
{
  struct as4segment *as4segment;
  u_int8_t *pnt;
  u_int8_t *end;

  if (!as)
    return;

  /* Increase as->data for new as value. */
  as->data = XREALLOC (MTYPE_AS4_SEG, as->data, as->length + 4);
  as->length += 4;

  pnt = as->data;
  end = as->data + as->length;
  as4segment = (struct as4segment *) pnt;

  /* Last segment search procedure. */
  while (pnt + 4 < end)
    {
      as4segment = (struct as4segment *) pnt;

      /* We add 2 for segment_type and segment_length and segment
         value as4segment->length * 4. */
      pnt += (AS4_HEADER_SIZE + (as4segment->length * AS4_VALUE_SIZE));
    }

  as4segment->asval[as4segment->length] = pal_hton32 (asno);
  as4segment->length++;

  return;
}

/* Add new as segment to the as path. */
void
as4path_segment_add (struct as4path *as, int type)
{
  struct as4segment *as4segment;

  if (as->data == NULL)
    {
      as->data = XCALLOC (MTYPE_AS4_SEG, 2);
      as4segment = (struct as4segment *) as->data;
      as->length = 2;
    }
  else
    {
      as->data = XREALLOC (MTYPE_AS4_SEG, as->data, as->length + 2);
      as4segment = (struct as4segment *) (as->data + as->length);
      as->length += 2;
    }

  as4segment->type = type;
  as4segment->length = 0;

  return;
}

struct as4path *
as4path_empty ()
{
  return as4path_parse (NULL, 0, NULL);
}

struct as4path *
as4path_empty_get ()
{
  struct as4path *as4path;

  as4path = as4path_new ();
  return as4path_intern (as4path);
}

struct as4path *
aspath4B_empty ()
{
  return aspath4B_parse (NULL, 0);
}


struct as4path *
aspath4B_empty_get ()
{
  struct as4path *aspath4B;

  aspath4B = as4path_new ();
  return aspath4B_intern (aspath4B);
}

u_int32_t
as4path_count ()
{
  return bgp_as4hash_tab->count;
}
u_int32_t
aspath4B_count ()
{
  return bgp_aspath4Bhash_tab->count;
}

/*
   Theoretically, one as path can have:

   One BGP packet size should be less than 4096.
   One BGP attribute size should be less than 4096 - BGP header size.
   One BGP as4path size should be less than 4096 - BGP header size -
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
as4path_gettoken (char *buf, enum as_token *token, unsigned int *asno)
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
      unsigned int asval;

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

struct as4path *
as4path_str2as4path (char *str)
{
  enum as_token token;
  unsigned short as_type;
  unsigned int asno;
  struct as4path *as4path;
  int needtype;

  as4path = as4path_new ();

  /* We start default type as BGP_AS_SEQUENCE. */
  as_type = BGP_AS_SEQUENCE;
  needtype = 1;

  while ((str = as4path_gettoken (str, &token, &asno)) != NULL)
    {
      switch (token)
        {
        case as_token_asval:
          if (needtype)
            {
              as4path_segment_add (as4path, as_type);
              needtype = 0;
            }
          as4path_as_add (as4path, asno);
          break;
        case as_token_set_start:
          as_type = BGP_AS_SET;
          as4path_segment_add (as4path, as_type);
          needtype = 0;
          break;
        case as_token_set_end:
          as_type = BGP_AS_SEQUENCE;
          needtype = 1;
          break;
        case as_token_confed_start:
          as_type = BGP_AS_CONFED_SEQUENCE;
          as4path_segment_add (as4path, as_type);
          needtype = 0;
          break;
        case as_token_confed_end:
          as_type = BGP_AS_SEQUENCE;
          needtype = 1;
          break;
        case as_token_unknown:
        default:
          if (as4path)
            as4path_free (as4path);
          return NULL;
          break;
        }
    }

  as4path->str = as4path_make_str_count (as4path);

  return as4path;
}

/* Make hash value by raw as4path data. */
u_int32_t
as4path_key_make (void *arg)
{
  struct as4path *as4path;
  u_int32_t length;
  u_int32_t key;
  u_int8_t *pnt;

  as4path = (struct as4path *) arg;
  key = 0;

  length = as4path->length;
  pnt = as4path->data;

  while (length)
    key += pnt[--length];

  return key;
}

/* If two as4path have same value then return 1 else return 0 */
bool_t
as4path_cmp (void *arg1, void *arg2)
{
  struct as4path *as1;
  struct as4path *as2;

  as1 = (struct as4path *) arg1;
  as2 = (struct as4path *) arg2;

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

/* AS4 path hash initialize. */
void
as4path_init (void)
{
  bgp_as4hash_tab = hash_create (as4path_key_make, as4path_cmp);
}

void
aspath4B_init (void)
{
  bgp_aspath4Bhash_tab = hash_create (as4path_key_make, as4path_cmp);
}


/* return  as path value */
u_int8_t *
as4path_print (struct as4path *as)
{
  return as->str;
}

struct hash *
as4path_hash (void)
{
  return bgp_as4hash_tab;
}
struct hash *
aspath4B_hash (void)
{
  return bgp_aspath4Bhash_tab;
}
#endif /* HAVE_EXT_CAP_ASN */

