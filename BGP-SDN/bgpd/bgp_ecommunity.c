/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

struct ecommunity *
ecommunity_new ()
{
  struct ecommunity *new;

  new = XCALLOC (MTYPE_ECOMMUNITY, sizeof (struct ecommunity));

  return new;
}

void
ecommunity_free (struct ecommunity *ecom)
{
  if (! ecom)
    return;

  if (ecom->val)
    XFREE (MTYPE_ECOMMUNITY_VAL, ecom->val);

  if (ecom->str)
    XFREE (MTYPE_ECOMMUNITY_STR, ecom->str);

  XFREE (MTYPE_ECOMMUNITY, ecom);
}

void *
ecommunity_hash_alloc (void *val)
{
  struct ecommunity *ecom_in;
  struct ecommunity *ecom;

  ecom_in = (struct ecommunity *) val;
  ecom = ecommunity_new ();

  ecom->size = ecom_in->size;
  ecom->val = XCALLOC (MTYPE_ECOMMUNITY_VAL, ecom_in->size * BGP_RD_SIZE);
  pal_mem_cpy (ecom->val, ecom_in->val, ecom_in->size * BGP_RD_SIZE);

  return ecom;
}

struct ecommunity *
ecommunity_parse (u_int8_t *pnt, u_int16_t length)
{
  struct ecommunity tmp;
  struct ecommunity *find;

  if (length % BGP_RD_SIZE)
    return NULL;

  tmp.size = length / BGP_RD_SIZE;
  tmp.val = pnt;

  find = (struct ecommunity *) hash_get (bgp_ecomhash_tab, &tmp,
                                         ecommunity_hash_alloc);
  if (find)
    find->refcnt++;

  return find;
}

struct ecommunity *
ecommunity_dup (struct ecommunity *ecom)
{
  struct ecommunity *new;

  new = XCALLOC (MTYPE_ECOMMUNITY, sizeof (struct ecommunity));

  new->size = ecom->size;
  if (new->size)
    {
      new->val = XCALLOC (MTYPE_ECOMMUNITY_VAL, ecom->size * BGP_RD_SIZE);
      pal_mem_cpy (new->val, ecom->val, ecom->size * BGP_RD_SIZE);
    }
  else
    new->val = NULL;
  return new;
}

struct ecommunity *
ecommunity_merge (struct ecommunity *ecom1, struct ecommunity *ecom2)
{
  if (ecom1->val)
    ecom1->val = XREALLOC (MTYPE_ECOMMUNITY_VAL, ecom1->val,
                           (ecom1->size + ecom2->size) * BGP_RD_SIZE);
  else
    ecom1->val = XCALLOC (MTYPE_ECOMMUNITY_VAL,
                          (ecom1->size + ecom2->size) * BGP_RD_SIZE);

  pal_mem_cpy (ecom1->val + (ecom1->size * BGP_RD_SIZE),
          ecom2->val, ecom2->size * BGP_RD_SIZE);
  ecom1->size += ecom2->size;

  return ecom1;
}

struct ecommunity *
ecommunity_intern (struct ecommunity *ecom)
{
  struct ecommunity *find;

  pal_assert (ecom->refcnt == 0);

  find = (struct ecommunity *) hash_get (bgp_ecomhash_tab, ecom, hash_alloc_intern);

  if (find != ecom)
    ecommunity_free (ecom);

  find->refcnt++;

  return find;
}

void
ecommunity_unintern (struct ecommunity *ecom)
{
  if (ecom->refcnt)
    ecom->refcnt--;

  if (ecom->refcnt == 0)
    {
      struct ecommunity *ret;

      ret = (struct ecommunity *) hash_release (bgp_ecomhash_tab, ecom);
      pal_assert (ret != NULL);

      ecommunity_free (ecom);
    }
}

u_int32_t
ecommunity_hash_make (void *arg)
{
  struct ecommunity *ecom;
  u_int8_t *pnt;
  u_int32_t key;
  u_int32_t c;

  ecom = (struct ecommunity *) arg;
  pnt = (u_int8_t *)ecom->val;
  key = 0;

  for (c = 0; c < ecom->size * BGP_RD_SIZE; c++)
    key += pnt[c];

  return key;
}

bool_t
ecommunity_cmp (void *arg1, void *arg2)
{
  struct ecommunity *ecom1;
  struct ecommunity *ecom2;

  ecom1 = (struct ecommunity *) arg1;
  ecom2 = (struct ecommunity *) arg2;

  if (ecom1 == NULL && ecom2 == NULL)
    return 1;
  if (ecom1 == NULL || ecom2 == NULL)
    return 0;

  if (ecom1->size == ecom2->size
      && ! pal_mem_cmp (ecom1->val, ecom2->val,
                        ecom1->size * BGP_RD_SIZE))
    return PAL_TRUE;

  return PAL_FALSE;
}

s_int32_t
ecommunity_add_val (struct ecommunity *ecom, struct bgp_rd *rd)
{
  s_int32_t ret;
  s_int32_t c;
  u_int8_t *p;

  ret = 0;

  if (! ecom->val)
    {
      ecom->size++;
      ecom->val = XCALLOC (MTYPE_ECOMMUNITY_VAL, ecom_length (ecom));
      pal_mem_cpy (ecom->val, rd->brd_val, BGP_RD_SIZE);

      ret = 0;
      goto EXIT;
    }

  c = 0;
  for (p = ecom->val; c < ecom->size; p += BGP_RD_SIZE, c++)
    {
      ret = pal_mem_cmp (p, rd->brd_val, BGP_RD_SIZE);
      if (! ret)
        {
          ret = -1;
          goto EXIT;
        }

      if (ret > 0)
        break;
    }

  ecom->size++;
  ecom->val = XREALLOC (MTYPE_ECOMMUNITY_VAL, ecom->val,
                        ecom_length (ecom));

  pal_mem_move (ecom->val + (c + 1) * BGP_RD_SIZE,
                ecom->val + c * BGP_RD_SIZE,
                (ecom->size - 1 - c) * BGP_RD_SIZE);
  pal_mem_cpy (ecom->val + c * BGP_RD_SIZE, rd->brd_val, BGP_RD_SIZE);

  ret = 0;

EXIT:

  return ret;
}

s_int32_t
ecommunity_del_val (struct ecommunity *ecom, struct bgp_rd *rd)
{
  u_int8_t *p, *q;
  s_int32_t ret;

  ret = 0;

  if (! ecom->val || ecom->size == 0)
    {
      ret = -1;
      goto EXIT;
    }

  q = ecom->val + ecom_length (ecom);
  for (p = ecom->val; p < q; p += BGP_RD_SIZE)
    {
      if (! pal_mem_cmp (p, rd->brd_val, BGP_RD_SIZE))
        {
          pal_mem_move (p, p + BGP_RD_SIZE, q - p - BGP_RD_SIZE);
          ecom->size--;

          if (ecom->size)
            ecom->val = XREALLOC (MTYPE_ECOMMUNITY_VAL,
                                  ecom->val, ecom_length (ecom));
          else
            {
              XFREE (MTYPE_ECOMMUNITY_VAL, ecom->val);
              ecom->val = NULL;
            }

          goto EXIT;
        }
    }

  ret = -1;

EXIT:

  return ret;
}

/* if ecom1 contains ecom2, return 1. otherwise return 0. */
int
ecommunity_match (struct ecommunity *ecom1, struct ecommunity *ecom2)
{
  int i = 0;
  int j = 0;

  if (ecom1->size < ecom2->size)
    return 0;

  while (i < ecom1->size && j < ecom2->size)
    {
      if (pal_mem_cmp (ecom1->val + i * 8, ecom2->val + j * 8, 8) == 0)
        j++;
      i++;
    }

  if (j == ecom2->size)
    return 1;
  else
    return 0;
}

/* If val is included in extended communities attribute, return
   1.  Otherwise return 0.  */
int
ecommunity_include (struct ecommunity *ecom, struct bgp_rd *rd)
{
  u_int8_t *ptr;

  if (ecom == NULL)
    return 0;

  for (ptr = ecom->val;
       ptr < ecom->val + ecom->size * BGP_RD_SIZE;
       ptr += BGP_RD_SIZE)
    if (! pal_mem_cmp (ptr, rd->brd_val, BGP_RD_SIZE))
      return 1;

  return 0;
}

/* If two extended communities attribute have at least one common
   value, return the pointer.  If there is no common value, return
   NULL.  */
struct bgp_rd *
ecommunity_intersect (struct ecommunity *ecom1, struct ecommunity *ecom2)
{
  u_int8_t *p, *q;

  if (! ecom1 || ! ecom1->size || ! ecom1->val)
    return NULL;

  if (! ecom2 || ! ecom2->size || ! ecom2->val)
    return NULL;

  for (p = ecom1->val; p < ecom1->val + ecom_length(ecom1); p += BGP_RD_SIZE)
    for (q = ecom2->val; q < ecom2->val + ecom_length(ecom2); q += BGP_RD_SIZE)
      if (! pal_mem_cmp (p, q, BGP_RD_SIZE))
        return (struct bgp_rd *) p;

  return NULL;
}

/* Extended Communities token enum. */
enum ecommunity_token
{
  ecommunity_token_rt,
  ecommunity_token_soo,
  ecommunity_token_val,
  ecommunity_token_unknown
};

/* Get next Extended Communities token from the string. */
u_int8_t *
ecommunity_gettoken (u_int8_t *str, struct ecommunity_val *eval,
                     enum ecommunity_token *token)
{
  int ret;
  int dot = 0;
  int digit = 0;
  int separator = 0;
  u_int32_t val_low = 0;
  u_int32_t val_high = 0;
  u_int8_t *p = str;
  struct pal_in4_addr ip;
  u_int8_t ipstr[INET_ADDRSTRLEN + 1];

  /* Skip white space. */
  while (pal_char_isspace ((int) *p))
    {
      p++;
      str++;
    }

  /* Check the end of the line. */
  if (*p == '\0')
    return NULL;

  /* "rt" and "soo" keyword parse. */
  if (! pal_char_isdigit ((int) *p))
    {
      /* "rt" match check.  */
      if (pal_char_tolower ((int) *p) == 'r')
        {
          p++;
           if (pal_char_tolower ((int) *p) == 't')
            {
              p++;
              *token = ecommunity_token_rt;
              return p;
            }
          if (pal_char_isspace ((int) *p) || *p == '\0')
            {
              *token = ecommunity_token_rt;
              return p;
            }
          goto error;
        }
      /* "soo" match check.  */
      else if (pal_char_tolower ((int) *p) == 's')
        {
          p++;
           if (pal_char_tolower ((int) *p) == 'o')
            {
              p++;
              if (pal_char_tolower ((int) *p) == 'o')
                {
                  p++;
                  *token = ecommunity_token_soo;
                  return p;
                }
              if (pal_char_isspace ((int) *p) || *p == '\0')
                {
                  *token = ecommunity_token_soo;
                  return p;
                }
              goto error;
            }
          if (pal_char_isspace ((int) *p) || *p == '\0')
            {
              *token = ecommunity_token_soo;
              return p;
            }
          goto error;
        }
      goto error;
    }

  while (pal_char_isdigit ((int) *p) || *p == ':' || *p == '.')
    {
      if (*p == ':')
        {
          if (separator)
            goto error;

          separator = 1;
          digit = 0;

          if (dot)
            {
              if ((p - str) > INET_ADDRSTRLEN)
                goto error;

              pal_mem_set (ipstr, 0, INET_ADDRSTRLEN + 1);
              pal_mem_cpy (ipstr, str, p - str);

              ret = pal_inet_pton (AF_INET, ipstr, &ip);
              if (ret == 0)
                goto error;
            }
          else
            val_high = val_low;

          val_low = 0;
        }
      else if (*p == '.')
        {
          if (separator)
            goto error;
          dot++;
          if (dot > 4)
            goto error;
        }
      else
        {
          digit = 1;
          val_low *= 10;
          val_low += (*p - '0');
        }
      p++;
    }

  /* Low digit part must be there. */
  if (! digit || ! separator)
    goto error;

  /* Encode result into routing distinguisher.  */
  if (dot)
    {
      eval->val[0] = ECOMMUNITY_ENCODE_IP;
      eval->val[1] = 0;
      pal_mem_cpy (&eval->val[2], &ip, sizeof (struct pal_in4_addr));
      eval->val[6] = (val_low >> 8) & 0xff;
      eval->val[7] = val_low & 0xff;
    }
  else
    {
      if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        {
          /*as per draft-rekhter-as4octet-ext-community-03.txt */
          eval->val[0] = ECOMMUNITY_ENCODE_AS4;
          eval->val[1] = 0;
          eval->val[2] = (val_high >>24) & 0xff;
          eval->val[3] = (val_high >>16) & 0xff;
          eval->val[4] = (val_high >>8) & 0xff;
          eval->val[5] = (val_high) & 0xff;
          eval->val[6] = (val_low >>8) & 0xff;
          eval->val[7] = val_low & 0xff;
        }
      else
        {  
          eval->val[0] = ECOMMUNITY_ENCODE_AS;
          eval->val[1] = 0;
          eval->val[2] = (val_high >>8) & 0xff;
          eval->val[3] = val_high & 0xff;
          eval->val[4] = (val_low >>24) & 0xff;
          eval->val[5] = (val_low >>16) & 0xff;
          eval->val[6] = (val_low >>8) & 0xff;
          eval->val[7] = val_low & 0xff;
        }
    }
  *token = ecommunity_token_val;
  return p;

 error:
  *token = ecommunity_token_unknown;
  return p;
}

/* Convert string to routing distinguisher.  First two octet format
   is differenct with extended communities attribute.  */
int
ecommunity_str2rd (u_int8_t *str, struct bgp_rd *rd)
{
  enum ecommunity_token token;

  /* Get routing distinguisher as extended community format.  */
  str = ecommunity_gettoken (str, (struct ecommunity_val *) rd, &token);

  /* Error check.  */
  if (! str || token != ecommunity_token_val)
    return -1;

  /* Set type to second octet.  First octet is zero.  */
  rd->brd_val[1] = rd->brd_val[0];
  rd->brd_val[0] = 0;

  return 0;
}

/* Convert Route-Distinguisher value to String */
int
ecommunity_rd2str (int encode, struct bgp_rd *rd,
                   u_int8_t *str, size_t size)
{
  struct ecommunity_as eas;
  struct ecommunity_ip eip;
  const u_int8_t *pnt;

  /* First two octet is type, not value.  */
  pnt = &rd->brd_val[2];

  if (encode == ECOMMUNITY_ENCODE_AS4)
    {
      eas.as = (*pnt++ << 24);
      eas.as |= (*pnt++ << 16);
      eas.as |= (*pnt++ << 8);
      eas.as |= (*pnt++);

      eas.val = (*pnt++ << 8);
      eas.val |= (*pnt++);

      return zsnprintf (str, size, "%u:%lu", eas.as, eas.val);
    }


  if (encode == ECOMMUNITY_ENCODE_AS)
    {
      eas.as = (*pnt++ << 8);
      eas.as |= (*pnt++);

      eas.val = (*pnt++ << 24);
      eas.val |= (*pnt++ << 16);
      eas.val |= (*pnt++ << 8);
      eas.val |= (*pnt++);

      return zsnprintf (str, size, "%u:%lu", eas.as, eas.val);
    }
  else if (encode == ECOMMUNITY_ENCODE_IP)
    {
      pal_mem_cpy (&eip.ip, pnt, 4);
      pnt += 4;
      eip.val = (*pnt++ << 8);
      eip.val |= (*pnt++);

      return zsnprintf (str, size, "%r:%u", &eip.ip, eip.val);
    }

  *str = '\0';
  return 0;
}

/* Convert string to extended community attribute.

   When type is already known, please specify both str and type.  str
   should not include keyword such as "rt" and "soo".  Type is
   ECOMMUNITY_ROUTE_TARGET or ECOMMUNITY_SITE_ORIGIN.
   keyword_included should be zero.

   For example route-map's "set extcommunity" command case:

   "rt 100:1 100:2 100:3"        -> str = "100:1 100:2 100:3"
                                    type = ECOMMUNITY_ROUTE_TARGET
                                    keyword_included = 0

   "soo 100:1"                   -> str = "100:1"
                                    type = ECOMMUNITY_SITE_ORIGIN
                                    keyword_included = 0

   When string includes keyword for each extended community value.
   Please specify keyword_included as non-zero value.

   For example standard extcommunity-list case:

   "rt 100:1 rt 100:2 soo 100:1" -> str = "rt 100:1 rt 100:2 soo 100:1"
                                    type = 0
                                    keyword_include = 1
*/
struct ecommunity *
ecommunity_str2com (u_int8_t *str, int type, int keyword_included)
{
  struct ecommunity *ecom = NULL;
  enum ecommunity_token token;
  struct ecommunity_val eval;
  int keyword = 0;

  while ((str = ecommunity_gettoken (str, &eval, &token)))
    {
      switch (token)
        {
        case ecommunity_token_rt:
        case ecommunity_token_soo:
          if (! keyword_included || keyword)
            {
              if (ecom)
                ecommunity_free (ecom);
              return NULL;
            }
          keyword = 1;

          if (token == ecommunity_token_rt)
            {
              type = ECOMMUNITY_ROUTE_TARGET;
            }
          if (token == ecommunity_token_soo)
            {
              type = ECOMMUNITY_SITE_ORIGIN;
            }
          break;
        case ecommunity_token_val:
          if (keyword_included)
            {
              if (! keyword)
                {
                  if (ecom)
                    ecommunity_free (ecom);
                  return NULL;
                }
              keyword = 0;
            }
          if (ecom == NULL)
            ecom = ecommunity_new ();
          eval.val[1] = type;
          ecommunity_add_val (ecom, (struct bgp_rd *) &eval);
          break;
        case ecommunity_token_unknown:
        default:
          if (ecom)
            ecommunity_free (ecom);
          return NULL;
          break;
        }
    }
  return ecom;
}

/* Convert extended community attribute to string.

   Due to historical reason of industry standard implementation, there
   are three types of format.

   route-map set extcommunity format
        "rt 100:1 100:2"
        "soo 100:3"

   extcommunity-list
        "rt 100:1 rt 100:2 soo 100:3"

   "show ip bgp" and extcommunity-list regular expression matching
        "RT:100:1 RT:100:2 SoO:100:3"

   For each formath please use below definition for format:

   ECOMMUNITY_FORMAT_ROUTE_MAP
   ECOMMUNITY_FORMAT_COMMUNITY_LIST
   ECOMMUNITY_FORMAT_DISPLAY
*/
u_int8_t *
ecommunity_ecom2str (struct ecommunity *ecom, int format)
{
  int i;
  u_int8_t *pnt;
  struct ecommunity_as eas;
  struct ecommunity_ip eip;
  int encode = 0;
  int type = 0;
#define ECOMMUNITY_STR_DEFAULT_LEN  26
  int str_size;
  int str_pnt;
  u_int8_t *str_buf;
  u_int8_t *prefix;
  int len = 0;
  int first = 1;

  if (ecom->size == 0)
    {
      str_buf = XCALLOC (MTYPE_ECOMMUNITY_STR, 1);
      str_buf[0] = '\0';
      return str_buf;
    }

  /* Prepare buffer.  */
  str_buf = XCALLOC (MTYPE_ECOMMUNITY_STR, ECOMMUNITY_STR_DEFAULT_LEN + 1);
  str_size = ECOMMUNITY_STR_DEFAULT_LEN + 1;
  str_pnt = 0;

  for (i = 0; i < ecom->size; i++)
    {
      pnt = ecom->val + (i * 8);

      /* High-order octet of type. */
      encode = *pnt++;
      if (encode != ECOMMUNITY_ENCODE_AS && encode != ECOMMUNITY_ENCODE_IP)
        {
          if (str_buf)
            XFREE (MTYPE_ECOMMUNITY_STR, str_buf);
          return "Unknown";
        }

      /* Low-order octet of type. */
      type = *pnt++;
      if (type !=  ECOMMUNITY_ROUTE_TARGET && type != ECOMMUNITY_SITE_ORIGIN)
        {
          if (str_buf)
            XFREE (MTYPE_ECOMMUNITY_STR, str_buf);
          return "Unknown";
        }

      switch (format)
        {
        case ECOMMUNITY_FORMAT_COMMUNITY_LIST:
          prefix = (type == ECOMMUNITY_ROUTE_TARGET ? "rt " : "soo ");
          break;
        case ECOMMUNITY_FORMAT_DISPLAY:
          prefix = (type == ECOMMUNITY_ROUTE_TARGET ? "RT:" : "SoO:");
          break;
        case ECOMMUNITY_FORMAT_ROUTE_MAP:
          prefix = "";
          break;
        default:
          if (str_buf)
            XFREE (MTYPE_ECOMMUNITY_STR, str_buf);
          return "Unknown";
          break;
        }

      /* Make it sure size is enough.  */
      while (str_pnt + ECOMMUNITY_STR_DEFAULT_LEN >= str_size)
        {
          str_size *= 2;
          str_buf = XREALLOC (MTYPE_ECOMMUNITY_STR, str_buf, str_size);
        }

      /* Space between each value.  */
      if (! first)
        str_buf[str_pnt++] = ' ';

      /* Put string into buffer.  */
      if (encode == ECOMMUNITY_ENCODE_AS)
        {
          eas.as = (*pnt++ << 8);
          eas.as |= (*pnt++);

          eas.val = (*pnt++ << 24);
          eas.val |= (*pnt++ << 16);
          eas.val |= (*pnt++ << 8);
          eas.val |= (*pnt++);

          len = pal_snprintf (str_buf + str_pnt, str_size - str_pnt,
                              "%s%d:%d", prefix, eas.as, eas.val);
          str_pnt += len;
          first = 0;
        }
      else if (encode == ECOMMUNITY_ENCODE_IP)
        {
          pal_mem_cpy (&eip.ip, pnt, 4);
          pnt += 4;
          eip.val = (*pnt++ << 8);
          eip.val |= (*pnt++);

          len = zsnprintf (str_buf + str_pnt, str_size - str_pnt,
                           "%s%r:%d", prefix, &eip.ip, eip.val);
          str_pnt += len;
          first = 0;
        }
    }
  return str_buf;
}

/* Transform RFC2547 routing distinguisher to extended communities
   type.  */
void
ecommunity_rd2com (struct bgp_rd *rd, u_int8_t type)
{
  rd->brd_val[0] = rd->brd_val[1];
  rd->brd_val[1] = type;
}

/* Initialize Extended Comminities related hash. */
void
ecommunity_init ()
{
  bgp_ecomhash_tab = hash_create (ecommunity_hash_make, ecommunity_cmp);
}

/* Extract the OSPF extended community attributes from 
   ecommunity  basing on the the type of ext_type required */
bool_t
ecommunity_get_ext_attribute (struct ecommunity *ecommunity,
                              struct ecomm_ospf_ext *ext_attr,
                              int ext_type)
{
  u_int8_t *ecomm = NULL;
  u_int8_t *pnt = NULL;
  u_int8_t size = 0;
  bool_t ret = PAL_FALSE;

  if (!ecommunity)
    return ret;

  if (!ecommunity->val)
    return ret;
     
  pnt = ecommunity->val;

  while (size < (ecommunity->size *8))
   {
     /* set ecomm to firt byte of extended attribute */
     ecomm = pnt;
     ecomm ++;
     if (*ecomm == ext_type)
       {
         ecomm --;
         pal_mem_cpy (ext_attr, ecomm, BGP_RD_SIZE);
         return PAL_TRUE;
       }

     /* move next extended attribute */
     pnt +=8;
     size +=8;
   } /* end of while (pnt) */

return ret;
}

/***************************************************************************
 * Function       : ecommuity_logging                                      *
 * Description    : this function will log recieved ecommunity in  bgpd    *
 *                  update message.                                        * 
 * Input :                                                                 *
 *    pnt         : The 8 byte extended community attribute                *
 *                                                                         *  
 ***************************************************************************/

int
ecommunity_logging (struct ecommunity *ecommunity)
{
  int ret = 0;
  u_int8_t *ecomm = NULL;
  u_int8_t *pnt = NULL;
  u_int8_t type = 0;
  u_int8_t size = 0;
  char ecomm_str [512];

  if (!ecommunity->val)
    {
       ret = -1;
       goto EXIT;
    }
  pnt = ecommunity->val;

  while (size < (ecommunity->size *8))
   {
     pal_mem_set (ecomm_str, 0x00, sizeof (ecomm_str));
     /* set ecomm to firt byte of extended attribute */
     ecomm = pnt;
     type = *ecomm & 0x0f;

     if ( *ecomm & ECOMMUNITY_NON_TRANSITIVE_ATTR)
       pal_strcpy (ecomm_str, "Non - Trasitive: ");
     else
       pal_strcpy (ecomm_str, "Transitive : ");

     /* entire range from 0x00 - 0xff is a valid range as per IANA */
     ecomm ++;
  
     /* log the AS specific sub-types  */
     if (type == ECOMMUNITY_ENCODE_AS || type == ECOMMUNITY_ENCODE_AS4)
       {
         if (type == ECOMMUNITY_ENCODE_AS)
           pal_strcat (ecomm_str, "AS Sepcific ");
         if (type == ECOMMUNITY_ENCODE_AS4)
           pal_strcat (ecomm_str, "AS 4 octect Sepcific ");
  
         switch (*ecomm)
           {
            case ECOMMUNITY_ROUTE_TARGET: pal_strcat (ecomm_str, 
                                                      "Route_target");
            break;
            case ECOMMUNITY_SITE_ORIGIN : pal_strcat (ecomm_str, "Route_orgin");
            break;
            case ECOMMUNITY_OSPF_DOMAIN_ID : pal_strcat (ecomm_str,
                                                         "OSPF Domain ID : ");
            break;
            case ECOMMUNITY_SOURCE_AS : pal_strcat (ecomm_str, "Source AS ");
            break;
            default : pal_strcat (ecomm_str, "Unknown sub-type :");
            break;
          }
       }
  
     /* log the ipv4 address specific sub-types */
     else if (type == ECOMMUNITY_ENCODE_IP)
       {
         pal_strcat (ecomm_str, "IPV4 Address Sepcific ");
  
         switch (*ecomm)
           {
             case ECOMMUNITY_ROUTE_TARGET: pal_strcat (ecomm_str, 
                                                       "Route_target");
             break;
             case ECOMMUNITY_SITE_ORIGIN : pal_strcat (ecomm_str,
                                                       "Route_orgin");
             break;
             case ECOMMUNITY_OSPF_DOMAIN_ID : pal_strcat (ecomm_str,
                                                          "OSPF Domain ID : ");
             break;
             case ECOMMUNITY_OSPF_ROUTER_ID : pal_strcat (ecomm_str,
                                                          "OSPF Router ID : ");
             break;
             case ECOMMUNITY_VRF_ROUTE_IMPORT : pal_strcat (ecomm_str,
                                                      "OSPF VRF Route Import ");
             break;
             default: pal_strcat (ecomm_str, "Unknown sub-type ");
             break;
          }
       }
  
     /*log the Opaque sub-types */
     else if (type == ECOMMUNITY_OPAQUE)
       {
         pal_strcat (ecomm_str, "Opaque specific ");
         switch (*ecomm)
           {
             case ECOMMUNITY_OSPF_ROUTE_TYPE: pal_strcat (ecomm_str,
                                                           "OSPF route type ");
             break;
             default : pal_strcat (ecomm_str, "Unkwown sub-type :");
              break;
           }
       }
  
      /* if the type is unknown */
      if ((type !=ECOMMUNITY_ENCODE_AS) 
          && (type != ECOMMUNITY_ENCODE_AS4)
          && (type != ECOMMUNITY_ENCODE_IP)
          && (type != ECOMMUNITY_OPAQUE))
        zlog (&BLG, NULL, ZLOG_WARN, "unknown type : %d \n", type);
      else
        {
          pal_strcat (ecomm_str, " \n");
          /* log the attribute */
         zlog (&BLG, NULL, ZLOG_INFO, ecomm_str);
        }
     /* move next extended attribute */
     pnt += 8;
     size += 8;
   } /* end of while (pnt) */
  
  return ret;

EXIT:
  return ret;
}

/***************************************************************************
 * Function       : ecommunity_com2str                                     *
 * Description    : this function will convert given ecommunity into       * 
 *                  string format.                                         * 
 * Input :                                                                 *
 *    ecom        : Extended community                                     *
 *                                                                         *
 * output :                                                                *
 *   str          : Ecommunity in string format                            *         
 *                                                                         *  
 ***************************************************************************/
u_int8_t *
ecommunity_com2str (struct ecommunity *ecom)
{
  int i = 0;
  char *str = NULL;
  char *pnt = NULL;
  int len= 0;
  int encode = 0;
  int first = 0;
  struct ecommunity_as eas;
  struct ecommunity_ip eip;
  struct prefix p;
  char buff [50];

  if (!ecom)
   return NULL; 

  /* When communities attribute is empty.  */
  if (ecom->size == 0)
    {
      str = XMALLOC (MTYPE_ECOMMUNITY, 1);
      str[0] = '\0';
      return str;
    }

   for (i = 0; i < ecom->size; i++)
     {
       pal_mem_set (&eas, 0, sizeof (struct ecommunity_as));
       pnt = ecom->val + (i * 8);
       pnt++;
       if (*pnt == ECOMMUNITY_ROUTE_TARGET)
         len += pal_strlen (" rt ");
       else if (*pnt == ECOMMUNITY_SITE_ORIGIN)
         len += pal_strlen (" soo ");
        else if (*pnt == ECOMMUNITY_OPAQUE)
         len += pal_strlen (" opaque ");
         /* calculate bytes required for ASN:NN or IP:NN */
         len += pal_strlen (" 255.255.255.255:65535 ");
     }  
   /* Allocate memory.  */
   str = pnt = XMALLOC (MTYPE_COMMUNITY_STR, len);
   first = 1;

   /* Fill in string.  */
   for (i = 0; i < ecom->size; i++)
     {
       if (first)
         first =0;
       else
         *pnt ++ = ' ';

       pnt = ecom->val + (i * 8);

       if (!pnt)
         break;

       encode = *pnt;
       pnt++;
       if (*pnt == ECOMMUNITY_ROUTE_TARGET)
         {
           pal_strcpy (pnt, " rt ");
           pnt += pal_strlen (" rt ");
         }
       else if (*pnt == ECOMMUNITY_SITE_ORIGIN)
         {
           pal_strcpy (pnt, " soo ");
           pnt += pal_strlen (" soo ");
         }
        else if (*pnt == ECOMMUNITY_OPAQUE)
          {
            pal_strcpy (pnt, " opaque ");
            pnt += pal_strlen (" opaque ");
          }
        if (encode == ECOMMUNITY_ENCODE_AS)
          {
            eas.as = (*pnt++ << 8);
            eas.as |= (*pnt++);

            eas.val = (*pnt++ << 24);
            eas.val |= (*pnt++ << 16);
            eas.val |= (*pnt++ << 8);
            eas.val |= (*pnt++);

            pal_snprintf (pnt, (str+len) - pnt,"%u:%u", eas.as, eas.val);
          }
        else if (encode == ECOMMUNITY_ENCODE_AS4)
          {
            eas.as = (*pnt++ << 24);
            eas.as |= (*pnt++ << 16);
            eas.as |= (*pnt++ << 8);
            eas.as |= (*pnt++);

            eas.val |= (*pnt++ << 8);
            eas.val |= (*pnt++);
            pal_snprintf (pnt, (str+len) - pnt,"%u:%u", eas.as, eas.val);
          }
        else if (encode == ECOMMUNITY_ENCODE_IP)
          {
            pal_mem_cpy (&eip.ip, pnt, 4);
            pnt += 4;
            eip.val = (*pnt++ << 8);
            eip.val |= (*pnt++);
            pal_mem_set (&p, 0, sizeof (struct prefix));
            pal_mem_set (buff, 0, sizeof (buff));
            p.family = AF_INET;
            p.u.prefix4 = eip.ip;
            prefix2str (&p, buff, 32);
            pal_snprintf (pnt, (str+len) - pnt, "%s:%u", buff, eip.val); 
          }
     }

   if (pnt)
     *pnt = '\0';

  return str;
}

/***************************************************************************
 * Function       : ecommunity_str                                         *
 * Description    : this function will convert given ecommunity into       * 
 *                  string format.                                         * 
 * Input :                                                                 *
 *   ecom         : Extended community                                     *
 *                                                                         *
 * output :                                                                *
 *   str          : Ecommunity in string format                            *         
 *                                                                         *  
 ***************************************************************************/
u_int8_t *
ecommunity_str (struct ecommunity *ecom)
{
  if (! ecom->str)
    ecom->str = ecommunity_com2str (ecom);

  return ecom->str;
}
