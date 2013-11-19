/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

/* Abstract Syntax Notation One, ASN.1.
   As defined in ISO/IS 8824 and ISO/IS 8825. */

#include "pal.h"
#include "asn1.h"


#define IS_EXTENSION_ID(B)                                                    \
    (((B) & ASN_EXTENSION_ID) == ASN_EXTENSION_ID)
#define ASN_MASK_OFFSET         ((sizeof (long) - 1) * 8)

/* Truncate "unnecessary" bytes off of the most significant
   end of this 2's complement integer.
   There should be no sequence of 9 consecutive 1's or 0's
   at the most significant end of the integer.  */
#define ASN_TRUNC_MS_BYTE(V,S)                                                \
    do {                                                                      \
      unsigned long _mask = (unsigned long)(((unsigned long)(0x1FF))          \
                                                    << (ASN_MASK_OFFSET - 1));\
      while ((((V) & _mask) == 0 || ((V) & _mask) == _mask) && (S) > 1)       \
        {                                                                     \
          (S)--;                                                              \
          (V) <<= 8;                                                          \
        }                                                                     \
    } while (0)

#define ASN_TRUNC_MS_BYTE64(H,L,S)                                            \
    do {                                                                      \
      unsigned long _mask = (unsigned long)(((unsigned long)(0x1FF))          \
                                                    << (ASN_MASK_OFFSET - 1));\
      while ((((H) & _mask) == 0 || ((H) & _mask) == _mask) && (S) > 1)       \
        {                                                                     \
          (S)--;                                                              \
          (H) = ((H) << 8) | (((L) & _mask) >> ASN_MASK_OFFSET);              \
          (L) <<= 8;                                                          \
        }                                                                     \
    } while (0)

#define ASN_SET_INTVAL(V,S,P)                                                 \
    do {                                                                      \
      unsigned long _mask = (unsigned long)(((unsigned long)(0xFF))           \
                                                   << ASN_MASK_OFFSET);       \
      while ((S)--)                                                           \
        {                                                                     \
          *(P)++ = (u_char)(((V) & _mask) >> ASN_MASK_OFFSET);                \
          (V) <<= 8;                                                          \
        }                                                                     \
    } while (0)

#define ASN_SET_INTVAL64(H,L,S,P)                                             \
    do {                                                                      \
      unsigned long _mask = (unsigned long)(((unsigned long)(0xFF))           \
                                                   << ASN_MASK_OFFSET);       \
      while ((S)--)                                                           \
        {                                                                     \
          *(P)++ = (u_char)(((H) & _mask) >> ASN_MASK_OFFSET);                \
          (H) = ((H) << 8) | (((L) & _mask) >> ASN_MASK_OFFSET);              \
          (L) <<= 8;                                                          \
        }                                                                     \
    } while (0)

#define ASN_OBJECT_ID_LEN_SET(V,S,L)                                          \
    do {                                                                      \
      unsigned long _val = (V);                                               \
      (S) = 1;                                                                \
      while (_val >= 0x80)                                                    \
        {                                                                     \
          _val >>= 7;                                                         \
          (S)++;                                                              \
        }                                                                     \
      (L) += (S);                                                             \
    } while (0)

#define ASN_OBJECT_ID_ENCODE(V,S,P)                                           \
    do {                                                                      \
      int _offset;                                                            \
      for (_offset = (S) - 1; _offset > 0; _offset--)                         \
        *(P)++ = (((V) >> (7 * _offset)) & 0x7F) | ASN_MSBIT;                 \
      *(P)++ = (V) & 0x7F;                                                    \
    } while (0)


/* Internal functions. */
static int
asn1_get_length_check (u_char *ptr, u_char *data,
                       size_t length, size_t dataleft)
{
  if (ptr == NULL)
    return 1;

  /* Message overflows data size. */
  if ((size_t)length + (size_t)(ptr - data) > dataleft)
    return 1;

  return 0;
}

static int
asn1_set_header_check (u_char *data, size_t length, size_t typelen)
{
  if (data == NULL)
    return 1;

  /* Length is too short. */
  if (length < typelen)
    return 1;

  return 0;
}


/* Get Length of the object.

   Parameters
     IN         u_char *data            Pointer to length field.
     OUT        size_t *length          Value of length field.

   Result
     Pointer to the start of data field.
     NULL for failure.                                                       */

static u_char *
asn1_get_length (u_char *data, size_t *length)
{
  u_char first;
  u_char bytes;
  u_char *ptr = data;
    
  if (ptr == NULL || length == NULL) 
    return NULL;

  /* Get first octet. */
  first = *ptr++;

  /* MSB is set, Long form. */
  if (CHECK_FLAG (first, ASN_LONG_LEN))
    {
      /* Turn MSB off. */
      bytes = (first & ~ASN_LONG_LEN);

      if (bytes == 0 || bytes > sizeof (long))
        return NULL;

      *length = 0;
      while (bytes--) 
        {
          *length <<= 8;
          *length |= *ptr++;
        }
    }
  /* Short form, Length is less than 128. */
  else
    *length = (long)first;

  return ptr;
}

/* Get ASN.1 header.

   Parameters
     IN         u_char *data            Pointer to the object.
     IN/OUT     size_t *dataleft        Number of valid bytes left in buffer.
     OUT        u_char *type            ASN object type.

   Result
     Pointer to this object.
     NULL for failure.                                                       */

u_char *
asn1_get_header (u_char *data, size_t *dataleft, u_char *type)
{
  u_char *ptr = data;
  size_t length;

  /* Sanity check .*/
  if (data == NULL || dataleft == NULL || type == NULL)
    return NULL;

  /* Not support extension ID. */
  if (IS_EXTENSION_ID (*ptr))
    return NULL;

  *type = *ptr++;

  ptr = asn1_get_length (ptr, &length);
  if (asn1_get_length_check (ptr, data, length, *dataleft))
    return NULL;

  *dataleft = (int)length;

  return ptr;
}

/* Get ASN.1 integer value.

   Parameters
     IN         u_char *data            Pointer to the object.
     IN/OUT     size_t *dataleft        Number of valid bytes left in buffer.
     OUT        u_char *type            ASN object type.
     IN/OUT     long   *ret             Pointer to output buffer.
     IN         size_t retsize          Size of output buffer.

   Results
     Pointer to the next object.
     NULL for failure.                                                       */

u_char *
asn1_get_int (u_char *data, size_t *dataleft,
              u_char *type, long *ret, size_t retsize)
{
  u_char *ptr = data;
  long val = 0;
  size_t length;

  /* Sanity check. */
  if (retsize != sizeof (long))
    return NULL;

  *type = *ptr++;
  ptr = asn1_get_length (ptr, &length);
  if (asn1_get_length_check (ptr, data, length, *dataleft))
    return NULL;

  /* Length overflows variable to return. */
  if (length > retsize)
    return NULL;

  *dataleft -= (int)length + (ptr - data);
  /* This is negative value. */
  if (*ptr & 0x80)
    val = -1;

  while (length--)
    {
      val <<= 8;
      val |= *ptr++;
    }

  *ret = val;
  return ptr;
}

/* Get ASN.1 charactor pointer.

   Parameters
     IN         u_char *data            Pointer to the object.
     IN         size_t *dataleft        Number of valid bytes left in buffer.
     OUT        u_char *type            ASN object type.
     OUT        size_t *len             ASN object length.
     IN         size_t retsize          Size of output buffer.

   Results
     Pointer to the data part.
     NULL for failure.                                                       */

u_char *
asn1_get_char (u_char *data, size_t *dataleft,
               u_char *type, size_t *len, size_t retsize)
{
  u_char *ptr = data;
  size_t length;

  *type = *ptr++;
  ptr = asn1_get_length (ptr, &length);
  if (asn1_get_length_check (ptr, data, length, *dataleft))
    return NULL;

  /* Length overflows variable to return. */
  if (length > retsize)
    return NULL;

  /* Store length. */
  *len = length;

  /* Return the pointer of the data. */
  return ptr;
}

/* Get ASN.1 Object-ID.

   Parameters
     IN         u_char *data            Pointer to start of object.
     IN/OUT     size_t *dataleft        Number of valid bytes left in buffer.
     OUT        u_char *type            ASN object type.
     IN/OUT     oid    *objid           Pointer to start of output buffer.
     IN/OUT     size_t *objidlength     Number of sub-id's in objid.

   Result
     Pointer to the next object.
     NULL for failure.                                                       */

u_char *
asn1_get_object_id (u_char *data, size_t *dataleft,
                    u_char *type, oid *objid, size_t *objidlen)
{
  oid *oidptr = objid + 1;
  u_char *ptr = data;
  unsigned long subid;
  long bytes;
  size_t length;

  *type = *ptr++;

  ptr = asn1_get_length (ptr, &length);
  if (asn1_get_length_check (ptr, data, length, *dataleft))
    return NULL;

  *dataleft -= (int)length + (ptr - data);

  /* Invalid OID encodings with length = 0. */
  if (length == 0)
    objid[0] = objid[1] = 0;

  bytes = length;
  (*objidlen)--;

  while (bytes > 0 && (*objidlen)-- > 0)
    {
      subid = 0;
      /* Ignore MSB and add rest of 7 bits. */
      do {
        subid <<= 7;
        subid += (*ptr & ~ASN_MSBIT);
        bytes--;
      } while (*ptr++ & ASN_MSBIT);

      *oidptr++ = (oid)subid;
    }

  /* X - first, Y - second octets, subid = (X * 40) + Y */
  subid = objid[1];
  if (subid == 0x2B)
    {
      objid[0] = 1;
      objid[1] = 3;
    }
  else
    {
      objid[0] = subid / 40;
      objid[1] = subid % 40;
    }

  *objidlen = (int)(oidptr - objid);

  return ptr;
}


/* Set ASN.1 integer object.

   Parameters
     IN         u_char *data            Pointer to start of output buffer.
     IN/OUT     size_t *datalen         Number of valid bytes left in buffer.
     IN         int     type            ASN type of object.
     IN         long   *intval          Pointer to start of long integer.
     IN         size_t  size            Size of input buffer.

   Results
     Pointer to the next object.
     NULL for failure.                                                       */

u_char *
asn1_set_int (u_char *data, size_t *datalen,
              u_char type, long *intval, size_t size)
{
  u_char *ptr = data;
  long val;
    
  /* Sanity check. */
  if (size != sizeof (long))
    return NULL;

  val = *intval;

  ASN_TRUNC_MS_BYTE (val, size);

  ptr = asn1_set_header (ptr, datalen, type, size);
  if (asn1_set_header_check (ptr, *datalen, size))
    return NULL;

  *datalen -= size;

  ASN_SET_INTVAL (val, size, ptr);

  return ptr;
}

/* Set ASN.1 unsigned integer

   Parameters
     IN         u_char *data            Pointer to start of output buffer.
     IN/OUT     size_t *datalen         Number of valid bytes left in buffer.
     IN         u_char type             ASN object type.
     IN         unsigned long *intval   Pointer to start of long integer.
     IN         size_t size             Size of input buffer.

   Results
     Pointer to the next object.
     NULL for failure.                                                       */

u_char *
asn1_set_unsigned_int (u_char *data, size_t *datalen,
                       u_char type, unsigned long *intval, size_t size)
{
  u_char *ptr = data;
  unsigned long val;
  int flag = 0;

  /* Sanity check. */
  if (size != sizeof (long))
    return NULL;

  val = *intval;
  /* If MSB is set. */
  if ((val >> ASN_MASK_OFFSET) & ASN_MSBIT)
    {
      flag++;
      size++;
    }
  else
    ASN_TRUNC_MS_BYTE (val, size);

  ptr = asn1_set_header (ptr, datalen, type, size);
  if (asn1_set_header_check (ptr, *datalen, size))
    return NULL;

  *datalen -= size;
  if (flag)
    {
      *ptr++ = '\0';
      size--;
    }

  ASN_SET_INTVAL (val, size, ptr);

  return ptr;
}

/* Set ASN.1 octet string.

   Parameters
     IN         u_char *data            Pointer to start of object.
     IN/OUT     size_t *datalen         Number of valid bytes left in buffer.
     IN         u_char  type            ASN object type.
     IN         u_char *str             Pointer to start of input buffer.
     IN         size_t  size            Size of input buffer.

   Results
     Pointer to the next object.
     NULL for failure.                                                       */

u_char *
asn1_set_string (u_char *data, size_t *datalen,
                 u_char type, const u_char *str, size_t size)
{
  u_char *ptr = data;
  
  ptr = asn1_set_header (ptr, datalen, type, size);
  if (asn1_set_header_check (ptr, *datalen, size))
    return NULL;

  if (size)
    {
      if (str == NULL)
        pal_mem_set (ptr, 0, size);
      else
        pal_mem_move (ptr, str, size);
    }

  *datalen -= size;

  return ptr + size;
}

/* Set ASN.1 header.

   Parameters
     IN         u_char *data            Pointer to start of object.
     IN/OUT     size_t *datalen         Number of valid bytes left in buffer.
     IN         u_char  type            ASN type of object.
     IN         size_t  size            Length of object.

   Results
     Pointer to the data of this object.
     NULL for failure.                                                       */

u_char *
asn1_set_header (u_char *data, size_t *datalen, u_char type, size_t length)
{
  u_char *ptr = data;

  /* Sanity check. */
  if (*datalen < 1)
    return NULL;

  /* Set type. */
  *ptr++ = type;
  (*datalen)--;

  /* Set length. */
  if (length < ASN_LONG_LEN)
    {
      if (*datalen < 1)
        return NULL;

      *ptr++ = length;
    }
  else if (length <= 0xFF)
    {
      if (*datalen < 2)
        return NULL;

      *ptr++ = 0x01 | ASN_LONG_LEN;
      *ptr++ = length;
    }
  else
    {
      if (*datalen < 3)
        return NULL;

      *ptr++ = 0x02 | ASN_LONG_LEN;
      *ptr++ = (length >> 8) & 0xFF;
      *ptr++ = length & 0xFF;
    }

  *datalen -= (ptr - data);
  return ptr;
}

/* Set ASN.1 header for a sequence.

   Parameters
     IN         u_char *data            Pointer to start of object.
     IN/OUT     size_t *datalen         Number of valid bytes left in buffer.
     IN         u_char  type            ASN type of object.
     IN         size_t  size            Length of object.

   Results
     Poitner to the data of this object.
     NULL for failure.                                                       */
u_char *
asn1_set_sequence (u_char *data, size_t *datalen, u_char type, size_t size)
{
  u_char *ptr = data;

  /* Sanity check. */
  if (*datalen < 4)
    return NULL;

  *datalen -= 4;
  *ptr++ = type;
  *ptr++ = 0x02 | ASN_LONG_LEN;
  *ptr++ = (size >> 8) & 0xFF;
  *ptr++ = size & 0xFF;

  return ptr;
}

/* Set ASN.1 Object ID.

   Parameters
     IN         u_char *data            Pointer to start of object.
     IN/OUT     size_t *datalen         Number of valid bytes left in buffer.
     IN         int     type            ASN object type.
     IN         oid    *objid           Pointer to start of input buffer.
     IN         size_t  objidlen        Number of sub-id's in objid.

   Results
     Pointer to the next object.
     NULL for failure.                                                       */

u_char *
asn1_set_object_id (u_char *data, size_t *datalen,
                    u_char type, oid *objid, size_t objidlen)
{
  size_t length = 0;
  u_char objid_size[MAX_OID_LEN];
  unsigned long objid_val_head = 0;
  int pos = 0;
  int i;

  /* Check if there are at least 2 sub-ids. */
  if (objidlen < 2)
    {
      if (objidlen == 1)
        {
          objid_val_head = (objid[0] * 40);
          pos++;
        }
      objidlen = 2;
    }
  else
    {
      /* Invalid second sub-id. */
      if (objid[1] > 40)
        return NULL;

      /* (X * 40) + Y. */
      objid_val_head = (objid[0] * 40) + objid[1];
      pos += 2;
    }

  /* Set first octet of Object ID. */
  ASN_OBJECT_ID_LEN_SET (objid_val_head, objid_size[1], length);

  /* Estimate length for rest of Object IDs. */
  for (i = pos; i < objidlen; i++)
    ASN_OBJECT_ID_LEN_SET (objid[i], objid_size[i], length);

  /* Set ASN.1 header. */
  data = asn1_set_header (data, datalen, type, length);
  if (asn1_set_header_check (data, *datalen, length))
    return NULL;

  /* Set encoded object IDs. */
  ASN_OBJECT_ID_ENCODE (objid_val_head, objid_size[1], data);
  for (i = 2; i < objidlen; i++)
    ASN_OBJECT_ID_ENCODE (objid[i], objid_size[i], data);

  *datalen -= length;

  return data;
}

/* Set ASN.1 null object.

   Parameters
     IN         u_char *data            Pointer to start of object.
     IN/OUT     size_t *datalen         Number of valid bytes left in buffer.
     IN         u_char  type            ASN object type.

   Results
     Pointer to the next object.
     NULL for failure.                                                       */

u_char *
asn1_set_null (u_char *data, size_t *datalen, u_char type)
{
  return asn1_set_header (data, datalen, type, 0);
}

/* Set ASN.1 bit string

   Parameters
     IN         u_char *data            Pointer to start of object.
     IN/OUT     size_t *datalen         Number of valid bytes left in buffer.
     IN         u_char  type            ASN object type.
     IN         u_char *str             Pointer to start of input buffer.
     IN         size_t  size            Size of input buffer.

   Results
     Pointer to the next object.
     NULL for failure.                                                       */

u_char *
asn1_set_bitstring (u_char *data, size_t *datalen,
                    u_char type, u_char *str, size_t size)
{
  u_char *ptr = data;

  /* Sanity check. */
  if (size < 1)
    return NULL;

  ptr = asn1_set_header (ptr, datalen, type, size);
  if (asn1_set_header_check (ptr, *datalen, size))
    return NULL;

  pal_mem_move (ptr, str, size);
  *datalen -= size;

  return ptr + size;
}

/* Set ASN.1 64-bit integer.
  
   Parameters
     IN         u_char *data            Pointer to start of output buffer.
     IN/OUT     size_t *datalength      Number of valid bytes left in buffer.
     IN         u_char  type            ASN type of object.
     IN         struct counter64 *cp    Pointer to counter struct.
     IN         size_t  countersize     Size of input buffer.

   Results
     Pointer to the next object.
     NULL for failure.                                                       */

u_char *
asn1_set_unsigned_int64 (u_char *data, size_t *datalen,
                         u_char type, struct counter64 *cnt, size_t size)
{
  u_char *ptr = data;
  unsigned long low, high;
  int flag = 0;
  size_t size64 = 8;

  /* Sanity check. */
  if (size != sizeof (struct counter64))
    return NULL;

  low = cnt->low;
  high = cnt->high;

  /* If MSB is set */
  if ((high >> ASN_MASK_OFFSET) & ASN_MSBIT)
    {
      flag++;
      size64++;
    }
  else
    ASN_TRUNC_MS_BYTE64 (high, low, size64);

  ptr = asn1_set_header (ptr, datalen, type, size64);
  if (asn1_set_header_check (ptr, *datalen, size64))
    return NULL;

  *datalen -= size64;
  if (flag)
    {
      *ptr++ = '\0';
      size64--;
    }

  ASN_SET_INTVAL64 (high, low, size64, ptr);

  return ptr;
} 

