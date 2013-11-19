/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_ASPATH_H
#define _BGPSDN_BGP_ASPATH_H


 /*****************************************************************
 aspath :  attribute structure
           It contains 2byte AS values. 2 byte AS values are used
           in traditional RFC 4271 compliant BGP speakers which
           has 2 byte AS number values. 2byte aspath is also used
           by RFC4893 compliant bgpspeakers when its AS value is
           2byte-mappable and it communicates with a 2byte ASN
           compliant peer.This attribute is stored in attribute hash
           table
 *******************************************************************/

/* AS path may be include some AsSegments. */
struct aspath
{
  /* Reference count to this aspath. */
  u_int32_t refcnt;

  /* Rawdata length */
  u_int32_t length;

  /* AS count. */
  u_int16_t count;
  u_int16_t count_confed;

  /* Rawdata */
  u_int8_t *data;

  /* String expression of AS path.  This string is used by vty output
     and AS path regular expression match. */
  u_int8_t *str;
};

/* To fetch and store as segment value. */
struct assegment
{
  u_int8_t type;
  u_int8_t length;
  u_int16_t asval[1];
};

/* Flags for indicating return types */
#define BGP_ASPATH_RET_FAILURE     0
#define BGP_ASPATH_RET_ASSEQUENCE  1
#define BGP_ASPATH_RET_ASSET       2 


/* Attr. Flags and Attr. Type Code. */
#define AS_HEADER_SIZE          (2)

/* Start and End delimiters for a particular Segment type */
#define AS_SEG_START            (0)
#define AS_SEG_END              (1)

/* Two octet is used for AS value. */
#define AS_VALUE_SIZE           (sizeof (u_int16_t))

/* Minimum and Maximum AS segment length. */
#define ASSEGMENT_LEN_MIN       (1)
#define ASSEGMENT_LEN_MAX       (255)

/* AS segment octet length. */
#define ASSEGMENT_LEN(X)  ((X)->length * AS_VALUE_SIZE + AS_HEADER_SIZE)

/* AS segment size */
#define ASSEGMENT_SIZE(N)  (AS_HEADER_SIZE + ((N) * AS_VALUE_SIZE))

/* Prototypes. */
void aspath_init ();
bool_t aspath_cmp (void *, void *);
struct aspath *aspath_parse ();
struct aspath *aspath_new (void);
struct aspath *aspath_dup (struct aspath *);
struct aspath *aspath_new_or_dup (struct aspath *);
struct aspath *aspath_aggregate (struct aspath *, struct aspath *, u_int8_t);
struct aspath *aspath_prepend (struct aspath *, struct aspath *);
struct aspath *aspath_add_seq (struct aspath *, u_int16_t);
struct aspath *aspath_add_confed_seq (struct aspath *, u_int16_t);
int aspath_cmp_left (struct aspath *, struct aspath *);
int aspath_cmp_left_confed (struct aspath *, struct aspath *);
struct aspath *aspath_delete_confed_seq (struct aspath *);
struct aspath *aspath_empty ();
struct aspath *aspath_empty_get ();
struct aspath *aspath_str2aspath (char *);
void aspath_free (struct aspath *);
struct aspath *aspath_intern (struct aspath *);
void aspath_unintern (struct aspath *);
u_int8_t *
aspath_print (struct aspath *);
u_int32_t aspath_key_make (void *);
int aspath_loop_check (struct aspath *, u_int16_t);
int aspath_confed_seg_check (struct aspath *);
int aspath_confed_first_seg_check (struct aspath *);
int aspath_private_as_check (struct aspath *);
int aspath_as_value_check (struct aspath *);
#ifdef HAVE_EXT_CAP_ASN
int aspath_as_value_astrans_check (struct aspath *);
int aspath_as_count(struct aspath *);
struct aspath *aspath_copy_aspath4B_to_aspath (struct as4path *, struct aspath *);
char *aspath_make_str_count (struct aspath *);
#endif /* HAVE_EXT_CAP_ASN */
int aspath_firstas_check (struct aspath *, u_int16_t);
u_int16_t aspath_origin (struct aspath *);
unsigned long aspath_count ();
struct hash *aspath_hash ();

#endif /* _BGPSDN_BGP_ASPATH_H */
