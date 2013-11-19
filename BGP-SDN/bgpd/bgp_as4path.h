/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_AS4PATH_H
#define _BGPSDN_BGP_AS4PATH_H

/*****************************************************************
 as4path : attribute structure
           It contains 4byte AS values. 4 byte AS values are used
           in RFC 4893 for communication between 4byte compliant BGP
           speakers. The two new attributes, aspath_4B and as4path
           uses 4byte AS values. aspath_4B is for communication 
           between RFC4893 compliant speakers(4byte compliant)and
           as4path is used for communication between 2 byte RFC 4271
           compliant speakers and 4 byte-unmappable FC4893 compliant 
           bgpspeakers. These 2 new attributes are stored in attribute
           hash table.
 *******************************************************************/

/* AS path may be include some AsSegments. */
struct as4path
{
  /* Reference count to this as4path. */
  u_int32_t refcnt;

  /* Rawdata length */
  u_int32_t length;

  /* AS count. */
  u_int32_t count;
  u_int32_t count_confed;

  /* Rawdata */
  u_int8_t *data;

  /* String expression of AS path.  This string is used by vty output
     and AS path regular expression match. */
  u_int8_t *str;
};

/* To fetch and store as segment value. */
struct as4segment
{
  u_int8_t type;
  u_int8_t length;
  as_t asval[1];
}__attribute__((__packed__));

/* Attr. Flags and Attr. Type Code. */
#define AS4_HEADER_SIZE          (2)

/* Start and End delimiters for a particular Segment type */
#define AS4_SEG_START            (0)
#define AS4_SEG_END              (1)

/* 4- octet is used for AS value. */
#define AS4_VALUE_SIZE           (sizeof (as_t))

/* Minimum and Maximum AS segment length. */
#define AS4SEGMENT_LEN_MIN       (1)
#define AS4SEGMENT_LEN_MAX       (255)

/* AS segment octet length. */
#define AS4SEGMENT_LEN(X)  ((X)->length * AS4_VALUE_SIZE + AS4_HEADER_SIZE)

/* AS segment size */
#define AS4SEGMENT_SIZE(N)  (AS4_HEADER_SIZE + ((N) * AS4_VALUE_SIZE))

/* Prototypes. */
void as4path_init ();
void aspath4B_init ();
bool_t as4path_cmp (void *, void *);
struct as4path *as4path_parse ();
struct as4path *aspath4B_parse();
struct as4path *as4path_new (void);
struct as4path *as4path_dup (struct as4path *);
struct as4path *as4path_new_or_dup (struct as4path *);
struct as4path *as4path_aggregate (struct as4path *, struct as4path *,u_int8_t);
struct as4path *as4path_prepend (struct as4path *, struct as4path *);
struct as4path *as4path_add_seq (struct as4path *, as_t);
struct as4path *as4path_add_confed_seq (struct as4path *, as_t);
int as4path_cmp_left (struct as4path *, struct as4path *);
int as4path_cmp_left_confed (struct as4path *, struct as4path *);
struct as4path *as4path_delete_confed_seq (struct as4path *);
struct as4path *as4path_empty ();
struct as4path *as4path_empty_get ();
struct as4path *aspath4B_empty ();
struct as4path *aspath4B_empty_get ();
struct as4path *as4path_str2as4path (char *);
void as4path_free (struct as4path *);
struct as4path *as4path_intern (struct as4path *);
struct as4path *aspath4B_intern (struct as4path *);
void as4path_unintern (struct as4path *);
void aspath4B_unintern (struct as4path *);
struct as4path *as4path_copy_aspath_to_aspath4B (struct aspath *, struct as4path *);
struct as4path *as4path_reconstruct_aspath4B (struct as4path *, struct as4path *);
struct as4path *construct_as4path_from_aspath4B (struct as4path *, struct as4path *);
char *as4path_make_str_count (struct as4path *);
u_int8_t *
as4path_print (struct as4path *);
u_int32_t as4path_key_make (void *);
int as4path_loop_check (struct as4path *, as_t);
int as4path_confed_seg_check (struct as4path *);
int as4path_private_as_check (struct as4path *);
int as4path_confed_first_seg_check (struct as4path * );
int as4path_as_value_check (struct as4path *);
int as4path_firstas_check (struct as4path *, as_t);
as_t as4path_origin (struct as4path *);
u_int32_t as4path_count ();
u_int32_t aspath4B_count ();
unsigned int as4path_as4_count (struct as4path *);
unsigned int aspath4B_nonmappable_count (struct as4path *);
u_int32_t bgp_as4path_get_num_of_bytes_from_4bas (unsigned char *, unsigned char *);
u_int32_t bgp_as4path_get_num_of_bytes (unsigned char *, unsigned char *);
struct hash *as4path_hash ();
struct hash *aspath4B_hash ();

#endif /* _BGPSDN_BGP_AS4PATH_H */
