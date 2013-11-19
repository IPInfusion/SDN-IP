/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_ECOMMUNITY_H
#define _BGPSDN_BGP_ECOMMUNITY_H

/* High-order octet of the Extended Communities type field. */
#define ECOMMUNITY_IANA_BIT        0X80
#define ECOMMUNITY_ENCODE_AS       0x00
#define ECOMMUNITY_ENCODE_IP       0x01
#define ECOMMUNITY_ENCODE_AS4      0x02
/*rfc 4360 */
#define ECOMMUNITY_OPAQUE                     0x03
/* sub-types defined by IANA */

/* Low-order octet of the Extended Communityes type field. */
#define ECOMMUNITY_ROUTE_TARGET               0x02
#define ECOMMUNITY_SITE_ORIGIN                0x03

#define ECOMMUNITY_OSPF_DOMAIN_ID             0x05
#define ECOMMUNITY_OSPF_ROUTE_TYPE            0x06
#define ECOMMUNITY_OSPF_ROUTER_ID             0X07
#define ECOMMUNITY_BGP_DATA_COLLECTION        0X08
#define ECOMMUNITY_SOURCE_AS                  0X09
#define ECOMMUNITY_VRF_ROUTE_IMPORT           0x0A

/* Extended communities attribute string format.  */
#define ECOMMUNITY_FORMAT_ROUTE_MAP            0
#define ECOMMUNITY_FORMAT_COMMUNITY_LIST       1
#define ECOMMUNITY_FORMAT_DISPLAY              2
/*rfc 4360 */
#define ECOMMUNITY_NON_TRANSITIVE_ATTR         0x40

/* Extended Communities attribute. */
struct ecommunity
{
  u_int32_t refcnt;
  u_int32_t size;
  u_int8_t *val;
  u_int8_t *str;
};

/* Extended community value is eight octet.  */
struct ecommunity_val
{
  u_int8_t val[8];
};

/* For parse Extended Community attribute tupple. */
struct ecommunity_as
{
  as_t as;
  u_int32_t val;
};

struct ecommunity_ip
{
  struct pal_in4_addr ip;
  u_int16_t val;
};

/*OSPF Router-ID attribute */
struct ecomm_ospf_rid
{
  u_int8_t type;
  u_int8_t subtype;
  struct pal_in4_addr router_id;
  u_int16_t pad_2b;
}__attribute__((__packed__));

/* OSPF Route-type attribute */
struct ecomm_ospf_rtype
{
  u_int8_t type;
  u_int8_t subtype;
  struct pal_in4_addr area_id;
  u_int8_t rtype;
  u_int8_t option;
}__attribute__((__packed__));

/*OSPF Domain-Id is six octet value */
struct ecomm_ospf_did
{
  u_int8_t type;
  u_int8_t subtype;
  u_int8_t did[6];
}__attribute__((__packed__));

/* OSPF ext community attributes */
struct ecomm_ospf_ext
{
  union{
    u_int8_t ext_val[BGP_RD_SIZE];
    struct ecomm_ospf_rtype rtype;
    struct ecomm_ospf_did domain_id;
    struct ecomm_ospf_rid rid;
    }u;
#define ext_val        u.ext_val
#define ext_areaid     u.rtype.area_id 
#define ext_rtype      u.rtype.rtype
#define ext_option     u.rtype.option 
#define ext_router_id  u.rid.router_id
}__attribute__((__packed__));

#define ecom_length(X)    ((X)->size * 8)

void ecommunity_init (void);
void ecommunity_free (struct ecommunity *);
struct ecommunity *ecommunity_new (void);
struct ecommunity *ecommunity_parse (u_int8_t *, unsigned short);
struct ecommunity *ecommunity_dup (struct ecommunity *);
struct ecommunity *ecommunity_merge (struct ecommunity *, struct ecommunity *);
struct ecommunity *ecommunity_intern (struct ecommunity *);
void ecommunity_unintern (struct ecommunity *);
u_int32_t ecommunity_hash_make (void *);

int ecommunity_add_val (struct ecommunity *, struct bgp_rd *);
int ecommunity_del_val (struct ecommunity *, struct bgp_rd *);
int ecommunity_include (struct ecommunity *ecom, struct bgp_rd *val);
int ecommunity_match (struct ecommunity *, struct ecommunity *);
bool_t ecommunity_cmp (void *, void *);
struct bgp_rd *ecommunity_intersect (struct ecommunity *, struct ecommunity *);

int ecommunity_str2rd (u_int8_t *, struct bgp_rd *);
int ecommunity_rd2str (int, struct bgp_rd *, u_int8_t *, size_t);
void ecommunity_rd2com (struct bgp_rd *, u_int8_t);
struct ecommunity *ecommunity_str2com (u_int8_t *, int, int);
void ecommunity_vty_out (struct vty *, struct ecommunity *);
u_int8_t *ecommunity_ecom2str (struct ecommunity *, int);
bool_t
ecommunity_get_ext_attribute (struct ecommunity *, struct ecomm_ospf_ext *, int);
int ecommunity_logging (struct ecommunity * ecommunity);
u_int8_t * ecommunity_str (struct ecommunity *com);

#endif /* _BGPSDN_BGP_ECOMMUNITY_H */
