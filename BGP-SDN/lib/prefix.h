/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_PREFIX_H
#define _BGPSDN_PREFIX_H

#include "pal.h"

#define PREFIX_STYLE_ADDR_LEN  0
#define PREFIX_STYLE_ADDR_MASK 1

#define PREFIX_AM4_VALIDATION_SUCCESS              1
#define PREFIX_AM4_ERR_INVALID_PREFIX              0 
#define PREFIX_AM4_ERR_MALFORMED_ADDRESS          -1
#define PREFIX_AM4_ERR_MALFORMED_NETMASK          -2
#define PREFIX_AM4_ERR_INCORRECT_MASK_FOR_PREFIX  -3

#define PREFIX_RET_SUCCESS_MASKLEN                1 
#define PREFIX_RET_SUCCESS_NETMASK                2

/* IPv4 and IPv6 unified prefix structure. */
struct prefix
{
  u_int8_t family;
  u_int8_t prefixlen;
  u_int8_t prefix_style;
  u_int8_t pad1;
  union
  {
    u_int8_t prefix;
    struct pal_in4_addr prefix4;
#ifdef HAVE_IPV6
    struct pal_in6_addr prefix6;
#endif /* HAVE_IPV6 */
    struct
    {
      struct pal_in4_addr id;
      struct pal_in4_addr adv_router;
    } lp;
    u_int8_t val[9];
  } u;
};

/* IPv4 prefix structure. */
struct prefix_ipv4
{
  u_int8_t family;
  u_int8_t prefixlen;
  u_int8_t pad1;
  u_int8_t pad2;
  struct pal_in4_addr prefix;
};

/* IPv6 prefix structure. */
#ifdef HAVE_IPV6
struct prefix_ipv6
{
  u_int8_t family;
  u_int8_t prefixlen;
  u_int8_t pad1;
  u_int8_t pad2;
  struct pal_in6_addr prefix;
};
#endif /* HAVE_IPV6 */

struct prefix_ls
{
  u_int8_t family;
  u_int8_t prefixlen;
  u_int8_t pad1;
  u_int8_t pad2;
  struct pal_in4_addr id;
  struct pal_in4_addr adv_router;
};

/* Number of bits in prefix type. */
#ifndef PNBBY
#define PNBBY 8
#endif /* PNBBY */

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif /* INET_ADDRSTRLEN */

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif /* INET6_ADDRSTRLEN */

#ifndef INET6_BUFSIZ
#define INET6_BUFSIZ 51
#endif /* INET6_BUFSIZ */

#ifndef INET_NTOP_BUFSIZ
#define INET_NTOP_BUFSIZ 51
#endif /* INET_NTOP_BUFSIZ */

/* Max bit/byte length of IPv4 address. */
#define IPV4_MAX_BYTELEN    4
#define IPV4_MAX_BITLEN    32
#define IPV4_MAX_PREFIXLEN 32
#define IPV4_CLASS_C_PREFIXLEN 24
#define UNNUMBERED_ADDRESS_BYTELEN  16
#define IPV4_ADDR_CMP(D,S)   (pal_mem_cmp ((D), (S), IPV4_MAX_BYTELEN))
#define IPV4_ADDR_MAX(A,B)   ((IPV4_ADDR_CMP ((A), (B)) >= 0) ? (A) : (B))
#define IPV4_ADDR_MIN(A,B)   ((IPV4_ADDR_CMP ((A), (B)) <= 0) ? (A) : (B))
#define IPV4_ADDR_SAME(D,S)  (pal_mem_cmp ((D), (S), IPV4_MAX_BYTELEN) == 0)
#define IPV4_ADDR_COPY(D,S)  (pal_mem_cpy ((D), (S), IPV4_MAX_BYTELEN))
#define IPV4_ADDR_MARTIAN(X)                                          \
  ((IN_CLASSA (X)                                                     \
    && ((((u_int32_t) (X)) & IN_CLASSA_NET) == 0x00000000L            \
        || (((u_int32_t) (X)) & IN_CLASSA_NET) == 0x7F000000L))       \
   || (IN_CLASSB (X)                                                  \
       && ((((u_int32_t) (X)) & IN_CLASSB_NET) == 0x80000000L         \
           || ((((u_int32_t) (X))) & IN_CLASSB_NET) == 0xBFFF0000L))  \
   || (IN_CLASSC (X)                                                  \
       && ((((u_int32_t) (X)) & IN_CLASSC_NET) == 0xC0000000L         \
           || ((((u_int32_t) (X))) & IN_CLASSC_NET) == 0xDFFFFF00L)))

#define IPV4_NET0(a)    ((((u_int32_t) (a)) & 0xff000000) == 0x00000000)
#define IPV4_NET127(a)  ((((u_int32_t) (a)) & 0xff000000) == 0x7f000000)
#define IPV4_ADDRESS0(a) ((((u_int32_t) (a)) & 0xffffffff) == 0x00000000)

#define IPV4_TO_MAPPED_IPV6(A,B)                                             \
   (A)->s6_addr32[0] = 0x00000000;                                      \
   (A)->s6_addr32[1] = 0x00000000;                                      \
   (A)->s6_addr32[2] = pal_hton32(0xFFFF);                             \
   (A)->s6_addr32[3] = ((B).s_addr)

#define MAPPED_IPV6_TO_IPV4(A,B)                                             \
   (A).s_addr = ((B).s6_addr32[3]);

#define VALIDATE_MAPPED_IPV6(A)                                           \
  ((A)->s6_addr32[0] == 0x00000000 ?                                      \
  ((A)->s6_addr32[1] == 0x00000000 ?                                      \
  (pal_ntoh32((A)->s6_addr32[2]) == 0xFFFF ? 1 : 0): 0): 0)

#define CLASS_A_BROADCAST(a)   ((((u_int32_t) (a)) & 0x00ffffff) == 0x00ffffff)
#define CLASS_B_BROADCAST(a)   ((((u_int32_t) (a)) & 0x0000ffff) == 0x0000ffff)
#define CLASS_C_BROADCAST(a)   ((((u_int32_t) (a)) & 0x000000ff) == 0x000000ff)

#define IN_CLASSA_PREFIXLEN    8
#define IN_CLASSB_PREFIXLEN    16
#define IN_CLASSC_PREFIXLEN    24

/* Max bit/byte length of IPv6 address. */
#define IPV6_MAX_BYTELEN    16
#define IPV6_MAX_BITLEN    128
#define IPV6_MAX_PREFIXLEN 128
#define IPV6_ADDR_CMP(D,S)   (pal_mem_cmp ((D), (S), IPV6_MAX_BYTELEN))
#define IPV6_ADDR_SAME(D,S)  (pal_mem_cmp ((D), (S), IPV6_MAX_BYTELEN) == 0)
#define IPV6_ADDR_COPY(D,S)  (pal_mem_cpy ((D), (S), IPV6_MAX_BYTELEN))
#define IPV6_ADDR_MAX(A,B)   ((IPV6_ADDR_CMP ((A), (B)) >= 0) ? (A) : (B))
#define IPV6_ADDR_MIN(A,B)   ((IPV6_ADDR_CMP ((A), (B)) <= 0) ? (A) : (B))

/* IPV4 prefix string maximum length */
#define IPV4_PREFIX_STR_MAX_LEN               19

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

/* Prefix's family member. */
#define PREFIX_FAMILY(p)  ((p)->family)

#ifdef HAVE_IPV6
#define PREFIX_MAX_BITLEN(family)                                             \
    ((family) == AF_INET ? IPV4_MAX_BITLEN :                                  \
     (family) == AF_INET6 ? IPV6_MAX_BITLEN : 0)
#else
#define PREFIX_MAX_BITLEN(family)                                             \
    ((family) == AF_INET ? IPV4_MAX_BITLEN : 0)
#endif /* HAVE_IPV6 */
#define PREFIX_MAX_PREFIXLEN(family)  PREFIX_MAX_BITLEN(family)

#ifdef HAVE_IPV6
#define PREFIX_MAX_BYTELEN(family)                                            \
    ((family) == AF_INET ? IPV4_MAX_BYTELEN :                                 \
     (family) == AF_INET6 ? IPV6_MAX_BYTELEN : 0)
#else
#define PREFIX_MAX_BYTELEN(family)                                            \
    ((family) == AF_INET ? IPV4_MAX_BYTELEN : 0)
#endif /* HAVE_IPV6 */

/* Shift and convert to network-byte order. */
#define PREP_FOR_NETWORK(val,v,l)               \
{                                               \
  val = v;                                      \
  val = pal_hton32 (((val) << (IPV4_MAX_BITLEN - l))); \
}

/* Shift and convert to host-byte order. */
#define PREP_FOR_HOST(val,v,l)                    \
{                                                 \
  val = v;                                        \
  val = ((pal_ntoh32 (val)) >> (IPV4_MAX_BITLEN - l)); \
}

/* Prototypes. */
s_int32_t afi2family (s_int32_t);
s_int32_t family2afi (s_int32_t);

s_int32_t prefix2str (struct prefix *, char *, s_int32_t);
s_int32_t str2prefix (const char *, struct prefix *);
int strmask2ipstr (char *, char *,char *);
struct prefix *prefix_new ();
void prefix_free (struct prefix *p);

struct prefix_ipv4 *prefix_ipv4_new ();
void prefix_ipv4_free ();
s_int32_t str2prefix_ipv4 (const char *, struct prefix_ipv4 *);
s_int32_t prefix2str_ipv4 (struct prefix_ipv4 *p, char *str, s_int32_t size);
void apply_mask_ipv4 (struct prefix_ipv4 *);
u_int8_t ip_masklen (struct pal_in4_addr);
void masklen2ip (s_int32_t, struct pal_in4_addr *);
void apply_classful_mask_ipv4 (struct prefix_ipv4 *);

const char *prefix_family_str (struct prefix *p);
struct prefix *sockunion2prefix ();
struct prefix *sockunion2hostprefix ();
void get_broadcast_addr(struct pal_in4_addr *addr,
                   u_int32_t masklen,
                   struct pal_in4_addr *broadcast);


#ifdef HAVE_IPV6
struct prefix_ipv6 *prefix_ipv6_new ();
void prefix_ipv6_free ();
struct prefix *str2routev6 (char *);
s_int32_t str2prefix_ipv6 (const char *str, struct prefix_ipv6 *p);
void apply_mask_ipv6 (struct prefix_ipv6 *p);
void str2in6_addr (char *str, struct pal_in6_addr *addr);
void masklen2ip6 (s_int32_t masklen, struct pal_in6_addr *netmask);
s_int32_t ip6_masklen (struct pal_in6_addr netmask);
s_int32_t v6prefix2str (struct prefix *p, char *str, s_int32_t size);
void get_broadcast_addr6(struct pal_in6_addr *addr,
                         u_int32_t masklen,
                         struct pal_in6_addr *broadcast);
#endif /* HAVE_IPV6 */

void apply_mask (struct prefix *);
int prefix_match (struct prefix *n, struct prefix *p);
int prefix_same (struct prefix *, struct prefix *);
int prefix_addr_same (struct prefix *, struct prefix *);
int prefix_cmp (struct prefix *, struct prefix *);
int prefix_addr_cmp (const struct prefix *p1, const struct prefix *p2);
void prefix_copy (struct prefix *, struct prefix *);
int prefix_cmp_with_mask (struct prefix *, struct prefix *);
void prefix_common (struct prefix *n, struct prefix *p, struct prefix *new);
s_int32_t prefix_overlap (struct prefix *p1, struct prefix *p2);

int all_digit (char *);


/* IPv4 and IPv6 extended prefix structure. */
struct prefix_am
{
  u_int8_t family;
  u_int8_t prefixlen;
  u_int8_t prefix_style;
  u_int8_t pad1;
  union
  {
    u_int8_t prefix;
    struct pal_in4_addr prefix4;
    struct      /* PREFIX_STYLE_ADDR_MASK */
    {
      struct pal_in4_addr addr4;
      struct pal_in4_addr mask4;
    } am4;
#ifdef HAVE_IPV6
    struct pal_in6_addr prefix6;
    struct      /* PREFIX_STYLE_ADDR_MASK */
    {
      struct pal_in6_addr addr6;
      struct pal_in6_addr mask6;
    } am6;
#endif /* HAVE_IPV6 */
  } u;
};

/* IPv4 prefix structure, including wild card mask. */
struct prefix_am4
{
  u_int8_t family;
  u_int8_t prefixlen;
  u_int8_t prefix_style;
  u_int8_t pad1;
  struct pal_in4_addr addr4;
  struct pal_in4_addr mask4;
};

/* IPv6 prefix structure, including wild card mask. */
#ifdef HAVE_IPV6
struct prefix_am6
{
  u_int8_t family;
  u_int8_t prefixlen;
  u_int8_t prefix_style;
  u_int8_t pad1;
  struct pal_in6_addr addr6;
  struct pal_in6_addr mask6;
};
#endif /* HAVE_IPV6 */

#define PREFIX_ADDR_STR_SIZE (INET6_ADDRSTRLEN)
#define PREFIX_AM_STR_SIZE (PREFIX_ADDR_STR_SIZE*2+4)

void prefix_am4_init (struct prefix_am4 *p);
s_int32_t str2prefix_am4 (const char *addr_str,
                          const char *mask_str,
                          struct prefix_am4 *p);
s_int32_t str2prefix_am4_invert (const char *addr_str,
                                 const char *mask_str,
                                 struct prefix_am4 *p);

s_int32_t prefix2str_am (struct prefix_am *p, char *str, s_int32_t size, char sep);
s_int32_t prefix2str_am_invert (struct prefix_am *p, 
                                char *str, s_int32_t size, char sep);

#ifdef HAVE_IPV6
void prefix_am6_init (struct prefix_am6 *p);
s_int32_t str2prefix_am6 (const char *addr_str,
                          const char *mask_str,
                          struct prefix_am6 *p);
s_int32_t str2prefix_am6_invert (const char *addr_str,
                                 const char *mask_str,
                                 struct prefix_am6 *p);
#endif /* HAVE_IPV6 */

bool_t prefix_am_incl_all(struct prefix_am *p);
int prefix_am_same (struct prefix_am *p1, struct prefix_am *p2);
void prefix_am_copy (struct prefix_am *dest, struct prefix_am *src);
void prefix_am_invert(struct prefix_am *p);
s_int32_t prefix_am_check_mask(struct prefix_am *p);
s_int32_t 
prefix_am4_validate_and_convert_to_prefix4 (const char *, 
                                            const char *,
                                            struct prefix_ipv4 *);
#endif /* _BGPSDN_PREFIX_H */
