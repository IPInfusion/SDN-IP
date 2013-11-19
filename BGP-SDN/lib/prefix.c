/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#include "prefix.h"
#include "sockunion.h"

/* Maskbit. */
static const u_int8_t maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
                                  0xf8, 0xfc, 0xfe, 0xff};


/* Address Famiy Identifier to Address Family converter. */
s_int32_t
afi2family (s_int32_t afi)
{
  if (afi == AFI_IP)
    return AF_INET;
#ifdef HAVE_IPV6
  else if (afi == AFI_IP6)
    return AF_INET6;
#endif /* HAVE_IPV6 */
  return 0;
}

s_int32_t
family2afi (s_int32_t family)
{
  if (family == AF_INET)
    return AFI_IP;
#ifdef HAVE_IPV6
  else if (family == AF_INET6)
    return AFI_IP6;
#endif /* HAVE_IPV6 */
  return 0;
}

/* If n includes p prefix then return 1 else return 0. */
s_int32_t
prefix_match (struct prefix *n, struct prefix *p)
{
  s_int32_t offset;
  s_int32_t shift;

  /* Set both prefix's head pointer. */
  u_int8_t *np = (u_int8_t *)&n->u.prefix;
  u_int8_t *pp = (u_int8_t *)&p->u.prefix;

  /* If n's prefix is longer than p's one return 0. */
  if (n->prefixlen > p->prefixlen)
    return 0;

  offset = n->prefixlen / PNBBY;
  shift =  n->prefixlen % PNBBY;

  if (shift)
    if (maskbit[shift] & (np[offset] ^ pp[offset]))
      return 0;

  while (offset--)
    if (np[offset] != pp[offset])
      return 0;
  return 1;
}

/* If any prefix overlaps the other return 1 else return 0. */
s_int32_t
prefix_overlap (struct prefix *p1, struct prefix *p2)
{
  if (p1->prefixlen >= p2->prefixlen)
  {
    return prefix_match(p2, p1);
  }
  else
  {
    return prefix_match(p1, p2);
  }
}

/* Creates a common prefix of n and p in new.
 * Note that n and new can be the same pointers since p is always
 * used in the function for comparision.
 */
void
prefix_common (struct prefix *n, struct prefix *p, struct prefix *new)
{
  int i;
  u_char diff;
  u_char mask;

  u_char *np = (u_char *)&n->u.prefix;
  u_char *pp = (u_char *)&p->u.prefix;
  u_char *newp = (u_char *)&new->u.prefix;

  for (i = 0; i < p->prefixlen / 8; i++)
    {
      if (np[i] == pp[i])
        newp[i] = np[i];
      else
        break;
    }

  new->prefixlen = i * 8;

  if (new->prefixlen != p->prefixlen)
    {
      diff = np[i] ^ pp[i];
      mask = 0x80;
      while (new->prefixlen < p->prefixlen && !(mask & diff))
        {
          mask >>= 1;
          new->prefixlen++;
        }
      newp[i] = np[i] & maskbit[new->prefixlen % 8];
    }
}
/* Copy prefix from src to dest. */
void
prefix_copy (struct prefix *dest, struct prefix *src)
{
  dest->family = src->family;
  dest->prefixlen = src->prefixlen;

  if (src->family == AF_INET)
    dest->u.prefix4 = src->u.prefix4;
#ifdef HAVE_IPV6
  else if (src->family == AF_INET6)
    dest->u.prefix6 = src->u.prefix6;
#endif /* HAVE_IPV6 */
  else if (src->family == AF_UNSPEC)
    {
      dest->u.lp.id = src->u.lp.id;
      dest->u.lp.adv_router = src->u.lp.adv_router;
    }
#ifdef AF_LOCAL
  else if (src->family == AF_LOCAL)
    pal_mem_cpy (dest->u.val, src->u.val, 9);
#endif /* AF_LOCAL */
}

/* If both prefix structure is same then return 1 else return 0. */
int
prefix_same (struct prefix *p1, struct prefix *p2)
{
  if (p1->family == p2->family && p1->prefixlen == p2->prefixlen)
    {
      if (p1->family == AF_INET)
        if (IPV4_ADDR_SAME (&p1->u.prefix, &p2->u.prefix))
          return 1;
#ifdef HAVE_IPV6
      if (p1->family == AF_INET6 )
        if (IPV6_ADDR_SAME (&p1->u.prefix, &p2->u.prefix))
          return 1;
#endif /* HAVE_IPV6 */
    }
  return 0;
}

/* If both prefix address is same then return 1 else return 0. */
int
prefix_addr_same (struct prefix *p1, struct prefix *p2)
{
  if (p1->family == p2->family)
    {
      if (p1->family == AF_INET)
        if (IPV4_ADDR_SAME (&p1->u.prefix, &p2->u.prefix))
          return 1;
#ifdef HAVE_IPV6
      if (p1->family == AF_INET6 )
        if (IPV6_ADDR_SAME (&p1->u.prefix, &p2->u.prefix))
          return 1;
#endif /* HAVE_IPV6 */
    }
  return 0;
}

/* When both prefix structure is not same, but will be same after
   applying mask, return 0. otherwise, return 1 */
int
prefix_cmp (struct prefix *p1, struct prefix *p2)
{
  int offset;
  int shift;

  /* Set both prefix's head pointer. */
  u_char *pp1 = (u_char *)&p1->u.prefix;
  u_char *pp2 = (u_char *)&p2->u.prefix;

  if (p1->family != p2->family || p1->prefixlen != p2->prefixlen)
    return 1;

  offset = p1->prefixlen / 8;
  /*shift = p1->prefixlen % 8;*/
  shift = p1->prefixlen & 7;

  if (shift)
    if (maskbit[shift] & (pp1[offset] ^ pp2[offset]))
      return 1;

  while (offset--)
    if (pp1[offset] != pp2[offset])
      return 1;

  return 0;
}

int
prefix_addr_cmp (const struct prefix *p1, const struct prefix *p2)
{
  if (p1->family != p2->family)
    return p1->family - p2->family;
  else
    {
      int size = PREFIX_MAX_BYTELEN (p1->family);
      return pal_mem_cmp (&p1->u.prefix, &p2->u.prefix, size);
    }
}

/* Return prefix family type string. */
const char *
prefix_family_str (struct prefix *p)
{
  if (p->family == AF_INET)
    return "inet";
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    return "inet6";
#endif /* HAVE_IPV6 */
  return "unspec";
}

/* Allocate new prefix_ipv4 structure. */
struct prefix_ipv4 *
prefix_ipv4_new ()
{
  struct prefix_ipv4 *p;
  p = XCALLOC (MTYPE_PREFIX_IPV4, sizeof (struct prefix_ipv4));
  p->family = AF_INET;
  return p;
}

/* Free prefix_ipv4 structure. */
void
prefix_ipv4_free (struct prefix_ipv4 *p)
{
  XFREE (MTYPE_PREFIX_IPV4, p);
}

/* When string format is invalid return 0. */
/* else return 1 */
s_int32_t
str2prefix_ipv4 (const char *str, struct prefix_ipv4 *p)
{
  u_int32_t network;
  s_int32_t plen;
  s_int32_t ret;
  size_t alloc;
  char *pnt;
  char *cp;

  /* Find slash inside string. */
  pnt = pal_strchr (str, '/');

  /* String doesn't contail slash. */
  if (pnt == NULL)
    {
      /* Convert string to prefix. */
      ret = pal_inet_pton(AF_INET,str,&p->prefix);
      if (ret <= 0)
        return 0;

      p->family = AF_INET;

      /* Natural Mask is derived for network without a mask */
      network = pal_ntoh32 (p->prefix.s_addr);

      if (IN_CLASSA (network))
        {
          if ((network & IN_CLASSA_NET) == network)
            p->prefixlen = IN_CLASSA_PREFIXLEN;
          else
            p->prefixlen = IPV4_MAX_PREFIXLEN;
        }
      else if (IN_CLASSB (network))
        {
          if ((network & IN_CLASSB_NET) == network)
            p->prefixlen = IN_CLASSB_PREFIXLEN;
          else
            p->prefixlen = IPV4_MAX_PREFIXLEN;
        }
      else if (IN_CLASSC (network))
        {
          if ((network & IN_CLASSC_NET) == network)
            p->prefixlen = IN_CLASSC_PREFIXLEN;
          else
            p->prefixlen = IPV4_MAX_PREFIXLEN;
        }
      else if (IN_CLASSD (network))
        p->prefixlen = IPV4_MAX_PREFIXLEN;
      else if (IN_BADCLASS (network))
        return 0;
      else
        return 0;

      return 1;
    }
  else
    {
      alloc = (pnt - str) + 1;
      cp = XMALLOC (MTYPE_TMP, alloc);
      pal_strncpy (cp, str, pnt - str);
      *(cp + (pnt - str)) = '\0';
      ret = pal_inet_pton (AF_INET,cp, &p->prefix);
      XFREE (MTYPE_TMP, cp);

      if (ret <= 0)
        return 0;

      /* Get prefix length. */
      plen = (u_int8_t) pal_strtou32 (++pnt,NULL,10);
      if (plen > 32)
        return 0;

      p->family = AF_INET;
      p->prefixlen = plen;
    }

  return 1;
}

s_int32_t
prefix2str_ipv4 (struct prefix_ipv4 *p, char *str, s_int32_t size)
{
  char buf[BUFSIZ];

  pal_inet_ntop (p->family, &p->prefix, buf, BUFSIZ);
  pal_snprintf (str, size, "%s/%d", buf, p->prefixlen);
  return 0;
}

/* Convert masklen into IP address's netmask. */
void
masklen2ip (s_int32_t masklen, struct pal_in4_addr *netmask)
{
  u_int8_t *pnt;
  s_int32_t bit;
  s_int32_t offset;

  pal_mem_set (netmask, 0, sizeof (struct pal_in4_addr));
  pnt = (u_int8_t *) netmask;

  offset = masklen / 8;
  bit = masklen % 8;

  while (offset--)
    *pnt++ = 0xff;

  if (bit)
    *pnt = maskbit[bit];
}

void
get_broadcast_addr(struct pal_in4_addr *addr,
                   u_int32_t masklen,
                   struct pal_in4_addr *broadcast)
{
  struct pal_in4_addr netmask;

  masklen2ip (masklen, &netmask);
  broadcast->s_addr = (addr->s_addr | ~(netmask.s_addr));
}

/* Convert IP address's netmask into integer. We assume netmask is
   sequential one. Argument netmask should be network byte order. */
u_int8_t
ip_masklen (struct pal_in4_addr netmask)
{
  u_int8_t len;
  u_int8_t *pnt;
  u_int8_t *end;
  u_int8_t val;

  len = 0;
  pnt = (u_int8_t *) &netmask;
  end = pnt + 4;

  while ((*pnt == 0xff) && pnt < end)
    {
      len+= 8;
      pnt++;
    }

  if (pnt < end)
    {
      val = *pnt;
      while (val)
        {
          len++;
          val <<= 1;
        }
    }
  return len;
}

/* Apply mask to IPv4 prefix. */
void
apply_mask_ipv4 (struct prefix_ipv4 *p)
{
  u_int8_t *pnt;
  s_int32_t index;
  s_int32_t offset;

  index = p->prefixlen / 8;

  if (index < 4)
    {
      pnt = (u_int8_t *) &p->prefix;
      offset = p->prefixlen % 8;

      pnt[index] &= maskbit[offset];
      index++;

      while (index < 4)
        pnt[index++] = 0;
    }
}


#ifdef HAVE_IPV6

/* Allocate a new ip version 6 route */
struct prefix_ipv6 *
prefix_ipv6_new ()
{
  struct prefix_ipv6 *p;

  p = XMALLOC (MTYPE_PREFIX_IPV6, sizeof (struct prefix_ipv6));
  pal_mem_set (p, 0, sizeof (struct prefix_ipv6));
  p->family = AF_INET6;
  return p;
}

/* Free prefix for IPv6. */
void
prefix_ipv6_free (struct prefix_ipv6 *p)
{
  XFREE (MTYPE_PREFIX_IPV6, p);
}

/* If given string is valid return pin6 else return NULL */
s_int32_t
str2prefix_ipv6 (const char *str, struct prefix_ipv6 *p)
{
  char *pnt;
  char *cp;
  s_int32_t ret;

  pnt = pal_strchr (str, '/');

  /* If string doesn't contain `/' treat it as host route. */
  if (pnt == NULL)
    {
      ret = pal_inet_pton (AF_INET6, str, (void*)&p->prefix);
      if (ret <= 0)
        return 0;
      p->prefixlen = IPV6_MAX_BITLEN;
    }
  else
    {
      s_int32_t plen;

      cp = XMALLOC (0, (pnt - str) + 1);
      pal_strncpy (cp, str, pnt - str);
      *(cp + (pnt - str)) = '\0';
      ret = pal_inet_pton (AF_INET6, cp, (void*)&p->prefix);
      XFREE (MTYPE_TMP, cp);
      if (ret <= 0)
        return 0;
      plen = (u_int8_t) pal_strtou32 (++pnt,NULL,10);
      if (plen > 128)
        return 0;
      p->prefixlen = plen;
    }
  p->family = AF_INET6;

  return ret;
}

/* Convert struct pal_in6_addr netmask into integer. */
s_int32_t
ip6_masklen (struct pal_in6_addr netmask)
{
  s_int32_t len = 0;
  char val;
  char *pnt;

  pnt = (char *) & netmask;

  while ((*pnt == 0xff) && len < 128)
    {
      len += 8;
      pnt++;
    }

  if (len < 128)
    {
      val = *pnt;
      while (val)
        {
          len++;
          val <<= 1;
        }
    }
  return len;
}

void
masklen2ip6 (s_int32_t masklen, struct pal_in6_addr *netmask)
{
  char *pnt;
  int bit;
  int offset;

  pal_mem_set (netmask, 0, sizeof (struct pal_in6_addr));
  pnt = (char *) netmask;

  offset = masklen / 8;
  bit = masklen % 8;

  while (offset--)
    *pnt++ = 0xff;

  if (bit)
    *pnt = maskbit[bit];
}

void
get_broadcast_addr6(struct pal_in6_addr *addr,
                   u_int32_t masklen,
                   struct pal_in6_addr *broadcast)
{
  char *pnt;
  char *addr_pnt;
  int bit;
  int offset;
  int index;

  pal_mem_set (broadcast, 0xff, sizeof (struct pal_in6_addr));
  pnt = (char *) broadcast;
  addr_pnt = (char *) &addr;

  offset = masklen / 8;
  bit = masklen % 8;
  index = 0;

  while (offset--)
  {
     *(pnt+index) = addr_pnt[index];
     index++;
  }

  if (bit)
    *(pnt + index) = (addr_pnt[index] | ~maskbit[bit]);
}



void
apply_mask_ipv6 (struct prefix_ipv6 *p)
{
  u_int8_t *pnt;
  s_int32_t index;
  s_int32_t offset;

  index = p->prefixlen / 8;

  if (index < 16)
    {
      pnt = (u_int8_t *) &p->prefix;
      offset = p->prefixlen % 8;

      pnt[index] &= maskbit[offset];
      index++;

      while (index < 16)
        pnt[index++] = 0;
    }
}

void
str2in6_addr (char *str, struct pal_in6_addr *addr)
{
  s_int32_t i;
  u_int32_t x;

  /* %x must point to unsinged int */
  for (i = 0; i < 16; i++)
    {
      pal_sscanf (str + (i * 2), "%02x", &x);
      addr->s6_addr[i] = x & 0xff;
    }
}
#endif /* HAVE_IPV6 */

void
apply_mask (struct prefix *p)
{
  switch (p->family)
    {
      case AF_INET:
        apply_mask_ipv4 ((struct prefix_ipv4 *)p);
        break;
#ifdef HAVE_IPV6
      case AF_INET6:
        apply_mask_ipv6 ((struct prefix_ipv6 *)p);
        break;
#endif /* HAVE_IPV6 */
      default:
        break;
    }
  return;
}

/* Utility function of convert between struct prefix <=> union sockunion.  */
struct prefix *
sockunion2prefix (union sockunion *dest, union sockunion *mask)
{
  struct prefix *p = NULL;

  if (dest->sa.sa_family == AF_INET)
    {
      p = prefix_new ();
      p->family = AF_INET;
      p->u.prefix4 = dest->sin.sin_addr;
      p->prefixlen = ip_masklen (mask->sin.sin_addr);
    }
#ifdef HAVE_IPV6
  else if (dest->sa.sa_family == AF_INET6)
    {
      p = prefix_new ();
      p->family = AF_INET6;
      p->prefixlen = ip6_masklen (mask->sin6.sin6_addr);
      IPV6_ADDR_COPY (&p->u.prefix6, &dest->sin6.sin6_addr);
    }
#endif /* HAVE_IPV6 */

  return p;
}

/* Utility function of convert between struct prefix <=> union sockunion.  */
struct prefix *
sockunion2hostprefix (union sockunion *su)
{
  struct prefix *p = NULL;

  if (su->sa.sa_family == AF_INET)
    {
      p = prefix_new ();
      p->family = AF_INET;
      p->u.prefix4 = su->sin.sin_addr;
      p->prefixlen = IPV4_MAX_BITLEN;
    }
#ifdef HAVE_IPV6
  else if (su->sa.sa_family == AF_INET6)
    {
      p = prefix_new ();
      p->family = AF_INET6;
      p->prefixlen = IPV6_MAX_BITLEN;
      IPV6_ADDR_COPY (&p->u.prefix6, &su->sin6.sin6_addr);
    }
#endif /* HAVE_IPV6 */

  return p;
}

/* Generic function for conversion string to struct prefix. */
s_int32_t
str2prefix (const char *str, struct prefix *p)
{
  s_int32_t ret;

  /* First we try to convert string to struct prefix_ipv4. */
  ret = str2prefix_ipv4 (str, (struct prefix_ipv4 *) p);
  if (ret)
    return ret;

#ifdef HAVE_IPV6
  /* Next we try to convert string to struct prefix_ipv6. */
  ret = str2prefix_ipv6 (str, (struct prefix_ipv6 *) p);
  if (ret)
    return ret;
#endif /* HAVE_IPV6 */

  return 0;
}

s_int32_t
prefix2str (struct prefix *p, char *str, s_int32_t size)
{
  char buf[BUFSIZ];

  pal_inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ);
  pal_snprintf (str, size, "%s/%d", buf, p->prefixlen);
  return 0;
}

/* Utility function to get the ipv4 address string
 * in the format A.B.C.D/M from the given prefix
 * string and the mask string
 */
int
strmask2ipstr (char *prefix_str, char *mask_str,
               char *ip_str)
{
  struct pal_in4_addr mask;
  u_int8_t masklen = 0;
  int ret = 0;

  pal_mem_set (&mask, 0, sizeof (struct pal_in4_addr));
  pal_mem_set (ip_str, 0, IPV4_PREFIX_STR_MAX_LEN);

  /* Convert string to prefix. */
  ret = pal_inet_pton(AF_INET, mask_str, &mask);
  if (ret <= 0)
    return PAL_FALSE;

  masklen = ip_masklen (mask);
  if (masklen > IPV4_MAX_BITLEN)
    return PAL_FALSE;

  pal_snprintf (ip_str, IPV4_PREFIX_STR_MAX_LEN, "%s/%d",
                prefix_str, masklen);

  return PAL_TRUE;
}

struct prefix *
prefix_new ()
{
  return (struct prefix *) XCALLOC (MTYPE_PREFIX, sizeof (struct prefix));
}

/* Free prefix structure. */
void
prefix_free (struct prefix *p)
{
  XFREE (MTYPE_PREFIX, p);
}

/* Utility function.  Check the string only contains digit
   character. */
s_int32_t
all_digit (char *str)
{
  for (; *str != '\0'; str++)
    if (!pal_char_isdigit ((s_int32_t) *str))
      return 0;
  return 1;
}

/* Utility function to convert ipv4 prefixes to Classful prefixes */
void
apply_classful_mask_ipv4 (struct prefix_ipv4 *p)
{

  u_int32_t destination;

  destination = pal_ntoh32 (p->prefix.s_addr);

  if (p->prefixlen == 32);
  /* do nothing for host routes */
  else if (IN_CLASSC (destination))
    {
      p->prefixlen = 24;
      apply_mask_ipv4(p);
    }
  else if (IN_CLASSB(destination))
    {
      p->prefixlen = 16;
      apply_mask_ipv4(p);
    }
  else
    {
      p->prefixlen = 8;
      apply_mask_ipv4(p);
    }
}

/*-----------------------------------------------------------------------
 *              prefix_am  ("addr" or addr/len" or "addr mask"
 *-----------------------------------------------------------------------
 */
 void
prefix_am4_init (struct prefix_am4 *p)
{
  pal_mem_set(p, 0, sizeof(*p));

  p->family        = AF_INET;
}

/* addr_str contains '/' => ignore mask_str
   addr_str do not contain '/' and mask_str eq. NULL =>
                            derrive the mask from addr_str.
   otherwise: decode addr_str and mask_str
   Return # tokens used or 0 if error;
*/
s_int32_t
str2prefix_am4 (const char *addr_str,
                const char *mask_str,
                struct prefix_am4 *p)
{
  s_int32_t ret;
  char *pnt;

  pal_mem_set(p, 0, sizeof(*p));

  /* If mask_str is NULL use the str2prefix_ipv4... */
    /* Find slash inside string. */
  pnt = pal_strchr (addr_str, '/');

  if (pnt || (!pnt && !mask_str))
    {
      ret = str2prefix_ipv4 (addr_str, (struct prefix_ipv4 *)p);
      if (ret <=0)
        return PREFIX_AM4_ERR_MALFORMED_ADDRESS;
      p->prefix_style = PREFIX_STYLE_ADDR_LEN;
      return PREFIX_RET_SUCCESS_MASKLEN;
    }
  else /* !pnt && mask_str */
    {
      /* Convert 1st string to address. */
      ret = pal_inet_pton(AF_INET, addr_str, &p->addr4);
      if (ret <= 0)
        return PREFIX_AM4_ERR_MALFORMED_ADDRESS;

      ret = pal_inet_pton(AF_INET, mask_str, &p->mask4);
      if (ret <= 0)
        return PREFIX_AM4_ERR_MALFORMED_NETMASK;

      p->family       = AF_INET;
      p->prefixlen    = sizeof (struct pal_in4_addr);
      p->prefix_style = PREFIX_STYLE_ADDR_MASK;
      return PREFIX_RET_SUCCESS_NETMASK;
    }
  return PREFIX_AM4_ERR_INVALID_PREFIX;
} /* end of str2prefix_am4 */

#ifdef HAVE_IPV6
void
prefix_am6_init (struct prefix_am6 *p)
{
  pal_mem_set(p, 0, sizeof(*p));

  p->family        = AF_INET6;
}

/* If input converted to IPv6 return #of strings used, otherwise return 0
*/
s_int32_t
str2prefix_am6 (const char *addr_str,
                const char *mask_str,
                struct prefix_am6 *p)
{
  char *pnt = NULL;
  char *cp;
  s_int32_t ret;

  if (! addr_str)
     return 0;
  pnt = pal_strchr (addr_str, '/');

  /* If string doesn't contain `/' treat it as host route. */
  if (pnt == NULL)
    {
      if (pal_inet_pton (AF_INET6, addr_str, (void*)&p->addr6) <= 0)
        return 0;
      if (mask_str)
        {
          if (pal_inet_pton (AF_INET6, mask_str, (void*)&p->mask6) <= 0)
            return 0;
          p->prefix_style = PREFIX_STYLE_ADDR_MASK;
        }
      else
        p->prefix_style = PREFIX_STYLE_ADDR_LEN;
      p->prefixlen = IPV6_MAX_BITLEN;
      p->family    = AF_INET6;
      return 2;
    }
  else
    {
      s_int32_t plen;

      cp = XMALLOC (0, (pnt - addr_str) + 1);
      pal_strncpy (cp, addr_str, pnt - addr_str);
      *(cp + (pnt - addr_str)) = '\0';
      ret = pal_inet_pton (AF_INET6, cp, (void*)&p->addr6);
      XFREE (MTYPE_TMP, cp);
      if (ret <= 0)
        return 0;
      plen = (u_int8_t) pal_strtou32 (++pnt,NULL,10);
      if (plen > IPV6_MAX_BITLEN)
        return 0;

      masklen2ip6(plen,(void*)&p->mask6);
      p->family = AF_INET6;
      p->prefixlen = plen;
      p->prefix_style = PREFIX_STYLE_ADDR_LEN;
      return 1;
    }
}
#endif /* HAVE_IPV6 */

/* If both prefix structure is same then return 1 else return 0. */
int
prefix_am_same (struct prefix_am *p1, struct prefix_am *p2)
{
  if (p1->family == p2->family && p1->prefixlen == p2->prefixlen &&
      p1->prefix_style == p2->prefix_style)
    {
      if (p1->prefix_style == PREFIX_STYLE_ADDR_LEN)
        {
          if (p1->family == AF_INET)
            if (IPV4_ADDR_SAME (&p1->u.prefix, &p2->u.prefix))
              return 1;
#ifdef HAVE_IPV6
          if (p1->family == AF_INET6 )
            if (IPV6_ADDR_SAME (&p1->u.prefix, &p2->u.prefix))
              return 1;
#endif /* HAVE_IPV6 */
        }
      else if (p1->prefix_style == PREFIX_STYLE_ADDR_MASK)
        {
          if (p1->family == AF_INET)
            if (IPV4_ADDR_SAME (&p1->u.am4.addr4, &p2->u.am4.addr4) &&
                IPV4_ADDR_SAME (&p1->u.am4.mask4, &p2->u.am4.mask4))
              return 1;
#ifdef HAVE_IPV6
          if (p1->family == AF_INET6 )
            if (IPV6_ADDR_SAME (&p1->u.am6.addr6, &p2->u.am6.addr6) &&
                IPV6_ADDR_SAME (&p1->u.am6.mask6, &p2->u.am6.mask6))
              return 1;
#endif /* HAVE_IPV6 */
        }
    }
  return 0;
}

s_int32_t
prefix2str_am (struct prefix_am *p, char *str, s_int32_t size, char sep)
{
  char buf1[PREFIX_ADDR_STR_SIZE+1];
  char buf2[PREFIX_ADDR_STR_SIZE+1];

  if (p->family == AF_INET)
    {
      if (p->prefix_style == PREFIX_STYLE_ADDR_LEN)
        {
          pal_inet_ntop (p->family, &p->u.am4.addr4, buf1,
                         PREFIX_ADDR_STR_SIZE);
          pal_snprintf (str, size, "%s/%d", buf1, p->prefixlen);
        }
      else if (p->prefix_style == PREFIX_STYLE_ADDR_MASK)
        {
          pal_inet_ntop (p->family, &p->u.am4.addr4, buf1,
                         PREFIX_ADDR_STR_SIZE);
          pal_inet_ntop (p->family, &p->u.am4.mask4, buf2,
                         PREFIX_ADDR_STR_SIZE);
          pal_snprintf (str, size, "%s%c%s", buf1, sep, buf2);
        }
      return 0;
    }
#ifdef HAVE_IPV6
  else if (p->family == AF_INET6)
    {
      if (p->prefix_style == PREFIX_STYLE_ADDR_LEN)
        {
          pal_inet_ntop (p->family, &p->u.am6.addr6, buf1,
                         PREFIX_ADDR_STR_SIZE);
          pal_snprintf (str, size, "%s/%d", buf1, p->prefixlen);
        }
      else if (p->prefix_style == PREFIX_STYLE_ADDR_MASK)
        {
          pal_inet_ntop (p->family, &p->u.am6.addr6, buf1,
                         PREFIX_ADDR_STR_SIZE);
          pal_inet_ntop (p->family, &p->u.am6.mask6, buf2,
                         PREFIX_ADDR_STR_SIZE);
          pal_snprintf (str, size, "%s%c%s", buf1, sep, buf2);
        }
      return 0;
    }
#endif
  return -1;
}

bool_t
prefix_am_incl_all(struct prefix_am *p)
{
  if (p->prefix_style == PREFIX_STYLE_ADDR_LEN)
    return p->prefixlen == 0;
  else
    return (p->u.am4.mask4.s_addr == 0);
}

/* This is on the occasion of reading the mask as wild card bits 
   (1 means ignore address bit) and storing it in the prefix structure 
   as a standard network mask (1 means valid address bit).
   This is also used when restoring original wild card mask.
 */
void
prefix_am_invert(struct prefix_am *p)
{
  u_int8_t *pnt = NULL;
  s_int8_t  len=0;

  if (p->prefix_style != PREFIX_STYLE_ADDR_MASK) 
      return; 

  len = PREFIX_MAX_BYTELEN(p->family);

  if (PREFIX_FAMILY(p) == AF_INET) 
      pnt = (u_int8_t *)&p ->u.am4.mask4.s_addr;
#ifdef HAVE_IPV6
  else if (PREFIX_FAMILY(p)== AF_INET6)
    pnt = (u_int8_t *)&p->u.am6.mask6;
#endif

  while (len-- > 0)
    pnt[len] = ~pnt[len];
}

s_int32_t
str2prefix_am4_invert (const char *addr_str,
                       const char *mask_str,
                       struct prefix_am4 *p)
{
  s_int32_t ret;

  ret = str2prefix_am4 (addr_str, mask_str,p);
  if (ret == 2)
    prefix_am_invert((struct prefix_am *)p);

  return ret;
}

#ifdef HAVE_IPV6
s_int32_t
str2prefix_am6_invert (const char *addr_str,
                       const char *mask_str,
                       struct prefix_am6 *p)
{
  s_int32_t ret;

  ret = str2prefix_am6 (addr_str, mask_str,p);
  if (ret == 2)
    prefix_am_invert((struct prefix_am *)p);

  return ret;
}
#endif


/* Copy prefix from src to dest. */
void
prefix_am_copy (struct prefix_am *dest, struct prefix_am *src)
{
  dest->family = src->family;
  dest->prefixlen = src->prefixlen;
  dest->prefix_style = src->prefix_style;

  if (src->family == AF_INET)
    dest->u.am4 = src->u.am4;
#ifdef HAVE_IPV6
  else if (src->family == AF_INET6)
    dest->u.am6 = src->u.am6;
#endif /* HAVE_IPV6 */
}

s_int32_t
prefix2str_am_invert (struct prefix_am *p, char *str, s_int32_t size, char sep)
{
  struct prefix_am tp;;

  pal_mem_set(&tp, 0, sizeof(tp));
  prefix_am_copy(&tp, p);
  prefix_am_invert(&tp);

  return prefix2str_am (&tp, str, size, sep);
}

/* Checks relation between 2 set of bits: address and mask.
   Returns 0 if mask overlaps all address bits; -1 - otherwise.
 */
s_int32_t
prefix_am_check_mask(struct prefix_am *p)
{
  u_int8_t *paddr = NULL, *pmask = NULL;
  s_int8_t  len=0, ix=0;

  if (p->prefix_style != PREFIX_STYLE_ADDR_MASK) 
      return 0; 

  len = PREFIX_MAX_BYTELEN(p->family);

  if (PREFIX_FAMILY(p) == AF_INET) 
    {
      paddr = (u_int8_t *)&p ->u.am4.addr4.s_addr;
      pmask = (u_int8_t *)&p ->u.am4.mask4.s_addr;
    }
#ifdef HAVE_IPV6
  else if (PREFIX_FAMILY(p)== AF_INET6)
    {
      paddr = (u_int8_t *)&p ->u.am4.addr4;
      pmask = (u_int8_t *)&p ->u.am4.mask4;
    }
#endif
  while ((ix < len) && ((paddr[ix] & pmask[ix]) == paddr[ix])) ix++;
  return (len <= ix ? 0 : PREFIX_AM4_ERR_INCORRECT_MASK_FOR_PREFIX);
}

s_int32_t 
prefix_am4_validate_and_convert_to_prefix4 (const char *addr_str,
                                            const char *mask_str,
                                            struct prefix_ipv4 *p)
{
  struct prefix_am4 pm;
  s_int32_t ret = 0;

  pal_mem_set (p, 0, sizeof (struct prefix_ipv4));
  prefix_am4_init (&pm);
  
  ret = str2prefix_am4 (addr_str, mask_str, &pm); 
  if (ret <= 0)
    return ret;

  if (pm.prefix_style == PREFIX_STYLE_ADDR_LEN)
    {
      masklen2ip (pm.prefixlen, &pm.mask4);
    }
  else
    {
      pm.prefixlen = ip_masklen (pm.mask4);
    }

  ret = prefix_am_check_mask ((struct prefix_am *) &pm);
  if (ret < 0)
    return ret;
 
  p->family    = pm.family;
  p->prefixlen = pm.prefixlen;
  p->pad1      = 0;
  p->pad2      = 0;
  pal_mem_cpy (&p->prefix, &pm.addr4, sizeof (struct pal_in4_addr));

  return PREFIX_AM4_VALIDATION_SUCCESS;
}
