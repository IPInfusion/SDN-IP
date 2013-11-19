/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "prefix.h"


/* Defines. */
#define ZVSNP_ERROR_PARSE              1
#define ZVSNP_ERROR_OVERFLOW           2

#define ZVSNP_TYPE_NONE                0
#define ZVSNP_TYPE_SHORT               1
#define ZVSNP_TYPE_INT                 2
#define ZVSNP_TYPE_LONG                3
#define ZVSNP_TYPE_U_CHAR              4
#define ZVSNP_TYPE_U_SHORT             5
#define ZVSNP_TYPE_U_INT               6
#define ZVSNP_TYPE_U_LONG              7
#define ZVSNP_TYPE_DOUBLE              8
#define ZVSNP_TYPE_LONG_DOUBLE         9
#define ZVSNP_TYPE_POINTER            10

#define ZVSNP_SIGN_PLUS                0
#define ZVSNP_SIGN_MINUS               1

#define ZVSNP_STATE_BEGIN              0
#define ZVSNP_STATE_FLAG               1
#define ZVSNP_STATE_WIDTH              2
#define ZVSNP_STATE_PRECDOT            3
#define ZVSNP_STATE_PRECISION          4
#define ZVSNP_STATE_QUALIFIER          5
#define ZVSNP_STATE_OPERATOR           6
#define ZVSNP_STATE_PERCENT            7
#define ZVSNP_STATE_END                8
#define ZVSNP_STATE_MAX                9

#define ZVSNP_CLASS_FLAG               1
#define ZVSNP_CLASS_WIDTH              2
#define ZVSNP_CLASS_PRECDOT            3
#define ZVSNP_CLASS_PRECISION          4
#define ZVSNP_CLASS_QUALIFIER          5
#define ZVSNP_CLASS_OPERATOR           6
#define ZVSNP_CLASS_PERCENT            7
#define ZVSNP_CLASS_MAX                8

#define ZVSNP_FLAG_NONE                0
#define ZVSNP_FLAG_MINUS        (1 << 0)
#define ZVSNP_FLAG_ZERO         (1 << 1)
#define ZVSNP_FLAG_PLUS         (1 << 2)
#define ZVSNP_FLAG_SPACE        (1 << 3)
#define ZVSNP_FLAG_HASH         (1 << 4)

#define ZVSNP_QUAL_DEFAULT             0
#define ZVSNP_QUAL_SHORT               1
#define ZVSNP_QUAL_LONG                2
#define ZVSNP_QUAL_LONG_DOUBLE         3

#define ZVSNP_NUM_STRLEN_MAX          16
#define ZVSNP_IN_ADDR_STRLEN_MAX      16
#define ZVSNP_IN6_ADDR_STRLEN_MAX     40
#define ZVSNP_PREFIX_IPV4_STRLEN_MAX  19
#define ZVSNP_PREFIX_IPV6_STRLEN_MAX  44

#define ZVSNP_BASE_DECIMAL            10
#define ZVSNP_BASE_OCTAL               8
#define ZVSNP_BASE_HEXA               16

/* Structures. */
struct zvsnp
{
  u_char flags;
  u_char width_star;
  s_int32_t width;
  s_int32_t prec;
  u_char qual;
  u_char opr;

  char *sp;
  char *ep;
};

struct zvsnp_val
{
  u_char sign;
  union
  {
    u_char c;
    u_int32_t ul;
    double df;
    void *p;
  } u;
};

/* Macros. */
#define ZVSNP_CLASS(C)         (zvsnp_class[(C) - ' '])
#define ZVSNP_CLASS_RANGE(C)   ((C) >= ' ' && (C) <= 'z')
#define ZVSNP_FLAG(C)          (zvsnp_flags[(C) - ' '])
#define ZVSNP_FLAG_RANGE(C)    ((C) >= ' ' && (C) <= '0')
#define ZVSNP_DIGIT(C)         ((C) - '0')
#define ZVSNP_QUAL(C)          ((C) == 'h' ? ZVSNP_QUAL_SHORT :               \
                                ((C) == 'l' ? ZVSNP_QUAL_LONG :               \
                                 ((C) == 'L' ? ZVSNP_QUAL_LONG_DOUBLE :       \
                                  ZVSNP_QUAL_DEFAULT)))
#define ZVSNP_QUAL_RANGE(C)    ((C) >= 'L' && (C) <= 'l')
#define ZVSNP_PAD(Z)           ((Z)->flags & ZVSNP_FLAG_ZERO ? '0' : ' ')
#define ZVSNP_ALIGN(Z)         ((Z)->flags & ZVSNP_FLAG_MINUS)
#define ZVSNP_EXPAND(Z,P,L,V)                                                 \
    zv_expand[(Z)->opr].func[ZVSNP_ALIGN (Z)] ((P), (L), (Z), (V))

#define ZVSNP_SIGN_CHAR_GET(Z,S,C,L)                                          \
  do {                                                                        \
    (C) = NULL;                                                               \
    (L) = 0;                                                                  \
    if ((S))                                                                  \
      {                                                                       \
        (C) = "-";                                                            \
        (L) = 1;                                                              \
      }                                                                       \
    else                                                                      \
      {                                                                       \
        if ((Z)->flags & ZVSNP_FLAG_PLUS)                                     \
          {                                                                   \
            (C) = "+";                                                        \
            (L) = 1;                                                          \
          }                                                                   \
        else if ((Z)->flags & ZVSNP_FLAG_SPACE)                               \
          {                                                                   \
            (C) = " ";                                                        \
            (L) = 1;                                                          \
          }                                                                   \
       }                                                                      \
  } while (0)

#define ZVSNP_EXPAND_OCTET(P,V)                                               \
    do {                                                                      \
      int _val = (V);                                                         \
      char _a, _b, _c;                                                        \
      _a = _val / 100;                                                        \
      _b = (_val % 100) / 10;                                                 \
      _c = _val % 10;                                                         \
      if (_a)                                                                 \
        *(P)++ = '0' + _a;                                                    \
      if (_a || _b)                                                           \
        *(P)++ = '0' + _b;                                                    \
      *(P)++ = '0' + _c;                                                      \
    } while (0)

#define ZVSNP_STRLEN(S,L)                                                     \
    do {                                                                      \
      char *_zv_p = (S);                                                      \
      (L) = 0;                                                                \
      while (*_zv_p++ != '\0')                                                \
        (L)++;                                                                \
    } while (0)

#define ZVSNP_MEMCPY(P,S,L,Z,W)                                               \
    do {                                                                      \
      int _zv_i;                                                              \
      int _zv_len = (P) + (Z) < (L) ? (Z) : (L) - (P);                        \
      if ((Z) <= 0)                                                           \
        break;                                                                \
      for (_zv_i = 0; _zv_i < _zv_len; _zv_i++)                               \
        *((P) + _zv_i) = *((S) + _zv_i);                                      \
      (P) += _zv_len;                                                         \
      (W) += (Z);                                                             \
    } while (0)

#define ZVSNP_MEMSET(P,C,L,Z,W)                                               \
    do {                                                                      \
      int _zv_i;                                                              \
      int _zv_len = (P) + (Z) < (L) ? (Z) : (L) - (P);                        \
      if ((Z) <= 0)                                                           \
        break;                                                                \
      for (_zv_i = 0; _zv_i < _zv_len; _zv_i++)                               \
        *((P) + _zv_i) = (C);                                                 \
      (P) += _zv_len;                                                         \
      (W) += (Z);                                                             \
    } while (0)

#define ZVSNP_VAL_GET(Q,O,V,A)                                                \
  {                                                                           \
    long l;                                                                   \
    double f;                                                                 \
    V.sign = ZVSNP_SIGN_PLUS;                                                 \
    switch (zv_expand[(O)].type[(Q)])                                         \
      {                                                                       \
      case ZVSNP_TYPE_U_CHAR:                                                 \
        V.u.c = (unsigned char)va_arg (A, int);                               \
        break;                                                                \
      case ZVSNP_TYPE_SHORT:                                                  \
        l = (short)va_arg (A, int);                                           \
        if (l < 0)                                                            \
          {                                                                   \
            V.u.ul = -l;                                                      \
            V.sign = ZVSNP_SIGN_MINUS;                                        \
          }                                                                   \
        else                                                                  \
          V.u.ul = l;                                                         \
        break;                                                                \
      case ZVSNP_TYPE_U_SHORT:                                                \
        V.u.ul = (unsigned short)va_arg (A, int);                             \
        break;                                                                \
      case ZVSNP_TYPE_INT:                                                    \
        l = va_arg (A, int);                                                  \
        if (l < 0)                                                            \
          {                                                                   \
            V.u.ul = -l;                                                      \
            V.sign = ZVSNP_SIGN_MINUS;                                        \
          }                                                                   \
        else                                                                  \
          V.u.ul = l;                                                         \
        break;                                                                \
      case ZVSNP_TYPE_U_INT:                                                  \
        V.u.ul = va_arg (A, unsigned int);                                    \
        break;                                                                \
      case ZVSNP_TYPE_LONG:                                                   \
        l = va_arg (A, long);                                                 \
        if (l < 0)                                                            \
          {                                                                   \
            V.u.ul = -l;                                                      \
            V.sign = ZVSNP_SIGN_MINUS;                                        \
          }                                                                   \
        else                                                                  \
          V.u.ul = l;                                                         \
        break;                                                                \
      case ZVSNP_TYPE_U_LONG:                                                 \
        V.u.ul = va_arg (A, unsigned long);                                   \
        break;                                                                \
      case ZVSNP_TYPE_DOUBLE:                                                 \
      case ZVSNP_TYPE_LONG_DOUBLE:                                            \
        f = va_arg (A, double);                                               \
        if (f < 0.0)                                                          \
          {                                                                   \
            V.u.df = -f;                                                      \
            V.sign = ZVSNP_SIGN_MINUS;                                        \
          }                                                                   \
        else                                                                  \
          V.u.df = f;                                                         \
        break;                                                                \
      case ZVSNP_TYPE_POINTER:                                                \
        V.u.p = va_arg (A, void *);                                           \
        break;                                                                \
      default:                                                                \
        break;                                                                \
      }                                                                       \
  }


/* Constants. */
static const u_char zvsnp_sm[] =
{
  /*                      7  6  5  4  3  2  1  0  */
  0xee, /* 0: BEGIN     { 1, 1, 1, 0, 1, 1, 1, 0 } */
  0x6e, /* 1: FLAG      { 0, 1, 1, 0, 1, 1, 1, 0 } */
  0x6c, /* 2: WIDTH     { 0, 1, 1, 0, 1, 1, 0, 0 } */
  0x10, /* 3: PRECDOT   { 0, 0, 0, 1, 0, 0, 0, 0 } */
  0x70, /* 4: PRECISION { 0, 1, 1, 1, 0, 0, 0, 0 } */
  0x40, /* 5: QUALIFIER { 0, 1, 0, 0, 0, 0, 0, 0 } */
  0x00, /* 6: OPERATOR  { 0, 0, 0, 0, 0, 0, 0, 0 } */
  0x00, /* 7: PERCENT   { 0, 0, 0, 0, 0, 0, 0, 0 } */
};

static const u_char zvsnp_class[] =
{
  /*    20 */ 0x02,  /* !  21 */ 0x00,  /* "  22 */ 0x00,  /* #  23 */ 0x02,
  /* $  24 */ 0x00,  /* %  25 */ 0x81,  /* &  26 */ 0x00,  /* '  27 */ 0x00,
  /* (  28 */ 0x00,  /* )  29 */ 0x00,  /* *  2a */ 0x04,  /* +  2b */ 0x02,
  /* ,  2c */ 0x00,  /* -  2d */ 0x02,  /* .  2e */ 0x08,  /* /  2f */ 0x00,
  /* 0  30 */ 0x16,  /* 1  31 */ 0x14,  /* 2  32 */ 0x14,  /* 3  33 */ 0x14,
  /* 4  34 */ 0x14,  /* 5  35 */ 0x14,  /* 6  36 */ 0x14,  /* 7  37 */ 0x14,
  /* 8  38 */ 0x14,  /* 9  39 */ 0x14,  /* :  3a */ 0x00,  /* ;  3b */ 0x00,
  /* <  3c */ 0x00,  /* =  3d */ 0x00,  /* >  3e */ 0x00,  /* ?  3f */ 0x00,
  /* @  40 */ 0x00,  /* A  41 */ 0x40,  /* B  42 */ 0x40,  /* C  43 */ 0x40,
  /* D  44 */ 0x40,  /* E  45 */ 0x40,  /* F  46 */ 0x40,  /* G  47 */ 0x40,
  /* H  48 */ 0x40,  /* I  49 */ 0x40,  /* J  4a */ 0x40,  /* K  4b */ 0x40,
  /* L  4c */ 0x20,  /* M  4d */ 0x40,  /* N  4e */ 0x40,  /* O  4f */ 0x40,
  /* P  50 */ 0x40,  /* Q  51 */ 0x40,  /* R  52 */ 0x40,  /* S  53 */ 0x40,
  /* T  54 */ 0x40,  /* U  55 */ 0x40,  /* V  56 */ 0x40,  /* W  57 */ 0x40,
  /* X  58 */ 0x40,  /* Y  59 */ 0x40,  /* Z  5a */ 0x40,  /* [  5b */ 0x00,
  /* \  5c */ 0x00,  /* ]  5d */ 0x00,  /* ^  5e */ 0x00,  /* _  5f */ 0x00,
  /* `  60 */ 0x00,  /* a  61 */ 0x40,  /* b  62 */ 0x40,  /* c  63 */ 0x40,
  /* d  64 */ 0x40,  /* e  65 */ 0x40,  /* f  66 */ 0x40,  /* g  67 */ 0x40,
  /* h  68 */ 0x20,  /* i  69 */ 0x40,  /* j  6a */ 0x40,  /* k  6b */ 0x40,
  /* l  6c */ 0x20,  /* m  6d */ 0x40,  /* n  6e */ 0x40,  /* o  6f */ 0x40,
  /* p  70 */ 0x40,  /* q  71 */ 0x40,  /* r  72 */ 0x40,  /* s  73 */ 0x40,
  /* t  74 */ 0x40,  /* u  75 */ 0x40,  /* v  76 */ 0x40,  /* w  77 */ 0x40,
  /* x  78 */ 0x40,  /* y  79 */ 0x40,  /* z  7a */ 0x40
};

static const char zvsnp_flags[] =
{
  ZVSNP_FLAG_SPACE,             /* ' ' */
  0,
  0,
  ZVSNP_FLAG_HASH,              /* '#' */
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  ZVSNP_FLAG_PLUS,              /* '+' */
  0,
  ZVSNP_FLAG_MINUS,             /* '-' */
  0,
  0,
  ZVSNP_FLAG_ZERO,              /* '0' */
};

static const u_char zvsnp_next[] =
{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

static char *zvsnp_digits_l = "0123456789abcdef";
static char *zvsnp_digits_u = "0123456789ABCDEF";


/* Parser. */
static int
zvsnp_ignore (u_char *sp, u_char *p, struct zvsnp *zv)
{
  return 0;
}

static int
zvsnp_parse_flags (u_char *p, u_char *lim, struct zvsnp *zv)
{
  zv->flags = 0;
  while (p < lim)
    zv->flags |= ZVSNP_FLAG (*p++);
  return 0;
}

static int
zvsnp_parse_width (u_char *p, u_char *lim, struct zvsnp *zv)
{
  zv->width = 0;
  if (*p == '*')
    zv->width_star = 1;
  else
    while (p < lim)
      zv->width = zv->width * 10 + ZVSNP_DIGIT (*p++);

  return 0;
}

static int
zvsnp_parse_precision (u_char *p, u_char *lim, struct zvsnp *zv)
{
  zv->prec = 0;
  while (p < lim)
    zv->prec = zv->prec * 10 + (ZVSNP_DIGIT (*p++));
  return 0;
}

static int
zvsnp_parse_qualifier (u_char *p, u_char *lim, struct zvsnp *zv)
{
  zv->qual = ZVSNP_QUAL (*p);
  return 0;
}

static int
zvsnp_parse_operator (u_char *p, u_char *lim, struct zvsnp *zv)
{
  zv->opr = *p;
  return 0;
}

int (*zvsnp_parse[]) (u_char *, u_char *, struct zvsnp *) =
{
  zvsnp_ignore,
  zvsnp_parse_flags,
  zvsnp_parse_width,
  zvsnp_ignore,
  zvsnp_parse_precision,
  zvsnp_parse_qualifier,
  zvsnp_parse_operator,
  zvsnp_ignore
};


/* Expander. */
#define ZVSNP_NUM_STRLEN(SP,BUF)        ((BUF) + ZVSNP_NUM_STRLEN_MAX - (SP))

static int
zv_exp_num_l_space (char *pp, char *lim, char *sign, long slen,
                    unsigned long val, u_char base, char *digits,
                    int width, int prec)
{
  char buf[ZVSNP_NUM_STRLEN_MAX];
  char *sp = buf + ZVSNP_NUM_STRLEN_MAX;
  int wlen = 0;

  ZVSNP_MEMCPY (pp, sign, lim, slen, wlen);

  if (!(prec == 0 && val == 0))
    do
      *--sp = digits[val % base];
    while ((val = val / base) && sp > buf);

  ZVSNP_MEMSET (pp, '0', lim, prec - ZVSNP_NUM_STRLEN (sp, buf), wlen);
  ZVSNP_MEMCPY (pp, sp, lim, ZVSNP_NUM_STRLEN (sp, buf), wlen);
  ZVSNP_MEMSET (pp, ' ', lim, width - wlen, wlen);

  return wlen;
}

static int
zv_exp_num_r_space (char *pp, char *lim, char *sign, long slen,
                    unsigned long val, u_char base, char *digits,
                    int width, int prec)
{
  char buf[ZVSNP_NUM_STRLEN_MAX];
  char *sp = buf + ZVSNP_NUM_STRLEN_MAX;
  int wlen = 0;

  if (!(prec == 0 && val == 0))
    do
      *--sp = digits[val % base];
    while ((val = val / base) && sp > buf);
  
  while (ZVSNP_NUM_STRLEN (sp, buf) < prec)
    *--sp = '0';

  ZVSNP_MEMSET (pp, ' ', lim,
                width - (slen + ZVSNP_NUM_STRLEN (sp, buf)), wlen);
  ZVSNP_MEMCPY (pp, sign, lim, slen, wlen);
  ZVSNP_MEMCPY (pp, sp, lim, ZVSNP_NUM_STRLEN (sp, buf), wlen);

  return wlen;
}

static int
zv_exp_num_r_zero (char *pp, char *lim, char *sign, long slen,
                   unsigned long val, u_char base, char *digits,
                   int width, int prec)
{
  char buf[ZVSNP_NUM_STRLEN_MAX];
  char *sp = buf + ZVSNP_NUM_STRLEN_MAX;
  int wlen = 0;
  int numlen;
  int zerolen = 0;

  if (!(prec == 0 && val == 0))
    do
      *--sp = digits[val % base];
    while ((val = val / base) && sp > buf);
  
  numlen = ZVSNP_NUM_STRLEN (sp, buf);
  if (prec < 0)
    zerolen = width - (slen + numlen);
  else if (numlen < prec)
    {
      zerolen = prec - numlen;
      if (width < numlen + slen + zerolen)
        zerolen = width - (numlen + slen);
    }

  ZVSNP_MEMSET (pp, ' ', lim, width - (slen + zerolen + numlen), wlen);
  ZVSNP_MEMCPY (pp, sign, lim, slen, wlen);
  ZVSNP_MEMSET (pp, '0', lim, zerolen, wlen);
  ZVSNP_MEMCPY (pp, sp, lim, numlen, wlen);

  return wlen;
}

#define ZVSNP_EXP_MASK          (ZVSNP_FLAG_MINUS|ZVSNP_FLAG_ZERO)

int (*zv_exp_num[]) (char *, char *, char *, long,
                     unsigned long, u_char, char *, int, int) =
{
  zv_exp_num_r_space,           /* -,    -     */
  zv_exp_num_l_space,           /* -,    MINUS */
  zv_exp_num_r_zero,            /* ZERO, -     */
  zv_exp_num_l_space,           /* ZERO, MINUS */
};

#define ZVSNP_EXPAND_IPV4(P,A)                                                \
    do {                                                                      \
      ZVSNP_EXPAND_OCTET ((P), *(A));       *(P)++ = '.';                     \
      ZVSNP_EXPAND_OCTET ((P), *((A) + 1)); *(P)++ = '.';                     \
      ZVSNP_EXPAND_OCTET ((P), *((A) + 2)); *(P)++ = '.';                     \
      ZVSNP_EXPAND_OCTET ((P), *((A) + 3));                                   \
    } while (0)

static int
zv_exp_r_prefix4 (char *pp, char *lim,
                  struct zvsnp *zv, struct zvsnp_val *val)
{
  struct prefix_ipv4 *p = val->u.p;
  u_char *addr = (u_char *)&p->prefix;
  char buf[ZVSNP_PREFIX_IPV4_STRLEN_MAX];
  char *sp = buf;
  int wlen = 0;

  ZVSNP_EXPAND_IPV4 (sp, addr);  *sp++ = '/';
  ZVSNP_EXPAND_OCTET (sp, p->prefixlen);

  ZVSNP_MEMSET (pp, ' ', lim, zv->width - (sp - buf), wlen);
  ZVSNP_MEMCPY (pp, buf, lim, sp - buf, wlen);

  return wlen;
}

static int
zv_exp_l_prefix4 (char *pp, char *lim,
                  struct zvsnp *zv, struct zvsnp_val *val)
{
  struct prefix_ipv4 *p = val->u.p;
  u_char *addr = (u_char *)&p->prefix;
  char buf[ZVSNP_PREFIX_IPV4_STRLEN_MAX];
  char *sp = buf;
  int wlen = 0;

  ZVSNP_EXPAND_IPV4 (sp, addr);  *sp++ = '/';
  ZVSNP_EXPAND_OCTET (sp, p->prefixlen);

  ZVSNP_MEMCPY (pp, buf, lim, sp - buf, wlen);
  ZVSNP_MEMSET (pp, ' ', lim, zv->width - (sp - buf), wlen);

  return wlen;
}

#ifdef HAVE_IPV6
static int zv_exp_in6_addr (char *, char *, u_char *);

static int
zv_exp_r_prefix6 (char *pp, char *lim,
                  struct zvsnp *zv, struct zvsnp_val *val)
{
  int wlen = 0;
  struct prefix_ipv6 *p = val->u.p;
  u_char *addr = (u_char *)&p->prefix;
  char buf[ZVSNP_PREFIX_IPV6_STRLEN_MAX];
  char *sp;
  int len;

  len = zv_exp_in6_addr (buf, buf + ZVSNP_PREFIX_IPV6_STRLEN_MAX, addr);
  sp = buf + len;
  *sp++ = '/';
  ZVSNP_EXPAND_OCTET (sp, p->prefixlen);

  ZVSNP_MEMSET (pp, ' ', lim, zv->width - (sp - buf), wlen);
  ZVSNP_MEMCPY (pp, buf, lim, sp - buf, wlen);

  return wlen;
}

static int
zv_exp_l_prefix6 (char *pp, char *lim,
                  struct zvsnp *zv, struct zvsnp_val *val)
{
  int wlen = 0;
  struct prefix_ipv6 *p = val->u.p;
  u_char *addr = (u_char *)&p->prefix;
  char buf[ZVSNP_PREFIX_IPV6_STRLEN_MAX];
  char *sp;
  int len;

  len = zv_exp_in6_addr (buf, buf + ZVSNP_PREFIX_IPV6_STRLEN_MAX, addr);
  sp = buf + len;
  *sp++ = '/';
  ZVSNP_EXPAND_OCTET (sp, p->prefixlen);

  ZVSNP_MEMCPY (pp, buf, lim, sp - buf, wlen);
  ZVSNP_MEMSET (pp, ' ', lim, zv->width - (sp - buf), wlen);

  return wlen;
}
#endif /* HAVE_IPV6 */

static int
zv_exp_l_prefix (char *pp, char *lim,
                 struct zvsnp *zv, struct zvsnp_val *val)
{
  struct prefix *p = val->u.p;

  if (p->family == AF_INET)
    return zv_exp_l_prefix4 (pp, lim, zv, val);
#ifdef HAVE_IPV6
  else if (p->family == AF_INET6)
    return zv_exp_l_prefix6 (pp, lim, zv, val);
#endif /* HAVE_IPV6 */

  return 0;
}

static int
zv_exp_r_prefix (char *pp, char *lim,
                 struct zvsnp *zv, struct zvsnp_val *val)
{
  struct prefix *p = val->u.p;

  if (p->family == AF_INET)
    return zv_exp_r_prefix4 (pp, lim, zv, val);
#ifdef HAVE_IPV6
  else if (p->family == AF_INET6)
    return zv_exp_r_prefix6 (pp, lim, zv, val);
#endif /* HAVE_IPV6 */

  return 0;
}

#define ZVSNP_WORD_GET(P,O)            ((*((P) + (O)) << 8) | *((P) + (O) + 1))

#define ZVSNP_EXP_HEXA(P,I,W)                                                 \
    do {                                                                      \
      int _flag = 0;                                                          \
      int _val = ((I) >> 12) & 0x0F;                                          \
      if (_val)                                                               \
        {                                                                     \
          *((P)++) = zvsnp_digits_l[_val];                                    \
          _flag++;                                                            \
          (W)++;                                                              \
        }                                                                     \
      _val = ((I) >> 8) & 0x0F;                                               \
      if (_flag || _val)                                                      \
        {                                                                     \
          *((P)++) = zvsnp_digits_l[_val];                                    \
          _flag++;                                                            \
          (W)++;                                                              \
        }                                                                     \
      _val = ((I) >> 4) & 0x0F;                                               \
      if (_flag || _val)                                                      \
        {                                                                     \
          *((P)++) = zvsnp_digits_l[_val];                                    \
          _flag++;                                                            \
          (W)++;                                                              \
        }                                                                     \
      *((P)++) = zvsnp_digits_l[((I)) & 0x0F];                                \
       (W)++;                                                                 \
    } while (0)

#ifdef HAVE_IPV6
static int
zv_exp_in6_addr (char *buf, char *lim, u_char *addr)
{
  char *pp = buf;
  u_int16_t word[8];
  int i;
  int wlen = 0;

  word[0] = ZVSNP_WORD_GET (addr, 0);
  word[1] = ZVSNP_WORD_GET (addr, 2);
  word[2] = ZVSNP_WORD_GET (addr, 4);
  word[3] = ZVSNP_WORD_GET (addr, 6);
  word[4] = ZVSNP_WORD_GET (addr, 8);
  word[5] = ZVSNP_WORD_GET (addr, 10);
  word[6] = ZVSNP_WORD_GET (addr, 12);
  word[7] = ZVSNP_WORD_GET (addr, 14);

  if (word[0] == 0)
    {
      i = 1;
      while (i < 8 && word[i] == 0)
        i++;

      ZVSNP_MEMSET (pp, ':', lim, 2, wlen);
      if (i < 8)
        {
          for (; i < 7; i++)
            {
              ZVSNP_EXP_HEXA (pp, word[i], wlen);
              ZVSNP_MEMSET (pp, ':', lim, 1, wlen);
            }
          ZVSNP_EXP_HEXA (pp, word[i], wlen);
        }
    }
  else
    {
      for (i = 0; i < 7; i++)
        {
          if (word[i] == 0 && word[i + 1] == 0)
            {
              ZVSNP_MEMSET (pp, ':', lim, 1, wlen);
              while (i < 8 && word[i] == 0)
                i++;
              break;
            }

          ZVSNP_EXP_HEXA (pp, word[i], wlen);
          ZVSNP_MEMSET (pp, ':', lim, 1, wlen);
        }

      if (i < 8)
        {
          for (; i < 7; i++)
            {
              ZVSNP_EXP_HEXA (pp, word[i], wlen);
              ZVSNP_MEMSET (pp, ':', lim, 1, wlen);
            }
          ZVSNP_EXP_HEXA (pp, word[i], wlen);
        }
    }

  return wlen;
}

static int
zv_exp_l_in6_addr (char *pp, char *lim,
                   struct zvsnp *zv, struct zvsnp_val *val)
{
  u_char *addr = val->u.p;
  char buf[ZVSNP_IN6_ADDR_STRLEN_MAX];
  int wlen = 0;
  int len;

  len = zv_exp_in6_addr (buf,  buf + ZVSNP_IN6_ADDR_STRLEN_MAX, addr);
  ZVSNP_MEMCPY (pp, buf, lim, len, wlen);
  ZVSNP_MEMSET (pp, ' ', lim, zv->width - len, wlen);

  return wlen;
}

static int
zv_exp_r_in6_addr (char *pp, char *lim,
                   struct zvsnp *zv, struct zvsnp_val *val)
{
  u_char *addr = val->u.p;
  char buf[ZVSNP_IN6_ADDR_STRLEN_MAX];
  int wlen = 0;
  int len;

  len = zv_exp_in6_addr (buf,  buf + ZVSNP_IN6_ADDR_STRLEN_MAX, addr);
  ZVSNP_MEMSET (pp, ' ', lim, zv->width - len, wlen);
  ZVSNP_MEMCPY (pp, buf, lim, len, wlen);

  return wlen;
}
#endif /* HAVE_IPV6 */

static int
zv_exp_l_char (char *pp, char *lim,
               struct zvsnp *zv, struct zvsnp_val *val)
{
  int padlen = zv->width - 1 < 0 ? 0 : zv->width - 1;
  int wlen = 0;

  ZVSNP_MEMSET (pp, val->u.ul, lim, 1, wlen);
  ZVSNP_MEMSET (pp, ' ', lim, padlen, wlen);

  return wlen;
}

static int
zv_exp_r_char (char *pp, char *lim,
               struct zvsnp *zv, struct zvsnp_val *val)
{
  int padlen = zv->width - 1 < 0 ? 0 : zv->width - 1;
  int wlen = 0;

  ZVSNP_MEMSET (pp, ' ', lim, padlen, wlen);
  ZVSNP_MEMSET (pp, val->u.ul, lim, 1, wlen);

  return wlen;
}

static int
zv_exp_int (char *pp, char *lim, struct zvsnp *zv, struct zvsnp_val *val)
{
  char *sign = NULL;
  int slen = 0;

  ZVSNP_SIGN_CHAR_GET(zv, val->sign, sign, slen);
  return zv_exp_num[zv->flags & ZVSNP_EXP_MASK] (pp, lim, sign, slen,
                                                 val->u.ul, ZVSNP_BASE_DECIMAL,
                                                 zvsnp_digits_l, zv->width,
                                                 zv->prec);
}

static int
zv_exp_octal (char *pp, char *lim,
              struct zvsnp *zv, struct zvsnp_val *val)
{
  char *sign = NULL;
  int slen = 0;

  if (zv->flags & ZVSNP_FLAG_HASH)
    {
      sign = "0";
      slen = 1;
    }

  return zv_exp_num[zv->flags & ZVSNP_EXP_MASK] (pp, lim, sign, slen,
                                                 val->u.ul, ZVSNP_BASE_OCTAL,
                                                 zvsnp_digits_l, zv->width,
                                                 zv->prec);
}

#define ZVSNP_FDIGITS_MAX  128

static void
zv_exp_double (char *ibuf, char *fbuf, int *ilen, int *flen,
               double val, int prec)
{
  double fint;
  double ffrac;
  double fval;
  char *ip, *ep;
  char *fp = fbuf;
  int overflow = 0;

  /* Integer part. */
  ip = ibuf + ZVSNP_FDIGITS_MAX;
  fval = pal_modf (val, &fint);

  if (fint != 0)
    {
      do {
        ffrac = pal_modf (fint / 10, &fint); 
        *--ip = zvsnp_digits_l[(int) (ffrac * 10 + 0.1)];
      } while (fint != 0 && ip > ibuf + 1);
      *(ip - 1) = '0';
    }
  else
    *--ip = '0';

  /* Fraction part. */
  if (prec)
    {
      ffrac = fval;
      while (fp - fbuf <= prec && fp < fbuf + ZVSNP_FDIGITS_MAX)
        {
          ffrac *= 10;
          ffrac = pal_modf (ffrac + 0.01, &fint) - 0.01;
          *fp++ = zvsnp_digits_l[(int) fint];
        }

      ep = fp - 1;
      *ep += 5;

      while (*ep > '9')
        {
          *ep-- = '0';
          if (ep < fbuf)
            {
              overflow = 1;
              break;
            }
          (*ep)++;
        }

      if (overflow)
        {
          ep = ibuf + ZVSNP_FDIGITS_MAX - 1;
          while (*ep > '9')
            {
              *ep-- = '0';
              if (ep < ibuf)
                break;

              (*ep)++;
            }
        }
    }

  *ilen = ibuf + ZVSNP_FDIGITS_MAX - ip;
  *flen = fp - fbuf - 1;
}

static int
zv_exp_l_double (char *pp, char *lim,
                 struct zvsnp *zv, struct zvsnp_val *val)
{
  char ibuf[ZVSNP_FDIGITS_MAX];
  char fbuf[ZVSNP_FDIGITS_MAX];
  int ilen, flen;
  int wlen = 0;
  char sign = '\0';
    
  if (zv->prec < 0)
    zv->prec = 6;

  if (pal_isnan (val->u.df))
    {
      ZVSNP_MEMCPY (pp, "NaN", lim, 3, wlen);
      return wlen;
    }

  if (val->sign == ZVSNP_SIGN_MINUS)
    sign = '-';
  else if (zv->flags & ZVSNP_FLAG_PLUS)
    sign = '+';
  else if (zv->flags & ZVSNP_FLAG_SPACE)
    sign = ' ';

  zv_exp_double (ibuf, fbuf, &ilen, &flen, val->u.df, zv->prec);

  if (sign)
    ZVSNP_MEMSET (pp, sign, lim, 1, wlen);

  ZVSNP_MEMCPY (pp, ibuf + ZVSNP_FDIGITS_MAX - ilen, lim, ilen, wlen);
  if (zv->prec > 0 && flen)
    {
      ZVSNP_MEMSET (pp, '.', lim, 1, wlen);
      ZVSNP_MEMCPY (pp, fbuf, lim, flen, wlen);
    }

  if (wlen < zv->width)
    ZVSNP_MEMSET (pp, ' ', lim, zv->width - wlen, wlen);

  return wlen;
}

static int
zv_exp_r_double (char *pp, char *lim,
                 struct zvsnp *zv, struct zvsnp_val *val)
{
  char ibuf[ZVSNP_FDIGITS_MAX];
  char fbuf[ZVSNP_FDIGITS_MAX];
  int ilen, flen;
  int wlen = 0;
  int numlen;
  char sign = '\0';
    
  if (zv->prec < 0)
    zv->prec = 6;

  if (pal_isnan (val->u.df))
    {
      ZVSNP_MEMCPY (pp, "NaN", lim, 3, wlen);
      return wlen;
    }

  if (val->sign == ZVSNP_SIGN_MINUS)
    sign = '-';
  else if (zv->flags & ZVSNP_FLAG_PLUS)
    sign = '+';
  else if (zv->flags & ZVSNP_FLAG_SPACE)
    sign = ' ';

  zv_exp_double (ibuf, fbuf, &ilen, &flen, val->u.df, zv->prec);

  numlen = ilen;
  if (flen)
    numlen += 1 + flen;
  if (sign)
    numlen++;

  if (!(zv->flags & ZVSNP_FLAG_ZERO))
    ZVSNP_MEMSET (pp, ' ', lim, zv->width - numlen, wlen);

  if (sign)
    ZVSNP_MEMSET (pp, sign, lim, 1, wlen);

  if (zv->flags & ZVSNP_FLAG_ZERO)
    ZVSNP_MEMSET (pp, '0', lim, zv->width - numlen, wlen);

  ZVSNP_MEMCPY (pp, ibuf + ZVSNP_FDIGITS_MAX - ilen, lim, ilen, wlen);
  if (zv->prec > 0 && flen)
    {
      ZVSNP_MEMSET (pp, '.', lim, 1, wlen);
      ZVSNP_MEMCPY (pp, fbuf, lim, flen, wlen);
    }

  return wlen;
}

static int
zv_exp_pointer (char *pp, char *lim,
                struct zvsnp *zv, struct zvsnp_val *val)
{
  char *sign = "0x";
  int slen = 2;
  unsigned long v = (unsigned long)val->u.p;

  if (v == 0)
    {
      int wlen = 0;
      ZVSNP_MEMSET (pp, ' ', lim, zv->width - 5, wlen);
      ZVSNP_MEMCPY (pp, "(nil)", lim, 5, wlen);
      return wlen;
    }

  return zv_exp_num[zv->flags & ZVSNP_EXP_MASK] (pp, lim, sign, slen,
                                                 v, ZVSNP_BASE_HEXA,
                                                 zvsnp_digits_l, zv->width,
                                                 zv->prec);
}

static int
zv_exp_l_in_addr (char *pp, char *lim,
                  struct zvsnp *zv, struct zvsnp_val *val)
{
  u_char *addr = val->u.p;
  char buf[ZVSNP_IN_ADDR_STRLEN_MAX];
  char *sp = buf;
  int wlen = 0;

  ZVSNP_EXPAND_IPV4 (sp, addr);

  ZVSNP_MEMCPY (pp, buf, lim, sp - buf, wlen);
  ZVSNP_MEMSET (pp, ' ', lim, zv->width - (sp - buf), wlen);

  return wlen;
}

static int
zv_exp_r_in_addr (char *pp, char *lim,
                  struct zvsnp *zv, struct zvsnp_val *val)
{
  u_char *addr = val->u.p;
  char buf[ZVSNP_IN_ADDR_STRLEN_MAX];
  char *sp = buf;
  int wlen = 0;

  ZVSNP_EXPAND_IPV4 (sp, addr);

  ZVSNP_MEMSET (pp, ' ', lim, zv->width - (sp - buf), wlen);
  ZVSNP_MEMCPY (pp, buf, lim, sp - buf, wlen);

  return wlen;
}

static int
zv_exp_l_string (char *pp, char *lim,
                 struct zvsnp *zv, struct zvsnp_val *val)
{
  char *str = (char *)val->u.p;
  int len, padlen;
  int wlen = 0;

  ZVSNP_STRLEN (str, len);
  if (zv->prec >= 0)
    if (zv->prec < len)
      len = zv->prec;

  padlen = zv->width - len < 0 ? 0 : zv->width - len;
  ZVSNP_MEMCPY (pp, str, lim, len, wlen);
  ZVSNP_MEMSET (pp, ' ', lim, padlen, wlen);

  return wlen;
}

static int
zv_exp_r_string (char *pp, char *lim,
                 struct zvsnp *zv, struct zvsnp_val *val)
{
  char *str = (char *)val->u.p;
  int len, padlen;
  int wlen = 0;

  ZVSNP_STRLEN (str, len);
  if (zv->prec >= 0)
    if (zv->prec < len)
      len = zv->prec;

  padlen = zv->width - len < 0 ? 0 : zv->width - len;
  ZVSNP_MEMSET (pp, ' ', lim, padlen, wlen);
  ZVSNP_MEMCPY (pp, str, lim, len, wlen);

  return wlen;
}

static int
zv_exp_unsigned (char *pp, char *lim,
                 struct zvsnp *zv, struct zvsnp_val *val)
{
  return zv_exp_num[zv->flags & ZVSNP_EXP_MASK] (pp, lim, NULL, 0, val->u.ul,
                                                 ZVSNP_BASE_DECIMAL,
                                                 zvsnp_digits_l, zv->width,
                                                 zv->prec);
}

static int
zv_exp_hexa_l (char *pp, char *lim,
               struct zvsnp *zv, struct zvsnp_val *val)
{
  char *sign = NULL;
  int slen = 0;

  if (zv->flags & ZVSNP_FLAG_HASH)
    {
      sign = "0x";
      slen = 2;
    }

  return zv_exp_num[zv->flags & ZVSNP_EXP_MASK] (pp, lim, sign, slen,
                                                 val->u.ul, ZVSNP_BASE_HEXA,
                                                 zvsnp_digits_l, zv->width,
                                                 zv->prec);
}

static int
zv_exp_hexa_u (char *pp, char *lim,
               struct zvsnp *zv, struct zvsnp_val *val)
{
  char *sign = NULL;
  int slen = 0;

  if (zv->flags & ZVSNP_FLAG_HASH)
    {
      sign = "0X";
      slen = 2;
    }

  return zv_exp_num[zv->flags & ZVSNP_EXP_MASK] (pp, lim, sign, slen,
                                                 val->u.ul, ZVSNP_BASE_HEXA,
                                                 zvsnp_digits_u, zv->width,
                                                 zv->prec);
}

static int
zv_exp_ignore (char *pp, char *lim,
               struct zvsnp *zv, struct zvsnp_val *val)
{
  return -1;
}

/* Callback function to expand operater. */
struct
{
  int (*func[2]) (char *, char *, struct zvsnp *, struct zvsnp_val *);
  char type[4];
} zv_expand[] =
{
  /* { { R_FUNC, L_FUNC }, { DEFAULT, SHORT, LONG, LONG_DOUBLE } } */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* A */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* B */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* C */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* D */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* E */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* F */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* G */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* H */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* I */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* J */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* K */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* L */
  { { zv_exp_ignore,      zv_exp_ignore },      {  7,  7,  5,  7 } },   /* M */
  { { zv_exp_ignore,      zv_exp_ignore },      {  7,  7,  5,  7 } },   /* N */
  { { zv_exp_r_prefix,    zv_exp_l_prefix },    { 10, 10, 10, 10 } },   /* O */
  { { zv_exp_r_prefix4,   zv_exp_l_prefix4 },   { 10, 10, 10, 10 } },   /* P */
#ifdef HAVE_IPV6
  { { zv_exp_r_prefix6,   zv_exp_l_prefix6 },   { 10, 10, 10, 10 } },   /* Q */
  { { zv_exp_r_in6_addr,  zv_exp_l_in6_addr },  { 10, 10, 10, 10 } },   /* R */
#else /* HAVE_IPV6 */
  { { zv_exp_ignore,      zv_exp_ignore },      { 10, 10, 10, 10 } },   /* Q */
  { { zv_exp_ignore,      zv_exp_ignore },      { 10, 10, 10, 10 } },   /* R */
#endif /* HAVE_IPV6 */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* S */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* T */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* U */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* V */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* W */
  { { zv_exp_hexa_u,      zv_exp_hexa_u },      {  6,  6,  7,  6 } },   /* X */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* Y */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* Z */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* a */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* b */
  { { zv_exp_r_char,      zv_exp_l_char },      {  2,  2,  2,  2 } },   /* c */
  { { zv_exp_int,         zv_exp_int },         {  2,  2,  3,  2 } },   /* d */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* e */
  { { zv_exp_r_double,    zv_exp_l_double },    {  8,  8,  8,  8 } },   /* f */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* g */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* h */
  { { zv_exp_int,         zv_exp_int },         {  2,  2,  3,  2 } },   /* i */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* j */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* k */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* l */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* m */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* n */
  { { zv_exp_octal,       zv_exp_octal },       {  6,  6,  7,  6 } },   /* o */
  { { zv_exp_pointer,     zv_exp_pointer },     { 10, 10, 10, 10 } },   /* p */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* q */
  { { zv_exp_r_in_addr,   zv_exp_l_in_addr },   { 10, 10, 10, 10 } },   /* r */
  { { zv_exp_r_string,    zv_exp_l_string },    { 10, 10, 10, 10 } },   /* s */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* t */
  { { zv_exp_unsigned,    zv_exp_unsigned },    {  6,  6,  7,  6 } },   /* u */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* v */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* w */
  { { zv_exp_hexa_l,      zv_exp_hexa_l },      {  6,  6,  7,  6 } },   /* x */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* y */
  { { zv_exp_ignore,      zv_exp_ignore },      {  0,  0,  0,  0 } },   /* z */
};


int
zvsnprintf (char *buf, size_t size, const char *format, va_list args)
{
  char *lim = buf + size - 1;
  char *putp = buf;
  char *fmtp = (char *)format;
  int wlen = 0;
  int len;
  
  while (*fmtp != '\0')
    {
      char *fsp = fmtp;

      if (*fmtp == '%')
        {
          struct zvsnp zvsnp;
          struct zvsnp_val zvsnp_val;
          int state = ZVSNP_STATE_BEGIN;
          char *sp;
          u_char class;
          int error = 0;

          /* Init zvsnp. */
          pal_mem_set (&zvsnp, 0, sizeof (struct zvsnp));
          zvsnp.prec = -1;
          zvsnp.sp = fmtp;

          /* First, get transform strings. */
          sp = fmtp;
          while (*++fmtp != '\0'
                 && state != ZVSNP_STATE_OPERATOR
                 && state != ZVSNP_STATE_PERCENT)
            {
              int next = ZVSNP_STATE_FLAG;

              if (!ZVSNP_CLASS_RANGE (*fmtp))
                {
                  error = ZVSNP_ERROR_PARSE;
                  break;
                }

              class = zvsnp_sm[state] & ZVSNP_CLASS (*fmtp);
              if (class == 0)
                {
                  error = ZVSNP_ERROR_PARSE;
                  break;
                }

              while (next < 8 && (class & zvsnp_next[next]) == 0)
                next++;

              if (state != next)
                {
                  zvsnp_parse[state] (sp, fmtp, &zvsnp);
                  sp = fmtp;
                  state = next;
                }
            }

          if (error == ZVSNP_ERROR_PARSE)
            {
              fmtp++;
              ZVSNP_MEMCPY (putp, fsp, lim, fmtp - fsp, wlen);
            }
          else if (state == ZVSNP_STATE_OPERATOR)
            {
              zvsnp.ep = sp + 1;
              zvsnp.opr = (*sp - 'A');

              if (zvsnp.width_star)
                zvsnp.width = va_arg (args, int);

              /* Second, get value with appropriate type. */
              ZVSNP_VAL_GET (zvsnp.qual, zvsnp.opr, zvsnp_val, args);

              /* If WIDTH is not specified, align LEFT. */
              if (zvsnp.width == 0)
                zvsnp.flags |= ZVSNP_FLAG_MINUS;

              /* Finally, expand string. */
              len = ZVSNP_EXPAND (&zvsnp, putp, lim, &zvsnp_val);
              if (len < 0)
                ZVSNP_MEMCPY (putp, fsp, lim, fmtp - fsp, wlen);
              else
                {
                  putp += len;
                  wlen += len;
                }
            }
          else if (state == ZVSNP_STATE_PERCENT)
            {
              ZVSNP_MEMSET (putp, '%', lim, 1, wlen);
            }

          fsp = fmtp;
        }

      if (*fmtp == '%')
        continue;

      /* Otherwise, put char as is. */
      while (*fmtp != '\0' && *fmtp != '%')
        fmtp++;

      ZVSNP_MEMCPY (putp, fsp, lim, fmtp - fsp, wlen);

      if (*fmtp != '%')
        break;
    }

  if (lim < putp)
    *lim = '\0';
  else
    *putp = '\0';

  return wlen;
}

int
zsnprintf (char *buf, size_t size, const char *format, ...)
{
  va_list arg;
  int ret;

  va_start (arg, format);
  ret = zvsnprintf (buf, size, format, arg);
  va_end (arg);

  return ret;
}
