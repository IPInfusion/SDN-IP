/*=============================================================================
**
** Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.
**
** pal_types.h -- BGP-SDN PAL common type definitions
**                for Linux
*/
#ifndef _PAL_TYPES_H
#define _PAL_TYPES_H

/*-----------------------------------------------------------------------------
**
** Include files
*/
#include <sys/utsname.h>

#include "pal_types.def"

/*-----------------------------------------------------------------------------
**
** Constans and enumerations
**
** Here is where all the literals and enumerations which are global for the OS
** and which are not provided in the OS includes need to be.
*/

/*
** Boolean values
*/
typedef enum
{
  PAL_FALSE = 0,                        /* Everybody calls zero false... */
  PAL_TRUE = (!PAL_FALSE)               /* Some want TRUE=1 or TRUE=-1 or TRUE!=0 */
}
bool_t;

/*
** Extreme values
*/
#ifndef UINT32_MAX
#define UINT32_MAX      0xFFFFFFFF
#endif
#define SINT32_MAX      0x7FFFFFFF
#define SINT32_MIN      0x80000000
#ifndef UINT16_MAX
#define UINT16_MAX      0xFFFF
#endif
#define SINT16_MAX      0x7FFF
#define SINT16_MIN      0x8000
#ifndef UINT8_MAX
#define UINT8_MAX       0xFF
#endif
#define SINT8_MAX       0x7F
#define SINT8_MIN       0x80


#ifndef UINT32_MIN
#define UINT32_MIN 0x00000000
#endif

#ifndef UINT16_MIN
#define UINT16_MIN 0x0000
#endif

#ifndef UINT8_MIN
#define UINT8_MIN 0x00
#endif

/*
** Some result codes which are returned.  Don't use the numbers!  Other
** error codes are defined by the platform.
*/
#define RESULT_OK                   0
#define RESULT_NO_SECONDARY_IF      1
#define RESULT_NO_SUPPORT           0x80
#define RESULT_ERROR                -1

/*
** Errors
*/
/*
** RESERVED: Error codes 125 through 142 have been reserved for VR.
*/
#ifdef HAVE_VRRP
#define EVRRP           143     /* Generic VRRP Error return. */
#define EVRRP_SOCK_OPEN 144     /* Error opening VRRP Socket. */
#define EVRRP_SOCK_BIND 145     /* Error binding socket. */
#define EVRRP_SOCK_SEND 146     /* Error sending packet via socket. */
#define EVRRP_MAC_SET   147     /* Error setting Mac address. */
#define EVRRP_MAC_UNSET 148     /* Error unsetting Mac address. */
#define EVRRP_GARP_SEND 149     /* Error sending gratuitous ARP. */
#endif /* HAVE_VRRP */

#define MAX_VRF_NAMELEN  64

/*-----------------------------------------------------------------------------
**
** Types
*/

/*
** This is used as pointer or whatever the pal implementation needs to be able
** to track its own local variables.  This will need to be typecast probably
** by individual pal modules.
*/
typedef void *pal_handle_t;

/*
** These types are unsigned and signed variations of known fixed length ints.
** We call chars ints when we use them as ints.
*/
#if 0 /* Please define these if not present in sys/types.h.  */
typedef unsigned int       u_int32_t; /* 32 bit unsigned integer */
typedef unsigned short u_int16_t; /* 16 bit unsigned integer */
typedef unsigned char           u_int8_t;  /* 8 bit unsigned integer */
#endif

typedef signed int s_int32_t;   /* 32 bit signed integer */
typedef signed short s_int16_t; /* 16 bit signed integer */
typedef signed char s_int8_t;   /* 8 bit signed integer */

typedef union {
        u_int8_t  c[8];
        u_int16_t s[4];
        u_int32_t l[2];
        u_int64_t ll;
} ut_int64_t;                    /* 64 bit unsigned integer */

typedef union {
        s_int8_t  c[8];
        s_int16_t s[4];
        s_int32_t l[2];
} st_int64_t;                    /* 64 bit signed integer */

#define PAL_ADD_64_UINT(A,B,RESULT)                             \
   do {                                                         \
   RESULT.l[0] = A.l[0] + B.l[0];                               \
   RESULT.l[1] = A.l[1] + B.l[1];                               \
   RESULT.l[1] += (RESULT.l[0] < MAX(A.l[0],B.l[0])) ? 1 : 0;   \
  } while (0)

#define PAL_SUB_64_UINT(A,B,RESULT)                             \
   do {                                                         \
   ut_int64_t *_res = &RESULT;                                  \
   if((A.l[1] < B.l[1]) ||                                      \
      ((A.l[1] == B.l[1]) &&                                    \
       (A.l[0] < B.l[0])))                                      \
     {                                                          \
        _res->l[0] = 0xFFFFFFFF - A.l[0];                       \
        _res->l[1] = 0xFFFFFFFF - A.l[1];                       \
        PAL_ADD_64_UINT(RESULT,B,RESULT);                       \
     }                                                          \
   else                                                         \
     {                                                          \
        if(A.l[0] < B.l[0])                                     \
          {                                                     \
             _res->l[0] = (0xFFFFFFFF -                         \
                     (B.l[0] - A.l[0] - 1));                    \
              A.l[1] -= 1;                                      \
          }                                                     \
        else                                                    \
          {                                                     \
             _res->l[0] = (A.l[0] - B.l[0]);                    \
          }                                                     \
        _res->l[1] = A.l[1] - B.l[1];                           \
     }                                                          \
  } while (0)

#define PAL_MUL_32_UINT(A,B,RESULT)                                    \
   do {                                                                \
   u_int32_t _a, _b, _c, _d;                                           \
   u_int32_t _x, _y;                                                   \
   ut_int64_t *_res = &RESULT;                                         \
                                                                       \
   _a = ((A) >> 16) & 0xffff;                                          \
   _b = (A) & 0xffff;                                                  \
   _c = ((B) >> 16) & 0xffff;                                          \
   _d = (B) & 0xffff;                                                  \
                                                                       \
   _res->l[0] = _b * _d;                                               \
   _x = _a * _d + _c * _b;                                             \
   _y = (((_res->l[0]) >> 16) & 0xffff) + _x;                          \
                                                                       \
   _res->l[0] = (((_res->l[0]) & 0xffff)  | ((_y & 0xffff) << 16));    \
   _res->l[1] = ((_y >> 16) & 0xffff);                                 \
                                                                       \
   _res->l[1] += (_a * _c);                                            \
  } while (0)

/*
** This is used to specify memory lengths.  It is probably whatever the
** architecture calls an 'unsigned int', but just in case (the IA16 and IA32
** make this point where int=16b but memory can be 32b).
*/
/* size_t provided by OS */
#define pal_size_t      size_t

/*
** This type must be large enough to hold results, but may be larger if that
** would improve efficiency on the platform.  It needs to be signed.
*/
typedef signed int result_t;    /* result from a function call */

/*
** These types are floating point of known fixed lengths.
*/
typedef double float64_t;       /* 64 bit float; okay resolution */

/* Some library such as Intel NP's SDK defines float32_t.  In such
   case, we need to have a mechanism to avoid the typedef conflict.
   There is no smart way of doing it.  HAVE_FLOAT32_T is defined, when
   third party library defines float32_t.  */

#ifdef HAVE_FLOAT32_T
#define float32_t float
#else
typedef float float32_t;        /* 32 bit float; poor resolution */
#endif /* HAVE_FLOAT32_T */

/*
** An IPv4 address.  Can probably #define on a real OS.
*/
#ifdef HAVE_IPNET
#define pal_in4_addr Ip_in_addr
#ifdef HAVE_IPV6
#define pal_in6_addr Ip_in6_addr
#endif /* HAVE_IPV6 */

#define in6_pktinfo Ip_in6_pktinfo

#define pal_socklen_t pal_sock_len_t

#else /* ! HAVE_IPNET */

#define pal_in4_addr in_addr
#ifdef HAVE_IPV6
#define pal_in6_addr in6_addr
#endif /* HAVE_IPV6 */

#define pal_socklen_t socklen_t

#endif /* ! HAVE_IPNET */


/*
** Structure describing the system and machine.
*/
/*
struct pal_utsname {
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
  char domainname[65];
};
*/
#define pal_utsname utsname

/*
** Used in virtual routing, but must be defined for lots of other places.
*/
#ifdef HAVE_VRX
#define VRF_ID_UNSPEC           0
#define VRF_ID_MAIN             0
#define VRF_ID_MIN              1
#define VRF_ID_MAX              252
#define VRF_ID_DISABLE          VRF_ID_MAX + 1

#define FIB_ID_UNSPEC           0
#define FIB_ID_MAIN             0
#define FIB_ID_LOCAL            0
#define FIB_ID_MIN              1
#define FIB_ID_MAX              252
#define FIB_ID_DISABLE          0

#else
#define VRF_ID_UNSPEC           0
#define VRF_ID_MAIN             0
#define VRF_ID_MIN              1
#define VRF_ID_MAX              65534
#define VRF_ID_DISABLE          VRF_ID_MAX + 1

#define FIB_ID_MAIN             RT_TABLE_UNSPEC
#define FIB_ID_LOCAL            RT_TABLE_LOCAL
#define FIB_ID_UNSPEC           254
#define FIB_ID_MIN              1
#define FIB_ID_MAX              252
#define FIB_ID_DISABLE          255
#endif /* HAVE_VRX */

typedef u_int32_t vrf_id_t;             /* virtual router ID */
typedef u_char fib_id_t;                /* forwarding table ID */

#ifndef HAVE_IPNET

/*
** IP Packet header.
*/
#define pal_in4_header ip

#define PAL_IPLEN_WORDS2BYTES(IP_LEN)      ((IP_LEN) << 2)

#ifdef HAVE_IPV6
/*
** IPv6 Packet header.
*/
#define pal_in6_header ip6_hdr
#define pal_ip6_ext ip6_ext
#define pal_ip6_hbh ip6_hbh
#define pal_ip6_dest ip6_dest
#define pal_ip6_rthdr ip6_rthdr
#define pal_ip6_rthdr0 ip6_rthdr0
#define pal_ip6_frag ip6_frag
#define pal_ip6_opt_router ip6_opt_router
#endif /* HAVE_IPV6 */

#ifdef HAVE_IPV6
#define pal_in6addr_loopback    in6addr_loopback
#define pal_in6addr_any        in6addr_any
#endif /* HAVE_IPV6 */

#else /* HAVE_IPNET */

/*
** IP Packet header.
*/
struct pal_in4_header
{
#ifdef IP_LITTLE_ENDIAN
  unsigned int ip_hl:4;               /* header length */
  unsigned int ip_v:4;                /* version */
#endif
#ifdef IP_BIG_ENDIAN
  unsigned int ip_v:4;                /* version */
  unsigned int ip_hl:4;               /* header length */
#endif
  u_int8_t ip_tos;                    /* type of service */
  u_short ip_len;                     /* total length */
  u_short ip_id;                      /* identification */
  u_short ip_off;                     /* fragment offset field */
#ifndef IP_RF
#define IP_RF 0x8000                    /* reserved fragment flag */
#endif /* IP_RF */
#ifdef IP_DF
#define IP_DF 0x4000                    /* dont fragment flag */
#endif /* IP_DF */
#ifdef IP_MF
#define IP_MF 0x2000                    /* more fragments flag */
#endif /* IP_MF */
#ifdef IP_OFFMASK
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
#endif /* IP_OFFMASK */
  u_int8_t ip_ttl;                    /* time to live */
  u_int8_t ip_p;                      /* protocol */
  u_short ip_sum;                     /* checksum */
  struct Ip_in_addr ip_src, ip_dst;      /* source and dest address */
};

#define PAL_IPLEN_WORDS2BYTES(IP_LEN)      ((IP_LEN) << 2)

#ifdef HAVE_IPV6
/*
** IPv6 Packet header.
*/
struct pal_in6_header
  {
    union
      {
        struct Ip_ip6_hdrctl
          {
            u_int32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                        20 bits flow-ID */
            u_int16_t ip6_un1_plen;   /* payload length */
            u_int8_t  ip6_un1_nxt;    /* next header */
            u_int8_t  ip6_un1_hlim;   /* hop limit */
          } ip6_un1;
        u_int8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
      } ip6_ctlun;
    struct pal_in6_addr ip6_src;      /* source address */
    struct pal_in6_addr ip6_dst;      /* destination address */
  };


/* Generic extension header.  */
struct pal_ip6_ext
  {
    uint8_t  ip6e_nxt;          /* next header.  */
    uint8_t  ip6e_len;          /* length in units of 8 octets.  */
  };

/* Hop-by-Hop options header.  */
struct pal_ip6_hbh
  {
    uint8_t  ip6h_nxt;          /* next header.  */
    uint8_t  ip6h_len;          /* length in units of 8 octets.  */
    /* followed by options */
  };

/* Destination options header */
struct pal_ip6_dest
  {
    uint8_t  ip6d_nxt;          /* next header */
    uint8_t  ip6d_len;          /* length in units of 8 octets */
    /* followed by options */
  };

/* Routing header */
struct pal_ip6_rthdr
  {
    uint8_t  ip6r_nxt;          /* next header */
    uint8_t  ip6r_len;          /* length in units of 8 octets */
    uint8_t  ip6r_type;         /* routing type */
    uint8_t  ip6r_segleft;      /* segments left */
    /* followed by routing type specific data */
  };

/* Type 0 Routing header */
struct pal_ip6_rthdr0
  {
    uint8_t  ip6r0_nxt;         /* next header */
    uint8_t  ip6r0_len;         /* length in units of 8 octets */
    uint8_t  ip6r0_type;        /* always zero */
    uint8_t  ip6r0_segleft;     /* segments left */
    uint8_t  ip6r0_reserved;    /* reserved field */
    uint8_t  ip6r0_slmap[3];    /* strict/loose bit map */
    struct in6_addr  ip6r0_addr[1];  /* up to 23 addresses */
  };

/* Fragment header */
struct pal_ip6_frag
  {
    uint8_t   ip6f_nxt;         /* next header */
    uint8_t   ip6f_reserved;    /* reserved field */
    uint16_t  ip6f_offlg;       /* offset, reserved, and flag */
    uint32_t  ip6f_ident;       /* identification */
  };

/* Router Alert Option */
struct pal_ip6_opt_router
  {
    uint8_t  ip6or_type;
    uint8_t  ip6or_len;
    uint8_t  ip6or_value[2];
  };

#endif /* HAVE_IPV6 */

#ifdef HAVE_IPV6
extern struct Ip_in6_addr ipi_in6addr_loopback;
extern struct Ip_in6_addr ipi_in6addr_any;
#define pal_in6addr_loopback   ipi_in6addr_loopback
#define pal_in6addr_any        ipi_in6addr_any
#endif /* HAVE_IPV6 */

#endif /* HAVE_IPNET */

/*
** UDP Packet header.
*/
struct  pal_udp_header
{
  u_int16_t uh_sport;
  u_int16_t uh_dport;
  u_int16_t uh_ulen;
  u_int16_t uh_sum;
};

/*****************************************************************************
                   ** License Manager for Linux **
*****************************************************************************/
#ifdef HAVE_LICENSE_MGR
#include "../../lmlicmgr/include/lm_api.h"
#define lic_mgr_handle_t  LS_HANDLE
#ifndef HAVE_SPLAT
#define LIC_MGR_FEATURE_IPV4 "IPV4RHAT"
#define LIC_MGR_FEATURE_IPV6 "IPV6RHAT"
#define LIC_MGR_FEATURE_BGP "BGPRHAT"
#else /* HAVE_SPLAT */
#define LIC_MGR_FEATURE_IPV4 "IPV4SPLAT"
#define LIC_MGR_FEATURE_IPV6 "IPV6SPLAT"
#define LIC_MGR_FEATURE_BGP "BGPSPLAT"
#endif /* HAVE_SPLAT */
#define LIC_MGR_VERSION_IPV4 ""
#define LIC_MGR_VERSION_IPV6 ""
#endif /* HAVE_LICENSE_MGR */

/*-----------------------------------------------------------------------------
**
** Done
*/
#endif /* def _PAL_TYPES_H */
