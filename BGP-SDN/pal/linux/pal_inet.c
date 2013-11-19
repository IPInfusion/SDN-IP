/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved. */

/*
** pal_inet.c -- Internet address translation functions.
*/

/*-----------------------------------------------------------------------------
**
** Include files
*/
#include "pal.h"

/*----------------------------------------------------------------------------
** 
** Globals
*/
#ifdef HAVE_IPNET
#ifdef HAVE_IPV6
struct Ip_in6_addr ipi_in6addr_any      = IP_IN6ADDR_ANY_INIT;
struct Ip_in6_addr ipi_in6addr_loopback = IP_IN6ADDR_LOOPBACK_INIT;
#endif /* HAVE_IPNET */
#endif /* HAVE_IPNET */

/*-----------------------------------------------------------------------------
**
** Functions
*/

/*
** pal_inet_nota ()
**
** Parameters:
**   IN  struct pal_in4_addr in         : IPv4 address to translate
**   OUT char *buf                    : pointer to character buffer
**
** Results:
**   RESULT_OK on success
*/
result_t
pal_inet_ntoa (struct pal_in4_addr in, char * buf)
{
#ifdef HAVE_IPNET
  struct in_addr tin;

  tin.s_addr = in.s_addr;
  strcpy (buf, (char *) inet_ntoa ((struct in_addr)tin));
#else
  strcpy (buf, (char *) inet_ntoa ((struct in_addr)in));
#endif /* HAVE_IPNET */

  return RESULT_OK;
}

/*
** pal_inet_aton ()
** 
** Parameters:
**   IN  char *buf                    : pointer to character buffer
**   OUT struct pal_in4_addr in         : IPv4 address to translate
**   
** Results:
**   Nonzero if address is valid, zero if not.
*/
s_int32_t 
pal_inet_aton (char *buf, struct pal_in4_addr *in)
{
  int tmp;

  tmp = inet_aton (buf, (struct in_addr *) in);
  return tmp;
}  

/*!
** Convert address to its 'presentation' form (ASCII? EBCDIC? JIS?) and store
** it in the provided buffer of given length.
**
** Parameters
**   IN  int family            : The address family
**   IN  const void *address   : A pointer to the address to convert
**   OUT char *buf           : A pointer to the buffer to use
**   IN  size_t len            : The length of the buffer
**
** Results
**   non-null pointer to buf, NULL for error
*/
const char*
pal_inet_ntop(int family,const void *address,char *buf,size_t len)
{
  const char *tmp;

  tmp = inet_ntop (family, address, (char*)buf, len);
  return tmp;
}

/*!
** Convert address from its 'presentation' form into the proper (network byte
** order) format, storing it in the provided buffer of the specified length.
**
** Parameters
**   IN  int family            : The address family
**   IN  const char *str     : A pointer to the presentation form
**   OUT void *buf             : A pointer to the buffer to use
**
** Results
**   -ve for invalid address family,
**   0 if str doesnot represent a valid network address.
**   +ve value for success
*/
s_int32_t
pal_inet_pton(int family,const char *str,void *buf)
{
  int tmp;

  tmp = inet_pton (family, str, buf);
  return tmp;
}
