/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_SMUX_H
#define _BGPSDN_SMUX_H

#ifdef HAVE_SNMP

#include "asn1.h"
#include "pal.h"

#include "pal_socket.h"
#include "lib.h"

#define SMUX_PORT_DEFAULT 199

#define SMUXMAXPKTSIZE    1500
#define SMUXMAXSTRLEN      256

#define SMUX_OPEN       (ASN_APPLICATION | ASN_CONSTRUCTOR | 0)
#define SMUX_CLOSE      (ASN_APPLICATION | ASN_PRIMITIVE | 1)
#define SMUX_RREQ       (ASN_APPLICATION | ASN_CONSTRUCTOR | 2)
#define SMUX_RRSP       (ASN_APPLICATION | ASN_PRIMITIVE | 3)
#define SMUX_SOUT       (ASN_APPLICATION | ASN_PRIMITIVE | 4)

#define SMUX_GET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0)
#define SMUX_GETNEXT    (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)
#define SMUX_GETRSP     (ASN_CONTEXT | ASN_CONSTRUCTOR | 2)
#define SMUX_SET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 3)
#define SMUX_TRAP       (ASN_CONTEXT | ASN_CONSTRUCTOR | 4)

#define SMUX_MAX_FAILURE 3

enum smux_event
{
  SMUX_SCHEDULE,
  SMUX_CONNECT,
  SMUX_READ,
  SMUX_RESTART,
  SMUX_STOP
};


void smux_initialize (struct lib_globals *);
void smux_event (struct lib_globals *, enum smux_event, s_int32_t);
#ifdef HAVE_IPV6
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
#endif /*HAVE_IPV6*/
#endif /* HAVE_SNMP */

#endif /* _BGPSDN_SMUX_H */
