/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_ASN1_H
#define _BGPSDN_ASN1_H

/* Definitions for Abstract Syntax Notation One, ASN.
   As defined in ISO/IS 8824 and ISO/IS 8825. */

typedef unsigned long   oid;
#define MAX_SUBID   0xFFFFFFFF

#define MIN_OID_LEN         2
#define MAX_OID_LEN         128

#define ASN_BOOLEAN         ((u_char)0x01)
#define ASN_INTEGER         ((u_char)0x02)
#define ASN_BIT_STR         ((u_char)0x03)
#define ASN_OCTET_STR       ((u_char)0x04)
#define ASN_NULL            ((u_char)0x05)
#define ASN_OBJECT_ID       ((u_char)0x06)
#define ASN_SEQUENCE        ((u_char)0x10)
#define ASN_SET             ((u_char)0x11)

#define ASN_UNIVERSAL       ((u_char)0x00)
#define ASN_APPLICATION     ((u_char)0x40)
#define ASN_CONTEXT         ((u_char)0x80)
#define ASN_PRIVATE         ((u_char)0xC0)

#define ASN_PRIMITIVE       ((u_char)0x00)
#define ASN_CONSTRUCTOR     ((u_char)0x20)

#define ASN_MSBIT           (0x80)
#define ASN_LONG_LEN        ASN_MSBIT
#define ASN_EXTENSION_ID    (0x1F)

struct counter64
{
  unsigned long high;
  unsigned long low;
};

/* Definition for SNMP constant. */
#define RESERVE1                0
#define RESERVE2                1
#define ACTION                  2
#define COMMIT                  3
#define FREE_DEL                4
#define UNDO                    5

#define RONLY                   0x1             /* read-only. */
#define RWRITE                  0x2             /* read-write. */
#define NOACCESS                0x0000          /* no-access. */

#define ASN_IPADDRESS           (ASN_APPLICATION | 0)
#define ASN_COUNTER             (ASN_APPLICATION | 1)
#define ASN_GAUGE               (ASN_APPLICATION | 2)
#define ASN_UNSIGNED            (ASN_APPLICATION | 2) /* RFC 1902 - same as GAUGE */
#define ASN_TIMETICKS           (ASN_APPLICATION | 3)
#define ASN_OPAQUE              (ASN_APPLICATION | 4)
#define ASN_NSAP                (ASN_APPLICATION | 5)
#define ASN_COUNTER64           (ASN_APPLICATION | 6)
#define ASN_UINTEGER            (ASN_APPLICATION | 7)

#define ASN_PRIV_INCL_RANGE     (ASN_PRIVATE | 2)
#define ASN_PRIV_EXCL_RANGE     (ASN_PRIVATE | 3)
#define ASN_PRIV_DELEGATED      (ASN_PRIVATE | 5)
#define ASN_PRIV_IMPLIED_OCTET_STR  (ASN_PRIVATE | ASN_OCTET_STR) /* 4 */
#define ASN_PRIV_IMPLIED_OBJECT_ID  (ASN_PRIVATE | ASN_OBJECT_ID) /* 6 */
#define ASN_PRIV_RETRY          (ASN_PRIVATE | 7)

#define asn_parse_int           asn1_get_int
#define asn_parse_char          asn1_get_char
#define asn_parse_header        asn1_get_header
#define asn_build_int           asn1_set_int
#define asn_build_unsigned_int  asn1_set_unsigned_int
#define asn_build_string        asn1_set_string
#define asn_build_header        asn1_set_header
#define asn_build_sequence      asn1_set_sequence
#define asn_build_objid         asn1_set_object_id

/* Prototypes. */
u_char *asn1_get_int (u_char *, size_t *, u_char *, long *, size_t);
u_char *asn1_get_char (u_char *, size_t *, u_char *, size_t *, size_t);
u_char *asn1_get_header (u_char *, size_t *, u_char *);
u_char *asn1_get_object_id (u_char *, size_t *, u_char *, oid *, size_t *);
u_char *asn1_set_int (u_char *, size_t *, u_char, long *, size_t);
u_char *asn1_set_unsigned_int (u_char *, size_t *, u_char, unsigned long *,
                               size_t);
u_char *asn1_set_unsigned_int64 (u_char *, size_t *, u_char,
                                 struct counter64 *, size_t);
u_char *asn1_set_string (u_char *, size_t *, u_char, const u_char *, size_t);
u_char *asn1_set_header (u_char *, size_t *, u_char, size_t);
u_char *asn1_set_sequence (u_char *, size_t *, u_char, size_t);
u_char *asn1_set_object_id (u_char *, size_t *, u_char, oid *, size_t);
u_char *asn1_set_null (u_char *, size_t *, u_char);
u_char *asn1_set_bitstring (u_char *, size_t *, u_char, u_char *, size_t);

#endif /* _BGPSDN_ASN1_H */
