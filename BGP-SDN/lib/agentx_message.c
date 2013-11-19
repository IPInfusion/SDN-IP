/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#ifdef HAVE_SNMP
#ifdef HAVE_AGENTX

#include "snmp.h"
#include "agentx.h"
#include "agentx_api.h"
#include "agentx_message.h"
#include "thread.h"
#include "log.h"
#include "snprintf.h"
#include "linklist.h"
#include "bgpsdn_version.h"
#include "sockunion.h"
#include "asn1.h"

const char *
agentx_cmd (u_char code)
{
  switch (code) {
    case AGENTX_MSG_OPEN:
      return "Open";
    case AGENTX_MSG_CLOSE:
      return "Close";
    case AGENTX_MSG_REGISTER:
      return "Register";
    case AGENTX_MSG_UNREGISTER:
      return "Unregister";
    case AGENTX_MSG_GET:
      return "Get";
    case AGENTX_MSG_GETNEXT:
      return "Get Next";
    case AGENTX_MSG_GETBULK:
      return "Get Bulk";
    case AGENTX_MSG_TESTSET:
      return "Test Set";
    case AGENTX_MSG_COMMITSET:
      return "Commit Set";
    case AGENTX_MSG_UNDOSET:
      return "Undo Set";
    case AGENTX_MSG_CLEANUPSET:
      return "Cleanup Set";
    case AGENTX_MSG_NOTIFY:
      return "Notify";
    case AGENTX_MSG_PING:
      return "Ping";
    case AGENTX_MSG_INDEX_ALLOCATE:
      return "Index Allocate";
    case AGENTX_MSG_INDEX_DEALLOCATE:
      return "Index Deallocate";
    case AGENTX_MSG_ADD_AGENT_CAPS:
      return "Add Agent Caps";
    case AGENTX_MSG_REMOVE_AGENT_CAPS:
      return "Remove Agent Caps";
    case AGENTX_MSG_RESPONSE:
      return "Response";
    default:
      return "Unknown";
  }
}

/*---------------------------------------------------*
 *  Utility functions for building an AgentX packet  *
 *---------------------------------------------------*/

#define AGENTX_MASK_OFFSET      ((sizeof (u_int32_t) - 1) * 8)

int
agentx_build_int (struct lib_globals *zg,
                  u_char **buf, size_t *buf_len, size_t *out_len,
                  u_int32_t value, int network_order)
{
  u_int32_t ivalue = value;
  size_t ilen = *out_len;
  u_int32_t _mask = (0xFF) << AGENTX_MASK_OFFSET;
  u_int32_t i = 0;

  while ((*out_len + 4) >= *buf_len) {
    if (!(snmp_realloc (buf, buf_len))) {
      return 0;
    }
  }

  /* Network byte order : Most  Significant  Byte  first (BIG_ENDIAN) */
  if (network_order) {
    for (i = 0; i < 4; i++) {
      *(*buf + *out_len) = (u_char) ((value & _mask) >> AGENTX_MASK_OFFSET);
      (*out_len)++;
      (value) <<= 8;
    }
  /* Host byte order : Least  Significant  Byte  first */
  } else {
    for (i = 0; i < 4; i++) {
      *(*buf + *out_len) = (u_char) value & 0xff;
      (*out_len)++;
      value >>= 8;
    }
  }
  if (IS_SUBAG_DEBUG_SEND && IS_SUBAG_DEBUG_DETAIL)
    zlog_info (zg, "->      Integer: %lu (0x%.2lX)", ivalue, ivalue);
  return (*out_len - ilen); /* built length may be 4 or 8 */
}

void
_agentx_build_int (struct lib_globals *zg,
                   u_char *buf, u_int32_t value, int network_byte_order)
{
  u_int32_t orig_val = value;
  u_int32_t _mask = (0xFF) << AGENTX_MASK_OFFSET;
  u_int32_t i = 0;

  /* Network byte order : Most  Significant  Byte  first (BIG_ENDIAN) */
  if (network_byte_order) {
    for (i = 0; i < 4; i++) {
      *(buf + i) = (u_char) ((value & _mask) >> AGENTX_MASK_OFFSET);
      (value) <<= 8;
    }
  /* Host byte order : Least  Significant  Byte  first */
  } else {
    for (i = 0; i < 4; i++) {
      *(buf + i) = (u_char) (value & 0xff);
      (value) >>= 8;
    }
  }
  if (IS_SUBAG_DEBUG_SEND && IS_SUBAG_DEBUG_DETAIL)
    zlog_info (zg, "->      Integer (length of PDU) : %ld (0x%.2X)",
               orig_val, orig_val);
}

int
agentx_build_short (struct lib_globals *zg,
                    u_char **buf, size_t *buf_len, size_t *out_len,
                    u_int16_t value, int network_order)
{
  u_int16_t ivalue = value;
  size_t ilen = *out_len;
  u_int16_t i = 0;

  while ((*out_len + 2) >= *buf_len) {
    if (!(snmp_realloc (buf, buf_len))) {
      return 0;
    }
  }

  /* Network byte order : Most  Significant  Byte  first (BIG_ENDIAN) */
  if (network_order) {
    for (i = 0; i < 2; i++) {
      *(*buf + *out_len) = (u_char) ((value & 0xff00) >> 8);
      (*out_len)++;
      (value) <<= 8;
    }
  /* Host byte order : Least  Significant  Byte  first */
  } else {
    for (i = 0; i < 2; i++) {
      *(*buf + *out_len) = (u_char) value & 0xff;
      (*out_len)++;
      value >>= 8;
    }
  }
  if (IS_SUBAG_DEBUG_SEND && IS_SUBAG_DEBUG_DETAIL)
    zlog_info (zg, "->      Short: %hu (0x%.2hX)", ivalue, ivalue);
  return (*out_len - ilen); /* built length may be 2 */
}

int
agentx_build_oid (struct lib_globals *zg,
                  u_char **buf, size_t *buf_len, size_t *out_len,
                  int inclusive, oid *name, size_t name_len,
                  int network_order)
{
  size_t ilen = *out_len, i = 0;
  int prefix = 0;

  if (IS_SUBAG_DEBUG_SEND && IS_SUBAG_DEBUG_DETAIL)
    snmp_oid_dump (zg, "->      OID:", name, name_len);

  if (name_len == 2 && (name[0] == 0 && name[1] == 0)) {
    name_len = 0;           /* Null OID */
  }

  /* 'Compact' internet OIDs */
  if (name_len >= 5 && (name[0] == 1 && name[1] == 3 &&
                        name[2] == 6 && name[3] == 1)) {
    prefix = name[4];
    name += 5;
    name_len -= 5;
  }

  while ((*out_len + 4 + (4 * name_len)) >= *buf_len) {
    if (!(snmp_realloc (buf, buf_len))) {
      return 0;
    }
  }

  *(*buf + *out_len) = (u_char) name_len;
  (*out_len)++;
  *(*buf + *out_len) = (u_char) prefix;
  (*out_len)++;
  *(*buf + *out_len) = (u_char) inclusive;
  (*out_len)++;
  *(*buf + *out_len) = (u_char) 0x00;
  (*out_len)++;

  if (IS_SUBAG_DEBUG_SEND) {
    zlog_info (zg, "->      OID Header:");
    zlog_info (zg, "          # subids: %d (0x%.2X)", name_len, name_len);
    zlog_info (zg, "          prefix: %d (0x%.2X)", prefix, prefix);
    zlog_info (zg, "          inclusive: %d (0x%.2X)", inclusive, inclusive);
    snmp_oid_dump (zg, "        OID Segments", name, name_len);
  }

  for (i = 0; i < name_len; i++) {
    if (!agentx_build_int (zg, buf, buf_len, out_len,
                           name[i], network_order)) {
      return 0;
    }
  }

  return (*out_len - ilen); /* built length may be greater than 4 */
}

int
agentx_build_string (struct lib_globals *zg,
                     u_char **buf, size_t *buf_len, size_t *out_len,
                     u_char *string, size_t string_len, int network_order)
{
  size_t ilen = *out_len, i = 0;

  while ((*out_len + 4 + (4 * ((string_len + 3) / 4))) >= *buf_len) {
    if (!(snmp_realloc (buf, buf_len))) {
      return 0;
    }
  }

  if (IS_SUBAG_DEBUG_SEND) {
    if (string_len == 0)
      zlog_info (zg, "->      String: <empty>");
    else {
      zlog_info (zg, "->      Build String:");
      zlog_info (zg, "          Length: %d (4-byte: %d)",
                 string_len, ((string_len + 3) / 4) * 4);
      zlog_info (zg, "          String: %s", string);
    }
  }
  if (!agentx_build_int (zg, buf, buf_len, out_len,
                         string_len, network_order)) {
    return 0;
  }

  if (string_len == 0) {
    return 1;
  }

  pal_mem_move ((*buf + *out_len), string, string_len);
  *out_len += string_len;

  /* Pad to a multiple of 4 bytes if necessary (per RFC 2741). */
  if (string_len % 4 != 0) {
    for (i = 0; i < 4 - (string_len % 4); i++) {
      *(*buf + *out_len) = 0;
      (*out_len)++;
    }
  }

  return (*out_len - ilen); /* built length may be greater than 1 */
}

int
agentx_build_varbind (struct lib_globals *zg,
                      u_char **buf, size_t *buf_len, size_t *out_len,
                      struct agentx_variable_list *vp,
                      int network_order)
{
  /* Encodes variable bindings */
  if (IS_SUBAG_DEBUG_SEND) {
    zlog_info (zg, "->      VarBind");
    zlog_info (zg, "          Value Type: %04x", vp->type);
  }
  /* value type (v.type) */
  if (vp->type == ASN_PRIV_INCL_RANGE || vp->type == ASN_PRIV_EXCL_RANGE) {
    if (!agentx_build_short
         (zg, buf, buf_len, out_len,
          (unsigned short) ASN_OBJECT_ID, network_order)) {
      return 0;
    }
  } else {
   if (!agentx_build_short
        (zg, buf, buf_len, out_len,
         (unsigned short) vp->type, network_order)) {
      return 0;
    }
  }

  while ((*out_len + 2) >= *buf_len) {
    if (!(snmp_realloc (buf, buf_len))) {
      return 0;
    }
  }

  /* value <reserved> */
  *(*buf + *out_len) = 0;
  (*out_len)++;
  *(*buf + *out_len) = 0;
  (*out_len)++;

  if (IS_SUBAG_DEBUG_SEND)
    snmp_oid_dump (zg, "          Value name", vp->name, vp->name_length);
  /* value name (v.name) : object identifier format */
  if (!agentx_build_oid (zg, buf, buf_len, out_len, 0,
                         vp->name, vp->name_length, network_order)) {
    return 0;
  }

  /* value data (v.data) : dependent on value type (v.type) */
  switch (vp->type) {
    case ASN_INTEGER:
    case ASN_COUNTER:
    case ASN_GAUGE:
    case ASN_TIMETICKS:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "          Value data: %lu (0x%.2lX)",
                   *(vp->val.integer), *(vp->val.integer));
      if (!agentx_build_int (zg, buf, buf_len, out_len,
                             *(vp->val.integer), network_order)) {
        return 0;
      }
      break;

    case ASN_OCTET_STR:
    case ASN_IPADDRESS:
    case ASN_OPAQUE:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "          Value data: %s (len: %d)",
                   vp->val.string, vp->val_len);
      if (!agentx_build_string
          (zg, buf, buf_len, out_len, vp->val.string,
           vp->val_len, network_order)) {
        return 0;
      }
      break;

    case ASN_OBJECT_ID:
    case ASN_PRIV_EXCL_RANGE:
    case ASN_PRIV_INCL_RANGE:
      if (IS_SUBAG_DEBUG_SEND)
        snmp_oid_dump (zg, "          Value data",
                           (oid *) vp->val.string, vp->val_len / sizeof(oid));
      if (!agentx_build_oid
          (zg, buf, buf_len, out_len, 1, vp->val.objid,
           vp->val_len / sizeof(oid), network_order)) {
        return 0;
      }
      break;

    case ASN_COUNTER64:
      if (network_order) {
        if (IS_SUBAG_DEBUG_SEND) {
          zlog_info (zg, "          Value data: Build Counter64 (high, low)");
          zlog_info (zg, "                      high %lu (0x%.2X)",
                     vp->val.counter64->high, vp->val.counter64->high);
          zlog_info (zg, "                      low  %lu (0x%.2X)",
                     vp->val.counter64->low, vp->val.counter64->low);
        }
        if (!agentx_build_int
            (zg, buf, buf_len, out_len,
             vp->val.counter64->high, network_order)
            || !agentx_build_int (zg, buf, buf_len, out_len,
                                  vp->val.counter64->low,
                                  network_order)) {
          return 0;
        }
      } else {
        if (IS_SUBAG_DEBUG_SEND) {
          zlog_info (zg, "          Value data: Build Counter64 (low, high)");
          zlog_info (zg, "                      low  %lu (0x%.2X)",
                     vp->val.counter64->low, vp->val.counter64->low);
          zlog_info (zg, "                      high %lu (0x%.2X)",
                     vp->val.counter64->high, vp->val.counter64->high);
        }
        if (!agentx_build_int
            (zg, buf, buf_len, out_len,
             vp->val.counter64->low, network_order)
            || !agentx_build_int (zg, buf, buf_len, out_len,
                                  vp->val.counter64->high,
                                  network_order)) {
          return 0;
        }
      }
      break;

    case ASN_NULL:
    case SNMP_NOSUCHOBJECT:
    case SNMP_NOSUCHINSTANCE:
    case SNMP_ENDOFMIBVIEW:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "          Value data: NULL");
      break;

    default:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "AgentX: agentx_build_varbind, unknown type %d (0x%02x)",
                   vp->type, vp->type);
      return 0;
  }
  return 1;
}

int
agentx_build_header (struct lib_globals *zg,
                     u_char **buf, size_t *buf_len, size_t *out_len,
                     struct agentx_pdu *pdu)
{
  size_t ilen = *out_len;
  const int network_order = pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER;

  while ((*out_len + 4) >= *buf_len) {
    if (!(snmp_realloc (buf, buf_len))) {
      return 0;
    }
  }

  /* First 4 bytes are version, pdu type, flags, and a 0 reserved byte. */

  *(*buf + *out_len) = AGENTX_VERSION_1;
  (*out_len)++;
  *(*buf + *out_len) = pdu->command;
  (*out_len)++;
  *(*buf + *out_len) = (u_char) (pdu->flags & AGENTX_MSG_FLAGS_MASK);
  (*out_len)++;
  *(*buf + *out_len) = 0;
  (*out_len)++;

  if (IS_SUBAG_DEBUG_SEND) {
    zlog_info (zg, "->  AgentX Header:");
    zlog_info (zg, "      Version: %d", AGENTX_VERSION_1);
    zlog_info (zg, "      Type: %d (%s)",
               pdu->command, agentx_cmd((u_char)pdu->command));
    zlog_info (zg, "      Flags: %02x",
               (pdu->flags & AGENTX_MSG_FLAGS_MASK));
    zlog_info (zg, "      <reserved>: 0");
  }

  if (IS_SUBAG_DEBUG_SEND)
    zlog_info (zg, "      Session ID: %lu (0x%.2lX)",
               pdu->sessid, pdu->sessid);
  if (!agentx_build_int (zg, buf, buf_len, out_len,
                         pdu->sessid, network_order)) {
    return 0;
  }

  if (IS_SUBAG_DEBUG_SEND)
    zlog_info (zg, "      Transaction ID: %lu (0x%.2lX)",
               pdu->transid, pdu->transid);
  if (!agentx_build_int (zg, buf, buf_len, out_len,
                         pdu->transid, network_order)) {
    return 0;
  }

  if (IS_SUBAG_DEBUG_SEND)
    zlog_info (zg, "      Packet ID: %lu (0x%.2lX)",
               pdu->reqid, pdu->reqid);
  if (!agentx_build_int (zg, buf, buf_len, out_len,
                         pdu->reqid, network_order)) {
    return 0;
  }

  if (IS_SUBAG_DEBUG_SEND)
    zlog_info (zg, "      Dummy Length: -(");
  if (!agentx_build_int (zg, buf, buf_len, out_len,
                         0, network_order)) {
    return 0;
  }

  if (pdu->flags & AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT) {
    if (IS_SUBAG_DEBUG_SEND)
      zlog_info (zg, "      Community: %s (len=%d)",
                 pdu->community, pdu->community_len);
    if (!agentx_build_string
        (zg, buf, buf_len, out_len, pdu->community,
         pdu->community_len, network_order)) {
      return 0;
    }
  }

  return (*out_len - ilen); /* built length may be greater than 20 */
}

static int
_agentx_build (struct lib_globals *zg,
               u_char **buf, size_t *buf_len, size_t *out_len,
               struct agentx_session *session, struct agentx_pdu *pdu)
{
  size_t ilen = *out_len, prefix_offset = 0;
  struct agentx_variable_list *vp;
  int inc, i = 0;
  const int network_order = pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER;

  session->lib_errno = 0;
  session->sys_errno = 0;

  /* check a type of pdu in subagent */
  switch (pdu->command) {
    case AGENTX_MSG_GET:
    case AGENTX_MSG_GETNEXT:
    case AGENTX_MSG_GETBULK:
    case AGENTX_MSG_TESTSET:
    case AGENTX_MSG_COMMITSET:
    case AGENTX_MSG_UNDOSET:
    case AGENTX_MSG_CLEANUPSET:
      zlog_warn (zg, "(Warning) AgentX: build %s-PDU in subagent",
                 agentx_cmd((u_char)pdu->command));
      break;
    default:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "AgentX: build %s-PDU",
                   agentx_cmd((u_char)pdu->command));
      break;
  }

  /* Various PDU types don't include context information (RFC 2741, p. 20). */
  switch (pdu->command) {
    case AGENTX_MSG_OPEN:
    case AGENTX_MSG_CLOSE:
    case AGENTX_MSG_RESPONSE:
    case AGENTX_MSG_COMMITSET:
    case AGENTX_MSG_UNDOSET:
    case AGENTX_MSG_CLEANUPSET:
      pdu->flags &= ~(AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT);
  }

  /* Build the header (and context if appropriate). */
  if (!agentx_build_header
      (zg, buf, buf_len, out_len, pdu)) {
    session->lib_errno = SNMPERR_BAD_BUILD;
    return 0;
  }

  /* Everything causes a response, except agentx-Response-PDU and
   * agentx-CleanupSet-PDU (agentx-Notify-PDU:no handle). */

  pdu->flags |= AGENTX_FLAGS_EXPECT_RESPONSE;

  if (IS_SUBAG_DEBUG_SEND)
    zlog_info (zg, "    Payload");

  switch (pdu->command) {
    case AGENTX_MSG_RESPONSE:
      pdu->flags &= ~(AGENTX_FLAGS_EXPECT_RESPONSE);
      /* sysUpTime */
      if (!agentx_build_int (zg, buf, buf_len, out_len,
                             pdu->time, network_order)) {
        session->lib_errno = SNMPERR_BAD_BUILD;
        return 0;
      }
      if (IS_SUBAG_DEBUG_SEND) {
        zlog_info (zg, "    Response");
        zlog_info (zg, "      sysUpTime: %d", pdu->time);
      }

      /* errstat, errindex */
      if (!agentx_build_short
          (zg, buf, buf_len, out_len,
           (u_short)pdu->errstat, network_order)
          || !agentx_build_short (zg, buf, buf_len, out_len,
                                  (u_short)pdu->errindex, network_order)) {
        session->lib_errno = SNMPERR_BAD_BUILD;
        return 0;
      }
      if (IS_SUBAG_DEBUG_SEND) {
        zlog_info (zg, "    Response errors");
        zlog_info (zg, "      errstat: %d", pdu->errstat);
        zlog_info (zg, "        : %s", agentx_errstring (pdu->errstat));
        zlog_info (zg, "      errindex: %d", pdu->errindex);
      }

      /* Fall through */

    case AGENTX_MSG_NOTIFY:
      /* Not to save the sending packet for handling response of it. */
      pdu->flags &= ~(AGENTX_FLAGS_EXPECT_RESPONSE);
    case AGENTX_MSG_INDEX_ALLOCATE:
    case AGENTX_MSG_INDEX_DEALLOCATE:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    Variable List");
      if (pdu->errstat != SNMP_ERR_TOOBIG)
        {
          for (vp = pdu->variables; vp != NULL; vp = vp->next_variable) {
            if (!agentx_build_varbind
                (zg, buf, buf_len, out_len, vp, network_order)) {
              session->lib_errno = SNMPERR_BAD_BUILD;
              return 0;
            }
          }
        }
      break;

    case AGENTX_MSG_PING:
      /* "Empty" packet. */
      break;

    case AGENTX_MSG_OPEN:
      /* Timeout */
      while ((*out_len + 4) >= *buf_len) {
        if (!(snmp_realloc (buf, buf_len))) {
          session->lib_errno = SNMPERR_MALLOC;
          return 0;
        }
      }
      *(*buf + *out_len) = (u_char) pdu->time;
      (*out_len)++;
      for (i = 0; i < 3; i++) {
        *(*buf + *out_len) = 0;
        (*out_len)++;
      }
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    Open Timeout: %d",
                   (int) *(*buf + *out_len - 4));

      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    Open ID:");
      if (!agentx_build_oid
          (zg, buf, buf_len, out_len, 0, pdu->variables->name,
           pdu->variables->name_length, network_order)) {
        session->lib_errno = SNMPERR_BAD_BUILD;
        return 0;
      }

      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    Open Description:");
      if (!agentx_build_string
          (zg, buf, buf_len, out_len, pdu->variables->val.string,
           pdu->variables->val_len, network_order)) {
        session->lib_errno = SNMPERR_BAD_BUILD;
        return 0;
      }
      break;

    case AGENTX_MSG_CLOSE:
      /* Reason */
      while ((*out_len + 4) >= *buf_len) {
        if (!(snmp_realloc (buf, buf_len))) {
          session->lib_errno = SNMPERR_MALLOC;
          return 0;
        }
      }
      *(*buf + *out_len) = (u_char) pdu->errstat;
      (*out_len)++;
      for (i = 0; i < 3; i++) {
        *(*buf + *out_len) = 0;
        (*out_len)++;
      }
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    Close Reason: %d", pdu->errstat);
      break;

    case AGENTX_MSG_REGISTER:
    case AGENTX_MSG_UNREGISTER:
      while ((*out_len + 4) >= *buf_len) {
        if (!(snmp_realloc (buf, buf_len))) {
          session->lib_errno = SNMPERR_MALLOC;
          return 0;
        }
      }
      if (pdu->command == AGENTX_MSG_REGISTER) {
        *(*buf + *out_len) = (u_char) pdu->time;
      } else {
        *(*buf + *out_len) = 0;
      }
      (*out_len)++;
      *(*buf + *out_len) = (u_char) pdu->priority;
      (*out_len)++;
      *(*buf + *out_len) = (u_char) pdu->range_subid;
      (*out_len)++;
      *(*buf + *out_len) = (u_char) 0;
      (*out_len)++;

      if (IS_SUBAG_DEBUG_SEND) {
        zlog_info (zg, "    (Un)Register Header:");
        if (pdu->command == AGENTX_MSG_REGISTER)
          zlog_info (zg, "      Timeout: %d", (int) *(*buf + *out_len - 4));
        zlog_info (zg, "      Priority: %d", (int) *(*buf + *out_len - 3));
        zlog_info (zg, "      Range SubID: %d", (int) *(*buf + *out_len - 2));
      }

      vp = pdu->variables;
      prefix_offset = *out_len + 1;
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    (Un)Register Prefix:");
      if (!agentx_build_oid
          (zg, buf, buf_len, out_len, 0, vp->name,
           vp->name_length, network_order)) {
        session->lib_errno = SNMPERR_BAD_BUILD;
        return 0;
      }

      if (pdu->range_subid) {
        if (IS_SUBAG_DEBUG_SEND)
          zlog_info (zg, "    (Un)Register Range:");
        if (!agentx_build_int
            (zg, buf, buf_len, out_len,
             vp->val.objid[pdu->range_subid - 1], network_order)) {
          session->lib_errno = SNMPERR_BAD_BUILD;
          return 0;
        }
      }
      break;

    case AGENTX_MSG_ADD_AGENT_CAPS:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    AgentCaps OID:");
      if (!agentx_build_oid
          (zg, buf, buf_len, out_len, 0, pdu->variables->name,
           pdu->variables->name_length, network_order)) {
        session->lib_errno = SNMPERR_BAD_BUILD;
        return 0;
      }

      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    AgentCaps Description:");
      if (!agentx_build_string
          (zg, buf, buf_len, out_len, pdu->variables->val.string,
           pdu->variables->val_len, network_order)) {
        session->lib_errno = SNMPERR_BAD_BUILD;
        return 0;
      }
      break;

    case AGENTX_MSG_REMOVE_AGENT_CAPS:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    AgentCaps OID:");
      if (!agentx_build_oid
          (zg, buf, buf_len, out_len, 0, pdu->variables->name,
           pdu->variables->name_length, network_order)) {
        session->lib_errno = SNMPERR_BAD_BUILD;
        return 0;
      }
      break;

    /*
     * Below messages related to Get and Set are generated by master agent.
     * : GetBulk, Get, GetNext, TestSet, CommitSet, UndoSet and CleanupSet
     */

    case AGENTX_MSG_GETBULK:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    GetBulk Non-Repeaters: %d",
                   pdu->non_repeaters); /* errstat */
      if (!agentx_build_short
          (zg, buf, buf_len, out_len,
           (u_short)pdu->non_repeaters, network_order)) {
        session->lib_errno = SNMPERR_BAD_BUILD;
        return 0;
      }

      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    GetBulk Max-Repetitions: %d",
                   pdu->max_repetitions); /* errindex */
      if (!agentx_build_short
          (zg, buf, buf_len, out_len,
           (u_short)pdu->max_repetitions, network_order)) {
        session->lib_errno = SNMPERR_BAD_BUILD;
        return 0;
      }

      /* Fall through */

    case AGENTX_MSG_GET:
    case AGENTX_MSG_GETNEXT:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    Get* Variable List:");
      for (vp = pdu->variables; vp != NULL; vp = vp->next_variable) {
        inc = (vp->type == ASN_PRIV_INCL_RANGE);
        if (!agentx_build_oid
            (zg, buf, buf_len, out_len, inc, vp->name,
             vp->name_length, network_order)) {
          session->lib_errno = SNMPERR_BAD_BUILD;
          return 0;
        }
        if (!agentx_build_oid
            (zg, buf, buf_len, out_len, 0, vp->val.objid,
             vp->val_len / sizeof(oid), network_order)) {
          session->lib_errno = SNMPERR_BAD_BUILD;
          return 0;
        }
      }
      break;

    case AGENTX_MSG_TESTSET:
      if (IS_SUBAG_DEBUG_SEND)
        zlog_info (zg, "    Get* Variable List");
      for (vp = pdu->variables; vp != NULL; vp = vp->next_variable) {
        if (!agentx_build_varbind
            (zg, buf, buf_len, out_len, vp, network_order)) {
          session->lib_errno = SNMPERR_BAD_BUILD;
          return 0;
        }
      }
      break;

    case AGENTX_MSG_COMMITSET:
    case AGENTX_MSG_UNDOSET:
      /* "Empty" packet. */
      break;

    case AGENTX_MSG_CLEANUPSET:
      /* Not to save the sending packet for handling response of it. */
      pdu->flags &= ~(AGENTX_FLAGS_EXPECT_RESPONSE);
      break;

    default:
      session->lib_errno = SNMPERR_UNKNOWN_PDU;
      return 0;
  }

  /* Fix the payload length (ignoring the 20-byte header). */

  _agentx_build_int (zg, (*buf + 16), (*out_len - ilen) - 20, network_order);

  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: built packet okay ");
  return 1;
}

int
agentx_build (struct lib_globals *zg,
              struct agentx_session *session, struct agentx_pdu *pdu,
              u_char **buf, size_t *buf_len, size_t *out_len)
{
  if (session == NULL || buf_len == NULL ||
      out_len == NULL || pdu == NULL || buf == NULL) {
    return -1;
  }
  if (!_agentx_build (zg, buf, buf_len, out_len, session, pdu)) {
    if (session->lib_errno == 0) {
      session->lib_errno = SNMPERR_BAD_BUILD;
    }
    return -1;
  }

  return 0;
}

/*--------------------------------------------------*
 *  Utility functions for parsing an AgentX packet  *
 *--------------------------------------------------*/

int
agentx_parse_int (struct lib_globals *zg,
                  u_char *data, u_int network_byte_order)
{
  u_int value = 0;

  /* Network byte order : Most  Significant  Byte  first (BIG_ENDIAN) */
  if (network_byte_order) {
    value += data[0];
    value <<= 8;
    value += data[1];
    value <<= 8;
    value += data[2];
    value <<= 8;
    value += data[3];
  /* Host byte order : Least  Significant  Byte  first */
  } else {
    value += data[3];
    value <<= 8;
    value += data[2];
    value <<= 8;
    value += data[1];
    value <<= 8;
    value += data[0];
  }
  if (IS_SUBAG_DEBUG_RECV && IS_SUBAG_DEBUG_DETAIL)
    zlog_info (zg, ">-      Integer: %ld (0x%.2X)", value, value);

  return value;
}


int
agentx_parse_short (struct lib_globals *zg,
                    u_char *data, u_int network_byte_order)
{
  u_short value = 0;

  /* Network byte order : Most  Significant  Byte  first (BIG_ENDIAN) */
  if (network_byte_order) {
    value += data[0];
    value <<= 8;
    value += data[1];
  /* Host byte order : Least  Significant  Byte  first */
  } else {
    value += data[1];
    value <<= 8;
    value += data[0];
  }

  if (IS_SUBAG_DEBUG_RECV && IS_SUBAG_DEBUG_DETAIL)
    zlog_info (zg, ">-      Short: %ld (0x%.2X)", value, value);
  return value;
}


u_char *
agentx_parse_oid (struct lib_globals *zg,
                  u_char *data, size_t *length, int *inc,
                  oid *oid_buf, size_t *oid_len, u_int network_byte_order)
{
  u_int n_subid;
  u_int prefix;
  int i;
  int int_offset;
  u_int *int_ptr = (u_int *)oid_buf;
  u_char *buf_ptr = data;

  if (*length < 4) {
    zlog_err (zg, "AgentX: parse_oid, Incomplete Object ID");
    return NULL;
  }

  if (IS_SUBAG_DEBUG_RECV) {
    zlog_info (zg, ">-      OID Header:");
    zlog_info (zg, "          # subids: %d (0x%.2X)", data[0],data[0]);
    zlog_info (zg, "          prefix: %d (0x%.2X)", data[1],data[1]);
    zlog_info (zg, "          inclusive: %d (0x%.2X)", data[2],data[2]);
    zlog_info (zg, "        OID Segments:");
  }

  n_subid = data[0];
  prefix = data[1];
  if (inc)
    *inc = data[2];
  int_offset = sizeof(oid)/4;

  buf_ptr += 4;
  *length -= 4;

  if (IS_SUBAG_DEBUG_PROCESS && IS_SUBAG_DEBUG_DETAIL) {
    zlog_info (zg, "          parse_oid: sizeof(oid) = %d", sizeof(oid));
  }
  if (n_subid == 0 && prefix == 0) {
    /* Null OID */
    *int_ptr = 0;
    int_ptr++;
    *int_ptr = 0;
    int_ptr++;
    *oid_len = 2;
    if (IS_SUBAG_DEBUG_RECV)
      zlog_info (zg, "          OID: NULL (0.0)");
    return buf_ptr;
  }


  if (*length < 4 * n_subid) {
    if (IS_SUBAG_DEBUG_RECV)
      zlog_info (zg, "          Incomplete Object ID");
    return NULL;
  }

  if (prefix) {
    if (sizeof(oid) == 8) {     /* align OID values in 64 bit agent */
      int_ptr[1] = int_ptr[3] = int_ptr[5] = int_ptr[7] = int_ptr[9] = 0;
      int_ptr[int_offset - 2] = 1;
      int_ptr[(int_offset * 2) - 2] = 3;
      int_ptr[(int_offset * 3) - 2] = 6;
      int_ptr[(int_offset * 4) - 2] = 1;
      int_ptr[(int_offset * 5) - 2] = prefix;
      int_ptr = int_ptr + (int_offset * 5);
    }
    else
    { /* Code for 32 bit agent */
    int_ptr[int_offset - 1] = 1;
    int_ptr[(int_offset * 2) - 1] = 3;
    int_ptr[(int_offset * 3) - 1] = 6;
    int_ptr[(int_offset * 4) - 1] = 1;
    int_ptr[(int_offset * 5) - 1] = prefix;
    int_ptr = int_ptr + (int_offset * 5);
  }
  }

  for (i = 0; i < (int) (int_offset * n_subid); i = i + int_offset) {
    if (sizeof(oid) == 8) {
    int_ptr[i + (int_offset - 1)] = 0;
    int_ptr[i] = agentx_parse_int (zg, buf_ptr, network_byte_order);
    }
    else
    { /* Code for 32 bit agent */
    int_ptr[i] = 0;
    int_ptr[i + (int_offset - 1)] = agentx_parse_int (zg, buf_ptr,
                                                      network_byte_order);
    }
    buf_ptr += 4;
    *length -= 4;
  }

  *oid_len = (prefix ? n_subid + 5 : n_subid);

  if (IS_SUBAG_DEBUG_RECV) {
    snmp_oid_dump (zg, "          OID", oid_buf, *oid_len);
  }

  return buf_ptr;
}


u_char *
agentx_parse_string (struct lib_globals *zg,
                     u_char *data, size_t *length,
                     u_char *string, size_t *str_len,
                     u_int network_byte_order)
{
  u_int len;

  if (*length < 4) {
    zlog_err (zg, "AgentX: parse_string, Incomplete string (too short: %d)",
              *length);
    return NULL;
  }

  len = agentx_parse_int (zg, data, network_byte_order);
  if (*length < len + 4) {
    zlog_err (zg, "AgentX: parse_string, Incomplete string (still too short: %d)",
              *length);
    return NULL;
  }
  if (len > *str_len) {
    zlog_err (zg, "AgentX: parse_string, String too long (too long)");
    return NULL;
  }
  pal_mem_move (string, data + 4, len);
  string[len] = '\0';
  *str_len = len;

  len += 3; /* Extend the string length to include the padding */
  len >>= 2;
  len <<= 2;

  *length -= (len + 4);
  if (IS_SUBAG_DEBUG_RECV) {
    zlog_info (zg, ">-      String: %s", string);
  }
  return data + (len + 4);
}

u_char *
agentx_parse_opaque (struct lib_globals *zg,
                     u_char *data, size_t *length, int *type,
                     u_char *opaque_buf, size_t *opaque_len,
                     u_int network_byte_order)
{
  u_char *buf;
  u_char *cp;

  cp = agentx_parse_string (zg, data, length,
                            opaque_buf, opaque_len, network_byte_order);
  if (cp == NULL)
    return NULL;

  buf = opaque_buf;

  /* It does not support opaque special types */
  return cp;
}


u_char *
agentx_parse_varbind (struct lib_globals *zg,
                      u_char *data, size_t *length, int *type,
                      oid *oid_buf, size_t *oid_len,
                      u_char *data_buf, size_t *data_len,
                      u_int network_byte_order)
{
  u_char *bufp = data;
  u_int int_val;
  int int_offset;
  u_int *int_ptr = (u_int *) data_buf;

  if (IS_SUBAG_DEBUG_RECV)
    zlog_info (zg, ">-      VarBind:");

  *type = agentx_parse_short (zg, bufp, network_byte_order);
  bufp += 4;
  *length -= 4;

  if (IS_SUBAG_DEBUG_RECV)
    zlog_info (zg, "          Value Type: %ld", *type);

  bufp = agentx_parse_oid (zg, bufp, length, NULL, oid_buf, oid_len,
                           network_byte_order);
  if (bufp == NULL) {
    return NULL;
  }

  switch (*type) {
    case ASN_INTEGER:
    case ASN_COUNTER:
    case ASN_GAUGE:
    case ASN_TIMETICKS:
      int_val = agentx_parse_int (zg, bufp, network_byte_order);
      pal_mem_move (data_buf, &int_val, 4);
      *data_len = 4;
      bufp += 4;
      *length -= 4;
      break;

    case ASN_OCTET_STR:
    case ASN_IPADDRESS:
      bufp = agentx_parse_string (zg, bufp, length, data_buf, data_len,
                                  network_byte_order);
      break;

    case ASN_OPAQUE:
      bufp = agentx_parse_opaque (zg, bufp, length, type, data_buf, data_len,
                                  network_byte_order);
      break;

    case ASN_PRIV_INCL_RANGE:
    case ASN_PRIV_EXCL_RANGE:
    case ASN_OBJECT_ID:
      bufp = agentx_parse_oid (zg, bufp, length, NULL, (oid *) data_buf,
                               data_len, network_byte_order);
      *data_len *= sizeof(oid);
      /* 'agentx_parse_oid()' returns the number of sub_ids */
      break;

    case ASN_COUNTER64:
      /* Set up offset to be 2 for 64-bit, 1 for 32-bit.
       * Use this value in formulas to correctly put integer values
       * extracted from buffer into correct place in byte buffer. */
      int_offset = sizeof(long) == 8 ? 2 : 1;
      if (network_byte_order) {
        /* For 64-bit, clear integers 2 & 3, then place values in 0 & 1.
         * For 32-bit, clear integers 0 & 1, then overwrite with values.
         * Could also put a conditional in here to skip clearing 0 & 1. */
        int_ptr[(2 * int_offset) - 2] = 0;
        int_ptr[(2 * int_offset) - 1] = 0;
        int_ptr[0] = agentx_parse_int (zg, bufp, network_byte_order);
        int_ptr[1] = agentx_parse_int (zg, bufp + 4, network_byte_order);
      } else {
        /* For 64-bit, clear integers 0 & 1, then place values in 2 & 3.
         * For 32-bit, clear integers 0 & 1, then overwrite with values.
         * Could also put a conditional in here to skip clearing 0 & 1. */
        int_ptr[0] = 0;
        int_ptr[1] = 0;
        int_ptr[(2 * int_offset) - 2] = agentx_parse_int (zg, bufp + 4,
                                                          network_byte_order);
        int_ptr[(2 * int_offset) - 1] = agentx_parse_int (zg, bufp,
                                                          network_byte_order);
      }

      /* return data_len 2*8 if 64-bit, 2*4 if 32-bit */
      *data_len = 2 * sizeof(long);
      bufp += 2 * sizeof(long);
      *length -= 8;
      break;

    case ASN_NULL:
    case SNMP_NOSUCHOBJECT:
    case SNMP_NOSUCHINSTANCE:
    case SNMP_ENDOFMIBVIEW:
      /*
       * No data associated with these types.
       */
      *data_len = 0;
      break;

    default:
      return NULL;
  }
  return bufp;
}

/*
 *  AgentX header:
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    h.version  |   h.type      |   h.flags     |  <reserved>   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       h.sessionID                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     h.transactionID                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       h.packetID                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     h.payload_length                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    Total length = 20 bytes
 *
 */

u_char *
agentx_parse_header (struct lib_globals *zg,
                     struct agentx_pdu *pdu,
                     u_char *data, size_t *length)
{
  register u_char *bufp = data;
  size_t payload;

  if (*length < AGENTX_HEADER_LENGTH) { /* Incomplete header : < 20 */
    return NULL;
  }

  if (IS_SUBAG_DEBUG_RECV) {
    zlog_info (zg, ">-  AgentX Header:");
    zlog_info (zg, "      Version: %d", *bufp);
  }
  pdu->version = *bufp;
  bufp++;

  if (IS_SUBAG_DEBUG_RECV)
    zlog_info (zg, "      Command: %d (%s)", *bufp, agentx_cmd(*bufp));

  pdu->command = *bufp;
  bufp++;

  if (IS_SUBAG_DEBUG_RECV)
    zlog_info (zg, "      Flags: 0x%x", *bufp);

  pdu->flags |= *bufp;
  bufp++;

  if (IS_SUBAG_DEBUG_RECV)
    zlog_info (zg, "      Reserved: 0x%x", *bufp);
  bufp++;

  pdu->sessid = agentx_parse_int (zg, bufp,
                                  pdu->flags &
                                  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
  if (IS_SUBAG_DEBUG_RECV)
    zlog_info (zg, "      Session ID: %ld (0x%x)",
               pdu->sessid, pdu->sessid);
  bufp += 4;

  pdu->transid = agentx_parse_int (zg, bufp,
                                   pdu->flags &
                                   AGENTX_FLAGS_NETWORK_BYTE_ORDER);
  if (IS_SUBAG_DEBUG_RECV)
    zlog_info (zg, "      Transaction ID: %ld (0x%x)",
               pdu->transid, pdu->transid);
  bufp += 4;

  pdu->reqid = agentx_parse_int (zg, bufp,
                                 pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER);
  if (IS_SUBAG_DEBUG_RECV)
    zlog_info (zg, "      Packet ID: %ld (0x%x)",
               pdu->reqid, pdu->reqid);
  bufp += 4;

  payload = agentx_parse_int (zg, bufp,
                              pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER);
  if (IS_SUBAG_DEBUG_RECV)
    zlog_info (zg, "      Payload Length: %ld (0x%x)",
               payload, payload);
  bufp += 4;

  *length -= AGENTX_HEADER_LENGTH;  /* 20 */
  if (*length != payload) {   /* Short payload */
    return NULL;
  }
  return bufp;
}


int
agentx_parse (struct lib_globals *zg,
              struct agentx_session *session,
              struct agentx_pdu *pdu,
              u_char *data, size_t len)
{
  register u_char *bufp = data;
  struct agentx_session *Session;
  u_char buffer[BUFSIZ];
  u_char *prefix_ptr;
  oid oid_buffer[MAX_OID_LEN], end_oid_buf[MAX_OID_LEN];
  size_t buf_len = BUFSIZ;
  size_t oid_buf_len = MAX_OID_LEN;
  size_t end_oid_buf_len = MAX_OID_LEN;
  struct snmp_master *snmpm;
  int range_bound;  /* OID-range upper bound */
  int inc;   /* Inclusive SearchRange flag */
  int type;  /* VarBind data type */
  size_t *length = &len;

  snmpm = SNMP_MASTER (zg);
  Session = &snmpm->Agx_session;

  if (pdu == NULL) {
    zlog_err (zg, "AgentX: parse, pdu is null\n");
    return SNMPERR_MALLOC;
  }
  if (!IS_AGENTX_VERSION (session->version)) {
    zlog_err (zg, "AgentX: parse, bad version\n");
    return SNMPERR_BAD_VERSION;
  }

  if (len < AGENTX_HEADER_LENGTH) { /* Incomplete header : < 20 */
    zlog_err (zg, "AgentX: parse, a length of packet (%d) is too short\n",
              len);
    return SNMPERR_TOO_SHORT;
  }

  /* check a type of pdu in subagent : command of pdu */
  switch (*(bufp + 1)) {
    case AGENTX_MSG_OPEN:
    case AGENTX_MSG_REGISTER:
    case AGENTX_MSG_UNREGISTER:
    case AGENTX_MSG_INDEX_ALLOCATE:
    case AGENTX_MSG_INDEX_DEALLOCATE:
    case AGENTX_MSG_ADD_AGENT_CAPS:
    case AGENTX_MSG_REMOVE_AGENT_CAPS:
    case AGENTX_MSG_NOTIFY:
    case AGENTX_MSG_PING:
      zlog_warn (zg, "(Warning) AgentX: parse %s-PDU in subagent",
                 agentx_cmd((u_char) *(bufp + 1)));
      break;
    default:
      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "AgentX: parse %s-PDU",
                   agentx_cmd((u_char) *(bufp + 1)));
      break;
  }

  /*  Handle (common) header. */
  bufp = agentx_parse_header (zg, pdu, bufp, length);
  if (bufp == NULL)
    return SNMPERR_PARSE_ERR;

  /* Control PDU handling */
  pdu->flags |= AGENTX_FLAGS_FORCE_PDU_COPY;
  pdu->flags &= (~AGENTX_FLAGS_RESPONSE_PDU);

  /*  ... and (not-un-common) context */
  if (pdu->flags & AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT) {
    if (IS_SUBAG_DEBUG_RECV)
      zlog_info (zg, "AgentX: parse: Context:");
    bufp = agentx_parse_string (zg, bufp, length, buffer, &buf_len,
                                pdu->flags &
                                AGENTX_FLAGS_NETWORK_BYTE_ORDER);
    if (bufp == NULL)
      return AGENTX_ERR_PARSE_ERROR;

    pdu->community_len = buf_len;
    agentx_clone_mem ((void **) &pdu->community,
                      (void *) buffer, (unsigned) buf_len);
    buf_len = BUFSIZ;
  }

  switch (pdu->command) {

    case AGENTX_MSG_GETBULK:
      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "    Non-repeaters");
      /* errstat */
      pdu->non_repeaters = agentx_parse_short (zg, bufp,
                                               pdu->flags &
                                               AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "    Max-repeaters");
      /* errindex */
      pdu->max_repetitions = agentx_parse_short (zg, bufp + 2,
                                                 pdu->flags &
                                                 AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      bufp += 4;
      *length -= 4;
      /* Fall through - SearchRange handling is the same */

    case AGENTX_MSG_GETNEXT:
    case AGENTX_MSG_GET:

      /* SearchRange List
       * Keep going while we have data left */

      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "    Search Range:");
      while (*length > 0) {
        /* #n Start OID of SearchRange List */
        bufp = agentx_parse_oid (zg, bufp, length, &inc,
                                 oid_buffer, &oid_buf_len,
                                 pdu->flags &
                                 AGENTX_FLAGS_NETWORK_BYTE_ORDER);
        if (bufp == NULL) {
          return AGENTX_ERR_PARSE_ERROR;
        }
        /* #n End OID of SearchRange List */
        bufp = agentx_parse_oid (zg, bufp, length, NULL,
                                 end_oid_buf, &end_oid_buf_len,
                                 pdu->flags &
                                 AGENTX_FLAGS_NETWORK_BYTE_ORDER);
        if (bufp == NULL) {
          return AGENTX_ERR_PARSE_ERROR;
        }
        end_oid_buf_len *= sizeof(oid);
        /* 'agentx_parse_oid()' returns the number of sub_ids */

        if (inc) {
          agentx_pdu_add_variable (zg, pdu, oid_buffer, oid_buf_len,
                                   ASN_PRIV_INCL_RANGE,
                                   (u_char *) end_oid_buf,
                                   end_oid_buf_len);
        } else {
          agentx_pdu_add_variable (zg, pdu, oid_buffer, oid_buf_len,
                                   ASN_PRIV_EXCL_RANGE,
                                   (u_char *) end_oid_buf,
                                   end_oid_buf_len);
        }
      }

      oid_buf_len = MAX_OID_LEN;
      end_oid_buf_len = MAX_OID_LEN;
      break;

    case AGENTX_MSG_RESPONSE:

      pdu->flags |= AGENTX_FLAGS_RESPONSE_PDU;

      /* Get session id from master agent in opening state */
      if (snmpm->Agx_state == AGENTX_OPENING)
        Session->sessid = pdu->sessid;

      /* sysUpTime */
      pdu->time = agentx_parse_int (zg, bufp,
                                    pdu->flags &
                                    AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      bufp += 4;
      *length -= 4;

      /* response error */
      pdu->errstat = agentx_parse_short (zg, bufp,
                                         pdu->flags &
                                         AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      /* response index */
      pdu->errindex = agentx_parse_short (zg, bufp + 2,
                                          pdu->flags &
                                          AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      bufp += 4;
      *length -= 4;
      /* Fall through - VarBind handling is the same */

    case AGENTX_MSG_NOTIFY:
      /* agentx-Notify-PDU is generated by subagent. */
    case AGENTX_MSG_TESTSET:

      /* VarBind List
       * Keep going while we have data left */

      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "    VarBindList:");
      while (*length > 0) {
        bufp = agentx_parse_varbind (zg, bufp, length, &type,
                                     oid_buffer, &oid_buf_len,
                                     buffer, &buf_len,
                                     pdu->flags &
                                     AGENTX_FLAGS_NETWORK_BYTE_ORDER);
        if (bufp == NULL) {
          return AGENTX_ERR_PARSE_ERROR;
        }
        agentx_pdu_add_variable (zg, pdu, oid_buffer, oid_buf_len,
                                 (u_char) type, buffer, buf_len);

        oid_buf_len = MAX_OID_LEN;
        buf_len = BUFSIZ;
      }
      break;

    case AGENTX_MSG_COMMITSET:
    case AGENTX_MSG_UNDOSET:
    case AGENTX_MSG_CLEANUPSET:
      /* "Empty" packet */
      break;

    case AGENTX_MSG_CLOSE:
      pdu->errstat = *bufp;   /* Reason */
      bufp += 4;
      *length -= 4;
      break;

    /*
     * There is no need to parsing below messages in subagent.
     * Below messages (and Notify-PDU) are generated by subagent.
     */

    case AGENTX_MSG_OPEN:
      pdu->time = *bufp;      /* Timeout */
      bufp += 4;
      *length -= 4;

      /* Store subagent OID & description in a VarBind */
      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "    Subagent OID");
      bufp = agentx_parse_oid (zg, bufp, length, NULL,
                               oid_buffer, &oid_buf_len,
                               pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      if (bufp == NULL) {
        return AGENTX_ERR_PARSE_ERROR;
      }
      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "    Subagent Description");
      bufp = agentx_parse_string (zg, bufp, length, buffer, &buf_len,
                                  pdu->flags &
                                  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      if (bufp == NULL) {
        return AGENTX_ERR_PARSE_ERROR;
      }
      agentx_pdu_add_variable (zg, pdu, oid_buffer, oid_buf_len,
                               ASN_OCTET_STR, buffer, buf_len);

      oid_buf_len = MAX_OID_LEN;
      buf_len = BUFSIZ;
      break;

    case AGENTX_MSG_UNREGISTER:
    case AGENTX_MSG_REGISTER:
      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "    Registration Header");
      if (pdu->command == AGENTX_MSG_REGISTER) {
        pdu->time = *bufp;  /* Timeout (Register only) */
        if (IS_SUBAG_DEBUG_RECV)
          zlog_info (zg, "      Timeout: %d", *bufp);
      }
      bufp++;
      pdu->priority = *bufp;
      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "      Priority: %d", *bufp);
      bufp++;
      pdu->range_subid = *bufp;
      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "      Range Sub-Id: %d", *bufp);
      bufp++;
      bufp++;
      *length -= 4;

      prefix_ptr = bufp + 1;
      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "    Registration OID:");
      bufp = agentx_parse_oid (zg, bufp, length, NULL,
                               oid_buffer, &oid_buf_len,
                               pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      if (bufp == NULL) {
        return AGENTX_ERR_PARSE_ERROR;
      }

      if (pdu->range_subid) {
        range_bound = agentx_parse_int (zg, bufp,
                                        pdu->flags &
                                        AGENTX_FLAGS_NETWORK_BYTE_ORDER);
        bufp += 4;
        *length -= 4;

        /* Construct the end-OID. */
        end_oid_buf_len = oid_buf_len * sizeof(oid);
        pal_mem_cpy (end_oid_buf, oid_buffer, end_oid_buf_len);
        end_oid_buf[pdu->range_subid - 1] = range_bound;

        agentx_pdu_add_variable (zg, pdu, oid_buffer, oid_buf_len,
                                 ASN_PRIV_INCL_RANGE,
                                 (u_char *) end_oid_buf, end_oid_buf_len);
      } else {
        agentx_add_null_var (zg, pdu, oid_buffer, oid_buf_len);
      }

      oid_buf_len = MAX_OID_LEN;
      break;

    case AGENTX_MSG_INDEX_ALLOCATE:
    case AGENTX_MSG_INDEX_DEALLOCATE:

      /* VarBind List
       * Keep going while we have data left */

      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "    VarBindList:");
      while (*length > 0) {
        bufp = agentx_parse_varbind (zg, bufp, length, &type,
                                     oid_buffer, &oid_buf_len,
                                     buffer, &buf_len,
                                     pdu->flags &
                                     AGENTX_FLAGS_NETWORK_BYTE_ORDER);
        if (bufp == NULL) {
          return AGENTX_ERR_PARSE_ERROR;
        }
        agentx_pdu_add_variable (zg, pdu, oid_buffer, oid_buf_len,
                                 (u_char) type, buffer, buf_len);

        oid_buf_len = MAX_OID_LEN;
        buf_len = BUFSIZ;
      }
      break;

    case AGENTX_MSG_ADD_AGENT_CAPS:
      /* Store AgentCap OID & description in a VarBind  */
      bufp = agentx_parse_oid (zg, bufp, length, NULL,
                               oid_buffer, &oid_buf_len,
                               pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      if (bufp == NULL)
        return AGENTX_ERR_PARSE_ERROR;
      bufp = agentx_parse_string (zg, bufp, length, buffer, &buf_len,
                                  pdu->flags &
                                  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      if (bufp == NULL)
        return AGENTX_ERR_PARSE_ERROR;
      agentx_pdu_add_variable (zg, pdu, oid_buffer, oid_buf_len,
                               ASN_OCTET_STR, buffer, buf_len);

      oid_buf_len = MAX_OID_LEN;
      buf_len = BUFSIZ;
      break;

    case AGENTX_MSG_REMOVE_AGENT_CAPS:
      /* Store AgentCap OID & description in a VarBind */
      bufp = agentx_parse_oid (zg, bufp, length, NULL,
                               oid_buffer, &oid_buf_len,
                               pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER);
      if (bufp == NULL)
        return AGENTX_ERR_PARSE_ERROR;
      agentx_add_null_var (zg, pdu, oid_buffer, oid_buf_len);

      oid_buf_len = MAX_OID_LEN;
      break;

    case AGENTX_MSG_PING:
      /* "Empty" packet */
      break;

    default:
      if (IS_SUBAG_DEBUG_RECV)
        zlog_info (zg, "    Unrecognised PDU type: %d", pdu->command);
      session->lib_errno = SNMPERR_UNKNOWN_PDU;
      return AGENTX_ERR_PARSE_ERROR;
  }
  /*
  RFC 2741, 7.2.2. Subagent Processing
   * 3) Otherwise, if h.sessionID does not correspond to a currently
   *    established session, res.error is set to `notOpen'.
   */
  if (session->sessid != pdu->sessid)
    return AGENTX_ERR_NOT_OPEN;

  return SNMP_ERR_NOERROR;
}

/*
 * returns the proper length of an incoming agentx packet.
 */
/*
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   h.version   |    h.type     |    h.flags    |  <reserved>   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                          h.sessionID                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        h.transactionID                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                          h.packetID                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        h.payload_length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    20 bytes in header
 */

int
agentx_check_packet (struct lib_globals *zg,
                     u_char *packet, size_t packet_len)
{
  if (packet_len < 20)
    return 0; /* minimum header length == 20 */

  return (agentx_parse_int (zg, packet + 16,
                            *(packet + 2) & AGENTX_FLAGS_NETWORK_BYTE_ORDER)
          + 20);
}


/*--------------------------------------------------*
 *  Utility functions for sending an AgentX packet  *
 *--------------------------------------------------*/

int
agentx_open_session (struct lib_globals *zg, struct agentx_session *sess)
{
  struct agentx_pdu *pdu;

  if (IS_SUBAG_DEBUG_SEND)
    zlog_info (zg, "AgentX: opening session");

  if (sess == NULL || !IS_AGENTX_VERSION(sess->version)) {
    return -1;
  }

  pdu = agentx_pdu_create (AGENTX_MSG_OPEN, 1, zg);
  if (pdu == NULL)
     return -1;
  pdu->time = 0;
  agentx_add_var (zg, pdu, zg->snmp.oid, zg->snmp.oid_len,
                  's', "BGP-SDN AgentX sub-agent");

  if (!agentx_send (zg, sess, pdu, agentx_handle_open_response, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
    agentx_free_pdu (pdu);
    return -1;
  }

  agentx_free_pdu (pdu);
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: opened session");
  return 0;
}

int
agentx_close_session (struct lib_globals *zg,
                      struct agentx_session *sess, int why)
{
  struct agentx_pdu *pdu;

  if (IS_SUBAG_DEBUG_SEND)
    zlog_info (zg, "AgentX: closing session");

  if (sess == NULL || !IS_AGENTX_VERSION(sess->version)) {
    return -1;
  }

  pdu = agentx_pdu_create (AGENTX_MSG_CLOSE, 1, zg);
  if (pdu == NULL)
    return -1;
  pdu->time = 0;
  pdu->errstat = why;
  pdu->sessid = sess->sessid;

  if (!agentx_send (zg, sess, pdu, NULL, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
    agentx_free_pdu (pdu);
    return -1;
  }

  agentx_free_pdu (pdu);
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: closed session");
  return 0;
}

int
agentx_send_register (struct lib_globals *zg, struct agentx_session *sess,
                      oid start[], size_t startlen,
                      int priority, int range_subid, oid range_ubound,
                      int timeout, u_char flags)
{
  struct agentx_pdu    *pdu;

  if (IS_SUBAG_DEBUG_SEND) {
    zlog_info (zg, "AgentX: registering:");
    /* start, startlen, range_subid, range_ubound */
  }

  if (sess == NULL || !IS_AGENTX_VERSION(sess->version)) {
    return -1;
  }

  pdu = agentx_pdu_create (AGENTX_MSG_REGISTER, 1, zg);
  if (pdu == NULL) {
    return -1;
  }
  pdu->time = timeout;
  pdu->priority = priority;
  pdu->sessid = sess->sessid;
  pdu->range_subid = range_subid;

  /* Default off */
  if (flags & FULLY_QUALIFIED_INSTANCE) {
    pdu->flags |= AGENTX_MSG_FLAG_INSTANCE_REGISTER;
  }

  if (range_subid) {
    agentx_pdu_add_variable (zg, pdu, start, startlen, ASN_OBJECT_ID,
                             (u_char *) start, startlen * sizeof(oid));
    pdu->variables->val.objid[range_subid - 1] = range_ubound;
  } else {
    agentx_add_null_var (zg, pdu, start, startlen);
  }

  if (!agentx_send (zg, sess, pdu, agentx_handle_reg_response, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
    agentx_free_pdu (pdu);
    return -1;
  }

  agentx_free_pdu (pdu);
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: registered");
  return 0;
}

int
agentx_send_unregister (struct lib_globals *zg, struct agentx_session *sess,
                        oid start[], size_t startlen,
                        int priority, int range_subid, oid range_ubound)
{
  struct agentx_pdu    *pdu;

  if (IS_SUBAG_DEBUG_SEND) {
    zlog_info (zg, "AgentX: unregistering:");
    /* start, startlen, range_subid, range_ubound */
  }

  if (sess == NULL || !IS_AGENTX_VERSION(sess->version)) {
    return -1;
  }

  pdu = agentx_pdu_create (AGENTX_MSG_UNREGISTER, 1, zg);
  if (pdu == NULL) {
    return -1;
  }
  pdu->time = 0;
  pdu->priority = priority;
  pdu->sessid = sess->sessid;
  pdu->range_subid = range_subid;
  if (range_subid) {
    agentx_pdu_add_variable (zg, pdu, start, startlen, ASN_OBJECT_ID,
                             (u_char *) start, startlen * sizeof(oid));
    pdu->variables->val.objid[range_subid - 1] = range_ubound;
  } else {
    agentx_add_null_var (zg, pdu, start, startlen);
  }

  if (!agentx_send (zg, sess, pdu, NULL, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
    agentx_free_pdu (pdu);
    return -1;
  }

  agentx_free_pdu (pdu);
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: unregistered");
  return 0;
}

int
agentx_send_index_allocate (struct lib_globals *zg, struct agentx_session *sess,
                            struct agentx_variable_list *varbind, int flags)
{
  struct agentx_pdu *pdu;
  struct agentx_variable_list *varbind2;

  if (IS_SUBAG_DEBUG_SEND) {
    zlog_info (zg, "AgentX: allocating index:");
    /* varbind */
  }

  if (sess == NULL || !IS_AGENTX_VERSION(sess->version)) {
    return -1;
  }

  /*
   * Make a copy of the index request varbind
   *    for the AgentX request PDU
   *    (since the pdu structure will be freed)
   */
  varbind2 = (struct agentx_variable_list *) XMALLOC (MTYPE_TMP,
                                      sizeof (struct agentx_variable_list));
  if (varbind2 == NULL)
    return -1;
  if (agentx_clone_var (varbind, varbind2)) {
    agentx_free_varbind (varbind2);
    return -1;
  }
  if (varbind2->val.string == NULL)
    varbind2->val.string = varbind2->buf;   /* ensure it points somewhere */

  pdu = agentx_pdu_create (AGENTX_MSG_INDEX_ALLOCATE, 1, zg);
  if (pdu == NULL) {
    agentx_free_varbind (varbind2);
    return -1;
  }
  pdu->time = 0;
  pdu->sessid = sess->sessid;
  /* Default off */
  if (flags == ALLOCATE_ANY_INDEX)
    pdu->flags |= AGENTX_MSG_FLAG_ANY_INSTANCE;
  if (flags == ALLOCATE_NEW_INDEX)
    pdu->flags |= AGENTX_MSG_FLAG_NEW_INSTANCE;

  /*
   *  Just send a single index request varbind.
   *  Although the AgentX protocol supports
   *    multiple index allocations in a single
   *    request, the model used in the net-snmp agent
   *    doesn't currently take advantage of this.
   *  I believe this is our prerogative - just as
   *    long as the master side Index request handler
   *    can cope with multiple index requests.
   */
  pdu->variables = varbind2;

  if (!agentx_send (zg, sess, pdu, NULL, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
    agentx_free_varbind (varbind2);
    agentx_free_pdu (pdu);
    return -1;
  }

  agentx_free_varbind (varbind2);
  agentx_free_pdu (pdu);
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: allocated index");
  return 0;
}

int
agentx_send_index_deallocate (struct lib_globals *zg,
                              struct agentx_session *sess,
                              struct agentx_variable_list *varbind)
{
  struct agentx_pdu *pdu;
  struct agentx_variable_list *varbind2;

  if (IS_SUBAG_DEBUG_SEND) {
    zlog_info (zg, "AgentX: deallocating index:");
    /* varbind */
  }

  if (sess == NULL || !IS_AGENTX_VERSION(sess->version)) {
    return -1;
  }

  /*
   * Make a copy of the index request varbind
   *    for the AgentX request PDU
   *    (since the pdu structure will be freed)
   */
  varbind2 = (struct agentx_variable_list *) XMALLOC (MTYPE_TMP,
                                      sizeof (struct agentx_variable_list));
  if (varbind2 == NULL)
    return -1;
  if (agentx_clone_var (varbind, varbind2)) {
    agentx_free_varbind (varbind2);
    return -1;
  }

  pdu = agentx_pdu_create (AGENTX_MSG_INDEX_DEALLOCATE, 1, zg);
  if (pdu == NULL) {
    agentx_free_varbind (varbind2);
    return -1;
  }
  pdu->time = 0;
  pdu->sessid = sess->sessid;

  /*
   *  Just send a single index release varbind.
   *      (as above)
   */
  pdu->variables = varbind2;

  if (!agentx_send (zg, sess, pdu, NULL, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
    agentx_free_varbind (varbind2);
    agentx_free_pdu (pdu);
    return -1;
  }

  agentx_free_varbind (varbind2);
  agentx_free_pdu (pdu);
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: deallocated index");
  return 0;
}

int
agentx_send_add_agentcaps (struct lib_globals *zg, struct agentx_session *sess,
                           oid * agent_cap, size_t agent_caplen,
                           const char *descr)
{
  struct agentx_pdu *pdu;

  if (IS_SUBAG_DEBUG_SEND) {
    zlog_info (zg, "AgentX: adding agent capabilities:");
    /* OID: agent_cap, agent_caplen */
    /* descr */
  }

  if (sess == NULL || !IS_AGENTX_VERSION(sess->version)) {
    return -1;
  }

  pdu = agentx_pdu_create (AGENTX_MSG_ADD_AGENT_CAPS, 1, zg);
  if (pdu == NULL)
    return -1;
  pdu->time = 0;
  pdu->sessid = sess->sessid;
  agentx_add_var (zg, pdu, agent_cap, agent_caplen, 's', descr);

  if (!agentx_send (zg, sess, pdu, NULL, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
    agentx_free_pdu (pdu);
    return -1;
  }

  agentx_free_pdu (pdu);
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: added agent capabilities");
  return 0;
}

int
agentx_send_remove_agentcaps (struct lib_globals *zg,
                              struct agentx_session *sess,
                              oid * agent_cap, size_t agent_caplen)
{
  struct agentx_pdu *pdu;

  if (IS_SUBAG_DEBUG_SEND) {
    zlog_info (zg, "AgentX: removing agent capabilities:");
    /* OID: agent_cap, agent_caplen */
  }

  if (sess == NULL || !IS_AGENTX_VERSION(sess->version)) {
    return -1;
  }

  pdu = agentx_pdu_create (AGENTX_MSG_REMOVE_AGENT_CAPS, 1, zg);
  if (pdu == NULL)
    return 0;
  pdu->time = 0;
  pdu->sessid = sess->sessid;
  agentx_add_null_var (zg, pdu, agent_cap, agent_caplen);

  if (!agentx_send (zg, sess, pdu, NULL, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
    agentx_free_pdu (pdu);
    return -1;
  }

  agentx_free_pdu (pdu);
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: removed agent capabilities");
  return 0;
}

int
agentx_send_ping (struct lib_globals *zg, struct agentx_session *sess)
{
  struct agentx_pdu *pdu;

  if (IS_SUBAG_DEBUG_SEND && IS_SUBAG_DEBUG_DETAIL) {
    zlog_info (zg, "AgentX: pinging:");
  }

  if (sess == NULL || !IS_AGENTX_VERSION(sess->version)) {
    return -1;
  }

  pdu = agentx_pdu_create (AGENTX_MSG_PING, 1, zg);
  if (pdu == NULL)
    return -1;
  pdu->time = 0;
  pdu->sessid = sess->sessid;
  /* As occasion demands, it adds context data (test pattern).
  {
     u_char ping_pattern[] = "ping test: abcbefg0123456789"; // 28 octets

     pdu->flags |= AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT;
     pdu->community_len = sizeof (ping_pattern);
     pdu->community = XMALLOC (MTYPE_TMP, pdu->community_len + 1);
     pal_strncpy (pdu->community, ping_pattern, pdu->community_len);
     pal_mem_set (pdu->community + pdu->community_len, 0, 1);
   }
   */

  if (!agentx_send (zg, sess, pdu, agentx_handle_ping_response, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
    agentx_free_pdu (pdu);
    return -1;
  }

  agentx_free_pdu (pdu);
  if (IS_SUBAG_DEBUG_PROCESS && IS_SUBAG_DEBUG_DETAIL)
    zlog_info (zg, "AgentX: pinged");
  return 0;
}

int
agentx_send_notify (struct lib_globals *zg, struct agentx_session *sess,
                    struct agentx_variable_list *varbind)
{
  struct agentx_pdu *pdu;
  struct agentx_variable_list *varbind2;

  if (IS_SUBAG_DEBUG_SEND) {
    zlog_info (zg, "AgentX: notifying:");
    /* varbind */
  }

  if (sess == NULL || !IS_AGENTX_VERSION(sess->version)) {
    agentx_free_varbind (varbind);
    return -1;
  }

  /*
   * Make a copy of the notifiable varbind
   *    for the AgentX request PDU
   *    (since the pdu structure will be freed)
   */
  varbind2 = (struct agentx_variable_list *) XMALLOC (MTYPE_TMP,
                                      sizeof (struct agentx_variable_list));
  if (varbind2 == NULL) {
    agentx_free_varbind (varbind);
    return -1;
  }
  if (agentx_clone_var (varbind, varbind2)) {
    agentx_free_varbind (varbind2);
    agentx_free_varbind (varbind);
    return -1;
  }

  pdu = agentx_pdu_create (AGENTX_MSG_NOTIFY, 1, zg);
  if (pdu == NULL) {
    agentx_free_varbind (varbind2);
    agentx_free_varbind (varbind);
    return -1;
  }
  pdu->time = 0;
  pdu->sessid = sess->sessid;

  /*
   *  Just notify a list of varbind.
   */
  pdu->variables = varbind;

  if (!agentx_send (zg, sess, pdu, NULL, NULL)) {
    IS_SUBAG_DEBUG_LIBERR_SHOW (sess->lib_errno);
    agentx_free_varbind (varbind2);
    agentx_free_varbind (varbind);
    pdu->variables = NULL; 
    agentx_free_pdu (pdu);
    return -1;
  }

  agentx_free_varbind (varbind2);
  pdu->variables = NULL;
  agentx_free_pdu (pdu);
  agentx_free_varbind (varbind);
  if (IS_SUBAG_DEBUG_PROCESS)
    zlog_info (zg, "AgentX: notified");
  return 0;
}

#endif  /* HAVE_AGENTX */
#endif  /* HAVE_SNMP */
