/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */
/* This file included api functions related to snmp and agentx */

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

/*--------------------------------------------------------*
 *   SNMP-API                                             *
 *--------------------------------------------------------*/

const char     *snmp_error_string[MAX_SNMP_ERR + 1] = {
    "(noError) No Error",
    "(tooBig) Response message would have been too large.",
    "(noSuchName) There is no such variable name in this MIB.",
    "(badValue) The value given has the wrong type or length.",
    "(readOnly) The two parties used do not have access to use the specified SNMP PDU.",
    "(genError) A general failure occured",
    "noAccess",
    "wrongType (The set datatype does not match the data type the agent expects)",
    "wrongLength (The set value has an illegal length from what the agent expects)",
    "wrongEncoding",
    "wrongValue (The set value is illegal or unsupported in some way)",
    "noCreation (that table does not support row creation)",
    "inconsistentValue (The set value is illegal or unsupported in some way)",
    "resourceUnavailable (This is likely a out-of-memory failure within the agent)",
    "commitFailed",
    "undoFailed",
    "authorizationError (access denied to that object)",
    "notWritable (that object does not support modification)",
    "inconsistentName"
};

const char *
snmp_errstring(int errstat)
{
    if (errstat <= MAX_SNMP_ERR && errstat >= SNMP_ERR_NOERROR) {
        return snmp_error_string[errstat];
    } else {
        return "Unknown Error";
    }
}

static const char *snmp_lib_errors[-SNMPERR_MAX + 1] = {
    "No error",                 /* SNMPERR_SUCCESS */
    "Generic error",            /* SNMPERR_GENERR */
    "Invalid local port",       /* SNMPERR_BAD_LOCPORT */
    "Unknown host",             /* SNMPERR_BAD_ADDRESS */
    "Unknown session",          /* SNMPERR_BAD_SESSION */
    "Too long",                 /* SNMPERR_TOO_LONG */
    "Too short",                /* SNMPERR_TOO_SHORT */
    "No socket",                /* SNMPERR_NO_SOCKET */
    "Bad value for non-repeaters",      /* SNMPERR_BAD_REPEATERS */
    "Bad value for max-repetitions",    /* SNMPERR_BAD_REPETITIONS */
    "Error building AgentX (ASN.1) representation", /* SNMPERR_BAD_BUILD */
    "Failure in sendto",        /* SNMPERR_BAD_SENDTO */
    "Bad parse of AgentX (ASN.1) type", /* SNMPERR_BAD_PARSE */
    "Bad version specified",    /* SNMPERR_BAD_VERSION */
    "Bad source party specified",       /* SNMPERR_BAD_SRC_PARTY */
    "Bad destination party specified",  /* SNMPERR_BAD_DST_PARTY */
    "Bad context specified",    /* SNMPERR_BAD_CONTEXT */
    "Bad community specified",  /* SNMPERR_BAD_COMMUNITY */
    "Bad ACL definition",       /* SNMPERR_BAD_ACL */
    "Bad Party definition",     /* SNMPERR_BAD_PARTY */
    "Session abort failure",    /* SNMPERR_ABORT */
    "Unknown PDU type",         /* SNMPERR_UNKNOWN_PDU */
    "Timeout",                  /* SNMPERR_TIMEOUT */
    "Failure in recvfrom",      /* SNMPERR_BAD_RECVFROM */
    "AgentX (ASN.1) parse error in message",    /* SNMPERR_PARSE_ERR */
    "Invalid message (e.g. msgFlags)",  /* SNMPERR_INVALID_MSG */
    "Not in time window",       /* SNMPERR_NOT_IN_TIME_WINDOW */
    "Unknown Report message",   /* SNMPERR_UNKNOWN_REPORT */
    "MIB not initialized",      /* SNMPERR_NOMIB */
    "Value out of range",       /* SNMPERR_RANGE */
    "Sub-id out of range",      /* SNMPERR_MAX_SUBID */
    "Bad sub-id in object identifier",  /* SNMPERR_BAD_SUBID */
    "Object identifier too long",       /* SNMPERR_LONG_OID */
    "Bad value name",           /* SNMPERR_BAD_NAME */
    "Bad value notation",       /* SNMPERR_VALUE */
    "Unknown Object Identifier",        /* SNMPERR_UNKNOWN_OBJID */
    "No PDU in snmp_send",      /* SNMPERR_NULL_PDU */
    "Missing variables in PDU", /* SNMPERR_NO_VARS */
    "Bad variable type",        /* SNMPERR_VAR_TYPE */
    "Out of memory (malloc failure)",   /* SNMPERR_MALLOC */
};

void
snmp_lib_errstring(int snmp_errnumber, char *msg_buf)
{
  char msg[256];

  pal_mem_set(msg, 0, 256);
  if (snmp_errnumber >= SNMPERR_MAX && snmp_errnumber <= SNMPERR_GENERR) {
    pal_strcpy (msg, snmp_lib_errors[-snmp_errnumber]);
  } else if (snmp_errnumber != SNMPERR_SUCCESS) {
    pal_strcpy (msg, "Unknown Error");
  }
  pal_strncpy (msg_buf, msg, 256);
  msg_buf[255] = '\0';
  return; 
}

void
snmp_perror (struct lib_globals *zg, const char *prog_string)
{
  char msg_buf[256];
  int snmp_lib_errno = 0;
  int xerr;

  xerr = snmp_lib_errno;
  snmp_lib_errstring(xerr, msg_buf);
  zlog_err (zg, "%s: %s\n", prog_string, msg_buf);
}

void
snmp_error (struct agentx_session *sess,
            int *p_errno, int *p_lib_errno, char **p_str)
{
  char buf[SPRINT_MAX_LEN];
  int snmp_errnumber;

  if (p_errno)
    *p_errno = sess->sys_errno;
  if (p_lib_errno)
    *p_lib_errno = sess->lib_errno;
  if (p_str == NULL)
    return;

  pal_strcpy (buf, "");
  snmp_errnumber = sess->lib_errno;
  if (snmp_errnumber >= SNMPERR_MAX && snmp_errnumber <= SNMPERR_GENERR) {
    pal_strncpy (buf, snmp_lib_errors[-snmp_errnumber], 256);
  } else {
    if (snmp_errnumber)
      snprintf(buf, 256, "Unknown Error %d", snmp_errnumber);
  }
    buf[255] = '\0';

  /* append a useful system errno interpretation. */
  if (sess->sys_errno) {
    const char* error = pal_strerror(sess->sys_errno);
    if (error == NULL)
      error = "Unknown Error";
    snprintf (&buf[pal_strlen(buf)], 256 - pal_strlen(buf),
              " (%s)", error);
  }
  buf[255] = '\0';
  *p_str = pal_strdup (MTYPE_TMP, buf);
}

int
snmp_realloc (u_char **buf, size_t *buf_len)
{
  u_char *new_buf = NULL;
  size_t new_buf_len = 0;

  if (buf == NULL) {
    return 0;
  }

  if (*buf_len <= 255) {
    new_buf_len = *buf_len + 256;
  } else if (*buf_len > 255 && *buf_len <= 8191) {
    new_buf_len = *buf_len * 2;
  } else if (*buf_len > 8191) {
    new_buf_len = *buf_len + 8192;
  }

  if (*buf == NULL) {
    new_buf = (u_char *) XMALLOC (MTYPE_TMP, new_buf_len);
  } else {
    new_buf = (u_char *) XREALLOC (MTYPE_TMP, *buf, new_buf_len);
  }

  if (new_buf != NULL) {
    *buf = new_buf;
    *buf_len = new_buf_len;
    return 1;
  } else {
    return 0;
  }
}

int
snmp_decimal_to_binary (u_char ** buf, size_t * buf_len, size_t * out_len,
                        const char *decimal)
{
  int subid = 0;
  const char *cp = decimal;

  if (buf == NULL || buf_len == NULL || out_len == NULL
      || decimal == NULL) {
    return 0;
  }

  while (*cp != '\0') {
    if (pal_char_isspace((int) *cp) || *cp == '.') {
      cp++;
      continue;
    }
    if (!pal_char_isdigit((int) *cp)) {
      return 0;
    }
    if ((subid = pal_atoi(cp)) > 255) {
      return 0;
    }
    if ((*out_len >= *buf_len) &&
        !(snmp_realloc (buf, buf_len))) {
      return 0;
    }
    *(*buf + *out_len) = (u_char) subid;
    (*out_len)++;
    while (pal_char_isdigit((int) *cp)) {
      cp++;
    }
  }
  return 1;
}

int
snmp_hex_to_binary (u_char ** buf, size_t * buf_len, size_t * out_len,
                    const char *hex)
{
  int subid = 0;
  const char *cp = hex;

  if (buf == NULL || buf_len == NULL || out_len == NULL || hex == NULL) {
    return 0;
  }

  if ((*cp == '0') && ((*(cp + 1) == 'x') || (*(cp + 1) == 'X'))) {
    cp += 2;
  }

  while (*cp != '\0') {
    if (pal_char_isspace((int) *cp)) {
      cp++;
      continue;
    }
    if (!pal_char_isxdigit((int) *cp)) {
      return 0;
    }
    if (sscanf(cp, "%2x", &subid) == 0) {
      return 0;
    }
    if ((*out_len >= *buf_len) &&
        !(snmp_realloc (buf, buf_len))) {
      return 0;
    }
    *(*buf + *out_len) = (u_char) subid;
    (*out_len)++;
    if (*++cp == '\0') {
      /* Odd number of hex digits is an error. */
      return 0;
    } else {
      cp++;
    }
  }
  return 1;
}

int
_add_str2oid (struct lib_globals *zg, char *cp,
              oid *objid, size_t *objidlen, size_t maxlen)
{
  oid subid;
  char *fcp, *ecp, *cp2 = NULL;
  char doingquote;
  int  len = -1;

  while (cp) {
    fcp = cp;
    switch (*cp) {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        cp2 = pal_strchr (cp, '.');
        if (cp2)
          *cp2++ = 0;
        subid = pal_strtou32 (cp, &ecp, 0);
        if (*ecp)
          goto bad_id;
        if (*objidlen >= maxlen)
          goto bad_id;
        objid[*objidlen] = subid;
        (*objidlen)++;
        break;
      case '"':
      case '\'':
        doingquote = *cp++;
        /* insert length if requested */
        if (doingquote == '"') {
          if (*objidlen >= maxlen)
            goto bad_id;
          objid[*objidlen] = len = pal_strchr (cp, doingquote) - cp;
          (*objidlen)++;
        }

        if (! cp)
          goto bad_id;
        while (*cp && *cp != doingquote) {
          if (*objidlen >= maxlen)
            goto bad_id;
          objid[*objidlen] = *cp++;
          (*objidlen)++;
        }
        cp2 = cp + 1;
        if (!*cp2)
          cp2 = NULL;
        else if (*cp2 == '.')
          cp2++;
        else
          goto bad_id;
        break;
      default:
        goto bad_id;
    }
    cp = cp2;
  }
  return 1;

  bad_id:
    {
      char            buf[256];

      snprintf(buf, sizeof(buf), "%s", fcp);
      buf[ sizeof(buf)-1 ] = 0;

      if (IS_SUBAG_DEBUG)
        zlog_info (zg, "str2oid failed! %s", buf);
    }
    return 0;
}

/*
 * Parse an object identifier from an input string into internal OID form.
 */
int
snmp_parse_oid (struct lib_globals *zg, const char *input,
                oid *output, size_t *out_len)
{
  int ret, max_out_len;
  char *name, ch;
  const char *cp;

  cp = input;
  while ((ch = *cp)) {
    if (('0' <= ch && ch <= '9')
        || ('a' <= ch && ch <= 'z')
        || ('A' <= ch && ch <= 'Z')
        || ch == '-')
      cp++;
    else
      break;
  }

  if (*input == '.')
    input++;
  name = pal_strdup (MTYPE_TMP, input);
  max_out_len = *out_len;
  *out_len = 0;
  if ((ret = _add_str2oid (zg, name, output, out_len, max_out_len)) <= 0) {
    if (ret == 0)
      ret = SNMPERR_UNKNOWN_OBJID;
    IS_SUBAG_DEBUG_LIBERR_SHOW (ret);
    AGENTX_FREE(name);
    return 0;
  }
  AGENTX_FREE (name);

  return 1;
}

/*--------------------------------------------------------*
 *   AGENTX-API                                           *
 *--------------------------------------------------------*/

const char *agentx_error_string[MAX_AGENTX_ERR-MIN_AGENTX_ERR + 1] = {
    "(openFailed) Failed to open session.", /* AGENTX_ERR_OPEN_FAILED */
    "(notOpen) h.sessionID doesn't correspond to a established session.",
                                /* AGENTX_ERR_NOT_OPEN */
    "indexWrongType",           /* AGENTX_ERR_INDEX_WRONG_TYPE */
    "indexAlreadyAllocated",    /* AGENTX_ERR_INDEX_ALREADY_ALLOCATED */
    "indexNoneAvailable",       /* AGENTX_ERR_INDEX_NONE_AVAILABLE */
    "indexNotAllocated",        /* AGENTX_ERR_INDEX_NOT_ALLOCATED */
    "unsupportedContext",       /* AGENTX_ERR_UNSUPPORTED_CONTEXT */
    "duplicateRegistration",    /* AGENTX_ERR_DUPLICATE_REGISTRATION */
    "unknownRegistration",      /* AGENTX_ERR_UNKNOWN_REGISTRATION */
    "unknownAgentCaps",         /* AGENTX_ERR_UNKNOWN_AGENTCAPS */
    "(parseError) The received PDU cannot be parsed",
                                /* AGENTX_ERR_PARSE_ERROR */
    "requestDenied",            /* AGENTX_ERR_REQUEST_DENIED */
    "(processingError) Resource cannot be allocated or ..."
                                /* AGENTX_ERR_PROCESSING_ERROR */
};

const char *
agentx_errstring (int errstat)
{
    if (errstat <= MAX_SNMP_ERR && errstat >= SNMP_ERR_NOERROR) {
        return snmp_error_string[errstat];
    } else if (errstat <= MAX_AGENTX_ERR && errstat >= MIN_AGENTX_ERR) {
        return agentx_error_string[errstat - MIN_AGENTX_ERR];
    } else {
        return "Unknown Error";
    }
}

int
agentx_action_test_set ()
{
  /* dummy function to keep up with agentx elaborate set action */
  return 0;
}

int
agentx_handle_cleanup_set ()
{
  /* dummy function to keep up with agentx elaborate set action */
  return 0;
}

int
agentx_action_undo_set ()
{
  /* dummy function to keep up with agentx elaborate set action */
  return 0;
}

long
agentx_get_next_reqid (struct lib_globals *zg)
{
  long retVal;
  
  if (!zg)
    return -1;

  retVal = 1 + (zg->snmp.Reqid);
  if (!retVal)
    retVal = 2;
  zg->snmp.Reqid = retVal;
  return retVal;
}

long
agentx_get_next_transid (struct lib_globals *zg)
{
  long retVal;

  if (!zg)
    return -1;

  retVal = 1 + zg->snmp.Transid;
  if (!retVal)
    retVal = 2;
  zg->snmp.Transid = retVal;
  return retVal;
}

struct agentx_pdu *
agentx_pdu_create (int command, int req_flag, struct lib_globals *zg)
{
  struct agentx_pdu *pdu;

  if (!zg)
    return NULL;

  pdu = (struct agentx_pdu *) XCALLOC (MTYPE_TMP, sizeof (struct agentx_pdu));
  if (pdu) {
    pdu->version = AGENTX_DEFAULT_VERSION;
    pdu->command = command;
    pdu->errstat = AGENTX_DEFAULT_ERRSTAT;
    pdu->errindex = AGENTX_DEFAULT_ERRINDEX;
    pdu->time = 0;
    /* pdu->flags : non-network byte order */
    if (req_flag)
      pdu->reqid = agentx_get_next_reqid (zg);
  }
  return pdu;
}


/*
 * Add a null variable with the requested name to the end of the list of
 * variables for this pdu.
 */
struct agentx_variable_list *
agentx_add_null_var (struct lib_globals *zg, struct agentx_pdu *pdu,
                     const oid *name, size_t name_length)
{
  return agentx_pdu_add_variable (zg, pdu, name, name_length, ASN_NULL, NULL, 0);
}

/* Clone an AgentX variable data structure. */
int
agentx_clone_var (struct agentx_variable_list * var,
                  struct agentx_variable_list * newvar)
{
  if (!newvar || !var)
    return 1;

  pal_mem_move (newvar, var, sizeof(struct agentx_variable_list));
  newvar->next_variable = 0;
  newvar->name = 0;
  newvar->val.string = 0;
  newvar->data = 0;
  newvar->dataFreeHook = 0;
  newvar->index = 0;

  /* Clone the object identifier and the value.
   * Allocate memory iff original will not fit into local storage. */
  if (agentx_set_var_objid (newvar, var->name, var->name_length))
    return 1;

  /* need a pointer and a length to copy a string value. */
  if (var->val.string && var->val_len) {
    if (var->val.string != &var->buf[0]) {
      if (var->val_len <= sizeof(var->buf))
        newvar->val.string = newvar->buf;
      else {
        newvar->val.string = (u_char *) XMALLOC (MTYPE_TMP, var->val_len);
        if (!newvar->val.string)
          return 1;
      }
      pal_mem_move (newvar->val.string, var->val.string, var->val_len);
    } else {  /* fix the pointer to new local store */
      newvar->val.string = newvar->buf;
    }
  } else {
    newvar->val.string = 0;
    newvar->val_len = 0;
  }
  return 0;
}

int
agentx_clone_mem (void **dstPtr, void *srcPtr, unsigned len)
{
  *dstPtr = 0;
  if (srcPtr) {
    *dstPtr = XMALLOC (MTYPE_TMP, len + 1);
    if (!*dstPtr) {
      return 1;
    }
    pal_mem_move (*dstPtr, srcPtr, len);
    /* this is for those routines that expect 0-terminated strings. */
    ((char *) *dstPtr)[len] = 0;
  }
  return 0;
}

/*
 * Creates and allocates a clone of the input PDU,
 * but does NOT copy the variables.
 */
static struct agentx_pdu *
_clone_pdu_header (struct agentx_pdu *pdu)
{
  struct agentx_pdu *newpdu;

  newpdu = (struct agentx_pdu *) XMALLOC (MTYPE_TMP, sizeof (struct agentx_pdu));
  if (!newpdu)
    return 0;

  pal_mem_move (newpdu, pdu, sizeof (struct agentx_pdu));

  /* reset copied pointers if copy fails. */
  newpdu->variables = 0;
  newpdu->community = 0;

  /* copy buffers individually. If any copy fails, all are freed. */
  if (agentx_clone_mem ((void **) &newpdu->community, pdu->community,
                      pdu->community_len)) {
    agentx_free_pdu (newpdu);
    return 0;
  }

  return newpdu;
}

static struct agentx_variable_list *
_copy_varlist (struct agentx_variable_list * var,      /* source varList */
               int errindex,   /* index of variable to drop (if any) */
               int copy_count) /* !=0 number variables to copy */
{
  struct agentx_variable_list *newhead, *newvar, *oldvar;
  int ii = 0;

  newhead = NULL;
  oldvar = NULL;

  while (var && (copy_count-- > 0)) {
    /* Drop the specified variable (if applicable). */
    if (++ii == errindex) {
      var = var->next_variable;
      continue;
    }

    /* clone the next variable. Cleanup if alloc fails. */
    newvar = (struct agentx_variable_list *)
              XMALLOC (MTYPE_TMP, sizeof (struct agentx_variable_list));
    if (agentx_clone_var (var, newvar)) {
      if (newvar)
        AGENTX_FREE (newvar);
      agentx_free_varbind (newhead);
      return 0;
    }

    /* add cloned variable to new list. */
    if (0 == newhead)
      newhead = newvar;
    if (oldvar)
      oldvar->next_variable = newvar;
    oldvar = newvar;
    var = var->next_variable;
  }
  return newhead;
}

/*
 * Copy some or all variables from source PDU to target PDU.
 */
static struct agentx_pdu *
_copy_pdu_vars(struct agentx_pdu *pdu,        /* source PDU */
               struct agentx_pdu *newpdu,     /* target PDU */
               int drop_err,    /* !=0 drop errored variable */
               int skip_count,  /* !=0 number of variables to skip */
               int copy_count)  /* !=0 number of variables to copy */
{
  struct agentx_variable_list *var, *oldvar;
  int ii, copied, drop_idx;

  if (!newpdu)
    return 0;               /* where is PDU to copy to ? */

  if (drop_err)
    drop_idx = pdu->errindex - skip_count;
  else
    drop_idx = 0;

  var = pdu->variables;
  while (var && (skip_count-- > 0))   /* skip over pdu variables */
    var = var->next_variable;

  oldvar = 0;
  ii = 0;
  copied = 0;
  if (pdu->flags & AGENTX_FLAGS_FORCE_PDU_COPY)
    copied = 1;             /* We're interested in 'empty' responses too */

  newpdu->variables = _copy_varlist (var, drop_idx, copy_count);
  if (newpdu->variables)
    copied = 1;

  return newpdu;
}


/*
 * Creates (allocates and copies) a clone of the input PDU.
 */
static struct agentx_pdu *
_clone_pdu (struct agentx_pdu *pdu, int drop_err)
{
  struct agentx_pdu    *newpdu;

  newpdu = _clone_pdu_header (pdu);
  newpdu = _copy_pdu_vars (pdu, newpdu, drop_err, 0, 10000);   /* skip none, copy all */

  return newpdu;
}


/*
 * This function will clone a full varbind list.
 */
struct agentx_variable_list *
agentx_clone_varbind (struct agentx_variable_list * varlist)
{
  return _copy_varlist (varlist, 0, 10000); /* skip none, copy all */
}

/*
 * This function will clone a PDU including all of its variables.
 */
struct agentx_pdu *
agentx_clone_pdu (struct agentx_pdu *pdu)
{
  return _clone_pdu (pdu, 0);  /* copies all variables */
}

/*
 * Add object identifier name to SNMP variable.
 */
int
agentx_set_var_objid (struct agentx_variable_list *vp,
                      const oid *objid, size_t name_length)
{
  size_t len = sizeof(oid) * name_length;

  if (vp->name != vp->name_loc && vp->name != NULL &&
      vp->name_length > (sizeof(vp->name_loc) / sizeof(oid))) {
    AGENTX_FREE (vp->name);
  }

  /* use built-in storage for smaller values */
  if (len <= sizeof (vp->name_loc)) {
    vp->name = vp->name_loc;
  } else {
    vp->name = (oid *) XMALLOC (MTYPE_TMP, len);
    if (!vp->name)
      return 1;
  }
  if (objid)
    pal_mem_move (vp->name, objid, len);
  vp->name_length = name_length;
  return 0;
}

/*
 * Add some value to AgentX variable.
 */
int
agentx_set_var_value (struct agentx_variable_list *newvar,
                      const u_char *val_str, size_t val_len)
{
  if (newvar->val.string && newvar->val.string != newvar->buf) {
    AGENTX_FREE (newvar->val.string);
  }

  newvar->val.string = 0;
  newvar->val_len = 0;

  /* need a pointer and a length to copy a string value. */
  if (val_str && val_len) {
    if (val_len <= sizeof(newvar->buf))
      newvar->val.string = newvar->buf;
    else {
      newvar->val.string = (u_char *) XMALLOC (MTYPE_TMP, val_len);
      if (!newvar->val.string)
        return 1;
    }
    pal_mem_move (newvar->val.string, val_str, val_len);
    newvar->val_len = val_len;
  } else if (val_str) {
    /* NULL STRING != NULL ptr */
    newvar->val.string = newvar->buf;
    newvar->val.string[0] = '\0';
    newvar->val_len = 0;
  }
  return 0;
}

/*
 * agentx_set_var_typed_value is used to set data into the agentx_variable_list
 * structure.
 */
int
agentx_set_var_typed_value (struct agentx_variable_list *newvar, u_char type,
                            const u_char *val_str, size_t val_len)
{
    newvar->type = type;
    return agentx_set_var_value (newvar, val_str, val_len);
}

/*
 * Frees the variable and any malloc'd data associated with it.
 */
void
agentx_free_var (struct agentx_variable_list *var)
{
  if (!var)
    return;

  if (var->name != var->name_loc)
    AGENTX_FREE(var->name);
  if (var->val.string != var->buf)
    AGENTX_FREE(var->val.string);
  if (var->data) {
    if (var->dataFreeHook) {
      var->dataFreeHook(var->data);
      var->data = NULL;
    } else {
      AGENTX_FREE (var->data);
    }
  }
  AGENTX_FREE (var);
}

void
agentx_free_varbind (struct agentx_variable_list *var)
{
  struct agentx_variable_list *ptr;

  while (var) {
    ptr = var->next_variable;
    agentx_free_var (var);
    var = ptr;
  }
  var = NULL;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
agentx_free_pdu (struct agentx_pdu *pdu)
{
  if (!pdu)
    return;
  agentx_free_varbind (pdu->variables);
  AGENTX_FREE (pdu->community);
  pal_mem_set(pdu, 0, sizeof (struct agentx_pdu));
  AGENTX_FREE (pdu);
  return;
}

/*
 * Add a variable with the requested name to the end of the list of
 * variables for this pdu.
 */
struct agentx_variable_list *
agentx_varlist_add_variable (struct lib_globals *zg,
                             struct agentx_variable_list **varlist,
                             const oid *name, size_t name_length,
                             u_char type, const u_char *value, size_t len)
{
  struct agentx_variable_list *vars, *vtmp;
  int largeval = 1;
  const long *val_long = NULL;
  const int *val_int  = NULL;

  if (varlist == NULL)
    return NULL;

  vars = (struct agentx_variable_list *) XMALLOC (MTYPE_TMP,
                                          sizeof (struct agentx_variable_list));
  if (vars == NULL)
    return NULL;

  vars->next_variable = 0;
  vars->name = 0;
  vars->name_length = 0;
  vars->val.string = 0;
  vars->data = 0;
  vars->dataFreeHook = 0;
  vars->index = 0;

  /* use built-in storage for smaller values */
  if (len <= (sizeof(vars->buf) - 1)) {
    vars->val.string = (u_char *) vars->buf;
    largeval = 0;
  }

  vars->type = type;
  vars->val_len = len;
  switch (type) {
    case ASN_INTEGER:
    case ASN_UNSIGNED:
    case ASN_TIMETICKS:
    case ASN_IPADDRESS:
    case ASN_COUNTER:
      if (value) {
        if (largeval) {
          zlog_err (zg, "AgentX: bad size for integer-like type (%d)\n",
                    vars->val_len);
          agentx_free_var (vars);
          return (0);
        } else if (vars->val_len == sizeof(int)) {
          val_int = (const int *) value;
          *(vars->val.integer) = (long) *val_int;
        } else {
          val_long = (const long *) value;
           *(vars->val.integer) = *val_long;
        }
      }
      vars->val_len = sizeof(long);
      break;

    case ASN_OBJECT_ID:
    case ASN_PRIV_IMPLIED_OBJECT_ID:
    case ASN_PRIV_INCL_RANGE:
    case ASN_PRIV_EXCL_RANGE:
      if (largeval) {
        vars->val.objid = (oid *) XMALLOC (MTYPE_TMP, vars->val_len);
      }
      if (vars->val.objid == NULL) {
        agentx_free_var (vars);
        return NULL;
      }
      pal_mem_move (vars->val.objid, value, vars->val_len);
      break;

    case ASN_PRIV_IMPLIED_OCTET_STR:
    case ASN_OCTET_STR:
    case ASN_BIT_STR:
    case ASN_OPAQUE:
    case ASN_NSAP:
      if (largeval) {
        vars->val.string = (u_char *) XMALLOC (MTYPE_TMP, vars->val_len + 1);
      }
      if (vars->val.string == NULL) {
        agentx_free_var (vars);
        return NULL;
      }
      pal_mem_move (vars->val.string, value, vars->val_len);
      /* Make sure the string is zero-terminated. */
      vars->val.string[vars->val_len] = '\0';
      break;

    case SNMP_NOSUCHOBJECT:
    case SNMP_NOSUCHINSTANCE:
    case SNMP_ENDOFMIBVIEW:
    case ASN_NULL:
      vars->val_len = 0;
      vars->val.string = NULL;
      break;

    case ASN_COUNTER64:
      if (largeval) {
        zlog_err (zg, "AgentX: bad size for counter 64 (%d)\n",
                  vars->val_len);
        agentx_free_var (vars);
        return (0);
      }
      vars->val_len = sizeof (struct counter64);
      pal_mem_move (vars->val.counter64, value, vars->val_len);
      break;

    default:
      zlog_err (zg, "AgentX: Internal error in type switching\n");
      agentx_free_var (vars);
      return (0);
  }

  if (name != NULL && agentx_set_var_objid (vars, name, name_length)) {
    agentx_free_var (vars);
    return (0);
  }

  /* put only qualified variable onto varlist */
  if (*varlist == NULL) {
    *varlist = vars;
  } else {
    for (vtmp = *varlist; vtmp->next_variable;
       vtmp = vtmp->next_variable);

    vtmp->next_variable = vars;
  }

  return vars;
}

/*
 * Add a variable with the requested name to the end of the list of
 * variables for this pdu.
 */
struct agentx_variable_list *
agentx_pdu_add_variable (struct lib_globals *zg, struct agentx_pdu *pdu,
                         const oid *name, size_t name_length,
                         u_char type, const u_char *value, size_t len)
{
  return agentx_varlist_add_variable (zg, &pdu->variables, name, name_length,
                                      type, value, len);
}


/*
 * Add a variable with the requested name to the end of the list of
 * variables for this pdu.
 */
int
agentx_add_var (struct lib_globals *zg, struct agentx_pdu *pdu,
                const oid *name, size_t name_length,
                char type, const char *value)
{
  const char     *cp;
  char           *ecp, *vp;
  int             result = SNMPERR_SUCCESS;
  u_char         *buf = NULL;
  const u_char   *buf_ptr = NULL;
  size_t          buf_len = 0, value_len = 0, tint;
  long            ltmp;
  int             itmp;
  struct pal_in4_addr addr;
  result_t ret;

  switch (type) {
    case 'i':
      if (!*value)
        goto fail;
      ltmp = pal_strtos32 (value, &ecp, 10);
      if (*ecp) {
        result = SNMPERR_BAD_NAME;
        break;
      }

      agentx_pdu_add_variable (zg, pdu, name, name_length, ASN_INTEGER,
                               (u_char *) &ltmp, sizeof(ltmp));
      break;

    case 'u':
      ltmp = pal_strtou32 (value, &ecp, 10);
      if (*value && !*ecp)
        agentx_pdu_add_variable (zg, pdu, name, name_length, ASN_UNSIGNED,
                                 (u_char *) &ltmp, sizeof(ltmp));
      else
        goto fail;
      break;

    case '3':
      ltmp = pal_strtos32 (value, &ecp, 10);
      if (*value && !*ecp)
        agentx_pdu_add_variable (zg, pdu, name, name_length, ASN_UINTEGER,
                                 (u_char *) &ltmp, sizeof(ltmp));
      else
        goto fail;
      break;

    case 'c':
      ltmp = pal_strtos32 (value, &ecp, 10);
      if (*value && !*ecp)
        agentx_pdu_add_variable (zg, pdu, name, name_length, ASN_COUNTER,
                                 (u_char *) &ltmp, sizeof(ltmp));
      else
        goto fail;
      break;

    case 't':
      ltmp = pal_strtos32 (value, &ecp, 10);
      if (*value && !*ecp)
        agentx_pdu_add_variable (zg, pdu, name, name_length, ASN_TIMETICKS,
                                 (u_char *) &ltmp, sizeof(long));
      else
        goto fail;
      break;

    case 'a':
      ret = pal_inet_pton (AF_INET, value, (void*)&addr);
      if (ret <= 0)
        goto fail;
      ltmp = addr.s_addr;
      if (ltmp != (long) -1 || !pal_strcmp (value, "255.255.255.255"))
        agentx_pdu_add_variable (zg, pdu, name, name_length, ASN_IPADDRESS,
                                 (u_char *) &ltmp, sizeof(long));
      else
        goto fail;
      break;

    case 'o':
      if ((buf = XMALLOC (MTYPE_TMP, sizeof(oid) * MAX_OID_LEN)) == NULL) {
        result = SNMPERR_MALLOC;
      } else {
        tint = MAX_OID_LEN;
        if (snmp_parse_oid (zg, value, (oid *) buf, &tint)) {
          agentx_pdu_add_variable (zg, pdu, name, name_length,
                                   ASN_OBJECT_ID, buf,
                                   sizeof(oid) * tint);
        } else {
          result = SNMPERR_BAD_PARSE;
        }
      }
      break;

    case 's':
    case 'x':
    case 'd':
      if (type == 'd') {
        if (!snmp_decimal_to_binary
            (&buf, &buf_len, &value_len, value)) {
          result = SNMPERR_VALUE;
          break;
        }
        buf_ptr = buf;
      } else if (type == 'x') {
        if (!snmp_hex_to_binary (&buf, &buf_len, &value_len, value)) {
          result = SNMPERR_VALUE;
          break;
        }
       /* initialize itmp value so that range check below works */
        itmp = value_len;
        buf_ptr = buf;
      } else if (type == 's') {
        buf_ptr = value;
        value_len = pal_strlen (value);
      }
      agentx_pdu_add_variable (zg, pdu, name, name_length, ASN_OCTET_STR,
                               buf_ptr, value_len);
      break;

    case 'n':
      agentx_pdu_add_variable (zg, pdu, name, name_length, ASN_NULL, 0, 0);
      break;

    case 'b':
      tint = 0;
      if ((buf = (u_char *) XMALLOC (MTYPE_TMP, 256)) == NULL) {
        result = SNMPERR_MALLOC;
        break;
      } else {
        buf_len = 256;
        pal_mem_set (buf, 0, buf_len);
      }

      vp = pal_strdup (MTYPE_TMP, value);
      for (cp = pal_strtok (vp, " ,\t"); cp; cp = pal_strtok (NULL, " ,\t")) {
        int ix, bit;

        ltmp = pal_strtou32 (cp, &ecp, 0);
        if (*ecp != 0) {
          result = SNMPERR_BAD_NAME;
          AGENTX_FREE (buf);
          AGENTX_FREE (vp);
          goto out;
        }

        ix = ltmp / 8;
        if (ix >= (int) tint) {
          tint = ix + 1;
        }
        if (ix >= (int)buf_len && !snmp_realloc (&buf, &buf_len)) {
          result = SNMPERR_MALLOC;
          break;
        }
        bit = 0x80 >> ltmp % 8;
        buf[ix] |= bit;

      }
      AGENTX_FREE (vp);
      agentx_pdu_add_variable (zg, pdu, name, name_length, ASN_OCTET_STR,
                               buf, tint);
      break;

    default:
      result = SNMPERR_VAR_TYPE;
        zlog_warn (zg, "AgentX: add_var, type error \"%c\"", type);
      break;
  }

  AGENTX_FREE (buf);
  IS_SUBAG_DEBUG_LIBERR_SHOW (result);
  return result;

  fail:
    result = SNMPERR_VALUE;
  out:
    IS_SUBAG_DEBUG_LIBERR_SHOW (result);
    return result;
}

#endif  /* HAVE_AGENTX */
#endif  /* HAVE_SNMP */
