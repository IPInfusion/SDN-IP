/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#ifdef HAVE_SNMP
#include "asn1.h"

#include "log.h"
#include "thread.h"
#include "linklist.h"
#include "bgpsdn_version.h"

#include "snmp.h"  
#include "snmp_misc.h"

#ifndef ibm032
#  define RETURN_SUB_BUF_LENGTH 258
#else
#  define RETURN_SUB_BUF_LENGTH 256     /* nee 64 */
#endif
long long_sub_return;
unsigned long unsigned_sub_return;
u_char return_sub_buf[RETURN_SUB_BUF_LENGTH];

int
snmp_util_advance_index_name (struct variable *vp, oid * name,
                              size_t * length, int exact)
{
  int result;

  if (exact)
    return 0;

  if (*length <= vp->namelen)
    {
      result = oid_compare (name, *length, vp->name, (int) vp->namelen);
      pal_mem_cpy ((char *) name, (char *) vp->name,
              ((int) vp->namelen) * sizeof (oid));
      *length = vp->namelen;
    }
  else
    {
      /* If the name is given with indexes - compare only the oids. */
      result =
        oid_compare (name, (int) vp->namelen, vp->name,
                          (int) vp->namelen);
      /* If it's not the same oid - change name to the new oid */
      if (result < 0)
        {
          pal_mem_cpy ((char *) name, (char *) vp->name,
                  ((int) vp->namelen) * sizeof (oid));
          *length = vp->namelen;
        }
    }

  if (result > 0)
    {
      ag_trace ("*length=%d result=%d !!!", (int) *length, (int) result);
      return -1;
    }
  return 0;
}

int
snmp_util_get_int_value (u_char * var_val, int for_smux,
                         long min_value, long max_value, long *long_tmp)
{
  pal_mem_cpy (long_tmp, var_val, 4);

  if (max_value >= min_value)
    {
      if (*long_tmp < min_value)
        {
          ag_trace ("%s: %ld=long_tmp < min=%ld", __FUNCTION__,
                    (long) *long_tmp, (long) min_value);
          return SNMP_ERR_BADVALUE;
        }

      if (*long_tmp > max_value)
        {
          ag_trace ("%s: %ld=long_tmp > max=%ld", __FUNCTION__,
                    (long) *long_tmp, (long) max_value);
          return SNMP_ERR_BADVALUE;
        }
    }

  return SNMP_ERR_NOERROR;
}

int
snmp_util_get_ip_value (u_char * var_val, u_char var_val_type,
                        int var_val_len, int for_smux,
                        struct pal_in4_addr *ip_addr)

{
  int s_addr_size = sizeof (ip_addr->s_addr);

  if (ASN_APPLICATION != var_val_type &&
      ASN_IPADDRESS != var_val_type && ASN_OCTET_STR != var_val_type)
    {
      ag_trace ("%s: invalid var_val_type: 0x%lx", __FUNCTION__,
                (long) var_val_type);
      return SNMP_ERR_WRONGTYPE;
    }

  if (var_val_len != sizeof (ip_addr->s_addr))
    {
      ag_trace ("%s: wrong param. len=%d != %d", __FUNCTION__,
                (int) var_val_len, sizeof (ip_addr->s_addr));
      return SNMP_ERR_WRONGLENGTH;
    }

  s_addr_size = var_val_len;

  pal_mem_cpy (ip_addr, var_val, s_addr_size);
  return SNMP_ERR_NOERROR;
}

int
snmp_util_check_ip_value (long *index, struct pal_in4_addr *addr)
{
  struct prefix p;
  long indx = 0;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;

  p.u.prefix4 = *addr;
  indx = pal_ntoh32 (p.u.prefix4.s_addr);
  if ((indx == (*index)))
    return SNMP_ERR_NOERROR;
  else
    return SNMP_ERR_BADVALUE;
}

#ifdef HAVE_IPV6
int
snmp_util_get_ipv6_value (u_char * var_val, u_char var_val_type,
                         int var_val_len, int for_smux,
                         struct pal_in6_addr *ip_addr)

{
  if (ASN_APPLICATION != var_val_type &&
      ASN_IPADDRESS != var_val_type && ASN_OCTET_STR != var_val_type)
    {
      ag_trace ("%s: invalid var_val_type: 0x%lx", __FUNCTION__,
                (long) var_val_type);
      return SNMP_ERR_WRONGTYPE;
    }

  if (var_val_len != IPV6_MAX_BYTELEN)
    {
      ag_trace ("%s: wrong param. len=%d != %d", __FUNCTION__,
                (int) var_val_len, IPV6_MAX_BYTELEN);
      return SNMP_ERR_WRONGLENGTH;
    }

  pal_mem_cpy (ip_addr, var_val, IPV6_MAX_BYTELEN);
  return SNMP_ERR_NOERROR;
}
#endif /* HAVE_IPV6 */

int
snmp_util_get_ostring_from_index (oid *name, int name_len,
                                  int wr_meth_snux_delta,
                                  int *offset,
                                  int olen, unsigned char *oval)
{
  register int iii;

  name += wr_meth_snux_delta;
  name_len -= wr_meth_snux_delta;

  if (*offset + olen > name_len)
    {
      return -1;
    }

  for (iii = 0; iii < olen; iii++)
    {
      oval[iii] = (unsigned char) name[iii + *offset];
    }

  *offset += olen;
  return 0;
}

int
snmp_util_get_int_from_index (oid * name, int name_len,
                              int wr_meth_snux_delta,
                              int *offset, long *int_val)
{
  name += wr_meth_snux_delta;
  name_len -= wr_meth_snux_delta;

  if (*offset >= name_len)
    {
      if (*offset > name_len)
        {
          ag_trace ("%s: %d=offset > name_len=%d",
                    __FUNCTION__, *offset, name_len);
        }
      return -1;
    }

  *int_val = name[(*offset)++];
  return 0;
}

int
snmp_util_set_ostring_to_index (oid *name, int *name_len,
                                int olen, unsigned char *oval)
{
  register int iii;

  for (iii = 0; iii < olen; iii++)
    {
      name[iii + *name_len] = (oid) oval[iii];
    }

  *name_len += olen;
  return 0;
}

int
snmp_util_set_int_to_index (oid * name, size_t * name_len,
                            long int_val)
{
  name[(*name_len)++] = int_val;
  return 0;
}

static struct lib_globals *dzg = NULL;

void
ag_trace (const char *format, ...)
{
#define AG_MAX_MSG_LEN  120
  char msg[AG_MAX_MSG_LEN];
  va_list args;

  /* create msg */
  va_start (args, format);
  pal_vsnprintf (msg, AG_MAX_MSG_LEN - 1, format, args);

  if (dzg)
    zlog_warn (dzg, "snmp: %s", msg);

  va_end (args);
}

int
write_dummy (int action,
             u_char * var_val,
             u_char var_val_type,
             size_t var_val_len, u_char * statP, oid * name, size_t name_len)
{
  return SNMP_ERR_NOERROR;
}

void
snmp_util_tracer_init (struct lib_globals *zg)
{
  dzg = zg;
}

const char *
_dbg_get_action_name (int action)
{
  switch (action)
    {
    case RESERVE1:
      return "RESERVE1";
    case RESERVE2:
      return "RESERVE2";
    case FREE_DEL:
      return "FREE";
    case ACTION:
      return "ACTION";
    case UNDO:
      return "UNDO";
    case COMMIT:
      return "COMMIT";
    default:
      return "Unknown";
    }
}

char *
_dbg_sprint_oid (oid * name, size_t length)
{
  static char c_oid[SPRINT_MAX_LEN];
  register size_t iii, cl;

  c_oid[0] = '\0';
  for (iii = 0; iii < length; iii++)
    {
      if (iii)
        pal_strcat (c_oid, ".");
      cl = pal_strlen (c_oid);
      if (cl > SPRINT_MAX_LEN - 16)
        {
          pal_strcat (c_oid, "..");
          break;
        }
      pal_snprintf (c_oid + cl, SPRINT_MAX_LEN,  "%d", (int) name[iii]);
    }
  return c_oid;
}

/*******************************************************************-o-******
 * generic_header
 *
 * Parameters:
 *        *vp      (I)     Pointer to variable entry that points here.
 *        *name    (I/O)   Input name requested, output name found.
 *        *length  (I/O)   Length of input and output oid's.
 *         exact   (I)     TRUE if an exact match was requested.
 *        *var_len (O)     Length of variable or 0 if function returned.
 *      (**write_method)   Hook to name a write method (UNUSED).
 *
 * Returns:
 *      MATCH_SUCCEEDED If vp->name matches name (accounting for exact bit).
 *      MATCH_FAILED    Otherwise,
 *
 *
 * Check whether variable (vp) matches name.
 */
int
snmp_utils_header_generic (struct variable *vp,
                           oid * name,
                           size_t * length,
                           int exact,
                           size_t * var_len, WriteMethod ** write_method)
{
  oid newname[MAX_OID_LEN];
  int result;

  pal_mem_cpy ((char *) newname, (char *) vp->name,
          (int) vp->namelen * sizeof (oid));
  newname[vp->namelen] = 0;
  result = oid_compare (name, *length, newname, vp->namelen + 1);
  if ((exact && (result != 0)) || (!exact && (result >= 0)))
    return (MATCH_FAILED);
  pal_mem_cpy ((char *) name, (char *) newname,
               ((int) vp->namelen + 1) * sizeof (oid));
  *length = vp->namelen + 1;

  *write_method = 0;
  *var_len = sizeof (long);     /* default to 'long' results */
  return (MATCH_SUCCEEDED);
}

#endif /* HAVE SNMP */
