/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#ifdef HAVE_SNMP

#include "snmp.h"
#ifdef HAVE_AGENTX
#include "agentx.h"
#else /* SMUX */
#include "smux.h"
#endif /* HAVE_AGENTX */
#include "thread.h"
#include "log.h"
#include "snprintf.h"
#include "linklist.h"
#include "bgpsdn_version.h"
#include "sockunion.h"
#include "asn1.h"


/*--------------------------------------------------------*
 *   SNMP : common functions                          *
 *--------------------------------------------------------*/

char snmp_progname[100];

void
snmp_progname_set ()
{
  char buf[50];

  zsnprintf (snmp_progname, 100, "bgpsdn-%s", bgpsdn_version (buf, 50));
}

void *
oid_copy (void *dest, void *src, size_t size)
{
  return pal_mem_cpy (dest, src, size * sizeof (oid));
}

void
oid2in_addr (oid oid[], s_int32_t len, struct pal_in4_addr *addr)
{
  s_int32_t i;
  u_int8_t *pnt;

  if (len == 0)
    return;

  pnt = (u_int8_t *) addr;

  for (i = 0; i < len; i++)
    *pnt++ = oid[i];
}

#ifdef HAVE_IPV6
void
oid2in6_addr (oid oid[], s_int32_t len, struct pal_in6_addr *addr)
{
  s_int32_t i;
  u_int8_t *pnt;

  if (len == 0)
    return;

  pnt = (u_int8_t *) addr;

  for (i = 0; i < len; i++)
    *pnt++ = oid[i];
}
#endif /* HAVE_IPV6 */

void
oid_copy_addr (oid oid[], struct pal_in4_addr *addr, s_int32_t len)
{
  s_int32_t i;
  u_int8_t *pnt;

  if (len == 0)
    return;

  pnt = (u_int8_t *) addr;

  for (i = 0; i < len; i++)
    oid[i] = *pnt++;
}

#ifdef HAVE_IPV6
void
oid_copy_in6_addr (oid oid[], struct pal_in6_addr *addr, s_int32_t len)
{
  s_int32_t i;
  u_int8_t *pnt;

  if (len == 0)
    return;

  pnt = (u_int8_t *) addr;

  for (i = 0; i < len; i++)
    oid[i] = *pnt++;
}
#endif /* HAVE_IPV6 */

s_int32_t
oid_compare (oid *o1, s_int32_t o1_len, oid *o2, s_int32_t o2_len)
{
  s_int32_t i;

  for (i = 0; i < MIN (o1_len, o2_len); i++)
    {
      if (o1[i] < o2[i])
        return -1;
      else if (o1[i] > o2[i])
        return 1;
    }
  if (o1_len < o2_len)
    return -1;
  if (o1_len > o2_len)
    return 1;

  return 0;
}

result_t
oid_compare_part (oid *o1, s_int32_t o1_len, oid *o2, s_int32_t o2_len)
{
  s_int32_t i;

  for (i = 0; i < MIN (o1_len, o2_len); i++)
    {
      if (o1[i] < o2[i])
        return -1;
      else if (o1[i] > o2[i])
        return 1;
    }
  if (o1_len < o2_len)
    return -1;

  return 0;
}


s_int32_t
snmp_header_generic (struct variable *v, oid *name, size_t *length,
                     s_int32_t exact, size_t *var_len,
                     WriteMethod **write_method)
{
  oid fulloid[MAX_OID_LEN];
  s_int32_t ret;

  oid_copy (fulloid, v->name, v->namelen);
  fulloid[v->namelen] = 0;
  /* Check against full instance. */
  ret = oid_compare (name, *length, fulloid, v->namelen + 1);

  /* Check single instance. */
  if ((exact && (ret != 0)) || (!exact && (ret >= 0)))
    return MATCH_FAILED;

  /* In case of getnext, fill in full instance. */
  pal_mem_cpy (name, fulloid, (v->namelen + 1) * sizeof (oid));
  *length = v->namelen + 1;

  *write_method = 0;
  *var_len = sizeof(long);    /* default to 'long' results */

  return MATCH_SUCCEEDED;
}


/* Snmp OID Dump */
void
snmp_oid_dump (struct lib_globals *zg, char *prefix,
               oid *oid, size_t oid_len)
{
  s_int32_t i;
  s_int32_t first = 1;
  int j; 
  char buf[MAX_OID_LEN * 3];
  int offset = 0;

  buf[0] = '\0';
  j = MAX_OID_LEN * 3;

  for (i = 0; i < oid_len; i++)
    {
      pal_snprintf (buf + offset, j - offset, 
                    "%s%2d", first ? "" : ".", (s_int32_t) oid[i]);
      if (first)
        offset += 2;
      else
        offset += 3;
      first = 0;
    }
  buf[offset] = '\0';
  zlog_info (zg, "%s: %s", prefix, buf);
}

/* Snmp HEXA Dump */
void
snmp_xdump (struct lib_globals *zg, char *prefix,
            u_char *ptr, size_t length)
{
  s_int32_t i = 0, col = 0, offset = 0;
  char buf[80]; 

  zlog_info (zg, "%s-XDUMP:", prefix);

  buf[0] = '\0';

  while (i < length)
    {
      pal_snprintf (buf + offset, 80 - offset, "%02x ", ptr[i]);
      offset += 3;
      i++;

      if (++col == 16)
        {
          buf[offset] = '\0';
          zlog_info (zg, "%s", buf);
          offset = 0;
          col = 0;
        }
    }
}


/* Compare function to keep treelist sorted */
s_int32_t
snmp_tree_cmp (struct subtree *tree1, struct subtree *tree2)
{
  return oid_compare (tree1->name, tree1->name_len,
                      tree2->name, tree2->name_len);
}

/*--------------------------------------------------------*
 *   SNMP : initialization                            *
 *--------------------------------------------------------*/

/* Init function for lib_globals. */
void
snmp_make_tree (struct lib_globals *zg)
{
  zg->snmp.sock = -1;

  /* Make MIB tree. */
  zg->snmp.treelist = list_new ();
  zg->snmp.treelist->cmp = (s_int32_t (*)(void *, void *))snmp_tree_cmp;
}

/* Init for protocol. */
void
snmp_init (struct lib_globals *zg, oid defoid[], size_t defoid_len)
{
  /* Set default Subagent oid. */
  zg->snmp.default_oid = defoid;
  zg->snmp.default_oid_len = defoid_len;

  zg->snmp.oid = zg->snmp.default_oid;
  zg->snmp.oid_len = zg->snmp.default_oid_len;

  /* Set program name. */
  snmp_progname_set ();

#ifndef HAVE_AGENTX
  /* Set default values related to SMUX : password and program name. */
  smux_initialize (zg);
#endif

  /* Install debugging cli */
  snmp_debug_cli_init (zg);
}

void
snmp_start (struct lib_globals *zg)
{
  /* Schedule first connection. */
#ifdef HAVE_AGENTX
  agentx_event (zg, AGENTX_SCHEDULE, 0);
#else
  smux_event (zg, SMUX_SCHEDULE, 0);
#endif
}

void
snmp_restart (struct lib_globals *zg)
{
  /* restarts the connection. */
#ifdef HAVE_AGENTX
  if (zg->snmp.fail >= AGENTX_MAX_FAILURE)
    zg->snmp.fail = 0;
  agentx_event (zg, AGENTX_RESTART, 0);
#else
  if (zg->snmp.fail >= SMUX_MAX_FAILURE)
    zg->snmp.fail = 0;
  smux_event (zg, SMUX_RESTART, 0);
#endif
}

void
snmp_stop (struct lib_globals *zg)
{
  /* closes the connection. */
#ifdef HAVE_AGENTX
  agentx_event (zg, AGENTX_STOP, 0);
#else
  smux_event (zg, SMUX_STOP, 0);
#endif
}

void
snmp_debug_init (struct lib_globals *zg)
{
  zg->snmp.debug = 0;
}

void
snmp_debug_set (struct lib_globals *zg)
{
  zg->snmp.debug = SUBAG_DEBUG_MASK;
}

CLI (show_debugging_snmp,
     show_debugging_snmp_cli,
     "show debugging snmp",
     CLI_SHOW_STR,
     "Debugging information outputs",
     "Snmp (AgentX or SMUX)")
{
  struct lib_globals *zg = cli->zg;
#ifdef HAVE_AGENTX
  struct snmp_master *snmpm = SNMP_MASTER (zg);
#endif /* HAVE_AGENTX */

#ifdef HAVE_AGENTX
  cli_out (cli, "Snmp (AgentX: %s state, sock %d) debugging status:\n",
           agentx_statestr (snmpm->Agx_state), zg->snmp.sock);
  if (IS_SUBAG_DEBUG_SEND &&
      IS_SUBAG_DEBUG_RECV)
    {
      if (IS_SUBAG_DEBUG_PROCESS &&
          IS_SUBAG_DEBUG_LIBERR &&
          IS_SUBAG_DEBUG_XDUMP &&
          IS_SUBAG_DEBUG_DETAIL) {
        cli_out (cli, "  Snmp all debugging is on\n");
      } else {
        cli_out (cli, "  Snmp packet send/receive debugging is on\n");
        if (IS_SUBAG_DEBUG_PROCESS)
          cli_out (cli, "  Snmp packet process debugging is on\n");
        if (IS_SUBAG_DEBUG_XDUMP)
          cli_out (cli, "  Snmp packet hexa dump debugging is on\n");
        if (IS_SUBAG_DEBUG_DETAIL)
          cli_out (cli, "  Snmp detail debugging is on\n");
        if (IS_SUBAG_DEBUG_LIBERR)
          cli_out (cli, "  Snmp error string debugging is on\n");
      }
    }
  else
    {
      if (IS_SUBAG_DEBUG_SEND)
        cli_out (cli, "  Snmp packet send debugging is on\n");
      if (IS_SUBAG_DEBUG_RECV)
        cli_out (cli, "  Snmp packet receive debugging is on\n");
      if (IS_SUBAG_DEBUG_PROCESS)
        cli_out (cli, "  Snmp packet process debugging is on\n");
      if (IS_SUBAG_DEBUG_XDUMP)
        cli_out (cli, "  Snmp packet hexa dump debugging is on\n");
      if (IS_SUBAG_DEBUG_DETAIL)
        cli_out (cli, "  Snmp detail debugging is on\n");
      if (IS_SUBAG_DEBUG_LIBERR)
        cli_out (cli, "  Snmp error string debugging is on\n");
    }
#else /* SMUX */
  cli_out (cli, "Snmp (SMUX) debugging status:\n");
  if (IS_SUBAG_DEBUG_SEND &&
      IS_SUBAG_DEBUG_RECV)
    {
      cli_out (cli, "  Snmp debugging is on\n");
    }
#endif /* HAVE_AGENTX */

  if (zg->snmp.debug == 0)
    cli_out (cli, "  Snmp debugging is off\n");
  return CLI_SUCCESS;
}

#define SUBAG_DEBUG_ON(a) (zg->snmp.debug |= SUBAG_DEBUG_ ## a)
#define SUBAG_DEBUG_OFF(a) \
        (zg->snmp.debug &= ~(SUBAG_DEBUG_ ## a))

CLI (debug_snmp,
     debug_snmp_cli,
     "debug snmp",
     CLI_DEBUG_STR,
     "SNMP  (AgentX or SMUX)")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_ON (SEND);
  SUBAG_DEBUG_ON (RECV);
  return CLI_SUCCESS;
}

CLI (no_debug_snmp,
     no_debug_snmp_cli,
     "no debug snmp",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_OFF (SEND);
  SUBAG_DEBUG_OFF (RECV);
  SUBAG_DEBUG_OFF (PROCESS);
  SUBAG_DEBUG_OFF (XDUMP);
  SUBAG_DEBUG_OFF (DETAIL);
  SUBAG_DEBUG_OFF (LIBERR);
  return CLI_SUCCESS;
}

#ifdef HAVE_AGENTX
CLI (debug_snmp_all,
     debug_snmp_all_cli,
     "debug snmp all",
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)",
     "all debugging (included hexa-dump and error-string)")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_ON (SEND);
  SUBAG_DEBUG_ON (RECV);
  SUBAG_DEBUG_ON (PROCESS);
  SUBAG_DEBUG_ON (XDUMP);
  SUBAG_DEBUG_ON (DETAIL);
  SUBAG_DEBUG_ON (LIBERR);
  return CLI_SUCCESS;
}

CLI (debug_snmp_send,
     debug_snmp_send_cli,
     "debug snmp send",
     CLI_DEBUG_STR,
     "SNMP  (AgentX or SMUX)",
     "Packet send")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_ON (SEND);
  return CLI_SUCCESS;
}

CLI (debug_snmp_recv,
     debug_snmp_recv_cli,
     "debug snmp receive",
     CLI_DEBUG_STR,
     "SNMP  (AgentX or SMUX)",
     "Packet receive")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_ON (RECV);
  return CLI_SUCCESS;
}

CLI (debug_snmp_process,
     debug_snmp_process_cli,
     "debug snmp process",
     CLI_DEBUG_STR,
     "SNMP  (AgentX or SMUX)",
     "Packet process")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_ON (PROCESS);
  return CLI_SUCCESS;
}

CLI (debug_snmp_xdump,
     debug_snmp_xdump_cli,
     "debug snmp xdump",
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)",
     "Packet hexa dump")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_ON (XDUMP);
  return CLI_SUCCESS;
}

CLI (debug_snmp_detail,
     debug_snmp_detail_cli,
     "debug snmp detail",
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)",
     "Detail debugging")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_ON (DETAIL);
  return CLI_SUCCESS;
}

CLI (debug_snmp_err_str,
     debug_snmp_err_str_cli,
     "debug snmp error-string",
     CLI_DEBUG_STR,
     "SNMP  (AgentX or SMUX)",
     "Error string display")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_ON (LIBERR);
  return CLI_SUCCESS;
}

CLI (no_debug_snmp_all,
     no_debug_snmp_all_cli,
     "no debug snmp all",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)",
     "all debugging (included hexa-dump and error-string)")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_OFF (SEND);
  SUBAG_DEBUG_OFF (RECV);
  SUBAG_DEBUG_OFF (PROCESS);
  SUBAG_DEBUG_OFF (XDUMP);
  SUBAG_DEBUG_OFF (DETAIL);
  SUBAG_DEBUG_OFF (LIBERR);
  return CLI_SUCCESS;
}

CLI (no_debug_snmp_send,
     no_debug_snmp_send_cli,
     "no debug snmp send",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)",
     "Packet send")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_OFF (SEND);
  return CLI_SUCCESS;
}

CLI (no_debug_snmp_recv,
     no_debug_snmp_recv_cli,
     "no debug snmp receive",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)",
     "Packet receive")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_OFF (RECV);
  return CLI_SUCCESS;
}

CLI (no_debug_snmp_process,
     no_debug_snmp_process_cli,
     "no debug snmp process",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)",
     "Packet process")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_OFF (PROCESS);
  return CLI_SUCCESS;
}

CLI (no_debug_snmp_xdump,
     no_debug_snmp_xdump_cli,
     "no debug snmp xdump",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)",
     "Packet hexa dump")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_OFF (XDUMP);
  return CLI_SUCCESS;
}

CLI (no_debug_snmp_detail,
     no_debug_snmp_detail_cli,
     "no debug snmp detail",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)",
     "Detail debugging")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_OFF (DETAIL);
  return CLI_SUCCESS;
}

CLI (no_debug_snmp_err_str,
     no_debug_snmp_err_str_cli,
     "no debug snmp error-string",
     CLI_NO_STR,
     CLI_DEBUG_STR,
     "SNMP (AgentX or SMUX)",
     "Error string display")
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_OFF (LIBERR);
  return CLI_SUCCESS;
}
#endif /* HAVE_AGENTX */

void snmp_debug_all_off(struct cli *cli)
{
  struct lib_globals *zg = cli->zg;

  SUBAG_DEBUG_OFF (SEND);
  SUBAG_DEBUG_OFF (RECV);
  SUBAG_DEBUG_OFF (PROCESS);
  SUBAG_DEBUG_OFF (XDUMP);
  SUBAG_DEBUG_OFF (DETAIL);
  SUBAG_DEBUG_OFF (LIBERR);
}

void
snmp_debug_cli_init (struct lib_globals *zg)
{
  struct cli_tree *ctree = zg->ctree;

  /* cli_install_config (ctree, DEBUG_SNMP_MODE, config_write_snmp_debug); */

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &show_debugging_snmp_cli);

  /* snmp debug flags */
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &debug_snmp_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &no_debug_snmp_cli);
#ifdef HAVE_AGENTX
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &debug_snmp_all_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &debug_snmp_send_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &debug_snmp_recv_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &debug_snmp_process_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &debug_snmp_xdump_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &debug_snmp_detail_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &debug_snmp_err_str_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &no_debug_snmp_all_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &no_debug_snmp_send_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &no_debug_snmp_recv_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &no_debug_snmp_process_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &no_debug_snmp_xdump_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &no_debug_snmp_detail_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_MAX, 0,
                   &no_debug_snmp_err_str_cli);
#endif /* HAVE_AGENTX */
}
#endif  /* HAVE_SNMP */
