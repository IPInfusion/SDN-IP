/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved. */

#include <pal.h>

#include "lib.h"
#include "table.h"
#include "memory.h"
#include "modbmap.h"
#include "thread.h"
#include "bgpsdn_version.h"
#include "snprintf.h"
#include "show.h"
#ifdef MEMMGR
#include "memmgr.h"
#endif /* MEMMGR */
#include "filter.h"
#include "log.h"
#ifdef HAVE_SNMP
#include "snmp.h"
#endif /* HAVE_SNMP */

#define MTYPE_IPI_VR            MTYPE_TMP /* XXX-VR */

#define IPI_MOTD_SIZE           100
#define IPI_COPYRIGHT_SIZE      80

extern void cli_tree_free (struct cli_tree *);


/* Default Message Of The Day. */
char *
ipi_motd_new (struct lib_globals *zg)
{
  char buf[IPI_COPYRIGHT_SIZE];
  char *motd;

  motd = XCALLOC (MTYPE_CONFIG_MOTD, IPI_MOTD_SIZE);
  if (motd == NULL)
    return NULL;

  /* Set the Message of The Day.  */
  zsnprintf (motd, IPI_MOTD_SIZE, "\r\nBGP-SDN%s",
             bgpsdn_copyright (buf, IPI_COPYRIGHT_SIZE));

  return motd;
}

void
ipi_motd_free (struct lib_globals *zg)
{
  XFREE (MTYPE_CONFIG_MOTD, zg->motd);
}

char *
ipi_cwd_new (struct lib_globals *zg)
{
  char buf[MAXPATHLEN];
  char *cwd;

  if (pal_getcwd (buf, MAXPATHLEN) != NULL)
    cwd = XSTRDUP (MTYPE_CONFIG, buf);
  else
    {
      cwd = XCALLOC (MTYPE_CONFIG, 2);
      if (cwd == NULL)
        return NULL;

      /* Set the separator.  */
      cwd[0] = PAL_FILE_SEPARATOR;
    }
  return cwd;
}

void
ipi_cwd_free (struct lib_globals *zg)
{
  XFREE (MTYPE_CONFIG, zg->cwd);
}


struct ipi_vr *
ipi_vr_new (void)
{
  struct ipi_vr *vr;

  vr = XCALLOC (MTYPE_IPI_VR, sizeof (struct ipi_vr));

  return vr;
}

void
ipi_vr_free (struct ipi_vr *vr)
{
  if (vr->name)
    XFREE (MTYPE_TMP, vr->name);

  if (vr->entLogical)
    {
      if (vr->entLogical->entLogicalCommunity)
        XFREE (MTYPE_COMMUNITY_STR, vr->entLogical->entLogicalCommunity);
      XFREE (MTYPE_TMP, vr->entLogical);
    }
  if (vr->mappedPhyEntList)
    list_delete (vr->mappedPhyEntList);

  THREAD_TIMER_OFF (vr->t_if_stat_threshold);

  XFREE (MTYPE_IPI_VR, vr);
}

void
ipi_vr_config_file_remove (struct ipi_vr *vr)
{
 char *path;
 char buf[MAXPATHLEN];

 if (vr->host == NULL)
   return;

 if (vr->name)
   {
     zsnprintf (buf, sizeof buf, "%s%c%s",
                vr->zg->cwd, PAL_FILE_SEPARATOR, vr->name);
     path = buf;
   }
 else
   {
     /* No VR Directory Path is found */
     return;
   }

  /* Delete the VR Config File */
  if (vr->host->config_file != NULL)
    pal_unlink (vr->host->config_file);

  /* Delete the VR Config Directory */
  if (path != NULL)
    pal_rmdir (path);
}

void
ipi_vr_delete (struct ipi_vr *vr)
{
  struct ipi_vr *pvr = ipi_vr_get_privileged (vr->zg);
  struct route_node *rn;
  struct interface *ifp;
  struct ipi_vrf *vrf, *vrf_next;

  /* Cleanup the interface.  */
  for (rn = route_top (vr->ifm.if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      {
        /* Bind the interfaces back to PVR if this VR is not the PVR.  */
        if (vr == pvr)
          if_vr_unbind (&vr->ifm, ifp->ifindex);
        else
          if_vr_bind (&pvr->ifm, ifp->ifindex);
      }

  for (vrf = vr->vrf_list; vrf; vrf = vrf_next)
    {
      vrf_next = vrf->next;
      ipi_vrf_delete (vrf);
    }

  vector_unset (vr->zg->vr_vec, vr->id);

  THREAD_OFF (vr->t_config);

  /* Finish the route-map.  */
  route_map_finish (vr);

  /* Finish the prefix-list.  */
  prefix_list_finish (vr);

  /* Finish the access-list.  */
  access_list_finish (vr);

  /* Remove the VR Directory, if present */
  if (CHECK_FLAG(vr->flags, LIB_FLAG_DELETE_VR_CONFIG_FILE))
    ipi_vr_config_file_remove (vr);

  /* Free the host.  */
  host_free (vr->host);

  /* Finish VR interface master.  */
  if_vr_master_finish (&vr->ifm, vr);

  /* Finish the VRF vector.  */
  vector_free (vr->vrf_vec);

  /* Free VR instance.  */
  ipi_vr_free (vr);
}

void
ipi_vr_delete_all (struct lib_globals *zg)
{
  struct ipi_vr *vr;
  int i;

  for (i = 0; i < vector_max (zg->vr_vec); i++)
    if ((vr = vector_slot (zg->vr_vec, i)))
      ipi_vr_delete (vr);
}

struct ipi_vr *
ipi_vr_get (struct lib_globals *zg)
{
  struct ipi_vr *vr;

  vr = ipi_vr_new ();
  vr->zg = zg;

  /* Create default VRF.  */
  vr->vrf_vec = vector_init (1);
  ipi_vrf_get_by_name (vr, NULL);

  /* Initialize Host. */
  vr->host = host_new (vr);

  /* Initialize VR interface master. */
  if_vr_master_init (&vr->ifm, vr);

  /* Initialize prefix lists. */
  vr->prefix_master_ipv4.seqnum = 1;
#ifdef HAVE_IPV6
  vr->prefix_master_ipv6.seqnum = 1;
#endif /* def HAVE_IPV6 */
  vr->prefix_master_orf.seqnum = 1;

  /* Initialize Route Map. */
  route_map_init (vr);

  /* Initialize SNMP Community */
  snmp_community_init (vr);

  /* Initialize access list master with AFI */
  vr->access_master_ipv4.afi = AFI_IP;
  vr->access_master_ipv4.max_count = ACCESS_LIST_ENTRY_MAX;
#ifdef HAVE_IPV6
  vr->access_master_ipv6.afi = AFI_IP6;
#endif /* def HAVE_IPV6 */

  return vr;
}

struct ipi_vr *
ipi_vr_get_by_id (struct lib_globals *zg, u_int32_t id)
{
  struct ipi_vr *vr;

  if (vector_max (zg->vr_vec) > id)
    {
      vr = vector_slot (zg->vr_vec, id);
      if (vr != NULL)
        return (struct ipi_vr *)vr;
    }

  vr = ipi_vr_get (zg);
  vr->id = vector_set_index (zg->vr_vec, id, vr);

  return vr;
}

struct ipi_vr *
ipi_vr_get_privileged (struct lib_globals *zg)
{
  return (struct ipi_vr *)vector_slot (zg->vr_vec, 0);
}

struct ipi_vr *
ipi_vr_lookup_by_id (struct lib_globals *zg, u_int32_t id)
{
  if (vector_max (zg->vr_vec) > id)
    return vector_slot (zg->vr_vec, id);

  return NULL;
}

struct ipi_vr *
ipi_vr_lookup_by_name (struct lib_globals *zg, char *name)
{
  struct ipi_vr *vr;
  int i;

  for (i = 0; i < vector_max (zg->vr_vec); i++)
    if ((vr = vector_slot (zg->vr_vec, i)))
      {
        if (name == NULL)
          {
            if (vr->name == NULL)
              return vr;
          }
        else
          {
            if (vr->name != NULL)
              if (pal_strcmp (vr->name, name) == 0)
                return vr;
          }
      }

  return NULL;
}

ZRESULT
ipi_vrs_walk_and_exec(struct lib_globals *zg,
                      IPI_VRS_WALK_CB func,
                      intptr_t user_ref)
{
  struct ipi_vr *vr;
  int i;
  ZRESULT res;

  if (zg==NULL || func==NULL)
    return ZRES_ERR;

  for (i = 0; i < vector_max (zg->vr_vec); i++)
    if ((vr = vector_slot (zg->vr_vec, i)) != NULL)
      if (func)
        if ((res = func(vr, user_ref)) != ZRES_OK)
          return res;

  return ZRES_OK;
}

void
ipi_vr_logical_entity_create (struct ipi_vr *vr)
{
  char community [255];

  pal_snprintf (community, sizeof (community), "public%d", vr->id);

  vr->entLogical = XMALLOC (MTYPE_TMP, sizeof (struct entLogicalEntry));
  if (! vr->entLogical)
    return;

  vr->entLogical->entLogicalIndex = vr->id;

  vr->entLogical->entLogicalDescr = "Virtual Router";
  vr->entLogical->entLogicalType = "MIB II";

  vr->entLogical->entLogicalCommunity = XMALLOC (MTYPE_COMMUNITY_STR,
                                                 sizeof (community));

  pal_strcpy (vr->entLogical->entLogicalCommunity, community);

  vr->entLogical->entLogicalTAddress = "161";
  vr->entLogical->entLogicalTDomain = "snmpUDPDomain";

  vr->entLogical->entLogicalContextEngineId = "";
  vr->entLogical->entLogicalContextName = "";
}

struct ipi_vr *
ipi_vr_get_by_name (struct lib_globals *zg, char *name)
{
  struct ipi_vr *vr;
  u_int32_t id;

  vr = ipi_vr_lookup_by_name (zg, name);
  if (vr != NULL)
    return vr;

  id = vector_empty_slot (zg->vr_vec);
  vr = ipi_vr_get_by_id (zg, id);
  if (name)
    vr->name = XSTRDUP (MTYPE_TMP, name);

  ipi_vr_logical_entity_create (vr);
  vr->mappedPhyEntList = list_new ();

  return vr;
}

struct ipi_vr *
ipi_vr_update_by_name (struct lib_globals *zg, char *name, u_int32_t vr_id)
{
  struct ipi_vr *vr = NULL, *vr_old = NULL;

  /* For default VR the name is NULL */
  vr = ipi_vr_lookup_by_name (zg, name);
  if (vr == NULL)
    return NULL;

  if (vr->id == vr_id)
    return vr;

  /* Delete the duplicated VR.  */
  vr_old = ipi_vr_lookup_by_id (zg, vr_id);
  if (vr_old != NULL)
    {
      /* Connection close callback.  */
      if (zg->vr_callback[VR_CALLBACK_CLOSE])
        (*zg->vr_callback[VR_CALLBACK_CLOSE]) (vr_old);

      /* Protocol callback. */
      if (zg->vr_callback[VR_CALLBACK_DELETE])
        (*zg->vr_callback[VR_CALLBACK_DELETE]) (vr_old);

      ipi_vr_delete (vr_old);
    }

  /* Update VR vector.  */
  vector_unset (zg->vr_vec, vr->id);
  vr->id = vector_set_index (zg->vr_vec, vr_id, vr);

  return vr;
}

void
ipi_vr_init (struct lib_globals *zg)
{
  /* Initialize VR vector.  */
  zg->vr_vec = vector_init (1);

  /* Initialize FIB to VRF map vector.  */
  zg->fib2vrf = vector_init (1);
}

void
ipi_vr_finish (struct lib_globals *zg)
{
  /* Delete all the VR.  */
  ipi_vr_delete_all (zg);

  /* Free the FIB to VRF map vector. */
  vector_free (zg->fib2vrf);

  /* Free the vector.  */
  vector_free (zg->vr_vec);
}


struct ipi_vrf *
ipi_vrf_new (void)
{
  struct ipi_vrf *vrf = NULL;

  vrf = XCALLOC (MTYPE_IPI_VRF, sizeof (struct ipi_vrf));

  return vrf;
}

void
ipi_vrf_free (struct ipi_vrf *vrf)
{
  if (vrf->name)
    XFREE (MTYPE_VRF_NAME, vrf->name);

  XFREE (MTYPE_IPI_VRF, vrf);
}

void
ipi_vrf_add_to_list (struct ipi_vr *vr, struct ipi_vrf *vrf)
{
  vrf->prev = vrf->next = NULL;
  if (vr->vrf_list)
    vr->vrf_list->prev = vrf;
  vrf->next = vr->vrf_list;
  vr->vrf_list = vrf;

  return;
}

void
ipi_vrf_delete_from_list (struct ipi_vr *vr, struct ipi_vrf *vrf)
{
  if (vrf->next)
    vrf->next->prev = vrf->prev;
  if (vrf->prev)
    vrf->prev->next = vrf->next;
  else
    vr->vrf_list = vrf->next;

  vrf->next = vrf->prev = NULL;

  return;
}

struct ipi_vrf *
ipi_vrf_get_by_name (struct ipi_vr *vr, char *name)
{
  struct ipi_vrf *vrf;

  vrf = ipi_vrf_lookup_by_name (vr, name);
  if (vrf == NULL)
    {
      vrf = ipi_vrf_new ();
      if (vrf  == NULL)
        return NULL;

      vrf->vr = vr;
      if (name != NULL)
        {
          vrf->name = XSTRDUP (MTYPE_VRF_NAME, name);
          if (vrf->name == NULL)    
            {
              XFREE (MTYPE_IPI_VRF, vrf);
              return NULL;
            }        
         }     

      /* Reset VRF and FIB IDs.  */
      vrf->id = VRF_ID_DISABLE;
      vrf->fib_id = FIB_ID_DISABLE;

      /* Enlist Into VRF-List */
      ipi_vrf_add_to_list (vr, vrf);

      /* Initialize VRF interface master. */
      if (if_vrf_master_init (&vrf->ifv, vrf) ==
                                       PAL_FALSE)
        return NULL;
    }

  return vrf;
}

void
ipi_vrf_delete (struct ipi_vrf *vrf)
{
  /* Unset from VRF2FIB vector.  */
  vector_unset (vrf->vr->zg->fib2vrf, vrf->fib_id);

  /* Unset from VRF vector.  */
  vector_unset (vrf->vr->vrf_vec, vrf->id);

  /* Delete from the list.  */
  ipi_vrf_delete_from_list (vrf->vr, vrf);

  /* Finish VRF interface master.  */
  if_vrf_master_finish (&vrf->ifv, vrf);

  /* Free VRF.  */
  ipi_vrf_free (vrf);
}

struct ipi_vrf *
ipi_vrf_lookup_by_name (struct ipi_vr *vr, char *name)
{
  struct ipi_vrf *vrf;

  if (vr == NULL)
    return NULL;

  for (vrf = vr->vrf_list; vrf; vrf = vrf->next)
    {
      if (vrf->name == NULL && name == NULL)
        return vrf;

      if (vrf->name != NULL && name != NULL)
        if (pal_strncmp (vrf->name, name, MAX_VRF_NAMELEN) == 0)
          return vrf;
    }

  return NULL;
}

struct ipi_vrf *
ipi_vrf_lookup_by_id (struct ipi_vr *vr, u_int32_t id)
{
  if (vector_max (vr->vrf_vec) > id)
    return (struct ipi_vrf *)vector_slot (vr->vrf_vec, id);

  return NULL;
}

struct ipi_vrf *
ipi_vrf_lookup_default (struct ipi_vr *vr)
{
  return ipi_vrf_lookup_by_id (vr, 0);
}

void
ipi_vr_add_callback (struct lib_globals *zg, enum vr_callback_type type,
                     int (*func) (struct ipi_vr *))
{
  if (type < 0 || type >= VR_CALLBACK_MAX)
    return;

  zg->vr_callback[type] = func;
}

void
ipi_vrf_add_callback (struct lib_globals *zg, enum vrf_callback_type type,
                     int (*func) (struct ipi_vrf *))
{
  if (type < 0 || type >= VRF_CALLBACK_MAX)
    return;

  zg->vrf_callback[type] = func;
}


struct lib_globals *
lib_clean (struct lib_globals *zg)
{
  if (!zg)
    return NULL;

  /* Stop the host configuration.  */
  HOST_CONFIG_STOP (zg);

  /* Finish the show server.  */
  if (zg->ss != NULL)
    show_server_finish (zg);

  /* Finish the interface master.  */
  if (zg->ifg.zg != NULL)
    if_master_finish (&zg->ifg);

  /* Finish the VR.  */
  if (zg->vr_vec != NULL)
    ipi_vr_finish (zg);

  /* Close the logger. */
  if (zg->log)
    closezlog (zg, zg->log);

  if (zg->log_default)
    closezlog (zg, zg->log_default);

  if (zg->motd != NULL)
    ipi_motd_free (zg);

  if (zg->cwd != NULL)
    ipi_cwd_free (zg);

  if (zg->pal_socket)
    pal_sock_stop (zg);

  if (zg->pal_stdlib)
    pal_stdlib_stop (zg);

  if (zg->pal_string)
    pal_strstop (zg);

  if (zg->pal_time)
    pal_time_stop (zg);

  if (zg->ctree)
    cli_tree_free (zg->ctree);

  pal_log_stop (zg);

  /* Free the thread master.  */
  if (zg->master != NULL)
    thread_master_finish (zg->master);

  /* Unset the lib globals in memory manager.  */
  memory_unset_lg ((void *)zg);

  XFREE (MTYPE_ZGLOB, zg);

  /* Finish the memory module.  */
  memory_finish ();

  return NULL;
}

struct lib_globals *
lib_create (char *progname)
{
  struct lib_globals *zg;
  int ret;

  /* Initialize Protocol Module Bitmaps. */
  modbmap_init_all ();

  zg = XCALLOC (MTYPE_ZGLOB, sizeof (struct lib_globals));
  if (zg == NULL)
    return NULL;

  /* Mark lib as not in shutdown */
  UNSET_LIB_IN_SHUTDOWN (zg);

  pal_strncpy(zg->progname, progname, LIB_MAX_PROG_NAME);

  /* PAL log.  */
  ret = pal_log_start (zg);
  if (ret != 0)
    return lib_clean (zg);

  /* PAL socket.  */
  zg->pal_socket = pal_sock_start (zg);
  if (!zg->pal_socket)
    return lib_clean (zg);

  /* PAL stdlib.  */
  zg->pal_stdlib = pal_stdlib_start (zg);
  if (!zg->pal_stdlib)
    return lib_clean (zg);

  /* PAL string.  */
  zg->pal_string = pal_strstart (zg);
  if (!zg->pal_string)
    return lib_clean (zg);

  /* PAL time.  */
  zg->pal_time = pal_time_start (zg);
  if (!zg->pal_time)
    return lib_clean (zg);

  /* Set the default MOTD.  */
  zg->motd = ipi_motd_new (zg);
  if (zg->motd == NULL)
    return lib_clean (zg);

  /* Get the current working directory.  */
  zg->cwd = ipi_cwd_new (zg);
  if (zg->cwd == NULL)
    return lib_clean (zg);

  zg->ctree = cli_tree_new ();
  if (zg->ctree == NULL)
    return lib_clean (zg);

  zg->pend_read_thread = NULL;

  zg->master = thread_master_create ();
  if (zg->master == NULL)
    return lib_clean (zg);

  /* Initialize default log. */
/*  zg->log_default = openzlog (zg, 0, zg->protocol, LOGDEST_DEFAULT); */

  /* Set the lib globals in memory manager */
  memory_set_lg ((void *)zg);

  /* Initialize the VR.  */
  ipi_vr_init (zg);

  /* Initialize Interface Master. */
  if_master_init (&zg->ifg, zg);

  return zg;
}

result_t
lib_start (struct lib_globals *zg)
{
  struct ipi_vr *vr;

#ifdef HAVE_SNMP
  snmp_make_tree (zg);

#ifdef HAVE_AGENTX
  agentx_initialize (&zg->snmp);
#endif /* HAVE_AGENTX */
#endif /* def HAVE_SNMP */

  /* Initialize PVR here. */
  vr = ipi_vr_get_by_id (zg, 0);

  LIB_GLOB_SET_VR_CONTEXT(zg, vr);

  return RESULT_OK;
}

/* Shut down the library and prepare for disuse.  */
result_t
lib_stop (struct lib_globals *zg)
{
  if (zg)
    {
      /* Mark lib in shutdown */
      SET_LIB_IN_SHUTDOWN (zg);

      /* Clean-up the global structures.  */
      if ((lib_clean (zg)) == NULL)
        zg = NULL;
    }

  return (RESULT_OK);
}

result_t
lib_set_context (struct lib_globals *zg,
                 struct ipi_vr *vr, struct ipi_vrf *vrf)
{
  if (! vr)
    vr = LIB_GLOB_GET_VR_CONTEXT (zg);

  if (! vrf)
    vrf = ipi_vrf_lookup_by_name (LIB_GLOB_GET_VR_CONTEXT (zg), NULL);

  if (! vr || ! vrf)
    return RESULT_ERROR;

  LIB_GLOB_SET_VR_CONTEXT (zg, vr);
  LIB_VR_SET_VRF_CONTEXT (vr, vrf);

  return RESULT_OK;
}

result_t
lib_set_context_by_ifp (struct lib_globals *zg, struct interface *ifp)
{
  return lib_set_context (zg, ifp->vr, ifp->vrf);
}

result_t
lib_set_context_by_id (struct lib_globals *zg,
                       u_int32_t vr_id, vrf_id_t vrf_id)
{
  struct ipi_vrf *vrf;
  struct ipi_vr *vr;

  vr = ipi_vr_lookup_by_id (zg, vr_id);
  if (! vr)
    return RESULT_ERROR;

  vrf = ipi_vrf_lookup_by_id (vr, vrf_id);
  if (! vrf)
    return RESULT_ERROR;

  return lib_set_context (zg, vr, vrf);
}

/* modname str */
char *
modname_strl (int index)
{
  switch (index)
    {
    case IPI_PROTO_UNSPEC:
      return "Unspec";
    case IPI_PROTO_BGP:
      return "BGP";
    case IPI_PROTO_MAX:
      return "Unknown";
    }
  return "Unknown";
}

/* modname str */
char *
modname_strs (int index)
{
  switch (index)
    {
    case IPI_PROTO_UNSPEC:
      return "unspec";
    case IPI_PROTO_BGP:
      return "bgpd";
    case IPI_PROTO_MAX:
      return "unknown";
    }
  return "unknown";
}

/* Protocol ID to route type. */
int
protoid2routetype (int proto_id)
{
  switch (proto_id)
    {
    case IPI_PROTO_BGP:
      return IPI_ROUTE_BGP;
    default:
      return -1;
    }

  return -1;
}
