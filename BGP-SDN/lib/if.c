/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#include "lib.h"
#include "if.h"
#include "prefix.h"
#include "table.h"
#include "log.h"
#include "snprintf.h"
#include "hash.h"

#define IFC_IPV4_CMP(A,B)                                               \
  (pal_ntoh32 ((A)->s_addr) < pal_ntoh32 ((B)->s_addr) ? -1 :           \
   (pal_ntoh32 ((A)->s_addr) > pal_ntoh32 ((B)->s_addr) ? 1 : 0))

#define IFC_IPV6_CMP(A,B)                                               \
  (*((u_char *)(A) + 0) < *((u_char *)(B) + 0) ? -1 :                   \
   (*((u_char *)(A) + 0) > *((u_char *)(B) + 0) ?  1 :                  \
    (*((u_char *)(A) + 1) < *((u_char *)(B) + 1) ? -1 :                 \
     (*((u_char *)(A) + 1) > *((u_char *)(B) + 1) ?  1 :                \
      (*((u_char *)(A) + 2) < *((u_char *)(B) + 2) ? -1 :               \
       (*((u_char *)(A) + 2) > *((u_char *)(B) + 2) ?  1 :              \
        (*((u_char *)(A) + 3) < *((u_char *)(B) + 3) ? -1 :             \
         (*((u_char *)(A) + 3) > *((u_char *)(B) + 3) ?  1 :            \
          (*((u_char *)(A) + 4) < *((u_char *)(B) + 4) ? -1 :           \
           (*((u_char *)(A) + 4) > *((u_char *)(B) + 4) ?  1 :          \
            (*((u_char *)(A) + 5) < *((u_char *)(B) + 5) ? -1 :         \
             (*((u_char *)(A) + 5) > *((u_char *)(B) + 5) ?  1 :        \
              (*((u_char *)(A) + 6) < *((u_char *)(B) + 6) ? -1 :       \
               (*((u_char *)(A) + 6) > *((u_char *)(B) + 6) ?  1 :      \
                (*((u_char *)(A) + 7) < *((u_char *)(B) + 7) ? -1 :     \
                 (*((u_char *)(A) + 7) > *((u_char *)(B) + 7) ?  1 :    \
                  (*((u_char *)(A) + 8) < *((u_char *)(B) + 8) ? -1 :   \
                   (*((u_char *)(A) + 8) > *((u_char *)(B) + 8) ?  1 :  \
                    (*((u_char *)(A) + 9) < *((u_char *)(B) + 9) ? -1 : \
                     (*((u_char *)(A) + 9) > *((u_char *)(B) + 9) ?  1 : \
                      (*((u_char *)(A) + 10) < *((u_char *)(B) + 10) ? -1 : \
                       (*((u_char *)(A) + 10) > *((u_char *)(B) + 10) ?  1 : \
                        (*((u_char *)(A) + 11) < *((u_char *)(B) + 11) ? -1 : \
                         (*((u_char *)(A) + 11) > *((u_char *)(B) + 11) ?  1 : \
                          (*((u_char *)(A) + 12) < *((u_char *)(B) + 12) ? -1 : \
                           (*((u_char *)(A) + 12) > *((u_char *)(B) + 12) ?  1 : \
                            (*((u_char *)(A) + 13) < *((u_char *)(B) + 13) ? -1 : \
                             (*((u_char *)(A) + 13) > *((u_char *)(B) + 13) ?  1 : \
                              (*((u_char *)(A) + 14) < *((u_char *)(B) + 14) ? -1 : \
                               (*((u_char *)(A) + 14) > *((u_char *)(B) + 14) ?  1 : \
                                (*((u_char *)(A) + 15) < *((u_char *)(B) + 15) ? -1 : \
                                 (*((u_char *)(A) + 15) > *((u_char *)(B) + 15) ?  1 : \
                                  0))))))))))))))))))))))))))))))))

#ifdef HAVE_L3
static void ifc_delete_all (struct lib_globals *zg, struct interface *);
#endif /* HAVE_L3 */


/* VR Interface Master. */
void
if_vr_master_init (struct if_vr_master *ifm, struct ipi_vr *vr)
{
  pal_mem_set (ifm, 0, sizeof (struct if_vr_master));

  ifm->vr = vr;
  ifm->if_table = route_table_init ();
  ifm->if_list = list_new ();
}

void
if_vr_master_finish (struct if_vr_master *ifm, struct ipi_vr *vr)
{
  route_table_finish (ifm->if_table);

  list_free (ifm->if_list);
}

int
if_vr_bind (struct if_vr_master *ifm, int ifindex)
{
  struct ipi_vr *vr = ifm->vr;
  struct if_master *ifg = &vr->zg->ifg;
  struct ipi_vrf *vrf;
  struct interface *ifp;
  struct prefix_if p;
  struct route_node *rn;
  int ret = 0;

  PREFIX_IF_SET (&p, ifindex);

  rn = route_node_get (ifm->if_table, (struct prefix *)&p);
  if (rn->info == NULL)
    {
      ifp = ifg_lookup_by_index (ifg, ifindex);
      if (ifp != NULL)
        {
          /* Unbind the interface from the previous VR.  */
          if (ifp->vr != NULL)
            if_vr_unbind (&ifp->vr->ifm, ifp->ifindex);

          RN_IF_INFO_SET (rn, ifp);
          listnode_add_sort (ifm->if_list, ifp);
          ifp->vr = vr;

          if (vr->zg->vr_callback[VR_CALLBACK_ADD] == NULL || vr->proto)
            if (LIB_CALLBACK_VERIFY (vr->zg, ifg,
                                     if_callback, IF_CALLBACK_VR_BIND))
              (*ifg->if_callback[IF_CALLBACK_VR_BIND]) (ifp);

          /* Bind default VRF here. */
          vrf = ipi_vrf_lookup_default (ifp->vr);
          if (vrf != NULL)
            if_vrf_bind (&vrf->ifv, ifp->ifindex);

          ret = 1;
        }
    }
  route_unlock_node (rn);
  return ret;
}

int
if_vr_unbind (struct if_vr_master *ifm, int ifindex)
{
  struct ipi_vr *vr = ifm->vr;
  struct if_master *ifg = &vr->zg->ifg;
  struct prefix_if p;
  struct route_node *rn;
  struct interface *ifp;

  PREFIX_IF_SET (&p, ifindex);

  rn = route_node_lookup (ifm->if_table, (struct prefix *)&p);
  if (rn)
    {
      ifp = rn->info;

      if (ifp->vrf)
        if_vrf_unbind (&ifp->vrf->ifv, ifp->ifindex);

      if (vr->zg->vr_callback[VR_CALLBACK_DELETE] == NULL || vr->proto)
        if (LIB_CALLBACK_VERIFY (vr->zg, ifg,
                                 if_callback, IF_CALLBACK_VR_UNBIND))
          (*ifg->if_callback[IF_CALLBACK_VR_UNBIND]) (ifp);

      listnode_delete (ifm->if_list, ifp);
      RN_IF_INFO_UNSET (rn);
      route_unlock_node (rn);
      ifp->vr = NULL;

#ifdef HAVE_L3
      ifc_delete_all (ifg->zg, ifp);
#endif /* HAVE_L3 */

      return 1;
    }
  return 0;
}

struct interface *
if_lookup_by_name (struct if_vr_master *ifm, char *name)
{
  struct interface *ifp;
  struct listnode *node;

  LIST_LOOP (ifm->if_list, ifp, node)
    if (pal_strcmp (ifp->name, name) == 0)
      return ifp;

  return NULL;
}

struct interface *
if_lookup_by_index (struct if_vr_master *ifm, u_int32_t ifindex)
{
  struct prefix_if p;
  struct route_node *rn;

  PREFIX_IF_SET (&p, ifindex);

  rn = route_node_lookup (ifm->if_table, (struct prefix *)&p);
  if (rn)
    {
      route_unlock_node (rn);
      return rn->info;
    }
  return NULL;
}

bool_t
if_vrf_master_init (struct if_vrf_master *ifv, struct ipi_vrf *vrf)
{
  pal_mem_set (ifv, 0, sizeof (struct if_vrf_master));

  ifv->vrf = vrf;
  ifv->if_table = route_table_init ();
  ifv->ipv4_table = route_table_init ();
  if (ifv->if_table == NULL || ifv->ipv4_table == NULL)
    return PAL_FALSE;
#ifdef HAVE_IPV6
  ifv->ipv6_table = route_table_init ();
  if (ifv->ipv6_table == NULL)
    return PAL_FALSE;
#endif /* HAVE_IPV6 */
  return PAL_TRUE;
}

void
if_vrf_master_finish (struct if_vrf_master *ifv, struct ipi_vrf *vrf)
{
  route_table_finish (ifv->ipv4_table);
#ifdef HAVE_IPV6
  route_table_finish (ifv->ipv6_table);
#endif /* HAVE_IPV6 */
  route_table_finish (ifv->if_table);
}

int
if_vrf_bind (struct if_vrf_master *ifv, int ifindex)
{
  struct ipi_vr *vr = ifv->vrf->vr;
  struct if_master *ifg = &vr->zg->ifg;
  struct interface *ifp;
  struct prefix_if p;
  struct route_node *rn;
  int ret = 0;

  PREFIX_IF_SET (&p, ifindex);

  rn = route_node_get (ifv->if_table, (struct prefix *)&p);
  if (rn->info == NULL)
    {
      ifp = if_lookup_by_index (&ifv->vrf->vr->ifm, ifindex);
      if (ifp != NULL)
        {
          /* Unbind the interface from the previous VRF */
          if (ifp->vrf != NULL)
            if_vrf_unbind (&ifp->vrf->ifv, ifp->ifindex);

          RN_IF_INFO_SET (rn, ifp);
          ifp->vrf = ifv->vrf;

          if (vr->zg->vrf_callback[VRF_CALLBACK_ADD] == NULL || ifv->vrf->proto)
            if (LIB_CALLBACK_VERIFY (vr->zg, ifg, if_callback,
                                     IF_CALLBACK_VRF_BIND))
              (*ifg->if_callback[IF_CALLBACK_VRF_BIND]) (ifp);

          ret = 1;

        }
    }
  route_unlock_node (rn);
  return ret;
}

int
if_vrf_unbind (struct if_vrf_master *ifv, int ifindex)
{
  struct ipi_vr *vr = ifv->vrf->vr;
  struct if_master *ifg = &vr->zg->ifg;
  struct prefix_if p;
  struct route_node *rn;
  struct interface *ifp;

  PREFIX_IF_SET (&p, ifindex);

  rn = route_node_lookup (ifv->if_table, (struct prefix *)&p);
  if (rn)
    {
      ifp = rn->info;

      if (vr->zg->vr_callback[VR_CALLBACK_DELETE] == NULL || ifv->vrf->proto)
        if (LIB_CALLBACK_VERIFY (vr->zg, ifg,
                                 if_callback, IF_CALLBACK_VRF_UNBIND))
          (*ifg->if_callback[IF_CALLBACK_VRF_UNBIND]) (ifp);

      RN_IF_INFO_UNSET (rn);
      route_unlock_node (rn);
      ifp->vrf = NULL;

      return 1;
    }
  return 0;
}

struct interface *
ifv_lookup_by_name (struct if_vrf_master *ifv, char *name)
{
  struct interface *ifp;
  struct route_node *rn;

  if (! name)
    return NULL;

  for (rn = route_top (ifv->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      if (pal_strcmp (ifp->name, name) == 0)
        {
          route_unlock_node (rn);
          return ifp;
        }

  return NULL;
}

struct interface *
ifv_lookup_by_index (struct if_vrf_master *ifv, u_int32_t ifindex)
{
  struct prefix_if p;
  struct route_node *rn;

  PREFIX_IF_SET (&p, ifindex);

  rn = route_node_lookup (ifv->if_table, (struct prefix *)&p);
  if (rn)
    {
      route_unlock_node (rn);
      return rn->info;
    }
  return NULL;
}

struct interface *
ifv_lookup_next_by_index (struct if_vrf_master *ifv, u_int32_t ifindex)
{
  struct prefix_if p;
  struct route_node *rn;
  struct interface *ifp;

  PREFIX_IF_SET (&p, ifindex);
  rn = NULL;
  ifp = NULL;

  if (ifindex)
    {
      rn = route_node_lookup (ifv->if_table, (struct prefix *)&p);
      if (rn)
        rn = route_next (rn);
    }
  else
    rn = route_top (ifv->if_table);

  for (ifp = NULL; rn; rn = route_next (rn))
    {
      if ((ifp = (rn->info)))
        break;
    }

  return ifp;
}


/* Connected. */
struct connected *
ifc_new (u_char family)
{
  struct connected *ifc;

  ifc = XCALLOC (MTYPE_CONNECTED, sizeof (struct connected));
  ifc->family = family;

  return ifc;
}

#ifdef HAVE_L3
struct connected *
ifc_get_ipv4 (struct pal_in4_addr *addr, u_char prefixlen,
              struct interface *ifp)
{
  struct connected *ifc;
  struct prefix_ipv4 *p;

  ifc = ifc_new (AF_INET);
  if (ifc != NULL)
    {
      ifc->ifp = ifp;

      p = prefix_ipv4_new ();
      p->family = AF_INET;
      p->prefix = *addr;
      p->prefixlen = prefixlen;
      ifc->address = (struct prefix *)p;

    }

  return ifc;
}

#endif /* HAVE_L3 */

#ifdef HAVE_IPV6
struct connected *
ifc_get_ipv6 (struct pal_in6_addr *addr, u_char prefixlen,
              struct interface *ifp)
{
  struct connected *ifc;
  struct prefix_ipv6 *p;

  ifc = ifc_new (AF_INET6);
  if (ifc != NULL)
    {
      ifc->ifp = ifp;

      p = prefix_ipv6_new ();
      p->family = AF_INET6;
      p->prefix = *addr;
      p->prefixlen = prefixlen;
      ifc->address = (struct prefix *)p;

    }

  return ifc;
}
#endif /* HAVE_IPV6 */

#ifdef HAVE_L3
void
ifc_free (struct lib_globals *zg, struct connected *ifc)
{
  if (ifc->family == AF_INET)
    {
      if (ifc->address)
        prefix_ipv4_free (ifc->address);
      if (ifc->destination)
        prefix_ipv4_free (ifc->destination);
    }
#ifdef HAVE_IPV6
  else if (ifc->family == AF_INET6)
    {
      if (ifc->address)
        prefix_ipv6_free (ifc->address);
      if (ifc->destination)
        prefix_ipv6_free (ifc->destination);
    }
#endif /* HAVE_IPV6 */
  else
    {
      if (ifc->address)
        prefix_free (ifc->address);
      if (ifc->destination)
        prefix_free (ifc->destination);
    }

  PAL_UNREFERENCED_PARAMETER (zg);

  XFREE (MTYPE_CONNECTED, ifc);
}

static void
ifc_delete_all (struct lib_globals *zg, struct interface *ifp)
{
  struct connected *ifc, *next;

  for (ifc = ifp->ifc_ipv4; ifc; ifc = next)
    {
      next = ifc->next;
      ifc_free (zg, ifc);
    }
  ifp->ifc_ipv4 = NULL;
#ifdef HAVE_IPV6
  for (ifc = ifp->ifc_ipv6; ifc; ifc = next)
    {
      next = ifc->next;
      ifc_free (zg, ifc);
    }
  ifp->ifc_ipv6 = NULL;
#endif /* HAVE_IPV6 */
}
#endif /* HAVE_L3 */

u_int32_t
if_ifc_ipv4_count (struct interface *ifp)
{
  struct connected *ifc;
  u_int32_t count = 0;

  for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)
    count++;

  return count;
}

void
if_add_ifc_ipv4 (struct interface *ifp, struct connected *ifc)
{
  struct connected *pp, *cp;
  struct pal_in4_addr *a, *b;
  int ret;

  a = &ifc->address->u.prefix4;

  for (pp = NULL, cp = ifp->ifc_ipv4; cp; pp = cp, cp = cp->next)
    {
      b = &cp->address->u.prefix4;
      ret = IFC_IPV4_CMP (a, b);
      if (ret < 0)
        break;
    }

  if (pp)
    pp->next = ifc;
  else
    ifp->ifc_ipv4 = ifc;

  if (cp)
    cp->prev = ifc;

  ifc->prev = pp;
  ifc->next = cp;
}

void
if_delete_ifc_ipv4 (struct interface *ifp, struct connected *ifc)
{
  if (ifc->next)
    ifc->next->prev = ifc->prev;
  if (ifc->prev)
    ifc->prev->next = ifc->next;
  else
    ifp->ifc_ipv4 = ifc->next;
}

struct connected *
if_lookup_ifc_ipv4 (struct interface *ifp, struct pal_in4_addr *addr)
{
  struct connected *ifc;
  struct prefix *p;

  for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)
    if ((p = ifc->address))
      if ((IFC_IPV4_CMP (&p->u.prefix4, addr)) == 0)
        return ifc;

  return NULL;
}

struct connected *
if_lookup_ifc_prefix (struct interface *ifp, struct prefix *p)
{
  struct connected *ifc;
  struct prefix *q;

  if (p->family == AF_INET)
    {
      for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)
        if ((q = ifc->address))
          if (prefix_same (q, p))
            return ifc;
    }
#ifdef HAVE_IPV6
  else if (p->family == AF_INET6)
    {
      for (ifc = ifp->ifc_ipv6; ifc; ifc = ifc->next)
        if ((q = ifc->address))
          if (prefix_same (q, p))
            return ifc;
    }
#endif /* HAVE_IPV6 */

  return NULL;
}

/* Check if given prefix matched direct connected network. */
struct connected *
if_match_ifc_ipv4_direct (struct interface *ifp, struct prefix *p)
{
  struct connected *ifc;
  struct prefix q;

  for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)
    {
      if (ifc->address)
        {
          prefix_copy (&q, ifc->address);
          apply_mask (&q);
          if (prefix_match (&q, p))
            return ifc;
        }

      if (ifc->destination)
        {
          prefix_copy (&q, ifc->destination);
          apply_mask (&q);
          if (prefix_match (&q, p))
            return ifc;
        }
    }

  return NULL;
}

void
if_delete_ifc_by_ipv4_addr (struct interface *ifp, struct pal_in4_addr *addr)
{
  struct connected *ifc;

  ifc = if_lookup_ifc_ipv4 (ifp, addr);
  if (ifc != NULL)
    if_delete_ifc_ipv4 (ifp, ifc);
}

#ifdef HAVE_IPV6
u_int32_t
if_ifc_ipv6_count (struct interface *ifp)
{
  struct connected *ifc;
  u_int32_t count = 0;

  for (ifc = ifp->ifc_ipv6; ifc; ifc = ifc->next)
    count++;

  return count;
}

void
if_add_ifc_ipv6 (struct interface *ifp, struct connected *ifc)
{
  struct connected *pp, *cp;
  struct pal_in6_addr *a, *b;
  int ret;

  a = &ifc->address->u.prefix6;

  for (pp = NULL, cp = ifp->ifc_ipv6; cp; pp = cp, cp = cp->next)
    {
      b = &cp->address->u.prefix6;
      ret = IFC_IPV6_CMP (a, b);
      if (ret < 0)
        break;
    }

  if (pp)
    pp->next = ifc;
  else
    ifp->ifc_ipv6 = ifc;

  if (cp)
    cp->prev = ifc;

  ifc->prev = pp;
  ifc->next = cp;
}

void
if_delete_ifc_ipv6 (struct interface *ifp, struct connected *ifc)
{
  if (ifc->next)
    ifc->next->prev = ifc->prev;
  if (ifc->prev)
    ifc->prev->next = ifc->next;
  else
    ifp->ifc_ipv6 = ifc->next;
}

struct connected *
if_lookup_ifc_ipv6 (struct interface *ifp, struct pal_in6_addr *addr)
{
  struct connected *ifc;
  struct prefix *p;

  for (ifc = ifp->ifc_ipv6; ifc; ifc = ifc->next)
    if ((p = ifc->address))
      if ((IFC_IPV6_CMP (&p->u.prefix6, addr)) == 0)
        return ifc;

  return NULL;
}

struct connected *
if_lookup_ifc_ipv6_linklocal (struct interface *ifp)
{
  struct connected *ifc;

  for (ifc = ifp->ifc_ipv6; ifc; ifc = ifc->next)
    if (IN6_IS_ADDR_LINKLOCAL (&ifc->address->u.prefix6))
      return ifc;

  return NULL;
}

struct connected *
if_lookup_ifc_ipv6_global (struct interface *ifp)
{
  struct connected *ifc;

  for (ifc = ifp->ifc_ipv6; ifc; ifc = ifc->next)
    if (!IN6_IS_ADDR_LINKLOCAL (&ifc->address->u.prefix6)
        && !IN6_IS_ADDR_LOOPBACK (&ifc->address->u.prefix6)
        && !IN6_IS_ADDR_UNSPECIFIED (&ifc->address->u.prefix6))
      return ifc;

  return NULL;
}

void
if_delete_ifc_by_ipv6_addr (struct interface *ifp, struct pal_in6_addr *addr)
{
  struct connected *ifc;

  ifc = if_lookup_ifc_ipv6 (ifp, addr);
  if (ifc != NULL)
    if_delete_ifc_ipv6 (ifp, ifc);
}

struct connected *
if_match_ifc_ipv6_direct (struct interface *ifp, struct prefix *p)
{
  struct connected *ifc;
  struct prefix *q;

  for (ifc = ifp->ifc_ipv6; ifc; ifc = ifc->next)
    if ((q = ifc->address)
        && ! IN6_IS_ADDR_LINKLOCAL (&q->u.prefix6)
        && ! IN6_IS_ADDR_LOOPBACK (&q->u.prefix6)
        && ! IN6_IS_ADDR_UNSPECIFIED (&q->u.prefix6))
      {
        if (if_is_pointopoint (ifp))
          {
            if ((q = ifc->destination)
                && prefix_same (p, q))
              break;
          }
        else
          {
            if (prefix_match (q, p))
              break;
          }
      }

  return ifc;
}
#endif /* HAVE_IPV6 */

struct interface *
ifv_lookup_by_prefix (struct if_vrf_master *ifv, struct prefix *cp)
{
  struct interface *ifp;
  struct connected *ifc;
  struct route_node *rn;
  struct prefix *p;
  s_int32_t ret;

  for (rn = route_top (ifv->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      {
        if (cp->family == AF_INET)
          {
            for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)
              if ((p = ifc->address))
                {
                  ret = IFC_IPV4_CMP (&p->u.prefix4, &cp->u.prefix4);
                  if (ret == 0)
                    {
                      route_unlock_node (rn);
                      return ifp;
                    }
                }
          }
#ifdef HAVE_IPV6
       else
         {
           for (ifc = ifp->ifc_ipv6; ifc; ifc = ifc->next)
             if ((p = ifc->address))
               {
                 ret = IFC_IPV6_CMP (&p->u.prefix6, &cp->u.prefix6);
                 if (ret == 0)
                   {
                     route_unlock_node (rn);
                     return ifp;
                   }
               }
          }
#endif /* HAVE_IPV6 */
      }

  return NULL;
}


struct interface *
if_lookup_by_ipv4_address (struct if_vr_master *ifm, struct pal_in4_addr *addr)
{
  struct interface *ifp;
  struct connected *ifc;
  struct route_node *rn;
  struct prefix *p;
  int ret;

  for (rn = route_top (ifm->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)
        if ((p = ifc->address))
          {
            ret = IFC_IPV4_CMP (&p->u.prefix4, addr);
            if (ret == 0)
              {
                route_unlock_node (rn);
                return ifp;
              }
            else if (ret > 0)
              break;
          }

  return NULL;
}

#define IF_MATCH_IFC_BY_IPV4_SUB(ifp, ifc, rn, p, match, best_prefixlen, addr)\
  do {                                                                  \
    for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)                     \
      if ((p = ifc->address))                                           \
        {                                                               \
          if (if_is_pointopoint (ifp))                                  \
            {                                                           \
              if ((p = ifc->destination))                               \
                  if (IPV4_ADDR_SAME (&p->u.prefix4, addr))             \
                  match = ifc;                                          \
            }                                                           \
          else                                                          \
                   {                                                    \
              if (prefix_match (p, &q) && p->prefixlen > best_prefixlen) \
                {                                                       \
                  best_prefixlen = p->prefixlen;                        \
                  match = ifc;                                          \
                }                                                       \
                   }                                                    \
               }                                                        \
  } while (0)

#define IF_MATCH_BY_IPV4_SUB(ifp, ifc, rn, p, match, best_prefixlen, addr)\
  do {                                                                  \
    for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)                     \
      if ((p = ifc->address))                                           \
        {                                                               \
          if (if_is_pointopoint (ifp))                                  \
            {                                                           \
              if ((p = ifc->destination))                               \
                if (IPV4_ADDR_SAME (&p->u.prefix4, addr))               \
                  match = ifp;                                          \
            }                                                           \
          else                                                          \
            {                                                           \
              if (prefix_match (p, &q) && p->prefixlen > best_prefixlen) \
                {                                                       \
                  best_prefixlen = p->prefixlen;                        \
                  match = ifp;                                          \
                }                                                       \
            }                                                           \
        }                                                               \
  } while (0)

#define IF_MATCH_BY_IPV4_ARP_SUB(ifp, ifc, rn, p, match, best_prefixlen, addr) \
  do {                                                                  \
    for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)                     \
      if ((p = ifc->address))                                           \
        {                                                               \
          if (if_is_pointopoint (ifp))                                  \
            {                                                           \
              if ((p = ifc->destination))                               \
                if (IPV4_ADDR_SAME (&p->u.prefix4, addr))               \
                  match = ifp;                                  \
            }                                                           \
          else                                                          \
            {                                                           \
              if (prefix_match (p, &q) && p->prefixlen > best_prefixlen) \
                {                                                       \
                  best_prefixlen = p->prefixlen;                        \
                  *if_c = ifc;                                          \
                  match = ifp;                                          \
                }                                                       \
            }                                                           \
        }                                                               \
  } while (0)

struct interface *
if_match_all_by_ipv4_address (struct if_vr_master *ifm,
                              struct pal_in4_addr *addr,
                              struct connected **if_c)
{
  struct interface *match = NULL;
  struct interface *ifp;
  struct connected *ifc;
  struct route_node *rn;
  struct prefix *p;
  struct prefix q;
  u_char best_prefixlen;

  pal_mem_set (&q, 0, sizeof q);
  best_prefixlen = 0;

  q.family = AF_INET;
  q.u.prefix4 = *addr;
  q.prefixlen = IPV4_MAX_BITLEN;

  for (rn = route_top (ifm->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      IF_MATCH_BY_IPV4_ARP_SUB (ifp, ifc, rn, p, match, best_prefixlen, addr);

  return match;
}

struct connected *
if_subnet_match_by_ipv4_address (struct if_vr_master *ifm,
                           struct pal_in4_addr *addr, vrf_id_t vrf_id)
{
   struct connected *match = NULL;
   struct interface *ifp = NULL;
   struct connected *ifc = NULL;
   struct route_node *rn = NULL;
   struct prefix *p = NULL;
   struct prefix q ;
   u_char best_prefixlen;

   pal_mem_set (&q, 0, sizeof q);
   best_prefixlen = 0;

   q.family = AF_INET;
   q.u.prefix4 = *addr;
   q.prefixlen = IPV4_MAX_BITLEN;

   for (rn = route_top (ifm->if_table); rn; rn = route_next (rn))
     if ((ifp = rn->info))
       if (ifp->vrf == NULL || ifp->vrf->id == vrf_id)
         {
           IF_MATCH_IFC_BY_IPV4_SUB (ifp, ifc, rn, p, match, best_prefixlen, addr);
           if (match)
              break;
         }
         
   return match;
}

struct interface *
if_match_by_ipv4_address (struct if_vr_master *ifm,
                          struct pal_in4_addr *addr, vrf_id_t vrf_id)
{
  struct interface *match = NULL;
  struct interface *ifp;
  struct connected *ifc;
  struct route_node *rn;
  struct prefix *p;
  struct prefix q;
  u_char best_prefixlen;

  pal_mem_set (&q, 0, sizeof q);
  best_prefixlen = 0;

  q.family = AF_INET;
  q.u.prefix4 = *addr;
  q.prefixlen = IPV4_MAX_BITLEN;

  for (rn = route_top (ifm->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      if (ifp->vrf == NULL || ifp->vrf->id == vrf_id)
        IF_MATCH_BY_IPV4_SUB (ifp, ifc, rn, p, match, best_prefixlen, addr);

  return match;
}

/*---------------------------------------------------------------------
 * NOTE: The ifp->hw_addr may not contain the original interface
 *       physical address. If such address is needed, please make use of
 *       the nsm_ifma.c container.
 */
struct interface *
if_lookup_by_hw_addr (struct if_vr_master *ifm,
                             char *mac_addr)
{
  struct interface *ifp;
  struct route_node *rn;

  for (rn = route_top (ifm->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      {
        if ( pal_mem_cmp ( ifp->hw_addr, mac_addr, ifp->hw_addr_len) == 0)
          {
            route_unlock_node (rn);
            return ifp;
          }
      }
  return NULL;
}

#ifdef HAVE_IPV6
struct interface *
if_lookup_by_ipv6_address (struct if_vr_master *ifm, struct pal_in6_addr *addr)
{
  struct interface *ifp;
  struct connected *ifc;
  struct route_node *rn;
  struct prefix *p;
  int ret;

  for (rn = route_top (ifm->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      for (ifc = ifp->ifc_ipv6; ifc; ifc = ifc->next)
        if ((p = ifc->address))
          {
            ret = IFC_IPV6_CMP (&p->u.prefix6, addr);
            if (ret == 0)
              {
                route_unlock_node (rn);
                return ifp;
              }
            else if (ret > 0)
              break;
          }

  return NULL;
}

#define IF_MATCH_BY_IPV6_SUB(ifp, ifc, rn, p, match, best_prefixlen)    \
  do {                                                                  \
    for (ifc = ifp->ifc_ipv6; ifc; ifc = ifc->next)                     \
      if ((p = ifc->address))                                           \
        {                                                               \
          if (if_is_pointopoint (ifp) && p->prefixlen == IPV6_MAX_BITLEN) \
            {                                                           \
              if ((p = ifc->destination))                               \
                if (IPV6_ADDR_SAME (&p->u.prefix6, addr))               \
                  {                                                     \
                    route_unlock_node (rn);                             \
                    return ifp;                                         \
                  }                                                     \
            }                                                           \
          else                                                          \
            {                                                           \
              if (prefix_match (p, &q) && p->prefixlen > best_prefixlen) \
                {                                                       \
                  best_prefixlen = p->prefixlen;                        \
                  match = ifp;                                          \
                }                                                       \
            }                                                           \
        }                                                               \
  } while (0)

struct interface *
if_match_by_ipv6_address (struct if_vr_master *ifm,
                          struct pal_in6_addr *addr, vrf_id_t vrf_id)
{
  struct interface *match = NULL;
  struct interface *ifp;
  struct connected *ifc;
  struct route_node *rn;
  struct prefix *p;
  struct prefix q;
  u_char best_prefixlen;

  pal_mem_set (&q, 0, sizeof q);
  best_prefixlen = 0;

  q.family = AF_INET6;
  q.u.prefix6 = *addr;
  q.prefixlen = IPV6_MAX_BITLEN;

  for (rn = route_top (ifm->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      if (ifp->vrf == NULL || ifp->vrf->id == vrf_id)
        IF_MATCH_BY_IPV6_SUB (ifp, ifc, rn, p, match, best_prefixlen);

  return match;
}

struct interface *
if_match_all_by_ipv6_address (struct if_vr_master *ifm,
                              struct pal_in6_addr *addr)
{
  struct interface *match = NULL;
  struct interface *ifp;
  struct connected *ifc;
  struct route_node *rn;
  struct prefix *p;
  struct prefix q;
  u_char best_prefixlen;

  pal_mem_set (&q, 0, sizeof q);
  best_prefixlen = 0;

  q.family = AF_INET6;
  q.u.prefix6 = *addr;
  q.prefixlen = IPV6_MAX_BITLEN;

  for (rn = route_top (ifm->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      IF_MATCH_BY_IPV6_SUB (ifp, ifc, rn, p, match, best_prefixlen);

  return match;
}
#endif /* HAVE_IPV6 */

struct interface *
if_lookup_by_prefix (struct if_vr_master *ifm, struct prefix *p)
{
  if (p->family == AF_INET)
    return if_lookup_by_ipv4_address (ifm, &p->u.prefix4);
#ifdef HAVE_IPV6
  else if (p->family == AF_INET6)
    return if_lookup_by_ipv6_address (ifm, &p->u.prefix6);
#endif /* HAVE_IPV6 */

  return NULL;
}

struct interface *
if_match_by_prefix (struct if_vr_master *ifm, struct prefix *p,
                    vrf_id_t vrf_id)
{
  switch (p->family)
    {
    case AF_INET:
      return if_match_by_ipv4_address (ifm, &p->u.prefix4, vrf_id);
#ifdef HAVE_IPV6
    case AF_INET6:
      return if_match_by_ipv6_address (ifm, &p->u.prefix6, vrf_id);
#endif /* HAVE_IPV6 */
    default:
      return NULL;
    }
}

char *
if_index2name (struct if_vr_master *ifm, int ifindex)
{
  struct interface *ifp;

  ifp = if_lookup_by_index (ifm, ifindex);
  if (ifp != NULL)
    return ifp->name;

  return "unknown";
}

s_int32_t
if_name2index (struct if_vr_master *ifm, char *name)
{
  struct interface *ifp;

  ifp = if_lookup_by_name (ifm, name);
  if (ifp != NULL)
    return ifp->ifindex;

  return 0;
}

/* Copy string to given buffer. */
char *
if_index2name_copy (struct if_vr_master *ifm, int ifindex, char *name)
{
  struct interface *ifp;

  ifp = if_lookup_by_index (ifm, ifindex);
  if (ifp != NULL)
    {
      pal_strncpy (name, ifp->name, INTERFACE_NAMSIZ + 1);
      return ifp->name;
    }

  return NULL;
}

/* Return kernel interface name.  */
char *
if_kernel_name (struct interface *ifp)
{
  return ifp->name;
}


u_int32_t
if_hash_make (struct interface *ifp)
{
  u_int32_t key;
  int i;

  key = 0;
  if (ifp)
    for (i = 0; i < pal_strlen (ifp->name); i++)
      key += ifp->name[i];

  return key;
}

bool_t
if_hash_cmp (void *a, void *b)
{
  struct interface *if1 = (struct interface *)a;
  struct interface *if2 = (struct interface *)b;

  if (if1 && if2)
    if (pal_strcmp (if1->name, if2->name) == 0)
      return 1;

  if (! if1 && ! if2)
    return 1;

  return 0;
}

/* Ineterface Master. */
void
if_master_init (struct if_master *ifg, struct lib_globals *zg)
{
  pal_mem_set (ifg, 0, sizeof (struct if_master));

  ifg->zg = zg;
  ifg->if_table = route_table_init ();
  ifg->if_list = list_new ();
  ifg->if_hash = hash_create (if_hash_make, if_hash_cmp);
}

void
if_master_finish (struct if_master *ifg)
{
  struct listnode *node, *next;
  struct interface *ifp;

  /* Clean up the interfaces.   */
  for (node = LISTHEAD (ifg->if_list); node; node = next)
    {
      next = node->next;
      ifp = GETDATA (node);
      if (ifp != NULL)
        if_delete (ifg, ifp);
    }

  /* Free the interface hash table.  */
  hash_free (ifg->if_hash);

  /* Free the interface table.  */
  route_table_finish (ifg->if_table);

  /* Free the interface linked-list.  */
  list_free (ifg->if_list);
}

struct interface *
if_new (struct if_master *ifg)
{
  struct interface *ifp;

  ifp = XCALLOC (MTYPE_IF, sizeof (struct interface));
  pal_mem_set(ifp,0,sizeof (struct interface)) ;
  
  /* Initialize the config duplex to default value. Used for config show */
  ifp->config_duplex = NSM_IF_DUPLEX_UNKNOWN;

  return ifp;
}

static int
_if_table_add (struct route_table *if_table,
               int ifindex, struct interface *ifp)
{
  struct prefix_if p;
  struct route_node *rn;
  int ret = 0;

  PREFIX_IF_SET (&p, ifindex);

  rn = route_node_get (if_table, (struct prefix *)&p);
  if (rn->info == NULL)
    {
      RN_IF_INFO_SET (rn, ifp);
      ret = 1;
    }
  route_unlock_node (rn);
  return ret;
}

static int
_if_table_delete (struct route_table *if_table, int ifindex)
{
  struct prefix_if p;
  struct route_node *rn;

  PREFIX_IF_SET (&p, ifindex);

  rn = route_node_lookup (if_table, (struct prefix *)&p);
  if (rn)
    {
      RN_IF_INFO_UNSET (rn);
      route_unlock_node (rn);

      return 1;
    }
  return 0;
}

int
ifg_table_add (struct if_master *ifg, int ifindex, struct interface *ifp)
{
  if (ifg->if_table)
    {
      return _if_table_add (ifg->if_table, ifindex, ifp);
    }

  return 0;
}

int
ifg_table_delete (struct if_master *ifg, int ifindex)
{
  if (ifg->if_table)
    {
      return _if_table_delete (ifg->if_table, ifindex);
    }
  return 0;
}

int
if_vr_table_add (struct if_vr_master *ifm, int ifindex, struct interface *ifp)
{
  if (ifm->if_table)
    {
      return _if_table_add (ifm->if_table, ifindex, ifp);
    }

  return 0;
}

int
if_vr_table_delete (struct if_vr_master *ifm, int ifindex)
{
  if (ifm->if_table)
    {
      return _if_table_delete (ifm->if_table, ifindex);
    }

  return 0;
}

int
if_vrf_table_add (struct if_vrf_master *ifm,
                  int ifindex, struct interface *ifp)
{
  if (ifm->if_table)
    {
      return _if_table_add (ifm->if_table, ifindex, ifp);
    }

  return 0;
}

int
if_vrf_table_delete (struct if_vrf_master *ifm, int ifindex)
{
  if (ifm->if_table)
    {
      return _if_table_delete (ifm->if_table, ifindex);
    }

  return 0;
}

int
if_all_tables_add (struct if_master *ifg, struct interface *ifp)
{
  /* Add ifp to global if_table. */
  ifg_table_add (ifg, ifp->ifindex, ifp);

  /* Add new ifindex to VR if_table. */
  if (ifp->vr)
    if_vr_table_add (&ifp->vr->ifm, ifp->ifindex, ifp);

  /* Add new ifindex to VRF if_table. */
  if (ifp->vrf)
    if_vrf_table_add (&ifp->vrf->ifv, ifp->ifindex, ifp);

  return 0;
}

int
if_all_tables_delete (struct if_master *ifg, struct interface *ifp)
{
  /* Delete ifp from global if_table. */
  ifg_table_delete (ifg, ifp->ifindex);

  /* Delete ifindex from VR if_table. */
  if (ifp->vr)
    if_vr_table_delete (&ifp->vr->ifm, ifp->ifindex);

  /* Delete ifindex from VRF if_table. */
  if (ifp->vrf)
    if_vrf_table_delete (&ifp->vrf->ifv, ifp->ifindex);

  return 0;
}

int
if_ifindex_update (struct if_master *ifg, struct interface *ifp, int ifindex)
{
  if (ifp->ifindex == ifindex)
    return 0;

  /* Withdraw from all the interface tables.  */
  if_all_tables_delete (ifg, ifp);

  /* Update the ifindex.  */
  ifp->ifindex = ifindex;

  /* Add to all the tables with the new ifindex.  */
  if_all_tables_add (ifg, ifp);

  return 1;
}

void
ifg_list_add (struct if_master *ifg, struct interface *ifp)
{

  listnode_add (ifg->if_list, ifp);

  /* update the time for if Tbl last change */
  ifg->ifTblLastChange = pal_time_current (NULL);

  hash_get (ifg->if_hash, ifp, hash_alloc_intern);
}

void
ifg_list_delete (struct if_master *ifg, struct interface *ifp)
{
  listnode_delete (ifg->if_list, ifp);

  /* update the time for if Tbl last change */
  ifg->ifTblLastChange = pal_time_current (NULL);

  hash_release (ifg->if_hash, ifp);
}

struct interface *
ifg_lookup_by_name (struct if_master *ifg, char *name)
{
  struct interface lookup;
  pal_strncpy (lookup.name, name, INTERFACE_NAMSIZ);

  return hash_lookup (ifg->if_hash, &lookup);
}

struct interface *
ifg_lookup_by_index (struct if_master *ifg, u_int32_t ifindex)
{
  struct prefix_if p;
  struct route_node *rn;

  PREFIX_IF_SET (&p, ifindex);

  rn = route_node_lookup (ifg->if_table, (struct prefix *)&p);
  if (rn)
    {
      route_unlock_node (rn);
      return rn->info;
    }
  return NULL;
}

static struct interface *
ifg_lookup_by_ipv4_address (struct if_master *ifg, struct pal_in4_addr *addr)
{
  struct interface *ifp;
  struct connected *ifc;
  struct route_node *rn;
  struct prefix *p;
  int ret;

  for (rn = route_top (ifg->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      for (ifc = ifp->ifc_ipv4; ifc; ifc = ifc->next)
        if ((p = ifc->address))
          {
            ret = IFC_IPV4_CMP (&p->u.prefix4, addr);
            if (ret == 0)
              {
                route_unlock_node (rn);
                return ifp;
              }
            else if (ret > 0)
              break;
          }

  return NULL;
}

struct prefix *
if_get_connected_address (struct interface *ifp, u_int8_t sa_family)
{
  struct connected *connected;
  struct prefix *p;

  if (sa_family == AF_INET || sa_family == AF_UNSPEC)
    for (connected = ifp->ifc_ipv4; connected; connected = connected->next)
      {
        p = (struct prefix *) connected->address;

        /* Ignore Loopback addresses */
        if (p != NULL)
         {
           if (p->family == AF_INET
               && IPV4_NET127 (pal_ntoh32 (p->u.prefix4.s_addr)))
             continue;
         }

        return p;
      }

#ifdef HAVE_IPV6
  if (sa_family == AF_INET6 || sa_family == AF_UNSPEC)
    for (connected = ifp->ifc_ipv6; connected; connected = connected->next)
      {
        p = (struct prefix *) connected->address;

        /* Ignore Loopback addresses */
        if (p != NULL)
          {
            if (p->family == AF_INET6
                && IN6_IS_ADDR_LOOPBACK(&p->u.prefix6))
              continue;
        }

        return p;
      }
#endif /* HAVE_IPV6 */

  return NULL;
}

#ifdef HAVE_IPV6
static struct interface *
ifg_lookup_by_ipv6_address (struct if_master *ifg, struct pal_in6_addr *addr)
{
  struct interface *ifp;
  struct connected *ifc;
  struct route_node *rn;
  struct prefix *p;
  int ret;

  for (rn = route_top (ifg->if_table); rn; rn = route_next (rn))
    if ((ifp = rn->info))
      for (ifc = ifp->ifc_ipv6; ifc; ifc = ifc->next)
        if ((p = ifc->address))
          {
            ret = IFC_IPV6_CMP (&p->u.prefix6, addr);
            if (ret == 0)
              {
                route_unlock_node (rn);
                return ifp;
              }
            else if (ret > 0)
              break;
          }

  return NULL;
}
#endif /* HAVE_IPV6 */

struct interface *
ifg_lookup_by_prefix (struct if_master *ifg, struct prefix *p)
{
  if (p->family == AF_INET)
    return ifg_lookup_by_ipv4_address (ifg, &p->u.prefix4);
#ifdef HAVE_IPV6
  else if (p->family == AF_INET6)
    return ifg_lookup_by_ipv6_address (ifg, &p->u.prefix6);
#endif /* HAVE_IPV6 */

  return NULL;
}

struct interface *
ifg_get_by_name (struct if_master *ifg, char *name)
{
  struct interface *ifp;

  ifp = ifg_lookup_by_name (ifg, name);
  if (ifp == NULL)
    {
      ifp = if_new (ifg);
      if (ifp != NULL)
        {
          pal_strncpy (ifp->name, name, INTERFACE_NAMSIZ);
          ifp->name [INTERFACE_NAMSIZ] = '\0';
          ifg_list_add (ifg, ifp);

          if (LIB_CALLBACK_VERIFY (ifg->zg, ifg, if_callback, IF_CALLBACK_NEW))
            (*ifg->if_callback[IF_CALLBACK_NEW]) (ifp);
        }
    }

  return ifp;
}

/* Delete and free interface structure. */
void
if_delete (struct if_master *ifg, struct interface *ifp)
{
  /* Make sure the interface is unbound from the VR.  */
  if (ifp->vr != NULL)
    if_vr_unbind (&ifp->vr->ifm, ifp->ifindex);

  /* Remove entry from table and list. */
  ifg_list_delete (ifg, ifp);
  ifg_table_delete (ifg, ifp->ifindex);

  /* Free the PM specific interface information.  */
  if (ifp->info != NULL)
    if (ifg->if_callback[IF_CALLBACK_DELETE])
      (*ifg->if_callback[IF_CALLBACK_DELETE]) (ifp);

#ifdef HAVE_L3
  /* Free connected address list. */
  ifc_delete_all (ifg->zg, ifp);
#endif /* HAVE_L3 */

  if (ifp->desc != NULL)
    XFREE (MTYPE_IF_DESC, ifp->desc);

  XFREE (MTYPE_IF, ifp);
  ifp = NULL;
}

/* Add hook to interface master. */
void
if_add_hook (struct if_master *ifg, enum if_callback_type type,
             int (*func) (struct interface *))
{
  if (type < 0 || type >= IF_CALLBACK_MAX)
    return;

  ifg->if_callback[type] = func;
}

void
ifc_add_hook (struct if_master *ifg, enum ifc_callback_type type,
              int (*func) (struct connected *))
{
  if (type < 0 || type >= IFC_CALLBACK_MAX)
    return;

  ifg->ifc_callback[type] = func;
}


/* Utility functions. */
u_int16_t
if_get_hw_type (struct interface *ifp)
{
  return ifp->hw_type;
}

result_t
if_is_up (const struct interface *ifp)
{
  return ifp->flags & IFF_UP;
}

result_t
if_is_running (struct interface *ifp)
{
  if (if_is_loopback (ifp))
    return if_is_up (ifp);

  return (ifp->flags & (IFF_UP|IFF_RUNNING)) == (IFF_UP|IFF_RUNNING);
}

/* Is this loopback interface ? */
result_t
if_is_loopback (struct interface *ifp)
{
  return ifp->flags & IFF_LOOPBACK;
}

/* Does this interface support broadcast ? */
result_t
if_is_broadcast (struct interface *ifp)
{
  return ifp->flags & IFF_BROADCAST;
}

/* Does this interface support broadcast ? */
result_t
if_is_pointopoint (struct interface *ifp)
{
  return ifp->flags & IFF_POINTOPOINT;
}

CLI (interface_desc,
     interface_desc_cli,
     "description LINE",
     "Interface specific description",
     "Characters describing this interface")
{
  struct interface *ifp;

  ifp = cli->index;

  if (ifp->desc)
    XFREE (MTYPE_IF_DESC, ifp->desc);
  ifp->desc = XSTRDUP (MTYPE_IF_DESC, argv[0]);

  return CLI_SUCCESS;
}

CLI (no_interface_desc,
     no_interface_desc_cli,
     "no description",
     CLI_NO_STR,
     "Interface specific description")
{
  struct interface *ifp;

  ifp = cli->index;
  if (ifp->desc)
    XFREE (MTYPE_IF_DESC, ifp->desc);
  ifp->desc = NULL;

  return CLI_SUCCESS;
}


/*
 * Helper function to convert bandwidth in bits in string format
 * to float in bytes.
 *
 * Returns 0 if conversion successful. -1 if not.
 *
 * Valid units are 'k', 'm' and 'g'.
 *
 * NOTE: The passed-in string is assumed to be of size BW_BUFSIZ.
 */
result_t
bandwidth_string_to_float (char *str, float32_t *bw)
{
  char delim [] = "KMGkmg";
  char buf [BW_BUFSIZ];
  char whole_str[MAX_WHOLE_STR_BUFSIZ];
  char decimal_str[BW_BUFSIZ];
  char *token;
  char *pnt;
  u_int64_t whole_num = 0;
  u_int64_t decimal_num = 0;
  s_int32_t unit_len;
  s_int32_t str_len;
  s_int32_t count;
  u_int32_t dot;
  u_char isRational = 0;
  u_char multiplier = 0;
  u_char bw_str_len = 0;
  u_char dec_str_len = 0;
  u_char mult_len = 0;
  u_char diff_len = 0;

  /* Init */
  pal_mem_set (decimal_str, 0, BW_BUFSIZ);
  pal_mem_set (whole_str, 0, MAX_WHOLE_STR_BUFSIZ);
  
  /* Copy string */
  pal_snprintf (buf,sizeof(buf),"%s", str);

  token = pal_strtok (str, delim);
  if (! token)
    /* No number specified */
    return -1;

  /* Check the token contains all numbers including period */
  /* More than one period (.) is not acceptable in numberic part. */
  dot = 0;
  str_len = pal_strlen (token);

  for (count = 0; count < str_len; count++)
    if (! pal_char_isdigit (token[count]))
      {
        if (token [count] == '.')
          {
            /* Restriction for only one period and period not at the
             * end of numeric part
            */
            if (++dot > 1 || (token [count + 1] == '\0'))
              return -1;

            isRational = count;
          }
        else
          {
            /* Error: Input string contains wrong characters */
            return -1;
          }
      }

  /* Fetch the mantissa */
  if (isRational)
    {
      strncpy (whole_str, token, isRational);
      whole_str[isRational] = '\0';

      strcpy (decimal_str, &token[isRational+1]);

       bw_str_len  = strlen (whole_str);
       dec_str_len = strlen (decimal_str);
    }
  else
    {
      strcpy (whole_str, token);

      bw_str_len  = strlen (whole_str);
      dec_str_len = 0;
    }

  if (bw_str_len > MAX_BW_STR_SIZE)
    return -1;

  /* Store it in an long long var and compare
 *  *  *   against max bandwidth */
  sscanf (whole_str, "%llu", &whole_num);
  sscanf (decimal_str, "%llu", &decimal_num);

  if (whole_num > MAX_BANDWIDTH_LONG)
    return -1;

  pal_sscanf (token, "%f", bw);
  pnt = buf + pal_strlen (token);
  unit_len = pal_strlen (buf) - pal_strlen (token);

  while (unit_len--)
    {
      if ((*pnt == 'k') || (*pnt == 'K'))
        {
          *bw = *bw * BW_CONSTANT;
          pnt++;
          multiplier = 1;
        }
      else if ((*pnt == 'm') || (*pnt == 'M'))
        {
          *bw = *bw * BW_CONSTANT * BW_CONSTANT;
          pnt++;
          multiplier = 2;
        }
      else if ((*pnt == 'g') || (*pnt == 'G'))
        {
          *bw = *bw * BW_CONSTANT * BW_CONSTANT * BW_CONSTANT;
          pnt++;
          multiplier = 3;
        }
      else
        return -1;
    }

  if (multiplier)
    {
      mult_len = 3 * multiplier;
      if (! isRational)
        {
          whole_num = (pal_power (BW_CONSTANT,multiplier)) * whole_num;
        }
      else
        {
          if (dec_str_len >= mult_len)
            {
              strncpy (&(whole_str[bw_str_len]), decimal_str, mult_len);
              whole_str[bw_str_len+mult_len] = '\0';
              sscanf (whole_str, "%llu", &whole_num);
            }
          else
            {
              diff_len = mult_len - dec_str_len;
              strncpy (&(whole_str[bw_str_len]), decimal_str, dec_str_len);
              whole_str[bw_str_len+dec_str_len] = '\0';
              sscanf (whole_str, "%llu", &whole_num);
              whole_num = whole_num * (pal_power(10, diff_len));
            }
        }
      bw_str_len += mult_len;
    }

  if ((bw_str_len > MAX_BW_STR_SIZE) ||
      (whole_num > MAX_BANDWIDTH_LONG))
    return -1;

  if (! LEGAL_BANDWIDTH (*bw))
    return -1;

  /* Convert to bytes */
  *bw = *bw / 8;

  return 0;
}

/*
 * Helper function to convert bandwidth in float format to string.
 * Returns NULL if float is out of bounds.
 *
 * If precision flag is set, output is to three decimal places.
 *
 * NOTE: It has been assumed here that the passed in buffer is of
 * size BW_BUFSIZ.
 */
char *
bandwidth_float_to_string (char *buf, float64_t bw)
{
  u_char k, g, m;
  int i;

  /* Presets */
  k = g = m = 0;
  pal_mem_set (buf, 0, BW_BUFSIZ);

  /* First convert bw to bits */
  bw = bw * 8;

  if ((bw / (BW_CONSTANT * BW_CONSTANT * BW_CONSTANT)) >= 1)
    {
      bw = bw / (BW_CONSTANT * BW_CONSTANT * BW_CONSTANT);
      g = 1;
      goto calc;
    }

  if ((bw / (BW_CONSTANT * BW_CONSTANT)) >= 1)
    {
      bw = bw / (BW_CONSTANT * BW_CONSTANT);
      m = 1;
      goto calc;
    }

  if ((bw / BW_CONSTANT) >= 1)
    {
      bw = bw / BW_CONSTANT;
      k = 1;
    }

 calc:
  zsnprintf (buf, (BW_BUFSIZ-1), "%f", bw);
  for (i = (BW_BUFSIZ - 1); i >= 0; --i)
    {
      /* Skip nul. */
      if (buf[i] == '\0')
        continue;

      /* If non-zero, stop. */
      if (buf[i] != '0')
        {
          if (buf[i] != '.')
            ++i;
          break;
        }

      /* Nullify non-necessary zeros. */
      if (buf[i] == '0')
        buf[i] = '\0';
    }
  buf[i] = ((g == 1) ? 'g' : ((m == 1) ? 'm' : ((k == 1) ? 'k' : '\0')));

  return buf;
}

struct interface *
if_lookup_loopback (struct if_vr_master *ifm)
{
  struct interface *ifp;
  struct listnode *node;

  LIST_LOOP (ifm->if_list, ifp, node)
    if (if_is_loopback (ifp))
      return ifp;

  return NULL;
}
