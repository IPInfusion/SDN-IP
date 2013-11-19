/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "lib.h"

/* Default route-map rule commands. */
struct route_map_rule_cmd route_map_interface_cmd =
{
  "interface",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_metric_cmd =
{
  "metric",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ip_addr_cmd =
{
  "ip address",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ip_addr_plist_cmd =
{
  "ip address prefix-list",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ip_nexthop_cmd =
{
  "ip next-hop",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ip_nexthop_plist_cmd =
{
  "ip next-hop prefix-list",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ip_peer_cmd =
{
  "ip peer",
  NULL,
  NULL,
  NULL
};

#ifdef HAVE_IPV6
struct route_map_rule_cmd route_map_ipv6_peer_cmd =
{
  "ipv6 peer",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ipv6_addr_cmd =
{
  "ipv6 address",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ipv6_addr_plist_cmd =
{
  "ipv6 address prefix-list",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ipv6_nexthop_cmd =
{
  "ipv6 next-hop",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ipv6_nexthop_plist_cmd =
{
  "ipv6 next-hop prefix-list",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ipv6_nexthop_local_cmd =
{
  "ipv6 next-hop local",
  NULL,
  NULL,
  NULL
};
#endif /* HAVE_IPV6 */

struct route_map_rule_cmd route_map_tag_cmd =
{
  "tag",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_route_type_cmd =
{
  "route-type external",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_metric_type_cmd =
{
  "metric-type",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_level_cmd =
{
  "level",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_as_path_cmd =
{
  "as-path",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_origin_cmd =
{
  "origin",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_community_cmd =
{
  "community",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_ecommunity_cmd =
{
  "extcommunity",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_as_path_prepend_cmd =
{
  "as-path prepend",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_local_preference_cmd =
{
  "local-preference",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_weight_cmd =
{
  "weight",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_atomic_aggregate_cmd =
{
  "atomic-aggregate",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_aggregator_as_cmd =
{
  "aggregator as",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_originator_id_cmd =
{
  "originator-id",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_community_delete_cmd =
{
  "comm-list",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_extcommunity_rt_cmd =
{
  "extcommunity rt",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_extcommunity_soo_cmd =
{
  "extcommunity soo",
  NULL,
  NULL,
  NULL
};

struct route_map_rule_cmd route_map_dampening_cmd =
{
  "dampening",
  NULL,
  NULL,
  NULL
};


/* Convert Access-List return codes into Route-Map return codes */
route_map_result_t
route_map_alist2rmap_rcode (enum filter_type ftype)
{
  route_map_result_t rcode;

  rcode = RMAP_ERROR;

  switch (ftype)
   {
     case FILTER_DENY:
       rcode = RMAP_DENYMATCH;
       break;

     case FILTER_PERMIT:
     case FILTER_DYNAMIC:
       rcode = RMAP_MATCH;
       break;

     case FILTER_NO_MATCH:
       rcode = RMAP_NOMATCH;
       break;

     default:
       break;
   }

  return rcode;
}

/* Convert Prefix-List return codes into Route-Map return codes */
route_map_result_t
route_map_plist2rmap_rcode (enum prefix_list_type ptype)
{
  route_map_result_t rcode;

  rcode = RMAP_ERROR;

  switch (ptype)
   {
     case PREFIX_DENY:
       rcode = RMAP_DENYMATCH;
       break;

     case PREFIX_PERMIT:
       rcode = RMAP_MATCH;
       break;

     case PREFIX_NO_MATCH:
       rcode = RMAP_NOMATCH;
       break;

     default:
       break;
   }

  return rcode;
}

/* Add new name to route_map. */
static struct route_map *
route_map_add (struct ipi_vr *vr, char *name)
{
  struct route_map_list *list;
  struct route_map *map;

  map = NULL;

  if (! vr || ! name)
    return map;

  map = XCALLOC (MTYPE_ROUTE_MAP, sizeof (struct route_map));

  if (! map)
    return map;

  map->name = XSTRDUP (MTYPE_ROUTE_MAP_NAME, name);

  if (! map->name)
    {
      XFREE (MTYPE_ROUTE_MAP, map);
      map = NULL;

      return map;
    }

  list = &vr->route_map_master;

  map->next = NULL;
  map->prev = list->tail;
  if (list->tail)
    list->tail->next = map;
  else
    list->head = map;
  list->tail = map;

  /* Execute hook. */
  if (vr->route_map_master.add_hook)
    (*vr->route_map_master.add_hook) (vr, name);

  return map;
}

/* Route map delete from list. */
static void
route_map_delete (struct ipi_vr *vr, struct route_map *map)
{
  struct route_map_list *list;
  struct route_map_index *index;
  u_int8_t *name;

  while ((index = map->head) != NULL)
    route_map_index_delete (vr, index, 0);

  name = map->name;

  list = &vr->route_map_master;

  if (map->next)
    map->next->prev = map->prev;
  else
    list->tail = map->prev;

  if (map->prev)
    map->prev->next = map->next;
  else
    list->head = map->next;

  XFREE (MTYPE_ROUTE_MAP, map);

  /* Execute deletion hook. */
  if (vr->route_map_master.delete_hook)
    (*vr->route_map_master.delete_hook) (vr, name);

  if (name)
    XFREE (MTYPE_ROUTE_MAP_NAME, name);

  return;
}

/* Lookup route map by route map name string. */
struct route_map *
route_map_lookup_by_name (struct ipi_vr *vr, char *name)
{
  struct route_map *map;

  map = NULL;

  for (map = vr->route_map_master.head; map; map = map->next)
    if (! pal_strcmp (map->name, name))
      break;

  return map;
}

/* Lookup route map.  If there isn't route map create one and return
   it. */
struct route_map *
route_map_get (struct ipi_vr *vr, char *name)
{
  struct route_map *map;

  map = route_map_lookup_by_name (vr, name);
  if (! map)
    map = route_map_add (vr, name);

  return map;
}

result_t
route_map_empty (struct route_map *map)
{
  if (! map->head && ! map->tail)
    return PAL_TRUE;
  else
    return PAL_FALSE;
}


/* Install rule command to the match list. */
void
route_map_install_match_default (struct ipi_vr *vr,
                                 struct route_map_rule_cmd *cmd)
{
  vector_set (vr->route_match_vec, cmd);
}

/* Install rule command to the set list. */
void
route_map_install_set_default (struct ipi_vr *vr,
                               struct route_map_rule_cmd *cmd)
{
  vector_set (vr->route_set_vec, cmd);
}

/* Install rule command to the match list. */
void
route_map_install_match (struct ipi_vr *vr, struct route_map_rule_cmd *cmd_add)
{
  struct route_map_rule_cmd *cmd;
  int i;

  for (i = 0; i < vector_max (vr->route_match_vec); i++)
    if ((cmd = vector_slot (vr->route_match_vec, i)))
      if (pal_strcmp (cmd->str, cmd_add->str) == 0)
        {
          /* Replace the route-map default rule. */
          vector_slot (vr->route_match_vec, i) = cmd_add;
          return;
        }
  vector_set (vr->route_match_vec, cmd_add);
}

/* Install rule command to the set list. */
void
route_map_install_set (struct ipi_vr *vr, struct route_map_rule_cmd *cmd_add)
{
  struct route_map_rule_cmd *cmd;
  int i;

  for (i = 0; i < vector_max (vr->route_set_vec); i++)
    if ((cmd = vector_slot (vr->route_set_vec, i)))
      if (pal_strcmp (cmd->str, cmd_add->str) == 0)
        {
          /* Replace the route-map default rule. */
          vector_slot (vr->route_set_vec, i) = cmd_add;
          return;
        }
  vector_set (vr->route_set_vec, cmd_add);
}

/* Lookup rule command from match list. */
struct route_map_rule_cmd *
route_map_lookup_match (struct ipi_vr *vr, char *name)
{
  struct route_map_rule_cmd *cmd;
  int i;

  for (i = 0; i < vector_max (vr->route_match_vec); i++)
    if ((cmd = vector_slot (vr->route_match_vec, i)) != NULL)
      if (pal_strcmp (cmd->str, name) == 0)
        return cmd;

  return NULL;
}

/* Lookup rule command from set list. */
struct route_map_rule_cmd *
route_map_lookup_set (struct ipi_vr *vr, char *name)
{
  int i;
  struct route_map_rule_cmd *cmd;

  for (i = 0; i < vector_max (vr->route_set_vec); i++)
    if ((cmd = vector_slot (vr->route_set_vec, i)) != NULL)
      if (pal_strcmp (cmd->str, name) == 0)
        return cmd;

  return NULL;
}

/* Add match and set rule to rule list. */
static void
route_map_rule_add (struct route_map_rule_list *list,
                    struct route_map_rule *rule)
{
  rule->next = NULL;
  rule->prev = list->tail;
  if (list->tail)
    list->tail->next = rule;
  else
    list->head = rule;
  list->tail = rule;
}

static void
route_map_rule_add_top (struct route_map_rule_list *list,
                        struct route_map_rule *rule)
{
  rule->prev = NULL;
  rule->next = list->head;

  if (list->head)
    list->head->prev = rule;
  else
    list->tail = rule;
  list->head = rule;
}

/* Delete rule from rule list. */
static void
route_map_rule_delete (struct route_map_rule_list *list,
                       struct route_map_rule *rule)
{
  if (rule->cmd->func_free)
    (*rule->cmd->func_free) (rule->value);

  if (rule->rule_str)
    XFREE (MTYPE_ROUTE_MAP_RULE_STR, rule->rule_str);

  if (rule->next)
    rule->next->prev = rule->prev;
  else
    list->tail = rule->prev;
  if (rule->prev)
    rule->prev->next = rule->next;
  else
    list->head = rule->next;

  XFREE (MTYPE_ROUTE_MAP_RULE, rule);
}


/* Free route map index. */
void
route_map_index_delete (struct ipi_vr *vr,
                        struct route_map_index *index, int notify)
{
  struct route_map_rule *rule;

  /* Free route match. */
  while ((rule = index->match_list.head) != NULL)
    route_map_rule_delete (&index->match_list, rule);

  /* Free route set. */
  while ((rule = index->set_list.head) != NULL)
    route_map_rule_delete (&index->set_list, rule);

  /* Remove index from route map list. */
  if (index->next)
    index->next->prev = index->prev;
  else
    index->map->tail = index->prev;

  if (index->prev)
    index->prev->next = index->next;
  else
    index->map->head = index->next;

    /* Execute event hook. */
  if (vr->route_map_master.event_hook && notify)
    (*vr->route_map_master.event_hook) (vr, RMAP_EVENT_INDEX_DELETED,
                                        index->map->name);

  XFREE (MTYPE_ROUTE_MAP_INDEX, index);
}

/* Lookup index from route map. */
struct route_map_index *
route_map_index_lookup (struct route_map *map, enum route_map_type type,
                        s_int32_t pref)
{
  struct route_map_index *index;

  for (index = map->head; index; index = index->next)
    if ((index->type == type || type == RMAP_ANY)
        && index->pref == pref)
      return index;

  return NULL;
}

/* Add new index to route map. */
struct route_map_index *
route_map_index_add (struct ipi_vr *vr, struct route_map *map,
                     enum route_map_type type, s_int32_t pref)
{
  struct route_map_index *index;
  struct route_map_index *point;

  /* Allocate new route map inex. */
  index = XCALLOC (MTYPE_ROUTE_MAP_INDEX, sizeof (struct route_map_index));

  if (! index)
    return index;

  index->map = map;
  index->type = type;
  index->pref = pref;

  /* Compare preference. */
  for (point = map->head; point; point = point->next)
    if (point->pref >= pref)
      break;

  if (! map->head)
    {
      map->head = map->tail = index;
    }
  else if (! point)
    {
      index->prev = map->tail;
      map->tail->next = index;
      map->tail = index;
    }
  else if (point == map->head)
    {
      index->next = map->head;
      map->head->prev = index;
      map->head = index;
    }
  else
    {
      index->next = point;
      index->prev = point->prev;
      if (point->prev)
        point->prev->next = index;
      point->prev = index;
    }

  /* Execute event hook. */
  if (vr->route_map_master.event_hook)
    (*vr->route_map_master.event_hook) (vr, RMAP_EVENT_INDEX_ADDED, map->name);

  return index;
}

/* Get route map index. */
struct route_map_index *
route_map_index_get (struct ipi_vr *vr, struct route_map *map,
                     enum route_map_type type, s_int32_t pref)
{
  struct route_map_index *index;

  index = route_map_index_lookup (map, RMAP_ANY, pref);
  if (index && index->type != type)
    {
      /* Delete index from route map. */
      route_map_index_delete (vr, index, 1);
      index = NULL;
    }
  if (! index)
    index = route_map_index_add (vr, map, type, pref);
  return index;
}

struct route_map_index *
route_map_index_install (struct ipi_vr *vr,
                         char *name, int permit, int pref)
{
  struct route_map *map;

  /* Get route map. */
  map = route_map_get (vr, name);
  if (!map)
    return NULL;

  /* Set the route map index. */
  return route_map_index_get (vr, map, permit, pref);
}

int
route_map_uninstall (struct ipi_vr *vr, char *name)
{
  struct route_map *map;

  /* Route map existence check. */
  map = route_map_lookup_by_name (vr, name);
  if (! map)
    return LIB_API_SET_ERR_UNKNOWN_OBJECT;

  /* Delete the entire route map. */
  route_map_delete (vr, map);

  return LIB_API_SET_SUCCESS;
}

int
route_map_index_uninstall (struct ipi_vr *vr, char *name,
                           int permit, int pref)
{
  struct route_map_index *index;
  struct route_map *map;

  /* Route map existence check. */
  map = route_map_lookup_by_name (vr, name);
  if (! map)
    return LIB_API_SET_ERR_UNKNOWN_OBJECT;

  /* Route map index existence check. */
  index = route_map_index_lookup (map, permit, pref);
  if (! index)
    return LIB_API_SET_ERR_UNKNOWN_OBJECT;

  /* Delete the specified route map index. */
  route_map_index_delete (vr, index, 1);

  /* If this route rule is the last one, delete route map itself. */
  if (route_map_empty (map))
    route_map_delete (vr, map);

  return LIB_API_SET_SUCCESS;
}

/* Apply route map's each index to the object.

   The matrix for a route-map looks like this:
   (note, this includes the description for the "NEXT"
   and "GOTO" frobs now

             Match   |   No Match
                     |
   permit      a     |      c
                     |
   ------------------+---------------
                     |
   deny        b     |      d
                     |

   a) Apply Set statements, accept route
      If NEXT is specified, goto NEXT statement
      If GOTO is specified, goto the first clause where pref > nextpref
      If nothing is specified, do as Cisco and finish
   b) If NEXT is specified, goto NEXT statement
      If nothing is specified, finally will be denied by route-map.
   c) & d)   Goto Next index

   If we get no matches after we've processed all updates, then the
   route is dropped too.  */

route_map_result_t
route_map_apply_index (struct route_map_index *index,
                       struct prefix *prefix, void *object)
{
  struct route_map_rule *match;
  struct route_map_rule *set;
  route_map_result_t ret;

  ret = RMAP_NOMATCH;

  /* Check match rules and if there is no match rule, go to set statement */
  if (! index->match_list.head)
    ret = RMAP_MATCH;
  else
    {
      for (match = index->match_list.head; match; match = match->next)
        if (match->cmd->func_apply)
          {
            /* Try each match statement in turn, If any return
               RMAP_MATCH, go direct to set statement, otherwise, walk
               to next match statement. */

            ret = (*match->cmd->func_apply) (match->value, prefix, match,
                                             object);

            /* Check for next sequence */
            if (ret == RMAP_DENYMATCH)
              ret = RMAP_NOMATCH;

            if (ret != RMAP_MATCH)
              break;
          }
    }

  /* If end of match statement, still can't get any RMAP_MATCH return,
     just return to next rout-map statement. */
  if (ret != RMAP_MATCH)
    return ret;

  /* We get here if all match statements matched From the matrix
     above, if this is PERMIT we go on and apply the SET functions. If
     we're deny, we return indicating we matched a deny */

  /* Apply set statement to the object. */
  if (index->type == RMAP_PERMIT)
    {
      for (set = index->set_list.head; set; set = set->next)
        if (set->cmd->func_apply)
          ret = (*set->cmd->func_apply) (set->value, prefix, set, object);

      return RMAP_MATCH;
    }

  return RMAP_DENYMATCH;
}

/* Apply route map to the object. */
route_map_result_t
route_map_apply (struct route_map *map, struct prefix *prefix, void *object)
{
  struct route_map_index *index;
  route_map_result_t ret;

  ret = RMAP_NOMATCH;

  if (! map)
    return RMAP_DENYMATCH;

  for (index = map->head; index; index = index->next)
    {
      /* Apply this index, until we get the end of route-map case. */
      ret = route_map_apply_index (index, prefix, object);

      if (ret == RMAP_MATCH || ret == RMAP_DENYMATCH)
        return ret;
    }

  /* Finally route-map does not match at all */
  return RMAP_DENYMATCH;
}

void
route_map_add_hook (struct ipi_vr *vr, void (*func) (struct ipi_vr *, char *))
{
  vr->route_map_master.add_hook = func;
}

void
route_map_delete_hook (struct ipi_vr *vr,
                       void (*func) (struct ipi_vr *, char *))
{
  vr->route_map_master.delete_hook = func;
}

void
route_map_event_hook (struct ipi_vr *vr,
                      void (*func) (struct ipi_vr *, route_map_event_t,
                                    char *))
{
  vr->route_map_master.event_hook = func;
}


/* pal_strcmp wrapper function which don't crush even argument is NULL. */
result_t
rulecmp (char *dst, char *src)
{
  if (! dst)
    {
      if (src ==  NULL)
        return 0;
      else
        return 1;
    }
  else
    {
      if (! src)
        return 1;
      else
        return pal_strcmp (dst, src);
    }
}

int
route_map_match_set (struct ipi_vr *vr,
                     char *name, int direct, int pref,
                     char *command, char *arg)
{
  struct route_map *map;
  struct route_map_index *index;
  struct route_map_rule *rule;
  struct route_map_rule *next;
  struct route_map_rule_cmd *cmd;
  void *compile;
  int replaced = 0;

  map = route_map_lookup_by_name (vr, name);
  if (! map)
    return LIB_API_SET_ERR_RMAP_NOT_EXIST;

  index = route_map_index_lookup (map, direct, pref);
  if (! index)
    return LIB_API_SET_ERR_RMAP_INDEX_NOT_EXIST;

  /* Then lookup rule for add match statement. */
  cmd = route_map_lookup_match (vr, command);
  if (! cmd)
    return LIB_API_SET_ERR_RMAP_RULE_MISSING;

  /* Next call compile function for this match statement. */
  if (cmd->func_compile)
    {
      compile = (*cmd->func_compile) (arg);
      if (! compile)
        return LIB_API_SET_ERR_RMAP_COMPILE_ERROR;
    }
  else
    compile = NULL;

  /* If argument is completely same ignore it. */
  for (rule = index->match_list.head; rule; rule = next)
    {
      next = rule->next;
      if (rule->cmd == cmd)
        {
          route_map_rule_delete (&index->match_list, rule);
          replaced = 1;
        }
    }

  /* Add new route map match rule. */
  rule = XCALLOC (MTYPE_ROUTE_MAP_RULE, sizeof (struct route_map_rule));

  if (! rule)
    return LIB_API_SET_ERR_OOM;

  rule->cmd = cmd;
  rule->value = compile;
  if (arg)
    {
      rule->rule_str = XSTRDUP (MTYPE_ROUTE_MAP_RULE_STR, arg);

      if (! rule->rule_str)
        {
          XFREE (MTYPE_ROUTE_MAP_RULE, rule);

          return LIB_API_SET_ERR_OOM;
        }
    }
  else
    rule->rule_str = NULL;

  /* Add new route match rule to linked list. */
  route_map_rule_add (&index->match_list, rule);

  /* Execute event hook. */
  if (vr->route_map_master.event_hook)
    (*vr->route_map_master.event_hook) (vr, replaced ?
                                        RMAP_EVENT_MATCH_REPLACED:
                                        RMAP_EVENT_MATCH_ADDED,
                                        index->map->name);

  return 0;
}

int
route_map_match_unset (struct ipi_vr *vr,
                       char *name, int direct, int pref,
                       char *command, char *arg)
{
  struct route_map *map;
  struct route_map_index *index;
  struct route_map_rule *rule;
  struct route_map_rule_cmd *cmd;

  map = route_map_lookup_by_name (vr, name);
  if (! map)
    return LIB_API_SET_ERR_RMAP_NOT_EXIST;

  index = route_map_index_lookup (map, direct, pref);
  if (! index)
    return LIB_API_SET_ERR_RMAP_INDEX_NOT_EXIST;

  cmd = route_map_lookup_match (vr, command);
  if (! cmd)
    return LIB_API_SET_ERR_RMAP_RULE_MISSING;

  for (rule = index->match_list.head; rule; rule = rule->next)
    if (rule->cmd == cmd
        && (rulecmp (rule->rule_str, arg) == 0 || ! arg))
      {
        route_map_rule_delete (&index->match_list, rule);

        /* Execute event hook. */
        if (vr->route_map_master.event_hook)
          (*vr->route_map_master.event_hook) (vr, RMAP_EVENT_MATCH_DELETED,
                                              index->map->name);
        return 0;
      }
  /* Can't find matched rule. */
  return 1;
}

int
route_map_set_set (struct ipi_vr *vr,
                   char *name, int direct, int pref,
                   char *command, char *arg, int flags)
{
  struct route_map *map;
  struct route_map_index *index;
  struct route_map_rule *rule;
  struct route_map_rule *next;
  struct route_map_rule_cmd *cmd;
  void *compile;
  int replaced = 0;

  map = route_map_lookup_by_name (vr, name);
  if (! map)
    return LIB_API_SET_ERR_RMAP_NOT_EXIST;

  index = route_map_index_lookup (map, direct, pref);
  if (! index)
    return LIB_API_SET_ERR_RMAP_INDEX_NOT_EXIST;

  cmd = route_map_lookup_set (vr, command);
  if (! cmd)
    return LIB_API_SET_ERR_RMAP_RULE_MISSING;

  /* Next call compile function for this match statement. */
  if (cmd->func_compile)
    {
      compile = (*cmd->func_compile) (arg);
      if (! compile)
        return LIB_API_SET_ERR_RMAP_COMPILE_ERROR;
    }
  else
    compile = NULL;

  /* When same command is there, replace it. */
  for (rule = index->set_list.head; rule; rule = next)
    {
      next = rule->next;
      if (rule->cmd == cmd)
        {
          route_map_rule_delete (&index->set_list, rule);
          replaced = 1;
        }
    }

  /* Add new route map match rule. */
  rule = XCALLOC (MTYPE_ROUTE_MAP_RULE, sizeof (struct route_map_rule));

  if (! rule)
    return LIB_API_SET_ERR_OOM;

  rule->cmd = cmd;
  rule->value = compile;
  rule->flags = flags;
  if (arg)
    {
      rule->rule_str = XSTRDUP (MTYPE_ROUTE_MAP_RULE_STR, arg);

      if (! rule->rule_str)
        {
          XFREE (MTYPE_ROUTE_MAP_RULE, rule);

          return LIB_API_SET_ERR_OOM;
        }
    }
  else
    rule->rule_str = NULL;

  /* Add new route match rule to linked list. */
  if (CHECK_FLAG (flags, ROUTE_MAP_FLAG_PRIORITY))
    route_map_rule_add_top (&index->set_list, rule);
  else
    route_map_rule_add (&index->set_list, rule);

  /* Execute event hook. */
  if (vr->route_map_master.event_hook)
    (*vr->route_map_master.event_hook) (vr, replaced ?
                                        RMAP_EVENT_SET_REPLACED:
                                        RMAP_EVENT_SET_ADDED,
                                        index->map->name);

  return 0;
}

int
route_map_set_unset (struct ipi_vr *vr,
                     char *name, int direct, int pref,
                     char *command, char *arg)
{
  struct route_map *map;
  struct route_map_index *index;
  struct route_map_rule *rule;
  struct route_map_rule_cmd *cmd;

  map = route_map_lookup_by_name (vr, name);
  if (! map)
    return LIB_API_SET_ERR_RMAP_NOT_EXIST;

  index = route_map_index_lookup (map, direct, pref);
  if (! index)
    return LIB_API_SET_ERR_RMAP_INDEX_NOT_EXIST;

  cmd = route_map_lookup_set (vr, command);
  if (! cmd)
    return LIB_API_SET_ERR_RMAP_RULE_MISSING;

  for (rule = index->set_list.head; rule; rule = rule->next)
    if (rule->cmd == cmd
        && (rulecmp (rule->rule_str, arg) == 0 || ! arg))
      {
        route_map_rule_delete (&index->set_list, rule);
        /* Execute event hook. */
        if (vr->route_map_master.event_hook)
          (*vr->route_map_master.event_hook) (vr, RMAP_EVENT_SET_DELETED,
                                              index->map->name);
        return 0;
      }
  /* Can't find matched rule. */
  return 1;
}

int route_map_set_set_nexthop (struct ipi_vr *vr,
                               char *name, int direct, int pref,
                               char *command, char *nexthop, s_int16_t nh_type,
                               char *ifname, int flags)
{
  struct route_map *map = NULL;
  struct route_map_index *index = NULL;
  struct route_map_rule *rule = NULL;
  struct route_map_rule *next = NULL;
  struct route_map_rule_cmd *cmd = NULL;
  void *compile;
  int replaced = 0;
   if (nh_type == NEXTHOP_SECONDARY)
    return LIB_API_SET_ERR_NEXTHOP_NOT_VALID;

   map = route_map_lookup_by_name (vr, name);
   if (! map)
     return LIB_API_SET_ERR_RMAP_NOT_EXIST;
 
   index = route_map_index_lookup (map, direct, pref);
   if (! index)
     return LIB_API_SET_ERR_RMAP_INDEX_NOT_EXIST;
 
   cmd = route_map_lookup_set (vr, command);
   if (! cmd)
     return LIB_API_SET_ERR_RMAP_RULE_MISSING;
 
  /* Next call compile function for this match statement. */
    {
      if (cmd->func_compile)
        {
          compile = (*cmd->func_compile) (nexthop);
          if (! compile)
            return LIB_API_SET_ERR_RMAP_COMPILE_ERROR;
        }
      else
        compile = NULL;
 
      /* When same command is there, replace it. */
      for (rule = index->set_list.head; rule; rule = next)
        {
          next = rule->next;
          if (rule->cmd == cmd)
            {
               route_map_rule_delete (&index->set_list, rule);
               replaced = 1;
               break;
            }
         }
 
      /* Add new route map match rule. */
      rule = XCALLOC (MTYPE_ROUTE_MAP_RULE, sizeof (struct route_map_rule));
 
      if (! rule)
        return LIB_API_SET_ERR_OOM;
 
      rule->cmd = cmd;
      rule->value = compile;
      rule->flags = flags;
      if (nexthop)
        {
          rule->rule_str = XSTRDUP (MTYPE_ROUTE_MAP_RULE_STR, nexthop);
  
          if (! rule->rule_str)
             {
               XFREE (MTYPE_ROUTE_MAP_RULE, rule);
 
               return LIB_API_SET_ERR_OOM;
             }
     
         }
      /* Add new route match rule to linked list. */
      if (CHECK_FLAG (flags, ROUTE_MAP_FLAG_PRIORITY))
        route_map_rule_add_top (&index->set_list, rule);
      else
        route_map_rule_add (&index->set_list, rule);
    }
    {
      /* Execute event hook. */
      if (vr->route_map_master.event_hook)
        (*vr->route_map_master.event_hook) (vr, replaced ?
                                        RMAP_EVENT_SET_REPLACED:
                                        RMAP_EVENT_SET_ADDED,
                                        index->map->name);  
    }
  return 0;
}

int route_map_set_unset_nexthop (struct ipi_vr *vr,
                               char *name, int direct, int pref,
                               char *command, char *nexthop, s_int16_t nh_type,
                               char *ifname)
{
  struct route_map *map = NULL;
  struct route_map_index *index = NULL;
  struct route_map_rule *rule = NULL;
  struct route_map_rule_cmd *cmd = NULL;
 
  map = route_map_lookup_by_name (vr, name);
  if (! map)
    return LIB_API_SET_ERR_RMAP_NOT_EXIST;
 
  index = route_map_index_lookup (map, direct, pref);
  if (! index)
    return LIB_API_SET_ERR_RMAP_INDEX_NOT_EXIST;
 
  cmd = route_map_lookup_set (vr, command);
  if (! cmd)
    return LIB_API_SET_ERR_RMAP_RULE_MISSING;
 
  for (rule = index->set_list.head; rule; rule = rule->next)
    {
      if (rule->cmd == cmd )
        {
          if ((rulecmp (rule->rule_str, nexthop) == 0) || (!nexthop))
            {
              route_map_rule_delete (&index->set_list, rule);
            }
            {
              /* Execute event hook. */
              if (vr->route_map_master.event_hook)
                {
                  (*vr->route_map_master.event_hook) (vr, RMAP_EVENT_SET_DELETED,
                                                 index->map->name);
                }
            }
          return 0; 
        }
    }
   
   return 0;
}



/* Function to display route maps */
void
route_map_display (struct cli *cli, struct route_map *map)
{
  struct route_map_index *index = NULL;
  struct route_map_rule *rule = NULL;

  for (index = map->head; index; index = index->next)
    {
      cli_out (cli, "route-map %s, %s, sequence %d\n",
               map->name, ROUTE_MAP_TYPE_STR (index->type), index->pref);

      cli_out (cli, "  Match clauses:\n");

      for (rule = index->match_list.head; rule; rule = rule->next)
        if (rule->cmd->comment)
          cli_out (cli, "    %s %s: %s\n",
                   rule->cmd->str, rule->cmd->comment,
                   rule->rule_str ? rule->rule_str : "");
        else
          cli_out (cli, "    %s %s\n",
                   rule->cmd->str,
                   rule->rule_str ? rule->rule_str : "");

      cli_out (cli, "  Set clauses:\n");

      for (rule = index->set_list.head; rule; rule = rule->next)
        if (rule->cmd->comment)
          cli_out (cli, "    %s %s: %s\n",
                   rule->cmd->str, rule->cmd->comment,
                   rule->rule_str ? rule->rule_str : "");
        else
          cli_out (cli, "    %s %s\n",
                   rule->cmd->str,
                   rule->rule_str ? rule->rule_str : "");
    }
}

/* CLIs. */
CLI (route_map,
     route_map_cmd,
     "route-map WORD (deny|permit) <1-65535>",
     CLI_ROUTEMAP_STR,
     "Route map tag",
     "Route map denies set operations",
     "Route map permits set operations",
     "Sequence to insert to/delete from existing route-map entry")
{
  struct route_map_index *index = NULL;
  u_int32_t pref;
  int permit;

  /* Permit check. */
  if (pal_strncmp (argv[1], "permit", pal_strlen (argv[1])) == 0)
    permit = RMAP_PERMIT;
  else if (pal_strncmp (argv[1], "deny", pal_strlen (argv[1])) == 0)
    permit = RMAP_DENY;
  else
    {
      cli_out (cli, "the third field must be [permit|deny]\n");
      return CLI_ERROR;
    }

  /* Preference check. */
  CLI_GET_INTEGER_RANGE ("sequence", pref, argv[2], 1, 65535);

  index = route_map_index_install (cli->vr, argv[0], permit, pref);

  if (index)
    {
      cli->index = index;
      cli->mode = RMAP_MODE;
    }

  return CLI_SUCCESS;
}

CLI (no_route_map,
     no_route_map_cmd,
     "no route-map WORD ((deny|permit) <1-65535>|)",
     CLI_NO_STR,
     CLI_ROUTEMAP_STR,
     "Route map tag",
     "Route map denies set operations",
     "Route map permits set operations",
     "Sequence to insert to/delete from existing route-map entry")
{
  u_int32_t pref;
  int permit;
  int ret;

  if (argc > 1)
    {
      /* Permit check. */
      if (pal_strncmp (argv[1], "permit", pal_strlen (argv[1])) == 0)
        permit = RMAP_PERMIT;
      else if (pal_strncmp (argv[1], "deny", pal_strlen (argv[1])) == 0)
        permit = RMAP_DENY;
      else
        {
          cli_out (cli, "%% The third field must be [permit|deny]\n");
          return CLI_ERROR;
        }

      CLI_GET_INTEGER_RANGE ("sequence", pref, argv[2], 1, 65535);

      ret = route_map_index_unset (cli->vr, argv[0], permit, pref);
    }
  else
    ret = route_map_unset (cli->vr, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (match_interface,
     match_interface_cmd,
     "match interface IFNAME",
     CLI_MATCH_STR,
     "Match first hop interface of route",
     CLI_IFNAME_STR)
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_interface_set (cli->vr, index->map->name,
                                       index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_interface,
     no_match_interface_cmd,
     "no match interface (IFNAME|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     "Match first hop interface of route",
     CLI_IFNAME_STR)
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_interface_unset (cli->vr, index->map->name,
                                         index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (match_metric,
     match_metric_cmd,
     "match metric <0-4294967295>",
     CLI_MATCH_STR,
     "Match metric of route",
     "Metric value")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_metric_set (cli->vr, index->map->name,
                                    index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_metric,
     no_match_metric_cmd,
     "no match metric (<0-4294967295>|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     "Match metric of route",
     "Metric value")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_metric_unset (cli->vr, index->map->name,
                                      index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_metric,
     set_metric_cmd,
     "set metric (<0-4294967295>|<+/-metric>)",
     CLI_SET_STR,
     "Metric value for destination routing protocol",
     "Metric value",
     "Add or subtract metric")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_set_metric_set (cli->vr, index->map->name,
                                  index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_set_metric,
     no_set_metric_cmd,
     "no set metric (<0-4294967295>|<+/-metric>|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "Metric value for destination routing protocol",
     "Metric value",
     "Add or subtract metric")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_set_metric_unset (cli->vr, index->map->name,
                                    index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

/* Configuration write function. */
int
route_map_config_encode (struct ipi_vr *vr, cfg_vect_t *cv)
{
  struct route_map *map;
  struct route_map_index *index;
  struct route_map_rule *rule;
  int first = 1;
  int write = 0;

  for (map = vr->route_map_master.head; map; map = map->next)
    for (index = map->head; index; index = index->next)
      {
        if (!first)
          cfg_vect_add_cmd (cv, "!\n");
        else
          first = 0;

        cfg_vect_add_cmd (cv, "route-map %s %s %d\n",
                 map->name, ROUTE_MAP_TYPE_STR (index->type), index->pref);

        for (rule = index->match_list.head; rule; rule = rule->next) {
          cfg_vect_add_cmd (cv, " match %s %s\n", rule->cmd->str,
                   rule->rule_str ? rule->rule_str : "");
        }
        for (rule = index->set_list.head; rule; rule = rule->next) {
          if (pal_strcmp (rule->cmd->str, "ip next-hop") != 0)
            {
              cfg_vect_add_cmd (cv, " set %s %s%s\n", rule->cmd->str,
                       rule->rule_str ? rule->rule_str : "",
                       CHECK_FLAG (rule->flags, ROUTE_MAP_FLAG_ADDITIVE)
                       ? " additive" : "");
            }
        else
            {
              cfg_vect_add_cmd (cv, " set %s %s", rule->cmd->str,
                               rule->rule_str ? rule->rule_str : "");

              cfg_vect_add_cmd (cv, " primary ");
              cfg_vect_add_cmd (cv, " %s\n", 
                         CHECK_FLAG (rule->flags, ROUTE_MAP_FLAG_ADDITIVE)
                         ? " additive" : "");
            }
        }
        write++;
      }
    if (write > 0) {
      cfg_vect_add_cmd (cv, "!\n");
    }
  return write;
}

int
route_map_config_write (struct cli *cli)
{
  cli->cv = cfg_vect_init(cli->cv);
  route_map_config_encode(cli->vr, cli->cv);
  cfg_vect_out(cli->cv, (cfg_vect_out_fun_t)cli->out_func, cli->out_val);
  return 0;
}

CLI (show_route_map,
     show_route_map_cmd,
     "show route-map (|WORD)",
     CLI_SHOW_STR,
     "route-map information",
     "route-map name")
{
  struct route_map *map = NULL;

  if (argc)
    {
      map = route_map_lookup_by_name(cli->vr, argv[0]);
      if (map)
        route_map_display (cli, map);
      else
        {
          cli_out (cli, "%% Can't find route-map name %s\n", argv[0]);
          return CLI_ERROR;
        }
    }
  else
    {
      for (map = cli->vr->route_map_master.head; map; map = map->next)
        route_map_display (cli, map);
    }

  return CLI_SUCCESS;
}

void
route_map_init_default (struct lib_globals *zg)
{
  struct cli_tree *ctree = zg->ctree;

  /* Install default commands. */
  cli_install_default (ctree, RMAP_MODE);
  cli_install_config (ctree, RMAP_MODE, route_map_config_write);

  /* Install configuration commands. */
  cli_install_imi (ctree, CONFIG_MODE, PM_RMAP, PRIVILEGE_NORMAL, 0,
                   &route_map_cmd);
  cli_set_imi_cmd (&route_map_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  cli_install_imi (ctree, CONFIG_MODE, PM_RMAP, PRIVILEGE_NORMAL, 0,
                   &no_route_map_cmd);

  /* "match interface". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_interface_cmd);
  cli_set_imi_cmd (&match_interface_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_interface_cmd);

  /* "match metric". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_metric_cmd);
  cli_set_imi_cmd (&match_metric_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_metric_cmd);

  /* "set metric". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_metric_cmd);
  cli_set_imi_cmd (&set_metric_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_metric_cmd);

  /* "show route-map". */
  cli_install_gen (zg->ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_route_map_cmd);
}


CLI (match_ip_addr,
     match_ip_addr_cmd,
     "match ip address (<1-199>|<1300-2699>|WORD)",
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match address of route",
     "IP access-list number",
     "IP access-list number (expanded range)",
     "IP access-list name")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_ip_address_set (cli->vr, index->map->name,
                                        index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_ip_addr,
     no_match_ip_addr_cmd,
     "no match ip address (<1-199>|<1300-2699>|WORD|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match address of route",
     "IP access-list number",
     "IP access-list number (expanded range)",
     "IP access-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_ip_address_unset (cli->vr, index->map->name,
                                          index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

/* "match ip address prefix-list" */
CLI (match_ip_addr_plist,
     match_ip_addr_plist_cmd,
     "match ip address prefix-list WORD",
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match address of route",
     "Match entries of prefix-lists",
     "IP prefix-list name")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_ip_address_prefix_list_set (cli->vr, index->map->name,
                                                    index->type, index->pref,
                                                    argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_ip_addr_plist,
     no_match_ip_addr_plist_cmd,
     "no match ip address prefix-list (WORD|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match address of route",
     "Match entries of prefix-lists",
     "IP prefix-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_ip_address_prefix_list_unset (cli->vr,
                                                      index->map->name,
                                                      index->type,
                                                      index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (match_ip_nexthop,
     match_ip_nexthop_cmd,
     "match ip next-hop (<1-199>|<1300-2699>|WORD)",
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match next-hop address of route",
     "IP access-list number",
     "IP access-list number (expanded range)",
     "IP Access-list name")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_ip_nexthop_set (cli->vr, index->map->name,
                                        index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_ip_nexthop,
     no_match_ip_nexthop_cmd,
     "no match ip next-hop (<1-199>|<1300-2699>|WORD|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match next-hop address of route",
     "IP access-list number",
     "IP access-list number (expanded range)",
     "IP Access-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_ip_nexthop_unset (cli->vr, index->map->name,
                                          index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (match_ip_peer,
     match_ip_peer_cmd,
     "match ip peer (<1-199>|<1300-2699>|WORD)",
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match peer address of route",
     "IP access-list number",
     "IP access-list number (expanded range)",
     "IP Access-list name")
{
  struct route_map_index *index = cli->index;
  int ret;
   
  ret = route_map_match_ip_peer_set (cli->vr, index->map->name,
                                     index->type, index->pref, argv[0]);
  return lib_vty_return (cli, ret);
}
 
CLI (no_match_ip_peer,
     no_match_ip_peer_cmd,
     "no match ip peer (<1-199>|<1300-2699>|WORD|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match peer address of route",
     "IP access-list number",
     "IP access-list number (expanded range)",
     "IP Access-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;
   
  ret = route_map_match_ip_peer_unset (cli->vr, index->map->name,
                                       index->type, index->pref, arg);
  return lib_vty_return (cli, ret);
}
#ifdef HAVE_IPV6
CLI (match_ipv6_peer,
     match_ipv6_peer_cmd,
     "match ipv6 peer (<1-199>|<1300-2699>|WORD)",
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match peer address of route",
     "IPv6 access-list number",
     "IP access-list number (expanded range)",
     "IP Access-list name")
{
  struct route_map_index *index = cli->index;
  int ret;
   
  ret = route_map_match_ipv6_peer_set (cli->vr, index->map->name,
                                     index->type, index->pref, argv[0]);
  return lib_vty_return (cli, ret);
}
 
CLI (no_match_ipv6_peer,
     no_match_ipv6_peer_cmd,
     "no match ipv6 peer (<1-199>|<1300-2699>|WORD|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match peer address of route",
     "IPv6 access-list number",
     "IP access-list number (expanded range)",
     "IP Access-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;
   
  ret = route_map_match_ipv6_peer_unset (cli->vr, index->map->name,
                                       index->type, index->pref, arg);
  return lib_vty_return (cli, ret);
}
#endif /*HAVE_IPV6*/

CLI (match_ip_nexthop_plist,
     match_ip_nexthop_plist_cmd,
     "match ip next-hop prefix-list WORD",
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match next-hop address of route",
     "Match entries of prefix-lists",
     "IP prefix-list name")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_ip_nexthop_prefix_list_set (cli->vr, index->map->name,
                                                    index->type, index->pref,
                                                    argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_ip_nexthop_plist,
     no_match_ip_nexthop_plist_cmd,
     "no match ip next-hop prefix-list (WORD|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     CLI_IP_STR,
     "Match next-hop address of route",
     "Match entries of prefix-lists",
     "IP prefix-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_ip_nexthop_prefix_list_unset (cli->vr,
                                                      index->map->name,
                                                      index->type,
                                                      index->pref, arg);

  return lib_vty_return (cli, ret);
}
CLI (set_ip_nexthop,
     set_ip_nexthop_cmd,
     "set ip next-hop A.B.C.D (interface IFNAME|) (primary|secondary |)",
     CLI_SET_STR,
     CLI_IP_STR,
     "Next hop address",
     "IP address of next hop",
     "Select an interface to configure",
     "Interface name",
     "Primary nexthop",
     "Secondary nexthop")
{
  struct route_map_index *index = cli->index;
  struct pal_in4_addr addr;
  int ret;
  char *ifname = NULL;
  s_int16_t nh_type = 0;
  int i; 
  CLI_GET_IPV4_ADDRESS ("next-hop", addr, argv[0]);

  for (i = 1; i < argc; i++)
    {
      if (pal_strncmp (argv[i], "p", 1) == 0)
        {
          nh_type = 0;
          break;
        }
      
      if (pal_strncmp (argv[i], "s", 1) == 0)
        {
          nh_type = 1;
          break;
        }

      if (pal_strncmp (argv[i], "i", 1) == 0)
        ifname = argv[++i];
    }

  ret = route_map_set_ip_nexthop_set (cli->vr, index->map->name,
                                      index->type, index->pref, argv[0],
                                      nh_type, ifname);

  return lib_vty_return (cli, ret);
}

CLI (no_set_ip_nexthop,
     no_set_ip_nexthop_cmd,
     "no set ip next-hop (A.B.C.D|) (interface IFNAME|) (primary|secondary |) ",
     CLI_NO_STR,
     CLI_SET_STR,
     CLI_IP_STR,
     "Next hop address",
     "IP address of next hop",
     "Select an interface to configure",
     "Interface name",
     "Primary nexthop",
     "Secondary nexthop")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;
  int nh_type = 0;
  char *ifname = NULL;
  int i;
  
  for (i = 1; i < argc; i++)
    {
      if (pal_strncmp (argv[i], "p", 1) == 0)
        {
          nh_type = 0;
          break;
        } 
      if (pal_strncmp (argv[i], "s", 1) == 0)
        {
          nh_type = 1;
          break;
        }
      if (pal_strncmp (argv[i], "i", 1) == 0)
        ifname = argv[++i];
          
    }

  ret = route_map_set_ip_nexthop_unset (cli->vr, index->map->name,
                                        index->type, index->pref, arg,
                                        nh_type, ifname);

  return lib_vty_return (cli, ret);
}

void
route_map_init_ipv4 (struct lib_globals *zg)
{
  /* "match ip address". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ip_addr_cmd);
  cli_set_imi_cmd (&match_ip_addr_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ip_addr_cmd);
  cli_set_imi_cmd (&no_match_ip_addr_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "match ip address prefix-list". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ip_addr_plist_cmd);
  cli_set_imi_cmd (&match_ip_addr_plist_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ip_addr_plist_cmd);
  cli_set_imi_cmd (&no_match_ip_addr_plist_cmd, RMAP_MODE, CFG_DTYP_RMAP);

   /* "match ip peer". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ip_peer_cmd);
  cli_set_imi_cmd (&match_ip_peer_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ip_peer_cmd);
  cli_set_imi_cmd (&no_match_ip_peer_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  
#ifdef HAVE_IPV6
   /* "match ip peer". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ipv6_peer_cmd);
  cli_set_imi_cmd (&match_ipv6_peer_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ipv6_peer_cmd);
  cli_set_imi_cmd (&no_match_ipv6_peer_cmd, RMAP_MODE, CFG_DTYP_RMAP);
#endif /*HAVE_IPV6*/
  
  /* "match ip next-hop". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ip_nexthop_cmd);
  cli_set_imi_cmd (&match_ip_nexthop_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ip_nexthop_cmd);
  cli_set_imi_cmd (&no_match_ip_nexthop_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "match ip next-hop prefix-list". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ip_nexthop_plist_cmd);
  cli_set_imi_cmd (&match_ip_nexthop_plist_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ip_nexthop_plist_cmd);
  cli_set_imi_cmd (&no_match_ip_nexthop_plist_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set ip next-hop". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_ip_nexthop_cmd);
  cli_set_imi_cmd (&set_ip_nexthop_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_ip_nexthop_cmd);
  cli_set_imi_cmd (&no_set_ip_nexthop_cmd, RMAP_MODE, CFG_DTYP_RMAP);
}


#ifdef HAVE_IPV6
CLI (match_ipv6_addr,
     match_ipv6_addr_cmd,
     "match ipv6 address WORD",
     CLI_MATCH_STR,
     CLI_IPV6_STR,
     "Match IPv6 address of route",
     "IPv6 access-list name")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_ipv6_address_set (cli->vr, index->map->name,
                                          index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_ipv6_addr,
     no_match_ipv6_addr_cmd,
     "no match ipv6 address (WORD|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     CLI_IPV6_STR,
     "Match IPv6 address of route",
     "IPv6 access-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_ipv6_address_unset (cli->vr, index->map->name,
                                            index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (match_ipv6_addr_plist,
     match_ipv6_addr_plist_cmd,
     "match ipv6 address prefix-list WORD",
     CLI_MATCH_STR,
     CLI_IPV6_STR,
     "Match address of route",
     "Match entries of prefix-lists",
     "IPv6 prefix-list name")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_ipv6_address_prefix_list_set (cli->vr,
                                                      index->map->name,
                                                      index->type, index->pref,
                                                      argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_ipv6_addr_plist,
     no_match_ipv6_addr_plist_cmd,
     "no match ipv6 address prefix-list (WORD|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     CLI_IPV6_STR,
     "Match address of route",
     "Match entries of prefix-lists",
     "IPv6 prefix-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_ipv6_address_prefix_list_unset (cli->vr,
                                                        index->map->name,
                                                        index->type,
                                                        index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (match_ipv6_nexthop,
     match_ipv6_nexthop_cmd,
     "match ipv6 next-hop (X:X::X:X|WORD)",
     CLI_MATCH_STR,
     CLI_IPV6_STR,
     "Match IPv6 next-hop address of route",
     "IPv6 address of next hop",
     "IPV6 access-list name")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_ipv6_nexthop_set (cli->vr, index->map->name,
                                          index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_ipv6_nexthop,
     no_match_ipv6_nexthop_cmd,
     "no match ipv6 next-hop (X:X::X:X|WORD|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     CLI_IPV6_STR,
     "Match IPv6 next-hop address of route",
     "IPv6 address of next hop",
     "IPV6 access-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_ipv6_nexthop_unset (cli->vr, index->map->name,
                                            index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (match_ipv6_nexthop_plist,
     match_ipv6_nexthop_plist_cmd,
     "match ipv6 next-hop prefix-list WORD",
     CLI_MATCH_STR,
     CLI_IPV6_STR,
     "Match IPv6 next-hop address of route",
     "Match entries of prefix-lists",
     "IPv6 prefix-list name")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_ipv6_nexthop_prefix_list_set (cli->vr,
                                                      index->map->name,
                                                      index->type, index->pref,
                                                      argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_ipv6_nexthop_plist,
     no_match_ipv6_nexthop_plist_cmd,
     "no match ipv6 next-hop prefix-list WORD",
     CLI_NO_STR,
     CLI_MATCH_STR,
     CLI_IPV6_STR,
     "Match IPv6 next-hop address of route",
     "Match entries of prefix-lists",
     "IPv6 prefix-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_ipv6_nexthop_prefix_list_unset (cli->vr,
                                                        index->map->name,
                                                        index->type,
                                                        index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_ipv6_nexthop,
     set_ipv6_nexthop_cmd,
     "set ipv6 next-hop X:X::X:X",
     CLI_SET_STR,
     CLI_IPV6_STR,
     "IPv6 next-hop address",
     "global address of next hop")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_set_ipv6_nexthop_set (cli->vr, index->map->name,
                                        index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

ALI (set_ipv6_nexthop,
     set_ipv6_nexthop_global_cmd,
     "set ipv6 next-hop global X:X::X:X",
     CLI_SET_STR,
     CLI_IPV6_STR,
     "IPv6 next-hop address",
     "IPv6 global address",
     "global address of next hop");

CLI (no_set_ipv6_nexthop,
     no_set_ipv6_nexthop_cmd,
     "no set ipv6 next-hop (X:X::X:X|)",
     CLI_NO_STR,
     CLI_SET_STR,
     CLI_IPV6_STR,
     "IPv6 next-hop address",
     "global address of next hop")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_set_ipv6_nexthop_unset (cli->vr, index->map->name,
                                          index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

ALI (no_set_ipv6_nexthop,
     no_set_ipv6_nexthop_global_cmd,
     "no set ipv6 next-hop global (X:X::X:X|)",
     CLI_NO_STR,
     CLI_SET_STR,
     CLI_IPV6_STR,
     "IPv6 next-hop address",
     "IPv6 global address",
     "global address of next hop");

CLI (set_ipv6_nexthop_local,
     set_ipv6_nexthop_local_cmd,
     "set ipv6 next-hop local X:X::X:X",
     CLI_SET_STR,
     CLI_IPV6_STR,
     "IPv6 next-hop address",
     "IPv6 local address",
     "IPv6 address of next hop")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_set_ipv6_nexthop_local_set (cli->vr, index->map->name,
                                              index->type, index->pref,
                                              argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_set_ipv6_nexthop_local,
     no_set_ipv6_nexthop_local_cmd,
     "no set ipv6 next-hop local (X:X::X:X|)",
     CLI_NO_STR,
     CLI_SET_STR,
     CLI_IPV6_STR,
     "IPv6 next-hop address",
     "IPv6 local address",
     "IPv6 address of next hop")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_set_ipv6_nexthop_local_unset (cli->vr, index->map->name,
                                                index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

void
route_map_init_ipv6 (struct lib_globals *zg)
{
  /* "match ipv6 address". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ipv6_addr_cmd);
  cli_set_imi_cmd (&match_ipv6_addr_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ipv6_addr_cmd);
  cli_set_imi_cmd (&no_match_ipv6_addr_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "match ipv6 address prefix-list". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ipv6_addr_plist_cmd);
  cli_set_imi_cmd (&match_ipv6_addr_plist_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ipv6_addr_plist_cmd);
  cli_set_imi_cmd (&no_match_ipv6_addr_plist_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "match ipv6 next-hop". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ipv6_nexthop_cmd);
  cli_set_imi_cmd (&match_ipv6_nexthop_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ipv6_nexthop_cmd);
  cli_set_imi_cmd (&no_match_ipv6_nexthop_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "match ipv6 next-hop prefix-list". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ipv6_nexthop_plist_cmd);
  cli_set_imi_cmd (&match_ipv6_nexthop_plist_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ipv6_nexthop_plist_cmd);
  cli_set_imi_cmd (&no_match_ipv6_nexthop_plist_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set ipv6 next-hop". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_ipv6_nexthop_cmd);
  cli_set_imi_cmd (&set_ipv6_nexthop_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_ipv6_nexthop_cmd);
  cli_set_imi_cmd (&no_set_ipv6_nexthop_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL_HIDDEN (zg, RMAP_MODE, PM_RMAP, &set_ipv6_nexthop_global_cmd);
  cli_set_imi_cmd (&set_ipv6_nexthop_global_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL_HIDDEN (zg, RMAP_MODE, PM_RMAP, &no_set_ipv6_nexthop_global_cmd);
  cli_set_imi_cmd (&no_set_ipv6_nexthop_global_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set ipv6 next-hop local". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_ipv6_nexthop_local_cmd);
  cli_set_imi_cmd (&set_ipv6_nexthop_local_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_ipv6_nexthop_local_cmd);
  cli_set_imi_cmd (&no_set_ipv6_nexthop_local_cmd, RMAP_MODE, CFG_DTYP_RMAP);
}
#endif /* HAVE_IPV6 */


CLI (match_tag,
     match_tag_cmd,
     "match tag <0-4294967295>",
     CLI_MATCH_STR,
     "Match tag",
     "Tag value")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_tag_set (cli->vr, index->map->name,
                                 index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_tag,
     no_match_tag_cmd,
     "no match tag (<0-4294967295>|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     "Match tag",
     "Tag value")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_tag_unset (cli->vr, index->map->name,
                                   index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_tag,
     set_tag_cmd,
     "set tag <0-4294967295>",
     CLI_SET_STR,
     "Tag value for destination routing protocol",
     "Tag value")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_set_tag_set (cli->vr, index->map->name,
                               index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_set_tag,
     no_set_tag_cmd,
     "no set tag (<0-4294967295>|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "Tag value for destination routing protocol",
     "Tag value")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_set_tag_unset (cli->vr, index->map->name,
                                 index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (match_aspath,
     match_aspath_cmd,
     "match as-path WORD",
     CLI_MATCH_STR,
     "Match BGP AS path list",
     "AS path access-list name")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_match_as_path_set (cli->vr, index->map->name,
                                     index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_match_aspath,
     no_match_aspath_cmd,
     "no match as-path (WORD|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     "Match BGP AS path list",
     "AS path access-list name")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_match_as_path_unset (cli->vr, index->map->name,
                                       index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (match_origin,
     match_origin_cmd,
     "match origin (egp|igp|incomplete)",
     CLI_MATCH_STR,
     "BGP origin code",
     "remote EGP",
     "local IGP",
     "unknown heritage")
{
  struct route_map_index *index = cli->index;
  char *arg;
  int ret;

  CLI_GET_RMAP_ORIGIN ("origin", arg, argc, argv[0]);
  if (! arg)
    return lib_vty_return (cli, RMAP_COMPILE_ERROR);

  ret = route_map_match_origin_set (cli->vr, index->map->name,
                                    index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (no_match_origin,
     no_match_origin_cmd,
     "no match origin (egp|igp|incomplete|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     "BGP origin code",
     "remote EGP",
     "local IGP",
     "unknown heritage")
{
  struct route_map_index *index = cli->index;
  char *arg;
  int ret;

  CLI_GET_RMAP_ORIGIN ("origin", arg, argc, argv[0]);

  ret = route_map_match_origin_unset (cli->vr, index->map->name,
                                      index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (match_community,
     match_community_cmd,
     "match community (<1-99>|<100-199>|WORD) (exact-match|)",
     CLI_MATCH_STR,
     "Match BGP community list",
     "Community-list number (standard)",
     "Community-list number (expanded)",
     "Community-list name",
     "Do exact matching of communities")
{
  struct route_map_index *index = cli->index;
  char *arg = NULL;
  int ret;
  int community_value = 0;

  if ( all_digit (argv[0])) {
     CLI_GET_INTEGER_RANGE("community", community_value, argv[0], 1, 199);
  }
  arg = argv_concat (argv, argc, 0);
  ret = route_map_match_community_set (cli->vr, index->map->name,
                                       index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

CLI (no_match_community,
     no_match_community_cmd,
     "no match community (<1-99>|<100-199>|WORD|) (exact-match|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     "Match BGP community list",
     "Community-list number (standard)",
     "Community-list number (expanded)",
     "Community-list name",
     "Do exact matching of communities")
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_match_community_unset (cli->vr, index->map->name,
                                         index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}
CLI (match_ecommunity,
     match_ecommunity_cmd,
     "match extcommunity (<1-99>|<100-199>|WORD) (exact-match|)",
     CLI_MATCH_STR,
     "Match BGP ecommunity list",
     "Community-list number (standard)",
     "Community-list number (expanded)",
     "Community-list name",
     "Do exact matching of ecommunities")
{
  struct route_map_index *index = cli->index;
  char *arg = NULL;
  int ret;
  int community_value = 0;
    
  if ( all_digit (argv[0])) {
     CLI_GET_INTEGER_RANGE("extcommunity", community_value, argv[0], 1, 199);
  }
  arg = argv_concat (argv, argc, 0);
  ret = route_map_match_ecommunity_set (cli->vr, index->map->name,
                                       index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

CLI (no_match_ecommunity,
     no_match_ecommunity_cmd,
     "no match extcommunity (<1-99>|<100-199>|WORD|) (exact-match|)",
     CLI_NO_STR,
     CLI_MATCH_STR,
     "Match BGP ecommunity list",
     "Community-list number (standard)",
     "Community-list number (expanded)",
     "Community-list name",
     "Do exact matching of ecommunities")
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_match_ecommunity_unset (cli->vr, index->map->name,
                                         index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}
#ifndef HAVE_EXT_CAP_ASN
CLI (set_as_path_prepend,
     set_as_path_prepend_cmd,
     "set as-path prepend .<1-65535>",
     CLI_SET_STR,
     "Prepend string for a BGP AS-path attribute",
     "Prepend to the as-path",
     "AS number")
#else
CLI (set_as_path_prepend,
     set_as_path_prepend_cmd,
     "set as-path prepend .<1-4294967295>",
     CLI_SET_STR,
     "Prepend string for a BGP AS-path attribute",
     "Prepend to the as-path",
     "AS number")
#endif /* HAVE_EXT_CAP_ASN */
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_set_as_path_prepend_set (cli->vr, index->map->name,
                                           index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}
#ifndef HAVE_EXT_CAP_ASN
CLI (no_set_as_path_prepend,
     no_set_as_path_prepend_cmd,
     "no set as-path prepend (.<1-65535>|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "Prepend string for a BGP AS-path attribute",
     "Prepend to the as-path",
     "AS number")
#else
CLI (no_set_as_path_prepend,
     no_set_as_path_prepend_cmd,
     "no set as-path prepend (.<1-4294967295>|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "Prepend string for a BGP AS-path attribute",
     "Prepend to the as-path",
     "AS number")
#endif /* HAVE_EXT_CAP_ASN */
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_set_as_path_prepend_unset (cli->vr, index->map->name,
                                             index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_origin,
     set_origin_cmd,
     "set origin (egp|igp|incomplete)",
     CLI_SET_STR,
     "BGP origin code",
     "remote EGP",
     "local IGP",
     "unknown heritage")
{
  struct route_map_index *index = cli->index;
  char *arg;
  int ret;

  CLI_GET_RMAP_ORIGIN ("origin", arg, argc, argv[0]);
  if (! arg)
    return lib_vty_return (cli, RMAP_COMPILE_ERROR);

  ret = route_map_set_origin_set (cli->vr, index->map->name,
                                  index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (no_set_origin,
     no_set_origin_cmd,
     "no set origin (egp|igp|incomplete|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP origin code",
     "remote EGP",
     "local IGP",
     "unknown heritage")
{
  struct route_map_index *index = cli->index;
  char *arg;
  int ret;

  CLI_GET_RMAP_ORIGIN ("origin", arg, argc, argv[0]);

  ret = route_map_set_origin_unset (cli->vr, index->map->name,
                                    index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_local_preference,
     set_local_preference_cmd,
     "set local-preference <0-4294967295>",
     CLI_SET_STR,
     "BGP local preference path attribute",
     "Preference value")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_set_local_preference_set (cli->vr, index->map->name,
                                            index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_set_local_preference,
     no_set_local_preference_cmd,
     "no set local-preference (<0-4294967295>|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP local preference path attribute",
     "Preference value")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_set_local_preference_unset (cli->vr, index->map->name,
                                              index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_weight,
     set_weight_cmd,
     "set weight <0-4294967295>",
     CLI_SET_STR,
     "BGP weight for routing table",
     "Weight value")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_set_weight_set (cli->vr, index->map->name,
                                  index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_set_weight,
     no_set_weight_cmd,
     "no set weight (<0-4294967295>|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP weight for routing table",
     "Weight value")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  int ret;

  ret = route_map_set_weight_unset (cli->vr, index->map->name,
                                    index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_atomic_aggregate,
     set_atomic_aggregate_cmd,
     "set atomic-aggregate",
     CLI_SET_STR,
     "BGP atomic aggregate attribute" )
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_set_atomic_aggregate_set (cli->vr, index->map->name,
                                            index->type, index->pref);

  return lib_vty_return (cli, ret);
}

CLI (no_set_atomic_aggregate,
     no_set_atomic_aggregate_cmd,
     "no set atomic-aggregate",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP atomic aggregate attribute" )
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_set_atomic_aggregate_unset (cli->vr, index->map->name,
                                              index->type, index->pref);

  return lib_vty_return (cli, ret);
}
#ifndef HAVE_EXT_CAP_ASN
CLI (set_aggregator_as,
     set_aggregator_as_cmd,
     "set aggregator as <1-65535> A.B.C.D",
     CLI_SET_STR,
     "BGP aggregator attribute",
     "AS number of aggregator",
     "AS number",
     "IP address of aggregator")
#else
CLI (set_aggregator_as,
     set_aggregator_as_cmd,
     "set aggregator as <1-4294967295> A.B.C.D",
     CLI_SET_STR,
     "BGP aggregator attribute",
     "AS number of aggregator",
     "AS number",
     "IP address of aggregator")
#endif /* HAVE_EXT_CAP_ASN */
{
  struct route_map_index *index = cli->index;
  struct pal_in4_addr addr;
  char *arg;
  int ret;
#ifndef HAVE_EXT_CAP_ASN
  int as;
#else
  unsigned int as;
#endif /* HAVE_EXT_CAP_ASN */
#ifndef HAVE_EXT_CAP_ASN
  CLI_GET_INTEGER_RANGE ("AS path", as, argv[0], 1, 65535);
#else
  CLI_GET_UINT32_RANGE ("AS path", as, argv[0], 1, 4294967295U);
#endif /* HAVE_EXT_CAP_ASN */

  CLI_GET_IPV4_ADDRESS ("aggregator IP address", addr, argv[1]);

  arg = argv_concat (argv, argc, 0);

  ret = route_map_set_aggregator_as_set (cli->vr, index->map->name,
                                         index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}
#ifndef HAVE_EXT_CAP_ASN
CLI (no_set_aggregator_as,
     no_set_aggregator_as_cmd,
     "no set aggregator as (<1-65535> A.B.C.D|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP aggregator attribute",
     "AS number of aggregator",
     "AS number",
     "IP address of aggregator")
#else
CLI (no_set_aggregator_as,
     no_set_aggregator_as_cmd,
     "no set aggregator as (<1-4294967295U> A.B.C.D|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP aggregator attribute",
     "AS number of aggregator",
     "AS number",
     "IP address of aggregator")
#endif /* HAVE_EXT_CAP_ASN */
{
  struct route_map_index *index = cli->index;
  struct pal_in4_addr addr;
  char *arg;
  int ret;
#ifndef HAVE_EXT_CAP_ASN
  int as;
#else
  unsigned int as;
#endif /* HAVE_EXT_CAP_ASN */

  if (argc > 0)
#ifndef HAVE_EXT_CAP_ASN
    CLI_GET_INTEGER_RANGE ("AS path", as, argv[0], 1, 65535);
#else
    CLI_GET_UINT32_RANGE ("AS path", as, argv[0], 1, 4294967295U);
#endif /* HAVE_EXT_CAP_ASN */

  if (argc > 1)
    CLI_GET_IPV4_ADDRESS ("aggregator IP address", addr, argv[1]);

  arg = argv_concat (argv, argc, 0);

  ret = route_map_set_aggregator_as_unset (cli->vr, index->map->name,
                                           index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_originator_id,
     set_originator_id_cmd,
     "set originator-id A.B.C.D",
     CLI_SET_STR,
     "BGP originator ID attribute",
     "IP address of originator")
{
  struct route_map_index *index = cli->index;
  struct pal_in4_addr addr;
  int ret;

  CLI_GET_IPV4_ADDRESS ("originator address", addr, argv[0]);

  ret = route_map_set_originator_id_set (cli->vr, index->map->name,
                                         index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_set_originator_id,
     no_set_originator_id_cmd,
     "no set originator-id (A.B.C.D|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP originator ID attribute",
     "IP address of originator")
{
  struct route_map_index *index = cli->index;
  char *arg = argc ? argv[0] : NULL;
  struct pal_in4_addr addr;
  int ret;

  if (arg)
    CLI_GET_IPV4_ADDRESS ("originator address", addr, arg);

  ret = route_map_set_originator_id_unset (cli->vr, index->map->name,
                                           index->type, index->pref, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_community_delete,
     set_community_delete_cmd,
     "set comm-list (<1-99>|<100-199>|WORD) delete",
     CLI_SET_STR,
     "set BGP community list (for deletion)",
     "Community-list number (standard)",
     "Communitly-list number (expanded)",
     "Community-list name",
     "Delete matching communities")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_set_community_delete_set (cli->vr, index->map->name,
                                            index->type, index->pref, argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (no_set_community_delete,
     no_set_community_delete_cmd,
     "no set comm-list (<1-99>|<100-199>|WORD) delete",
     CLI_NO_STR,
     CLI_SET_STR,
     "set BGP community list (for deletion)",
     "Community-list number (standard)",
     "Communitly-list number (expanded)",
     "Community-list name",
     "Delete matching communities")
{
  struct route_map_index *index = cli->index;
  int ret;

  ret = route_map_set_community_delete_unset (cli->vr, index->map->name,
                                              index->type, index->pref,
                                              argv[0]);

  return lib_vty_return (cli, ret);
}

CLI (set_community,
     set_community_cmd,
     "set community [<1-65535>|AA:NN|internet|local-AS|no-advertise|no-export] "
     "(additive|)",
     CLI_SET_STR,
     "BGP community attribute",
     "community number",
     "community number in aa:nn format",
     "Internet (well-known community)",
     "Do not send outside local AS (well-known community)",
     "Do not advertise to any peer (well-known community)",
     "Do not export to next AS (well-known community)",
     "Add to the existing community")
{
  struct route_map_index *index = cli->index;
  int additive = 0;
  char *arg;
  int ret;
  u_int32_t AA;
  u_int32_t NN;
  u_int16_t sret;
  u_int16_t i;
  char symbol;
  char extra;

  if (! pal_strncmp ("additive", argv[argc - 1], pal_strlen (argv[argc - 1])))
  {
    argc--;
    additive = 1;
  }
  arg = argv_concat (argv, argc, 0);

  /* check if arg is valid when additive is set*/
  if (additive && !arg)
    {
       cli_out (cli, "Invalid input: nothing to add \n");
       return CLI_ERROR;
    }

  for (i = 0; i < argc; i++)
    {
      if (!pal_strcmp(argv[i],"internet") || !pal_strcmp(argv[i],"local-AS") ||
          !pal_strcmp(argv[i],"no-advertise") || !pal_strcmp(argv[i],"no-export")
           || !pal_strcmp(argv[i],"additive") || !pal_strcmp(argv[i],"none"))
       {
         continue;
       }
       else
       {
         sret = pal_sscanf(argv[i],"%u%c%u%c",&AA,&symbol,&NN,&extra);
         if ((sret == 1 && AA >= 1 && AA <= 65535) ||
             (sret == 3 && symbol == ':' && AA < 65535 && NN < 65535)) {
            continue;
          }
         else {
             break;
          }
        }
     }
  if (i >= argc) {
    ret = route_map_set_community_set (cli->vr, index->map->name, index->type,
                                         index->pref, arg, additive);
  }
  else {
    ret = LIB_API_SET_ERR_INVALID_VALUE;
  }
  if (arg) {
    XFREE (MTYPE_TMP, arg);
  }
  return lib_vty_return (cli, ret);
}

ALI (set_community,
     set_community_none_cmd,
     "set community (none)",
     CLI_SET_STR,
     "BGP community attribute",
     "No community attribute");

CLI (no_set_community,
     no_set_community_cmd,
     "no set community [AA:NN|internet|local-AS|no-advertise|no-export] "
     "(additive|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP communty attribute",
     "community number in aa:nn format",
     "Internet (well-known community)",
     "Do not send outside local AS (well-known community)",
     "Do not advertise to any peer (well-known community)",
     "Do not export to next AS (well-known community)",
     "Add to the existing community")
{
  struct route_map_index *index = cli->index;
  char *arg;
  int ret;

  if (! pal_strncmp ("additive", argv[argc - 1], pal_strlen (argv[argc - 1])))
    argc--;

  arg = argv_concat (argv, argc, 0);

  ret = route_map_set_community_unset (cli->vr, index->map->name,
                                       index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

ALI (no_set_community,
     no_set_community_none_cmd,
     "no set community (none)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP community attribute",
     "No community attribute");

CLI (set_community_additive,
     set_community_additive_cmd,
     "set community-additive .AA:NN",
     CLI_SET_STR,
     "BGP community attribute (Add to the existing community)",
     "Community number in aa:nn format or local-AS|no-advertise|no-export")
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int additive = 1;
  int ret;

  ret = route_map_set_community_set (cli->vr, index->map->name,
                                     index->type, index->pref, arg, additive);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

CLI (no_set_community_additive,
     no_set_community_additive_cmd,
     "no set community-additive (.AA:NN|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP community attribute (Add to the existing community)",
     "Community number in aa:nn format or local-AS|no-advertise|no-export")
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_set_community_unset (cli->vr, index->map->name,
                                       index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_extcommunity_rt,
     set_extcommunity_rt_cmd,
     "set extcommunity rt .AA:NN",
     CLI_SET_STR,
     "BGP extended community attribute",
     "Route Target extended community",
     "VPN extended community")
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_set_ext_community_rt_set (cli->vr, index->map->name,
                                            index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

CLI (no_set_extcommunity_rt,
     no_set_extcommunity_rt_cmd,
     "no set extcommunity rt (.AA:NN|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP extended community attribute",
     "Route Target extended community",
     "VPN extended community")
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_set_ext_community_rt_unset (cli->vr, index->map->name,
                                              index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_extcommunity_soo,
     set_extcommunity_soo_cmd,
     "set extcommunity soo .AA:NN",
     CLI_SET_STR,
     "BGP extended community attribute",
     "Site-of-Origin extended community",
     "VPN extended community")
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_set_ext_community_soo_set (cli->vr, index->map->name,
                                             index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

CLI (no_set_extcommunity_soo,
     no_set_extcommunity_soo_cmd,
     "no set extcommunity soo (.AA:NN|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "BGP extended community attribute",
     "Site-of-Origin extended community",
     "VPN extended community")
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_set_ext_community_soo_unset (cli->vr, index->map->name,
                                               index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

CLI (set_dampening,
     set_dampening_cmd,
     "set dampening <1-45> <1-20000> <1-20000> <1-255> (<1-45>|)",
     CLI_SET_STR,
     "Enable route-flap dampening",
     "Reachability Half-life time for the penalty(minutes)",
     "Value to start reusing a route",
     "Value to start suppressing a route",
     "Maximum duration to suppress a stable route(minutes)",
     "Un-reachability Half-life time for the penalty(minutes)")
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_set_dampening_set (cli->vr, index->map->name,
                                     index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

ALI (set_dampening,
     set_dampening2_cmd,
     "set dampening (<1-45>|)",
     CLI_SET_STR,
     "Enable route-flap dampening",
     "Reachability Half-life time for the penalty(minutes)");

CLI (no_set_dampening,
     no_set_dampening_cmd,
     "no set dampening <1-45> <1-20000> <1-20000> <1-255> (<1-45>|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "Enable route-flap dampening",
     "Reachability Half-life time for the penalty(minutes)",
     "Value to start reusing a route",
     "Value to start suppressing a route",
     "Maximum duration to suppress a stable route(minutes)",
     "Un-reachability Half-life time for the penalty(minutes)")
{
  struct route_map_index *index = cli->index;
  char *arg = argv_concat (argv, argc, 0);
  int ret;

  ret = route_map_set_dampening_unset (cli->vr, index->map->name,
                                       index->type, index->pref, arg);

  if (arg)
    XFREE (MTYPE_TMP, arg);

  return lib_vty_return (cli, ret);
}

ALI (no_set_dampening,
     no_set_dampening2_cmd,
     "no set dampening (<1-45>|)",
     CLI_NO_STR,
     CLI_SET_STR,
     "Enable route-flap dampening",
     "Reachability Half-life time for the penalty(minutes)");

void
route_map_init_bgp (struct lib_globals *zg)
{
  /* "match as-path". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_aspath_cmd);
  cli_set_imi_cmd (&match_aspath_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_aspath_cmd);
  cli_set_imi_cmd (&no_match_aspath_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "match origin". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_origin_cmd);
  cli_set_imi_cmd (&match_origin_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_origin_cmd);
  cli_set_imi_cmd (&no_match_origin_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "match community". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_community_cmd);
  cli_set_imi_cmd (&match_community_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_community_cmd);
  cli_set_imi_cmd (&no_match_community_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "match ecommunity". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_ecommunity_cmd);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_ecommunity_cmd);

  /* "set as-path prepend". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_as_path_prepend_cmd);
  cli_set_imi_cmd (&set_as_path_prepend_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_as_path_prepend_cmd);
  cli_set_imi_cmd (&no_set_as_path_prepend_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set origin". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_origin_cmd);
  cli_set_imi_cmd (&set_origin_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_origin_cmd);
  cli_set_imi_cmd (&no_set_origin_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set local-preference". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_local_preference_cmd);
  cli_set_imi_cmd (&set_local_preference_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_local_preference_cmd);
  cli_set_imi_cmd (&no_set_local_preference_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set weight". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_weight_cmd);
  cli_set_imi_cmd (&set_weight_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_weight_cmd);
  cli_set_imi_cmd (&no_set_weight_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set atomic-aggregate". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_atomic_aggregate_cmd);
  cli_set_imi_cmd (&set_atomic_aggregate_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_atomic_aggregate_cmd);
  cli_set_imi_cmd (&no_set_atomic_aggregate_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set aggregator as". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_aggregator_as_cmd);
  cli_set_imi_cmd (&set_aggregator_as_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_aggregator_as_cmd);
  cli_set_imi_cmd (&no_set_aggregator_as_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set originator-id". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_originator_id_cmd);
  cli_set_imi_cmd (&set_originator_id_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_originator_id_cmd);
  cli_set_imi_cmd (&no_set_originator_id_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set comm-list delete". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_community_delete_cmd);
  cli_set_imi_cmd (&set_community_delete_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_community_delete_cmd);
  cli_set_imi_cmd (&no_set_community_delete_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set community". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_community_cmd);
  cli_set_imi_cmd (&set_community_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_community_none_cmd);
  cli_set_imi_cmd (&set_community_none_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_community_cmd);
  cli_set_imi_cmd (&no_set_community_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_community_none_cmd);
  cli_set_imi_cmd (&no_set_community_none_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set community-additive". */
  CLI_INSTALL_HIDDEN (zg, RMAP_MODE, PM_RMAP, &set_community_additive_cmd);
  cli_set_imi_cmd (&set_community_additive_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL_HIDDEN (zg, RMAP_MODE, PM_RMAP, &no_set_community_additive_cmd);
  cli_set_imi_cmd (&no_set_community_additive_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set extcommunity rt". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_extcommunity_rt_cmd);
  cli_set_imi_cmd (&set_extcommunity_rt_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_extcommunity_rt_cmd);
  cli_set_imi_cmd (&no_set_extcommunity_rt_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set extcommunity soo". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_extcommunity_soo_cmd);
  cli_set_imi_cmd (&set_extcommunity_soo_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_extcommunity_soo_cmd);
  cli_set_imi_cmd (&no_set_extcommunity_soo_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "set dampening". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_dampening_cmd);
  cli_set_imi_cmd (&set_dampening_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &set_dampening2_cmd);
  cli_set_imi_cmd (&set_dampening2_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_dampening_cmd);
  cli_set_imi_cmd (&no_set_dampening_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_set_dampening2_cmd);
  cli_set_imi_cmd (&no_set_dampening2_cmd, RMAP_MODE, CFG_DTYP_RMAP);

  /* "match tag". */
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &match_tag_cmd);
  cli_set_imi_cmd (&match_tag_cmd, RMAP_MODE, CFG_DTYP_RMAP);
  CLI_INSTALL (zg, RMAP_MODE, PM_RMAP, &no_match_tag_cmd);
  cli_set_imi_cmd (&no_match_tag_cmd, RMAP_MODE, CFG_DTYP_RMAP);
}

void
route_map_init (struct ipi_vr *vr)
{
  vr->route_match_vec = vector_init (1);
  vr->route_set_vec = vector_init (1);

  route_map_install_match_default (vr, &route_map_interface_cmd);
  route_map_install_match_default (vr, &route_map_metric_cmd);
  route_map_install_set_default (vr, &route_map_metric_cmd);

  route_map_install_match_default (vr, &route_map_ip_addr_cmd);
  route_map_install_match_default (vr, &route_map_ip_addr_plist_cmd);
  route_map_install_match_default (vr, &route_map_ip_nexthop_cmd);
  route_map_install_match_default (vr, &route_map_ip_peer_cmd);
#ifdef HAVE_IPV6
  route_map_install_match_default (vr, &route_map_ipv6_peer_cmd);
#endif /*HAVE_IPV6*/
  route_map_install_match_default (vr, &route_map_ip_nexthop_plist_cmd);
  route_map_install_set_default (vr, &route_map_ip_nexthop_cmd);

#ifdef HAVE_IPV6
  route_map_install_match_default (vr, &route_map_ipv6_addr_cmd);
  route_map_install_match_default (vr, &route_map_ipv6_addr_plist_cmd);
  route_map_install_match_default (vr, &route_map_ipv6_nexthop_cmd);
  route_map_install_match_default (vr, &route_map_ipv6_nexthop_plist_cmd);
  route_map_install_set_default (vr, &route_map_ipv6_nexthop_cmd);
  route_map_install_set_default (vr, &route_map_ipv6_nexthop_local_cmd);
#endif /* HAVE_IPV6 */

  route_map_install_match_default (vr, &route_map_tag_cmd);
  route_map_install_match_default (vr, &route_map_route_type_cmd);
  route_map_install_set_default (vr, &route_map_tag_cmd);
  route_map_install_set_default (vr, &route_map_metric_type_cmd);

  route_map_install_set_default (vr, &route_map_level_cmd);

  route_map_install_match_default (vr, &route_map_as_path_cmd);
  route_map_install_match_default (vr, &route_map_origin_cmd);
  route_map_install_match_default (vr, &route_map_community_cmd);
  route_map_install_match_default (vr, &route_map_ecommunity_cmd);
  route_map_install_set_default (vr, &route_map_as_path_prepend_cmd);
  route_map_install_set_default (vr, &route_map_origin_cmd);
  route_map_install_set_default (vr, &route_map_local_preference_cmd);
  route_map_install_set_default (vr, &route_map_weight_cmd);
  route_map_install_set_default (vr, &route_map_atomic_aggregate_cmd);
  route_map_install_set_default (vr, &route_map_aggregator_as_cmd);
  route_map_install_set_default (vr, &route_map_originator_id_cmd);
  route_map_install_set_default (vr, &route_map_community_delete_cmd);
  route_map_install_set_default (vr, &route_map_community_cmd);
  route_map_install_set_default (vr, &route_map_ecommunity_cmd);
  route_map_install_set_default (vr, &route_map_extcommunity_rt_cmd);
  route_map_install_set_default (vr, &route_map_extcommunity_soo_cmd);
  route_map_install_set_default (vr, &route_map_dampening_cmd);
}

void
route_map_finish (struct ipi_vr *vr)
{
  vector_free (vr->route_match_vec);
  vector_free (vr->route_set_vec);
}

void
route_map_cli_init (struct lib_globals *zg)
{
  /* Install default route map CLIs. */
  route_map_init_default (zg);

  /* Install IPv4 route map CLIs. */
  route_map_init_ipv4 (zg);

#ifdef HAVE_IPV6
  /* Install IPv6 route map CLIs. */
  route_map_init_ipv6 (zg);
#endif /* HAVE_IPV6 */

  /* Install BGP specific route map CLIs. */
  route_map_init_bgp (zg);
}
