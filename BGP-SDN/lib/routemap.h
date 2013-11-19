/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_ROUTEMAP_H
#define _BGPSDN_ROUTEMAP_H

#include "prefix.h"



#define   PBR_ROUTE_MAP_MATCH_COMMAND        "ip address"
#define   PBR_ROUTE_MAP_SET_COMMAND          "ip next-hop"

/* Route map's type */
enum route_map_type
{
  RMAP_PERMIT,
  RMAP_DENY,
  RMAP_ANY
};

typedef enum
{
  RMAP_MATCH,
  RMAP_DENYMATCH,
  RMAP_NOMATCH,
  RMAP_ERROR,
  RMAP_OKAY
} route_map_result_t;

typedef enum
{
  RMAP_EVENT_SET_ADDED,
  RMAP_EVENT_SET_DELETED,
  RMAP_EVENT_SET_REPLACED,
  RMAP_EVENT_MATCH_ADDED,
  RMAP_EVENT_MATCH_DELETED,
  RMAP_EVENT_MATCH_REPLACED,
  RMAP_EVENT_INDEX_ADDED,
  RMAP_EVENT_INDEX_DELETED
} route_map_event_t;

typedef enum
{
  RMAP_UPDATE_HOOK,
  RMAP_DELETE_HOOK,
  RMAP_EVENT_HOOK
} RMAP_HOOK;


enum nexthop_type
{
  NEXTHOP_PRIMARY,
  NEXTHOP_SECONDARY
};

struct route_map_rule;

/* Route map rule structure for matching and setting. */
struct route_map_rule_cmd
{

  /* Route map rule name (e.g. as-path, metric) */
  char *str;

  /* Function for value set or match. */
  route_map_result_t (*func_apply) (void *, struct prefix *,
                                    struct route_map_rule *rule, void *);

  /* Compile argument and return result as void *. */
  void *(*func_compile) (char *);

  /* Free allocated value by func_compile (). */
  void (*func_free) (void *);

  /* Commentary for "show route-map". */
  char *comment;
};

/* Route map apply error. */
enum
{
  /* Route map rule is missing. */
  RMAP_RULE_MISSING = 1,

  /* Route map rule can't compile */
  RMAP_COMPILE_ERROR
};

/* Route map rule list. */
struct route_map_rule_list
{
  struct route_map_rule *head;
  struct route_map_rule *tail;
};

/* Route map index structure. */
struct route_map_index
{
  struct route_map *map;

  /* Preference of this route map rule. */
  s_int32_t pref;

  /* Route map type permit or deny. */
  enum route_map_type type;

  /* If we're using "GOTO", to where do we go? */
  s_int32_t nextpref;

  /* Matching rule list. */
  struct route_map_rule_list match_list;
  struct route_map_rule_list set_list;

  /* Make linked list. */
  struct route_map_index *next;
  struct route_map_index *prev;
};

/* Route map list structure. */
struct route_map
{
  /* Name of route map. */
  char *name;

  /* Route map's rule. */
  struct route_map_index *head;
  struct route_map_index *tail;

  /* Make linked list. */
  struct route_map *next;
  struct route_map *prev;
};

/* Route map rule. This rule has both `match' rule and `set' rule. */
struct route_map_rule
{
  /* Rule type. */
  struct route_map_rule_cmd *cmd;

  /* For pretty printing. */
  char *rule_str;

  /* Pre-compiled match rule. */
  void *value;

  /* Linked list. */
  struct route_map_rule *next;
  struct route_map_rule *prev;

  /* Flags for special action.  */
#define ROUTE_MAP_FLAG_PRIORITY      (1 << 0)
#define ROUTE_MAP_FLAG_ADDITIVE      (1 << 1)
  u_char flags;
};

/* SNMP Community string */
struct snmpCommunity
{
  char *current_community;
  void (*event_hook) (struct ipi_vr *, char *);
};

/* Making route map list. */
struct route_map_list
{
  struct route_map *head;
  struct route_map *tail;

  void (*add_hook) (struct ipi_vr *, char *);
  void (*delete_hook) (struct ipi_vr *, char *);
  void (*event_hook) (struct ipi_vr *, route_map_event_t, char *);
};

/* Match interface structure */
 struct match_interface
 {
   /* Name of route map. */
   char *rmname;
 
   /* Preference of route map rule. */
   s_int32_t pref;
 
   /* Route map type permit or deny. */
   enum route_map_type type;

};

#define ROUTE_MAP_TYPE_STR(T)                                                 \
    ((T) == RMAP_PERMIT ? "permit" : (T) == RMAP_DENY ? "deny" : "")

route_map_result_t
route_map_alist2rmap_rcode (enum filter_type);
route_map_result_t
route_map_plist2rmap_rcode (enum prefix_list_type);
void route_map_install_set (struct ipi_vr *, struct route_map_rule_cmd *);
void route_map_install_match (struct ipi_vr *, struct route_map_rule_cmd *);
void route_map_add_hook (struct ipi_vr *,
                         void (*func) (struct ipi_vr *, char *));
void route_map_delete_hook (struct ipi_vr *,
                            void (*func) (struct ipi_vr *, char *));
void route_map_event_hook (struct ipi_vr *,
                           void (*func) (struct ipi_vr *, route_map_event_t,
                                         char *));

route_map_result_t route_map_apply (struct route_map *,
                                    struct prefix *, void *);
struct route_map *route_map_lookup_by_name (struct ipi_vr *, char *);

struct route_map_index *route_map_index_install (struct ipi_vr *, char *, int,
                                                 int);
int route_map_uninstall (struct ipi_vr *, char *);
int route_map_index_uninstall (struct ipi_vr *, char *, int, int);
void route_map_index_delete (struct ipi_vr *, struct route_map_index *, int);

int route_map_match_set (struct ipi_vr *, char *, int, int, char *, char *);
int route_map_match_unset (struct ipi_vr *, char *, int, int, char *, char *);
int route_map_set_set (struct ipi_vr *, char *, int, int, char *, char *, int);
int route_map_set_unset (struct ipi_vr *, char *, int, int, char *, char *);

void route_map_init (struct ipi_vr *);
void route_map_finish (struct ipi_vr *);
void route_map_cli_init (struct lib_globals *);
int route_map_config_write (struct cli *);
int route_map_config_encode (struct ipi_vr *vr, cfg_vect_t *cv);
struct route_map_rule_cmd * route_map_lookup_match (struct ipi_vr *vr, 
                                                    char *name);
int route_map_set_set_nexthop (struct ipi_vr *vr, char *name, int direct, 
                               int pref, char *command, char *nexthop, 
                               s_int16_t nh_type, char *ifname, int flags);
int route_map_set_unset_nexthop (struct ipi_vr *vr, char *name, int direct,
                                 int pref, char *command, char *nexthop,
                                 s_int16_t nh_type, char *ifname);
struct route_map_rule_cmd * route_map_lookup_set (struct ipi_vr *vr, char *name);

#endif /* _BGPSDN_ROUTEMAP_H */
