/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_CLIST_H
#define _BGPSDN_BGP_CLIST_H

/* Community types */
enum community_type
{
  COMMUNITY_NO_MATCH,
  COMMUNITY_DENY,
  COMMUNITY_PERMIT
};

/* Number and string based community-list name.  */
enum community_name_type
{
  COMMUNITY_LIST_STRING,
  COMMUNITY_LIST_NUMBER
};

/* Community-list entry types.  */
enum community_list_type
{
  COMMUNITY_LIST_STANDARD,              /* Standard community-list.  */
  COMMUNITY_LIST_EXPANDED,              /* Expanded community-list.  */
  COMMUNITY_LIST_AUTO,                  /* Automatically detected.  */
  EXTCOMMUNITY_LIST_STANDARD,           /* Standard extcommunity-list.  */
  EXTCOMMUNITY_LIST_EXPANDED,           /* Expanded extcommunity-list.  */
  EXTCOMMUNITY_LIST_AUTO                /* Automatically detected.  */
};

/* Community-list.  */
struct community_list
{
  /* Name of the community-list.  */
  u_int8_t *name;

  /* String or number.  */
  int sort;

  /* Link to upper list.  */
  struct community_list_list *parent;

  /* Linked list for other community-list.  */
  struct community_list *next;
  struct community_list *prev;

  /* Community-list entry in this community-list.  */
  struct community_entry *head;
  struct community_entry *tail;
};

/* Each entry in community-list */
struct community_entry
{
  struct community_entry *next;
  struct community_entry *prev;

  /* Permit or deny */
  enum community_type direct;

  /* Standard or expanded */
  u_int8_t style;

  /* Any match */
  u_int8_t any;

  /* Community structure */
  union
  {
    struct community *com;
    struct ecommunity *ecom;
  } u;

  /* Configuration string */
  u_int8_t *config;

  /* Expanded community-list regular expression */
  pal_regex_t *reg;
};

/* Linked list of community-list */
struct community_list_list
{
  struct community_list *head;
  struct community_list *tail;
};

/* Master structure of community-list and extcommunity-list */
struct community_list_master
{
  struct community_list_list num;
  struct community_list_list str;
};

/* Community-list handler */
struct community_list_handler
{
  /* Community-list */
  struct community_list_master community_list;

  /* Exteded community-list */
  struct community_list_master extcommunity_list;
};

/* Prototypes */
s_int32_t
community_list_set (struct community_list_handler *,
                    u_int8_t *, u_int8_t *,
                    enum community_type,
                    enum community_list_type);
s_int32_t
community_list_unset (struct community_list_handler *,
                      u_int8_t *, u_int8_t *,
                      enum community_type,
                      enum community_list_type);
s_int32_t
extcommunity_list_set (struct community_list_handler *,
                       u_int8_t *, u_int8_t *,
                       enum community_type,
                       enum community_list_type);
s_int32_t
extcommunity_list_unset (struct community_list_handler *,
                         u_int8_t *, u_int8_t *,
                         enum community_type,
                         enum community_list_type);

struct community_list_master *
community_list_master_lookup (struct community_list_handler *,
                              enum community_list_type);
struct community_list *
community_list_lookup (struct community_list_handler *,
                       u_int8_t *name,
                       enum community_list_type style);
enum community_type
community_list_match (struct community *,
                      struct community_list *);
enum community_type
community_list_exact_match (struct community *,
                            struct community_list *);
struct community *
community_list_match_delete (struct community *,
                             struct community_list *);
struct community_list_handler *
bgp_community_list_init (void);
s_int32_t
bgp_community_list_terminate (struct community_list_handler *);

enum community_type ecommunity_list_exact_match (struct ecommunity *ecom,
                                                 struct community_list *list);
enum community_type ecommunity_list_match (struct ecommunity *ecom,
                                           struct community_list *list);
#endif /* _BGPSDN_BGP_CLIST_H */
