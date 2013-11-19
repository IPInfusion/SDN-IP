/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_FILTER_H
#define _BGPSDN_BGP_FILTER_H

enum as_filter_type
{
  AS_FILTER_NO_MATCH,
  AS_FILTER_DENY,
  AS_FILTER_PERMIT
};

/* List of AS filter list. */
struct as_list_list
{
  struct as_list *head;
  struct as_list *tail;
};

/* AS path filter master. */
struct bgp_as_list_master
{
  /* List of access_list which name is number. */
  struct as_list_list num;

  /* List of access_list which name is string. */
  struct as_list_list str;

  /* Hook function which is executed when new access_list is added. */
  void (*add_hook) ();

  /* Hook function which is executed when access_list is deleted. */
  void (*delete_hook) ();
};

/* Element of AS path filter. */
struct as_filter
{
  struct as_filter *next;
  struct as_filter *prev;

  enum as_filter_type type;

  pal_regex_t *reg;
  char *reg_str;
};

/* AS path filter list. */
struct as_list
{
  char *name;

  enum access_type type;

  struct as_list *next;
  struct as_list *prev;

  struct as_filter *head;
  struct as_filter *tail;
};

struct bgp_as_list_master *
bgp_as_list_init (void);
void
bgp_as_list_terminate (struct bgp_as_list_master *);
enum as_filter_type as_list_apply (struct as_list *, void *);

struct as_list *as_list_lookup (char *);
void as_list_add_hook (void (*func) ());
void as_list_delete_hook (void (*func) ());

int as_list_entry_make (char *, char *, enum as_filter_type);
int as_list_entry_delete (char *, char *, enum as_filter_type);
void
bgp_filter_cli_init (void);

#endif /* _BGPSDN_BGP_FILTER_H */
