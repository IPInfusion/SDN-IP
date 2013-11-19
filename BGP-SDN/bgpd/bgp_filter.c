/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/* Initialize as-list-master. Return bgp_aslist_master */
struct bgp_as_list_master *
bgp_as_list_init (void)
{
  struct bgp_as_list_master *aslist_master;

  aslist_master = XCALLOC (MTYPE_AS_LIST_MASTER,
                           sizeof (struct bgp_as_list_master));

  return aslist_master;
}

/* Terminate aslist_master  */
void
bgp_as_list_terminate (struct bgp_as_list_master *aslist_master)
{
  XFREE (MTYPE_AS_LIST_MASTER, aslist_master);

  return;
}

/* Allocate new AS filter. */
struct as_filter *
as_filter_new ()
{
  struct as_filter *new;

  new = XMALLOC (MTYPE_AS_FILTER, sizeof (struct as_filter));
  pal_mem_set (new, 0, sizeof (struct as_filter));
  return new;
}

/* Free allocated AS filter. */
void
as_filter_free (struct as_filter *asfilter)
{
  if (asfilter->reg)
    bgp_regex_free (asfilter->reg);
  if (asfilter->reg_str)
    XFREE (MTYPE_AS_FILTER_STR, asfilter->reg_str);
  XFREE (MTYPE_AS_FILTER, asfilter);
}

/* Make new AS filter. */
struct as_filter *
as_filter_make (pal_regex_t *reg, char *reg_str, enum as_filter_type type)
{
  struct as_filter *asfilter;

  asfilter = as_filter_new ();
  asfilter->reg = reg;
  asfilter->type = type;
  asfilter->reg_str = XSTRDUP (MTYPE_AS_FILTER_STR, reg_str);

  return asfilter;
}

struct as_filter *
as_filter_lookup (struct as_list *aslist, char *reg_str,
                  enum as_filter_type type)
{
  struct as_filter *asfilter;

  for (asfilter = aslist->head; asfilter; asfilter = asfilter->next)
    if (pal_strcmp (reg_str, asfilter->reg_str) == 0)
      return asfilter;
  return NULL;
}

void
as_list_filter_add (struct as_list *aslist, struct as_filter *asfilter)
{
  asfilter->next = NULL;
  asfilter->prev = aslist->tail;

  if (aslist->tail)
    aslist->tail->next = asfilter;
  else
    aslist->head = asfilter;
  aslist->tail = asfilter;
}

/* Lookup as_list from list of as_list by name. */
struct as_list *
as_list_lookup (char *name)
{
  struct as_list *aslist;

  if (name == NULL)
    return NULL;

  for (aslist = bgp_aslist_master->num.head; aslist; aslist = aslist->next)
    if (pal_strcmp (aslist->name, name) == 0)
      return aslist;

  for (aslist = bgp_aslist_master->str.head; aslist; aslist = aslist->next)
    if (pal_strcmp (aslist->name, name) == 0)
      return aslist;

  return NULL;
}

struct as_list *
as_list_new ()
{
  struct as_list *new;

  new = XMALLOC (MTYPE_AS_LIST, sizeof (struct as_list));
  pal_mem_set (new, 0, sizeof (struct as_list));
  return new;
}

void
as_list_free (struct as_list *aslist)
{
  if (aslist->name)
    XFREE (MTYPE_TMP, aslist->name);
  XFREE (MTYPE_AS_LIST, aslist);
}

/* Insert new AS list to list of as_list.  Each as_list is sorted by
   the name. */
struct as_list *
as_list_insert (char *name)
{
  int i;
  s_int32_t number;
  struct as_list *aslist;
  struct as_list *point;
  struct as_list_list *list;

  /* Allocate new access_list and copy given name. */
  aslist = as_list_new ();
  aslist->name = XSTRDUP (MTYPE_TMP, name);

  /* If name is made by all digit character.  We treat it as
     number. */
  for (number = 0, i = 0; i < pal_strlen (name); i++)
    {
      if (pal_char_isdigit ((int) name[i]))
        number = (number * 10) + (name[i] - '0');
      else
        break;
    }

  /* In case of name is all digit character */
  if (i == pal_strlen (name))
    {
      aslist->type = ACCESS_TYPE_NUMBER;

      /* Set access_list to number list. */
      list = &bgp_aslist_master->num;

      for (point = list->head; point; point = point->next)
        if (pal_strtos32 (point->name, (char **)NULL, 10) >= number)
          break;
    }
  else
    {
      aslist->type = ACCESS_TYPE_STRING;

      /* Set access_list to string list. */
      list = &bgp_aslist_master->str;

      /* Set point to insertion point. */
      for (point = list->head; point; point = point->next)
        if (pal_strcmp (point->name, name) >= 0)
          break;
    }

  /* In case of this is the first element of master. */
  if (list->head == NULL)
    {
      list->head = list->tail = aslist;
      return aslist;
    }

  /* In case of insertion is made at the tail of access_list. */
  if (point == NULL)
    {
      aslist->prev = list->tail;
      list->tail->next = aslist;
      list->tail = aslist;
      return aslist;
    }

  /* In case of insertion is made at the head of access_list. */
  if (point == list->head)
    {
      aslist->next = list->head;
      list->head->prev = aslist;
      list->head = aslist;
      return aslist;
    }

  /* Insertion is made at middle of the access_list. */
  aslist->next = point;
  aslist->prev = point->prev;

  if (point->prev)
    point->prev->next = aslist;
  point->prev = aslist;

  return aslist;
}

struct as_list *
as_list_get (char *name)
{
  struct as_list *aslist;

  aslist = as_list_lookup (name);
  if (aslist == NULL)
    {
      aslist = as_list_insert (name);

      /* Run hook function. */
      if (bgp_aslist_master->add_hook)
        (*bgp_aslist_master->add_hook) ();
    }

  return aslist;
}

static char *
filter_type_str (enum as_filter_type type)
{
  switch (type)
    {
    case AS_FILTER_PERMIT:
      return "permit";
      break;
    case AS_FILTER_DENY:
      return "deny";
      break;
    default:
      return "";
      break;
    }
}

void
as_list_delete (struct as_list *aslist)
{
  struct as_list_list *list;
  struct as_filter *filter, *next;

  for (filter = aslist->head; filter; filter = next)
    {
      next = filter->next;
      as_filter_free (filter);
    }

  if (aslist->type == ACCESS_TYPE_NUMBER)
    list = &bgp_aslist_master->num;
  else
    list = &bgp_aslist_master->str;

  if (aslist->next)
    aslist->next->prev = aslist->prev;
  else
    list->tail = aslist->prev;

  if (aslist->prev)
    aslist->prev->next = aslist->next;
  else
    list->head = aslist->next;

  as_list_free (aslist);
}

static int
as_list_empty (struct as_list *aslist)
{
  if (aslist->head == NULL && aslist->tail == NULL)
    return 1;
  else
    return 0;
}

void
as_list_filter_delete (struct as_list *aslist, struct as_filter *asfilter)
{
  if (asfilter->next)
    asfilter->next->prev = asfilter->prev;
  else
    aslist->tail = asfilter->prev;

  if (asfilter->prev)
    asfilter->prev->next = asfilter->next;
  else
    aslist->head = asfilter->next;

  as_filter_free (asfilter);

  /* If access_list becomes empty delete it from access_master. */
  if (as_list_empty (aslist))
    as_list_delete (aslist);

  /* Run hook function. */
  if (bgp_aslist_master->delete_hook)
    (*bgp_aslist_master->delete_hook) ();
}

static int
as_filter_match (struct as_filter *asfilter, struct aspath *aspath)
{
  if (bgp_regexec (asfilter->reg, aspath) != REG_NOMATCH)
    return 1;
  return 0;
}
#ifdef HAVE_EXT_CAP_ASN
static int
as_4b_filter_match (struct as_filter *asfilter, struct as4path *aspath4B)
{
  if (bgp_regexec_aspath4B (asfilter->reg, aspath4B) != REG_NOMATCH)
    return 1;
  return 0;
}
#endif /* HAVE_EXT_CAP_ASN */

/* Apply AS path filter to AS. */
enum as_filter_type
as_list_apply (struct as_list *aslist, void *object)
{
  struct as_filter *asfilter;
  struct aspath *aspath;
#ifdef HAVE_EXT_CAP_ASN
  struct as4path *aspath4B;
#endif /* HAVE_EXT_CAP_ASN */ 
  aspath = NULL;
#ifdef HAVE_EXT_CAP_ASN
  aspath4B = NULL;
#endif /* HAVE_EXT_CAP_ASN */
#ifndef HAVE_EXT_CAP_ASN
  aspath = (struct aspath *) object;
#else
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    aspath4B = (struct as4path *) object;
  else
    aspath = (struct aspath *) object;
#endif /* HAVE_EXT_CAP_ASN */
  if (! aslist)
    return AS_FILTER_NO_MATCH;

  for (asfilter = aslist->head; asfilter; asfilter = asfilter->next)
    {
#ifndef HAVE_EXT_CAP_ASN
      if (as_filter_match (asfilter, aspath))
        return asfilter->type;
#else
      if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        {
         if (as_4b_filter_match (asfilter, aspath4B))
           return asfilter->type;
        }
      else if (as_filter_match (asfilter, aspath))
         return asfilter->type;
#endif /* HAVE_EXT_CAP_ASN */
    }

  return AS_FILTER_NO_MATCH;
}

/* Add hook function. */
void
as_list_add_hook (void (*func) ())
{
  bgp_aslist_master->add_hook = func;
}

/* Delete hook function. */
void
as_list_delete_hook (void (*func) ())
{
  bgp_aslist_master->delete_hook = func;
}

int
as_list_dup_check (struct as_list *aslist, struct as_filter *new)
{
  struct as_filter *asfilter;

  for (asfilter = aslist->head; asfilter; asfilter = asfilter->next)
    {
      if (asfilter->type == new->type
          && pal_strcmp (asfilter->reg_str, new->reg_str) == 0)
        return 1;
    }
  return 0;
}

/* Make an as-path access-list filter entry.
   If this access-list doesn't exist, create a new one.
*/
int
as_list_entry_make (char *name, char *regstr, enum as_filter_type type)
{
  struct as_filter *asfilter;
  struct as_list *aslist;
  pal_regex_t *regex;

  regex = bgp_regcomp (regstr);
  if (! regex)
    return BGP_API_SET_ERR_REGEXP_COMPILE_FAIL;

  asfilter = as_filter_make (regex, regstr, type);

  /* Install new filter to the access_list. */
  aslist = as_list_get (name);

  /* Duplicate insertion check. */;
  if (as_list_dup_check (aslist, asfilter))
    as_filter_free (asfilter);
  else
    as_list_filter_add (aslist, asfilter);

  return 0;
}

/* Delete an as-path access-list filter entry.
   If only name is provided, delete the whole aslist.
*/
int
as_list_entry_delete (char *name, char *regstr, enum as_filter_type type)
{
  struct as_filter *asfilter;
  struct as_list *aslist;

  /* Lookup aslist from AS path access-list. */
  aslist = as_list_lookup (name);
  if (aslist == NULL)
    return BGP_API_SET_ERR_UNKNOWN_OBJECT;

  /* Delete the whole aslist form AS path access-list. */
  if (regstr == NULL)
    {
      as_list_delete (aslist);
      return 0;
    }

  /* Lookup asfilter. */
  asfilter = as_filter_lookup (aslist, regstr, type);

  if (asfilter == NULL)
    return BGP_API_SET_ERR_UNKNOWN_OBJECT;

  /* Delete the filter entry from aslist. */
  as_list_filter_delete (aslist, asfilter);

  return 0;
}

CLI (ip_as_path,
     ip_as_path_cmd,
     "ip as-path access-list WORD (deny|permit) LINE",
     CLI_IP_STR,
     "BGP autonomous system path filter",
     "Specify an access list name",
     "Regular expression access list name",
     "Specify packets to reject",
     "Specify packets to forward",
     "A regular-expression to match the BGP AS paths")
{
  enum as_filter_type type;
  int ret;

  /* Check the filter type. */
  if (pal_strncmp (argv[1], "p", 1) == 0)
    type = AS_FILTER_PERMIT;
  else if (pal_strncmp (argv[1], "d", 1) == 0)
    type = AS_FILTER_DENY;
  else
    {
      cli_out (cli, "filter type must be [permit|deny]\n");
      return CLI_ERROR;
    }

  /* Check AS path regex. */
  ret = as_list_entry_make (argv[0], argv[2], type);

  return bgp_cli_return (cli, ret);
}

CLI (no_ip_as_path,
     no_ip_as_path_cmd,
     "no ip as-path access-list WORD (deny|permit) LINE",
     CLI_NO_STR,
     CLI_IP_STR,
     "BGP autonomous system path filter",
     "Specify an access list name",
     "Regular expression access list name",
     "Specify packets to reject",
     "Specify packets to forward",
     "A regular-expression to match the BGP AS paths")
{
  enum as_filter_type type;
  int ret;

  /* Check the filter type. */
  if (pal_strncmp (argv[1], "p", 1) == 0)
    type = AS_FILTER_PERMIT;
  else if (pal_strncmp (argv[1], "d", 1) == 0)
    type = AS_FILTER_DENY;
  else
    {
      cli_out (cli, "filter type must be [permit|deny]\n");
      return CLI_ERROR;
    }

  /* Compile AS path. */
  ret = as_list_entry_delete (argv[0], argv[2], type);

  return bgp_cli_return (cli, ret);
}

CLI (no_ip_as_path_all,
     no_ip_as_path_all_cmd,
     "no ip as-path access-list WORD",
     CLI_NO_STR,
     CLI_IP_STR,
     "BGP autonomous system path filter",
     "Specify an access list name",
     "Regular expression access list name")
{
  int ret;

  ret = as_list_entry_delete (argv[0], NULL, 0);

  return bgp_cli_return (cli, ret);
}

static void
as_list_show (struct cli *cli, struct as_list *aslist)
{
  struct as_filter *asfilter;

  cli_out (cli, "AS path access list %s\n", aslist->name);

  for (asfilter = aslist->head; asfilter; asfilter = asfilter->next)
    {
      cli_out (cli, "    %s %s\n", filter_type_str (asfilter->type),
               asfilter->reg_str);
    }
}

static void
as_list_show_all (struct cli *cli)
{
  struct as_list *aslist;
  struct as_filter *asfilter;

  for (aslist = bgp_aslist_master->num.head; aslist; aslist = aslist->next)
    {
      cli_out (cli, "AS path access list %s\n", aslist->name);

      for (asfilter = aslist->head; asfilter; asfilter = asfilter->next)
        {
          cli_out (cli, "    %s %s\n", filter_type_str (asfilter->type),
                   asfilter->reg_str);
        }
    }

  for (aslist = bgp_aslist_master->str.head; aslist; aslist = aslist->next)
    {
      cli_out (cli, "AS path access list %s\n", aslist->name);

      for (asfilter = aslist->head; asfilter; asfilter = asfilter->next)
        {
          cli_out (cli, "    %s %s\n", filter_type_str (asfilter->type),
                   asfilter->reg_str);
        }
    }
}

CLI (show_ip_as_path_access_list,
     show_ip_as_path_access_list_cli,
     "show ip as-path-access-list WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "List AS path access lists",
     "AS path access list name")
{
  struct as_list *aslist;

  aslist = as_list_lookup (argv[0]);
  if (aslist)
    as_list_show (cli, aslist);

  return CLI_SUCCESS;
}

CLI (show_ip_as_path_access_list_all,
     show_ip_as_path_access_list_all_cli,
     "show ip as-path-access-list",
     CLI_SHOW_STR,
     CLI_IP_STR,
     "List AS path access lists")
{
  as_list_show_all (cli);
  return CLI_SUCCESS;
}

int
config_write_as_list (struct cli *cli)
{
  struct as_list *aslist;
  struct as_filter *asfilter;
  int write = 0;

  for (aslist = bgp_aslist_master->num.head; aslist; aslist = aslist->next)
    for (asfilter = aslist->head; asfilter; asfilter = asfilter->next)
      {
        cli_out (cli, "ip as-path access-list %s %s %s\n",
                 aslist->name, filter_type_str (asfilter->type),
                 asfilter->reg_str);
        write++;
      }

  for (aslist = bgp_aslist_master->str.head; aslist; aslist = aslist->next)
    for (asfilter = aslist->head; asfilter; asfilter = asfilter->next)
      {
        cli_out (cli, "ip as-path access-list %s %s %s\n",
                 aslist->name, filter_type_str (asfilter->type),
                 asfilter->reg_str);
        write++;
      }
  return write;
}

/* BGP Filter-List CLI Initialization */
void
bgp_filter_cli_init (void)
{
  cli_install_config (BLG.ctree, AS_LIST_MODE, config_write_as_list);

  cli_install_gen (BLG.ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_as_path_cmd);
  cli_install_gen (BLG.ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_as_path_cmd);
  cli_install_gen (BLG.ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_as_path_all_cmd);

  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_as_path_access_list_cli);
  cli_install_gen (BLG.ctree, EXEC_MODE, PRIVILEGE_NORMAL, 0,
                   &show_ip_as_path_access_list_all_cli);

  return;
}
