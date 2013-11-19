/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#include "lib.h"
#include "cli.h"
#include "stream.h"

struct prefix_master *
prefix_master_get (struct ipi_vr *vr, afi_t afi)
{
  if (afi == AFI_IP)
    return &vr->prefix_master_ipv4;
#ifdef HAVE_IPV6
  else if (afi == AFI_IP6)
    return &vr->prefix_master_ipv6;
#endif /* HAVE_IPV6 */
  else if (afi == AFI_ORF_PREFIX)
    return &vr->prefix_master_orf;
  return NULL;
}

/* Lookup prefix_list from list of prefix_list by name. */
struct prefix_list *
prefix_list_lookup (struct ipi_vr *vr, afi_t afi, char *name)
{
  struct prefix_list *plist;
  struct prefix_master *master;

  if (name == NULL)
    return NULL;

  master = prefix_master_get (vr, afi);
  if (master == NULL)
    return NULL;

  for (plist = master->num.head; plist; plist = plist->next)
    if (pal_strcmp (plist->name, name) == 0)
      return plist;

  for (plist = master->str.head; plist; plist = plist->next)
    if (pal_strcmp (plist->name, name) == 0)
      return plist;

  return NULL;
}

struct prefix_list *
prefix_list_new ()
{
  return (struct prefix_list*) XCALLOC (MTYPE_PREFIX_LIST,
                                        sizeof (struct prefix_list));
}

void
prefix_list_free (struct prefix_list *plist)
{
  XFREE (MTYPE_PREFIX_LIST, plist);
}

struct prefix_list_entry *
prefix_list_entry_new ()
{
  return
    (struct prefix_list_entry*) XCALLOC (MTYPE_PREFIX_LIST_ENTRY,
                                         sizeof (struct prefix_list_entry));
}

void
prefix_list_entry_free (struct prefix_list_entry *pentry)
{
  XFREE (MTYPE_PREFIX_LIST_ENTRY, pentry);
}

/* Insert new prefix list to list of prefix_list.  Each prefix_list
   is sorted by the name. */
struct prefix_list *
prefix_list_insert (struct ipi_vr *vr, afi_t afi, char *name)
{
  int i;
  long number;
  struct prefix_list *plist;
  struct prefix_list *point;
  struct prefix_list_list *list;
  struct prefix_master *master;

  master = prefix_master_get (vr, afi);
  if (master == NULL)
    return NULL;

  /* Allocate new prefix_list and copy given name. */
  plist = prefix_list_new ();
  plist->name = XSTRDUP (MTYPE_PREFIX_LIST_STR, name);
  plist->master = master;

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
      plist->type = PREFIX_TYPE_NUMBER;

      /* Set prefix_list to number list. */
      list = &master->num;

      for (point = list->head; point; point = point->next)
        if (pal_strtos32(point->name,NULL,10) >= number)
          break;
    }
  else
    {
      plist->type = PREFIX_TYPE_STRING;

      /* Set prefix_list to string list. */
      list = &master->str;

      /* Set point to insertion point. */
      for (point = list->head; point; point = point->next)
        if (pal_strcmp (point->name, name) >= 0)
          break;
    }

  /* In case of this is the first element of master. */
  if (list->head == NULL)
    {
      list->head = list->tail = plist;
      return plist;
    }

  /* In case of insertion is made at the tail of access_list. */
  if (point == NULL)
    {
      plist->prev = list->tail;
      list->tail->next = plist;
      list->tail = plist;
      return plist;
    }

  /* In case of insertion is made at the head of access_list. */
  if (point == list->head)
    {
      plist->next = list->head;
      list->head->prev = plist;
      list->head = plist;
      return plist;
    }

  /* Insertion is made at middle of the access_list. */
  plist->next = point;
  plist->prev = point->prev;

  if (point->prev)
    point->prev->next = plist;
  point->prev = plist;

  return plist;
}

struct prefix_list *
prefix_list_get (struct ipi_vr *vr, afi_t afi, char *name)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (vr, afi, name);

  if (plist == NULL)
    plist = prefix_list_insert (vr, afi, name);
  return plist;
}

/* Delete prefix-list from prefix_list_master and free it. */
void
prefix_list_delete (struct prefix_list *plist)
{
  struct prefix_list_list *list;
  struct prefix_master *master;
  struct prefix_list_entry *pentry;
  struct prefix_list_entry *next;

  /* If prefix-list contain prefix_list_entry free all of it. */
  for (pentry = plist->head; pentry; pentry = next)
    {
      next = pentry->next;
      prefix_list_entry_free (pentry);
      plist->count--;
    }

  master = plist->master;

  if (plist->type == PREFIX_TYPE_NUMBER)
    list = &master->num;
  else
    list = &master->str;

  if (plist->next)
    plist->next->prev = plist->prev;
  else
    list->tail = plist->prev;

  if (plist->prev)
    plist->prev->next = plist->next;
  else
    list->head = plist->next;

  if (plist->desc)
    XFREE (MTYPE_PREFIX_LIST_DESC, plist->desc);

  /* Make sure master's recent changed prefix-list information is
     cleared. */
  master->recent = NULL;

  if (plist->name)
    XFREE (MTYPE_PREFIX_LIST_STR, plist->name);

  prefix_list_free (plist);

  if (master->delete_hook)
    (*master->delete_hook) ();
}

struct prefix_list_entry *
prefix_list_entry_make (struct prefix *prefix, enum prefix_list_type type,
                        int seq, int le, int ge, int any)
{
  struct prefix_list_entry *pentry;

  pentry = prefix_list_entry_new ();

  if (any)
    pentry->any = 1;

  prefix_copy (&pentry->prefix, prefix);
  pentry->type = type;
  pentry->seq = seq;
  pentry->le = le;
  pentry->ge = ge;

  return pentry;
}

/* Add hook function. */
void
prefix_list_add_hook (struct ipi_vr *vr, void (*func) ())
{
  vr->prefix_master_ipv4.add_hook = func;
#ifdef HAVE_IPV6
  vr->prefix_master_ipv6.add_hook = func;
#endif /* HAVE_IPV6 */
}

/* Delete hook function. */
void
prefix_list_delete_hook (struct ipi_vr *vr, void (*func) ())
{
  vr->prefix_master_ipv4.delete_hook = func;
#ifdef HAVE_IPV6
  vr->prefix_master_ipv6.delete_hook = func;
#endif /* HAVE_IPVt6 */
}

/* Calculate new sequential number. */
int
prefix_new_seq_get (struct prefix_list *plist)
{
  int maxseq;
  int newseq;
  struct prefix_list_entry *pentry;

  maxseq = newseq = 0;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if (maxseq < pentry->seq)
        maxseq = pentry->seq;
    }

  newseq = ((maxseq / 5) * 5) + 5;

  return newseq;
}

/* Return prefix list entry which has same seq number. */
struct prefix_list_entry *
prefix_seq_check (struct prefix_list *plist, int seq)
{
  struct prefix_list_entry *pentry;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    if (pentry->seq == seq)
      return pentry;
  return NULL;
}

struct prefix_list_entry *
prefix_list_entry_lookup (struct prefix_list *plist, struct prefix *prefix,
                          enum prefix_list_type type, int seq, int le, int ge)
{
  struct prefix_list_entry *pentry;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    if (prefix_same (&pentry->prefix, prefix) && pentry->type == type)
      {
        if (seq > 0 && pentry->seq != seq)
          continue;

        if (pentry->le != le)
          continue;
        if (pentry->ge != ge)
          continue;

        return pentry;
      }

  return NULL;
}

void
prefix_list_entry_delete (struct prefix_list *plist,
                          struct prefix_list_entry *pentry,
                          int update_list)
{
  if (plist == NULL || pentry == NULL)
    return;
  if (pentry->prev)
    pentry->prev->next = pentry->next;
  else
    plist->head = pentry->next;
  if (pentry->next)
    pentry->next->prev = pentry->prev;
  else
    plist->tail = pentry->prev;

  prefix_list_entry_free (pentry);

  plist->count--;

  if (update_list)
    {
      if (plist->master->delete_hook)
        (*plist->master->delete_hook) ();

      if (plist->head == NULL && plist->tail == NULL && plist->desc == NULL)
        prefix_list_delete (plist);
      else
        plist->master->recent = plist;
    }
}

void
prefix_list_entry_add (struct prefix_list *plist,
                       struct prefix_list_entry *pentry)
{
  struct prefix_list_entry *replace;
  struct prefix_list_entry *point;

  /* Automatic asignment of seq no. */
  if (pentry->seq == 0)
    pentry->seq = prefix_new_seq_get (plist);

  /* Is there any same seq prefix list entry? */
  replace = prefix_seq_check (plist, pentry->seq);
  if (replace)
    prefix_list_entry_delete (plist, replace, 0);

  /* Check insert point. */
  for (point = plist->head; point; point = point->next)
    if (point->seq >= pentry->seq)
      break;

  /* In case of this is the first element of the list. */
  pentry->next = point;

  if (point)
    {
      if (point->prev)
        point->prev->next = pentry;
      else
        plist->head = pentry;

      pentry->prev = point->prev;
      point->prev = pentry;
    }
  else
    {
      if (plist->tail)
        plist->tail->next = pentry;
      else
        plist->head = pentry;

      pentry->prev = plist->tail;
      plist->tail = pentry;
    }

  /* Increment count. */
  plist->count++;

  /* Run hook function. */
  if (plist->master->add_hook)
    (*plist->master->add_hook) ();

  plist->master->recent = plist;
}

/* Return string of prefix_list_type. */
static const char *
prefix_list_type_str (struct prefix_list_entry *pentry)
{
  switch (pentry->type)
    {
    case PREFIX_PERMIT:
      return "permit";
    case PREFIX_DENY:
      return "deny";
    default:
      return "";
    }
}

static result_t
prefix_list_entry_match (struct prefix_list_entry *pentry, struct prefix *p)
{
  result_t ret;

  ret = prefix_match (&pentry->prefix, p);
  if (! ret)
    return 0;

  /* In case of le nor ge is specified, exact match is performed. */
  if (! pentry->le && ! pentry->ge)
    {
      if (pentry->prefix.prefixlen != p->prefixlen)
        return 0;
    }
  else
    {
      if (pentry->le)
        if (p->prefixlen > pentry->le)
          return 0;

      if (pentry->ge)
        if (p->prefixlen < pentry->ge)
          return 0;
    }
  return 1;
}

static result_t
prefix_list_entry_match_custom (struct prefix_list_entry *pentry,
                                result_t (* cust_func) (void *, void *),
                                void *object)
{
  result_t ret;

  ret = PAL_FALSE;

  if (cust_func)
    ret = cust_func (object, (void *) &pentry->prefix);

  return ret;
}

enum prefix_list_type
prefix_list_apply (struct prefix_list *plist, void *object)
{
  struct prefix_list_entry *pentry;
  struct prefix *p;

  p = (struct prefix *) object;

  if (! plist)
    return PREFIX_NO_MATCH;

  if (plist->count == 0)
    return PREFIX_PERMIT;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      pentry->refcnt++;
      if (prefix_list_entry_match (pentry, p))
        {
          pentry->hitcnt++;
          return pentry->type;
        }
    }

  return PREFIX_NO_MATCH;
}

enum prefix_list_type
prefix_list_custom_apply (struct prefix_list *plist,
                          result_t (* cust_func) (void *, void *),
                          void *object)
{
  struct prefix_list_entry *pentry;

  if (! plist)
    return PREFIX_NO_MATCH;

  if (plist->count == 0)
    return PREFIX_PERMIT;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      pentry->refcnt++;

      if (prefix_list_entry_match_custom (pentry, cust_func, object))
        {
          pentry->hitcnt++;
          return pentry->type;
        }
    }

  return PREFIX_NO_MATCH;
}

/* Retrun 1 when plist already include pentry policy. */
struct prefix_list_entry *
prefix_entry_dup_check (struct prefix_list *plist,
                        struct prefix_list_entry *new)
{
  struct prefix_list_entry *pentry;
  int seq = 0;

  if (new->seq == 0)
    seq = prefix_new_seq_get (plist);
  else
    seq = new->seq;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if (prefix_same (&pentry->prefix, &new->prefix)
          && pentry->type == new->type
          && pentry->le == new->le
          && pentry->ge == new->ge
          && pentry->seq != seq)
        return pentry;
    }
  return NULL;
}

result_t
vty_invalid_prefix_range (struct cli *cli, char *prefix)
{
  cli_out (cli, "%% Invalid prefix range for %s, make sure: len < ge-value <= le-value\n", prefix);
  return CLI_ERROR;
}

int
prefix_list_install (struct ipi_vr *vr, afi_t afi,
                     char *name, int type, struct prefix *p,
                     u_int32_t seqnum, u_int32_t genum,
                     u_int32_t lenum, int any)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix_list_entry *dup;

  /* Get prefix_list with name. */
  plist = prefix_list_get (vr, afi, name);

  /* Make prefix entry. */
  pentry = prefix_list_entry_make (p, type, seqnum, lenum, genum, any);

  /* Check same policy. */
  dup = prefix_entry_dup_check (plist, pentry);

  if (dup)
    {
      prefix_list_entry_free (pentry);
      return LIB_API_SET_ERR_DUPLICATE_POLICY;
    }

  /* Install new filter to the access_list. */
  prefix_list_entry_add (plist, pentry);

  return LIB_API_SET_SUCCESS;
}

int
prefix_list_uninstall (struct ipi_vr *vr, afi_t afi,
                         char *name, struct prefix *p, int type,
                           u_int32_t seqnum, u_int32_t genum,
                       u_int32_t lenum)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;

  plist = prefix_list_lookup (vr, afi, name);
  if (!  plist)
    return LIB_API_SET_ERR_UNKNOWN_OBJECT;

  /* Lookup prefix entry. */
  pentry = prefix_list_entry_lookup (plist, p, type, seqnum, lenum, genum);

  if (pentry == NULL)
    return LIB_API_SET_ERR_UNKNOWN_OBJECT;

  /* Install new filter to the access_list. */
  prefix_list_entry_delete (plist, pentry, 1);

  return LIB_API_SET_SUCCESS;
}

int
vty_prefix_list_entry_modify (struct cli *cli, afi_t afi,
                              char *name, char *seq,
                              char *typestr, char *prefix,
                              char *ge, char *le, int set)
{
  enum prefix_list_type type;
  u_int32_t seqnum = 0;
  u_int32_t lenum = 0;
  u_int32_t genum = 0;

  if (seq == NULL && typestr == NULL && prefix == NULL
      && ge == NULL && le == NULL)
    {
      if (set)
        return CLI_ERROR;
      else
        /* Call API function. */
        return prefix_list_unset (cli->vr, afi, name);
    }

  /* Sequential number. */
  if (seq)
    seqnum = pal_strtou32 (seq, NULL, 10);

  /* ge and le number */
  if (ge)
    genum = pal_strtou32 (ge, NULL, 10);
  if (le)
    lenum = pal_strtou32 (le, NULL, 10);

  /* Check filter type. */
  if (typestr == NULL)
    return LIB_API_SET_ERR_INVALID_FILTER_TYPE;

  if (pal_strncmp ("permit", typestr, 1) == 0)
    type = PREFIX_PERMIT;
  else if (pal_strncmp ("deny", typestr, 1) == 0)
    type = PREFIX_DENY;
  else
    return LIB_API_SET_ERR_INVALID_FILTER_TYPE;

  /* Call API function. */
  if (set)
     return prefix_list_entry_set (cli->vr, afi, name, seqnum,
                                   type, prefix, genum, lenum);
  else
     return prefix_list_entry_unset (cli->vr, afi, name, seqnum,
                                     type, prefix, genum, lenum);
}

enum display_type
{
  normal_display,
  summary_display,
  detail_display,
  sequential_display,
  longer_display,
  first_match_display
};

void
vty_show_prefix_entry (struct cli *cli, afi_t afi, struct prefix_list *plist,
                       struct prefix_master *master, enum display_type dtype,
                       int seqnum)
{
  struct prefix_list_entry *pentry;

      if (dtype == normal_display)
        {
          cli_out (cli, "ip%s prefix-list %s: %d entries\n",
                   afi == AFI_IP ? "" : "v6",
                   plist->name, plist->count);
          if (plist->desc)
            cli_out (cli, "   Description: %s\n", plist->desc);
        }
      else if (dtype == summary_display || dtype == detail_display)
        {
          cli_out (cli, "ip%s prefix-list %s:\n",
                   afi == AFI_IP ? "" : "v6", plist->name);

          if (plist->desc)
            cli_out (cli, "   Description: %s\n", plist->desc);

          cli_out (cli, "   count: %d, range entries: %d, sequences: %lu - %lu\n",
                   plist->count, plist->rangecount,
                   plist->head ? plist->head->seq : 0,
                   plist->tail ? plist->tail->seq : 0);
        }
      if (dtype != summary_display)
        {
          for (pentry = plist->head; pentry; pentry = pentry->next)
            {
              if (dtype == sequential_display
                  && (seqnum && pentry->seq != seqnum))
                continue;

              if (master->seqnum)
                {
                  if (cli->type == VTY_SHELL_SERV)
                    cli_out (cli, "   seq %6lu ", pentry->seq);
                  else
                    cli_out (cli, "   seq %lu ", pentry->seq);
                }

              cli_out (cli, "%s ", prefix_list_type_str (pentry));

              if (pentry->any)
                cli_out (cli, "any");
              else
                {
                  struct prefix *p = &pentry->prefix;
                  char buf[BUFSIZ];

                  pal_inet_ntop(p->family,&p->u.prefix,buf,BUFSIZ);
                  cli_out (cli, "%s/%d",buf,p->prefixlen);

                  if (pentry->ge)
                    cli_out (cli, " ge %d", pentry->ge);
                  if (pentry->le)
                    cli_out (cli, " le %d", pentry->le);
                }

              if (dtype == detail_display || dtype == sequential_display)
                cli_out (cli, " (hit count: %lu, refcount: %lu)",
                         pentry->hitcnt, pentry->refcnt);

              cli_out (cli, "\n");
            }
        }
}

result_t
vty_show_prefix_list (struct cli *cli, afi_t afi, char *name,
                      char *seq, enum display_type dtype)
{
  struct prefix_master *master;
  struct prefix_list *plist;
  bool_t loop_done;
  u_int32_t seqnum;

  loop_done = PAL_FALSE;
  seqnum = 0;

  master = prefix_master_get (cli->vr, afi);
  if (master == NULL)
    return CLI_ERROR;

  if (seq)
    seqnum = pal_strtou32(seq,NULL,10);

  if (name)
    {
      plist = prefix_list_lookup (cli->vr, afi, name);
      if (! plist)
        {
          cli_out (cli, "%% Can't find specified prefix-list\n");
          return CLI_ERROR;
        }
      vty_show_prefix_entry (cli, afi, plist, master, dtype, seqnum);
    }
  else
    {
      plist = master->num.head;

      do {
        for (; plist; plist = plist->next)
          {
            vty_show_prefix_entry (cli, afi, plist, master, dtype, seqnum);

           if (plist == master->str.tail)
              {
                loop_done = PAL_TRUE;
                break;
              }
          }

        if (!loop_done && !(plist = master->str.head))
          break;

      } while (! loop_done);
    }

  return CLI_SUCCESS;
}

result_t
vty_show_prefix_list_prefix (struct cli *cli, afi_t afi, char *name,
                             char *prefix, enum display_type type)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;
  int ret;
  int match;

  pal_mem_set (&p, 0, sizeof (struct prefix));
  plist = prefix_list_lookup (cli->vr, afi, name);
  if (! plist)
    {
      cli_out (cli, "%% Can't find specified prefix-list\n");
      return CLI_ERROR;
    }

  ret = str2prefix (prefix, &p);
  if (ret <= 0)
    {
      cli_out (cli, "%% prefix is malformed\n");
      return CLI_ERROR;
    }

      for (pentry = plist->head; pentry; pentry = pentry->next)
        {
          match = 0;

          if (type == normal_display || type == first_match_display)
            if (prefix_same (&p, &pentry->prefix))
               match = 1;

          if (type == longer_display)
            if (prefix_match (&p, &pentry->prefix))
              match = 1;

          if (match)
            {
              cli_out (cli, "   seq %lu %s ",
                       pentry->seq,
                       prefix_list_type_str (pentry));

              if (pentry->any)
                cli_out (cli, "any");
              else
                {
                  struct prefix *p = &pentry->prefix;
                  char buf[BUFSIZ];

                  pal_inet_ntop(p->family,&p->u.prefix,buf,BUFSIZ);
                  cli_out (cli, "%s/%d",buf,p->prefixlen);

                 if (pentry->ge)
                   cli_out (cli, " ge %d", pentry->ge);
                 if (pentry->le)
                   cli_out (cli, " le %d", pentry->le);
                }

              if (type == normal_display || type == first_match_display)
                cli_out (cli, " (hit count: %lu, refcount: %lu)",
                         pentry->hitcnt, pentry->refcnt);

              cli_out (cli, "\n");

              if (type == first_match_display)
                return CLI_SUCCESS;
            }
        }

  return CLI_SUCCESS;
}

result_t
vty_clear_prefix_list (struct cli *cli, afi_t afi, char *name, char *prefix)
{
  struct prefix_master *master;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  result_t ret;
  struct prefix p;

  master = prefix_master_get (cli->vr, afi);
  if (master == NULL)
    return CLI_ERROR;

  if (name == NULL && prefix == NULL)
    {
      for (plist = master->num.head; plist; plist = plist->next)
        for (pentry = plist->head; pentry; pentry = pentry->next)
          pentry->hitcnt = 0;

      for (plist = master->str.head; plist; plist = plist->next)
        for (pentry = plist->head; pentry; pentry = pentry->next)
          pentry->hitcnt = 0;
    }
  else
    {
      plist = prefix_list_lookup (cli->vr, afi, name);
      if (! plist)
        {
          cli_out (cli, "%% Can't find specified prefix-list\n");
          return CLI_ERROR;
        }

      if (prefix)
        {
          ret = str2prefix (prefix, &p);
          if (ret <= 0)
            {
              cli_out (cli, "%% prefix is malformed\n");
              return CLI_ERROR;
            }
        }

      for (pentry = plist->head; pentry; pentry = pentry->next)
        {
          if (prefix)
            {
              if (prefix_same (&pentry->prefix, &p))
                pentry->hitcnt = 0;
            }
          else
            pentry->hitcnt = 0;
        }
    }
  return CLI_SUCCESS;
}

CLI (ip_prefix_list,
     ip_prefix_list_cli,
     "ip prefix-list WORD (deny|permit) (A.B.C.D/M|any)",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     "Any prefix match. Same as \"0.0.0.0/0 le 32\"")
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL,
                                      argv[1], argv[2], NULL, NULL,
                                      1);
  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_ge,
     ip_prefix_list_ge_cli,
     "ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32>",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL, argv[1],
                                      argv[2], argv[3], NULL, 1);
  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_ge_le,
     ip_prefix_list_ge_le_cli,
     "ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL, argv[1],
                                      argv[2], argv[3], argv[4], 1);
  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_le,
     ip_prefix_list_le_cli,
     "ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32>",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL, argv[1],
                                      argv[2], NULL, argv[3], 1);
  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_le_ge,
     ip_prefix_list_le_ge_cli,
     "ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL, argv[1],
                                      argv[2], argv[4], argv[3], 1);
  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_seq,
     ip_prefix_list_seq_cli,
     "ip prefix-list WORD seq <1-4294967295> (deny|permit) (A.B.C.D/M|any)",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     "Any prefix match. Same as \"0.0.0.0/0 le 32\"")
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], argv[1], argv[2],
                                      argv[3], NULL, NULL, 1);
  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_seq_ge,
     ip_prefix_list_seq_ge_cli,
     "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32>",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], argv[1], argv[2],
                                      argv[3], argv[4], NULL, 1);
  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_seq_ge_le,
     ip_prefix_list_seq_ge_le_cli,
     "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], argv[1], argv[2],
                                      argv[3], argv[4], argv[5], 1);
  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_seq_le,
     ip_prefix_list_seq_le_cli,
     "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32>",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], argv[1], argv[2],
                                      argv[3], NULL, argv[4], 1);
  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_seq_le_ge,
     ip_prefix_list_seq_le_ge_cli,
     "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], argv[1], argv[2],
                                      argv[3], argv[5], argv[4], 1);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list,
     no_ip_prefix_list_cli,
     "no ip prefix-list WORD",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL, NULL,
                                      NULL, NULL, NULL, 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_prefix,
     no_ip_prefix_list_prefix_cli,
     "no ip prefix-list WORD (deny|permit) (A.B.C.D/M|any)",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     "Any prefix match.  Same as \"0.0.0.0/0 le 32\"")
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL, argv[1],
                                      argv[2], NULL, NULL, 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_ge,
     no_ip_prefix_list_ge_cli,
     "no ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32>",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL, argv[1],
                                      argv[2], argv[3], NULL, 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_ge_le,
     no_ip_prefix_list_ge_le_cli,
     "no ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL, argv[1],
                                      argv[2], argv[3], argv[4], 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_le,
     no_ip_prefix_list_le_cli,
     "no ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32>",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL, argv[1],
                                      argv[2], NULL, argv[3], 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_le_ge,
     no_ip_prefix_list_le_ge_cli,
     "no ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], NULL, argv[1],
                                      argv[2], argv[4], argv[3], 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_seq,
     no_ip_prefix_list_seq_cli,
     "no ip prefix-list WORD seq <1-4294967295> (deny|permit) (A.B.C.D/M|any)",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     "Any prefix match.  Same as \"0.0.0.0/0 le 32\"")
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], argv[1], argv[2],                                                        argv[3], NULL, NULL, 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_seq_ge,
     no_ip_prefix_list_seq_ge_cli,
     "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32>",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], argv[1], argv[2],
                                      argv[3], argv[4], NULL, 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_seq_ge_le,
     no_ip_prefix_list_seq_ge_le_cli,
     "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], argv[1], argv[2],
                                      argv[3], argv[4], argv[5], 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_seq_le,
     no_ip_prefix_list_seq_le_cli,
     "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32>",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], argv[1], argv[2],
                                      argv[3], NULL, argv[4], 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_seq_le_ge,
     no_ip_prefix_list_seq_le_ge_cli,
     "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP, argv[0], argv[1], argv[2],
                                      argv[3], argv[5], argv[4], 0);
  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_sequence_number,
     ip_prefix_list_sequence_number_cli,
     "ip prefix-list sequence-number",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     "Include/exclude sequence numbers in NVGEN")
{
  int ret;

  ret = prefix_list_sequence_number_set (cli->vr, AFI_IP);

  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_sequence_number,
     no_ip_prefix_list_sequence_number_cli,
     "no ip prefix-list sequence-number",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     "Include/exclude sequence numbers in NVGEN")
{
  int ret;

  ret = prefix_list_sequence_number_unset (cli->vr, AFI_IP);

  return lib_vty_return (cli, ret);
}

CLI (ip_prefix_list_description,
     ip_prefix_list_description_cli,
     "ip prefix-list WORD description LINE",
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     "Prefix-list specific description",
     "Up to 80 characters describing this prefix-list")
{
  int ret;

  /* Below is description get codes. */
  ret = prefix_list_description_set (cli->vr, AFI_IP, argv[0], argv[1]);

  return lib_vty_return (cli, ret);
}

CLI (no_ip_prefix_list_description,
     no_ip_prefix_list_description_cli,
     "no ip prefix-list WORD description",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     "Prefix-list specific description")
{
  int ret;

  ret = prefix_list_description_unset (cli->vr, AFI_IP, argv[0]);

  return lib_vty_return (cli, ret);
}

ALI (no_ip_prefix_list_description,
     no_ip_prefix_list_description_arg_cli,
     "no ip prefix-list WORD description LINE",
     CLI_NO_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     "Prefix-list specific description",
     "Up to 80 characters describing this prefix-list");

CLI (show_ip_prefix_list,
     show_ip_prefix_list_cli,
     "show ip prefix-list",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR)
{
  return vty_show_prefix_list (cli, AFI_IP, NULL, NULL, normal_display);
}

CLI (show_ip_prefix_list_name,
     show_ip_prefix_list_name_cli,
     "show ip prefix-list WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR)
{
  return vty_show_prefix_list (cli, AFI_IP, argv[0], NULL, normal_display);
}

CLI (show_ip_prefix_list_name_seq,
     show_ip_prefix_list_name_seq_cli,
     "show ip prefix-list WORD seq <1-4294967295>",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR)
{
  return vty_show_prefix_list (cli, AFI_IP, argv[0], argv[1], sequential_display);
}

CLI (show_ip_prefix_list_prefix,
     show_ip_prefix_list_prefix_cli,
     "show ip prefix-list WORD A.B.C.D/M",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_NETWORK_STR)
{
  return vty_show_prefix_list_prefix (cli, AFI_IP, argv[0], argv[1], normal_display);
}

CLI (show_ip_prefix_list_prefix_longer,
     show_ip_prefix_list_prefix_longer_cli,
     "show ip prefix-list WORD A.B.C.D/M longer",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_NETWORK_STR,
     "Lookup longer prefix")
{
  return vty_show_prefix_list_prefix (cli, AFI_IP, argv[0], argv[1], longer_display);
}

CLI (show_ip_prefix_list_prefix_first_match,
     show_ip_prefix_list_prefix_first_match_cli,
     "show ip prefix-list WORD A.B.C.D/M first-match",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_NETWORK_STR,
     "First matched prefix")
{
  return vty_show_prefix_list_prefix (cli, AFI_IP, argv[0], argv[1], first_match_display);
}

CLI (show_ip_prefix_list_summary,
     show_ip_prefix_list_summary_cli,
     "show ip prefix-list summary",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     "Summary of prefix lists")
{
  return vty_show_prefix_list (cli, AFI_IP, NULL, NULL, summary_display);
}

CLI (show_ip_prefix_list_summary_name,
     show_ip_prefix_list_summary_name_cli,
     "show ip prefix-list summary WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     "Summary of prefix lists",
     CLI_PREFIX_LIST_NAME_STR)
{
  return vty_show_prefix_list (cli, AFI_IP, argv[0], NULL, summary_display);
}


CLI (show_ip_prefix_list_detail,
     show_ip_prefix_list_detail_cli,
     "show ip prefix-list detail",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     "Detail of prefix lists")
{
  return vty_show_prefix_list (cli, AFI_IP, NULL, NULL, detail_display);
}

CLI (show_ip_prefix_list_detail_name,
     show_ip_prefix_list_detail_name_cli,
     "show ip prefix-list detail WORD",
     CLI_SHOW_STR,
     CLI_IP_STR,
     CLI_PREFIX_LIST_STR,
     "Detail of prefix lists",
     CLI_PREFIX_LIST_NAME_STR)
{
  return vty_show_prefix_list (cli, AFI_IP, argv[0], NULL, detail_display);
}

CLI (clear_ip_prefix_list,
     clear_ip_prefix_list_cli,
     "clear ip prefix-list",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_CLEAR_PREFIX_LIST_STR)
{
  return vty_clear_prefix_list (cli, AFI_IP, NULL, NULL);
}

CLI (clear_ip_prefix_list_name,
     clear_ip_prefix_list_name_cli,
     "clear ip prefix-list WORD",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_CLEAR_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR)
{
  return vty_clear_prefix_list (cli, AFI_IP, argv[0], NULL);
}

CLI (clear_ip_prefix_list_name_prefix,
     clear_ip_prefix_list_name_prefix_cli,
     "clear ip prefix-list WORD A.B.C.D/M",
     CLI_CLEAR_STR,
     CLI_IP_STR,
     CLI_CLEAR_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_NETWORK_STR)
{
  return vty_clear_prefix_list (cli, AFI_IP, argv[0], argv[1]);
}

#ifdef HAVE_IPV6
CLI (ipv6_prefix_list,
     ipv6_prefix_list_cli,
     "ipv6 prefix-list WORD (deny|permit) (X:X::X:X/M|any)",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     "Any prefix match.  Same as \"::0/0 le 128\"")
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL,
                                      argv[1], argv[2], NULL, NULL, 1);
  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_ge,
     ipv6_prefix_list_ge_cli,
     "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128>",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL, argv[1],
                                      argv[2], argv[3], NULL, 1);
  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_ge_le,
     ipv6_prefix_list_ge_le_cli,
     "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)

{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL, argv[1],
                                      argv[2], argv[3], argv[4], 1);
  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_le,
     ipv6_prefix_list_le_cli,
     "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128>",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL, argv[1],
                                      argv[2], NULL, argv[3], 1);
  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_le_ge,
     ipv6_prefix_list_le_ge_cli,
     "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL, argv[1],
                                      argv[2], argv[4], argv[3], 1);
  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_seq,
     ipv6_prefix_list_seq_cli,
     "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) (X:X::X:X/M|any)",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     "Any prefix match.  Same as \"::0/0 le 128\"")
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], argv[1], argv[2],
                                      argv[3], NULL, NULL, 1);
  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_seq_ge,
     ipv6_prefix_list_seq_ge_cli,
     "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128>",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], argv[1], argv[2],
                                      argv[3], argv[4], NULL, 1);
  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_seq_ge_le,
     ipv6_prefix_list_seq_ge_le_cli,
     "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], argv[1], argv[2],
                                      argv[3], argv[4], argv[5], 1);
  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_seq_le,
     ipv6_prefix_list_seq_le_cli,
     "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128>",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], argv[1], argv[2],
                                      argv[3], NULL, argv[4], 1);
  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_seq_le_ge,
     ipv6_prefix_list_seq_le_ge_cli,
     "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], argv[1], argv[2],
                                      argv[3], argv[5], argv[4], 1);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list,
     no_ipv6_prefix_list_cli,
     "no ipv6 prefix-list WORD",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL, NULL,
                                      NULL, NULL, NULL, 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_prefix,
     no_ipv6_prefix_list_prefix_cli,
     "no ipv6 prefix-list WORD (deny|permit) (X:X::X:X/M|any)",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     "Any prefix match.  Same as \"::0/0 le 128\"")
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL, argv[1],
                                      argv[2], NULL, NULL, 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_ge,
     no_ipv6_prefix_list_ge_cli,
     "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128>",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL, argv[1],
                                      argv[2], argv[3], NULL, 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_ge_le,
     no_ipv6_prefix_list_ge_le_cli,
     "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL, argv[1],
                                      argv[2], argv[3], argv[4], 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_le,
     no_ipv6_prefix_list_le_cli,
     "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128>",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL, argv[1],
                                      argv[2], NULL, argv[3], 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_le_ge,
     no_ipv6_prefix_list_le_ge_cli,
     "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], NULL, argv[1],
                                      argv[2], argv[4], argv[3], 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_seq,
     no_ipv6_prefix_list_seq_cli,
     "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) (X:X::X:X/M|any)",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     "Any prefix match.  Same as \"::0/0 le 128\"")
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], argv[1], argv[2],
                                      argv[3], NULL, NULL, 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_seq_ge,
     no_ipv6_prefix_list_seq_ge_cli,
     "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128>",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], argv[1], argv[2],
                                      argv[3], argv[4], NULL, 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_seq_ge_le,
     no_ipv6_prefix_list_seq_ge_le_cli,
     "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], argv[1], argv[2],
                                      argv[3], argv[4], argv[5], 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_seq_le,
     no_ipv6_prefix_list_seq_le_cli,
     "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128>",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], argv[1], argv[2],
                                      argv[3], NULL, argv[4], 0);
  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_seq_le_ge,
     no_ipv6_prefix_list_seq_le_ge_cli,
     "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR,
     CLI_ACCESS_DENY_STR,
     CLI_ACCESS_PERMIT_STR,
     CLI_PREFIX6_NETWORK_STR,
     CLI_PREFIX_LENGTH_MAX_MATCH,
     CLI_PREFIX_LENGTH_MAX,
     CLI_PREFIX_LENGTH_MIN_MATCH,
     CLI_PREFIX_LENGTH_MIN)
{
  int ret;
  ret = vty_prefix_list_entry_modify (cli, AFI_IP6, argv[0], argv[1], argv[2],
                                      argv[3], argv[5], argv[4], 0);
  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_sequence_number,
     ipv6_prefix_list_sequence_number_cli,
     "ipv6 prefix-list sequence-number",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     "Include/exclude sequence numbers in NVGEN")
{
  int ret;

  ret = prefix_list_sequence_number_set (cli->vr, AFI_IP6);

  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_sequence_number,
     no_ipv6_prefix_list_sequence_number_cli,
     "no ipv6 prefix-list sequence-number",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     "Include/exclude sequence numbers in NVGEN")
{
  int ret;

  ret = prefix_list_sequence_number_unset (cli->vr, AFI_IP6);

  return lib_vty_return (cli, ret);
}

CLI (ipv6_prefix_list_description,
     ipv6_prefix_list_description_cli,
     "ipv6 prefix-list WORD description LINE",
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     "Prefix-list specific description",
     "Up to 80 characters describing this prefix-list")
{
  int ret;

  ret = prefix_list_description_set (cli->vr, AFI_IP6, argv[0], argv[1]);

  return lib_vty_return (cli, ret);
}

CLI (no_ipv6_prefix_list_description,
     no_ipv6_prefix_list_description_cli,
     "no ipv6 prefix-list WORD description",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     "Prefix-list specific description")
{
  int ret;

  ret = prefix_list_description_unset (cli->vr, AFI_IP6, argv[0]);

  return lib_vty_return (cli, ret);
}

ALI (no_ipv6_prefix_list_description,
     no_ipv6_prefix_list_description_arg_cli,
     "no ipv6 prefix-list WORD description LINE",
     CLI_NO_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     "Prefix-list specific description",
     "Up to 80 characters describing this prefix-list");

CLI (show_ipv6_prefix_list,
     show_ipv6_prefix_list_cli,
     "show ipv6 prefix-list",
     CLI_SHOW_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR)
{
  return vty_show_prefix_list (cli, AFI_IP6, NULL, NULL, normal_display);
}

CLI (show_ipv6_prefix_list_name,
     show_ipv6_prefix_list_name_cli,
     "show ipv6 prefix-list WORD",
     CLI_SHOW_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR)
{
  return vty_show_prefix_list (cli, AFI_IP6, argv[0], NULL, normal_display);
}

CLI (show_ipv6_prefix_list_name_seq,
     show_ipv6_prefix_list_name_seq_cli,
     "show ipv6 prefix-list WORD seq <1-4294967295>",
     CLI_SHOW_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX_SEQ_STR,
     CLI_PREFIX_SEQNUM_STR)
{
  return vty_show_prefix_list (cli, AFI_IP6, argv[0], argv[1],
                               sequential_display);
}

CLI (show_ipv6_prefix_list_prefix,
     show_ipv6_prefix_list_prefix_cli,
     "show ipv6 prefix-list WORD X:X::X:X/M",
     CLI_SHOW_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX6_NETWORK_STR)
{
  return vty_show_prefix_list_prefix (cli, AFI_IP6, argv[0], argv[1],
                                      normal_display);
}

CLI (show_ipv6_prefix_list_prefix_longer,
     show_ipv6_prefix_list_prefix_longer_cli,
     "show ipv6 prefix-list WORD X:X::X:X/M longer",
     CLI_SHOW_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX6_NETWORK_STR,
     "Lookup longer prefix")
{
  return vty_show_prefix_list_prefix (cli, AFI_IP6, argv[0], argv[1],
                                      longer_display);
}

CLI (show_ipv6_prefix_list_prefix_first_match,
     show_ipv6_prefix_list_prefix_first_match_cli,
     "show ipv6 prefix-list WORD X:X::X:X/M first-match",
     CLI_SHOW_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX6_NETWORK_STR,
     "First matched prefix")
{
  return vty_show_prefix_list_prefix (cli, AFI_IP6, argv[0], argv[1],
                                      first_match_display);
}

CLI (show_ipv6_prefix_list_summary,
     show_ipv6_prefix_list_summary_cli,
     "show ipv6 prefix-list summary",
     CLI_SHOW_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     "Summary of prefix lists")
{
  return vty_show_prefix_list (cli, AFI_IP6, NULL, NULL, summary_display);
}

CLI (show_ipv6_prefix_list_summary_name,
     show_ipv6_prefix_list_summary_name_cli,
     "show ipv6 prefix-list summary WORD",
     CLI_SHOW_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     "Summary of prefix lists",
     CLI_PREFIX_LIST_NAME_STR)
{
  return vty_show_prefix_list (cli, AFI_IP6, argv[0], NULL, summary_display);
}

CLI (show_ipv6_prefix_list_detail,
     show_ipv6_prefix_list_detail_cli,
     "show ipv6 prefix-list detail",
     CLI_SHOW_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     "Detail of prefix lists")
{
  return vty_show_prefix_list (cli, AFI_IP6, NULL, NULL, detail_display);
}

CLI (show_ipv6_prefix_list_detail_name,
     show_ipv6_prefix_list_detail_name_cli,
     "show ipv6 prefix-list detail WORD",
     CLI_SHOW_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     "Detail of prefix lists",
     CLI_PREFIX_LIST_NAME_STR)
{
  return vty_show_prefix_list (cli, AFI_IP6, argv[0], NULL, detail_display);
}

CLI (clear_ipv6_prefix_list,
     clear_ipv6_prefix_list_cli,
     "clear ipv6 prefix-list",
     CLI_CLEAR_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR)
{
  return vty_clear_prefix_list (cli, AFI_IP6, NULL, NULL);
}

CLI (clear_ipv6_prefix_list_name,
     clear_ipv6_prefix_list_name_cli,
     "clear ipv6 prefix-list WORD",
     CLI_CLEAR_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR)
{
  return vty_clear_prefix_list (cli, AFI_IP6, argv[0], NULL);
}

CLI (clear_ipv6_prefix_list_name_prefix,
     clear_ipv6_prefix_list_name_prefix_cli,
     "clear ipv6 prefix-list WORD X:X::X:X/M",
     CLI_CLEAR_STR,
     CLI_IPV6_STR,
     CLI_PREFIX_LIST_STR,
     CLI_PREFIX_LIST_NAME_STR,
     CLI_PREFIX6_NETWORK_STR)
{
  return vty_clear_prefix_list (cli, AFI_IP6, argv[0], argv[1]);
}
#endif /* HAVE_IPV6 */

/* Configuration write function. */
int
config_encode_prefix_afi (struct ipi_vr *vr, afi_t afi, cfg_vect_t *cv)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix_master *master;
  int write = 0;

  master = prefix_master_get (vr, afi);
  if (master == NULL)
    return 0;

  if (! master->seqnum)
    {
      cfg_vect_add_cmd (cv, "no ip%s prefix-list sequence-number\n",
               afi == AFI_IP ? "" : "v6");
      cfg_vect_add_cmd (cv, "!\n");
    }

  for (plist = master->num.head; plist; plist = plist->next)
    {
      if (plist->desc)
        {
          cfg_vect_add_cmd (cv, "ip%s prefix-list %s description %s\n",
                   afi == AFI_IP ? "" : "v6",
                   plist->name, plist->desc);
          write++;
        }

      for (pentry = plist->head; pentry; pentry = pentry->next)
        {
          cfg_vect_add_cmd (cv, "ip%s prefix-list %s ",
                   afi == AFI_IP ? "" : "v6",
                   plist->name);

          if (master->seqnum)
            cfg_vect_add_cmd (cv, "seq %lu ", pentry->seq);

          cfg_vect_add_cmd (cv, "%s ", prefix_list_type_str (pentry));

          if (pentry->any)
            cfg_vect_add_cmd (cv, "any");
          else
            {
              struct prefix *p = &pentry->prefix;
              char buf[BUFSIZ];

              pal_inet_ntop(p->family,&p->u.prefix,buf,BUFSIZ);
              cfg_vect_add_cmd (cv, "%s/%d",buf,p->prefixlen);

              if (pentry->ge)
                cfg_vect_add_cmd (cv, " ge %d", pentry->ge);
              if (pentry->le)
                cfg_vect_add_cmd (cv, " le %d", pentry->le);
            }
          cfg_vect_add_cmd (cv, "\n");
          write++;
        }
/*     cfg_vect_add_cmd (cv, "!\n"); */
  }

  for (plist = master->str.head; plist; plist = plist->next)
    {
      if (plist->desc)
        {
          cfg_vect_add_cmd (cv, "ip%s prefix-list %s description %s\n",
                   afi == AFI_IP ? "" : "v6",
                   plist->name, plist->desc);
          write++;
        }

      for (pentry = plist->head; pentry; pentry = pentry->next)
        {
          cfg_vect_add_cmd (cv, "ip%s prefix-list %s ",
                   afi == AFI_IP ? "" : "v6",
                   plist->name);

          if (master->seqnum)
            cfg_vect_add_cmd (cv, "seq %lu ", pentry->seq);

          cfg_vect_add_cmd (cv, "%s", prefix_list_type_str (pentry));

          if (pentry->any)
            cfg_vect_add_cmd (cv, " any");
          else
            {
              struct prefix *p = &pentry->prefix;
              char buf[BUFSIZ];

              pal_inet_ntop(p->family,&p->u.prefix,buf,BUFSIZ);
              cfg_vect_add_cmd (cv, " %s/%d",buf,p->prefixlen);

              if (pentry->ge)
                cfg_vect_add_cmd (cv, " ge %d", pentry->ge);
              if (pentry->le)
                cfg_vect_add_cmd (cv, " le %d", pentry->le);
            }
          cfg_vect_add_cmd (cv, "\n");
          write++;
        }
/*    cfg_vect_add_cmd (cv, "!\n"); */
  }
  return write;
}

struct stream *
prefix_bgp_orf_entry (struct stream *s, struct prefix_list *plist,
                      u_int8_t init_flag, u_int8_t permit_flag,
                      u_int8_t deny_flag)
{
  struct prefix_list_entry *pentry;

  if (! plist)
    return s;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      u_int8_t flag = init_flag;
      struct prefix *p = &pentry->prefix;

      flag |= (pentry->type == PREFIX_PERMIT ?
               permit_flag : deny_flag);
      stream_putc (s, flag);
      stream_putl (s, (u_int32_t)pentry->seq);
      stream_putc (s, (u_int8_t)pentry->ge);
      stream_putc (s, (u_int8_t)pentry->le);
      stream_put_prefix (s, p);
    }

  return s;
}

int
prefix_bgp_orf_set (struct ipi_vr *vr, char *name, afi_t afi,
                    struct orf_prefix *orfp,
                    int permit, int set)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;

  /* ge and le value check */
  if (orfp->ge && orfp->ge <= orfp->p.prefixlen)
    return CLI_ERROR;
  if (orfp->le && orfp->le <= orfp->p.prefixlen)
    return CLI_ERROR;
  if (orfp->le && orfp->ge > orfp->le)
    return CLI_ERROR;

  if (orfp->ge && orfp->le == (afi == AFI_IP ? 32 : 128))
    orfp->le = 0;

  plist = prefix_list_get (vr, AFI_ORF_PREFIX, name);
  if (! plist)
    return CLI_ERROR;

  if (set)
    {
      pentry = prefix_list_entry_make (&orfp->p,
                                       (permit ? PREFIX_PERMIT : PREFIX_DENY),
                                       orfp->seq, orfp->le, orfp->ge, 0);

      if (prefix_entry_dup_check (plist, pentry))
        {
          prefix_list_entry_free (pentry);
          return CLI_ERROR;
        }

      prefix_list_entry_add (plist, pentry);
    }
  else
    {
      pentry = prefix_list_entry_lookup (plist, &orfp->p,
                                         (permit ? PREFIX_PERMIT : PREFIX_DENY),
                                         orfp->seq, orfp->le, orfp->ge);

      if (! pentry)
        return CLI_ERROR;

      prefix_list_entry_delete (plist, pentry, 1);
    }

  return CLI_SUCCESS;
}

void
prefix_bgp_orf_remove_all (struct ipi_vr *vr, char *name)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (vr, AFI_ORF_PREFIX, name);
  if (plist)
    prefix_list_delete (plist);
}

/* return prefix count */
int
prefix_bgp_show_prefix_list (struct ipi_vr *vr, struct cli *cli,
                             afi_t afi, char *name)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;

  plist = prefix_list_lookup (vr, AFI_ORF_PREFIX, name);
  if (! plist)
    return 0;

  if (! cli)
    return plist->count;

  cli_out (cli, "ip%s prefix-list %s: %d entries\n",
           afi == AFI_IP ? "" : "v6",
           plist->name, plist->count);

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      struct prefix *p = &pentry->prefix;
      char buf[BUFSIZ];

      pal_inet_ntop(p->family,&p->u.prefix,buf,BUFSIZ);
      cli_out (cli, "   seq %lu %s %s/%d", pentry->seq,
               prefix_list_type_str (pentry),
               buf,
               p->prefixlen);

      if (pentry->ge)
        cli_out (cli, " ge %d", pentry->ge);
      if (pentry->le)
        cli_out (cli, " le %d", pentry->le);

      cli_out (cli, "\n");
    }
  return plist->count;
}

void
prefix_list_finish_orf (struct ipi_vr *vr)
{
  struct prefix_list *plist;
  struct prefix_list *next;
  struct prefix_master *master;

  master = prefix_master_get (vr, AFI_ORF_PREFIX);
  if (master == NULL)
    return;

  for (plist = master->num.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }
  for (plist = master->str.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }

  pal_assert (master->num.head == NULL);
  pal_assert (master->num.tail == NULL);
  pal_assert (master->str.head == NULL);
  pal_assert (master->str.tail == NULL);

  master->seqnum = 1;
  master->recent = NULL;
}

int
config_encode_prefix_ipv4 (struct ipi_vr *vr, cfg_vect_t *cv)
{
  if (config_encode_prefix_afi (vr, AFI_IP, cv) > 0)  {
    cfg_vect_add_cmd (cv, "!\n");
  }
  return 0;
}

int
config_write_prefix_ipv4 (struct cli *cli)
{
  cli->cv = cfg_vect_init(cli->cv);
  config_encode_prefix_ipv4(cli->vr, cli->cv);
  cfg_vect_out(cli->cv, (cfg_vect_out_fun_t)cli->out_func, cli->out_val);
  return 0;
}

void
prefix_list_finish_ipv4 (struct ipi_vr *vr)
{
  struct prefix_list *plist;
  struct prefix_list *next;
  struct prefix_master *master;

  master = prefix_master_get (vr, AFI_IP);
  if (master == NULL)
    return;

  for (plist = master->num.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }
  for (plist = master->str.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }

  pal_assert (master->num.head == NULL);
  pal_assert (master->num.tail == NULL);
  pal_assert (master->str.head == NULL);
  pal_assert (master->str.tail == NULL);

  master->seqnum = 1;
  master->recent = NULL;
}

void
prefix_list_init_ipv4 (struct lib_globals *zg)
{
  struct cli_tree *ctree = zg->ctree;

  cli_install_config (ctree, PREFIX_MODE, config_write_prefix_ipv4);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_ge_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_le_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_seq_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_seq_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_seq_ge_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_seq_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_seq_le_ge_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_prefix_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_ge_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_le_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_seq_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_seq_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_seq_ge_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_seq_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_seq_le_ge_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_description_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_description_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_description_arg_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ip_prefix_list_sequence_number_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ip_prefix_list_sequence_number_cli);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ip_prefix_list_detail_name_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ip_prefix_list_name_seq_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ip_prefix_list_prefix_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ip_prefix_list_prefix_first_match_cli);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ip_prefix_list_detail_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ip_prefix_list_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ip_prefix_list_name_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ip_prefix_list_prefix_longer_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ip_prefix_list_summary_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ip_prefix_list_summary_name_cli);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_prefix_list_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_prefix_list_name_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ip_prefix_list_name_prefix_cli);
}

#ifdef HAVE_IPV6
int
config_encode_prefix_ipv6 (struct ipi_vr *vr, cfg_vect_t *cv)
{
  if (config_encode_prefix_afi (vr, AFI_IP6, cv) > 0)  {
    cfg_vect_add_cmd (cv, "!\n");
  }
  return 0;
}

int
config_write_prefix_ipv6 (struct cli *cli)
{
  cli->cv = cfg_vect_init(cli->cv);
  config_encode_prefix_ipv6(cli->vr, cli->cv);
  cfg_vect_out(cli->cv, (cfg_vect_out_fun_t)cli->out_func, cli->out_val);
  return 0;
}

void
prefix_list_finish_ipv6 (struct ipi_vr *vr)
{
  struct prefix_list *plist;
  struct prefix_list *next;
  struct prefix_master *master;

  master = prefix_master_get (vr, AFI_IP6);
  if (master == NULL)
    return;

  for (plist = master->num.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }
  for (plist = master->str.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }

  pal_assert (master->num.head == NULL);
  pal_assert (master->num.tail == NULL);
  pal_assert (master->str.head == NULL);
  pal_assert (master->str.tail == NULL);

  master->seqnum = 1;
  master->recent = NULL;
}

void
prefix_list_init_ipv6 (struct lib_globals *zg)
{
  struct cli_tree *ctree = zg->ctree;

  cli_install_config (ctree, PREFIX_IPV6_MODE, config_write_prefix_ipv6);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_ge_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_le_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_seq_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_seq_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_seq_ge_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_seq_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_seq_le_ge_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_prefix_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_ge_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_le_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_seq_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_seq_ge_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_seq_ge_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_seq_le_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_seq_le_ge_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_description_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_description_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_description_arg_cli);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &ipv6_prefix_list_sequence_number_cli);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_ipv6_prefix_list_sequence_number_cli);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ipv6_prefix_list_detail_name_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ipv6_prefix_list_name_seq_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ipv6_prefix_list_prefix_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ipv6_prefix_list_prefix_first_match_cli);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ipv6_prefix_list_detail_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ipv6_prefix_list_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ipv6_prefix_list_name_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ipv6_prefix_list_prefix_longer_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ipv6_prefix_list_summary_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &show_ipv6_prefix_list_summary_name_cli);

  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ipv6_prefix_list_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ipv6_prefix_list_name_cli);
  cli_install_gen (ctree, EXEC_MODE, PRIVILEGE_VR_MAX, 0,
                   &clear_ipv6_prefix_list_name_prefix_cli);
}

#endif /* HAVE_IPV6 */

void
prefix_list_init (struct lib_globals *zg)
{
  prefix_list_init_ipv4 (zg);
#ifdef HAVE_IPV6
  prefix_list_init_ipv6 (zg);
#endif /* HAVE_IPV6 */
}

void
prefix_list_finish (struct ipi_vr *vr)
{
  prefix_list_finish_ipv4 (vr);
#ifdef HAVE_IPV6
  prefix_list_finish_ipv6 (vr);
#endif /* HAVE_IPV6 */
  prefix_list_finish_orf (vr);
}
