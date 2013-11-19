/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_PLIST_H
#define _BGPSDN_PLIST_H

#include "pal.h"

#include "prefix.h"
#include "vty.h"

#define AFI_ORF_PREFIX 65535

enum prefix_list_type
{
  PREFIX_NO_MATCH,
  PREFIX_DENY,
  PREFIX_PERMIT
};

enum prefix_name_type
{
  PREFIX_TYPE_STRING,
  PREFIX_TYPE_NUMBER
};

struct prefix_list
{
  char *name;
  char *desc;

  struct prefix_master *master;

  enum prefix_name_type type;

  s_int32_t count;
  s_int32_t rangecount;

  struct prefix_list_entry *head;
  struct prefix_list_entry *tail;

  struct prefix_list *next;
  struct prefix_list *prev;
};

struct orf_prefix
{
  u_int32_t seq;
  u_int8_t ge;
  u_int8_t le;
  u_int8_t dummy[2];
  struct prefix p;
};

/* Each prefix-list's entry. */
struct prefix_list_entry
{
  u_int32_t seq;

  int le;
  int ge;

  enum prefix_list_type type;

  int any;
  struct prefix prefix;

  u_int32_t refcnt;
  u_int32_t hitcnt;

  struct prefix_list_entry *next;
  struct prefix_list_entry *prev;
};

/* List of struct prefix_list. */
struct prefix_list_list
{
  struct prefix_list *head;
  struct prefix_list *tail;
};

/* Master structure of prefix_list. */
struct prefix_master
{
  /* List of prefix_list which name is number. */
  struct prefix_list_list num;

  /* List of prefix_list which name is string. */
  struct prefix_list_list str;

  /* Whether sequential number is used. */
  int seqnum;

  /* The latest update. */
  struct prefix_list *recent;

  /* Hook function which is executed when new prefix_list is added. */
  void (*add_hook) ();

  /* Hook function which is executed when prefix_list is deleted. */
  void (*delete_hook) ();
};

/* Static structure of IPv4 prefix_list's master. */
/* Prototypes. */
void prefix_list_add_hook (struct ipi_vr *, void (*func) (void));
void prefix_list_delete_hook (struct ipi_vr *, void (*func) (void));

struct prefix_list *prefix_list_lookup (struct ipi_vr *, afi_t, char *);
enum prefix_list_type prefix_list_apply (struct prefix_list *, void *);
enum prefix_list_type prefix_list_custom_apply (struct prefix_list *plist,
                                                result_t (*) (void *, void *),
                                                void *);
struct stream *
prefix_bgp_orf_entry (struct stream *, struct prefix_list *,
                      u_int8_t, u_int8_t, u_int8_t);
int prefix_bgp_orf_set (struct ipi_vr *, char *, afi_t, struct orf_prefix *,
                        int, int);
void prefix_bgp_orf_remove_all (struct ipi_vr *, char *);
int prefix_bgp_show_prefix_list (struct ipi_vr *, struct cli *, afi_t, char *);

void prefix_list_delete (struct prefix_list *);
struct prefix_list * prefix_list_get (struct ipi_vr *, afi_t, char *);

int prefix_list_install (struct ipi_vr *, afi_t, char *, int, struct prefix *,
                         u_int32_t, u_int32_t, u_int32_t, int);
int prefix_list_uninstall (struct ipi_vr *, afi_t, char *, struct prefix *,
                           int, u_int32_t, u_int32_t, u_int32_t);
int config_encode_prefix_ipv4 (struct ipi_vr *vr, cfg_vect_t *cv);
int config_write_prefix_ipv4 (struct cli *);
#ifdef HAVE_IPV6
int config_encode_prefix_ipv6 (struct ipi_vr *vr, cfg_vect_t *cv);
int config_write_prefix_ipv6 (struct cli *);
#endif /* HAVE_IPV6 */

void prefix_list_init (struct lib_globals *);
void prefix_list_finish (struct ipi_vr *);
int config_encode_prefix_ipv4 (struct ipi_vr *vr, cfg_vect_t *cv);

#endif /* _BGPSDN_PLIST_H */
