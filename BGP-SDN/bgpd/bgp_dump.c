/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

#ifdef HAVE_BGP_DUMP

/* Some define for BGP packet dump. */
FILE *
bgp_dump_open_file (struct bgp_dump *bgp_dump)
{
  u_int8_t fullpath [MAXPATHLEN];
  u_int8_t realpath [MAXPATHLEN];
  struct pal_tm tm;
  pal_time_t clock;
  s_int32_t ret;

  pal_time_current (&clock);
  pal_time_loc (&clock, &tm);

  if (bgp_dump->filename[0] != DIRECTORY_SEP)
    {
      pal_snprintf (fullpath, MAXPATHLEN, "%s/%s",
                    vty_get_cwd (&BLG), bgp_dump->filename);
      ret = pal_time_strf (realpath, MAXPATHLEN, fullpath, &tm);
    }
  else
    ret = pal_time_strf (realpath, MAXPATHLEN, bgp_dump->filename, &tm);

  if (ret == 0)
    {
      zlog_warn (&BLG, "bgp_dump_open_file: strftime error");
      return NULL;
    }

  if (bgp_dump->fp)
    pal_fclose (bgp_dump->fp);


  bgp_dump->fp = pal_fopen (realpath, "w");

  if (bgp_dump->fp == NULL)
    return NULL;

  return bgp_dump->fp;
}

s_int32_t
bgp_dump_interval_add (struct bgp_dump *bgp_dump,
                       u_int32_t interval)
{
  bgp_dump->t_interval = thread_add_timer (&BLG, bgp_dump_interval_func,
                                           bgp_dump, interval);
  return 0;
}

/* Dump common header. */
void
bgp_dump_header (struct stream *obuf,
                 u_int32_t type,
                 u_int32_t subtype)
{
  pal_time_t now;

  /* Set header. */
  pal_time_current (&now);

  /* Put dump packet header. */
  stream_putl (obuf, now);
  stream_putw (obuf, type);
  stream_putw (obuf, subtype);

  stream_putl (obuf, 0);
}

void
bgp_dump_set_size (struct stream *s,
                   u_int32_t type)
{
  stream_putl_at (s, 8, stream_get_putp (s) - BGP_DUMP_HEADER_SIZE);
}

/* Make attribute packet. */
void
bgp_dump_routes_attr (struct stream *s, struct attr *attr)
{
  struct aspath *aspath;
#ifdef HAVE_EXT_CAP_ASN
  struct as4path *aspath4B;
#endif /* HAVE_EXT_CAP_ASN */
  u_int32_t len;
  u_int32_t cp;

  /* Remember current pointer. */
  cp = stream_get_putp (s);

  /* Place holder of length. */
  stream_putw (s, 0);

  /* Origin attribute. */
  stream_putc (s, BGP_ATTR_FLAG_TRANS);
  stream_putc (s, BGP_ATTR_ORIGIN);
  stream_putc (s, 1);
  stream_putc (s, attr->origin);
#ifndef HAVE_EXT_CAP_ASN
  aspath = attr->aspath;
#else
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    aspath4B = attr->aspath4B;
  else
    aspath = attr->aspath;
#endif /* HAVE_EXT_CAP_ASN */

#ifndef HAVE_EXT_CAP_ASN
  if (aspath->length > 255)
    {
      stream_putc (s, BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
      stream_putc (s, BGP_ATTR_AS_PATH);
      stream_putw (s, aspath->length);
    }
  else
    {
      stream_putc (s, BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_AS_PATH);
      stream_putc (s, aspath->length);
    }
  stream_put (s, aspath->data, aspath->length);
#else
   if (! CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
     {
       if (aspath->length > 255)
         {
           stream_putc (s, BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
           stream_putc (s, BGP_ATTR_AS_PATH);
           stream_putw (s, aspath->length);
         }
       else
         {
           stream_putc (s, BGP_ATTR_FLAG_TRANS);
           stream_putc (s, BGP_ATTR_AS_PATH);
           stream_putc (s, aspath->length);
         }
       stream_put (s, aspath->data, aspath->length); 
     }
   /* Local speaker is NBGP */
   else
     {
        if (aspath4B->length > 255)
         {
           stream_putc (s, BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
           stream_putc (s, BGP_ATTR_AS_PATH);
           stream_putw (s, aspath4B->length);
         }
       else
         {
           stream_putc (s, BGP_ATTR_FLAG_TRANS);
           stream_putc (s, BGP_ATTR_AS_PATH);
           stream_putc (s, aspath4B->length);
         }
       stream_put (s, aspath4B->data, aspath4B->length);
     }
#endif /* HAVE_EXT_CAP_ASN */ 

  /* Nexthop attribute. */
  stream_putc (s, BGP_ATTR_FLAG_TRANS);
  stream_putc (s, BGP_ATTR_NEXT_HOP);
  stream_putc (s, 4);
  stream_put_ipv4 (s, attr->nexthop.s_addr);

  /* MED attribute. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    {
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL);
      stream_putc (s, BGP_ATTR_MULTI_EXIT_DISC);
      stream_putc (s, 4);
      stream_putl (s, attr->med);
    }

  /* Local preference. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    {
      stream_putc (s, BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_LOCAL_PREF);
      stream_putc (s, 4);
      stream_putl (s, attr->local_pref);
    }

  /* Atomic aggregate. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE))
    {
      stream_putc (s, BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_ATOMIC_AGGREGATE);
      stream_putc (s, 0);
    }

  /* Aggregator. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR))
    {
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_AGGREGATOR);
#ifndef HAVE_EXT_CAP_ASN
      stream_putc (s, 6);
      stream_putw (s, attr->aggregator_as);
#else
      if (! CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        {
          stream_putc (s, 6);
          stream_putw (s, attr->aggregator_as);
        } 
      /* Local Speaker is NBGP, uses 4 byte as for aggregation */
      else if (attr->aggregator_as4 != NULL)
        {
          stream_putc (s, 8);
          stream_putw (s, attr->aggregator_as4);
        }
#endif /* HAVE_EXT_CAP_ASN */
      stream_put_ipv4 (s, attr->aggregator_addr.s_addr);
    }

  /* Community attribute. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES))
    {
      if (attr->community->size * 4 > 255)
        {
          stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
          stream_putc (s, BGP_ATTR_COMMUNITIES);
          stream_putw (s, attr->community->size * 4);
        }
      else
        {
          stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS);
          stream_putc (s, BGP_ATTR_COMMUNITIES);
          stream_putc (s, attr->community->size * 4);
        }
      stream_put (s, attr->community->val, attr->community->size * 4);
    }

  /* Return total size of attribute. */
  len = stream_get_putp (s) - cp - 2;
  stream_putw_at (s, cp, len);
}

void
bgp_dump_routes_entry (struct prefix *p,
                       struct bgp_info *info,
                       afi_t afi,
                       u_int32_t type,
                       u_int32_t seq)
{
  struct bgp_peer *peer;
  struct stream *obuf;
  struct attr *attr;
  u_int32_t plen;
  safi_t safi;

  safi = 0;

  /* Make dump stream. */
  obuf = bgp_dump_obuf;
  stream_reset (obuf);

  attr = info->attr;
  peer = info->peer;

  /* We support MRT's old format. */
  if (type == BGP_DUMP_TABLE)
    {
      bgp_dump_header (obuf, BGP_DUMP_TABLE, afi);
      stream_putw (obuf, 0);            /* View # */
      stream_putw (obuf, seq);          /* Sequence number. */
    }
  else
    {
      bgp_dump_header (obuf, MSG_PROTOCOL_BGP4MP, BGP4MP_ENTRY);

      stream_putl (obuf, info->bri_uptime); /* Time Last Change */
      stream_putw (obuf, afi);          /* Address Family */
      stream_putc (obuf, safi);         /* SAFI */
    }

  if (afi == AFI_IP)
    {
      if (type == BGP_DUMP_TABLE)
        {
          /* Prefix */
          stream_put_in_addr (obuf, &p->u.prefix4);
          stream_putc (obuf, p->prefixlen);

          /* Status */
          stream_putc (obuf, 1);

          /* Originated */
          stream_putl (obuf, info->bri_uptime);

          /* Peer's IP address */
          stream_put_in_addr (obuf, &peer->su.sin.sin_addr);

          /* Peer's AS number. */
          stream_putw (obuf, peer->as);

          /* Dump attribute. */
          bgp_dump_routes_attr (obuf, attr);
        }
      else
        {
          /* Next-Hop-Len */
          stream_putc (obuf, IPV4_MAX_BYTELEN);
          stream_put_in_addr (obuf, &attr->nexthop);
          stream_putc (obuf, p->prefixlen);
          plen = PSIZE (p->prefixlen);
          stream_put (obuf, &p->u.prefix4, plen);
          bgp_dump_routes_attr (obuf, attr);
        }
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && afi == AFI_IP6)
    {
      if (type == BGP_DUMP_TABLE)
        {
          /* Prefix */
          stream_write (obuf, (u_char *)&p->u.prefix6, IPV6_MAX_BYTELEN);
          stream_putc (obuf, p->prefixlen);

          /* Status */
          stream_putc (obuf, 1);

          /* Originated */
          stream_putl (obuf, info->bri_uptime);

          /* Peer's IP address */
          stream_write (obuf, (u_char *)&peer->su.sin6.sin6_addr,
                        IPV6_MAX_BYTELEN);

          /* Peer's AS number. */
          stream_putw (obuf, peer->as);

          /* Dump attribute. */
          bgp_dump_routes_attr (obuf, attr);
        }
      else
        {
          ;
        }
    }
#endif /* HAVE_IPV6 */

  /* Set length. */
  bgp_dump_set_size (obuf, type);

  pal_fwrite (STREAM_DATA (obuf), stream_get_putp (obuf), 1,
              bgp_dump_routes->fp);
  pal_fflush (bgp_dump_routes->fp);

  return;
}

/* Runs under child process. */
void
bgp_dump_routes_func (afi_t afi)
{
  struct bgp_ptree *table;
  struct bgp_info *info;
  struct stream *obuf;
  struct bgp_node *rn;
  struct bgp *bgp;
  u_int32_t seq;
  struct prefix rnp;

  obuf = bgp_dump_obuf;
  seq = 0;

  bgp = bgp_lookup_default ();
  if (!bgp)
    return;

  if (bgp_dump_routes->fp == NULL)
    return;

  /* Walk down each BGP route. */
  table = bgp->rib[BGP_AFI2BAAI (afi)] [BGP_SAFI2BSAI (SAFI_UNICAST)];

  for (rn = bgp_table_top (table); rn; 
       rn = bgp_route_next (rn))
    for (info = rn->info; info; info = info->next)
    {
      BGP_GET_PREFIX_FROM_NODE (rn);	
      bgp_dump_routes_entry (&rnp, info, afi, BGP_DUMP_TABLE, seq++);
    }
}

s_int32_t
bgp_dump_interval_func (struct thread *t)
{
  struct bgp_dump *bgp_dump;

  bgp_dump = THREAD_ARG (t);
  bgp_dump->t_interval = NULL;

  if (bgp_dump_open_file (bgp_dump) == NULL)
    return 0;

  /* In case of bgp_dump_routes, we need special route dump function. */
  if (bgp_dump->type == BGP_DUMP_ROUTES)
    {
      bgp_dump_routes_func (AFI_IP);
      bgp_dump_routes_func (AFI_IP6);
    }

  bgp_dump_interval_add (bgp_dump, bgp_dump->interval);

  return 0;
}

/* Dump common information. */
void
bgp_dump_common (struct stream *obuf, struct bgp_peer *peer)
{
  u_int8_t empty [16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

  /* Source AS number and Destination AS number. */
  stream_putw (obuf, peer->as);
  stream_putw (obuf, peer->local_as);

  if (peer->afc[BGP_AFI2BAAI (AFI_IP)][BGP_SAFI2BSAI (SAFI_UNICAST)])
    {
      stream_putw (obuf, AFI_IP);

      stream_put (obuf, &peer->su.sin.sin_addr, IPV4_MAX_BYTELEN);

      if (peer->su_local)
        stream_put (obuf, &peer->su_local->sin.sin_addr, IPV4_MAX_BYTELEN);
      else
        stream_put (obuf, empty, IPV4_MAX_BYTELEN);
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && peer->afc[BGP_AFI2BAAI (AFI_IP6)][BGP_SAFI2BSAI (SAFI_UNICAST)])
    {
      /* Interface Index and Address family. */
      stream_putw (obuf, AFI_IP6);

      /* Source IP Address and Destination IP Address. */
      stream_put (obuf, &peer->su.sin6.sin6_addr, IPV6_MAX_BYTELEN);

      if (peer->su_local)
        stream_put (obuf, &peer->su_local->sin6.sin6_addr, IPV6_MAX_BYTELEN);
      else
        stream_put (obuf, empty, IPV6_MAX_BYTELEN);
    }
#endif /* HAVE_IPV6 */
}

/* Dump BGP status change. */
void
bgp_dump_state (struct bgp_peer *peer,
                u_int32_t status_old,
                u_int32_t status_new)
{
  struct stream *obuf;

  /* If dump file pointer is disabled return immediately. */
  if (bgp_dump_all->fp == NULL)
    return;

  /* Make dump stream. */
  obuf = bgp_dump_obuf;
  stream_reset (obuf);

  bgp_dump_header (obuf, MSG_PROTOCOL_BGP4MP, BGP4MP_STATE_CHANGE);
  bgp_dump_common (obuf, peer);

  stream_putw (obuf, status_old);
  stream_putw (obuf, status_new);

  /* Set length. */
  bgp_dump_set_size (obuf, MSG_PROTOCOL_BGP4MP);

  /* Write to the stream. */
  pal_fwrite (STREAM_DATA (obuf), stream_get_putp (obuf),
              1, bgp_dump_all->fp);
  pal_fflush (bgp_dump_all->fp);

  return;
}

void
bgp_dump_packet_func (struct bgp_dump *bgp_dump,
                      struct bgp_peer *peer,
                      struct stream *packet)
{
  struct stream *obuf;

  /* If dump file pointer is disabled return immediately. */
  if (bgp_dump->fp == NULL)
    return;

  /* Make dump stream. */
  obuf = bgp_dump_obuf;
  stream_reset (obuf);

  /* Dump header and common part. */
  bgp_dump_header (obuf, MSG_PROTOCOL_BGP4MP, BGP4MP_MESSAGE);
  bgp_dump_common (obuf, peer);

  /* Packet contents. */
  stream_put (obuf, STREAM_DATA (packet), stream_get_endp (packet));

  /* Set length. */
  bgp_dump_set_size (obuf, MSG_PROTOCOL_BGP4MP);

  /* Write to the stream. */
  pal_fwrite (STREAM_DATA (obuf), stream_get_putp (obuf),
              1, bgp_dump->fp);
  pal_fflush (bgp_dump->fp);

  return;
}

/* Dump received messages */
void
bgp_dump_packet (struct bgp_peer *peer,
                 u_int32_t type,
                 struct stream *packet)
{
  /* bgp_dump_all. */
  bgp_dump_packet_func (bgp_dump_all, peer, packet);

  /* bgp_dump_updates. */
  if (type == BGP_MSG_UPDATE)
    bgp_dump_packet_func (bgp_dump_updates, peer, packet);
}

u_int32_t
bgp_dump_parse_time (u_int8_t *str)
{
  u_int32_t seen_h;
  u_int32_t seen_m;
  u_int32_t total;
  pal_time_t time;
  u_int32_t len;
  u_int32_t i;

  time = 0;
  total = 0;
  seen_h = 0;
  seen_m = 0;
  len = pal_strlen (str);

  for (i = 0; i < len; i++)
    {
      if (pal_char_isdigit ((int) str[i]))
        {
          time *= 10;
          time += str[i] - '0';
        }
      else if (str[i] == 'H' || str[i] == 'h')
        {
          if (seen_h)
            return 0;
          if (seen_m)
            return 0;
          total += time * 60 *60;
          time = 0;
          seen_h = 1;
        }
      else if (str[i] == 'M' || str[i] == 'm')
        {
          if (seen_m)
            return 0;
          total += time * 60;
          time = 0;
          seen_h = 1;
        }
      else
        return 0;
    }
  return total + time;
}

s_int32_t
bgp_dump_set (struct cli *cli,
              struct bgp_dump *bgp_dump,
              u_int32_t type,
              u_int8_t *path,
              u_int8_t *interval_str)
{
  u_int32_t interval;

  if (interval_str)
    {
      /* Check interval string. */
      interval = bgp_dump_parse_time (interval_str);
      if (interval == 0)
        {
          cli_out (cli, "Malformed interval string\n");
          return CLI_ERROR;
        }
      /* Set interval. */
      bgp_dump->interval = interval;
      if (bgp_dump->interval_str)
        XFREE (MTYPE_TMP, bgp_dump->interval_str);
      bgp_dump->interval_str = XSTRDUP (MTYPE_TMP, interval_str);

      /* Create interval thread. */
      bgp_dump_interval_add (bgp_dump, interval);
    }

  /* Set type. */
  bgp_dump->type = type;

  /* Set file name. */
  if (bgp_dump->filename)
    XFREE (MTYPE_TMP, bgp_dump->filename);
  bgp_dump->filename = XSTRDUP (MTYPE_TMP, path);

  /* This should be called when interval is expired. */
  bgp_dump_open_file (bgp_dump);

  return CLI_SUCCESS;
}

int
bgp_dump_unset (struct cli *cli, struct bgp_dump *bgp_dump)
{
  /* Set file name. */
  if (bgp_dump->filename)
    {
      XFREE (MTYPE_TMP, bgp_dump->filename);
      bgp_dump->filename = NULL;
    }

  /* This should be called when interval is expired. */
  if (bgp_dump->fp)
    {
      pal_fclose (bgp_dump->fp);
      bgp_dump->fp = NULL;
    }

  /* Create interval thread. */
  if (bgp_dump->t_interval)
    {
      thread_cancel (bgp_dump->t_interval);
      bgp_dump->t_interval = NULL;
    }

  bgp_dump->interval = 0;

  if (bgp_dump->interval_str)
    {
      XFREE (MTYPE_TMP, bgp_dump->interval_str);
      bgp_dump->interval_str = NULL;
    }

  return CLI_SUCCESS;
}

CLI (dump_bgp_all,
     dump_bgp_all_cmd,
     "dump bgp all PATH",
     "Dump packet",
     "BGP packet dump",
     "Dump all BGP packets",
     "Output filename")
{
  return bgp_dump_set (cli, bgp_dump_all, BGP_DUMP_ALL, argv[0], NULL);
}

CLI (dump_bgp_all_interval,
     dump_bgp_all_interval_cmd,
     "dump bgp all PATH INTERVAL",
     "Dump packet",
     "BGP packet dump",
     "Dump all BGP packets",
     "Output filename",
     "Interval of output")
{
  return bgp_dump_set (cli, bgp_dump_all, BGP_DUMP_ALL, argv[0], argv[1]);
}

CLI (no_dump_bgp_all,
     no_dump_bgp_all_cmd,
     "no dump bgp all PATH INTERVAL",
     CLI_NO_STR,
     "Dump packet",
     "BGP packet dump",
     "Dump all BGP packets",
     "Output filename",
     "Interval of output")
{
  return bgp_dump_unset (cli, bgp_dump_all);
}

CLI (dump_bgp_updates,
     dump_bgp_updates_cmd,
     "dump bgp updates PATH",
     "Dump packet",
     "BGP packet dump",
     "Dump BGP updates only",
     "Output filename")
{
  return bgp_dump_set (cli, bgp_dump_updates, BGP_DUMP_UPDATES, argv[0], NULL);
}

CLI (dump_bgp_updates_interval,
     dump_bgp_updates_interval_cmd,
     "dump bgp updates PATH INTERVAL",
     "Dump packet",
     "BGP packet dump",
     "Dump BGP updates only",
     "Output filename",
     "Interval of output")
{
  return bgp_dump_set (cli, bgp_dump_updates, BGP_DUMP_UPDATES, argv[0], argv[1]);
}

CLI (no_dump_bgp_updates,
     no_dump_bgp_updates_cmd,
     "no dump bgp updates PATH INTERVAL",
     CLI_NO_STR,
     "Dump packet",
     "BGP packet dump",
     "Dump BGP updates only",
     "Output filename",
     "Interval of output")
{
  return bgp_dump_unset (cli, bgp_dump_updates);
}

CLI (dump_bgp_routes,
     dump_bgp_routes_cmd,
     "dump bgp routes-mrt PATH",
     "Dump packet",
     "BGP packet dump",
     "Dump whole BGP routing table",
     "Output filename")
{
  return bgp_dump_set (cli, bgp_dump_routes, BGP_DUMP_ROUTES, argv[0], NULL);
}

CLI (dump_bgp_routes_interval,
     dump_bgp_routes_interval_cmd,
     "dump bgp routes-mrt PATH INTERVAL",
     "Dump packet",
     "BGP packet dump",
     "Dump whole BGP routing table",
     "Output filename",
     "Interval of output")
{
  return bgp_dump_set (cli, bgp_dump_routes, BGP_DUMP_ROUTES, argv[0], argv[1]);
}

CLI (no_dump_bgp_routes,
     no_dump_bgp_routes_cmd,
     "no dump bgp routes-mrt PATH INTERVAL",
     CLI_NO_STR,
     "Dump packet",
     "BGP packet dump",
     "Dump whole BGP routing table",
     "Output filename",
     "Interval of output")
{
  return bgp_dump_unset (cli, bgp_dump_routes);
}

s_int32_t
config_write_bgp_dump (struct cli *cli)
{
  if (bgp_dump_all->filename)
    {
      if (bgp_dump_all->interval_str)
        cli_out (cli, "dump bgp all %s %s\n",
                 bgp_dump_all->filename,
                 bgp_dump_all->interval_str);
      else
        cli_out (cli, "dump bgp all %s\n",
                 bgp_dump_all->filename);
    }
  if (bgp_dump_updates->filename)
    {
      if (bgp_dump_updates->interval_str)
        cli_out (cli, "dump bgp updates %s %s\n",
                 bgp_dump_updates->filename,
                 bgp_dump_updates->interval_str);
      else
        cli_out (cli, "dump bgp updates %s\n",
                 bgp_dump_updates->filename);
    }
  if (bgp_dump_routes->filename)
    {
      if (bgp_dump_routes->interval_str)
        cli_out (cli, "dump bgp routes-mrt %s %s\n",
                 bgp_dump_routes->filename,
                 bgp_dump_routes->interval_str);
      else
        cli_out (cli, "dump bgp routes-mrt %s\n",
                 bgp_dump_routes->filename);
    }
  return 0;
}

/* Initialize BGP packet dump functionality. */
void
bgp_dump_cli_init (struct cli_tree *ctree)
{
  cli_install_config (ctree, DUMP_MODE, config_write_bgp_dump);

  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &dump_bgp_all_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &dump_bgp_all_interval_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_dump_bgp_all_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &dump_bgp_updates_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &dump_bgp_updates_interval_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_dump_bgp_updates_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &dump_bgp_routes_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &dump_bgp_routes_interval_cmd);
  cli_install_gen (ctree, CONFIG_MODE, PRIVILEGE_NORMAL, 0,
                   &no_dump_bgp_routes_cmd);

  return;
}
#endif /* HAVE_BGP_DUMP */
