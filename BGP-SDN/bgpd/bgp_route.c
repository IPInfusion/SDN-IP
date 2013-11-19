/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

#ifdef HAVE_BGP_SDN
#include <onion/onion.h>
#include <onion/dict.h>
#include <onion/shortcuts.h>
#include <curl/curl.h>
#endif /* HAVE_BGP_SDN */

#define IPV4_NEXTHOP_ADDR_CMP(A,B) ((IPV4_ADDR_CMP(&((A)->nexthop), &((B)->nexthop))))
#define IPV6_NEXTHOP_ADDR_CMP(A,B) ((IPV6_ADDR_CMP(&((A)->mp_nexthop_global), &((B)->mp_nexthop_global))))

#ifdef HAVE_BGP_SDN

static onion *bgp_onion = NULL;

#define BGP_MAX_CURL_LIST 700
#define MAX_BGP_URL 256

s_int32_t
bgp_curl_free (void *url)
{
  if (url)
    XFREE (MTYPE_TMP, url);
  return 0;
}

int
bgp_get_router_id (const char *path, struct pal_in4_addr *addr)
{
  char *str;
  char *rid;
  char *p;

  str = XSTRDUP(MTYPE_TMP, path);
  if (!str)
    return -1;

  rid = str;

  /* skip the first */
  rid++;

  p = pal_strstr (rid, "/");
  if (p)
    *p = '\0';
 
  if (pal_inet_pton (AF_INET, rid, addr) != 1)
    return -1;

  XFREE(MTYPE_TMP, str);

  return 0;
}

struct bgp *
bgp_lookup_from_path (onion_request *req)
{
  const char *path;
  struct pal_in4_addr rid;
  struct bgp *bgp;

  path = onion_request_get_path (req);
  if (path)
    {
      if (bgp_get_router_id (path, &rid) < 0)
	return NULL;
    }
  else
    {
      return NULL;
    }    

  bgp = bgp_lookup_by_routerid (&rid);
  if (! bgp)
    {
      zlog_warn (&BLG, "[SDN] no bgp instance");
      return NULL;
    }

  return bgp;
}

static int
bgp_get_method(void *p, onion_request *req, onion_response *res)
{
  int ret = OCS_PROCESSED;
  char *idx;
  onion_dict *dict = NULL;
  onion_dict *a = NULL;
  onion_dict *d = NULL;
  char pfx[24];
  char rid[INET_ADDRSTRLEN];
  char nh[INET_ADDRSTRLEN];
  const char *s;
  struct bgp *bgp;
  struct bgp_ptree *table;
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct prefix rnp;

  bgp = bgp_lookup_from_path (req);
  if (! bgp)
    {
      zlog_warn (&BLG, "[SDN] no bgp instance");
      ret = OCS_INTERNAL_ERROR;
      goto end;
    }

  s = pal_inet_ntop (AF_INET, &bgp->router_id, rid, INET_ADDRSTRLEN);
  if (! s)
    {
      zlog_warn (&BLG, "[SDN] inet_ntop(%d)", errno);
      ret = OCS_INTERNAL_ERROR;
      goto end;
    }

  /* onion_dict_new: return check will not be done */
  dict = onion_dict_new ();

  onion_dict_add (dict, "router-id", rid, OD_DUP_ALL);

  table = bgp->rib [BAAI_IP][BSAI_UNICAST];
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      bgp_ptree_get_prefix_from_node (rn, &rnp);

      prefix2str_ipv4 ((struct prefix_ipv4 *)&rnp, pfx, 24);

      s = NULL;
      for (ri = rn->info; ri; ri = ri->next)
        {
	  if (! CHECK_FLAG (ri->flags_misc, BGP_INFO_MULTI_POST))
	    continue;

          s = pal_inet_ntop (AF_INET, &ri->attr->nexthop, nh, INET_ADDRSTRLEN);
          if (! s)
            zlog_warn (&BLG, "[SDN] inet_ntop(%d)", errno);
	  else
            {
	      if (!a)
  	        a = onion_dict_new ();

	      d = onion_dict_new ();
              onion_dict_add (d, "prefix", pfx, OD_DUP_ALL);
              onion_dict_add (d, "nexthop", nh, OD_DUP_ALL);

  	      idx = strdup("");
              onion_dict_add (a, idx, d, OD_DICT|OD_FREE_ALL);
            }
        }
    }

  if (a)
    {
      idx = strdup("rib");
      onion_dict_add (dict, idx, a, OD_DICT_ARRAY|OD_FREE_ALL);
    }

  ret = onion_shortcut_response_json(dict, req, res);
  if (ret != OCS_PROCESSED)
    {
      zlog_warn (&BLG, "[SDN] onion_shortcut_response_json failed");
      goto end;
    }

end:
  return ret;
}

int
bgp_get_rib_from_path (onion_request *req, struct prefix *pfx, struct pal_in4_addr *nh)
{
  int ret = 0;
  const char *path = NULL;
  char *str = NULL;
  char *p, *tmp;

  pfx->family = AF_INET;

  path = onion_request_get_path (req);
  if (!path)
    {
      ret = -1;
      goto end;
    }

  str = XSTRDUP(MTYPE_TMP, path);
  if (!str)
    {
      ret = -1;
      goto end;
    }

  p = str;

  /* skip the first */
  p++;
  
  /* skip router-id */
  p = pal_strstr (p, "/");
  if (!p)
    {
      ret = -1;
      goto end;
    }

  /* prefix */
  tmp = ++p;
  p = pal_strstr (p, "/");
  if (!p)
    {
      ret = -1;
      goto end;
    }

  *p = '\0';
  p++;

  if (pal_inet_pton (AF_INET, tmp, &pfx->u.prefix4) != 1)
    {
      ret = -1;
      goto end;
    }

  /* prefix length */
  tmp = p;
  p = pal_strstr (p, "/");
  if (!p)
    {
      ret = -1;
      goto end;
    }

  *p = '\0';
  p++;

  pfx->prefixlen = (u_int8_t)pal_strtou32 (tmp, (char **)NULL, 10);

  /* nexthop */
  tmp = p;
  p = pal_strstr (p, "/");
  if (p)
    *p = '\0';

  if (pal_inet_pton (AF_INET, tmp, nh) != 1)
    {
      ret = -1;
      goto end;
    }


end:
  if (str)
    XFREE(MTYPE_TMP, str);

  return ret;
}

int
bgp_post_method (void *p, onion_request *req, onion_response *res)
{
  int ret = OCS_PROCESSED;
  struct bgp *bgp;
  struct prefix pfx;
  struct pal_in4_addr nh;
  struct bgp_msg_route_ipv4 msg;

  bgp = bgp_lookup_from_path (req);
  if (! bgp)
    {
      zlog_warn (&BLG, "[SDN] no bgp instance");
      ret = OCS_INTERNAL_ERROR;
      goto end;
    }

  if (bgp_get_rib_from_path (req, &pfx, &nh) < 0)
    {
      zlog_warn (&BLG, "[SDN] no rib info\n");
      ret = OCS_INTERNAL_ERROR;
      goto end;
    }

  pal_mem_set (&msg, 0, sizeof(struct bgp_msg_route_ipv4));
  SET_FLAG (msg.flags, BGP_MSG_ROUTE_FLAG_ADD);

  msg.type = IPI_ROUTE_SDN;
  msg.sub_type = 0;
  msg.distance = IPI_DISTANCE_SDN;
  msg.metric = IPI_METRIC_SDN;
  msg.prefix = pfx.u.prefix4;
  msg.prefixlen = pfx.prefixlen;
  msg.nexthop_num = 1;
  BGP_SET_CTYPE (msg.cindex, BGP_ROUTE_CTYPE_IPV4_NEXTHOP);
  msg.nexthop[0].addr = nh; 

  bgp_redistribute_add (bgp, &msg, AF_INET, PAL_FALSE);

end:
  return ret;
}

int
bgp_delete_method (void *p, onion_request *req, onion_response *res)
{
  int ret = OCS_PROCESSED;
  struct bgp *bgp;
  struct prefix pfx;
  struct pal_in4_addr nh;

  bgp = bgp_lookup_from_path (req);
  if (! bgp)
    {
      zlog_warn (&BLG, "[SDN] no bgp instance");
      ret = OCS_INTERNAL_ERROR;
      goto end;
    }

  if (bgp_get_rib_from_path (req, &pfx, &nh) < 0)
    {
      zlog_warn (&BLG, "[SDN] no rib info\n");
      ret = OCS_INTERNAL_ERROR;
      goto end;
    }

  bgp_redistribute_delete (bgp, &pfx, IPI_ROUTE_SDN, PAL_FALSE);

end:
  return ret;
}

int
bgp_req_handler(void *p, onion_request *req, onion_response *res)
{
  int ret;

  zlog_warn(&BLG, "%s is called\n", __FUNCTION__);

  if ((onion_request_get_flags(req) & OR_METHODS) == OR_GET)
    {
      /* GET */
      ret = bgp_get_method (p, req, res);
    }
  else if ((onion_request_get_flags(req) & OR_METHODS) == OR_POST)
    {
      /* POST */
      ret = bgp_post_method (p, req, res);
    }
  else if ((onion_request_get_flags(req) & OR_METHODS) == OR_DELETE)
    {
      /* DELETE */
      ret = bgp_delete_method (p, req, res);
    }
  else
    {
      ret = OCS_NOT_IMPLEMENTED;
    }

  return ret;
}

void
bgp_onion_stop (void)
{
  if (bgp_onion)
    {
      onion_listen_stop (bgp_onion);
      onion_free (bgp_onion);
    }

  bgp_onion = NULL;

  return;
}

int
bgp_onion_init (void)
{
  int ret = 0;
  int api_ret;
  onion_url *urls;

  /* onion_new: return check will not be done */
  bgp_onion = onion_new(O_POOL|O_DETACH_LISTEN|O_THREADED|O_SYSTEMD);
  if (!bgp_onion)
    {
      zlog_warn (&BLG, "[SDN] onion_new failed\n");
      ret = -1;
      goto end;
    }

  if (bgp_rest_addr)
    onion_set_hostname (bgp_onion, bgp_rest_addr);

  if (bgp_rest_port)
    onion_set_port (bgp_onion, bgp_rest_port);

  urls = onion_root_url(bgp_onion);
  if (urls == NULL)
    {
      zlog_warn (&BLG, "[SDN] onion_root_url failed");
      ret = -1;
      goto end;
    }

  api_ret = onion_url_add(urls, "^wm\/bgp", bgp_req_handler);
  if (api_ret != 0)
    {
      zlog_warn (&BLG, "[SDN] onion_url_add failed");
      ret = -1;
      goto end;
    }

  api_ret = onion_listen(bgp_onion);
  if (api_ret != 0) 
    {
      zlog_warn (&BLG, "[SDN] onion_listen failed\n");
      ret = -1;
      goto end;
    }

  return ret;

end:
  if (bgp_onion != NULL)
    onion_free(bgp_onion);
  bgp_onion = NULL;

  return ret;
}

void
bgp_curl_cleanup (CURL *handle, int resubmit)
{
  struct listnode *node;
  struct bgp_curl_info *info;

  if (! bgp_curl_list)
    return;

  LIST_LOOP (bgp_curl_list, info, node)
    {
      if (info->handle == handle)
	break;
    }

  if (node)
    {
      if (resubmit)
	(void) bgp_send_url (NULL, info->url, info->post);

      XFREE (MTYPE_TMP, info->url);
      XFREE (MTYPE_TMP, info);
      node->data = NULL;

      list_delete_node (bgp_curl_list, node);
    }

  return;
}

void
bgp_process_pending_url (void)
{
  struct listnode *node, *next;
  struct bgp_curl_info *info;

  node = bgp_curl_list_pending->head;
  while (node && LISTCOUNT(bgp_curl_list) < BGP_MAX_CURL_LIST)
    {
      next = node->next;
      info = (struct bgp_curl_info *)node->data;
      if (info)
	{
          (void) bgp_send_url (NULL, info->url, info->post);

          XFREE (MTYPE_TMP, info->url);
          XFREE (MTYPE_TMP, info);
          node->data = NULL;

          list_delete_node (bgp_curl_list_pending, node);
	}
      node = next;
    }
}

int
bgp_send_url_check(struct thread *t)
{
  int msg_left;
  int cnt = 0;
  int running;
  CURLMsg *msg;

#define BGP_SEND_URL_CHECK_MAX 100

  bgp_curlm_thread = NULL;

  curl_multi_perform (bgp_curlm, &running);
  if (running)
    {
      msg_left = 1;
      goto EXIT;
    }

  while ((msg = curl_multi_info_read(bgp_curlm, &msg_left)) != NULL)
    {
      if (msg->msg == CURLMSG_DONE)
  	{
 	  if (msg->data.result == CURLE_COULDNT_CONNECT
           || msg->data.result == CURLE_RECV_ERROR
           || msg->data.result == CURLE_SEND_ERROR)
	    {
	      bgp_curl_cleanup (msg->easy_handle, 1);
	    }
	  else
	    {
	      bgp_curl_cleanup (msg->easy_handle, 0);
	    }

          /* always cleanup */ 
          curl_multi_remove_handle (bgp_curlm, msg->easy_handle);
          curl_easy_cleanup(msg->easy_handle);
        }

      if (++cnt > BGP_SEND_URL_CHECK_MAX)
        break;
    }

EXIT:
  bgp_process_pending_url ();

  if (msg_left)
    bgp_curlm_thread = thread_add_timer (&BLG, bgp_send_url_check, NULL, 1);

  return 0;
}

int
bgp_send_url (struct bgp *bgp, char *url, int post)
{
  CURL *curl;
  CURLcode code;
  int running;
  struct bgp_curl_info *info;

  if (! bgp_curlm)
    return -1;

  if (LISTCOUNT(bgp_curl_list) > BGP_MAX_CURL_LIST)
    {
      info = XCALLOC (MTYPE_TMP, sizeof (struct bgp_curl_info));
      if (info)
	{
	  info->url = XSTRDUP (MTYPE_TMP, url);
          info->post = post;
	  (void) listnode_add (bgp_curl_list_pending, info);
    	}

      goto EXIT;
    }

  curl = curl_easy_init ();
  if (! curl)
    return -1;

  curl_easy_setopt(curl, CURLOPT_URL, url);
  if (post)
    {
      curl_easy_setopt(curl, CURLOPT_HTTPPOST, NULL);
    }
  else
    {
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
    }

  //curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);

  curl_multi_add_handle (bgp_curlm, curl);
  code = curl_multi_perform(bgp_curlm, &running);

  if(code != CURLE_OK)
    zlog_warn(&BLG, "curl_multi_perform() failed: %s\n",
          curl_easy_strerror(code));
 
  if (! running)
    {
      curl_multi_remove_handle (bgp_curlm, curl);
      curl_easy_cleanup (curl);
      return 0;
    }

  info = XCALLOC (MTYPE_TMP, sizeof (struct bgp_curl_info));
  if (info)
    {
      info->handle = curl;
      info->url = XSTRDUP (MTYPE_TMP, url);
      info->post = post;

      (void) listnode_add (bgp_curl_list, info);
    }
 
EXIT:
  if (!bgp_curlm_thread)
    bgp_curlm_thread = thread_add_timer(&BLG, bgp_send_url_check, NULL, 1); 

  return 0;
}

char *
bgp_make_url (struct bgp *bgp, char *addr, u_int16_t port,
	      struct prefix *p, struct bgp_info *bi,
              char *url, int size)
{
  char pfx[24];
  char rid[INET_ADDRSTRLEN];
  char nh[INET_ADDRSTRLEN];
  const char *s;
  pal_time_t uptime = 0;
  static pal_time_t prev = 0;
  static long seq = 0;

  if ((uptime = pal_time_since_boot ()) < 0)
    {
      zlog_warn (&BLG, "[SDN] Failed to get the current sysuptime");
      return NULL;
    }

  if (uptime > prev)
    {
      seq = 0;
      prev = uptime;
    }
  else
    {
      uptime = prev;
    }

  s = pal_inet_ntop (AF_INET, &bgp->router_id, rid, INET_ADDRSTRLEN);
  if (!s)
    {
      zlog_warn (&BLG, "[SDN] inet_ntop(%d)", errno);
      return NULL;
    }

  prefix2str_ipv4 ((struct prefix_ipv4 *)p, pfx, 24);

  s = pal_inet_ntop (AF_INET, &bi->attr->nexthop, nh, INET_ADDRSTRLEN);
  if (! s)
    {
      zlog_warn (&BLG, "[SDN] inet_ntop(%d)", errno);
      return NULL;
    }

  pal_snprintf (url, size, "http://%s:%d/wm/bgp/%ld/%ld/%s/%s/%s",
		addr, port, uptime, ++seq, rid, pfx, nh); 

  return url;
}

void
bgp_post_rib (struct bgp *bgp, struct prefix *p, struct bgp_info *bi)
{
  char url[MAX_BGP_URL];
  char *addr;
  u_int16_t port;
  int i;

  if (CHECK_FLAG (bi->flags_misc, BGP_INFO_MULTI_POST))
    return;

  for (i = 0; i < BGP_MAX_SDN_CLIENT; i++)
    {
      addr = bgp_sdn_addr[i];
      port = bgp_sdn_port[i];

      if (! addr || ! port)
	continue;

      if (bgp_make_url(bgp, addr, port, p, bi, url, MAX_BGP_URL) == NULL)
        {
          zlog_warn (&BLG, "[SDN] failed to create a post url");
          continue;
        }

      if (bgp_send_url (bgp, url, 1) < 0)
        {
          zlog_warn (&BLG, "[SDN] failed to post url");
          continue;
        }
    }

  SET_FLAG (bi->flags_misc, BGP_INFO_MULTI_POST);

  return;
}

void
bgp_delete_rib (struct bgp *bgp, struct prefix *p, struct bgp_info *bi)
{
  char url[MAX_BGP_URL];
  char *addr;
  u_int16_t port;
  int i;

  if (! CHECK_FLAG (bi->flags_misc, BGP_INFO_MULTI_POST))
    return;

  for (i = 0; i < BGP_MAX_SDN_CLIENT; i++)
    {
      addr = bgp_sdn_addr[i];
      port = bgp_sdn_port[i];

      if (! addr || ! port)
	continue;
 
      if (bgp_make_url(bgp, addr, port, p, bi, url, MAX_BGP_URL) == NULL)
        {
          zlog_warn (&BLG, "[SDN] failed to create a post url");
          continue;
        }

      if (bgp_send_url (bgp, url, 0) < 0)
        {
          zlog_warn (&BLG, "[SDN] failed to delete url");
          continue;
        }
    }

  UNSET_FLAG (bi->flags_misc, BGP_INFO_MULTI_POST);

  return;
}

void
bgp_rest_handler (struct bgp *bgp, struct bgp_node *rn,
	          struct bgp_info *new, struct bgp_info *old,
		  struct bgp_info *del)
{
  struct prefix rnp;
  struct bgp_info *ri;

  bgp_ptree_get_prefix_from_node (rn, &rnp);

  if (old && old != new)
    bgp_delete_rib (bgp, &rnp, old);

  if (del)
    bgp_delete_rib (bgp, &rnp, del);

  if (new)
    bgp_post_rib (bgp, &rnp, new);

  if (! bgp_config_check(bgp, BGP_CFLAG_ECMP_ENABLE))
    return;

  for (ri = rn->info; ri != NULL; ri = ri->next)
    {
      if ((new && ri == new)
       || (del && ri == del))
	continue;

      if (! CHECK_FLAG(ri->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE))
	{
	  bgp_delete_rib (bgp, &rnp, ri);
	}
      else
	{
	  bgp_post_rib (bgp, &rnp, ri);
	}
    }

  return;
}

char *
bgp_make_url_for_routerid (struct bgp *bgp, char *addr,
		  	   u_int16_t port, char *url, int size)
{
  char rid[INET_ADDRSTRLEN];
  const char *s;
  u_int32_t capability = 0;

  s = pal_inet_ntop (AF_INET, &bgp->router_id, rid, INET_ADDRSTRLEN);
  if (!s)
    {
      zlog_warn (&BLG, "[SDN] inet_ntop(%d)", errno);
      return NULL;
    }

#if 0
  if (bgp_status_check (bgp, BGP_SFLAG_GRST_GRRESET_SUPPORT))
    {
      capability = 0x01;
    }
#endif

  pal_snprintf (url, size, "http://%s:%d/wm/bgp/%s/%u",
		addr, port, rid, capability); 

  return url;
}

void
bgp_post_routerid (struct bgp *bgp)
{
  char url[MAX_BGP_URL];
  int idx;

  for (idx = 0; idx < BGP_MAX_SDN_CLIENT; idx++)
    {
      if (! bgp_sdn_addr[idx])
	continue;

      if (bgp_make_url_for_routerid (bgp, bgp_sdn_addr[idx], bgp_sdn_port[idx], url, MAX_BGP_URL) == NULL)
        {
          zlog_warn (&BLG, "[SDN] failed to create a post url");
      	  continue;
        }

      bgp_send_url (bgp, url, 1);
    }


  return;
}

void
bgp_delete_routerid (struct bgp *bgp)
{
  char url[MAX_BGP_URL];
  int idx;

  for (idx = 0; idx < BGP_MAX_SDN_CLIENT; idx++)
    {
      if (! bgp_sdn_addr[idx])
	continue;

      if (bgp_make_url_for_routerid (bgp, bgp_sdn_addr[idx], bgp_sdn_port[idx], url, MAX_BGP_URL) == NULL)
        {
          zlog_warn (&BLG, "[SDN] failed to create a post url");
      	  continue;
        }

      bgp_send_url (bgp, url, 0);
    }

  return;
}
#endif /* HAVE_BGP_SDN */

struct bgp_node *
bgp_afi_node_get (struct bgp *bgp, afi_t afi, safi_t safi,
                  struct prefix *p, struct bgp_rd_node *prn)
{
  struct bgp_ptree *table;
  struct bgp_node *rn = NULL;

  table = bgp->rib [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (table)
    rn = bgp_node_get (table, p);

  if (NULL == rn)
    return NULL;

  return rn;
}

/* Allocate new bgp info structure. */
struct bgp_info *
bgp_info_new ()
{
  return (struct bgp_info *)
    XCALLOC (MTYPE_BGP_ROUTE, sizeof (struct bgp_info));
}

/* Free bgp route information. */
void
bgp_info_free (struct bgp_info *ri)
{
  if (ri->attr)
    bgp_attr_unintern (ri->attr);

  /* Free the RFD History Information */
  if (ri->rfd_hinfo)
    bgp_rfd_hinfo_free (ri->rfd_hinfo);

  XFREE (MTYPE_BGP_ROUTE, ri);
}

/*
 * This function is used to sort the bgp_info list of a particular route(rn)
 * according to the ascending order of ip-address HAVE_ORDER_NEXTHOP is turned
 * on. Otherwise the sorted list contains the unsorted list of mpath candidates. 
 * Returns mpath_count in success, 0 in failure. Currently it return 0 if ECMP is not turned ON.
 *
 * Input: The caller MUST pass a reference to bgp_info_sort data structure. Thus
 * this function expects that memory is allocated already for bgp_info_sort
 */
u_int32_t
bgp_info_sort (struct bgp_node *rn,  struct bgp_info_sort *sorted)
{
  struct bgp_info *ri;
  struct bgp	*bgp;
  int i = 0;
  int v4_addr_cmp = -1;

  if(rn == NULL || sorted == NULL)
    return 0;

  ri = rn->info;

  if (ri == NULL)
    return 0;
  if (ri->peer)
    bgp = ri->peer->bgp;
  else
    return 0;

  pal_mem_set(sorted, 0, sizeof (struct bgp_info_sort));

  if (!CHECK_FLAG(bgp->bgp_cflags, BGP_CFLAG_ECMP_ENABLE)) 
    {
	return 0;
     }
   else
     {
	/* Traverse the list */
	for (ri = rn->info; ri != NULL; ri = ri->next)
	  { 
	    if (!CHECK_FLAG(ri->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE))
		continue;
	    if (!CHECK_FLAG(ri->flags, BGP_INFO_NHOP_VALID))
		continue;

	    if (BGP_DEBUG (normal, NORMAL)) {
	        zlog_info (&BLG, "%s-%s [RIB] bgp_info_sort: %d "
                           "MPATH candidate type",
                           ri->peer->host, BGP_PEER_DIR_STR (ri->peer),  peer_sort(ri->peer));
            }


	    if (sorted->mpath_count == 0)
              {
	  	  sorted->mpath_count++ ;
		  sorted->sort_list[0] = ri;
	       }
             else
	       {
		  bool_t  adjusted = PAL_FALSE;
		  bool_t  duplicate_nexthop = PAL_FALSE;

		 /* check if this ip-address is the lowest value */
		 for (i = sorted->mpath_count-1; i >= 0; i--)	
		   {
		      v4_addr_cmp = IPV4_NEXTHOP_ADDR_CMP((sorted->sort_list[i]->attr), ri->attr);

		      if (v4_addr_cmp == 0 )
			duplicate_nexthop = PAL_TRUE;

#ifdef HAVE_ORDER_NEXTHOP
                      if (v4_addr_cmp > 0)
         		{
			  sorted->sort_list[i + 1] = sorted->sort_list[i];
			  sorted->sort_list[i] = ri;
			  adjusted = PAL_TRUE;
	  		}
#endif /* ENABLE_ORDER_NEXTHOP */
	           }
		/* Don't allow duplicate nexthop for the same prefix */
		 if (duplicate_nexthop)
		   {
		     UNSET_FLAG(ri->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE);
		     continue;
		   }

		 if (!adjusted)
		   sorted->sort_list[sorted->mpath_count] = ri;
		 /* Simply copy the unsorted MPATH CANDIDATE ri */

		 sorted->mpath_count++ ;
		}
             }
	 }  
   if (sorted->mpath_count > 0)
     return (sorted->mpath_count);
   return 0;
}

/* Add bgp route infomation to routing table node. */
void
bgp_info_add (struct bgp_node *rn, struct bgp_info *ri)
{
  struct bgp_info *top;

  top = rn->info;

  ri->next = rn->info;
  ri->prev = NULL;
  if (top)
    top->prev = ri;
  rn->info = ri;
}


/* Delete rib from rib list. */
void
bgp_info_delete (struct bgp_node *rn, struct bgp_info *ri)
{
  if (ri->next)
    ri->next->prev = ri->prev;

  if (ri->prev)
    ri->prev->next = ri->next;
  else
    rn->info = ri->next;
}

/* Get MED value.  If MED value is missing and "bgp bestpath
   missing-as-worst" is specified, treat it as the worst value. */
u_int32_t
bgp_med_value (struct attr *attr, struct bgp *bgp)
{ 
  /* If REMOVE_MED is not configured then we return MED */
  /* if (!(bgp_config_check (bgp, BGP_CFLAG_MED_REMOVE_MED)))
  {*/
    if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
      return attr->med;
    else
      { /* MED is missing */
        if (bgp_config_check (bgp, BGP_CFLAG_MED_MISSING_AS_WORST))
          return BGP_MED_MAX;
        else
          return BGP_MED_MIN;
      }
 /* } end of if */
}/* end */

/* Compare two bgp route entity.  br is preferable then return 1. */
s_int32_t
bgp_info_cmp (struct bgp *bgp, struct bgp_info *new, struct bgp_info *exist)
{
  u_int32_t new_pref;
  u_int32_t exist_pref;
  u_int32_t new_med;
  u_int32_t exist_med;
  struct pal_in4_addr new_id;
  struct pal_in4_addr exist_id;
  s_int32_t new_cluster;
  s_int32_t exist_cluster;
  s_int32_t internal_as_route = 0;
  s_int32_t confed_as_route = 0;
  s_int32_t ret;
  bool_t skip_prefer_old_route = PAL_FALSE;

  /* 0. Null check. */
  if (new == NULL)
    return 0;

  /* UNSET MULTIPATH FLAG if set, then set if checks are OK */
  if (CHECK_FLAG(new->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE))
    UNSET_FLAG(new->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE);

  if (exist == NULL)
    return 1;

  /* 1. Weight check. */
  if (new->attr->weight > exist->attr->weight)
    return 1;
  if (new->attr->weight < exist->attr->weight)
    return 0;

  /* 2. Local preference check. */
  if (new->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    new_pref = new->attr->local_pref;
  else
    new_pref = bgp->default_local_pref;

  if (exist->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    exist_pref = exist->attr->local_pref;
  else
    exist_pref = bgp->default_local_pref;

  if (new_pref > exist_pref)
    return 1;
  if (new_pref < exist_pref)
    return 0;

  /* 3. Local route check. */
  if (new->type == IPI_ROUTE_CONNECT)
    return 1;
  if (exist->type == IPI_ROUTE_CONNECT)
    return 0;

  if (new->type == IPI_ROUTE_STATIC)
    return 1;
  if (exist->type == IPI_ROUTE_STATIC)
    return 0;

  if (new->sub_type == BGP_ROUTE_STATIC)
    return 1;
  if (exist->sub_type == BGP_ROUTE_STATIC)
    return 0;

  if (new->sub_type == BGP_ROUTE_AGGREGATE)
    return 1;
  if (exist->sub_type == BGP_ROUTE_AGGREGATE)
    return 0;

  /* 4. AS path length check. */
  if (! bgp_config_check (bgp, BGP_CFLAG_ASPATH_IGNORE))
    {
      if (bgp_config_check (bgp, BGP_CFLAG_COMPARE_CONFED_ASPATH))
        {
#ifdef HAVE_EXT_CAP_ASN
          /* Check for the Local Speaker */
          if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP)) 
            {
              if (new->attr->aspath4B->count_confed < exist->attr->aspath4B->count_confed)
                return 1;
              if (new->attr->aspath4B->count_confed > exist->attr->aspath4B->count_confed)
                return 0;
            }
           /* Local Speaker is OBGP */ 
          else
            { 
#endif /* HAVE_EXT_CAP_ASN */
             if (new->attr->aspath->count_confed < exist->attr->aspath->count_confed)
                 return 1;
               if (new->attr->aspath->count_confed > exist->attr->aspath->count_confed)
                 return 0;
#ifdef HAVE_EXT_CAP_ASN
            }
#endif /* HAVE_EXT_CAP_ASN */ 
        }
      else
        {
#ifdef HAVE_EXT_CAP_ASN
          if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
            {
              if (new->attr->aspath4B && exist->attr->aspath4B)
                {
                  if (new->attr->aspath4B->count < exist->attr->aspath4B->count)
                    return 1;
                  if (new->attr->aspath4B->count > exist->attr->aspath4B->count)
                    return 0;
                }
            }
          else
            {
#endif /* HAVE_EXT_CAP_ASN */
              if (new->attr->aspath && exist->attr->aspath)
                {
                  if (new->attr->aspath->count < exist->attr->aspath->count)
                    return 1;
                  if (new->attr->aspath->count > exist->attr->aspath->count)
                    return 0; 
                }
#ifdef HAVE_EXT_CAP_ASN
            }    
#endif /* HAVE_EXT_CAP_ASN */
        }
    }

  /* 5. Origin check. */
  if (new->attr->origin < exist->attr->origin)
    return 1;
  if (new->attr->origin > exist->attr->origin)
    return 0;

  /* 6. MED check. */
#ifdef HAVE_EXT_CAP_ASN
    if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
      {
        if (new->attr->aspath4B && exist->attr->aspath4B)
          {
            internal_as_route = (new->attr->aspath4B->length == 0
                                && exist->attr->aspath4B->length == 0);
            confed_as_route = (new->attr->aspath4B->length > 0
                               && exist->attr->aspath4B->length > 0
                               && new->attr->aspath4B->count == 0
                               && exist->attr->aspath4B->count == 0);
            /* If REMOVE_MED is not configured then we return MED */
            if (!(bgp_config_check (bgp, BGP_CFLAG_MED_REMOVE_RCVD)))
              {
                if (bgp_config_check (bgp, BGP_CFLAG_ALWAYS_COMPARE_MED)
     	                	      || (bgp_config_check (bgp, BGP_CFLAG_MED_CONFED)
                                      && confed_as_route)
                                      || as4path_cmp_left (new->attr->aspath4B, exist->attr->aspath4B)
                                      || as4path_cmp_left_confed (new->attr->aspath4B, exist->attr->aspath4B)
                                      || internal_as_route)
                  {
                    new_med = bgp_med_value (new->attr, bgp);
                    exist_med = bgp_med_value (exist->attr, bgp);

                    if (new_med < exist_med)
                      return 1;
                    if (new_med > exist_med)
                      return 0;
                  }
              }
          }
      }
    /* Local Speaker is OBGP */
    else
      {
#endif /* HAVE_EXT_CAP_ASN */
        if (new->attr->aspath && exist->attr->aspath)
          {
            internal_as_route = (new->attr->aspath->length == 0
                                && exist->attr->aspath->length == 0);
            confed_as_route = (new->attr->aspath->length > 0
                              && exist->attr->aspath->length > 0
                              && new->attr->aspath->count == 0
                              && exist->attr->aspath->count == 0);
            /* If REMOVE_MED is not configured then we return MED */
            if (!(bgp_config_check (bgp, BGP_CFLAG_MED_REMOVE_RCVD)))
              {
                if (bgp_config_check (bgp, BGP_CFLAG_ALWAYS_COMPARE_MED)
                                     || (bgp_config_check (bgp, BGP_CFLAG_MED_CONFED)
                                     && confed_as_route)
                                     || aspath_cmp_left (new->attr->aspath, exist->attr->aspath)
                                     || aspath_cmp_left_confed (new->attr->aspath, exist->attr->aspath)
                                     || internal_as_route)
                  {
                    new_med = bgp_med_value (new->attr, bgp);
                    exist_med = bgp_med_value (exist->attr, bgp);

                    if (new_med < exist_med)
                      return 1;
                    if (new_med > exist_med)
                      return 0;
                  }
              }
          }
#ifdef HAVE_EXT_CAP_ASN
      }
#endif /* HAVE_EXT_CAP_ASN */

  /* 7. Peer type check. */
  if (peer_sort (new->peer) == BGP_PEER_EBGP
      && peer_sort (exist->peer) == BGP_PEER_IBGP)
    return 1;
  if (peer_sort (new->peer) == BGP_PEER_EBGP
      && peer_sort (exist->peer) == BGP_PEER_CONFED)
    return 1;
  if (peer_sort (new->peer) == BGP_PEER_IBGP
      && peer_sort (exist->peer) == BGP_PEER_EBGP)
    return 0;
  if (peer_sort (new->peer) == BGP_PEER_CONFED
      && peer_sort (exist->peer) == BGP_PEER_EBGP)
    return 0;

  /* When RFC1771 path selection is checked, this part is skipped.  */
  if (! bgp_option_check (BGP_OPT_RFC1771_PATH_SELECT))
    {
      /* 8. IGP metric check. */
      if (new->igpmetric < exist->igpmetric)
        return 1;
      if (new->igpmetric > exist->igpmetric)
        return 0;

      /* 9. Maximum path ECMP check. */

      if (bgp_config_check(bgp, BGP_CFLAG_ECMP_ENABLE))
	{
	  bool_t mpath_candidate = PAL_FALSE;
	  enum bgp_peer_type new_peer_type;
	  enum bgp_peer_type exist_peer_type;
	  u_int8_t ebgp_mpath_enabled = 0;
	  u_int8_t ibgp_mpath_enabled = 0;


	  /* XXX-Debug */
	  if (BGP_DEBUG (normal, NORMAL)) {
	      zlog_info (&BLG, "%s-%s [RIB] bgp_info_cmp: %0x"
                   "new_flags misc",
                   new->peer->host, BGP_PEER_DIR_STR (new->peer), new->flags_misc);
	  }


	  /* Checking for neighboring case is always done with MED
 	   * check above.> Just in case MED_REMOVE_RECVD is set then 
 	   * we need to comapre the leftmost AS here
 	   * */
		
#ifdef HAVE_EXT_CAP_ASN
          if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
            {
	       if (new->attr->aspath4B && exist->attr->aspath4B)
	          if (as4path_cmp_left (new->attr->aspath4B, exist->attr->aspath4B) ||
			  as4path_cmp_left_confed (new->attr->aspath4B, exist->attr->aspath4B))
			  {
				mpath_candidate = PAL_TRUE;
			  }
             }
	    else
	      {
#endif /* EXT_CAP_ASN */
		   if (new->attr->aspath && exist->attr->aspath)
		     {
		       if (aspath_cmp_left (new->attr->aspath, exist->attr->aspath) ||
		            aspath_cmp_left_confed (new->attr->aspath, exist->attr->aspath))
		         {
				mpath_candidate = PAL_TRUE;
		         }
		     }	
#ifdef HAVE_EXT_CAP_ASN
	      }
#endif /* EXT_CAP_ASN */
	   new_peer_type = peer_sort(new->peer);
	   exist_peer_type = peer_sort(exist->peer);
	

	   if (new_peer_type == BGP_PEER_EBGP)
	     {
		/* If 'max-paths ebgp n' is configured (>1) then
  		 * do process for multipath candidacy, but if max-paths
  		 * is unconfigured, then no need to process for multipath
  		 * and unset "installed flag". Note the "multipath_candidate"
  		 * flag is already unset in the beginning of the function.
  		 * We don't want to unset installed flag in the beginning of this 
  		 * function because we don't want to install path at every rib-scan
  		 */
		if (bgp->maxpath_ebgp > 1)
	          ebgp_mpath_enabled = 1;
		else
		  if (CHECK_FLAG(new->flags_misc, BGP_INFO_MULTI_INSTALLED))
		    UNSET_FLAG (new->flags_misc, BGP_INFO_MULTI_INSTALLED);		    
	     }

	   if (new_peer_type == BGP_PEER_IBGP)
	     {
		/* Same logic as EBGP as mentioned above */
	 	if (bgp->maxpath_ibgp > 1)
	          ibgp_mpath_enabled = 1;
		else
		  if (CHECK_FLAG(new->flags_misc, BGP_INFO_MULTI_INSTALLED))
		    UNSET_FLAG (new->flags_misc, BGP_INFO_MULTI_INSTALLED);
	     }

	   if ((ebgp_mpath_enabled || ibgp_mpath_enabled) && 
               (new_peer_type == exist_peer_type))
	     {
		/* For IBGP peer leftmost AS value comparison is not required */
		if (new_peer_type ==  BGP_PEER_IBGP) 
		  mpath_candidate = PAL_TRUE;

		/* Check if the nexthops are different */
		if (IPV4_NEXTHOP_ADDR_CMP(new->attr, exist->attr) == 0)
		  mpath_candidate = PAL_FALSE;

	   	if (mpath_candidate)
		  {
	             SET_FLAG (new->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE);
		     if (!CHECK_FLAG(exist->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE))
		        SET_FLAG(exist->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE); 
		  }

 	     }
        }
		 
      if (bgp_config_check (bgp, BGP_CFLAG_COMPARE_ROUTER_ID) ||  
        (new->peer->remote_id.s_addr == exist->peer->remote_id.s_addr))
        skip_prefer_old_route = PAL_TRUE;
		  
      /* 10. If both paths are external, prefer the path that was received
         first (the oldest one).  This step minimizes route-flap, since a
         newer path won't displace an older one, even if it was the
         preferred route based on the additional decision criteria below.  */
      if (bgp_config_check(bgp, BGP_CFLAG_PREFER_OLD_ROUTE) &&
          !skip_prefer_old_route
          && peer_sort (new->peer) == BGP_PEER_EBGP
          && peer_sort (exist->peer) == BGP_PEER_EBGP)
        {
          if (CHECK_FLAG (new->flags, BGP_INFO_SELECTED))
            return 1;
          if (CHECK_FLAG (exist->flags, BGP_INFO_SELECTED))
            return 0;
        }
    }

  /* 11. Rourter-ID  and originator-id comparision.
   *      By default both router-id and originator-id comparison 
   *      is done. If dont-compare-originator-id is set in 
   *      config, originator-id is not compared even if the 
   *      RR attribute is present. 
   */

  /*Router-ID comparision*/
  if (bgp_config_check (bgp, BGP_CFLAG_COMPARE_ROUTER_ID))
    {
      if (new->peer->remote_id.s_addr < exist->peer->remote_id.s_addr)
        return 1;
      else if (new->peer->remote_id.s_addr > exist->peer->remote_id.s_addr)
        return 0;
    }

  if (! bgp_config_check (bgp, BGP_CFLAG_DONT_COMP_ORIG_ID))
    {
      if (new->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
         new_id.s_addr = new->attr->originator_id.s_addr;
      else
	 new_id.s_addr = new->peer->remote_id.s_addr;
    }
  else
    new_id.s_addr = new->peer->remote_id.s_addr;
  
  if (! bgp_config_check (bgp, BGP_CFLAG_DONT_COMP_ORIG_ID))
    {
      if (exist->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
        exist_id.s_addr = exist->attr->originator_id.s_addr;
      else
	exist_id.s_addr = exist->peer->remote_id.s_addr;
    }
  else
    exist_id.s_addr = exist->peer->remote_id.s_addr;

  if (pal_ntoh32 (new_id.s_addr) < pal_ntoh32 (exist_id.s_addr))
    return 1;
  if (pal_ntoh32 (new_id.s_addr) > pal_ntoh32 (exist_id.s_addr))
    return 0;

  /* 12. Cluster length comparision. */
  if (new->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
    new_cluster = new->attr->cluster->length;
  else
    new_cluster = 0;
  if (exist->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
    exist_cluster = exist->attr->cluster->length;
  else
    exist_cluster = 0;

  if (new_cluster < exist_cluster)
    return 1;
  if (new_cluster > exist_cluster)
    return 0;

  /* 13. Neighbor address comparision. */
  ret = sockunion_cmp (new->peer->su_remote, exist->peer->su_remote);

  if (ret == 1)
    return 0;
  if (ret == -1)
    return 1;

  return 1;
}

enum filter_type
bgp_input_filter (struct bgp_peer *peer, struct prefix *p,
                  struct attr *attr, afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;

  if (peer->pbgp_node_inctx)
    filter = &peer->pbgp_node_inctx->filter[BGP_AFI2BAAI (afi)]
                                     [BGP_SAFI2BSAI (safi)];
  else
    filter = &peer->filter [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (DISTRIBUTE_IN (filter)
      && access_list_apply (DISTRIBUTE_IN (filter), p) != FILTER_PERMIT)
    return FILTER_DENY;

  if (PREFIX_LIST_IN (filter)
      && prefix_list_apply (PREFIX_LIST_IN (filter), p) != PREFIX_PERMIT)
    return FILTER_DENY;

#ifdef HAVE_EXT_CAP_ASN
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      if (FILTER_LIST_IN (filter)
          && as_list_apply (FILTER_LIST_IN (filter), attr->aspath4B) != AS_FILTER_PERMIT)
        return FILTER_DENY;
    }
  else
    {
#endif /* HAVE_EXT_CAP_ASN */
      if (FILTER_LIST_IN (filter)
         &&  as_list_apply (FILTER_LIST_IN (filter), attr->aspath) != AS_FILTER_PERMIT)
        return FILTER_DENY;
#ifdef HAVE_EXT_CAP_ASN
    }
#endif /* HAVE_EXT_CAP_ASN */

  return FILTER_PERMIT;
}

enum filter_type
bgp_output_filter (struct bgp_peer *peer, struct prefix *p,
                   struct attr *attr, afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;

  filter = &peer->filter [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  if (DISTRIBUTE_OUT (filter)
      && access_list_apply (DISTRIBUTE_OUT (filter), p) != FILTER_PERMIT)
    return FILTER_DENY;

  if (PREFIX_LIST_OUT (filter)
      && prefix_list_apply (PREFIX_LIST_OUT (filter), p) != PREFIX_PERMIT)
    return FILTER_DENY;

#ifdef HAVE_EXT_CAP_ASN
    if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
      {
         if (FILTER_LIST_OUT (filter) 
             &&  as_list_apply (FILTER_LIST_OUT (filter), attr->aspath4B) != AS_FILTER_PERMIT)
           return FILTER_DENY;
      }
    else 
      {
#endif /* HAVE_EXT_CAP_ASN */
         if (FILTER_LIST_OUT (filter) 
             &&  as_list_apply (FILTER_LIST_OUT (filter), attr->aspath) != AS_FILTER_PERMIT)
         return FILTER_DENY;
#ifdef HAVE_EXT_CAP_ASN
      } 
#endif /* HAVE_EXT_CAP_ASN */     
  return FILTER_PERMIT;
}

/* If community attribute includes no_export then return 1. */
bool_t
bgp_community_filter (struct bgp_peer *peer, struct attr *attr)
{
  if (attr->community)
    {
      /* NO_ADVERTISE check. */
      if (community_include (attr->community, COMMUNITY_NO_ADVERTISE))
        return PAL_TRUE;

      /* NO_EXPORT check. */
      if (peer_sort (peer) == BGP_PEER_EBGP &&
          community_include (attr->community, COMMUNITY_NO_EXPORT))
        return PAL_TRUE;

      /* NO_EXPORT_SUBCONFED check. */
      if (peer_sort (peer) == BGP_PEER_EBGP
          || peer_sort (peer) == BGP_PEER_CONFED)
        if (community_include (attr->community, COMMUNITY_NO_EXPORT_SUBCONFED))
          return PAL_TRUE;
    }

  return PAL_FALSE;
}

bool_t
bgp_cluster_filter (struct bgp_peer *peer, struct attr *attr)
{
  struct pal_in4_addr cluster_id;

  /* Route reflection loop check. */
  if (attr->cluster)
    {
      if (bgp_config_check (peer->bgp, BGP_CFLAG_CLUSTER_ID))
        cluster_id = peer->bgp->cluster_id;
      else
        cluster_id = peer->bgp->router_id;

      if (cluster_loop_check (attr->cluster, cluster_id))
        return PAL_TRUE;
    }

  return PAL_FALSE;
}


/* Apply filters and return interned struct attr. */
s_int32_t
bgp_input_modifier (struct bgp_peer *peer, struct prefix *p,
                    struct attr *attr, afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  struct bgp_rmap_info brmi;
  route_map_result_t ret;
  struct bgp_info tmp_ri;

  if (peer->pbgp_node_inctx)
    filter = &peer->pbgp_node_inctx->filter [BGP_AFI2BAAI (afi)]
                                         [BGP_SAFI2BSAI (safi)];
  else
    filter = &peer->filter [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];

  /* If any weight is configured for that particular AFI/SAFI apply it,
   * else if any weight is configured in the router-mode(IPV4-UNICAST) 
   * apply it, else apply the default weight for the Peer.
   */
  if (peer->weight [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)])
    attr->weight = peer->weight [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)];
  else if (peer->weight [BAAI_IP][BSAI_UNICAST])
    attr->weight = peer->weight [BAAI_IP][BSAI_UNICAST];
  else
    attr->weight = BGP_DEFAULT_WEIGHT;

  /* Route map apply. */
  if (ROUTE_MAP_IN_NAME (filter))
    {
      /* Duplicate current value to new strucutre for modification. */
      pal_mem_set (&tmp_ri, 0, sizeof (struct bgp_info));
      tmp_ri.peer = peer;
      tmp_ri.attr = attr;

      pal_mem_set (&brmi, 0, sizeof (struct bgp_rmap_info));
      brmi.brmi_type = BGP_RMAP_INFO_REGULAR;
      brmi.brmi_bgp = peer->bgp;
      brmi.brmi_bri = &tmp_ri;

      /* Apply BGP route map to the attribute. */
      ret = route_map_apply (ROUTE_MAP_IN (filter), p, &brmi);
      if (ret == RMAP_DENYMATCH)
        {
          /* Free newly generated AS path and community by route-map. */
          bgp_attr_flush (attr);

          return RMAP_DENY;
        }
    }
  return RMAP_PERMIT;
}

s_int32_t
bgp_announce_check (struct bgp_info *ri,
                    struct bgp_peer *peer,
                    struct prefix *p,
                    struct attr *attr,
                    afi_t afi, safi_t safi)
{
  enum bgp_peer_type from_peer_type;
  enum bgp_peer_type to_peer_type;
  struct bgp_rmap_info brmi;
  struct bgp_filter *filter;
  struct attr dummy_attr;
  struct bgp_info tmp_ri;
  struct bgp_peer *from;
  bool_t transparent;
  struct bgp *bgp;
  u_int32_t baai;
  u_int32_t bsai;
  bool_t reflect;
  s_int32_t ret;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  transparent = PAL_FALSE;
  reflect = PAL_FALSE;
  ret = 0;

  pal_mem_set (&tmp_ri, 0, sizeof (struct bgp_info));

  if (peer->pbgp_node_inctx)
    filter = &peer->pbgp_node_inctx->filter[baai][bsai];
  else
    filter = &peer->filter [baai][bsai];

  if (!ri || !ri->attr)
    return 0;

  from = ri->peer;
  bgp = peer->bgp;

  /* Do not send back route to sender. */
  if (from == peer)
    return 0;

  /* For modify attribute, copy it to temporary structure. */
  *attr = *ri->attr;

  /* Get the peer types */
  from_peer_type = peer_sort (from);
  to_peer_type = peer_sort (peer);

  /* Do not send back route to same NextHop. */
  if ((peer->su.sa.sa_family == AF_INET
       && ri->attr
       && IPV4_ADDR_SAME (&ri->attr->nexthop, &peer->su.sin.sin_addr))
#ifdef HAVE_IPV6
      || (BGP_CAP_HAVE_IPV6
          && peer->su.sa.sa_family == AF_INET6
          && ri->attr
          && (IPV6_ADDR_SAME (&ri->attr->mp_nexthop_global,
                              &peer->su.sin6.sin6_addr)
              || IPV6_ADDR_SAME (&ri->attr->mp_nexthop_local,
                                 &peer->su.sin6.sin6_addr)))
#endif /* HAVE_IPV6 */
      )
    return 0;

  /* Aggregate-address suppress check. */
  if (ri->suppress)
    if (! UNSUPPRESS_MAP_NAME (filter))
      return 0;

  /* Transparency check. */
  if (CHECK_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_RSERVER_CLIENT)
      && CHECK_FLAG (from->af_flags [baai][bsai], PEER_FLAG_RSERVER_CLIENT))
    transparent = PAL_TRUE;

  /* If community is not disabled check the no-export and local. */
  if (transparent == PAL_FALSE
      && bgp_community_filter (peer, ri->attr))
    return 0;

  /* If the attribute has originator-id and it is same as remote
     peer's id. */
  if (ri->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID)
      && IPV4_ADDR_SAME (&peer->remote_id, &ri->attr->originator_id))
    {
      if (BGP_DEBUG (filter, FILTER))
        zlog_info (&BLG, "%s-%s [RIB] Announce Check: %O "
                   "Originator-ID is same as Remote Router-ID",
                   peer->host, BGP_PEER_DIR_STR (peer), p);
      return 0;
    }

  /* ORF prefix-list filter check */
  if (CHECK_FLAG (peer->af_cap [baai][bsai],
                  PEER_CAP_ORF_PREFIX_RM_ADV)
      && (CHECK_FLAG (peer->af_cap [baai][bsai],
                      PEER_CAP_ORF_PREFIX_SM_RCV)
          || CHECK_FLAG (peer->af_cap [baai][bsai],
                         PEER_CAP_ORF_PREFIX_SM_OLD_RCV)))
    {
      if (peer->orf_plist [baai][bsai]
          && prefix_list_apply (peer->orf_plist [baai][bsai], p)
             != PREFIX_PERMIT)
        return 0;
    }

  /* Output filter check. */
  if (bgp_output_filter (peer, p, ri->attr, afi, safi) == FILTER_DENY)
    {
      if (BGP_DEBUG (filter, FILTER))
        zlog_info (&BLG, "%s-%s [RIB] Announce Check: %O "
                   "is filtered",
                   peer->host, BGP_PEER_DIR_STR (peer), p);
      return 0;
    }

  /* If we're a CONFED we need to loop check the CONFED ID too */
  if (bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION))
    {
#ifdef HAVE_EXT_CAP_ASN
      if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        {
          if (as4path_loop_check(ri->attr->aspath4B, bgp->confed_id))
            {
               if (BGP_DEBUG (filter, FILTER))
                 zlog_info (&BLG, "%s-%s [RIB] Announce Check: %O "
                            "No announcement since AS %u is in AS Path",
                            peer->host, BGP_PEER_DIR_STR (peer), p,
                            bgp->confed_id);
               return 0;
            }
         }
       /* Local speaker is OBGP */
       else
         {
#endif /* HAVE_EXT_CAP_ASN */
           if (aspath_loop_check(ri->attr->aspath, bgp->confed_id))
             {
               if (BGP_DEBUG (filter, FILTER))
               zlog_info (&BLG, "%s-%s [RIB] Announce Check: %O "
                          "No announcement since AS %d is in AS Path",
                          peer->host, BGP_PEER_DIR_STR (peer), p,
                          bgp->confed_id);
               return 0;
             }
#ifdef HAVE_EXT_CAP_ASN
         }
#endif /* HAVE_EXT_CAP_ASN */
     }

  /* Route-Reflect check. */
  if (from_peer_type == BGP_PEER_IBGP
      && to_peer_type == BGP_PEER_IBGP)
    reflect = PAL_TRUE;

  /* IBGP reflection check. */
  if (reflect == PAL_TRUE)
    {
      /* A route from a Client peer. */
      if (CHECK_FLAG (from->af_flags [baai][bsai],
                      PEER_FLAG_REFLECTOR_CLIENT))
        {
          /* Reflect to all the Non-Client peers and also to the
             Client peers other than the originator.  Originator check
             is already done.  So there is noting to do. */
          /* no bgp client-to-client reflection check. */
          if (bgp_config_check (bgp, BGP_CFLAG_NO_CLIENT_TO_CLIENT))
            if (CHECK_FLAG (peer->af_flags [baai][bsai],
                            PEER_FLAG_REFLECTOR_CLIENT))
              return 0;
        }
      else
        {
          /* A route from a Non-client peer. Reflect to all other
             clients. */
          if (! CHECK_FLAG (peer->af_flags [baai][bsai],
                            PEER_FLAG_REFLECTOR_CLIENT))
            return 0;
        }
    }

  /* If local-preference is not set. */
  if ((to_peer_type == BGP_PEER_IBGP
       || to_peer_type == BGP_PEER_CONFED)
      && (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))))
    {
      attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);
      attr->local_pref = bgp->default_local_pref;
    }

  /* Remove MED if its an EBGP peer - will get overwritten by route-maps */
  if (to_peer_type == BGP_PEER_EBGP
      && attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    {
      if (transparent == PAL_FALSE
          && ri->peer != bgp->peer_self
          && ! CHECK_FLAG (peer->af_flags [baai][bsai],
                           PEER_FLAG_MED_UNCHANGED))
        attr->flag &= ~(ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC));
    }

  /* If this is EBGP peer and remove-private-AS is set.  */
#ifdef HAVE_EXT_CAP_ASN
     if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
       { 
         if (to_peer_type == BGP_PEER_EBGP
             && peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS)
             && as4path_private_as_check (attr->aspath4B))
         attr->aspath4B = aspath4B_empty_get ();
       }
     /* Local Speaker is OBGP */
     else
       {
#endif /* HAVE_EXT_CAP_ASN */
         if (to_peer_type == BGP_PEER_EBGP
             && peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS)
             && aspath_private_as_check (attr->aspath))
         attr->aspath = aspath_empty_get ();
#ifdef HAVE_EXT_CAP_ASN
       }        
#endif /* HAVE_EXT_CAP_ASN */

  /* Route map apply. */
  if (ROUTE_MAP_OUT_NAME (filter)
      || ri->suppress)
    {
      tmp_ri.peer = peer;
      tmp_ri.attr = attr;

      /* If Route-reflector, do not modify attributes of reflected routes */
      if (from_peer_type == BGP_PEER_IBGP
          && to_peer_type == BGP_PEER_IBGP)
        {
          dummy_attr = *attr;
          tmp_ri.attr = &dummy_attr;
        }

      pal_mem_set (&brmi, 0, sizeof (struct bgp_rmap_info));
      brmi.brmi_type = BGP_RMAP_INFO_REGULAR;
      brmi.brmi_bgp = bgp;
      brmi.brmi_bri = &tmp_ri;

      if (ri->suppress)
        ret = route_map_apply (UNSUPPRESS_MAP (filter), p, &brmi);
      else
        ret = route_map_apply (ROUTE_MAP_OUT (filter), p, &brmi);

      if (ret == RMAP_DENYMATCH)
        {
          bgp_attr_flush (attr);
          return 0;
        }
    }

  /* NextHop Attribute setting */
#ifdef HAVE_IPV6
  /* By default, do not transit Link-local address */
  if (BGP_CAP_HAVE_IPV6
      && peer->su.sa.sa_family == AF_INET6)
    attr->mp_nexthop_len = IPV6_MAX_BYTELEN;
#endif /* HAVE_IPV6 */

  if (transparent == PAL_TRUE
      || reflect == PAL_TRUE
      || (CHECK_FLAG (peer->af_flags [baai][bsai],
                      PEER_FLAG_NEXTHOP_UNCHANGED)
          && ((p->family == AF_INET
               && attr->nexthop.s_addr != INADDR_ANY)
#ifdef HAVE_IPV6
              || (BGP_CAP_HAVE_IPV6
                  && (p->family == AF_INET6
                      && ri->peer != bgp->peer_self))
#endif /* HAVE_IPV6 */
              )))
    {
      /* NEXT-HOP Unchanged. */
    }
  else if (CHECK_FLAG (peer->af_flags [baai][bsai], PEER_FLAG_NEXTHOP_SELF)
           || (p->family == AF_INET
               && attr->nexthop.s_addr == INADDR_ANY)
#ifdef HAVE_IPV6
           || (BGP_CAP_HAVE_IPV6
               && p->family == AF_INET6
               && ri->peer == bgp->peer_self)
#endif /* HAVE_IPV6 */
           || (to_peer_type == BGP_PEER_EBGP
               && (peer->ttl > BGP_PEER_TTL_EBGP_DEF)))
    {
      /* Set IPv4 nexthop. */
      if (!CHECK_FLAG (tmp_ri.flags_misc, BGP_INFO_RMAP_NEXTHOP_APPLIED))
        IPV4_ADDR_COPY (&attr->nexthop, &peer->nexthop.v4);

      UNSET_FLAG (tmp_ri.flags_misc, BGP_INFO_RMAP_NEXTHOP_APPLIED);
#ifdef HAVE_IPV6
      /* Set IPv6 nexthop. */
      if (BGP_CAP_HAVE_IPV6
          && peer->su.sa.sa_family == AF_INET6)
        {
          /* IPv6 global nexthop must be included. */
          IPV6_ADDR_COPY (&attr->mp_nexthop_global,
                          &peer->nexthop.v6_global);
          attr->mp_nexthop_len = IPV6_MAX_BYTELEN;

          /* Set link-local address for shared network peer */
          if (peer->shared_network
              && ! IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
            {
              IPV6_ADDR_COPY (&attr->mp_nexthop_local,
                              &peer->nexthop.v6_local);
              attr->mp_nexthop_len = IPV6_MAX_BYTELEN * 2;
            }
        }
#endif /* HAVE_IPV6 */
    }

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      if (peer->su.sa.sa_family == AF_INET6)
        {
          /* If a BGP-4+ R-Reflector, dont send link-local address */
          if (reflect == PAL_TRUE)
            attr->mp_nexthop_len = IPV6_MAX_BYTELEN;

          /* If BGP-4+ link-local nexthop is not link-local nexthop */
          if (! IN6_IS_ADDR_LINKLOCAL (&peer->nexthop.v6_local))
            attr->mp_nexthop_len = IPV6_MAX_BYTELEN;
        }
      else if (p->family == AF_INET6)
        {
          /*Set nexhop for bgp ipv6 extend on bgp4+*/

          /*If link local address and global address are not present send 
           *IPV4 mapped  IPV6 address
           */
          if (IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local) &&
              IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_global)) 
            {
              attr->mp_nexthop_len = IPV6_MAX_BYTELEN;
              /* RFC 4271:Sec 5.1.3 (2) if the peer is in same subnet as the subnet
                         of receive nexthop then the nexthop should not be changed */
              switch (to_peer_type)
                {
                  case BGP_PEER_EBGP:
                    if (peer->ttl == BGP_PEER_TTL_EBGP_DEF)
                      {
                        IPV4_TO_MAPPED_IPV6 (&attr->mp_nexthop_global,
                                             attr->nexthop);
                        IPV4_ADDR_COPY (&attr->mp_nexthop_global_in,
                                        &attr->nexthop);
                      }
                    else
                      {
                        IPV4_TO_MAPPED_IPV6 (&attr->mp_nexthop_global,
                                             peer->nexthop.v4);
                        IPV4_ADDR_COPY (&attr->mp_nexthop_global_in,
                                        &peer->nexthop.v4);
                      }
                    break;
                  case BGP_PEER_IBGP:
                    if ( ri->peer == bgp->peer_self
                         || CHECK_FLAG (peer->flags, PEER_FLAG_6PE_ENABLED))
                      {
                        IPV4_TO_MAPPED_IPV6 (&attr->mp_nexthop_global,
                                             peer->nexthop.v4);
                        IPV4_ADDR_COPY (&attr->mp_nexthop_global_in,
                                        &peer->nexthop.v4);
                      }
                    else
                      {
                        IPV4_TO_MAPPED_IPV6 (&attr->mp_nexthop_global,
                                             attr->nexthop);
                        IPV4_ADDR_COPY (&attr->mp_nexthop_global_in,
                                        &attr->nexthop);
                      }
                    break;
                  default:
                    break;
                }
            }
          else
            {
              /* IPv6 global nexthop must be included. */
              IPV6_ADDR_COPY (&attr->mp_nexthop_global,
                              &peer->nexthop.v6_global);
              attr->mp_nexthop_len = IPV6_MAX_BYTELEN;
   
              /* Set link-local address for shared network peer*/ 
              if (! IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
                {
                  IPV6_ADDR_COPY (&attr->mp_nexthop_local,
                                  &peer->nexthop.v6_local);
                  attr->mp_nexthop_len = IPV6_MAX_BYTELEN * 2;
                }
            }
        }
    }
#endif /* HAVE_IPV6 */

  return 1;
}

/* Process changed routing entry */
void
bgp_process (struct bgp *bgp, struct bgp_node *rn,
             afi_t afi, safi_t safi, struct bgp_info *del)
{
  enum bgp_peer_type peer_type;
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_peer *peer = NULL;
  struct bgp_info *ri1;
  struct bgp_info *ri2;
  struct bgp_info *ri;
  struct bgp_info *rii;
  struct listnode *nn;
  bool_t rnp_default;
  bool_t install_mpath;
  u_int8_t installed_ibgp;
  u_int8_t installed_ebgp;
  struct prefix *p;
  struct attr attr;
  u_int32_t baai;
  u_int32_t bsai;
  struct prefix rnp;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  rnp_default = PAL_FALSE;
  new_select = NULL;
  BGP_GET_PREFIX_FROM_NODE (rn);
  p = &rnp;

  install_mpath = PAL_FALSE;
  installed_ibgp = 0;
  installed_ebgp = 0;

  if (bgp_config_check(bgp, BGP_CFLAG_ECMP_ENABLE)) 
    {
       /* Count the currently installed multipaths */
       for (rii = rn->info; rii != NULL; rii = rii->next)
	 {
	    if (CHECK_FLAG(rii->flags_misc, BGP_INFO_MULTI_INSTALLED))
              {
                 if (peer_sort(rii->peer) == BGP_PEER_EBGP)
                   installed_ebgp++;
                 else if (peer_sort(rii->peer) == BGP_PEER_IBGP)
                   installed_ibgp++;
              }

         }
     }

  /* BGP deterministic-med */
  if (bgp_config_check (bgp, BGP_CFLAG_DETERMINISTIC_MED))
    for (ri1 = rn->info; ri1; ri1 = ri1->next)
      {
        if (ri1->as_selected != 0)
          continue;

        if (BGP_INFO_HOLDDOWN (ri1))
          {
            ri1->as_selected = -1;
            continue;
          }
        new_select = ri1;

        if (ri1->next)
          for (ri2 = ri1->next; ri2; ri2 = ri2->next)
            {
              if (ri2->as_selected != 0)
                continue;

              if (BGP_INFO_HOLDDOWN (ri2))
                {
                  ri2->as_selected = -1;
                  continue;
                }
#ifdef HAVE_EXT_CAP_ASN
              if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
                {
                  if (as4path_cmp_left (ri1->attr->aspath4B, ri2->attr->aspath4B)
                      || as4path_cmp_left_confed (ri1->attr->aspath4B,
                                                  ri2->attr->aspath4B))
                    {
                      if (bgp_info_cmp (bgp, ri2, new_select))
                        {
                          new_select->as_selected = -1;
                          new_select = ri2;
                        }
                      else
                        ri2->as_selected = -1;
                    }
                 }
               else
                 {     
#endif /* HAVE_EXT_CAP_ASN */
               /* Local Speaker is OBGP */
                if (aspath_cmp_left (ri1->attr->aspath, ri2->attr->aspath)
                       || aspath_cmp_left_confed (ri1->attr->aspath,
                                                  ri2->attr->aspath))
                 {
                   if (bgp_info_cmp (bgp, ri2, new_select))
                     {
                       new_select->as_selected = -1;
                       new_select = ri2;
                     }
                   else
                     ri2->as_selected = -1;
                 }
#ifdef HAVE_EXT_CAP_ASN
                 }
#endif /* HAVE_EXT_CAP_ASN */
            }
        new_select->as_selected = 1;
      }

  /* Check old selected route and new selected route. */
  old_select = NULL;
  new_select = NULL;

  for (ri = rn->info; ri; ri = ri->next)
    {
      /* If the route is locally originated default-route,
         donot include for selection process */
      if (ri && ri->sub_type == BGP_ROUTE_DEFAULT)
        {
          /* Setting the rnp_default to TRUE for default routes. */
          rnp_default = PAL_TRUE;
          continue;
        }

      peer_type = peer_sort (ri->peer);

      if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
        old_select = ri;

      if (BGP_INFO_HOLDDOWN (ri))
        {
          ri->as_selected = 0;
          continue;
        }

      if (bgp_af_config_check (ri->peer->bgp, afi, safi,
                               BGP_AF_CFLAG_SYNCHRONIZATION)
          && (peer_type == BGP_PEER_IBGP
              || peer_type == BGP_PEER_CONFED)
          && CHECK_FLAG (ri->flags, BGP_INFO_UNSYNCHRONIZED))
        continue;

      if (bgp_config_check (bgp, BGP_CFLAG_DETERMINISTIC_MED)
          && ri->as_selected != 1)
        {
          ri->as_selected = 0;
          continue;
        }
      ri->as_selected = 0;

      if (bgp_info_cmp (bgp, ri, new_select))
        new_select = ri;
    }

  /* bgp_mpath_to_install() should be called irrespective of old_select
   * being equal to new_select or not.
   */
  if (CHECK_FLAG(bgp->bgp_cflags, BGP_CFLAG_ECMP_ENABLE) &&  new_select)
    {
       if (bgp_mpath_to_install(rn, bgp, new_select,
            installed_ibgp, installed_ebgp))
              install_mpath = PAL_TRUE;
    }

  /* Selection result is same as previous one. */
  if (old_select && old_select == new_select)
    {
      if (! CHECK_FLAG (old_select->flags, BGP_INFO_ATTR_CHANGED))
        {
          /* when bgp multiple instance is enabled
           * Installed routes learned by bgp instance
           * if it is not a view
           */
          if (!bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE)
                || (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE) && !bgp->name))
          if (! bgp_option_check (BGP_OPT_NO_FIB)
              && old_select->type == IPI_ROUTE_BGP
              && (old_select->sub_type == BGP_ROUTE_NORMAL
                  || old_select->sub_type == BGP_ROUTE_AGGREGATE)
              )
            {
              if (CHECK_FLAG (old_select->flags, BGP_INFO_IGP_CHANGED) || install_mpath)
		{
#ifdef HAVE_BGP_SDN
	  	bgp_rest_handler (bgp, rn, new_select, old_select, del);
#endif /* HAVE_BGP_SDN */
	 	}
            }

#ifdef HAVE_BGP_SDN
          if (CHECK_FLAG (old_select->flags, BGP_INFO_IGP_CHANGED)
	   || install_mpath)
    	    bgp_rest_handler (bgp, rn, new_select, old_select, del);
#endif /* HAVE_BGP_SDN */

          return;
        }
    }

  /* Update selected flag and attr changed flag */
  if (old_select)
    {
      UNSET_FLAG (old_select->flags, BGP_INFO_SELECTED);
      UNSET_FLAG (old_select->flags, BGP_INFO_ATTR_CHANGED);
    }

  if (new_select)
    {
      SET_FLAG (new_select->flags, BGP_INFO_SELECTED);
      UNSET_FLAG (new_select->flags, BGP_INFO_ATTR_CHANGED);
      /* If there is a new_select, de-register the nexthop of old_select 
       * or del (del will be non-NULL in case of route deletion/clearing)
       * from NSM.
      */
      if ((old_select && (new_select != old_select))
          || (del && (new_select != del)))
        {
          /* decrement the route selected count
           * will again increment the count when new_select is sent to NSM.
          */
          if (bgp->selrt_count[BGP_AFI2BAAI(afi)])
            --bgp->selrt_count[BGP_AFI2BAAI(afi)];
        }
    }

  /* Table version update.  */
  if (bgp_af_status_check (bgp, afi, safi, BGP_AF_SFLAG_TABLE_ANNOUNCED))
    {
      bgp->table_version [baai][bsai]++;
      bgp_af_status_unset (bgp, afi, safi,
                           BGP_AF_SFLAG_TABLE_ANNOUNCED);
    }

  /* Announcement to all BGP peers included in this BGP instance. */
  LIST_LOOP (bgp->peer_list, peer, nn)
    {
      /* Announce route to Established peer. */
      if (peer->bpf_state != BPF_STATE_ESTABLISHED)
        continue;

      /* Address family configuration check. */
      if (! peer->afc_nego [baai][bsai])
        continue;

      /* Defer UPDATEs till ORF/ROUTE-REFRESH is received */
      if (CHECK_FLAG (peer->af_sflags [baai][bsai],
                      PEER_STATUS_ORF_WAIT_REFRESH))
        continue;

      /* rnp_default is TRUE which implies  rn->prefix is 0.0.0.0. In this
       *  case check whether default-originate is enabled on the peer
       */
      if (rnp_default == PAL_TRUE
          && CHECK_FLAG (peer->af_flags [baai][bsai],
                         PEER_FLAG_DEFAULT_ORIGINATE))
        {
          /* If peer is enabled with default-originate, donot send
           * learnt 0.0.0.0 route to that peer in UPDATE or WITHDRAW.
           */
          if ( (new_select
                && new_select->sub_type != BGP_ROUTE_DEFAULT)
              || (del
                  && del->sub_type == BGP_ROUTE_NORMAL))
             continue;
        }

      /* Announcement/Withdrawal to the peer */
      if (new_select
          && bgp_announce_check (new_select, peer, p, &attr, afi, safi))
        bgp_adj_out_set (rn, peer, &attr, afi, safi, new_select);
      else
        bgp_adj_out_unset (rn, peer, del, afi, safi);
    }

  /* Resetting the peer to NULL. */
  peer = NULL;

#ifdef HAVE_BGP_SDN
  bgp_rest_handler (bgp, rn, new_select, old_select, del);
#endif /* HAVE_BGP_SDN */

  /* FIB update. */
  /* when bgp multiple instance is enabled
   * Installed routes learned by bgp instance
   * if it is not a view
   */
   if ((!bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE)
       || (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE) && !bgp->name))
      && ! bgp_option_check (BGP_OPT_NO_FIB))
    {
      if (! new_select
          || new_select->type != IPI_ROUTE_BGP
          || (new_select->sub_type != BGP_ROUTE_NORMAL
              && new_select->sub_type != BGP_ROUTE_AGGREGATE)
          )
        {
          /* If selected route is deleted re-assign as selected */
          if (! old_select
              && del
              && CHECK_FLAG (del->flags, BGP_INFO_SELECTED))
            old_select = del;
        }
    }

  return;
}

bool_t
bgp_peer_max_prefix_overflow (struct bgp_peer *peer,
                              afi_t afi, safi_t safi)
{
  s_int32_t threshold_cnt;
  u_int32_t prefix_count;
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  /* Pre-count the incoming Prefix */
  prefix_count = peer->pcount [baai][bsai] + 1;

  /* "peer maximum-prefix" is configured */
  if (peer->pmax [baai][bsai])
    {
      /* Warning for Prefix-Count threshold over-flow */
      if (prefix_count <= peer->pmax [baai][bsai])
        {
          threshold_cnt = peer->pmax [baai][bsai] *
                          peer->threshold [baai][bsai] / 100;

          if (prefix_count >= threshold_cnt)
            zlog_warn (&BLG, "%%BGP-4-MAXPFX: No. of prefix received "
                       "from %s (afi-safi %d-%d): reaches %lu, max %lu",
                       peer->host, afi, safi, prefix_count,
                       peer->pmax [baai][bsai]);
        }
      else
        {
          /* Generate warning message with MAXPFXEXCEED */
          zlog_warn (&BLG, "%%BGP-3-MAXPFXEXCEED: No. of prefix received"
                     " from %s (afi-safi %d-%d): %lu exceed limit %lu",
                     peer->host, afi, safi, prefix_count,
                     peer->pmax [baai][bsai]);

          /* If NOT 'warning-only', NOTIFY and terminate session */
          if (! CHECK_FLAG (peer->af_flags [baai][bsai],
                            PEER_FLAG_MAX_PREFIX_WARNING))
            {
              u_int8_t ndata [7];

              ndata [0] = (u_int8_t)(afi >>  8);
              ndata [1] = (u_int8_t) afi;
              ndata [2] = (u_int8_t) safi;
              ndata [3] = (u_int8_t)(peer->pmax [baai][bsai] >> 24);
              ndata [4] = (u_int8_t)(peer->pmax [baai][bsai] >> 16);
              ndata [5] = (u_int8_t)(peer->pmax [baai][bsai] >> 8);
              ndata [6] = (u_int8_t)(peer->pmax [baai][bsai]);

              SET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);

              bpf_event_notify (peer, BPF_EVENT_UPDATE_ERR,
                                BGP_NOTIFY_CEASE,
                                BGP_NOTIFY_CEASE_MAX_PREFIX,
                                ndata, 7);
              return PAL_TRUE;
            }
        }
    }

  return PAL_FALSE;
}

void
bgp_rib_withdraw (struct bgp_peer *peer, struct bgp_node *rn,
                  struct bgp_info *ri, afi_t afi, safi_t safi)
{
  struct bgp *bgp_mvrf;
  s_int32_t valid;

  valid = CHECK_FLAG (ri->flags, BGP_INFO_NHOP_VALID);
  UNSET_FLAG (ri->flags, BGP_INFO_NHOP_VALID);

  bgp_mvrf = peer->bgp;

  bgp_process (bgp_mvrf, rn, afi, safi, ri);

  if (valid)
    SET_FLAG (ri->flags, BGP_INFO_NHOP_VALID);

  if (! ri->rfd_hinfo)
    {
      bgp_info_delete (rn, ri);
      bgp_info_free (ri);
      bgp_unlock_node (rn);
    }

  return;
}

/* BGP RIB Update (Advertised) NLRI Processing */
s_int32_t
bgp_update_route (struct bgp_peer *peer,
                  struct prefix *p,
                  struct attr *attr,
                  afi_t afi, safi_t safi,
                  u_int32_t type, u_int32_t sub_type,
                  struct bgp_rd_node *prn,
                  u_int32_t soft_reconfig,
                  bool_t pcount)
{
  enum bgp_rfd_rt_state rt_state;
  enum bgp_peer_type peer_type;
  struct bgp_info *ri_tmp;
  struct attr *attr_new;
  struct interface *ifp;
  struct attr new_attr;
  struct bgp *bgp_mvrf;
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct prefix pnhop;
  u_int8_t *reason;
  struct bgp *bgp = NULL;
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;
  struct prefix rnp;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  ret = 0;

  peer_type = peer_sort (peer);

   bgp = peer->bgp;
   bgp_mvrf = bgp;

  rn = bgp_afi_node_get (bgp, afi, safi, p, prn);
  if (rn == NULL)
    goto EXIT;

  /* Record attributes for inbound soft-reconfiguration */
  if (CHECK_FLAG (peer->af_flags [baai][bsai],
                  PEER_FLAG_SOFT_RECONFIG)
      && ! soft_reconfig)
    bgp_adj_in_set (rn, peer, attr);

  /* Check previously received route */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer
        && ri->type == type
        && ri->sub_type == sub_type)
      break; 
    
  /* Aspath loop check. */
#ifdef HAVE_EXT_CAP_ASN
   if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
     {
       if (as4path_loop_check (attr->aspath4B, bgp->as) >
           peer->allowas_in [baai][bsai]
#ifndef BGP_STRICT_RFC3065
           || (bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION)
           && (as4path_loop_check(attr->aspath4B, bgp->confed_id) >
               peer->allowas_in [baai][bsai]))
#endif /* BGP_STRICT_RFC3065 */
      )
         {
            reason = "as-path contains our own AS";
            goto FILTERED;
         }
     }
   else
     {
#endif /* HAVE_EXT_CAP_ASN */
    /* Local speaker is OBGP */
  if (aspath_loop_check (attr->aspath, bgp->as) >
      peer->allowas_in [baai][bsai]
#ifndef BGP_STRICT_RFC3065
      || (bgp_config_check (bgp, BGP_CFLAG_CONFEDERATION)
          && (aspath_loop_check(attr->aspath, bgp->confed_id) >
              peer->allowas_in [baai][bsai]))
#endif /* BGP_STRICT_RFC3065 */
      )
    {
      reason = "as-path contains our own AS";
      goto FILTERED;
    }
#ifdef HAVE_EXT_CAP_ASN
     }
#endif /* HAVE_EXT_CAP_ASN */

  /* Route reflector originator ID check. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID)
      && IPV4_ADDR_SAME (&bgp->router_id, &attr->originator_id))
    {
      reason = "originator is us";
      goto FILTERED;
    }

  /* Route reflector cluster ID check. */
  if (bgp_cluster_filter (peer, attr))
    {
      reason = "reflected from the same cluster";
      goto  FILTERED;
    }

  /* Apply input filter and route-map.  Filter and route-map
     application logging is also done in the function. */
  if (bgp_input_filter (peer, p, attr, afi, safi) == FILTER_DENY)
    {
      reason = "filter";
      goto FILTERED;
    }

  /* Apply input route-map. */
  new_attr = *attr;

  if (bgp_input_modifier (peer, p, &new_attr, afi, safi) == RMAP_DENY)
    {
      reason = "route-map";
      goto FILTERED;
    }

  /* Prepare a prefix structure for NHop */
  pnhop.family = p->family;

  if (p->family == AF_INET)
    {
      pnhop.prefixlen = IPV4_MAX_PREFIXLEN;
      IPV4_ADDR_COPY (&pnhop.u.prefix4, attr->mp_nexthop_len ?
                                        &attr->mp_nexthop_global_in :
                                        &attr->nexthop);
    }
#ifdef HAVE_IPV6
  else
    {
      pnhop.prefixlen = IPV6_MAX_PREFIXLEN;
      IPV6_ADDR_COPY (&pnhop.u.prefix6, &attr->mp_nexthop_global);
      if (peer->su.sa.sa_family == AF_INET
          && VALIDATE_MAPPED_IPV6(&attr->mp_nexthop_global) )
        {
          MAPPED_IPV6_TO_IPV4 (pnhop.u.prefix4,
                               attr->mp_nexthop_global);
          MAPPED_IPV6_TO_IPV4 (attr->mp_nexthop_global_in,
                               attr->mp_nexthop_global);
        }
    }
#endif /* HAVE_IPV6 */

  /* Validate that NHop is non-local */
  ifp = ifv_lookup_by_prefix (LIB_VRF_GET_IF_MASTER (bgp->owning_ivrf), 
			      &pnhop);
  if (ifp)
    {
      reason = "Nexthop matched local interface address";
      goto FILTERED;
    }

  /* NextHop must be Connected Addr for EBGP-single-hop Peer */
  if ((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_UNICAST
      && peer_type == BGP_PEER_EBGP
      && peer->ttl == BGP_PEER_TTL_EBGP_DEF
      && ! CHECK_FLAG (peer->flags, PEER_FLAG_ENFORCE_MULTIHOP))
    {
      reason = "non-connected next-hop;";
      goto FILTERED;
    }

  /* Compute the new distance value */
  ret = bgp_distance_apply (peer, p, &new_attr, afi, safi);

  if (ret < 0)
    {
      reason = "distance apply failed";
      goto FILTERED;
    }

  /* Received Logging. */
  if (BGP_DEBUG (update, UPDATE_IN))
    zlog_info (&BLG, "%s-%s [RIB] Update: Received Prefix %O",
               peer->host, BGP_PEER_DIR_STR (peer), p);

  attr_new = bgp_attr_intern (&new_attr);

  /* If the update is implicit withdraw. */
  if (ri)
    {
      /* Update timestamp.  */
      ri->bri_uptime = pal_time_sys_current (NULL);

      /* Same attribute comes in. */
      if (PAL_TRUE == attrhash_cmp (ri->attr, attr_new))
        {
          UNSET_FLAG (ri->flags, BGP_INFO_ATTR_CHANGED);

          /* Update BGP Route Dampening information */
          bgp_rfd_rt_update (ri, &rt_state);
          switch (rt_state)
            {
              case BGP_RFD_RT_STATE_NONE:
                  if (BGP_DEBUG (update, UPDATE_IN))
                    zlog_info (&BLG, "%s-%s [RIB] Update: "
                               "...duplicate route ignored",
                               peer->host, BGP_PEER_DIR_STR (peer));
                  break;

              case BGP_RFD_RT_STATE_USE:
                  bgp_aggregate_increment (bgp, p, ri, afi, safi);
                  bgp_process (bgp_mvrf, rn, afi, safi, NULL);
                  /* Do not break here */
              case BGP_RFD_RT_STATE_DAMPED:
                  peer->pcount [baai][bsai]++;
                  break;
            }

          bgp_attr_unintern (attr_new);
        }
      else
        {
          /* The attributes have changed. */
          SET_FLAG (ri->flags, BGP_INFO_ATTR_CHANGED);

#ifdef HAVE_BGP_SDN
	  bgp_delete_rib (bgp, p, ri);
#endif

          /* Withdraw aggregation if any with old attr */
          bgp_aggregate_decrement (bgp, p, ri, afi, safi);

          /* Update attr changes */
          bgp_attr_unintern (ri->attr);
          ri->attr = attr_new;

          /*
           * Update bgp route dampening information. Route change
           * is treated as Route Withdraw + Update.
           */
          bgp_rfd_rt_withdraw (bgp, peer, afi, safi, rn, ri, &rt_state);
          bgp_rfd_rt_update (ri, &rt_state);
          switch (rt_state)
            {
              case BGP_RFD_RT_STATE_NONE:
              case BGP_RFD_RT_STATE_USE:
                  bgp_aggregate_increment (bgp, p, ri, afi, safi);
                  bgp_process (bgp_mvrf, rn, afi, safi, NULL);
                  break;

              case BGP_RFD_RT_STATE_DAMPED:
                  break;
            }
        }

      bgp_unlock_node (rn);

      goto EXIT;
    }
  /* increment the pcount only if the flag is true */
  if (PAL_TRUE == pcount)
    peer->pcount [baai][bsai]++;

  /* Create a new BGP info */
  ri = bgp_info_new ();
  ri->type = type;
  ri->sub_type = sub_type;
  ri->peer = peer;
  ri->attr = attr_new;
  ri->bri_uptime = pal_time_sys_current (NULL);

  /* Validate Prefix for IGP Synchronization */
  if (bgp_af_config_check (bgp, afi, safi, BGP_AF_CFLAG_SYNCHRONIZATION)
      && (peer_type == BGP_PEER_IBGP
          || peer_type == BGP_PEER_CONFED))
    {
      /* Check if already verified for IGP Synchronization */
      for (ri_tmp = rn->info; ri_tmp; ri_tmp = ri_tmp->next)
        if (CHECK_FLAG (ri_tmp->flags, BGP_INFO_SYNCHRONIZED)
            || CHECK_FLAG (ri_tmp->flags, BGP_INFO_UNSYNCHRONIZED))
          break;

      if (ri_tmp)
        {
          if (CHECK_FLAG (ri_tmp->flags, BGP_INFO_SYNCHRONIZED))
            SET_FLAG (ri->flags, BGP_INFO_SYNCHRONIZED);
          else
            SET_FLAG (ri->flags, BGP_INFO_UNSYNCHRONIZED);
        }
      else
      {
	BGP_GET_PREFIX_FROM_NODE (rn);
      }
    }

  /* Valid Nexthop */
  SET_FLAG (ri->flags, BGP_INFO_NHOP_VALID);

  /* Register new BGP information. */
  bgp_info_add (rn, ri);

  /* Aggregate address increment. */
  bgp_aggregate_increment (bgp, p, ri, afi, safi);

  /* Process change. */
  bgp_process (bgp_mvrf, rn, afi, safi, NULL);
     
  goto EXIT;

FILTERED:

  /* BGP update is filtered.  */
  if (BGP_DEBUG (update, UPDATE_IN))
    zlog_info (&BLG, "%s-%s [RIB] Update: Prefix %O denied due to %s",
               peer->host, BGP_PEER_DIR_STR (peer), p, reason);

  if (ri)
    {
      if (PAL_TRUE == pcount && peer->pcount[baai][bsai] > 0)
        peer->pcount[baai][bsai]--;
      bgp_rib_withdraw (peer, rn, ri, afi, safi);
    }

  bgp_unlock_node (rn);

EXIT:
  return ret;
  
}

s_int32_t
bgp_update_route_all_instances (struct bgp_peer *peer,
                                struct prefix *p,
                                struct attr *attr,
                                afi_t afi, safi_t safi,
                                u_int32_t type, u_int32_t sub_type,
                                struct bgp_rd_node *prn,
                                u_int32_t soft_reconfig)
{
  s_int32_t ret;
  struct peer_bgp_node * pbgp_node = NULL;
  struct listnode *node = NULL;
  u_int32_t baai;
  u_int32_t bsai;
  bool_t is_first_peer;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  ret = 0;
  is_first_peer = PAL_TRUE;

 if (!bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
   return -1;

 /*allow same peer multiplet instance is set then update in all the instance
  * that this peer is visible
  */
  LIST_LOOP (peer->peer_bgp_node_list, pbgp_node, node)
    {
     /* if the peer is not activated for this address family in the 
      * current instance then continue */
      if (!pbgp_node->afc[baai][bsai])
        continue;

      peer->bgp = pbgp_node->bgp;
      peer->pbgp_node_inctx = pbgp_node;

      ret = bgp_update_route(peer, p, attr, afi, safi, type, sub_type, prn, 
                             soft_reconfig, is_first_peer);
     /* to increament pcount only once */
      is_first_peer = PAL_FALSE;
    } 

  return ret;
}
/* BGP RIB Update (Advertised) NLRI Processing */
s_int32_t
bgp_update (struct bgp_peer *peer,
            struct prefix *p,
            struct attr *attr,
            afi_t afi, safi_t safi,
            u_int32_t type, u_int32_t sub_type,
            struct bgp_rd_node *prn,
            u_int32_t soft_reconfig)
{
  s_int32_t ret;

   ret = 0;
    
   if (!attr)
     return -1;

   if (!bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
     ret = bgp_update_route(peer, p, attr, afi, safi, type, sub_type, prn,
                            soft_reconfig, PAL_TRUE);
   /* all same peer is set  then update in all the instance that this 
    * peer is visible
    */
   else 
     ret = bgp_update_route_all_instances (peer, p, attr, afi, safi, type,
                                           sub_type, prn, soft_reconfig);

  return ret;
}

/* BGP RIB Withdrawn NLRI Processing */
s_int32_t
bgp_withdraw_route (struct bgp_peer *peer,
                    struct prefix *p,
                    afi_t afi, safi_t safi,
                    u_int32_t type, u_int32_t sub_type,
                    struct bgp_rd_node *prn,
                    struct bgp_rd_node *prn_origin,
                    bool_t pcount)
{
  enum bgp_rfd_rt_state rt_state;
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp *bgp = NULL;
  s_int32_t ret;
  struct prefix rnp;

  ret = 0;

  /* Sanity check */
  if (! peer || ! peer->bgp)
    {
      ret = -1;
      goto EXIT;
    }

  bgp = peer->bgp;

    /* Logging. */
    if (BGP_DEBUG (update, UPDATE_IN))
      zlog_info (&BLG, "%s-%s [RIB] Withdraw: Prefix %O",
                 peer->host, BGP_PEER_DIR_STR (peer), p);

    /* Lookup node */
    rn = bgp_afi_node_get (bgp, afi, safi, p, prn);
    if (!rn)
     {
       ret = -1;
       goto EXIT;
     }

    /* Release recorded inbound soft-reconfiguration */
    if (CHECK_FLAG (peer->af_flags [BGP_AFI2BAAI (afi)]
                                   [BGP_SAFI2BSAI (safi)],
                    PEER_FLAG_SOFT_RECONFIG))
      bgp_adj_in_unset (rn, peer);

    /* Lookup withdrawn route. */
    for (ri = rn->info; ri; ri = ri->next)
      if (ri->peer == peer
          && ri->type == type
          && ri->sub_type == sub_type)
        break;

    /* Withdraw specified route from routing table */
    if (ri)
      {
        /* Decrement for the first bgp instance only */
        if (PAL_TRUE == pcount && 
            peer->pcount [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)] > 0)
          peer->pcount [BGP_AFI2BAAI (afi)][BGP_SAFI2BSAI (safi)]--;

        BGP_GET_PREFIX_FROM_NODE (rn);
        bgp_aggregate_decrement (peer->bgp, &rnp, ri, afi, safi);
        bgp_rfd_rt_withdraw (peer->bgp, peer, afi, safi, rn, ri, &rt_state);
        switch (rt_state)
          {
            case BGP_RFD_RT_STATE_NONE:
            case BGP_RFD_RT_STATE_USE:
            case BGP_RFD_RT_STATE_DAMPED:
              bgp_rib_withdraw (peer, rn, ri, afi, safi);
              break;
          }
      }
    else
      zlog_warn (&BLG, "%s-%s [RIB] Withdraw: Can't find route %O",
                 peer->host, BGP_PEER_DIR_STR (peer), p);

      /* Unlock bgp_node_get() lock. */
      bgp_unlock_node (rn);
      goto EXIT;

EXIT:
   return ret;
}

s_int32_t
bgp_withdraw_route_all_instances (struct bgp_peer *peer,
                                  struct prefix *p,
                                  afi_t afi, safi_t safi,
                                  u_int32_t type, u_int32_t sub_type,
                                  struct bgp_rd_node *prn,
                                  struct bgp_rd_node *prn_origin)
{
  s_int32_t ret;
  struct peer_bgp_node * pbgp_node = NULL;
  struct listnode *node = NULL;
  u_int32_t baai;
  u_int32_t bsai; 
  bool_t is_first_peer;

  if (!bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
    return -1;

  ret = 0;
  is_first_peer = PAL_TRUE;
  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
 /*allow same peer multiplet instance is set then update in all the instance
  * that this peer is visible
  */
  LIST_LOOP (peer->peer_bgp_node_list, pbgp_node, node)
    {
      /* if the peer is not activated for this address family in the 
       * current instance then continue */
      if (!pbgp_node->afc[baai][bsai])
        continue;

       peer->bgp = pbgp_node->bgp;
       peer->pbgp_node_inctx = pbgp_node;
       prn_origin = NULL; 

       ret = bgp_withdraw_route(peer, p, afi, safi, type, sub_type, prn, 
                                prn_origin, is_first_peer);

       /* make sure the pcount for this peer is update only once */
       is_first_peer = PAL_FALSE;
    } 

 return ret;
}

/* BGP RIB Withdrawn NLRI Processing */
s_int32_t
bgp_withdraw (struct bgp_peer *peer,
              struct prefix *p,
              afi_t afi, safi_t safi,
              u_int32_t type, u_int32_t sub_type,
              struct bgp_rd_node *prn,
              struct bgp_rd_node *prn_origin)
{
 s_int32_t ret;
 
  ret = 0;

  if (!bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
    ret = bgp_withdraw_route (peer, p, afi, safi, type, sub_type, prn, 
                        prn_origin, PAL_TRUE);
  else 
    ret = bgp_withdraw_route_all_instances (peer, p, afi, safi, type, sub_type,
                                            prn, prn_origin);
  return ret;
}

/* This function sends the learnt default-route to the peer.
   This function checks whether the DEFAULT-ORIGINATE flag is
   enabled for this peer or not. If the flag is not enabled
   the function sends the learnt default-route. */
void
bgp_peer_send_default_route (struct bgp_peer *peer,
                         struct bgp_node *rn,
                         struct attr attr,
                         struct prefix p,
                         afi_t afi, safi_t safi)

{
  struct bgp_info *ri;

  ri = NULL;
  for (ri = rn->info; ri; ri = ri->next)
    {
      if (ri->sub_type == BGP_ROUTE_NORMAL
          && CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
        break;
    }
  if (ri &&  bgp_announce_check (ri, peer, &p, &attr, afi, safi))
    bgp_adj_out_set (rn, peer, &attr, afi, safi, ri);
  else
    bgp_adj_out_unset (rn, peer, ri, afi, safi);
}

/* BGP Peer Default-Orignate route updation */
s_int32_t
bgp_peer_default_originate (struct bgp_peer *peer,
                            afi_t afi, safi_t safi,
                            bool_t remove)
{
  struct bgp_rmap_info brmi;
  route_map_result_t rmret;
  struct bgp_info tmp_ri;
  struct attr *attr_new;
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct attr attr;
  struct bgp *bgp;
  struct prefix p;
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;

  pal_mem_set (&p, 0, sizeof (struct prefix));
  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  rmret = RMAP_NOMATCH;
  bgp = peer->bgp;
  ret = 0;

  if (afi == AFI_IP)
    p.family = AF_INET;
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && afi == AFI_IP6)
    p.family = AF_INET6;
#endif /* HAVE_IPV6 */
  else
    {
      ret = -1;
      goto EXIT;
    }

  rn = bgp_afi_node_get (bgp, afi, safi, &p, NULL);

  if (! rn)
    {
      ret = -1;
      goto EXIT;
    }

  /* Extract an existing route */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
        && ri->type == IPI_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_DEFAULT)
      {
        break;
      }

  /* Initialize Attributes with Default values */
  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);

  attr.local_pref = bgp->default_local_pref;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);

  if (! remove && peer->default_rmap [baai][bsai].name)
    {
      if (! peer->default_rmap [baai][bsai].map)
        peer->default_rmap [baai][bsai].map =
            route_map_lookup_by_name (BGP_VR.owning_ivr,
                                      peer->default_rmap [baai][bsai].name);

      pal_mem_set (&tmp_ri, 0, sizeof (struct bgp_info));
      tmp_ri.peer = bgp->peer_self;
      tmp_ri.attr = &attr;

      pal_mem_set (&brmi, 0, sizeof (struct bgp_rmap_info));
      brmi.brmi_type = BGP_RMAP_INFO_SYNC_PREFIX;
      brmi.brmi_bgp = bgp;
      brmi.brmi_bri = &tmp_ri;

      rmret = route_map_apply (peer->default_rmap [baai][bsai].map,
                               &p, &brmi);
    }

  /* Internalize the attributes */
  attr_new = bgp_attr_intern (&attr);

  /* Update RIB entry if necessary */
  if (ri)
    {
      /* Withdraw Default route from RIB */
      if (remove
          || rmret == RMAP_DENYMATCH)
        {
          if (bgp_adj_out_lookup (peer, rn))
            {
              if (! rn->adj_out->next)
                {
                  bgp_aggregate_decrement (bgp, &p, ri, afi, safi);
                  bgp_info_delete (rn, ri);
                  /* when default-originated route is sent to only one peer
                     and the DEFAULT_ORIGINATE flag is disabled on this peer
                     control comes here. Then send the learnt default-route
                     if present. */
                  bgp_peer_send_default_route (peer, rn, attr, p, afi, safi);
                  bgp_info_free (ri);
                  bgp_unlock_node (rn);
                }
              else
                /* when default-originated route is sent to more than one peer
                   and the DEFAULT_ORIGINATE flag is disabled on a peer
                   control comes here. Then send the learnt default-route
                   if present to the peer on which DEFAULT_ORIG is disabled. */
                bgp_peer_send_default_route (peer, rn, attr, p, afi, safi);
            }
          else if (remove
                  && (rn->adj_out && !rn->adj_out->next
                      && (rn->adj_out->peer == peer)))
            {
              bgp_aggregate_decrement (bgp, &p, ri, afi, safi);
              bgp_info_delete (rn, ri);
              bgp_peer_send_default_route (peer, rn, attr, p, afi, safi);
              bgp_info_free (ri);
              bgp_unlock_node (rn);
            }
       /* NOTE: Since when the BGP_OPT_DISABLE_ADJ_OUT is enabled
         * rn->adj_out will not be there hence it is difficult to
         * handle complex default originate scenarios.
         */
          else if (remove 
                      && bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
            {
              bgp_aggregate_decrement (bgp, &p, ri, afi, safi);
              bgp_adj_out_unset (rn, peer, ri, afi, safi);
              bgp_info_delete (rn, ri); 
              bgp_info_free (ri);
              bgp_unlock_node (rn);
            }
          /* default-originated route is not sent so make this FALSE.*/
          peer->def_orig_route_sent = PAL_FALSE;
          bgp_attr_unintern (attr_new);
        }
      /* Process any changes in attributes */
      else
        {
          if (! attrhash_cmp (ri->attr, attr_new))
            {
              SET_FLAG (ri->flags, BGP_INFO_ATTR_CHANGED);

              bgp_attr_unintern (ri->attr);
              ri->attr = attr_new;
             /* when attributes are changed then the default-originated route
                 is sent to the peer to which default-originated route is
                 sent earlier. */
              if (ri
                  && peer->def_orig_route_sent == PAL_TRUE
                  && bgp_announce_check (ri, peer, &p, &attr, afi, safi))
                {
                   /* set the select SELECT flag as bgp_update_adj_out()
                    * need select route to pick the attributes.
                    * NOTE: need to set when BGP_OPT_DISABLE_ADJ_OUT  option
                    * not set.
                    */
                 if (bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
                    SET_FLAG (ri->flags, BGP_INFO_SELECTED);

                  bgp_adj_out_set (rn, peer, &attr, afi, safi, ri);
                }
              else
                {
                  if (ri)
                    {
                      if (bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
                        UNSET_FLAG (ri->flags, BGP_INFO_SELECTED);

                      bgp_adj_out_unset (rn, peer, ri, afi, safi);
                    }
                }
            }
          else
            {
              /* if DEFAULT_ORIGINATE flag is enabled on one more peer,
                 ri will not be NULL. Then send the default-originated route
                 based on whether the default-route is previously sent or not.
              */
              if (peer->def_orig_route_sent == PAL_FALSE)
                {
                  if (ri && bgp_announce_check (ri, peer, &p, &attr, afi, safi))
                    {
                      /* set the select SELECT flag as bgp_update_adj_out()
                       * need select route to pick the attributes.
                       * NOTE: need to set when BGP_OPT_DISABLE_ADJ_OUT  option
                       * not set.
                       */
                      if (bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
                          SET_FLAG (ri->flags, BGP_INFO_SELECTED);

                      bgp_adj_out_set (rn, peer, &attr, afi, safi, ri);
                      peer->def_orig_route_sent = PAL_TRUE;
                    }
                  else
                    {
                      if (ri)
                        {
                          if (bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
                            UNSET_FLAG (ri->flags, BGP_INFO_SELECTED);

                          bgp_adj_out_unset (rn, peer, ri, afi, safi);
                        }
                    }
                }
              bgp_attr_unintern (attr_new);
            }
        }

      bgp_unlock_node (rn);
    }
  /* Do Nothing if RIB entry is not needed */
  else if (remove
           || rmret == RMAP_DENYMATCH)
    {
      bgp_attr_unintern (attr_new);

      bgp_unlock_node (rn);
    }
  /* Finally, add the RIB entry since route is valid */
  else
    {
      ri = bgp_info_new ();

      if (! ri)
        {
          ret = -1;
          goto EXIT;
        }

      ri->type = IPI_ROUTE_BGP;
      ri->sub_type = BGP_ROUTE_DEFAULT;
      ri->peer = bgp->peer_self;
      ri->attr = attr_new;
      ri->bri_uptime = pal_time_sys_current (NULL);
      SET_FLAG (ri->flags, BGP_INFO_NHOP_VALID);

      bgp_aggregate_increment (bgp, &p, ri, afi, safi);

      bgp_info_add (rn, ri);

      /* Send the created ri to the peer, without under-going any
         selection process. This is a special case of default-originate.
         For Ex: R1 ---- R2 ---- R3. R1 can be a default-originate to R2 and
         R2 can be default-originate to R3. */
      if (ri && bgp_announce_check (ri, peer, &p, &attr, afi, safi))
        {
          /* set the select SELECT flag as bgp_update_adj_out()
          * need select route to pick the attributes.          
          * NOTE: need to set when BGP_OPT_DISABLE_ADJ_OUT  option
          * not set.
          */
          if (bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
            SET_FLAG (ri->flags, BGP_INFO_SELECTED);
          bgp_adj_out_set (rn, peer, &attr, afi, safi, ri);
          peer->def_orig_route_sent = PAL_TRUE;
        }
      else
        {
          if (ri)
            {
              if (bgp_option_check (BGP_OPT_DISABLE_ADJ_OUT))
                UNSET_FLAG (ri->flags, BGP_INFO_SELECTED);

              bgp_adj_out_unset (rn, peer, ri, afi, safi);
            }
        }

    }

EXIT:

  return ret;
}

void
bgp_peer_process_nlri (struct bgp_peer *peer,
                       struct attr *attr,
                       struct bgp_nlri *nlri_buf)
{
  struct attr tmp_attr;
  u_int32_t nlri_size;
  u_int8_t *nlri_bufp;
  void *prn_origin;
  struct prefix p;
  u_int8_t psize;
  safi_t safi;
  afi_t afi;
  void *prn;

  pal_mem_set (&tmp_attr, 0, sizeof (struct attr));
  nlri_size = nlri_buf->ni_length;
  nlri_bufp = nlri_buf->ni_data;
  safi = nlri_buf->ni_safi;
  afi = nlri_buf->ni_afi;
  prn_origin = NULL;
  prn = NULL;

  /*
   * NOTE: ALL Error checking has already been performed on 'nlri_buf'
   */

  if (attr)
    tmp_attr = *attr;

  while (nlri_size)
    {
      /* Clear Prefix structure */
      pal_mem_set (&p, 0, sizeof (struct prefix));

      /* Determine Prefix Family */
      p.family = afi2family (afi);

      /* Get 'PrefixLen' structure */
      p.prefixlen = *nlri_bufp++;
      nlri_size -= sizeof (u_int8_t);

      /* Determine Prefix size */
      psize = PSIZE (p.prefixlen);

      switch (safi)
        {
        case SAFI_UNICAST:
        case SAFI_MULTICAST:
          /* Get 'Prefix' value */
          pal_mem_cpy (&p.u.prefix, nlri_bufp, psize);
          nlri_bufp += psize;
          nlri_size -= psize;
          break;

        default:
          /* We have earlier ensured AFI-SAFI validation */
          pal_assert (0);
          goto EXIT;
        }

      /* Validate Prefix value for Semantic correctness */
      if (afi == AFI_IP
          && safi == SAFI_UNICAST)
        {
          if (IN_EXPERIMENTAL (pal_ntoh32 (p.u.prefix4.s_addr)))
            {
              zlog_warn (&BLG, "%s-%s [FSM] NLRI: Experimental (Class"
                         " E) Unicast NLRI (%O), Ignoring...",
                         peer->host, BGP_PEER_DIR_STR (peer), &p);

              continue;
            }

          if (IN_CLASSD (pal_ntoh32 (p.u.prefix4.s_addr)))
            {
              zlog_warn (&BLG, "%s-%s [FSM] NLRI: Unicast NLRI %O"
                         " is Multicast address, Ignoring...",
                         peer->host, BGP_PEER_DIR_STR (peer), &p);

              continue;
            }

          /* Allow Net-0 route (0.0.0.0/0) for default-origination */
          if (! IPV4_NET0 (pal_ntoh32 (p.u.prefix4.s_addr))
              && IPV4_ADDR_MARTIAN (pal_ntoh32 (p.u.prefix4.s_addr)))
            {
              zlog_warn (&BLG, "%s-%s [FSM] NLRI: Martian "
                         "Unicast NLRI (%O), Ignoring...",
                         peer->host, BGP_PEER_DIR_STR (peer), &p);

              continue;
            }
        }
#ifdef HAVE_IPV6
      /* Ignore Link-Local IPv6 Address */
      else if (BGP_CAP_HAVE_IPV6
               && afi == AFI_IP6 && safi == SAFI_UNICAST
               && IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
        {
          zlog_warn (&BLG, "%s-%s [FSM] NLRI: IPV6 link-"
                     "local NLRI received %R, Ignoring NLRI...",
                     peer->host, BGP_PEER_DIR_STR (peer),
                     &p.u.prefix6);

          continue;
        }
#endif /* HAVE_IPV6 */

      /* Maximum Prefix-Count check */
      if (PAL_TRUE == bgp_peer_max_prefix_overflow (peer, afi, safi))
        goto EXIT;

      if (attr)
        bgp_update (peer, &p, &tmp_attr, afi, safi, IPI_ROUTE_BGP,
                    BGP_ROUTE_NORMAL, prn, 0);
      else
        bgp_withdraw (peer, &p, afi, safi, IPI_ROUTE_BGP,
                      BGP_ROUTE_NORMAL, prn, prn_origin);
    }

EXIT:

  return;
}

/* Inbound Soft Reconfiguration */
void
bgp_soft_reconfig_in (struct bgp_peer *peer,
                      afi_t afi, safi_t safi)
{
  struct bgp_adj_in *bai;
  struct bgp_node *rn;
  struct bgp *bgp;
  s_int32_t ret;
  struct prefix rnp;

  bgp = peer->bgp;
  if (! bgp)
    return;

  for (rn = bgp_table_top (bgp->rib [BGP_AFI2BAAI (afi)]
                                    [BGP_SAFI2BSAI (safi)]);
       rn; rn = bgp_route_next (rn))
    for (bai = rn->adj_in; bai; bai = bai->next)
      if (bai->peer == peer)
        {
	  BGP_GET_PREFIX_FROM_NODE (rn);
          ret = bgp_update (peer, &rnp, bai->attr, afi, safi,
                            IPI_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, 1);

          /* Address family configuration mismatch or maximum-prefix count
             overflow. */
          if (ret < 0)
            {
              bgp_unlock_node (rn);
              return;
            }
        }

  return;
}

/* BGP Peer Route-Table Announcement */
void
bgp_peer_initial_announce (struct bgp_peer *peer)
{
  u_int32_t baai;
  u_int32_t bsai;

  /* Reset capability open status flag. */
  if (! CHECK_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN))
    SET_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

  /* Send Route-Refresh when ORF is enabled */
  for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX ; bsai++)
      if (CHECK_FLAG (peer->af_cap [baai][bsai],
                      PEER_CAP_ORF_PREFIX_SM_ADV))
        {
          if (CHECK_FLAG (peer->af_cap [baai][bsai],
                          PEER_CAP_ORF_PREFIX_RM_RCV))
            bgp_peer_send_route_refresh (peer, BGP_BAAI2AFI (baai),
                                         BGP_BSAI2SAFI (bsai),
                                         BGP_ORF_TYPE_PREFIX,
                                         BGP_ORF_REFRESH_IMMEDIATE,
                                         0);
          else if (CHECK_FLAG (peer->af_cap [baai][bsai],
                               PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
            bgp_peer_send_route_refresh (peer, BGP_BAAI2AFI (baai),
                                         BGP_BSAI2SAFI (bsai),
                                         BGP_ORF_TYPE_PREFIX_OLD,
                                         BGP_ORF_REFRESH_IMMEDIATE,
                                         0);
        }

  /* Defer first UPDATE till ORF or ROUTE-REFRESH is received */
  for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX ; bsai++)
      {
        if (CHECK_FLAG (peer->af_cap [baai][bsai],
                        PEER_CAP_ORF_PREFIX_RM_ADV)
            && (CHECK_FLAG (peer->af_cap [baai][bsai],
                            PEER_CAP_ORF_PREFIX_SM_RCV)
              || CHECK_FLAG (peer->af_cap [baai][bsai],
                             PEER_CAP_ORF_PREFIX_SM_OLD_RCV)))
         {
           if (! CHECK_FLAG (peer->af_sflags [baai][bsai],
                             PEER_STATUS_ORF_NOT_WAIT_REFRESH))
             {
               SET_FLAG (peer->af_sflags [baai][bsai],
                         PEER_STATUS_ORF_WAIT_REFRESH);
               if (BGP_DEBUG (events, EVENTS))
                 zlog_info (&BLG, "%s-%s [ENCODE] PEER_STATUS_ORF_WAIT_REFRESH set!\n", peer->host, BGP_PEER_DIR_STR (peer));
             }
           else
             {
               UNSET_FLAG (peer->af_sflags [baai][bsai],
                           PEER_STATUS_ORF_NOT_WAIT_REFRESH);
               if (BGP_DEBUG (events, EVENTS))
                 zlog_info (&BLG, "%s-%s [ENCODE] PEER_STATUS_ORF_NOT_WAIT_REFRESH unset!\n", peer->host, BGP_PEER_DIR_STR (peer));
             }
          }

        bgp_announce_route (peer, BGP_BAAI2AFI (baai),
                            BGP_BSAI2SAFI (bsai));
      }

  /* When Peer's MinASOrigin interval is zero, enable immediate advt. */
  if (peer->v_asorig && ! peer->t_asorig)
    BGP_TIMER_ON (&BLG, peer->t_asorig, peer, bpf_timer_asorig, 1);
  else if (! peer->v_asorig && ! peer->t_asorig)
    for (baai = BAAI_IP ; baai < BAAI_MAX ; baai++)
      for (bsai = BSAI_UNICAST; bsai < BSAI_MAX ; bsai++)
        SET_FLAG (peer->af_sflags [baai][bsai],
                  PEER_STATUS_AF_ASORIG_ROUTE_ADV);

  /* When Peer's MinRouteAdv interval is zero, send immediately */
  if (peer->v_routeadv && ! peer->t_routeadv)
    BGP_TIMER_ON (&BLG, peer->t_routeadv, peer, bpf_timer_routeadv, 1);
  else if (! peer->v_routeadv && ! peer->t_routeadv)
    BGP_PEER_FSM_EVENT_ADD (&BLG, peer, BPF_EVENT_ROUTEADV_EXP);

  return;
}

void
bgp_announce_table (struct bgp_peer *peer,
                    afi_t afi, safi_t safi,
                    struct bgp_rd_node *prn)
{
  struct bgp_node *rn = NULL;
  struct bgp_info *ri;
  struct attr attr;
  struct prefix p;
  u_int32_t baai;
  u_int32_t bsai;
  struct prefix rnp;
  struct bgp_ptree *table;
  
  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  /*  Set prefix p to  default address 0.0.0.0 */
  pal_mem_set (&p, 0, sizeof(struct prefix));

  if (afi == AFI_IP)
    p.family = AF_INET;
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && afi == AFI_IP6)
    p.family = AF_INET6;
#endif /* HAVE_IPV6 */

  if (! prn)
    table = peer->bgp->rib [baai][bsai];
  else
    table = prn->rib;

  if (CHECK_FLAG (peer->af_flags [baai][bsai],
                  PEER_FLAG_DEFAULT_ORIGINATE))
    bgp_peer_default_originate (peer, afi, safi, PAL_FALSE);

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next(rn))
    {
      /* If the rn prefix is a default prefix and if this peer is
       * already selected to advertise default-route
       * i.e. peer is present in the ADJ-OUT of default-route, no need to
       * loop through again to send the default-route.
      */
      BGP_GET_PREFIX_FROM_NODE (rn);
      if ( (!prefix_cmp (&p, &rnp))
          && (bgp_adj_out_lookup (peer, rn) == PAL_TRUE))
        continue;

      for (ri = rn->info; ri; ri = ri->next)
        if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED) && ri->peer != peer)
          {
            BGP_GET_PREFIX_FROM_NODE (rn);
            /* Check against the passed AFI and prefix's family */
#ifdef HAVE_IPV6
            if ((rnp.family == AF_INET6?AFI_IP6:AFI_IP) != afi)
              continue;
#endif /* HAVE_IPV6 */

	    if (bgp_announce_check (ri, peer, &rnp, &attr, afi, safi))
	      bgp_adj_out_set (rn, peer, &attr, afi, safi, ri);
	    else
	      {
                if (ri)
                  bgp_adj_out_unset (rn, peer, ri, afi, safi);
	      }
          }
    }
  return;
}

void
bgp_announce_route (struct bgp_peer *peer,
                    afi_t afi, safi_t safi)
{
  u_int32_t baai;
  u_int32_t bsai;
  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  if (!peer || !peer->bgp)
    return;

  if (! peer->afc_nego [baai][bsai])
    {
        return;
    }

  /* Defer first UPDATE till ORF or ROUTE-REFRESH is received */
  if (CHECK_FLAG (peer->af_sflags [baai][bsai],
                  PEER_STATUS_ORF_WAIT_REFRESH))
    return;

  bgp_announce_table (peer, afi, safi, NULL);

  return;
}


/* Internal function to clear peer routes.  */
void
bgp_clear_route_table (struct bgp_peer *peer,
                       afi_t afi, safi_t safi,
                       struct bgp_ptree *table)
{
  struct bgp_adj_out *aout_next;
  struct bgp_adj_out *aout;
  struct bgp_adj_in *ain;
  struct bgp *bgp_mvrf;
  struct bgp_node *rn;
  struct bgp_info *ri;
  u_int32_t baai;
  u_int32_t bsai;
  struct prefix rnp;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  if (! table
      && peer->bgp->rib [baai][bsai])
    table = peer->bgp->rib [baai][bsai];

  bgp_mvrf = peer->bgp;

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->next)
        if (ri->peer == peer)
          {
	    BGP_GET_PREFIX_FROM_NODE (rn);
            /* Check against the passed AFI and prefix's family */
#ifdef HAVE_IPV6
            if ((rnp.family == AF_INET6?AFI_IP6:AFI_IP) != afi)
              continue;
#endif /* HAVE_IPV6 */
            bgp_aggregate_decrement (peer->bgp, &rnp, ri, afi, safi);
            bgp_info_delete (rn, ri);
            bgp_process (bgp_mvrf, rn, afi, safi, ri);
            bgp_info_free (ri);
            bgp_unlock_node (rn);
            break;
          }
      for (ain = rn->adj_in; ain; ain = ain->next)
        if (ain->peer == peer)
          {
            bgp_adj_in_remove (rn, ain);
            break;
          }
      for (aout = rn->adj_out; aout; aout = aout_next)
        {
          aout_next = aout->next;
          if (aout->peer == peer)
            {
              bgp_adj_out_remove (rn, aout, peer, afi, safi, PAL_FALSE);
              break;
            }
        }
    }

  return;
}

/* Clear specified AFI and SAFI routes.  */
void
bgp_clear_all_routes (struct bgp_peer *peer, afi_t afi, safi_t safi,
                      struct list * list) 
{
  u_int32_t baai;
  u_int32_t bsai;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  bgp_clear_route_table (peer, afi, safi, NULL);

  /* If peer is enabled with default-originate reset the def-route-sent
     to PAL_FALSE so that default-route is once again advertised if peer session
     is reset. */
  if (CHECK_FLAG (peer->af_flags [baai][bsai],
                  PEER_FLAG_DEFAULT_ORIGINATE))
    peer->def_orig_route_sent = PAL_FALSE;

  /* When allow same peer is enabled,
   * reset the send count and receive of a peer only when 
   * routes are removed from all the instance.
   */
  if (!bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
    {
       peer->pcount [baai][bsai] = 0;
       peer->scount [baai][bsai] = 0;
    }

}

void
bgp_clear_all_instance_routes (struct bgp_peer *peer, afi_t afi, safi_t safi)
{
  struct list *list;
  struct listnode *node;
  struct peer_bgp_node *pbgp_node;
  u_int32_t baai;
  u_int32_t bsai;

 if (!bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
   return;
   
  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);
  pbgp_node = NULL;
  node = NULL;

  LIST_LOOP (peer->peer_bgp_node_list, pbgp_node, node)
    { 
      list = NULL;
      peer->bgp = pbgp_node->bgp;

      bgp_clear_all_routes (peer, afi, safi, list);
    }

  peer->pcount [baai][bsai] = 0;
  peer->scount [baai][bsai] = 0;
  
}

/* Clear specified AFI and SAFI routes.  */
void
bgp_clear_route (struct bgp_peer *peer, afi_t afi, safi_t safi)
{
 struct list *list  = NULL;

 if (!bgp_option_check (BGP_OPT_MULTI_INS_ALLOW_SAME_PEER))
    bgp_clear_all_routes (peer, afi, safi, list);
 else 
     bgp_clear_all_instance_routes (peer, afi, safi);
 return;
}

/* Clear specified BGP Peer's routes of all address families */
void
bgp_peer_clear_route_all (struct bgp_peer *peer)
{
  u_int32_t baai;
  u_int32_t bsai;

  for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
    for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
        bgp_clear_route (peer, BGP_BAAI2AFI (baai),
                         BGP_BSAI2SAFI (bsai));

  return;
}

/* BGP static network updation */
s_int32_t
bgp_static_network_update (struct bgp *bgp,
                           struct prefix *p,
                           struct bgp_static *bstatic,
                           afi_t afi, safi_t safi,
                           bool_t remove)
{
  struct bgp_rmap_info brmi;
  route_map_result_t rmret;
  struct bgp_info tmp_ri;
  struct attr *attr_new;
  struct bgp *bgp_mvrf;
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct attr attr;
  s_int32_t ret;

  rmret = RMAP_NOMATCH;
  bgp_mvrf = bgp;
  ret = 0;

  pal_mem_set (&attr, 0, sizeof (struct attr));

  rn = bgp_afi_node_get (bgp, afi, safi, p, NULL);
  if (! rn)
    {
      ret = -1;
      goto EXIT;
    }

  /* Process backdoor route if the network command is backdoor */
    if (bstatic->bs_backdoor)
      bgp_static_network_backdoor_process (bgp, p, rn, remove, afi, safi);

  /* Extract an existing route */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
        && ri->type == IPI_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_STATIC)
      {
        break;
      }

  /* Initialize Attributes with Default values */
  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);

  attr.local_pref = bgp->default_local_pref;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);

  /* Apply route-map */
  if (! remove && bstatic->bs_rmap.name)
    {
      bstatic->bs_rmap.map =
          route_map_lookup_by_name (BGP_VR.owning_ivr,
                                    bstatic->bs_rmap.name);

      pal_mem_set (&tmp_ri, 0, sizeof (struct bgp_info));
      tmp_ri.peer = bgp->peer_self;
      tmp_ri.attr = &attr;

      pal_mem_set (&brmi, 0, sizeof (struct bgp_rmap_info));
      brmi.brmi_type = BGP_RMAP_INFO_SYNC_PREFIX;
      brmi.brmi_bgp = bgp;
      brmi.brmi_bri = &tmp_ri;

      rmret = route_map_apply (bstatic->bs_rmap.map, p, &brmi);
    }

  /* Internalize the attributes */
  attr_new = bgp_attr_intern (&attr);

  /* Update RIB entry if necessary */
  if (ri)
    {
      /* Withdraw BGP static route from RIB */
      if (remove
          || rmret == RMAP_DENYMATCH
          || bstatic->bs_backdoor
          || (bgp_af_config_check (bgp, afi, safi,
                                   BGP_AF_CFLAG_NETWORK_SYNC)))
        {
          bgp_aggregate_decrement (bgp, p, ri, afi, safi);
          bgp_info_delete (rn, ri);
          bgp_process (bgp_mvrf, rn, afi, safi, ri);
          bgp_info_free (ri);
          bgp_unlock_node (rn);

          bgp_attr_unintern (attr_new);
        }
      /* Process any changes in attributes */
      else
        {
          if (! attrhash_cmp (ri->attr, attr_new))
            {
              SET_FLAG (ri->flags, BGP_INFO_ATTR_CHANGED);

#ifdef HAVE_BGP_SDN
	      bgp_delete_rib (bgp, p, ri);
#endif /* HAVE_BGP_SDN */

              bgp_attr_unintern (ri->attr);
              ri->attr = attr_new;

              bgp_process (bgp_mvrf, rn, afi, safi, NULL);
            }
          else
            bgp_attr_unintern (attr_new);
        }

      bgp_unlock_node (rn);
    }
  /* Do Nothing if RIB entry is not needed */
  else if (remove
           || rmret == RMAP_DENYMATCH
           || bstatic->bs_backdoor
           || (bgp_af_config_check (bgp, afi, safi,
                                    BGP_AF_CFLAG_NETWORK_SYNC)))
    {
      bgp_attr_unintern (attr_new);

      bgp_unlock_node (rn);
    }
  /* Finally, add the RIB entry since route is valid */
  else
    {
      ri = bgp_info_new ();
      ri->type = IPI_ROUTE_BGP;
      ri->sub_type = BGP_ROUTE_STATIC;
      ri->peer = bgp->peer_self;
      ri->attr = attr_new;
      ri->bri_uptime = pal_time_sys_current (NULL);
      SET_FLAG (ri->flags, BGP_INFO_NHOP_VALID);

      bgp_aggregate_increment (bgp, p, ri, afi, safi);

      bgp_info_add (rn, ri);

      bgp_process (bgp_mvrf, rn, afi, safi, NULL);
    }

EXIT:

  return ret;
}

/*
 * Function name: bgp_static_network_backdoor_process ()
 * Input        : bgp, prefix, bgp_node structures, bool_t
 * Output       : None
 * Purpose      : For Updating FIB for the bgp learned route with new distance
                  so that IGP routes for the same network if
                  any will be preferred.
*/

void
bgp_static_network_backdoor_process(struct bgp *bgp,
                                    struct prefix *p,
                                    struct bgp_node *rn,
                                    bool_t remove,
                                    afi_t afi, safi_t safi)
{
  struct attr attr;
  struct attr *attr_new = NULL;
  struct bgp_info *ri = NULL;
  u_int32_t baai = 0;
  u_int32_t bsai = 0;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);

  /* Extract an existing bgp learned route and update the distance */
  for (ri = rn->info; ri; ri = ri->next)
    if (peer_sort (ri->peer) == BGP_PEER_EBGP
        && ri->type == IPI_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_NORMAL)
      {
        attr = *ri->attr;

        /* Check if already backdoor is processed */
        if (!remove && (attr.distance == IPI_DISTANCE_IBGP))
          continue;

        /* if remove is PAL_FALSE, backdoor is configured */
        if (!remove)
          attr.distance = IPI_DISTANCE_IBGP;

        /* if remove is PAL_TRUE, backdoor is unconfigured and if distance is
         * configured it should take the configured value  */
        else if ((ri->peer->bgp)
           && (ri->peer->bgp->distance_ebgp[baai][bsai]))
          attr.distance = ri->peer->bgp->distance_ebgp[baai][bsai];
        else
          attr.distance = IPI_DISTANCE_EBGP;

        attr_new = bgp_attr_intern (&attr);
        bgp_attr_unintern (ri->attr);
        ri->attr = attr_new;
        if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
	  {
#ifdef HAVE_BGP_SDN
	    bgp_rest_handler (bgp, rn, ri, NULL, NULL);
#endif /* HAVE_BGP_SDN */
	  }
      }
  return;
}

/* BGP static network set */
s_int32_t
bgp_static_network_set (struct bgp *bgp,
                        u_int8_t *ip_str,
                        afi_t afi, safi_t safi,
                        u_int32_t backdoor,
                        u_int8_t *rmap_name)
{
  struct bgp_static *bstatic;
  struct bgp_node *rn;
  struct prefix p;
  s_int32_t ret;
  struct prefix rnp;

  pal_mem_set (&p, 0, sizeof (struct prefix));

  /* Convert IP prefix string to struct prefix */
  ret = str2prefix (ip_str, &p);

  if (! ret || ! bgp)
    return BGP_API_SET_ERR_INVALID_NETWORK;

  ret = BGP_API_SET_SUCCESS;
  apply_mask (&p);

   if (afi == AFI_IP)
    {
      /* IPv4 address cannot be Class E or Maritian */
      if (IN_BADCLASS (pal_ntoh32 (p.u.prefix4.s_addr))
          || IN_MULTICAST (pal_ntoh32 (p.u.prefix4.s_addr))
          || (p.prefixlen
              && IPV4_ADDR_MARTIAN (pal_ntoh32 (p.u.prefix4.s_addr))))
        return BGP_API_SET_ERR_INVALID_NETWORK;
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && afi == AFI_IP6)
    {
      /* IPv6 link-local address is not acceptable */
      if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
        return BGP_API_SET_ERR_INVALID_NETWORK;
    }
#endif /* HAVE_IPV6 */
  else
    return BGP_API_SET_ERROR;

  /* Lookup existing network configuration */

  rn = bgp_node_get (bgp->route [BGP_AFI2BAAI (afi)]
                                [BGP_SAFI2BSAI (safi)], &p);
  if (NULL == rn)
    return BGP_API_SET_ERROR;

  if (! (bstatic = rn->info))
    {
      /* Create a new network static strucutre */
      bstatic = XCALLOC (MTYPE_BGP_STATIC,
                         sizeof (struct bgp_static));

      if (! bstatic)
        {
          bgp_unlock_node (rn);

          return BGP_API_SET_ERROR;
        }

      rn->info = bstatic;
    }
  else
    {
      bgp_unlock_node (rn);

      if (bstatic->bs_backdoor == backdoor
          && ((! rmap_name && ! bstatic->bs_rmap.name)
              || (rmap_name && bstatic->bs_rmap.name
                  && ! pal_strcmp (bstatic->bs_rmap.name, rmap_name))))
        return BGP_API_SET_ERR_OBJECT_ALREADY_EXIST;
    }

  bstatic->bs_backdoor = backdoor;
  if (bstatic->bs_rmap.name)
    {
      XFREE (MTYPE_TMP, bstatic->bs_rmap.name);
      bstatic->bs_rmap.name = NULL;
    }

  if (rmap_name)
    bstatic->bs_rmap.name = XSTRDUP (MTYPE_TMP, rmap_name);

  /* Update BGP RIB with static network route */
  BGP_GET_PREFIX_FROM_NODE (rn);
  ret = bgp_static_network_update (bgp, &rnp, bstatic,
                                   afi, safi, PAL_FALSE);

  return ret;
}

/* BGP static network unset */
s_int32_t
bgp_static_network_unset (struct bgp *bgp,
                          u_int8_t *ip_str,
                          afi_t afi, safi_t safi)
{
  struct bgp_static *bstatic;
  struct bgp_node *rn;
  struct prefix p;
  s_int32_t ret;

  pal_mem_set (&p, 0, sizeof (struct prefix));
  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, &p);

  if (! ret || ! bgp)
    return BGP_API_SET_ERR_INVALID_NETWORK;

  ret = BGP_API_SET_SUCCESS;
  apply_mask (&p);

  if (afi == AFI_IP)
    {
      /* IPv4 address cannot be Class E or Maritian */
      if (IN_BADCLASS (pal_ntoh32 (p.u.prefix4.s_addr))
          || IN_MULTICAST (pal_ntoh32 (p.u.prefix4.s_addr))
          || (p.prefixlen
              && IPV4_ADDR_MARTIAN (pal_ntoh32 (p.u.prefix4.s_addr))))
        return BGP_API_SET_ERR_INVALID_NETWORK;
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && afi == AFI_IP6)
    {
      /* IPv6 link-local address is not acceptable */
      if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
        return BGP_API_SET_ERR_INVALID_NETWORK;
    }
#endif /* HAVE_IPV6 */
  else
    return BGP_API_SET_ERROR;

  rn = bgp_node_lookup (bgp->route [BGP_AFI2BAAI (afi)]
                                   [BGP_SAFI2BSAI (safi)], &p);
  if (! rn)
    return BGP_API_SET_ERR_UNKNOWN_OBJECT;

  if ((bstatic = rn->info))
    {
      /* Withdraw static network route from BGP RIB */
      ret = bgp_static_network_update (bgp, &p, bstatic,
                                       afi, safi, PAL_TRUE);

      /* Release the static structure */
      if (bstatic->bs_rmap.name)
        XFREE (MTYPE_TMP, bstatic->bs_rmap.name);

      rn->info = NULL;
      XFREE (MTYPE_BGP_STATIC, bstatic);
      bgp_unlock_node (rn);
    }

  bgp_unlock_node (rn);

  return ret;
}


/* This function handles the dynamic change of the client to client
 * route reflection capability from cli. */  
void
bgp_reflected_routes_update (struct bgp *bgp)
{
  struct listnode *nn = NULL;
  struct bgp_peer *peer = NULL;
  u_int32_t baai;
  u_int32_t bsai;
  struct bgp_info *ri = NULL;
  struct prefix rnp;
  struct bgp_node *rn = NULL ;
  struct attr attr; 
  /* Announce or withdraw routes to neighbors */
  LIST_LOOP (bgp->peer_list, peer,nn)
    for (baai = BAAI_IP; baai < BAAI_MAX; baai++)
      for (bsai = BSAI_UNICAST; bsai < BSAI_MAX; bsai++)
        {
           for (rn = bgp_table_top (bgp->rib [baai][bsai]);
                rn; rn = bgp_route_next (rn))
             { 
               for (ri = rn->info; ri; ri = ri->next)
                 {
                   if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
                       && ri->peer != peer
                       && peer_sort (peer) == BGP_PEER_IBGP 
                       && peer_sort (ri->peer) == BGP_PEER_IBGP)
                     {
                       BGP_GET_PREFIX_FROM_NODE (rn);
                       if  (ri &&  bgp_announce_check (ri, peer, &rnp, &attr,
                                   BGP_BAAI2AFI (baai), BGP_BSAI2SAFI (bsai)))
                          bgp_adj_out_set (rn, peer, &attr, BGP_BAAI2AFI (baai),
                                                  BGP_BSAI2SAFI (bsai), ri);
                       else
                          bgp_adj_out_unset (rn, peer, ri, BGP_BAAI2AFI (baai),
                                                      BGP_BSAI2SAFI (bsai));
                     }
                 }
             }
        }
  return; 
}

/* BGP Aggregate address manipulation functions */
bool_t
bgp_aggregate_attr_same (struct attr *attr1, struct attr *attr2)
{
    return PAL_FALSE;
#ifdef HAVE_EXT_CAP_ASN
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      if (! as4path_cmp (attr1->aspath4B, attr2->aspath4B))
        return PAL_FALSE;
    }
  else
    {
#endif /* HAVE_EXT_CAP_ASN */
    if (! aspath_cmp (attr1->aspath, attr2->aspath))
      return PAL_FALSE;
#ifdef HAVE_EXT_CAP_ASN
    }
#endif /* HAVE_EXT_CAP_ASN */

  if ((! attr1->community && attr2->community)
      || (attr1->community && ! attr2->community))
    return PAL_FALSE;

  if (! community_cmp (attr1->community, attr2->community))
    return PAL_FALSE;

  return PAL_TRUE;
}

void
bgp_aggregate_increment (struct bgp *bgp,
                         struct prefix *p,
                         struct bgp_info *ri,
                         afi_t afi, safi_t safi)
{
  struct bgp_aggregate *aggregate;
  struct bgp_node *child;
  struct bgp_node *rn;
  u_int32_t baai;
  u_int32_t bsai;
  struct prefix rnp;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  if (p->prefixlen == 0)
    return;

  if (BGP_INFO_HOLDDOWN (ri))
    return;

  child = bgp_node_get (bgp->aggregate [baai][bsai], p);
  if (child == NULL)
    return;

  /* Aggregate address configuration check. */
  for (rn = child; rn; rn = rn->parent)
    {
      /* Extract prefix from node */
      pal_mem_set (&rnp, 0x00, sizeof (struct prefix));
      bgp_ptree_get_prefix_from_node (rn, &rnp);

      if ((aggregate = rn->info) != NULL
          && rnp.prefixlen < p->prefixlen)
        {
          bgp_aggregate_new_route (bgp, &rnp, p, ri, aggregate, afi, safi,
                                   PAL_FALSE);
          /* if the route is suppressed or became a consituent route
           *  for some aggregate node, break the loop. 
           */
          if (ri->riagg)
            break;
        }
    }

  bgp_unlock_node (child);
}

void
bgp_aggregate_decrement (struct bgp *bgp,
                         struct prefix *p,
                         struct bgp_info *del,
                         afi_t afi, safi_t safi)
{
  struct bgp_aggregate *aggregate;
  struct bgp_node *child;
  struct bgp_node *rn;
  u_int32_t baai;
  u_int32_t bsai;
  struct prefix rnp;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  if (p->prefixlen == 0)
    return;

  if (BGP_INFO_HOLDDOWN (del))
    return;

  child = bgp_node_get (bgp->aggregate [baai][bsai], p);
  if (child == NULL)
    return;

  /* Aggregate address configuration check. */
  for (rn = child; rn; rn = rn->parent)
    {
      /* Extract prefix from node */
      pal_mem_set (&rnp, 0x00, sizeof (struct prefix));
      bgp_ptree_get_prefix_from_node (rn, &rnp);

      if ((aggregate = rn->info) != NULL
          && (rnp.prefixlen < p->prefixlen)
          && (del->riagg == aggregate))
        {
           bgp_aggregate_del_route (bgp, &rnp, del, aggregate, afi, safi);
           /* if the constituent route is removed from the 
             aggregated node break.*/
          if (!del->riagg)
            break;
        }
    }


  bgp_unlock_node (child);

  return;
}

bool_t
bgp_check_config_change (struct bgp_aggregate *aggregate, u_int32_t aggr_type)
{
  bool_t config_change = PAL_FALSE;

   if (CHECK_FLAG (aggr_type, BGP_AGGREGATE_SUMMARY_ONLY) 
       && !aggregate->summary_only)
     config_change = PAL_TRUE;
  else if (CHECK_FLAG (aggr_type, BGP_AGGREGATE_AS_SET) 
           && !aggregate->as_set)
    config_change = PAL_TRUE;
  else if (!CHECK_FLAG (aggr_type, BGP_AGGREGATE_SUMMARY_ONLY)
            && aggregate->summary_only)
    config_change = PAL_TRUE;
  else if (!CHECK_FLAG (aggr_type, BGP_AGGREGATE_AS_SET) 
           && aggregate->as_set)
     config_change = PAL_TRUE;

  return config_change;
}

/* BGP aggregate set */
s_int32_t
bgp_aggregate_set (struct bgp *bgp,
                   u_int8_t *prefix_str,
                   afi_t afi, safi_t safi,
                   u_int32_t aggr_type)
{
  struct bgp_aggregate *aggregate;
  struct bgp_node *rn;
  struct prefix p;
  s_int32_t ret;
  bool_t config_change;
 
  pal_mem_set (&p, 0, sizeof (struct prefix));
  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  config_change = PAL_FALSE;

  if (! ret || ! bgp)
    return BGP_API_SET_ERR_MALFORMED_ARG;

  if (afi == AFI_IP)
    {
      /* IPv4 address cannot be Class E or Maritian */
      if (IN_EXPERIMENTAL (pal_ntoh32 (p.u.prefix4.s_addr))
          || IPV4_ADDR_MARTIAN (pal_ntoh32 (p.u.prefix4.s_addr)))
        return BGP_API_SET_ERR_INVALID_NETWORK;
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && afi == AFI_IP6)
    {
      /* IPv6 link-local address is not acceptable */
      if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
        return BGP_API_SET_ERR_INVALID_NETWORK;
    }
#endif /* HAVE_IPV6 */
  else
    return BGP_API_SET_ERROR;

  apply_mask (&p);

  /* Lookup existing aggregate configuration */
  rn = bgp_node_get (bgp->aggregate [BGP_AFI2BAAI (afi)]
                                    [BGP_SAFI2BSAI (safi)], &p);
  if (NULL == rn)
    return BGP_API_SET_ERROR;

  if (! (aggregate = rn->info))
    {
      /* Create a new aggregate structure */
      aggregate = XCALLOC (MTYPE_BGP_AGGREGATE,
                           sizeof (struct bgp_aggregate));

      if (! aggregate)
        {
          bgp_unlock_node (rn);

          return BGP_API_SET_ERROR;
        }

      rn->info = aggregate;

      /* set the back pointer to rn */ 
      aggregate->rnagg = rn;
    }
  else
    {
      bgp_unlock_node (rn);

      config_change = bgp_check_config_change (aggregate, aggr_type);
      /* if there is any change in the aggregation config
       * then preform de-aggregate with the previous config 
       */
      if (PAL_TRUE == config_change)
         bgp_aggregate_remove_aggregator (bgp, &p, aggregate, afi, safi);
      else
          return BGP_API_SET_ERR_OBJECT_ALREADY_EXIST;
    }

  aggregate->summary_only =
      CHECK_FLAG (aggr_type, BGP_AGGREGATE_SUMMARY_ONLY);
  aggregate->as_set =
      CHECK_FLAG (aggr_type, BGP_AGGREGATE_AS_SET);

  /* Aggregate address update in BGP routing table. */
   bgp_aggregate_process_new_aggregator (bgp, &p, aggregate, afi, safi);

  return BGP_API_SET_SUCCESS;
}

/* BGP aggregate unset */
s_int32_t
bgp_aggregate_unset (struct bgp *bgp,
                     u_int8_t *prefix_str,
                     afi_t afi, safi_t safi)
{
  struct bgp_aggregate *aggregate;
  struct bgp_node *rn;
  struct prefix p;
  s_int32_t ret;

  pal_mem_set (&p, 0, sizeof (struct prefix));
  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);

  if (! ret || ! bgp)
    return BGP_API_SET_ERR_MALFORMED_ARG;

  ret = BGP_API_SET_SUCCESS;

  if (afi == AFI_IP)
    {
      /* IPv4 address cannot be Class E or Maritian */
      if (IN_EXPERIMENTAL (pal_ntoh32 (p.u.prefix4.s_addr))
          || IPV4_ADDR_MARTIAN (pal_ntoh32 (p.u.prefix4.s_addr)))
        return BGP_API_SET_ERR_INVALID_NETWORK;
    }
#ifdef HAVE_IPV6
  else if (BGP_CAP_HAVE_IPV6 && afi == AFI_IP6)
    {
      /* IPv6 link-local address is not acceptable */
      if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
        return BGP_API_SET_ERR_INVALID_NETWORK;
    }
#endif /* HAVE_IPV6 */
  else
    return BGP_API_SET_ERROR;

  apply_mask (&p);

  /* Old configuration check. */
  rn = bgp_node_lookup (bgp->aggregate [BGP_AFI2BAAI (afi)]
                                       [BGP_SAFI2BSAI (safi)], &p);
  if (! rn)
    return BGP_API_SET_ERR_UNKNOWN_OBJECT;

  if ((aggregate = rn->info))
    {
      bgp_aggregate_remove_aggregator (bgp, &p, aggregate, afi, safi);
                                       
      /* Release the aggregate structure */
      aggregate->rnagg = NULL;
      rn->info = NULL;
      XFREE (MTYPE_BGP_AGGREGATE, aggregate);
      bgp_unlock_node (rn);
    }

  bgp_unlock_node (rn);

  return ret;
}

CLI (aggregate_address,
     aggregate_address_cmd,
     "aggregate-address A.B.C.D/M",
     "Configure BGP aggregate entries",
     "Aggregate prefix")
{
  s_int32_t ret;

  ret = bgp_aggregate_addr_set (cli->index, argv[0],
                                AFI_IP, SAFI_UNICAST, 0);
  return bgp_cli_return (cli, ret);
}

CLI (aggregate_address_summary_only,
     aggregate_address_summary_only_cmd,
     "aggregate-address A.B.C.D/M summary-only",
     "Configure BGP aggregate entries",
     "Aggregate prefix",
     "Filter more specific routes from updates")
{
  u_int32_t aggr_type;
  s_int32_t ret;

  aggr_type = 0;
  SET_FLAG (aggr_type, BGP_AGGREGATE_SUMMARY_ONLY);

  ret =  bgp_aggregate_addr_set (cli->index, argv[0],
                                 AFI_IP, SAFI_UNICAST, aggr_type);
  return bgp_cli_return (cli, ret);
}

CLI (aggregate_address_as_set,
     aggregate_address_as_set_cmd,
     "aggregate-address A.B.C.D/M as-set",
     "Configure BGP aggregate entries",
     "Aggregate prefix",
     "Generate AS set path information")
{
  u_int32_t aggr_type;
  s_int32_t ret;

  aggr_type = 0;
  SET_FLAG (aggr_type, BGP_AGGREGATE_AS_SET);

  ret = bgp_aggregate_addr_set (cli->index, argv[0],
                                AFI_IP, SAFI_UNICAST, aggr_type);
  return bgp_cli_return (cli, ret);
}

CLI (aggregate_address_as_set_summary,
     aggregate_address_as_set_summary_cmd,
     "aggregate-address A.B.C.D/M as-set summary-only",
     "Configure BGP aggregate entries",
     "Aggregate prefix",
     "Generate AS set path information",
     "Filter more specific routes from updates")
{
  u_int32_t aggr_type;
  s_int32_t ret;

  aggr_type = 0;
  SET_FLAG (aggr_type, BGP_AGGREGATE_SUMMARY_ONLY);
  SET_FLAG (aggr_type, BGP_AGGREGATE_AS_SET);

  ret = bgp_aggregate_addr_set (cli->index, argv[0],
                                AFI_IP, SAFI_UNICAST, aggr_type);
  return bgp_cli_return (cli, ret);
}

ALI (aggregate_address_as_set_summary,
     aggregate_address_summary_as_set_cmd,
     "aggregate-address A.B.C.D/M summary-only as-set",
     "Configure BGP aggregate entries",
     "Aggregate prefix",
     "Filter more specific routes from updates",
     "Generate AS set path information");

CLI (no_aggregate_address,
     no_aggregate_address_cmd,
     "no aggregate-address A.B.C.D/M",
     CLI_NO_STR,
     "Configure BGP aggregate entries",
     "Aggregate prefix")
{
  s_int32_t ret;
  ret =  bgp_aggregate_addr_unset (cli->index, argv[0], AFI_IP, SAFI_UNICAST);

  return bgp_cli_return (cli, ret);
}

CLI (no_aggregate_address_summary_only,
     no_aggregate_address_summary_only_cmd,
     "no aggregate-address A.B.C.D/M summary-only",
     CLI_NO_STR,
     "Configure BGP aggregate entries",
     "Aggregate prefix",
     "Filter more specific routes from updates")
{
  s_int32_t ret;
  ret = bgp_aggregate_addr_unset (cli->index, argv[0], AFI_IP, SAFI_UNICAST);

  return bgp_cli_return (cli, ret);
}

CLI (no_aggregate_address_as_set,
     no_aggregate_address_as_set_cmd,
     "no aggregate-address A.B.C.D/M as-set",
     CLI_NO_STR,
     "Configure BGP aggregate entries",
     "Aggregate prefix",
     "Generate AS set path information")
{
  s_int32_t ret;
  ret = bgp_aggregate_addr_unset (cli->index, argv[0], AFI_IP, SAFI_UNICAST);

  return bgp_cli_return (cli, ret);
}

CLI (no_aggregate_address_as_set_summary,
     no_aggregate_address_as_set_summary_cmd,
     "no aggregate-address A.B.C.D/M as-set summary-only",
     CLI_NO_STR,
     "Configure BGP aggregate entries",
     "Aggregate prefix",
     "Generate AS set path information",
     "Filter more specific routes from updates")
{
  s_int32_t ret;
  ret = bgp_aggregate_addr_unset (cli->index, argv[0], AFI_IP, SAFI_UNICAST);

  return bgp_cli_return (cli, ret);
}

ALI (no_aggregate_address_as_set_summary,
     no_aggregate_address_summary_as_set_cmd,
     "no aggregate-address A.B.C.D/M summary-only as-set",
     CLI_NO_STR,
     "Configure BGP aggregate entries",
     "Aggregate prefix",
     "Filter more specific routes from updates",
     "Generate AS set path information");

#ifdef HAVE_IPV6
CLI (ipv6_aggregate_address,
     ipv6_aggregate_address_cmd,
     "aggregate-address X:X::X:X/M",
     "Configure BGP aggregate entries",
     "Aggregate IPv6 prefix")
{
  s_int32_t ret;

  ret = bgp_aggregate_addr_set (cli->index, argv[0],
                                AFI_IP6, SAFI_UNICAST, 0);
  return bgp_cli_return (cli, ret);
}

CLI (ipv6_aggregate_address_summary_only,
     ipv6_aggregate_address_summary_only_cmd,
     "aggregate-address X:X::X:X/M summary-only",
     "Configure BGP aggregate entries",
     "Aggregate IPv6 prefix",
     "Filter more specific routes from updates")
{
  u_int32_t aggr_type;
  s_int32_t ret;

  aggr_type = 0;
  SET_FLAG (aggr_type, BGP_AGGREGATE_SUMMARY_ONLY);

  ret = bgp_aggregate_addr_set (cli->index, argv[0],
                                AFI_IP6, SAFI_UNICAST, aggr_type);
  return bgp_cli_return (cli, ret);
}

CLI (ipv6_aggregate_address_as_set,
     ipv6_aggregate_address_as_set_cmd,
     "aggregate-address X:X::X:X/M as-set",
     "Configure BGP aggregate entries",
     "Aggregate IPv6 prefix",
     "Generate AS set path information")
{
  u_int32_t aggr_type;
  s_int32_t ret;

  aggr_type = 0;
  SET_FLAG (aggr_type, BGP_AGGREGATE_AS_SET);

  ret = bgp_aggregate_addr_set (cli->index, argv[0],
                                AFI_IP6, SAFI_UNICAST, aggr_type);
  return bgp_cli_return (cli, ret);
}

CLI (ipv6_aggregate_address_summary_as_set,
     ipv6_aggregate_address_summary_as_set_cmd,
     "aggregate-address X:X::X:X/M summary-only as-set",
     "Configure BGP aggregate entries",
     "Aggregate IPv6 prefix",
     "Filter more specific routes from updates",
     "Generate AS set path information")
{
  u_int32_t aggr_type;
  s_int32_t ret;

  aggr_type = 0;
  SET_FLAG (aggr_type, BGP_AGGREGATE_SUMMARY_ONLY);
  SET_FLAG (aggr_type, BGP_AGGREGATE_AS_SET);

  ret = bgp_aggregate_addr_set (cli->index, argv[0],
                                AFI_IP6, SAFI_UNICAST, aggr_type);
  return bgp_cli_return (cli, ret);
}

ALI (ipv6_aggregate_address_summary_as_set,
     ipv6_aggregate_address_as_set_summary_cmd,
     "aggregate-address X:X::X:X/M as-set summary-only",
     "Configure BGP aggregate entries",
     "Aggregate IPv6 prefix",
     "Generate AS set path information",
     "Filter more specific routes from updates");

CLI (no_ipv6_aggregate_address,
     no_ipv6_aggregate_address_cmd,
     "no aggregate-address X:X::X:X/M",
     CLI_NO_STR,
     "Configure BGP aggregate entries",
     "Aggregate IPv6 prefix")
{
  s_int32_t ret;
  ret = bgp_aggregate_addr_unset (cli->index, argv[0],
                                  AFI_IP6, SAFI_UNICAST);
  return bgp_cli_return (cli, ret);
}

ALI (no_ipv6_aggregate_address,
     no_ipv6_aggregate_address_summary_only_cmd,
     "no aggregate-address X:X::X:X/M summary-only",
     CLI_NO_STR,
     "Configure BGP aggregate entries",
     "Aggregate IPv6 prefix",
     "Filter more specific routes from updates");

ALI (no_ipv6_aggregate_address,
     no_ipv6_aggregate_address_as_set_cmd,
     "no aggregate-address X:X::X:X/M as-set",
     CLI_NO_STR,
     "Configure BGP aggregate entries",
     "Aggregate IPv6 prefix",
     "Generate AS set path information");

ALI (no_ipv6_aggregate_address,
     no_ipv6_aggregate_address_summary_as_set_cmd,
     "no aggregate-address X:X::X:X/M summary-only as-set",
     CLI_NO_STR,
     "Configure BGP aggregate entries",
     "Aggregate IPv6 prefix",
     "Filter more specific routes from updates",
     "Generate AS set path information");

ALI (no_ipv6_aggregate_address,
     no_ipv6_aggregate_address_as_set_summary_cmd,
     "no aggregate-address X:X::X:X/M as-set summary-only",
     CLI_NO_STR,
     "Configure BGP aggregate entries",
     "Aggregate IPv6 prefix",
     "Generate AS set path information",
     "Filter more specific routes from updates");

#endif /* HAVE_IPV6 */


/* Redistribute route treatment. */
s_int32_t
bgp_redistribute_add (struct bgp *bgp,
		      void* message,
		      u_int8_t route_type,
		      bool_t check)
{
  struct bgp_rmap_info brmi;
  struct bgp_info tmp_ri;
  struct bgp_info *new;
  struct attr attr_new;
  u_int8_t origin_type;
  struct bgp *bgp_mvrf;
  struct bgp_node *rn;
  struct attr attr;
  s_int32_t ret;
  afi_t afi;
  struct bgp_msg_route_ipv4 *msg4 = NULL;
#ifdef HAVE_IPV6
  struct bgp_msg_route_ipv6 *msg6 = NULL;
#endif
  struct prefix p;
  struct nexthop_addr nexthop;
  u_int32_t metric  = 0;
  u_int32_t type    = 0;
  u_int32_t tag     = 0;

  ret = 0;

  if (! bgp)
    {
      ret = -1;
      goto EXIT;
    }
  
  if (route_type == AF_INET)
    {
      msg4 = message;
      p.family = route_type;
      p.prefixlen = msg4->prefixlen;
      p.u.prefix4 = msg4->prefix;

      IPV4_ADDR_COPY (&nexthop.u.ipv4, &msg4->nexthop[0].addr);
      nexthop.afi = AFI_IP;

      metric = msg4->metric;
      type   = msg4->type;
      tag    = msg4->tag;
    }
#ifdef HAVE_IPV6
  else if (route_type == AF_INET6)
    {
      msg6 = message;
      p.family = route_type;
      p.prefixlen = msg6->prefixlen;
      p.u.prefix6 = msg6->prefix;

      IPV6_ADDR_COPY (&nexthop.u.ipv6, &msg6->nexthop[0].addr);
      nexthop.afi = AFI_IP6;

      metric = msg6->metric;
      type   = msg6->type;
      tag    = msg6->tag;
    }
#endif
  else
    {
      ret = -1;
      goto EXIT;
    }

  afi = family2afi (p.family);

  if (check && ! bgp->redist [BGP_AFI2BAAI (afi)][type])
    {
      ret = -1;
      goto EXIT;
    }

  /*
   * Determine the ORIGIN Type. Industry standard implementation
   * uses origin INCOMPLETE, but RFC1771 says it should be origin IGP.
   */
  origin_type = BGP_ORIGIN_INCOMPLETE;
  if (bgp_option_check (BGP_OPT_RFC1771_STRICT))
    {
      switch (type)
        {
          case IPI_ROUTE_SDN:
            origin_type = BGP_ORIGIN_IGP;
            break;

          default:
            origin_type = BGP_ORIGIN_INCOMPLETE;
            break;
        }
    }

  /* Setup Default Attribute */
  bgp_attr_default_set (&attr, origin_type);

  if (nexthop.afi == AFI_IP)
      IPV4_ADDR_COPY (&attr.nexthop, &nexthop.u.ipv4);
#ifdef HAVE_IPV6
  else 
      IPV6_ADDR_COPY (&attr.mp_nexthop_global, &nexthop.u.ipv6);
#endif
      SET_FLAG (attr.flag, ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP));

  if (metric)
    {
      attr.nsm_metric = attr.med = metric;
      SET_FLAG (attr.flag, ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC));
    }

  /* Copy attribute for modification */
  attr_new = attr;

  /* Apply route-map */
  ret = RMAP_MATCH;
  if (bgp->rmap [BGP_AFI2BAAI (afi)][type].name)
    {
      pal_mem_set (&tmp_ri, 0, sizeof (struct bgp_info));
      tmp_ri.peer = bgp->peer_self;
      tmp_ri.attr = &attr_new;

      if (tag)
        {
          tmp_ri.tag = tag;
        }

      pal_mem_set (&brmi, 0, sizeof (struct bgp_rmap_info));
      brmi.brmi_type = BGP_RMAP_INFO_REGULAR;
      brmi.brmi_bgp = bgp;
      brmi.brmi_bri = &tmp_ri;

      ret = route_map_apply (bgp->rmap [BGP_AFI2BAAI (afi)]
                                       [type].map,
                             &p, &brmi);
    }

  new = bgp_info_new ();
  new->type = type;
  new->peer = bgp->peer_self;
  new->attr = bgp_attr_intern (&attr_new);
  new->tag = tag;
  bgp_mvrf = bgp;

  if (ret == RMAP_DENYMATCH)
    UNSET_FLAG (new->flags, BGP_INFO_NHOP_VALID);
  else
    {
      SET_FLAG (new->flags, BGP_INFO_NHOP_VALID);
      new->bri_uptime = pal_time_sys_current (NULL);
    }

  rn = bgp_afi_node_get (bgp, afi, SAFI_UNICAST, &p, NULL);
  bgp_aggregate_increment (bgp, &p, new, afi, SAFI_UNICAST);
  if(!rn)
    {
      ret = -1;
      goto EXIT;
    }
  bgp_info_add (rn, new);
  bgp_process (bgp_mvrf, rn, afi, SAFI_UNICAST, NULL);
  aspath_unintern (attr.aspath);
#ifdef HAVE_EXT_CAP_ASN
  aspath4B_unintern (attr.aspath4B);
  as4path_unintern (attr.as4path);
#endif /* HAVE_EXT_CAP_ASN */
EXIT:

  return ret;
}

s_int32_t
bgp_redistribute_delete (struct bgp *bgp,
                         struct prefix *p,
                         u_int32_t type,
			 bool_t check)
{
  struct bgp *bgp_mvrf;
  struct bgp_node *rn;
  struct bgp_info *ri;
  s_int32_t ret;
  afi_t afi;

  ret = 0;

  if (! bgp || ! p)
    {
      ret = -1;
      goto EXIT;
    }

  bgp_mvrf = bgp;

  afi = family2afi (p->family);

  if (check && ! bgp->redist [BGP_AFI2BAAI (afi)][type])
    {
      ret = -1;
      goto EXIT;
    }

  rn = bgp_afi_node_get (bgp, afi, SAFI_UNICAST, p, NULL);
  if (!rn)
    {
      ret = -1;
      goto EXIT;
    }

  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
        && ri->type == type)
       break;

  if (ri)
    {
      bgp_aggregate_decrement (bgp, p, ri, afi, SAFI_UNICAST);
      bgp_info_delete (rn, ri);
      bgp_process (bgp_mvrf, rn, afi, SAFI_UNICAST, ri);
      bgp_info_free (ri);
      bgp_unlock_node (rn);
    }
  bgp_unlock_node (rn);

EXIT:

  return ret;
}

/* Withdraw Redistributed Route of specified Type */
void
bgp_redistribute_withdraw (struct bgp *bgp,
                           afi_t afi, u_int32_t type)
{
  struct bgp_ptree *table;
  struct bgp *bgp_mvrf;
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct prefix rnp;

  bgp_mvrf = bgp;

  table = bgp->rib [BGP_AFI2BAAI (afi)][BSAI_UNICAST];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->next)
        if (ri->peer == bgp->peer_self
         && ri->type == type)
          break;

      if (ri)
        {
	  BGP_GET_PREFIX_FROM_NODE (rn);
          bgp_aggregate_decrement (bgp, &rnp, ri,
                                   afi, SAFI_UNICAST);
          bgp_info_delete (rn, ri);
          bgp_process (bgp_mvrf, rn, afi, SAFI_UNICAST, ri);
          bgp_info_free (ri);
          bgp_unlock_node (rn);
        }
    }

  return;
}

struct bgp_distance *
bgp_distance_new (void)
{
  return (struct bgp_distance *) XCALLOC (MTYPE_BGP_DISTANCE,
                                 sizeof (struct bgp_distance));
}

void
bgp_distance_free (struct bgp_distance *bdistance)
{
  XFREE (MTYPE_BGP_DISTANCE, bdistance);
}

/* Reset BGP distance table */
s_int32_t
bgp_distance_reset (struct bgp *bgp)
{
  struct bgp_distance *bdistance;
  struct bgp_node *rn;
  s_int32_t ret;

  ret = 0;

  if (! bgp || ! bgp->distance_table)
    {
      ret = -1;
      goto EXIT;
    }

  for (rn = bgp_table_top (bgp->distance_table);
       rn; rn = bgp_route_next (rn))
    if ((bdistance = rn->info) != NULL)
      {
        if (bdistance->access_list)
          XFREE (MTYPE_TMP, bdistance->access_list);
        bgp_distance_free (bdistance);
        rn->info = NULL;
        bgp_unlock_node (rn);
      }

EXIT:

  return ret;
}

/* Calculate BGP route-distance value */
s_int32_t
bgp_distance_apply (struct bgp_peer *peer,
                    struct prefix *p,
                    struct attr *attr,
                    afi_t afi, safi_t safi)
{
  struct bgp_distance *bdistance;
  enum bgp_peer_type peer_type;
  struct bgp_static *bstatic;
  struct access_list *alist;
  struct prefix_ipv4 q;
  struct bgp_node *rn;
  u_int32_t baai = 0;
  u_int32_t bsai = 0;
  s_int32_t ret = 0;

  ret = 0;

  if (! peer || ! p || ! attr)
    {
      ret = -1;
      goto EXIT;
    }

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);
  peer_type = peer_sort (peer);

  switch (peer_type)
    {
    case BGP_PEER_INTERNAL:
      attr->distance = IPI_DISTANCE_IBGP;
      break;

    case BGP_PEER_IBGP:
    case BGP_PEER_CONFED:
      /* If any internal distance is configured for that particular AFI/SAFi 
       * use it, else if any distance is configured in router-mode assign it 
       * else, assign the default distance 
       */
      if (peer->bgp->distance_ibgp[baai][bsai])
        attr->distance = peer->bgp->distance_ibgp[baai][bsai];
      else if (peer->bgp->distance_ibgp[BAAI_IP][BSAI_UNICAST])
        attr->distance = peer->bgp->distance_ibgp[BAAI_IP][BSAI_UNICAST];
      else
        attr->distance = IPI_DISTANCE_IBGP;
      break;

    case BGP_PEER_EBGP:
      /* If any external distance is configured for that particular AFI/SAFi 
       * use it, else if any distance is configured in router-mode assign it 
       * else, assign the default distance.
       */
      if (peer->bgp->distance_ebgp[baai][bsai])
        attr->distance = peer->bgp->distance_ebgp[baai][bsai];
      else if (peer->bgp->distance_ebgp[BAAI_IP][BSAI_UNICAST])
        attr->distance = peer->bgp->distance_ebgp[BAAI_IP][BSAI_UNICAST];
      else
        attr->distance = IPI_DISTANCE_EBGP;
      break;
    }

  /* Handling Backdoor configuration */
  rn = bgp_node_lookup (peer->bgp->route [baai][bsai], p);
  if (rn)
    {
      bstatic = rn->info;
      bgp_unlock_node (rn);

      if (bstatic->bs_backdoor)
        attr->distance = IPI_DISTANCE_IBGP;      
    }

  if (peer->su.sa.sa_family == AF_INET)
    {
      pal_mem_set (&q, 0, sizeof (struct prefix_ipv4));
      q.family = AF_INET;
      q.prefix = peer->su.sin.sin_addr;
      q.prefixlen = IPV4_MAX_BITLEN;

      /* Check source address */
      rn = bgp_node_match (peer->bgp->distance_table,
                           (struct prefix *) &q);
      if (rn)
        {
          bdistance = rn->info;
          bgp_unlock_node (rn);

          if (bdistance->access_list)
            {
              alist = access_list_lookup (BGP_VR.owning_ivr, AFI_IP,
                                          bdistance->access_list);
              if (alist
                  && access_list_apply (alist, p) == FILTER_PERMIT)
                attr->distance = bdistance->distance;
            }
          else
            attr->distance = bdistance->distance;
        }
    }

EXIT:

  return ret;
}

/*
 * Match bestpath attribute for multipath check.
 * This step is required after the final-step bestpath algorithm
 * in order to make sure that multipathed routes' attributes match with
 * the bestpath's. Note: it will weed out some multipaths which were chosen
 * before the new-bestpath as a set of multipaths are chosen.
 */
u_int8_t
bgp_match_attr_bestpath(struct bgp *bgp, struct bgp_info *bestpath, struct bgp_info *ri)
{
  s_int32_t internal_as_route = 0;

  if (bestpath->attr->weight != ri->attr->weight)
    return 0;
  if (bestpath->attr->local_pref != ri->attr->local_pref)
    return 0;
  if (bestpath->attr->aspath && ri->attr->aspath)
    {
        internal_as_route = (bestpath->attr->aspath->length == 0
                       && ri->attr->aspath->length == 0);
      if (bestpath->attr->aspath->count != ri->attr->aspath->count)
	return 0;
    }
  
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      if (bestpath->attr->aspath4B && ri->attr->aspath4B)
        {
            internal_as_route = (bestpath->attr->aspath4B->length == 0
                       && ri->attr->aspath4B->length == 0);
          if (bestpath->attr->aspath4B->count != ri->attr->aspath4B->count)
            return 0;
        }
    }
  if (bestpath->attr->origin != ri->attr->origin)
    return 0;

  if (bestpath->attr->med != ri->attr->med)
    return 0;

  
  if (! bgp_config_check (bgp, BGP_CFLAG_ASPATH_IGNORE))
    {
      if (!internal_as_route && bestpath->attr->aspath && ri->attr->aspath )
        {
          if (!aspath_cmp (bestpath->attr->aspath, ri->attr->aspath))
            return 0;
        }
    }

  if (bestpath->igpmetric != ri->igpmetric)
    return 0;

  return 1;
}

/*
 * Function name: bgp_mpath_to_install() - input: rnode, bgp structure, selected bgp_info
 * and currently installed multipath counts for ibgp and ebgp
 * It counts number of mpaths installed for this route. If the installed
 * multipath number is different than what is specified in configuration
 * and if re-install is required and the function returns 1.
 * It is used by bgp_process to find out if multipath install is necessary
 * when BGP bestpath selected route stays the same.
 * This function is also used for newly selected routes to make sure that the selected route
 * type matches with the multipath type.
 * If no mpath is instlled or no change in number then it returns 0
 */
u_int8_t
bgp_mpath_to_install(struct bgp_node *rnode, struct bgp *bgp, struct bgp_info *selected,
   u_int8_t inst_ibgp, u_int8_t inst_ebgp)
{
  u_int8_t mp_installed_ibgp;
  u_int8_t mp_installed_ebgp;
  u_int8_t mp_candidate_ibgp;
  u_int8_t mp_candidate_ebgp;
  u_int8_t selected_mpath;
  struct bgp_info *ri;

  mp_installed_ibgp = 0;
  mp_installed_ebgp = 0;
  mp_candidate_ibgp = 0;
  mp_candidate_ebgp = 0;
  selected_mpath = 0;

  if (rnode == NULL || bgp == NULL)
    return 0;
  
  if (bgp->maxpath_ebgp == 1 && bgp->maxpath_ibgp == 1)
    return 0;
  if (!selected)
    return 0;

  /* Selected path must be also MULTIPATHed - otherwise turn off MPATH flags */
  if (CHECK_FLAG(selected->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE))
    selected_mpath = 1;

  /* Unset multipath if selected  best path characteristics do not match*/
  for (ri = rnode->info; ri != NULL; ri = ri->next)
     {
	if (!CHECK_FLAG(ri->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE))
	  continue;

	if (!selected_mpath || peer_sort(ri->peer) != peer_sort(selected->peer) ||
	     !bgp_match_attr_bestpath(bgp, selected, ri))
	  {
	     UNSET_FLAG(ri->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE); 
	     UNSET_FLAG(ri->flags_misc, BGP_INFO_MULTI_INSTALLED); 
	  }
     }
  /*
   * If the selected path is not a MPATH candidate
   * no other paths can be multipath candidate, hence
   * no multipath to install. But we return 1 to make
   * sure any change in multi-installed paths
   */
  if (!selected_mpath)
    return 1;

  for (ri = rnode->info; ri != NULL; ri = ri->next)
    {
	if (!CHECK_FLAG(ri->flags_misc, BGP_INFO_ECMP_MULTI_CANDIDATE))
	  {
	     if (CHECK_FLAG(ri->flags_misc, BGP_INFO_MULTI_INSTALLED))
	        UNSET_FLAG(ri->flags_misc, BGP_INFO_MULTI_INSTALLED); 
             continue;
	  }

 	if (!CHECK_FLAG(ri->flags, BGP_INFO_NHOP_VALID))
                continue;

	if (peer_sort(ri->peer) == BGP_PEER_EBGP)
	  mp_candidate_ebgp++;
	else if (peer_sort(ri->peer) == BGP_PEER_IBGP)
	  mp_candidate_ibgp++;

	if (CHECK_FLAG(ri->flags_misc, BGP_INFO_MULTI_INSTALLED))
	  {
	     if (peer_sort(ri->peer) == BGP_PEER_EBGP)
	       mp_installed_ebgp++;
	     else if (peer_sort(ri->peer) == BGP_PEER_IBGP)
	       mp_installed_ibgp++;
	  }
    }

    /*  XXXX - Debug */
   if (BGP_DEBUG (normal, NORMAL)) {
       zlog_info (&BLG, "%s-%s [RIB] mpath_to_install:  ebgp_installed %d ebgp_candidate %d "
                   " ibgp installed %d ibgp candidate %d ",
                   selected->peer->host, BGP_PEER_DIR_STR (selected->peer), mp_installed_ebgp,
		   mp_candidate_ebgp, mp_installed_ibgp, mp_candidate_ibgp);
   }

  /*
   * Logic: if installed bgp(inst_bgp)  count is not the same with mp_installed_bgp
   * it means that some change of installed flag has been done recently.
   * Thus we always return 1 when these two don't match.
   * If they are the same then return 1 in the three cases:
   * 1.  No mpath installed currently and maxpath is confgired [ first time ]
   * 2.  The installed mpath is larger than configured maxpath. It means recently
   *     maxpath has been configured to a lower value
   * 3.  mpath_installed is less than configured bgp maxpath and multipath_candidate
   *     is higher than installed multipath(mpath_installed).
   *
   * NOTE: bgp_maxpath_ebgp could be higher or less than mp_installed_ebgp as one
   *       can change the configuration variable dynamically 
   */
  if (mp_candidate_ebgp && (mp_installed_ebgp != bgp->maxpath_ebgp))
    {
       if (mp_installed_ebgp == inst_ebgp)
	 {
	    /* First time MULTIPATH is turned ON */
 	    if ((bgp->maxpath_ebgp > 1) && (inst_ebgp == 0))
		return 1;
	    if (mp_installed_ebgp > bgp->maxpath_ebgp)
		return 1;
	    else if (mp_installed_ebgp < bgp->maxpath_ebgp)
		if (mp_candidate_ebgp > mp_installed_ebgp)
		  return 1;
	 }
       else
         return 1;
    }
  else if (mp_candidate_ibgp && (mp_installed_ibgp != bgp->maxpath_ibgp))
    {
       if (mp_installed_ibgp == inst_ibgp)
         {
	    /* First time MULTIPATH is turned ON */
 	    if ((bgp->maxpath_ibgp > 1) && (inst_ibgp == 0))
	        return 1;
            if (mp_installed_ibgp > bgp->maxpath_ibgp)
                return 1;
            else if (mp_installed_ibgp < bgp->maxpath_ibgp)
                if (mp_candidate_ibgp > mp_installed_ibgp)
                  return 1;
         }
       else
         return 1;
    }
  
  return 0;
  
}

/***********************************************************************
 * Function Name : bgp_update_aggregate_origin                         *
 *                                                                     *
 * Input parameter                                                     *
 *  bgp : bgp instance                                                 *
 *  aggr_p   : aggregated prefix                                       *
 *  aggregate : aggregate information                                  *
 *  afi  : address family (ipv4 or ipv6)                               *
 *  safi : sub-address family (unicast, multicast....)                 *
 *                                                                     *
 *                                                                     *
 *  Description : This function re calculates the attribute of the     *
 *                the aggregate route and compare its with  old attr   *
 *                if there is any change in the attribute then it      *
 *                uninterns the old attr and returns new attr.         *
 *                                                                     *
 ***********************************************************************/

static void
bgp_update_aggregate_origin (struct bgp *bgp, struct prefix *aggr_p,
                             struct bgp_aggregate *aggregate, afi_t afi,
                             safi_t safi) 
{
  struct attr *old_attr;
  struct attr *new_attr;
  struct bgp *bgp_mvrf;
  struct bgp_ptree *table;
  struct bgp_node *rnagg;
  struct bgp_node *rn;
  struct bgp_info *riagg;
  struct bgp_info *ri;
  struct community *community = NULL;
  struct aspath *aspath = NULL;
#ifdef HAVE_EXT_CAP_ASN
  struct as4path *as4path = NULL;
  struct as4path *aspath4B = NULL;
#endif /* HAVE_EXT_CAP_ASN */
  
  u_int32_t baai;
  u_int32_t bsai;
  u_int8_t origin;
  bool_t atomic_set = PAL_FALSE;

  /* intialization */
  old_attr = NULL;
  new_attr = NULL;
  rnagg = NULL;
  table = NULL;
  riagg = NULL;
  rn = NULL;
  ri = NULL;
  origin = BGP_ORIGIN_IGP;

  baai = BGP_AFI2BAAI (afi);
  bsai = BGP_SAFI2BSAI (safi);
  bgp_mvrf = bgp;

  table = bgp->rib [baai][bsai];
  rnagg = bgp_node_get (table, aggr_p);

  if (! rnagg)
    return ;


 /* Find the aggregate route for prefix p */
  for (riagg = rnagg->info; riagg; riagg = riagg->next)
    if (riagg->peer == bgp->peer_self
        && riagg->type == IPI_ROUTE_BGP
        && riagg->sub_type == BGP_ROUTE_AGGREGATE)
      {
        old_attr = riagg->attr;
        break;
      }

   if (!old_attr)
     return;

  for (rn = bgp_node_get (table, aggr_p); rn;
       rn = bgp_route_next_until (rn, rnagg))
   for (ri = rn->info; ri; ri = ri->next)
      {
        if (ri->riagg != aggregate)
          continue;

       if (origin < ri->attr->origin)
          origin = ri->attr->origin;
        /* If at least one of the routes to be aggregated has ATOMIC_AGGREGATE
          path attribute, then the aggregated route SHALL have this attribute
          as well. 
        */
        if ((!atomic_set) && (ri->attr->flag & 
                                 ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)))
          atomic_set = PAL_TRUE;
     }

  if (aggregate->origin == origin)
    return;

  if (old_attr->aspath)
    aspath = aspath_dup (old_attr->aspath);
  if (old_attr->community)
    community = community_dup (old_attr->community);
 
#ifdef HAVE_EXT_CAP_ASN
  if (old_attr->aspath4B)
    aspath4B = as4path_dup (old_attr->aspath4B);
  if (old_attr->as4path)
    as4path =  as4path_dup (old_attr->as4path);

   if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
     new_attr = bgp_attr_aggregate_4b_intern (bgp, origin,
                                              aspath, aspath4B,
                                              as4path, community,
                                              aggregate->as_set,
                                              old_attr->distance,
                                              atomic_set);
    /* local speaker is OBGP */
  else
#endif /* HAVE_EXT_CAP_ASN */
  new_attr = bgp_attr_aggregate_intern (bgp, origin, 
                                        aspath, community,
                                        aggregate->as_set,
                                        old_attr->distance,  
                                        atomic_set);
  /* compare the new attribute against the old attr if there any changed
   * then unintern the old attr and return the new attr.
   */
  if (! bgp_aggregate_attr_same (new_attr, old_attr))
    {
       bgp_attr_unintern (old_attr);

        riagg->attr = new_attr;
        SET_FLAG (riagg->flags, BGP_INFO_ATTR_CHANGED);
        bgp_process (bgp_mvrf, rnagg, afi, safi, NULL);
        aggregate->origin = origin;
  } 
 else 
   bgp_attr_unintern (new_attr);

}


/***********************************************************************
 * Function Name : bgp_update_aggregate_attr                           *
 *                                                                     *
 * Input parameter                                                     *
 *  bgp : bgp instance                                                 *
 *  aggr_p   : aggregated prefix                                       *
 *  aggregate : aggregate information                                  *
 *  afi  : address family (ipv4 or ipv6)                               *
 *  safi : sub-address family (unicast, multicast....)                 *
 *                                                                     *
 *  Output                                                             *
 *  attr  - return old_attr if there no change, else return new attr   *
 *                                                                     *
 *  Description : This function re calculates the attribute of the     *
 *                the aggregate route and compare its with  old attr   *
 *                if there is any change in the attribute then it      *
 *                uninterns the old attr and returns new attr.         *
 *                                                                     *
 *                This function should be called only when the as-set  *
 *                is enabled.                                          *
 ***********************************************************************/

struct attr *
bgp_update_aggregate_attr (struct bgp *bgp, struct bgp_aggregate *aggregate,
                           struct prefix * aggr_p, afi_t afi, safi_t safi)
{
  u_int8_t asset_type;
  struct aspath * aspath;
  struct community *community;
  struct aspath *asmerge;
  struct community *commerge;
  struct bgp_node *rnagg;
  struct bgp_node *rn;
  struct bgp_info *riagg;
  struct bgp_info *ri;
  struct attr *old_attr;
  struct attr *new_attr;
  struct bgp *bgp_mvrf;
  struct bgp_ptree *table;
  u_int32_t baai;
  u_int32_t bsai;
  u_int8_t origin;
  u_int32_t distance;
  bool_t atomic_set = PAL_FALSE;
#ifdef HAVE_EXT_CAP_ASN
  struct as4path *aspath4B;
  struct as4path *as_4b_merge;
  struct as4path *as4path;
  struct as4path *as4_merge;
#endif /* HAVE_EXT_CAP_ASN */
  /* intialize the variables */
  aspath = NULL;
  community = NULL;
  asmerge = NULL;
  commerge = NULL;
  riagg = NULL;
  old_attr = NULL;
  new_attr = NULL;
  distance = 0;
#ifdef HAVE_EXT_CAP_ASN
  aspath4B = NULL;
  as_4b_merge = NULL;
  as4path = NULL;
  as4_merge = NULL;
#endif /* HAVE_EXT_CAP_ASN */


  /* no further processing if the as-set is not enabled */
  if (!aggregate->as_set)
    return NULL;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  origin = BGP_ORIGIN_IGP;

  /* If any local distance is configured for that particular AFI/SAFI 
  * use it, else if distance is configured in router-mode assign it 
  * else, assign the default distance.
  */
  if (bgp->distance_local[baai][bsai])
    distance = bgp->distance_local[baai][bsai];
  else if (bgp->distance_local[BAAI_IP][BSAI_UNICAST])
    distance = bgp->distance_local[BAAI_IP][BSAI_UNICAST];
  else
    distance = IPI_DISTANCE_IBGP;



  bgp_mvrf = bgp;

  table = bgp->rib [baai][bsai];
  rnagg = bgp_node_get (table, aggr_p);

  if (! rnagg)
    return NULL;


 /* Find the aggregate route for prefix p */
  for (riagg = rnagg->info; riagg; riagg = riagg->next)
    if (riagg->peer == bgp->peer_self
        && riagg->type == IPI_ROUTE_BGP
        && riagg->sub_type == BGP_ROUTE_AGGREGATE)
      {
        old_attr = riagg->attr;
        break;
      }
#ifdef HAVE_EXT_CAP_ASN
            /* Check Local Speaker is NBGP */
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    {
      for (rn = bgp_node_get (table, aggr_p); rn;
           rn = bgp_route_next_until (rn, rnagg))
        for (ri = rn->info; ri; ri = ri->next)
         {
            if (ri->riagg != aggregate)
            continue;
   
            /* update the origin */
            if (origin < ri->attr->origin)
              origin = ri->attr->origin;

            if (! aspath4B)
              aspath4B = as4path_new ();
             if (! aspath)
               aspath = aspath_new ();
             if (! as4path)
               as4path = as4path_new ();

             if (aspath4B && ri->attr->aspath4B)
               {
                 if (peer_sort (ri->peer) == BGP_PEER_CONFED)
                   asset_type = BGP_AS_CONFED_SET;
                 else
                   asset_type = BGP_AS_SET;

                 as_4b_merge = as4path_aggregate (aspath4B,
                                                  ri->attr->aspath4B,
                                                  asset_type);
                 as4path_free (aspath4B);
                 aspath4B = as_4b_merge;
              }

             if (aspath && ri->attr->aspath)
               {
                 if (peer_sort (ri->peer) == BGP_PEER_CONFED)
                   asset_type = BGP_AS_CONFED_SET;
                 else
                   asset_type = BGP_AS_SET;

                 asmerge = aspath_aggregate (aspath,
                                             ri->attr->aspath,
                                             asset_type);
                 aspath_free (aspath);
                 aspath = asmerge;
              }

          if (as4path && ri->attr->as4path)
            {
              /* RFC4893 does not allow AS_CONFED_SET or
               * AS_CONFED_SEQ in AS4_PATH.
               */
               asset_type = BGP_AS_SET;
               as4_merge = as4path_aggregate (as4path,
                                              ri->attr->as4path,
                                              asset_type);
               as4path_free (as4path);
               as4path = as4_merge;
            }

         if (ri->attr->community)
           {
             if (community)
               {
                 commerge = community_merge (community,
                                             ri->attr->community);
                 community = community_uniq_sort (commerge);
                 community_free (commerge);
               }
             else
               {
                 community = community_dup (ri->attr->community);
               }
           }
          /* If at least one of the routes to be aggregated has 
             ATOMIC_AGGREGATE path attribute, then the aggregated 
             route SHALL have this attribute as well */
          if((!atomic_set) && (ri->attr->flag &
                         ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)))
            atomic_set = PAL_TRUE;
       }
       
   }           
/* Local Speaker is OBGP */
  else
    {
#endif /* HAVE_EXT_CAP_ASN */
  
  /* recreate the aspath and community */
    for (rn = bgp_node_get (table, aggr_p); rn;
         rn = bgp_route_next_until (rn, rnagg))
       for (ri = rn->info; ri; ri = ri->next)
       {
         if (ri->riagg != aggregate)
           continue; 

         /* update the origin */
         if (origin < ri->attr->origin)
           origin = ri->attr->origin;
       
         if (ri->attr->aspath)
           {
             if (! aspath)
               aspath = aspath_new ();

             if (aspath)
               {
                 if (peer_sort (ri->peer) == BGP_PEER_CONFED)
                   asset_type = BGP_AS_CONFED_SET;
                 else
                   asset_type = BGP_AS_SET;

                 asmerge = aspath_aggregate (aspath,
                                             ri->attr->aspath,
                                             asset_type);
                 aspath_free (aspath);
                 aspath = asmerge;
               }
           }

         if (ri->attr->community)
           {
             if (community)
               {
                 commerge = community_merge (community,
                                             ri->attr->community);
                 community = community_uniq_sort (commerge);
                 community_free (commerge);
               }
             else
               {
                 community = community_dup (ri->attr->community);
               }
           }
          /* If at least one of the routes to be aggregated has 
             ATOMIC_AGGREGATE path attribute, then the aggregated 
             route SHALL have this attribute as well */
          if((!atomic_set) && (ri->attr->flag &
                         ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)))
            atomic_set = PAL_TRUE;
     }
#ifdef HAVE_EXT_CAP_ASN
  }
#endif /*HAVE_EXT_CAP_ASN*/
  /* create the new attribute */
#ifdef HAVE_EXT_CAP_ASN
   if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
     new_attr = bgp_attr_aggregate_4b_intern (bgp, origin,
                                              aspath, aspath4B,
                                              as4path, community,
                                              aggregate->as_set,
                                              distance, atomic_set);
    /* local speaker is OBGP */
  else
#endif /* HAVE_EXT_CAP_ASN */
  new_attr = bgp_attr_aggregate_intern (bgp, origin, aspath, community,
                                        aggregate->as_set,
                                        distance,
                                        atomic_set);

  /* if there is no attribute earlier then return new attr. 
   * old_attr will be NULL for the  new aggregator.
   */
  if (!old_attr)
    return new_attr;
  else
    {
      /* compare the new attribute against the old attr if there any changed
       * then unintern the old attr and return the new attr.
       */
       if (! bgp_aggregate_attr_same (new_attr, old_attr))
         {
            bgp_attr_unintern (old_attr);
             
            riagg->attr = new_attr;
            SET_FLAG (riagg->flags, BGP_INFO_ATTR_CHANGED);
            bgp_process (bgp_mvrf, rnagg, afi, safi, NULL);
          
            return new_attr;
         } 
      /* if there is no change then unintern the new_attr to avoid any
       * un wanted reference count of aspath and community hash table
       */
       else
          bgp_attr_unintern (new_attr);
    }
 
  return old_attr;
}

/***********************************************************************
 * Function Name : bgp_aggregate_info_new                              *
 *                                                                     *
 * Input parameter                                                     *
 *  bgp       : bgp instance                                           *
 *  aggr_p    : aggregated prefix                                      *
 *  aggregate : aggregate information                                  *
 *  rnagg     : aggregate node in afi and safi                         *
 *  afi  : address family (ipv4 or ipv6)                               *
 *  safi : sub-address family (unicast, multicast....)                 *
 *                                                                     *
 *  Output                                                             *
 *  info  - returns info (riagg) after adding it to rnagg              *
 *                                                                     *
 *Description : This function creates info for the aggregate route     * 
 *              and also addeds the same to rnagg. If as-set is        *
 *              enabled then attr for the new infor will be set        *
 *              based on the return value of                           * 
 *              bgp_update_aggregate_attr ().                          *
 ***********************************************************************/
static struct bgp_info *
bgp_aggregate_info_new (struct bgp * bgp, struct bgp_aggregate *aggregate,
                        struct prefix *aggr_p, struct bgp_node *rnagg,
                        afi_t afi, safi_t safi, u_int8_t origin)
{
  struct bgp_info * new;
  u_int32_t baai;
  u_int32_t bsai;
  u_int32_t distance;
  
  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  distance = 0;

  new = bgp_info_new ();
  if (!new)
    return NULL;

 /* If any local distance is configured for that particular AFI/SAFI
  * use it, else if distance is configured in router-mode assign it
  * else, assign the default distance.
  */
  if (bgp->distance_local[baai][bsai])
    distance = bgp->distance_local[baai][bsai];
  else if (bgp->distance_local[BAAI_IP][BSAI_UNICAST])
    distance = bgp->distance_local[BAAI_IP][BSAI_UNICAST];
  else
    distance = IPI_DISTANCE_IBGP;



  new->type = IPI_ROUTE_BGP;
  new->sub_type = BGP_ROUTE_AGGREGATE;
  new->peer = bgp->peer_self;
  SET_FLAG (new->flags, BGP_INFO_NHOP_VALID);
  new->bri_uptime = pal_time_sys_current (NULL);

  /* add the info to the rnagg */
  bgp_info_add (rnagg, new);
   
  /* origin information */
  aggregate->origin = origin;

  /* if as-set enabled create attr based on the aggregated routes */
  if (aggregate->as_set)
    new->attr = bgp_update_aggregate_attr (bgp, aggregate, aggr_p, afi, safi);
  else
   {
#ifdef HAVE_EXT_CAP_ASN
  if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
    new->attr = bgp_attr_aggregate_4b_intern (bgp, origin,
                                             NULL, NULL, 
                                             NULL, NULL,
                                             aggregate->as_set,
                                             distance,PAL_FALSE);
  else
#endif /*HAVE_EXT_CAP_ASN*/
    new->attr = bgp_attr_aggregate_intern (bgp, origin, NULL, NULL,
                                          aggregate->as_set,
                                          distance, PAL_FALSE);
   }
  
  SET_FLAG (new->flags, BGP_INFO_ATTR_CHANGED);

  return new;
}
/***********************************************************************
 * Function Name : bgp_aggregate_withdraw                              *
 *                                                                     *
 * Input parameter                                                     *
 *   bgp : bgp instance                                                *
 *   p   : aggregated prefix                                           *
 *  afi  : address family (ipv4 or ipv6)                               *
 *  safi : sub-address family (unicast, multicast....)                 *
 *                                                                     *
 *  Output                                                             *
 *  0 - on success                                                     *
 *  -1 - on error                                                      *
 *                                                                     *
 *  Description : this function will be called when the                *
 *                aggregate count is zero.                             *
 ***********************************************************************/
static s_int32_t
bgp_aggregate_withdraw (struct bgp * bgp , 
                        struct prefix *p, afi_t afi, safi_t safi)
{
  struct bgp_ptree *table;
  struct bgp *bgp_mvrf;
  struct bgp_node *rnagg;
  struct bgp_info *riagg;
  u_int32_t baai;
  u_int32_t bsai;
  s_int32_t ret;
  

  riagg = NULL;
  ret = 0;
  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  bgp_mvrf = bgp;

  table = bgp->rib [baai][bsai];
  rnagg = bgp_node_get (table, p);

  if (! rnagg)
    {
      ret = -1;
      return ret; 
    }
  /* Find the aggregate route for prefix p */
  for (riagg = rnagg->info; riagg; riagg = riagg->next)
    if (riagg->peer == bgp->peer_self
        && riagg->type == IPI_ROUTE_BGP
        && riagg->sub_type == BGP_ROUTE_AGGREGATE)
      break;
 
  if (NULL == riagg)
    return -1;

  bgp_info_delete (rnagg, riagg);
  bgp_process (bgp_mvrf, rnagg, afi, safi, riagg);
  bgp_info_free (riagg);
  bgp_unlock_node (rnagg);

  return 0;
}

/***********************************************************************
 * Function Name : bgp_aggregate_announce                              *
 *                                                                     *
 * Input parameter                                                     *
 *   bgp : bgp instance                                                *
 *   p   : aggregated prefix                                           *
 *  aggregate : aggregate information                                  *
 *  afi  : address family (ipv4 or ipv6)                               *
 *  safi : sub-address family (unicast, multicast....)                 *
 *                                                                     *
 *  Output                                                             *
 *  0 - on success                                                     *
 *  -1 - on error                                                      *
 *                                                                     *
 *  Description : This function will be called when the                *
 *  aggregate count is greater than zero. i.e., if aggregator          *
 *  had suppressed atleast one route in case of summary-only,          *
 *  and incase of as-set or without as-set & summary-only if any       *
 *  of the routes come under the aggregated route prefix               *
 ***********************************************************************/ 

static s_int32_t
bgp_aggregate_announce (struct bgp * bgp, struct prefix *aggr_p,  
                        struct bgp_aggregate *aggregate, 
                        afi_t afi, safi_t safi)
{
  u_int32_t baai;
  u_int32_t bsai;
  struct bgp_info *riagg;
  struct bgp_node *rnagg;
  struct bgp_ptree *table;
  struct bgp * bgp_mvrf;
  s_int32_t ret;


  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  riagg = NULL;
  ret = 0;

  /* do not annouce the aggregate route if the aggregate route
   * has not aggregated any route(s). 
   */
  if (aggregate->count == 0)
    return -1;

  bgp_mvrf = bgp;
 
  table = bgp->rib [baai][bsai];
  rnagg = bgp_node_lookup (table, aggr_p);

  if (! rnagg)
    {
      ret = -1;
      return ret;
    }

  /* Find the aggregate route for prefix p */
  for (riagg = rnagg->info; riagg; riagg = riagg->next)
    if (riagg->peer == bgp->peer_self
        && riagg->type == IPI_ROUTE_BGP
        && riagg->sub_type == BGP_ROUTE_AGGREGATE)
     break;
              
  if (!riagg)
    {
      ret = -2;
      return ret;
    }

  /* set the attribute changed flag so that aggregate route is 
   * announced 
   */
  SET_FLAG (riagg->flags, BGP_INFO_ATTR_CHANGED);
  bgp_process (bgp_mvrf, rnagg, afi, safi, NULL);

  return ret;
}

/***********************************************************************
 * Function Name : bgp_process_aggregation_takeover                    *
 *                                                                     *
 * Input parameter                                                     *
 *   bgp : bgp instance                                                *
 * curr_riagg : current aggregator route informatino                   *
 * afi  : address family (ipv4 or ipv6)                                *
 * safi : sub-address family (unicast, multicast....)                  *
 * ri : route information of current route (learned route)             *
 *                                                                     *
 *  Output                                                             *
 *  0 - on success                                                     *
 *  -1 - on error                                                      *
 *                                                                     *
 *Description : This function will be called when the route is already *
 *                part of parent aggregator (prev_riagg). The          *
 *                aggregation takeover will happen only if the med     *
 *                and nexthop matches with current aggregator.         *
 *                                                                     *
 *               This aggregation take over if the route is earlier    *
 *               part of parent aggregator (/16) and the current       *
 *               aggregator is (/24).                                  * 
 ***********************************************************************/

static bool_t 
bgp_process_aggregation_takeover (struct bgp *bgp, 
                                  struct bgp_aggregate *curr_riagg, afi_t afi, 
                                  safi_t safi, struct bgp_info *ri,
                                  u_int8_t *origin )
{
  bool_t change;
  struct bgp_node *prev_rnagg;
  struct bgp_aggregate *prev_riagg;
  s_int8_t nsame;
  struct bgp_node * curr_rnagg;
  struct prefix prev_rnp;
  struct prefix curr_rnp;
  
  /* set the flag to false */ 
  change = PAL_FALSE;
  nsame = 0;
  prev_riagg = NULL;
  curr_rnagg = NULL;

  if (!bgp || !curr_riagg || !ri)
    return change;

  prev_riagg = ri->riagg;
  if (!prev_riagg)
    return change;

  /* get the aggregated node from aggreated rib */
  prev_rnagg = prev_riagg->rnagg;

  /* current aggregate node */
  curr_rnagg = curr_riagg->rnagg;
  if (!prev_rnagg || !curr_rnagg)
    return change;

 
   pal_mem_set (&prev_rnp, 0x00, sizeof (struct prefix));
   pal_mem_set (&curr_rnp, 0x00, sizeof (struct prefix));
   /* Extract the prefix from the node */
   bgp_ptree_get_prefix_from_node (prev_rnagg, &prev_rnp); 
   bgp_ptree_get_prefix_from_node (curr_rnagg, &curr_rnp);

   /* determine if it is same network */  
  if (prev_rnp.prefixlen > curr_rnp.prefixlen)
    nsame = prefix_match (&curr_rnp, &prev_rnp);
  else
    {
      nsame = prefix_match (&prev_rnp, &curr_rnp);
  /* if same network and new aggregate prefix len is greater than
   * previously aggregate prefix then change the suppression ownership
   * to new aggregation prefix.
   */
      if (PAL_TRUE == nsame)
         change = PAL_TRUE;
     }

   /* no further processing */
   if (PAL_FALSE == change)
     return change;

  /* if no route(s) have been aggregated so far. record the 
   * med and nexthop value.
   */
   if (curr_riagg->count == 0)
     {
       curr_riagg->med = ri->attr->med;

       if (afi == AFI_IP)
         curr_riagg->nexthop = ri->attr->nexthop;
#ifdef HAVE_IPV6
       else if (afi == AFI_IP6)
         curr_riagg->nexthop_global = ri->attr->mp_nexthop_global;
#endif /* HAVE_IPV6 */

       ri->riagg = curr_riagg;
       curr_riagg->count++;
      /* decrement the aggregate count for previous one
       *  as the route will no more be a constituent route for
       *  this aggregated node. 
       */      
       prev_riagg->count--;

       if (origin && (*origin < ri->attr->origin))
          *origin = ri->attr->origin;
      
       /* update the origin  only if as-set is not set
        * if as-set is set then update aggregate will take
        * care of updating the origin
        */
       if (!prev_riagg->as_set)
          bgp_update_aggregate_origin (bgp, &prev_rnp, prev_riagg,
                                       afi, safi);

       if (prev_riagg->as_set)
         bgp_update_aggregate_attr (bgp, prev_riagg, &prev_rnp, 
                                    afi, safi);
     }

  /* if the current med does not match with med of new aggregator 
   * ignore the route.
   */
  else if (curr_riagg->med != ri->attr->med)
      return -1; 

  /* do not take over the aggregation ownership if the nexthop does not match,
   * when aggregation nexthop check is enabled.
   */
  else if (bgp_option_check (BGP_OPT_AGGREGATE_NEXTHOP_CHECK))
    {
      if (afi == AFI_IP && !IPV4_ADDR_SAME (&ri->attr->nexthop,
                                            &curr_riagg->nexthop))
        return -1; 
#ifdef HAVE_IPV6
      else if (afi == AFI_IP6 && !IPV6_ADDR_SAME (&ri->attr->mp_nexthop_global,                                                                                                &curr_riagg->nexthop_global))
        return -1;
#endif /* HAVE_IPV6 */
    }
 /* else take over the aggregation ownership */
  else
    {
      ri->riagg = curr_riagg;
      curr_riagg->count++;
      /* decrement the aggregate count for previous one
       *  as the route will no more be a constituent route for
       *  this aggregated node. 
       */      
       prev_riagg->count--;

       if (origin && (*origin < ri->attr->origin))
          *origin = ri->attr->origin;

       /* update the origin  only if as-set is not set
        * if as-set is set then update aggregate will take
        * care of updating the origin
        */
       if (!prev_riagg->as_set)
          bgp_update_aggregate_origin (bgp, &prev_rnp, prev_riagg,
                                       afi, safi);

      /* if as-set is enable in the previous aggregator then check
       * if there change in attribute of aggregate routee due to 
       * aggregation take over.
       */ 
       if (prev_riagg->as_set)
         bgp_update_aggregate_attr (bgp, prev_riagg, &prev_rnp, 
                                    afi, safi);
    }
  /* if there are no more aggregated routes then unselect the previous
   * aggregated route
   */
   if (prev_riagg->count == 0)
       bgp_aggregate_withdraw(bgp, &prev_rnp, afi, safi);
        
  /* if the new aggregate command  does
   * not have summary_only option and if it
   * previously suppressed, then decrement
   * the suppress count of route
   */
  if (!curr_riagg->summary_only && ri->suppress)
    {
      ri->suppress--;
      SET_FLAG (ri->flags, BGP_INFO_ATTR_CHANGED);
    }

  if (curr_riagg->summary_only && !ri->suppress)
    {
      ri->suppress++;
      SET_FLAG (ri->flags, BGP_INFO_ATTR_CHANGED);
    }

  return change;
}

/***********************************************************************
 * Function Name : bgp_aggregate_del_route                             *
 *                                                                     *
 * Input parameter                                                     *
 *   bgp  : bgp instance                                               *
 * aggr_p : current aggregator route informatino                       *
 * del_ri : route information of route which withdrawn                 *
 * afi    : address family (ipv4 or ipv6)                              *
 * safi   : sub-address family (unicast, multicast....)                *
 *                                                                     *
 *  Output                                                             *
 *  0 - on success                                                     *
 *  -1 - on error                                                      *
 *                                                                     *
 *  Description : This function will be called when the route is       *
 *                withdrawn bgp_aggregate_decrement () or when the     *
 *                operator had issued no on aggregate command          *
 *                bgp_aggregate_remove_aggregator ().                  *
 *                                                                     *
 *                This function reduces the count of aggregate route   *
 *                and if the count reaches zero, it does withdraw the  *
 *                aggregate route.                                     *
 ***********************************************************************/
s_int32_t
bgp_aggregate_del_route (struct bgp *bgp, struct prefix *aggr_p,
                         struct bgp_info *del_ri,
                         struct bgp_aggregate *aggregate,
                         afi_t afi, safi_t safi)
{
  struct attr *old_attr;
  u_int32_t baai;
  u_int32_t bsai;
  struct bgp_info *riagg;
  struct bgp_node *rnagg;
  struct bgp_ptree *table;

  old_attr = NULL;
  riagg = NULL;
  rnagg = NULL;
  table = NULL;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
 
  table = bgp->rib [baai][bsai];
  rnagg = bgp_node_get (table, aggr_p);

  if (! rnagg)
    return -1;

 /* Find the aggregate route for prefix p */
  for (riagg = rnagg->info; riagg; riagg = riagg->next)
    if (riagg->peer == bgp->peer_self
        && riagg->type == IPI_ROUTE_BGP
        && riagg->sub_type == BGP_ROUTE_AGGREGATE)
      {
        old_attr = riagg->attr;
        break;
      }

  if (del_ri->riagg != aggregate)
    return -1;
  
  del_ri->riagg = NULL;

  if (aggregate->count)
    aggregate->count--;

  /* if as-set is enabled and old attribute is present 
   */
  if (aggregate->as_set && aggregate->count && old_attr)
    {
      bgp_update_aggregate_attr (bgp, aggregate, aggr_p, afi, safi);
    }

  /* decrement suppress count, so that the route is not shown as suppressed 
   * when the nexthop of the routes goes invalid.
   */
  if (del_ri->suppress)
    del_ri->suppress--;


  if (aggregate->count == 0)
    bgp_aggregate_withdraw (bgp, aggr_p, afi, safi);


 return 0;
}
/***********************************************************************
 * Function Name : bgp_aggregate_remove_aggregator                     *
 *                                                                     *
 * Input parameter                                                     *
 *   bgp  : bgp instance                                               *
 * aggr_p : current aggregator route informatino                       *
 * aggregate : info of the aggregate route from aggregate rib          *
 * afi    : address family (ipv4 or ipv6)                              *
 * safi   : sub-address family (unicast, multicast....)                *
 *                                                                     *
 *  Output                                                             *
 *  0 - on success                                                     *
 *  -1 - on error                                                      *
 *                                                                     *
 *  Description : This function will be called when the route operator *
 *                had issued no aggregate command.                     *  
 ***********************************************************************/
s_int32_t
bgp_aggregate_remove_aggregator (struct bgp *bgp, struct prefix *aggr_p,
                                 struct bgp_aggregate *aggregate,
                                  afi_t afi, safi_t safi)
{ 
  u_int32_t baai;
  u_int32_t bsai;
  struct bgp_ptree *table;
  struct bgp * bgp_mvrf;
  struct bgp_node * rn;
  struct bgp_node * rnagg;
  struct bgp_info *ri;
  struct prefix rnp;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  rn = NULL;
  rnagg = NULL;
  ri = NULL;

  bgp_mvrf = bgp;
 
  table = bgp->rib [baai][bsai];
  if (!table)
    return -1;

  rnagg = bgp_node_get (table, aggr_p);
 if (!rnagg)
    return -1;
 

  for (rn = bgp_node_get (table, aggr_p); rn;
       rn = bgp_route_next_until (rn, rnagg))
    {
      /* Extract the prefix from node */
      pal_mem_set (&rnp, 0x00, sizeof (struct prefix));
      bgp_ptree_get_prefix_from_node (rn, &rnp);

      if (rnp.prefixlen > aggr_p->prefixlen)
        {
         for (ri = rn->info; ri; ri = ri->next)
           {
             if (BGP_INFO_HOLDDOWN (ri))
               continue;
             /* ignoring suppression process if the route type is
              * BGP_ROUTE_AGGREGATE
              */
             if (ri->sub_type == BGP_ROUTE_AGGREGATE)
               continue;
             
            /* if the aggregate ownership is not matching then ignore the
             * route.
             */
            
             if (ri->riagg != aggregate)
               continue;

             if (aggregate->summary_only)
               {
                 ri->suppress --;
                 SET_FLAG (ri->flags, BGP_INFO_ATTR_CHANGED);
                 bgp_process (bgp_mvrf, rn, afi, safi, NULL);
               }
             /* make a call to del route it actually reduces the aggregate
              * count and if it reaches zero it withdraw's as well.
              */
              bgp_aggregate_del_route (bgp, aggr_p, ri, aggregate, afi, safi);
            
           }
        }  
     }  

 return 0;
}
/***********************************************************************
 * Function Name :bgp_aggregate_new_route                              *
 *                                                                     *
 * Input parameter                                                     *
 *   bgp  : bgp instance                                               *
 * aggr_p : current aggregator route informatino                       *
 * aggregate : info of the aggregate route from aggregate rib          *
 * afi    : address family (ipv4 or ipv6)                              *
 * safi   : sub-address family (unicast, multicast....)                *
 * new_aggregator : will PAL_TRUE only when the                        *
 *                  bgp_aggregate_new_route is called from             *
 *                  bgp_aggregate_process_new_aggregator and it will   *
 *                  PAL_FALSE when called from bgp_aggregate_increment *
 *                                                                     *
 *  Output                                                             *
 *  0 -  on success                                                    *
 *  -1 - the memory allocation fails                                   *
 *  -2 - the prefixlen is less than the aggregate route prefixlen      *
 *  -3 - the med does not match with aggregate route med               *
 *  -4 - nexthop does not match when nexthop check is enabled          *
 *  -5 -  already part of another aggregator                           *
 *                                                                     *
 *                                                                     *
 *  Description : This function will be called when the route operator *
 *                had issued  aggregate command (bgp_aggregate_set) or *
 *                new route is learned (bgp_aggregate_incerement).     *
 ***********************************************************************/
s_int32_t
bgp_aggregate_new_route (struct bgp *bgp, struct prefix *aggr_p,
                         struct prefix *p, struct bgp_info *rinew,
                         struct bgp_aggregate *aggregate,
                         afi_t afi, safi_t safi, 
                         bool_t new_aggregator)
{
  s_int32_t ret;
  u_int32_t baai;
  u_int32_t bsai;
  struct bgp_ptree *table;
  bool_t is_first_route;
  struct bgp_info * riagg;
  u_int8_t origin;
  struct bgp_node *rnagg;
  struct bgp_node *rn;
  struct bgp * bgp_mvrf;
  struct attr * old_attr;
  struct attr * new_attr;
  struct bgp_info *new;
  struct bgp_aggregate * old_aggregator;
  bool_t announce;
  bool_t prev_aggregator;
  struct prefix rnp;
  u_int32_t distance;
  
  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);

  rnagg = NULL;
  old_attr = NULL;
  new_attr = NULL;
  new = NULL;
  old_aggregator = NULL;
  bgp_mvrf = bgp;
  distance = 0;

  prev_aggregator = PAL_FALSE;
  is_first_route = PAL_FALSE;
  announce = PAL_FALSE;
  origin = BGP_ORIGIN_IGP;
  ret =0;
 
  table = bgp->rib [baai][bsai];
  if (!table)
    return -1;

  rnagg = bgp_node_get (table, aggr_p);
  if (! rnagg)
    {
      ret = -1;
      return ret;
    }
 /* Find the aggregate route for prefix p */
  for (riagg = rnagg->info; riagg; riagg = riagg->next)
    if (riagg->peer == bgp->peer_self
        && riagg->type == IPI_ROUTE_BGP
        && riagg->sub_type == BGP_ROUTE_AGGREGATE)
     {
       old_attr = riagg->attr;
       break;
     }

  rn = bgp_node_get (table, p);
  if (! rn)
    return -1;

 /* If any local distance is configured for that particular AFI/SAFI
  * use it, else if distance is configured in router-mode assign it
  * else, assign the default distance.
  */
  if (bgp->distance_local[baai][bsai])
    distance = bgp->distance_local[baai][bsai];
  else if (bgp->distance_local[BAAI_IP][BSAI_UNICAST])
    distance = bgp->distance_local[BAAI_IP][BSAI_UNICAST];
  else
    distance = IPI_DISTANCE_IBGP;


  /* if already part of another aggregator then perform the 
   * decrement of old aggregator. rinew will valid riagg when the 
   * same route is announce with different med and previous aggregator
   * had reject due to different med value.
   */
  if (rinew->riagg)
    {
       old_aggregator = rinew->riagg;     
       prev_aggregator = PAL_TRUE;
       /* Extract the prefix from node */
       pal_mem_set (&rnp, 0x00, sizeof (struct prefix));
       bgp_ptree_get_prefix_from_node (old_aggregator->rnagg, &rnp);
       bgp_aggregate_decrement (bgp, &rnp, rinew, afi, safi);
    }

  /* if no routes have been aggregated so far . */
  if (aggregate->count == 0)
    is_first_route = PAL_TRUE;

  /* check if the new route is the first route to be aggregated */
  if (is_first_route)
    {
      /* update the aggregate info */
      rinew->riagg = aggregate;
      aggregate->med = rinew->attr->med;
      aggregate->nexthop = rinew->attr->nexthop;
       
       if (afi == AFI_IP)
         aggregate->nexthop = rinew->attr->nexthop;
#ifdef HAVE_IPV6
       else if (afi == AFI_IP6)
         aggregate->nexthop_global = rinew->attr->mp_nexthop_global;
#endif /* HAVE_IPV6 */

      aggregate->count++;
      /* when as-set is enabled then the aggregate route should contain
       * aspath of the new route. 
       */
        if (PAL_FALSE == new_aggregator)
          {
            new = bgp_aggregate_info_new (bgp, aggregate, aggr_p, rnagg, 
                                          afi, safi, rinew->attr->origin);
            if (new == NULL)
              { 
                bgp_unlock_node (rnagg);
                return -1;  /* Memory allocation failure */
              }
         } 

      /* if summary-only is enabled then suppress the new route.*/
      if (aggregate->summary_only && !rinew->suppress)
        {
          rinew->suppress ++;
          SET_FLAG (rinew->flags, BGP_INFO_ATTR_CHANGED);
          bgp_process (bgp_mvrf, rn, afi, safi, NULL);
        }

      /* when the route was previously suppressed and if the same route 
       * is re-annouced with different med value, in this case if summary-only
       * is disable in  the parent  aggregate route 
       * (parent = /16 and child = /24)  .
       */
      if (!aggregate->summary_only && rinew->suppress)
        {
           rinew->suppress --;
           SET_FLAG (rinew->flags, BGP_INFO_ATTR_CHANGED);
           bgp_process (bgp_mvrf, rn, afi, safi, NULL);
        }

       /* announce the aggregate route */
       if (PAL_FALSE == new_aggregator)
         announce = PAL_TRUE;
     /* no further processing */
      goto EXIT;
    }
 
   /* if the control reaches here, it means that the aggregate route had
    * aggregated routes and as been announced, from here the aggregate
    * route will be announced only when as-set is enabled and there is 
    * change in the attribute of aggregate route.
    */

  /* do not aggregate if the prefix of the new route is less than 
   * the aggregate route.
   */
  if (p->prefixlen < aggr_p->prefixlen)
    return -2;

  /* do not aggregate if the med does not match */
  if (aggregate->med != rinew->attr->med)
    return -3;

  /* when nexthop check is available and the new route
   * nexthop does not match with aggregated route nexthop
   * do not proceed further.
   */
  if (bgp_option_check (BGP_OPT_AGGREGATE_NEXTHOP_CHECK))
    {
      if (afi == AFI_IP && !IPV4_ADDR_SAME (&rinew->attr->nexthop,
                                            &aggregate->nexthop))
        return -4;
#ifdef HAVE_IPV6
       else if (afi == AFI_IP6 &&
                !IPV6_ADDR_SAME (&rinew->attr->mp_nexthop_global,
                                 &aggregate->nexthop_global))
         return -4;
#endif /* HAVE_IPV6 */
     }
  
   /* however we can still keep this check to ensure that
   * the route is not part of more than one aggregate command. 
   */
  if (rinew->riagg)
    return -5;
   /* when the aggregation command is issued without
    * sumary-only and as-set.
    */ 
  if (!aggregate->summary_only && !aggregate->as_set)
    {
       aggregate->count++;
       /* if the previous aggregator had supressed the route
        * and for the current aggregator summary-only is not
        * enabled, then un-suppress the route. This can happen
        * if the same route is re-announced with different med 
        * or if the route nexthop is changed, when the nexthop
        * check is enabled.
        */
       if (rinew->suppress && (PAL_TRUE == prev_aggregator))
         {
           rinew->suppress --;
           SET_FLAG (rinew->flags, BGP_INFO_ATTR_CHANGED);
           bgp_process (bgp_mvrf, rn, afi, safi, NULL);
        }
    }

   /* when the aggregation command is isssued with
    * summmary-only or summaryonly & as-set.
    */
  if (aggregate->summary_only)
    {
      if (!rinew->suppress)
        {
          rinew->suppress++;
          SET_FLAG (rinew->flags, BGP_INFO_ATTR_CHANGED);
          bgp_process (bgp_mvrf, rn, afi, safi, NULL);
        }
     /* do not increment the count if as-set is also there
      * as the count will also be incremented in as-set
      * i.e., increment only when summary-only is enabled.
      */
      if (!aggregate->as_set)
        aggregate->count++;
    }

  if (aggregate->as_set && !aggregate->summary_only)
    {
       if (rinew->suppress && (PAL_TRUE == prev_aggregator))
         {
           rinew->suppress --;
           SET_FLAG (rinew->flags, BGP_INFO_ATTR_CHANGED);
           bgp_process (bgp_mvrf, rn, afi, safi, NULL);
        }
    }

  /* update the aggregate info with med and nexthop
   * so that med and nexthop can be check for next route
   * onwards.
   */
  aggregate->med = rinew->attr->med;
  aggregate->nexthop = rinew->attr->nexthop;
  rinew->riagg = aggregate;

  if (!aggregate->as_set && aggregate->origin < rinew->attr->origin
      && (PAL_FALSE == new_aggregator))
    {
       aggregate->origin = rinew->attr->origin;
       origin = rinew->attr->origin;
       if (old_attr)
         bgp_attr_unintern (old_attr);
#ifdef HAVE_EXT_CAP_ASN
      if (CHECK_FLAG (BGP_VR.bvr_options, BGP_OPT_EXTENDED_ASN_CAP))
        new_attr = bgp_attr_aggregate_4b_intern (bgp, origin,
                                                 NULL, NULL,
                                                 NULL, NULL,
                                                 aggregate->as_set,
                                                 distance,PAL_FALSE);
  else
#endif /*HAVE_EXT_CAP_ASN*/
        new_attr = bgp_attr_aggregate_intern (bgp, origin, NULL, NULL,
                                              aggregate->as_set,
                                              distance,PAL_FALSE);

       /* replace the old attribute with new attribute */
       if (riagg)
         riagg->attr = new_attr;

       announce = PAL_TRUE;
    }
       
   /* when the aggregation command is issued 
    * with as-set or summary-only & as-set.
    */
   /* when new_aggregator is PAL_TRUE do not check if there is any
    * change in the attribute.
    */
  if (aggregate->as_set && (PAL_FALSE == new_aggregator) && old_attr) 
    {
      /* get the new attribute including the new route */
      bgp_update_aggregate_attr (bgp, aggregate, aggr_p, afi, safi);
      aggregate->count++;
      goto EXIT;
    }

  if (aggregate->as_set && (PAL_TRUE == new_aggregator))
    aggregate->count++;

EXIT:
  /* announce will true only when the as-set is enabled and 
   * attribute of the aggregate route is changed due the new route
   * for example , aggregate route had aggregated only the routes 
   * from a particular AS and the new route is from a different AS.
   * in such case the aspath of the aggregate route will updated 
   * with new route AS. Hence need to re-announce the aggregate route.
   */
  if (PAL_TRUE == announce)
     bgp_aggregate_announce (bgp, aggr_p, aggregate, afi, safi);

  bgp_unlock_node (rnagg);
      
 return 0;
}
/***********************************************************************
 * Function Name : bgp_aggregate_process_new_aggregator                *
 *                                                                     *
 * Input parameter                                                     *
 *   bgp  : bgp instance                                               *
 *     p : current aggregator route informatino                        *
 * aggregate : info of the aggregate route from aggregate rib          *
 * afi    : address family (ipv4 or ipv6)                              *
 * safi   : sub-address family (unicast, multicast....)                *
 *                                                                     *
 *  Output                                                             *
 *  0 - on success                                                     *
 *  -1 - on error                                                      *
 *                                                                     *
 *  Description : This function will be called when the route operator *
 *                had issued  aggregate command (bgp_aggregate_set)    *
 ***********************************************************************/
s_int32_t
bgp_aggregate_process_new_aggregator (struct bgp *bgp, struct prefix *p,
                                      struct bgp_aggregate *aggregate,
                                      afi_t afi, safi_t safi)
{
  struct bgp_ptree *table;
  struct bgp_node *rnagg;
  struct bgp_info *riagg;
  struct bgp *bgp_mvrf;
  struct bgp_node *rn;
  struct bgp_info *ri;
  u_int32_t match;
  u_int32_t baai;
  u_int32_t bsai;
  u_int8_t origin;
  bool_t change;
  struct prefix rnp;

  bsai = BGP_SAFI2BSAI (safi);
  baai = BGP_AFI2BAAI (afi);
  change = PAL_FALSE;
  origin = BGP_ORIGIN_IGP;
  riagg = NULL;

  bgp_mvrf = bgp;

  table = bgp->rib [baai][bsai];

   rnagg = bgp_node_get (table, p);
  if (!rnagg)
    return -1;

  for (rn = bgp_node_get (table, p); rn;
       rn = bgp_route_next_until (rn, rnagg))
    {
      /* Extract prefix from node */
      pal_mem_set (&rnp, 0x00, sizeof (struct prefix));
      bgp_ptree_get_prefix_from_node (rn, &rnp);
  
      if (rnp.prefixlen > p->prefixlen)
        {
          match = 0;
          for (ri = rn->info; ri; ri = ri->next)
            {
              if (BGP_INFO_HOLDDOWN (ri) || ri == riagg)
                continue;
               /* ignoring suppression process if the route type is
                * BGP_ROUTE_AGGREGATE
                */
              if (ri->sub_type == BGP_ROUTE_AGGREGATE)
                continue;
              /* update the origin */
              if (origin < ri->attr->origin)
                 origin = ri->attr->origin;

              /* if the route is not part of any aggregator */            
              if (NULL == ri->riagg)
                bgp_aggregate_new_route (bgp, p, &rnp, ri, aggregate,
                                         afi, safi, PAL_TRUE); 
              else
                {
                   change =  bgp_process_aggregation_takeover (bgp, aggregate,
                                                               afi, safi, ri,
                                                               &origin);
                   if (PAL_TRUE == change)
                     match++;
                }

            }
          if (match)
            bgp_process (bgp_mvrf, rn, afi, safi, NULL);
        }/* rn->p.prefixlen */
     }

  /* check if the aggregated route needs to be announced */
  if (aggregate->count)
    {
      bgp_aggregate_info_new (bgp, aggregate, p, rnagg, afi, safi, origin);
      bgp_aggregate_announce  (bgp, p, aggregate, afi, safi);
    }
 else
   bgp_unlock_node (rnagg);

  return 0;
}


/* BGP RIB related CLI commands Initialization */
void
bgp_route_cli_init (struct cli_tree *ctree)
{
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &aggregate_address_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &aggregate_address_summary_only_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &aggregate_address_as_set_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &aggregate_address_as_set_summary_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &aggregate_address_summary_as_set_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_aggregate_address_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_aggregate_address_summary_only_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_aggregate_address_as_set_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_aggregate_address_as_set_summary_cmd);
  cli_install_gen (ctree, BGP_MODE, PRIVILEGE_NORMAL, 0,
                   &no_aggregate_address_summary_as_set_cmd);

#ifdef HAVE_IPV6
  IF_BGP_CAP_HAVE_IPV6
    {
      /* IPv6 BGP commands. */
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &ipv6_aggregate_address_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &ipv6_aggregate_address_summary_only_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &ipv6_aggregate_address_as_set_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &ipv6_aggregate_address_as_set_summary_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &ipv6_aggregate_address_summary_as_set_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_ipv6_aggregate_address_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_ipv6_aggregate_address_summary_only_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_ipv6_aggregate_address_as_set_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_ipv6_aggregate_address_as_set_summary_cmd);
      cli_install_gen (ctree, BGP_IPV6_MODE, PRIVILEGE_NORMAL, 0,
                       &no_ipv6_aggregate_address_summary_as_set_cmd);
    }
#endif /* HAVE_IPV6 */

  return;
}

