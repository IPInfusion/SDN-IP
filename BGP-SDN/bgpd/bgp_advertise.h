/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_ADVERTISE_H
#define _BGPSDN_BGP_ADVERTISE_H

enum {
  BGP_REACH   = 0,
  BGP_UNREACH = 1,
};

/* BGP advertise attribute.  */
struct bgp_advertise_attr
{
  /* Head of advertisement pointer. */
  struct bgp_advertise *adv;

  /* Reference counter.  */
  u_int32_t refcnt;

  /* Attribute pointer to be announced.  */
  struct attr *attr;

  /* Bitmap indicating enqueued advertisement FIFOs */
  u_int32_t bitmap;
#define BGP_ADV_FIFO_INVALID        0
#define BGP_ADV_FIFO_ADV_REACH      1
#define BGP_ADV_FIFO_ASORIG_REACH   2
#define BGP_ADV_FIFO_ADV_UNREACH    4
#define BGP_ADV_FIFO_ASORIG_UNREACH 8
};

/* FIFO element holding a pointerr to 'bgp_advertise' */
struct bgp_adv_attr_fifo
{
  /* FIFO for advertisement.  */
  struct fifo badv_fifo;

  /*
   * XXXX THIS MEMBER MUST NOT BE MOVED XXXX
   *
   *  Union ID: must be BGP_ADV_UID_ATTR or BGP_ADV_UID_ADV_WITHDRAW
   */
  u_int16_t uid;
#define BGP_ADV_UID_ATTR 0
#define BGP_ADV_UID_ADV  1
#define BGP_ADV_UID_ADV_WITHDRAW 2

  /* Current advertisement FIFO type */
  u_int16_t type;

  /* Advertisement attribute.  */
  struct bgp_advertise_attr *baa;
};

struct bgp_advertise
{
  /* FIFO for advertisement.  */
  struct fifo badv_fifo;

  /*
   * XXXX THIS MEMBER MUST NOT BE MOVED XXXX
   *
   *  Union ID: must be BGP_ADV_UID_ADV
   */
  u_int16_t uid;

  /* Reference counter */
  s_int16_t cnt;

  /* Link list for same attribute advertise.  */
  struct bgp_advertise *next;
  struct bgp_advertise *prev;

  /* Prefix information.  */
  struct bgp_node *rn;

  /* Reference pointer.  */
  struct bgp_adj_out *adj;

  /* Advertisement attribute.  */
  struct bgp_advertise_attr *baa;

  /* BGP info.  */
  struct bgp_info *binfo;

  /* peer ID bitmap in peer group */
  u_int32_t bitmap;
};

/* BGP adjacency out.  */
struct bgp_adj_out
{
  /* Lined list pointer.  */
  struct bgp_adj_out *next;
  struct bgp_adj_out *prev;

  /* Received peer */
  struct bgp_peer *from_peer;

  /* Advertised peer.  */
  struct bgp_peer *peer;

  /* Advertised attribute.  */
  struct attr *attr;

  /* Advertisement information.  */
  struct bgp_advertise *adv;
};

/* This struct is refined struct
 * of adj_out. This is used to
 * only when the disable adj out
 * feature is enabled. This struct
 * contain only the rn (route) and
 * all other necessary information
 * is extracted at time of encoding
 * bgp update message.
 */
struct adv_out
{
  struct fifo  adv_out_fifo;
  struct bgp_node * rn;
};

/* BGP adjacency in. */
struct bgp_adj_in
{
  /* Linked list pointer.  */
  struct bgp_adj_in *next;
  struct bgp_adj_in *prev;

  /* Received peer.  */
  struct bgp_peer *peer;

  /* Received attribute.  */
  struct attr *attr;
};

/* BGP Peer advertisement list */
struct bgp_peer_adv_list
{
  struct fifo reach;
  struct fifo unreach;
};

/* BGP Peer advertisement list in the case BGP_OPT_DISABLE_ADJ_OUT is set */
struct bgp_peer_adv_list_new
{
  struct bgp_peer_adv_list adv_list;

  /* Number of elements in adv_lists */
  u_int32_t cnt_reach;
  u_int32_t cnt_unreach;
  /*
   * Do not use peer group (i.e., each pear has a copy of advertisements)
   * if (# of elements in adv_lsit) * 5 <
   * BGP_MAX_PACKET_SIZE * BGP_SEND_MSG_CLUST_MAX_COUNT
   * 5 is size of IPv4 prefix (4 + 1, 1 is for prefix length)
   */
#define BGP_THRESH_NUM_ADVS (4*1024)
};

/* BGP adjacency linked list.  */
#define BGP_INFO_ADD(N,A,TYPE)                        \
  do {                                                \
    (A)->prev = NULL;                                 \
    (A)->next = (N)->TYPE;                            \
    if ((N)->TYPE)                                    \
      (N)->TYPE->prev = (A);                          \
    (N)->TYPE = (A);                                  \
  } while (0)

#define BGP_INFO_DEL(N,A,TYPE)                        \
  do {                                                \
    if ((A)->next)                                    \
      (A)->next->prev = (A)->prev;                    \
    if ((A)->prev)                                    \
      (A)->prev->next = (A)->next;                    \
    else                                              \
      (N)->TYPE = (A)->next;                          \
  } while (0)

#define BGP_ADJ_IN_ADD(N,A)    BGP_INFO_ADD(N,A,adj_in)
#define BGP_ADJ_IN_DEL(N,A)    BGP_INFO_DEL(N,A,adj_in)
#define BGP_ADJ_OUT_ADD(N,A)   BGP_INFO_ADD(N,A,adj_out)
#define BGP_ADJ_OUT_DEL(N,A)   BGP_INFO_DEL(N,A,adj_out)

/* Prototypes.  */
void bgp_adj_out_set (struct bgp_node *, struct bgp_peer *,
                          struct attr *, afi_t, safi_t, struct bgp_info *);

void bgp_adj_out_unset (struct bgp_node *, struct bgp_peer *,
                        struct bgp_info *,  afi_t, safi_t);

struct bgp_advertise * bgp_adj_out_remove (struct bgp_node *, struct bgp_adj_out *,
                                           struct bgp_peer *, afi_t, safi_t, bool_t);

bool_t bgp_adj_out_lookup (struct bgp_peer *,
                           struct bgp_node *);

void bgp_adj_in_set (struct bgp_node *, struct bgp_peer *, struct attr *);

void bgp_adj_in_unset (struct bgp_node *, struct bgp_peer *);

void bgp_adj_in_remove (struct bgp_node *, struct bgp_adj_in *);

struct bgp_advertise_attr * bgp_advertise_intern (struct hash *, struct attr *);

struct bgp_advertise * bgp_advertise_new ();

void bgp_advertise_add (struct bgp_advertise_attr *, struct bgp_advertise *);

struct bgp_advertise * bgp_advertise_clean (struct bgp_peer *, 
                                            struct bgp_adj_out **, 
                                            afi_t, safi_t);
void bgp_peer_adv_list_init (struct bgp_peer *);

void bgp_peer_adv_list_delete (struct bgp_peer *);

void bgp_populate_adj_out (struct bgp_peer *peer, u_int32_t baai, 
                           u_int32_t bsai);

struct bgp_advertise * bgp_rib_out_free (struct bgp_node *rn,
                                         struct bgp_adj_out *adj,
                                         struct bgp_peer *peer,
                                         afi_t afi, safi_t safi,
                                         bool_t auto_summary_update);

bool_t bgp_advertise_peer_id_isset (struct bgp_peer *peer,
                                    struct bgp_advertise *adv);
void bgp_advertise_peer_id_set (struct bgp_peer *peer,
                                struct bgp_advertise *adv);
void bgp_advertise_peer_id_unset (struct bgp_peer *peer,
                                  struct bgp_advertise *adv);

#endif /* _BGPSDN_BGP_ADVERTISE_H */
