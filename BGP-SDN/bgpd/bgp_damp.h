/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_BGP_DAMP_H
#define _BGPSDN_BGP_DAMP_H

/*
 * Configurable parameter limit values
 */
/* Min value of Reach Half-Life in min */
#define BGP_RFD_REACH_HLIFE_MIN_VAL  (1)
/* Max value of Reach Half-Life in min */
#define BGP_RFD_REACH_HLIFE_MAX_VAL  (45)
/* Default value of Reach Half-Life in min */
#define BGP_RFD_REACH_HLIFE_DEF_VAL  (15)
/* Min value of Reuse penalty */
#define BGP_RFD_REUSE_MIN_VAL        (1)
/* Max value of Reuse penalty */
#define BGP_RFD_REUSE_MAX_VAL        (20000)
/* Default value of Reuse penalty */
#define BGP_RFD_REUSE_DEF_VAL        (750)
/* Min value of Suppress penalty */
#define BGP_RFD_SUPPRESS_MIN_VAL     (1)
/* Max value of Suppress penalty */
#define BGP_RFD_SUPPRESS_MAX_VAL     (20000)
/* Default value of Suppress penalty */
#define BGP_RFD_SUPPRESS_DEF_VAL     (2000)
/* Min value of Max-Suppress in min */
#define BGP_RFD_MAX_SUPPRESS_MIN_VAL (1)
/* Max value of Max-Suppress in min */
#define BGP_RFD_MAX_SUPPRESS_MAX_VAL (255)
/* Default value of Max-Suppress in min */
#define BGP_RFD_MAX_SUPPRESS_DEF_VAL (60)
/* Min value of Un-reach Half-Life in min */
#define BGP_RFD_UREACH_HLIFE_MIN_VAL (1)
/* Max value of Un-reach Half-Life in min */
#define BGP_RFD_UREACH_HLIFE_MAX_VAL (45)
/* Default value of Un-reach Half-Life in min */
#define BGP_RFD_UREACH_HLIFE_DEF_VAL (15)

/*
 * System wide and non-configurable settings
 */
/* Default Penalty increment value */
#define BGP_RFD_DEF_PENALTY          (1000)
/* Decay Timer Interval in secs */
#define BGP_RFD_DECAY_TICK           (5)
/* Max Decay Array Span Time in min */
#define BGP_RFD_DECAY_ARY_MAX_TIME   (60)
/* Max Decay Array Span Time in min */
#define BGP_RFD_DECAY_ARY_MAX_SIZE   (BGP_RFD_DECAY_ARY_MAX_TIME * \
                                      ONE_MIN_SECOND / BGP_RFD_DECAY_TICK)
/* Reuse Timer Interval in secs */
#define BGP_RFD_REUSE_TICK           (10)
/* Non-Reuse Timer Interval in secs */
#define BGP_RFD_NON_REUSE_TICK       (30)
/* Reuse-Index-Array-Size */
#define BGP_RFD_REUSE_IDX_ARY_SIZE   (1024)
/* Reuse-List-Array-Size:
 * Preferably this value can be as large as:
 * (BGP_RFD_MAX_SUPPRESS_MAX_VAL * \
 *  ONE_MIN_SECOND / BGP_RFD_REUSE_TICK)
 */
#define BGP_RFD_REUSE_LIST_SIZE      (512)

/* Invalid Reuse-List-Array Index */
#define BGP_RFD_REUSE_LIST_INV_IDX   (BGP_RFD_REUSE_LIST_SIZE + 1)

/* BGP Route Flap Dampening route state */
enum bgp_rfd_rt_event
{
  BGP_RFD_RT_EVENT_REACH = 1,
  BGP_RFD_RT_EVENT_UNREACH,
  BGP_RFD_RT_EVENT_REUSE_TIMER,
  BGP_RFD_RT_EVENT_NON_REUSE_TIMER
};

/* BGP Route Flap Dampening route state */
enum bgp_rfd_rt_state
{
  BGP_RFD_RT_STATE_NONE = 1,
  BGP_RFD_RT_STATE_USE,
  BGP_RFD_RT_STATE_DAMPED
};

/* BGP Route Flap Dampening history info */
struct bgp_rfd_hist_info
{
  /* D-Link-List of hist_info elements of associated RFD_CB */
  struct bgp_rfd_hist_info *rfdh_rfdcb_prev;
  struct bgp_rfd_hist_info *rfdh_rfdcb_next;

  /* D-Link-List of hist_info elements of a reuse_list */
  struct bgp_rfd_hist_info *rfdh_reuse_prev;
  struct bgp_rfd_hist_info *rfdh_reuse_next;

  /* Index of Reuse-list if in one */
  u_int32_t rfdh_reuse_idx;

  /* Figure-of-merit */
  u_int32_t rfdh_penalty;

  /* Number of flaps */
  u_int32_t rfdh_flap_count;

  /* Time-stamp of start of suppression */
  pal_time_t rfdh_suppress_time;

  /* Last time penalty was updated */
  pal_time_t rfdh_lupdate;

  /* Time-stamp of start of record */
  pal_time_t rfdh_rec_duration;

  /* Back reference to rfd_cb */
  struct bgp_rfd_cb *rfdh_rfd_cb;

  /* Back reference to bgp_info */
  struct bgp_info *rfdh_binfo;

  /* Back reference to bgp_node */
  struct bgp_node *rfdh_rn;

  /* Recorded route event (ONLY reach/un-reach) */
  enum bgp_rfd_rt_event rfdh_rec_event;
  
  /* Record first_withdrawal of this route */
  u_int16_t rfdh_first_withdraw_done; 
};

/* BGP Route Flap Dampening User Configurable Parameters */
struct bgp_rfd_cb_cfg_param
{
  /* Half life for reachable prefixes in sec */
  u_int32_t rfdc_reach_hlife;

  /* Penalty value below which routes are un-suppressed */
  u_int32_t rfdc_reuse;

  /* Penalty value over which routes are suppressed */
  u_int32_t rfdc_suppress;

  /* Max suppress time in sec */
  u_int32_t rfdc_max_suppress;

  /* Half life for unreachable prefixes in sec */
  u_int32_t rfdc_unreach_hlife;
};

/* BGP Route Flap Dampening Control Block */
struct bgp_rfd_cb
{
  /* Back pointer to configuration block */
  struct bgp_rfd_cfg *rfd_cfg;

  /* Configurable parameters */
  struct bgp_rfd_cb_cfg_param rfd_config;
#define rfd_reach_hlife   rfd_config.rfdc_reach_hlife
#define rfd_reuse         rfd_config.rfdc_reuse
#define rfd_suppress      rfd_config.rfdc_suppress
#define rfd_max_suppress  rfd_config.rfdc_max_suppress
#define rfd_unreach_hlife rfd_config.rfdc_unreach_hlife

  /* Max penalty ceiling */
  s_int32_t rfd_penalty_ceil;

  /* Min penalty value */
  s_int32_t rfd_penalty_floor;

  /* Num of elements in reach decay array */
  u_int32_t rfd_nrdecay;
  /* Decay array when reachable */
  float64_t *rfd_rdecay;

  /* Num of elements in unreach decay array */
  u_int32_t rfd_nudecay;
  /* Decay array when un-reachable */
  float64_t *rfd_udecay;

  /* Reachability reuse-index-array */
  u_int32_t rfd_reach_reuse_idx_ary[BGP_RFD_REUSE_IDX_ARY_SIZE];
  /* Reachability reuse-index-array scale-factor */
  float64_t rfd_rscale_factor;

  /* Un-reachability reuse-index-array */
  u_int32_t rfd_unreach_reuse_idx_ary[BGP_RFD_REUSE_IDX_ARY_SIZE];
  /* Un-reachability reuse-index-array scale-factor */
  float64_t rfd_uscale_factor;

  /* List of RFD History Info elements assoc with this CB */
  struct bgp_rfd_hist_info *rfd_hinfo_list;
};

/* BGP RFD Config Unit */
struct bgp_rfd_cfg
{
  /* BGP RFD Control Blocks Linked-List */
  struct list *rfdg_rfd_cb_list;

  /* BGP RFD Route-map */
  struct bgp_rmap rfdg_rmap;

  /* AFI for this Config Block */
  afi_t rfdg_afi;

  /* SAFI for this Config Block */
  safi_t rfdg_safi;
};

/* Macro for stringizing Route State */
#define BGP_RFD_RT_STATE_STR(RT_STATE)                               \
  (((RT_STATE) == BGP_RFD_RT_STATE_NONE)   ? "Route State: NONE" :   \
   ((RT_STATE) == BGP_RFD_RT_STATE_USE)    ? "Route State: USE" :    \
   ((RT_STATE) == BGP_RFD_RT_STATE_DAMPED) ? "Route State: DAMPED" : \
                                             "Route State: INVALID")

/* Macro to check if Route is in HISTORY state */
#define BGP_RFD_RT_STATE_IS_HISTORY(BGP_INFO)                        \
  ((BGP_INFO)                                                        \
   && ((BGP_INFO)->rfd_hinfo)                                        \
   && ((BGP_INFO)->rfd_hinfo->rfdh_rec_event ==                      \
       BGP_RFD_RT_EVENT_UNREACH))

/* Macro to check if Route is in DAMPED state */
#define BGP_RFD_RT_STATE_IS_DAMPED(BGP_INFO)                         \
  ((BGP_INFO)                                                        \
   && ((BGP_INFO)->rfd_hinfo)                                        \
   && ((BGP_INFO)->rfd_hinfo->rfdh_suppress_time))

/* Macro to check if Route is in VALID state */
#define BGP_RFD_RT_STATE_IS_VALID(BGP_INFO)                          \
  (! BGP_RFD_RT_STATE_IS_HISTORY (BGP_INFO))

/* Macro to check if Route is in a Reuse List */
#define BGP_RFD_RT_IS_IN_REUSE_LIST(BGP_INFO)                        \
  ((BGP_INFO)                                                        \
   && ((BGP_INFO)->rfd_hinfo)                                        \
   && ((BGP_INFO)->rfd_hinfo->rfdh_reuse_idx !=                      \
       BGP_RFD_REUSE_LIST_INV_IDX))

/* Macro to check if Route has history record */
#define BGP_RFD_RT_HAS_RECORD(BGP_INFO)                              \
  ((BGP_INFO) && (BGP_INFO)->rfd_hinfo)

/* Macro to obtain Penalty value */
#define BGP_RFD_RT_GET_PENALTY(BGP_INFO)                             \
  (((BGP_INFO) && (BGP_INFO)->rfd_hinfo) ?                           \
   (BGP_INFO)->rfd_hinfo->rfdh_penalty : 0)

/* Macro to obtain Flap Count */
#define BGP_RFD_RT_GET_FLAP_COUNT(BGP_INFO)                          \
  (((BGP_INFO) && (BGP_INFO)->rfd_hinfo) ?                           \
   (BGP_INFO)->rfd_hinfo->rfdh_flap_count : 0)

/* Macro to obtain Duration of record */
#define BGP_RFD_RT_GET_RECORD_DURATION(BGP_INFO)                     \
  (((BGP_INFO) && (BGP_INFO)->rfd_hinfo) ?                           \
   (BGP_INFO)->rfd_hinfo->rfdh_rec_duration : 0)

/* Macro to obtain Time-to-reuse */
#define BGP_RFD_RT_GET_TIME_TO_REUSE(BGP_VR, BGP_INFO)               \
  (((BGP_VR)                                                         \
    && BGP_RFD_RT_IS_IN_REUSE_LIST(BGP_INFO)) ?                      \
    (((BGP_INFO)->rfd_hinfo->rfdh_reuse_idx >                        \
      (BGP_VR)->rfd_reuse_list_offset ?                              \
      ((BGP_INFO)->rfd_hinfo->rfdh_reuse_idx -                       \
       (BGP_VR)->rfd_reuse_list_offset) :                            \
      (BGP_INFO)->rfd_hinfo->rfdh_reuse_idx <                        \
      (BGP_VR)->rfd_reuse_list_offset ?                              \
      (BGP_RFD_REUSE_LIST_SIZE - (BGP_VR)->rfd_reuse_list_offset     \
       + (BGP_INFO)->rfd_hinfo->rfdh_reuse_idx) : 1) *               \
      BGP_RFD_REUSE_TICK) : 0)

/*
 * Function Prototype declarations
 */

s_int32_t
bgp_rfd_reuse_timer (struct thread *);
s_int32_t
bgp_rfd_non_reuse_timer (struct thread *);
s_int32_t
bgp_rfd_hinfo_create (struct bgp_rfd_cb *,
                      struct bgp_rfd_hist_info **);
s_int32_t
bgp_rfd_hinfo_delete (struct bgp_rfd_hist_info *);
s_int32_t
bgp_rfd_hinfo_free (struct bgp_rfd_hist_info *);
s_int32_t
bgp_rfd_hinfo_clear_flap_stats (struct bgp_rfd_hist_info *);
s_int32_t
bgp_rfd_rfdcb_list_insert (struct bgp_rfd_cb *,
                           struct bgp_rfd_hist_info *);
s_int32_t
bgp_rfd_rfdcb_list_remove (struct bgp_rfd_hist_info *);
s_int32_t
bgp_rfd_reuse_list_index (struct bgp_rfd_hist_info *);
s_int32_t
bgp_rfd_reuse_list_insert (struct bgp_rfd_hist_info *);
s_int32_t
bgp_rfd_reuse_list_remove (struct bgp_rfd_hist_info *);
s_int32_t
bgp_rfd_non_reuse_list_insert (struct bgp_rfd_hist_info *);
s_int32_t
bgp_rfd_non_reuse_list_remove (struct bgp_rfd_hist_info *);
s_int32_t
bgp_rfd_update_penalty (struct bgp_rfd_hist_info *,
                        enum bgp_rfd_rt_event);
s_int32_t
bgp_rfd_rt_withdraw (struct bgp *, struct bgp_peer *,
                     afi_t, safi_t,
                     struct bgp_node *, struct bgp_info *,
                     enum bgp_rfd_rt_state *);
s_int32_t
bgp_rfd_rt_update (struct bgp_info *,
                   enum bgp_rfd_rt_state *);
s_int32_t
bgp_rfd_cb_lookup (struct bgp *, afi_t, safi_t,
                   struct bgp_node *, struct bgp_info *,
                   struct bgp_rfd_cb **);
s_int32_t
bgp_rfd_cb_enable (struct bgp_rfd_cb *);
s_int32_t
bgp_rfd_cb_disable (struct bgp_rfd_cb *);
s_int32_t
bgp_rfd_cb_restart (struct bgp_rfd_cb *);
s_int32_t
bgp_rfd_cb_clear_flap_stats (struct bgp_rfd_cb *);
s_int32_t
bgp_rfd_cb_create (struct bgp_rfd_cfg *,
                   struct bgp_rfd_cb_cfg_param *,
                   struct bgp_rfd_cb **);
s_int32_t
bgp_rfd_cb_delete (struct bgp_rfd_cb *);
s_int32_t
bgp_rfd_cfg_create (struct bgp *, afi_t, safi_t,
                    struct bgp_rfd_cb_cfg_param *,
                    s_int8_t *);
s_int32_t
bgp_rfd_cfg_delete (struct bgp *, afi_t, safi_t);
s_int32_t
bgp_rfd_str2cfgparams (s_int8_t *,
                       struct bgp_rfd_cb_cfg_param *);
s_int32_t
bgp_rfd_config_write (struct cli *, struct bgp *,
                      afi_t, safi_t, u_int32_t *);
s_int32_t
bgp_rfd_config_show (struct cli *, struct bgp *,
                     afi_t, safi_t);

#endif /* _BGPSDN_BGP_DAMP_H */
