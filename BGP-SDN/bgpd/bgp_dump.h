/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

/* MRT compatible packet dump values.  */
/* type value */
#define MSG_PROTOCOL_BGP4MP  16
/* subtype value */
#define BGP4MP_STATE_CHANGE   0
#define BGP4MP_MESSAGE        1
#define BGP4MP_ENTRY          2
#define BGP4MP_SNAPSHOT       3

#define BGP_DUMP_HEADER_SIZE 12

enum bgp_dump_type
{
  BGP_DUMP_ALL,
  BGP_DUMP_UPDATES,
  BGP_DUMP_ROUTES,
  BGP_DUMP_TABLE
};

struct bgp_dump
{
  enum bgp_dump_type type;

  u_int8_t *filename;

  FILE *fp;

  u_int32_t interval;

  u_int8_t *interval_str;

  struct thread *t_interval;
};

/*
 * Function Prototype Declatations
 */

FILE *
bgp_dump_open_file (struct bgp_dump *);
s_int32_t
bgp_dump_interval_add (struct bgp_dump *, u_int32_t);
void
bgp_dump_header (struct stream *, u_int32_t, u_int32_t);
void
bgp_dump_set_size (struct stream *, u_int32_t);
void
bgp_dump_routes_attr (struct stream *, struct attr *);
void
bgp_dump_routes_entry (struct prefix *,
                       struct bgp_info *,
                       afi_t,
                       u_int32_t,
                       u_int32_t);
void
bgp_dump_routes_func (afi_t);
s_int32_t
bgp_dump_interval_func (struct thread *);
void
bgp_dump_common (struct stream *, struct bgp_peer *);
void
bgp_dump_state (struct bgp_peer *, u_int32_t, u_int32_t);
void
bgp_dump_packet_func (struct bgp_dump *,
                      struct bgp_peer *,
                      struct stream *);
void
bgp_dump_packet (struct bgp_peer *,
                 u_int32_t,
                 struct stream *);
u_int32_t
bgp_dump_parse_time (u_int8_t *);
s_int32_t
bgp_dump_set (struct cli *,
              struct bgp_dump *,
              u_int32_t,
              u_int8_t *,
              u_int8_t *);
s_int32_t
bgp_dump_unset (struct cli *, struct bgp_dump *);
s_int32_t
config_write_bgp_dump (struct cli *);
void
bgp_dump_cli_init (struct cli_tree *);
