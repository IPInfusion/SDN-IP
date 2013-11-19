/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_LINE_H
#define _BGPSDN_LINE_H

#include "cli.h"
#include "imi_confses.h"

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Length             |            CLI Key            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Module                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Code     |    Reserved   |     Mode      |   Privilege   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             VR ID                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Configuration ID                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 IMISH's PID or VTY socket#                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Message  .....
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/* Line length. */
#define LINE_MESSAGE_MAX                                         512
#define LINE_HEADER_LEN                    (20 + sizeof (modbmap_t))
#define LINE_BODY_LEN           (LINE_MESSAGE_MAX - LINE_HEADER_LEN)

/* "line" structure.  */
struct line
{
  /* Global pointer.  */
  struct lib_globals *zg;

  /* Flags.  */
  u_char flags;
#define LINE_FLAG_UP                                        (1 << 0)
#define LINE_FLAG_MONITOR                                   (1 << 1)

  /* Configuration flags.  */
  u_char config;
#define LINE_CONFIG_LOGIN                                   (1 << 0)
#define LINE_CONFIG_LOGIN_LOCAL                             (1 << 1)
#define LINE_CONFIG_PRIVILEGE                               (1 << 2)
#define LINE_CONFIG_TIMEOUT                                 (1 << 3)
#define LINE_CONFIG_HISTORY                                 (1 << 4)

  /* Line types.  */
  u_char type;
#define LINE_TYPE_CONSOLE                                          0
#define LINE_TYPE_AUX                                              1
#define LINE_TYPE_VTY                                              2
#define LINE_TYPE_MAX                                              3

#define LINE_TYPE_STR(T)                                                      \
    ((T) == LINE_TYPE_CONSOLE ? "con" :                                       \
     (T) == LINE_TYPE_AUX ?     "aux" :                                       \
     (T) == LINE_TYPE_VTY ?     "vty" : "(null)")

  /* Index of this line.  */
  u_int32_t index;
#define LINE_CONSOLE_MIN                                           0
#define LINE_CONSOLE_MAX                                         128
#define LINE_AUX_MIN                                             129
#define LINE_AUX_MAX                                             129
#define LINE_VTY_MIN                                             130
#define LINE_VTY_MAX                                            1001

#define LINE_CONSOLE_DEFAULT                                       1
#define LINE_AUX_DEFAULT                                           1
#define LINE_VTY_DEFAULT                                          40

#define LINE_TYPE_INDEX(T, I)                                                 \
    ((T) == LINE_TYPE_CONSOLE ? (I) + LINE_CONSOLE_MIN :                      \
     (T) == LINE_TYPE_AUX     ? (I) + LINE_AUX_MIN :                          \
     (T) == LINE_TYPE_VTY     ? (I) + LINE_VTY_MIN : 0)

  /* Total length of the line message.  */
  u_int16_t length;

  /* Key to the CLI.  */
  u_int16_t key;

  /* Module to be executed.  */
  modbmap_t module;

  /* Line code.  */
  u_char code;
#define LINE_CODE_SUCCESS                                          0
#define LINE_CODE_ERROR                                            1
#define LINE_CODE_COMMAND                                          2
#define LINE_CODE_EOL                                              3
#define LINE_CODE_AUTH_REQUIRED                                    4
#define LINE_CODE_CONNECT                                          5
#define LINE_CODE_CONTEXT_SET                                      6
#define LINE_CODE_CONFIG_REQUEST                                   7
#define LINE_CODE_CONFIG_END                                       8
/* Used to notify the PM that the IMI session shall be
   cleared.This may be used when the IMISH is killed or
   the config context is switched to another PM (module).
*/
#define LINE_CODE_CONFSES_CLR                                      9
/* Used to request the IMI to download all non-PVRs instances.
   In response the IMI sends one "vr-instance" command per VR.
 */
#define LINE_CODE_GET_VRS_REQUEST                                 10

  /* Max History accepted */
  u_int32_t maxhist;

  /* Mode.  */
  u_char mode;

  /* Privilege.  */
  u_char privilege;

  /* User string.  */
  char *str;

  /* Read buffer.  */
  char buf[LINE_MESSAGE_MAX];

  /* Exec timeout.  */
  u_int32_t exec_timeout_min;
  u_int32_t exec_timeout_sec;
#define LINE_TIMEOUT_DEFAULT_MIN                                  10
#define LINE_TIMEOUT_DEFAULT_SEC                                   0

  /* Running CLI status.  */
  struct cli cli;

  /* User id. */
  char *user;

  /* TTY. */
  char *tty;

  /* Pid.  */
  pid_t pid;

  /* Socket.  */
  pal_sock_handle_t sock;

  /* VR ID.  */
  u_int32_t vr_id;

  /* Configuration ID. */
  u_int32_t config_id;

  /* VR.  */
  struct ipi_vr *vr;
};

/* Each "line" port. */
#define IMI_LINE_PORT           3001
#ifdef HAVE_SPLAT
#define IMI_LINE_PATH           "/var/opt/OPSEC/ipinfusion/tmp/.imi_line"
#else /* HAVE_SPLAT */
#define IMI_LINE_PATH           "/tmp/.imi_line"
#endif /* HAVE_SPLAT */

/* Encode and decode routine.  */
void line_header_encode (struct line *);
void line_header_decode (struct line *);
int line_out (struct cli *, const char *, ...);
void line_error_out (struct line *, const char *, ...);
int line_parser (struct line *, struct imi_confses *confses);

#endif /* _BGPSDN_LINE_H */

