/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <pal.h>
#include <lib.h>

#include "modbmap.h"
#include "message.h"
#include "line.h"
#include "cli.h"
#include "tlv.h"
#include "snprintf.h"

/* #define _LINE_DEBUG */

void
line_header_encode (struct line *line)
{
  u_char *ptr = (u_char *)line->buf;
  u_char **pnt = &ptr;
  u_int16_t length = LINE_HEADER_LEN;
  u_int16_t *size = &length;

  /* Set length.  */
  line->length = LINE_HEADER_LEN;
  if (line->str)
    line->length += pal_strlen (line->str) + 1;

#ifdef _LINE_DEBUG
  printf("\n ENC this:%d sid:%d len:%d key:%d code:%d mode:%d vr:%d buf:%-16s",
         pal_get_process_id(),
         line->pid, line->length, line->key, line->code, line->mode, line->vr_id,
         line->str);
  modbmap_printvalue (line->module);
#endif

  /* Length.  */
  TLV_ENCODE_PUTW (line->length);

  /* CLI key.  */
  TLV_ENCODE_PUTW (line->key);

  /* Module.  */
  TLV_ENCODE_PUT_MODBMAP (line->module);

  /* Code.  */
  TLV_ENCODE_PUTC (line->code);

  /* Reserved.  */
  TLV_ENCODE_PUTC (0);

  /* Mode.  */
  TLV_ENCODE_PUTC (line->mode);

  /* Privilege.  */
  TLV_ENCODE_PUTC (line->privilege);

  /* VR ID.  */
  TLV_ENCODE_PUTL (line->vr_id);

  /* Configuration ID.  */
  TLV_ENCODE_PUTL (line->config_id);

  /* IMISH's PID or VTY's socket number */
  TLV_ENCODE_PUTL (line->pid);
}

void
line_header_decode (struct line *line)
{
  u_char *ptr = (u_char *)line->buf;
  u_char **pnt = &ptr;
  u_int16_t length = line->length;
  u_int16_t *size = &length;

  /* Length.  */
  TLV_DECODE_GETW (line->length);

  /* CLI key.  */
  TLV_DECODE_GETW (line->key);

  /* Module.  */
  TLV_DECODE_GET_MODBMAP (line->module);

  /* Code.  */
  TLV_DECODE_GETC (line->code);

  /* Reserved.  */
  TLV_DECODE_SKIP (1);

  /* Mode.  */
  TLV_DECODE_GETC (line->mode);

  /* Previllege */
  TLV_DECODE_GETC (line->privilege);

  /* VR ID.  */
  TLV_DECODE_GETL (line->vr_id);

  /* Configuration ID.  */
  TLV_DECODE_GETL (line->config_id);

  /* IMISH's PID or VTY's socket number  */
  TLV_DECODE_GETL (line->pid);

  /* Line string.  */
  line->str = &line->buf[LINE_HEADER_LEN];

  /* Reset strings.  */
  if (line->length == LINE_HEADER_LEN)
    line->str[0] = '\0';

#ifdef _LINE_DEBUG
  printf("\n DEC this:%d sid:%d len:%d key:%d code:%d mode:%d vr:%d <be4 recv string>",
         pal_get_process_id(),
         line->pid, line->length, line->key, line->code, line->mode, line->vr_id);
  modbmap_printvalue (line->module);
#endif
}


int
line_out (struct cli *cli, const char *format, ...)
{
  struct line *line = cli->line;

  va_list args;
  va_start (args, format);
  line->str = &line->buf[LINE_HEADER_LEN];
  zvsnprintf (line->str, LINE_BODY_LEN, format, args);
  va_end (args);

  return 0;
}

void
line_error_out (struct line *line, const char *format, ...)
{
  va_list args;
  va_start (args, format);
  zvsnprintf (line->str, LINE_BODY_LEN, format, args);
  va_end (args);
}

/* Generic "line" parser for IMI client (except IMISH).  */
int
line_parser (struct line *line, struct imi_confses *confses)
{
  int ret;
  struct cli_node *node;
  struct cli *cli = &line->cli;
  struct cli_tree *ctree = line->zg->ctree;

  /* Parse the line.  */
  ret = cli_parse (ctree, line->mode, line->privilege, line->str, 1, 0);

  switch (ret)
  {
  case CLI_PARSE_SUCCESS:
    node = ctree->exec_node;

    /* CLI preparation.  */
    cli->zg = line->zg;
    cli->vr = line->vr;
    cli->line = line;
    cli->mode = line->mode;
    cli->out_func = (CLI_OUT_FUNC) line_out;
    cli->out_val = cli;

    cli->index     = IMI_CONFSES_GET_INDEX(confses);
    cli->index_sub = IMI_CONFSES_GET_INDEX_SUB(confses);

    LIB_GLOB_SET_VR_CONTEXT (cli->zg, cli->vr);

    /* Call function.  */
    ret = (*node->cel->func) (cli, ctree->argc, ctree->argv);

    /* Output buffer may have error string.  */
    switch (ret)
    {
    case CLI_SUCCESS:
      /* Save the session only in case of SUCCESS
         We will prevent PM inconsistency when it assigns a new index
         but returns here with an error.
      */
      IMI_CONFSES_SET_INDEX(confses,cli->index);
      IMI_CONFSES_SET_INDEX_SUB(confses,cli->index_sub);
      IMI_CONFSES_SET_MODE(confses,cli->mode);
      line->code = LINE_CODE_SUCCESS;
      break;
    case CLI_EOL:
      line->code = LINE_CODE_EOL;
      break;
    case CLI_AUTH_REQUIRED:
      line->code = LINE_CODE_AUTH_REQUIRED;
      break;
    case CLI_ERROR:
    default:
      /* Error is returned, error string may be put by line_out()
   function. */
      line->code = LINE_CODE_ERROR;
      break;
    }
    break;

    /* These errors does not generate error string. */
  case CLI_PARSE_NO_MATCH:
    /* No matched command.  */
    line_error_out (line, "%% No such command\n");
  case CLI_PARSE_INCOMPLETE:
  case CLI_PARSE_INCOMPLETE_PIPE:
  case CLI_PARSE_EMPTY_LINE:
  case CLI_PARSE_AMBIGUOUS:
  case CLI_PARSE_NO_MODE:
  default:
    line->code = LINE_CODE_ERROR;
    break;
  }
  cli_free_arguments (ctree);

  /* The rest moved to the imi_client, where it belongs. */

  return 0;
}

