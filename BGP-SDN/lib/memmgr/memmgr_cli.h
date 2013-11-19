/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */

#ifndef _MEMMGR_CLI_H
#define _MEMMGR_CLI_H

int memmgr_cli_init (struct lib_globals * lib_node);
int memmgr_show_memory_summary (struct cli *);
int memmgr_show_memory_free (struct cli *);
int memmgr_show_memory_module (struct cli *, int);

#endif /* _MEMMGR_CLI_H */
