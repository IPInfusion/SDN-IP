/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.  */

#include "pal.h"

#ifdef MEMMGR

#include "lib.h"
#include "cli.h"
#include "memory.h"

#include "memmgr/memmgr.h"
#include "memmgr/memmgr_config.h"
#include "memmgr/memmgr_cli.h"


/* Map a protocol string to protocol id and return.  */
int
memmgr_get_protocol_id (char *pstr)
{
  if (!pal_strncmp ("nsm", pstr, 1))
    return IPI_PROTO_NSM;
  else if (!pal_strncmp ("lib", pstr, 2))
    return IPI_PROTO_UNSPEC;
  else if (!pal_strncmp ("imi", pstr, 2))
    return IPI_PROTO_IMI;
  else if (!pal_strncmp ("rip", pstr, 2))
    return IPI_PROTO_RIP;
  else if (!pal_strncmp ("ipv6 rip", pstr, 6))
    return IPI_PROTO_RIPNG;
  else if (!pal_strncmp ("ospf", pstr, 1))
    return IPI_PROTO_OSPF;
  else if (!pal_strncmp ("ipv6 ospf", pstr, 6))
    return IPI_PROTO_OSPF6;
  else if (!pal_strncmp ("isis", pstr, 2))
    return IPI_PROTO_ISIS;
  else if (!pal_strncmp ("bgp", pstr, 1))
    return IPI_PROTO_BGP;
  else if (!pal_strncmp ("ldp", pstr, 2))
    return IPI_PROTO_LDP;
  else if (!pal_strncmp ("rsvp", pstr, 3))
    return IPI_PROTO_RSVP;
  else if (!pal_strncmp ("pim", pstr, 3))
    return IPI_PROTO_PIM;
  else if (!pal_strncmp ("dvmrp", pstr, 2))
    return IPI_PROTO_DVMRP;
  else if (!pal_strncmp ("dot1x", pstr, 2)
           || !pal_strncmp ("auth", pstr, 1))
    return IPI_PROTO_8021X;
  else if (!pal_strncmp ("onmd", pstr, 2))
    return IPI_PROTO_ONM;
  else if (!pal_strncmp ("lacp", pstr, 2))
    return IPI_PROTO_LACP;
  else if (!pal_strncmp ("stp", pstr, 1))
    return IPI_PROTO_STP;
  else if (!pal_strncmp ("rstp", pstr, 3))
    return IPI_PROTO_RSTP;
  else if (!pal_strncmp ("mstp", pstr, 2))
    return IPI_PROTO_MSTP;
  else if (!pal_strncmp ("elmi", pstr, 2))
    return IPI_PROTO_ELMI;
  else
    return -1;
}

/* Return TRUE if a given protocol module is enabled.  */
int
memmgr_check_enable_module_sts (int pmodule)
{
  modbmap_t active_pms;

  active_pms = memory_active_modules ();

  /* check if the bit corresponding to this module is set */
  if (MODBMAP_ISSET (active_pms, pmodule))
    return 1;

  return 0;
}

/*
 *  memmgr_print_module_separator ()
 *
 *  Prints a module separator string for mtype display.
 */
void
memmgr_print_module_separator (struct cli *cli)
{
    char *format = "----------------------------------- ------------- ---------------\n";

    cli_out (cli, format);
}

/*
 *   memmgr_print_memory_header ()
 *
 *   Displays memory column headers
 */
void
memmgr_print_memory_header (struct cli *cli)
{
    char *format1 = "Memory type                          Alloc cells   Alloc bytes  \n";
    char *format2 = "=================================== ============= ===============\n";

    cli_out (cli, "%s%s", format1, format2);
}

/*
 *   memmgr_print_mtype_header ()
 *
 *   Displays memory column headers
 */
void
memmgr_print_mtype_header (struct cli *cli)
{
    char *format1 = "Memory type                          Alloc cells   Alloc bytes \n";
    char *format2 = "=================================== ============= ===============\n";
    cli_out (cli, "%s%s", format1, format2);
}

/*
 *   memmgr_print_mtype_stats()
 *
 *   Display a given mtype and module stats
 */
void
memmgr_print_mtype_stats (struct cli *cli, char *str, int size, int count)
{
    cli_out (cli,
             "%-34s:%12d %15d\n",
             (str == NULL) ? "NULL" : str,
             count,
             size);
}


/*
 *  show_memory_all ()
 *
 *  Display memory stats of each mtype of each module.
 */
CLI (show_memory_all,
     show_memory_all_cli,
     "show memory (all|)",
     CLI_SHOW_STR,
     CLI_SHOW_MEMORY_STR,
     "All memory information")
{
     int  i, j;
     char *mptr;
     int  size;
     int  count;

     memmgr_print_memory_header (cli);

     for (i = 0; i < IPI_PROTO_MAX; i++)
       {
         /* display memory stats only if this module is enabled */
         if (i && !memmgr_check_enable_module_sts (i))
           continue;

         for (j = 0; j < MTYPE_MAX; j++)
           {
             /* skip if mtype id don't match protocol id */
             if (memmgr_match_protocol_id (i, j) < 0)
               continue;

             /* get mtype description string */
             mptr = memmgr_get_mtype_str (j);

             /* get total byte count allocated for this mtype */
             size = memmgr_get_mtype_size (j);

             /* get number of blocks allocated for this mtype */
             count = memmgr_get_mtype_count (j);

             /* print if only some memory is allocated for this mtype */
             if (count)
               memmgr_print_mtype_stats (cli, mptr, size, count);
           }
         memmgr_print_module_separator (cli);
       }

    return CLI_SUCCESS;
}

/*
 *   Allow IMI call this function directly
 */
int
memmgr_show_memory_module (struct cli *cli, int id)
{
     int    i;
     char   *mptr;
     int    count;
     int    size;

     /* display memory stats only if this module is enabled */
     if (!memmgr_check_enable_module_sts (id))
       return CLI_ERROR;

     memmgr_print_memory_header (cli);

     for (i = 0; i < MTYPE_MAX; i++)
       {
         /* skip if mtype id don't match protocol id */
         if (memmgr_match_protocol_id (id, i) < 0)
           continue;

         /* get mtype description string */
         mptr = memmgr_get_mtype_str (i);

         /* get total byte count allocated for this mtype */
         size = memmgr_get_mtype_size (i);

         /* get number of blocks allocated for this mtype */
         count = memmgr_get_mtype_count (i);

         /* print only whem mtype memory is allocated */
         if (count)
           memmgr_print_mtype_stats (cli, mptr, size, count);
       }

    return CLI_SUCCESS;
}


/*
 *  show_memory_module ()
 *
 *  Display mtype stats of a given protocol module.
 */
CLI (show_memory_module,
     show_memory_module_cli,
     "show memory LINE",
     CLI_SHOW_STR,
     CLI_SHOW_MEMORY_STR,
     "Specific module memory stats")
{
     int    proto_id;

     if ((proto_id = memmgr_get_protocol_id (argv[0])) < 0)
        return CLI_ERROR;

     memmgr_show_memory_module (cli, proto_id);

     return CLI_SUCCESS;
}

/*
 *  memmgr_show_memory_mtype ()
 *
 *  Display stats of a given mtype for each PM
 */
int
memmgr_show_memory_mtype (struct cli *cli, int mtype_id)
{
     int   mtype_max;
     int   count;
     char  *mptr;
     int   size;

     /* the mtype max might vary based on the enabled options.
      * Return a warning if it exceeds the max. */
     mtype_max = memmgr_get_mtype_max ();
     if (mtype_id > mtype_max)
       {
         cli_out (cli, "Exceeded max mtype id %d\n", mtype_max);
         return CLI_SUCCESS;
       }

     /* get mtype description string */
     mptr = memmgr_get_mtype_str (mtype_id);

     /* get total byte count allocated for this mtype */
     size = memmgr_get_mtype_size (mtype_id);

     /* get number of blocks allocated for this mtype */
     count = memmgr_get_mtype_count (mtype_id);

     memmgr_print_mtype_header (cli);

     memmgr_print_mtype_stats (cli, mptr, size, count);

     return CLI_SUCCESS;
}

/*
 *  memmgr_show_memory_summary ()
 *
 *  Display memory summary for a given PM
 */
int
memmgr_show_memory_summary (struct cli *cli)
{
     int  size;
     int  count;
     unsigned int req_size;
     unsigned int total_size;
     unsigned int total_count;
     int i;

     /* get total bytes allocated */
     size = memmgr_get_total_mtype_size ();

     /* get total count of blocks allocated */
     count = memmgr_get_total_mtype_count ();

     cli_out (cli, "  Total preallocated memory size:                %d\n",
              memmgr_get_pa_mem_size ());
     cli_out (cli, "  Total preallocated memory overhead:            %d\n",
              memmgr_get_pa_mem_overhead ());
     cli_out (cli, "  Total preallocated memory blocks:              %d\n",
              memmgr_get_pa_mem_blocks ());

     cli_out (cli, "\n");

     cli_out (cli, "  Total on demand allocated memory size:         %d\n",
              memmgr_get_rt_mem_size ());
     cli_out (cli, "  Total on demand allocated memory overhead:     %d\n",
              memmgr_get_rt_mem_overhead ());
     cli_out (cli, "  Total on demand allocated memory count:        %d\n",
              memmgr_get_rt_mem_blocks ());

     cli_out (cli, "\n");

     req_size = memmgr_get_total_mtype_req_size ();

     cli_out (cli, "  Requested ZebOS memory size:                   %d\n", req_size);
     cli_out (cli, "  Allocated ZebOS memory size:                   %d\n", size);
     cli_out (cli, "  Allocated ZebOS memory blocks:                 %d\n", count);
     cli_out (cli, "\n");

     total_count = 0;
     total_size = 0;

     for (i = 0; i < BUKT_COUNT; i++)
       {
         total_size  += memmgr_get_bucket_size (i);
         total_count += memmgr_get_bucket_count (i);
       }

     cli_out (cli, "  Total memory left in the free pool:            %d\n", total_size);
     cli_out (cli, "  Total blocks left in the free pool:            %d\n", total_count);
     cli_out (cli, "\n");

     return CLI_SUCCESS;
}


/*
 *  show_memory_summary ()

 *  Display the complete summary of allocated and free memory stats
 */
CLI (show_memory_summary,
     show_memory_summary_cli,
     "show memory summary",
     CLI_SHOW_STR,
     CLI_SHOW_MEMORY_STR,
     "Summary of memory statistics")
{
     memmgr_show_memory_summary (cli);

     return CLI_SUCCESS;
}

/*
 *  memmgr_show_memory_free ()
 *
 *  Display free memory for a given PM.
 */
int
memmgr_show_memory_free (struct cli *cli)
{
     int  i;
     int  count;
     int  block_size;
     unsigned int total_size;

     cli_out (cli, "Block size        Total bytes       Block count\n");
     cli_out (cli, "===============  ===============  ==============\n");

     for (i = 0; i < BUKT_COUNT; i++)
       {
         block_size = memmgr_get_bucket_block_size (i);

         /* total free size available */
         total_size  = memmgr_get_bucket_size (i);

         /* number of of free blocks available */
         count = memmgr_get_bucket_count (i);

         cli_out (cli, "%-18d %-16d %-16d\n", block_size, total_size, count);
       }

     return CLI_SUCCESS;
}

/*
 *   show_memory_free()
 *
 *    Display stats of free memory.
 */
CLI (show_memory_free,
     show_memory_free_cli,
     "show memory free",
     CLI_SHOW_STR,
     CLI_SHOW_MEMORY_STR,
     "Statistics of free memory")
{
     memmgr_show_memory_free (cli);

     return CLI_SUCCESS;
}

/*
 *   memmgr_cli_init()
 *
 *   Initialize the memory related CLI commands here.
 *
 */
int
memmgr_cli_init (struct lib_globals * lib_node)
{
    struct cli_tree *ctree;

    ctree = lib_node->ctree;

    cli_install (ctree, EXEC_MODE, &show_memory_all_cli);
    cli_install (ctree, EXEC_MODE, &show_memory_module_cli);

    cli_install (ctree, EXEC_MODE, &show_memory_summary_cli);
    cli_install (ctree, EXEC_MODE, &show_memory_free_cli);

    return RESULT_OK;
}

#endif /* MEMMGR */
