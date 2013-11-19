/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved. */

#ifndef _PAL_FILE_H
#define _PAL_FILE_H

#define PAL_CONSOLE_PATH        "/dev/console"

#ifdef HAVE_SPLAT
#undef PATH_SYSCONFDIR
#define PATH_SYSCONFDIR         "/var/opt/OPSEC/ipinfusion/BGP-SDN-SRS/etc"
#endif /* HAVE_SPLAT */

#define PAL_FILE_SUFFIX         "conf"
#define PAL_FILE_SEPARATOR      '/'

#define PAL_OPEN_RO             "r"
#define PAL_OPEN_RW             "w+"

#define PAL_DIR_MODE            0755

#define PAL_FILE_DEFAULT_LINELEN        512

/* Standard file descriptors */
#define PAL_STDIN_FILENO  STDIN_FILENO  /* Standard input */
#define PAL_STDOUT_FILENO STDOUT_FILENO /* Standard output */
#define PAL_STDERR_FILENO STDERR_FILENO /* Standard error output */

#undef PAL_EOF
#define PAL_EOF EOF

#undef pal_fopen
#ifdef HAVE_NO_STORAGE_DEV
#define pal_fopen(A,B) NULL  
#else  /* HAVE_NO_STORAGE_DEV */
#define pal_fopen fopen
#endif /* HAVE_NO_STORAGE_DEV */

#undef pal_fclose
#define pal_fclose fclose

#undef pal_fgets
#define pal_fgets fgets

#undef pal_fputs
#define pal_fputs fputs

#undef pal_fprintf
#define pal_fprintf fprintf

#undef pal_feof
#define pal_feof feof

#undef pal_fscanf
#define pal_fscanf fscanf

#undef pal_fwrite
#define pal_fwrite fwrite

#undef pal_fflush
#define pal_fflush fflush

#undef pal_unlink
#define pal_unlink unlink

#undef pal_rename
#define pal_rename rename

#undef pal_mkdir
#define pal_mkdir mkdir

#undef pal_rmdir
#define pal_rmdir rmdir

#undef pal_fseek
#define pal_fseek fseek

#undef PAL_SEEK_SET
#define PAL_SEEK_SET SEEK_SET

#undef PAL_SEEK_CUR
#define PAL_SEEK_CUR SEEK_CUR

#undef PAL_SEEK_END
#define PAL_SEEK_END SEEK_END

#endif /* _PAL_FILE_H */
