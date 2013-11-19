/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.*/

/* pal_posix.h -- POSIX calls.  */
#ifndef _PAL_POSIX_H
#define _PAL_POSIX_H

#include "pal_posix.def"

#undef pal_get_process_id
#define pal_get_process_id      getpid

#undef PAL_S_IRWXU
#define PAL_S_IRWXU S_IRWXU
#undef PAL_S_IRUSR
#define PAL_S_IRUSR S_IRUSR
#undef PAL_S_IWUSR
#define PAL_S_IWUSR S_IWUSR
#undef PAL_S_IXUSR
#define PAL_S_IXUSR S_IXUSR
                                                                                
#undef PAL_S_IRWXG
#define PAL_S_IRWXG S_IRWXG
#undef PAL_S_IRGRP
#define PAL_S_IRGRP S_IRGRP
#undef PAL_S_IWGRP
#define PAL_S_IWGRP S_IWGRP
#undef PAL_S_IXGRP
#define PAL_S_IXGRP S_IXGRP

#undef PAL_S_IRWXO
#define PAL_S_IRWXO S_IRWXO
#undef PAL_S_IROTH
#define PAL_S_IROTH S_IROTH
#undef PAL_S_IWOTH
#define PAL_S_IWOTH S_IWOTH
#undef PAL_S_IXOTH
#define PAL_S_IXOTH S_IXOTH

#define PID_REGISTER(P)                                      \
  do {                                                       \
    pid_t pid = getpid();                                    \
    FILE *fp = fopen (P, "w");                               \
    if (fp != NULL)                                          \
      {                                                      \
        chmod (P, (S_IROTH | S_IRGRP | S_IRUSR | S_IWUSR));  \
        fprintf (fp, "%d\n", (int) pid);                     \
        fclose (fp);                                         \
      }                                                      \
  } while (0)

#define PID_REMOVE(P)           remove (P)

gid_t pal_get_gid_by_name (const char *);
int pal_chown (const char *, const char *);
int pal_chmod (const char *, mode_t);

#endif /* _PAL_POSIX_H */
