/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.*/

#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

gid_t
pal_get_gid_by_name (const char *name)
{
  struct group *grp;
  grp = getgrnam(name);
  if (grp)
    return grp->gr_gid;
  else
    return -1;
}
 
int
pal_chown (const char *path, const char *gr_name)
{
  return chown (path, -1, pal_get_gid_by_name (gr_name));
}

int
pal_chmod (const char *path, mode_t mode)
{
  return chmod (path, mode);
}

