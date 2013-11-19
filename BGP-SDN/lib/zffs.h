/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_FFS_H
#define _BGPSDN_FFS_H

#ifdef HAVE_FFS
#undef  zffs
#define zffs ffs
#else
int     zffs (u_int32_t);
#endif /* HAVE_FFS */

#endif /* _BGPSDN_FFS_H */
