/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.*/

#ifndef _PAL_STDLIB_H
#define _PAL_STDLIB_H

struct lib_globals;

#include "pal_stdlib.def"

#define pal_geteuid geteuid
#define pal_getegid getegid
#define pal_sysconf sysconf
#define pal_getenv getenv
#define pal_getcwd getcwd

#define pal_SC_PAGESIZE _SC_PAGESIZE

/*
** Exit
** 
** Parameters:
**   status
**
** Results:
**   Exits the current process or task
*/
#define pal_exit exit

/*
** Return a (pseudo)random number from 0 through RAND_MAX.  If the system has
** a real random number generator (radioactive decay or similar), it should
** probably use that instead of the pseudorandom number routine, unless the
** pseudorandom number routine is faster.
**
** Parameters
**   none
**
** Results
**   A (pseudo)random number from 0 through RAND_MAX, inclusive.
*/

#undef pal_rand
#define pal_rand rand

#undef pal_srand
#define pal_srand srand

#undef pal_qsort
#define pal_qsort qsort

#undef pal_div32
#define pal_div32 ldiv

#undef pal_uname
#define pal_uname uname

#undef pal_atoi
#define pal_atoi(x) atoi(x)

/* BGP-SDN00068634 : typdef added for atol() */
#undef pal_atol
#define pal_atol(x) atol(x)
#undef pal_atoll
#define pal_atoll(x) atoll(x)
/* BGP-SDN00068634 : ends */

#undef pal_popen
#define pal_popen popen

#undef pal_pclose
#define pal_pclose pclose

extern char *pal_get_sys_name ();
#endif /* _PAL_STDLIB_H */
