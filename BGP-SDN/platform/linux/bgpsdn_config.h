/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */
#ifndef _BGPSDN_CONFIG_H
#define _BGPSDN_CONFIG_H

/* Define if you have the ANSI C header files.  */
#ifndef STDC_HEADERS 
#define STDC_HEADERS 1
#endif /* STDC_HEADERS */

/* Define if you have the inet_aton function.  */
/* Don't use the VxWorks one as it gives a wrong output */
#ifndef HAVE_INET_ATON 
#define HAVE_INET_ATON 1
#endif /* HAVE_INET_ATON */ 

/* whether sockaddr has a sa_len field */
#ifndef HAVE_SA_LEN
#define HAVE_SA_LEN
#endif /* HAVE_SA_LEN */

/* whether in_pktinfo is supported.  */
#ifndef HAVE_IN_PKTINFO 
#define HAVE_IN_PKTINFO 1
#endif /* STDC_HEADERS */


/* whether sockaddr_in has a sin_len field */
#undef HAVE_SIN_LEN

/* whether sockaddr_un has a sun_len field */
#ifndef HAVE_SUN_LEN
#undef HAVE_SUN_LEN
#endif /* HAVE_SUN_LEN */

/* have IPv6 scope id */
#ifndef HAVE_SIN6_SCOPE_ID
#define HAVE_SIN6_SCOPE_ID
#endif /* HAVE_SIN6_SCOPE_ID */

/* have sin6_len. */
#ifndef HAVE_SIN6_LEN
#define HAVE_SIN6_LEN
#endif /* HAVE_SIN6_LEN */

/* Define if there is socklen_t. */
#ifndef HAVE_SOCKLEN_T 
#define HAVE_SOCKLEN_T 
#endif /* HAVE_SOCKLEN_T  */

/* Define if there is sockaddr_dl structure. */
#ifndef HAVE_SOCKADDR_DL
#define HAVE_SOCKADDR_DL
#endif /* HAVE_SOCKADDR_DL */

/* Define if there is ifaliasreq structure. */
#ifndef HAVE_IFALIASREQ
#define HAVE_IFALIASREQ
#endif /* HAVE_IFALIASREQ */

/* Define if there is in6_aliasreq structure. */
#ifndef HAVE_IN6_ALIASREQ
#define HAVE_IN6_ALIASREQ
#endif /* HAVE_IN6_ALIASREQ */

/* Define if there is rt_addrinfo structure. */
#ifndef HAVE_RT_ADDRINFO
#define HAVE_RT_ADDRINFO
#endif /* HAVE_RT_ADDRINFO */

/* Define if there is nd_opt_advinterval structure. */
/* #undef HAVE_ND_OPT_ADVINTERVAL */

/* Define if there is nd_opt_homeagent_info atructure. */
/* #undef HAVE_ND_OPT_HOMEAGENT_INFO */

/* Define if there is ha_discov_req structure. */
/* #undef HAVE_HA_DISCOV_REQ */

/* Define if there is ha_discov_rep structure. */
/* #undef HAVE_HA_DISCOV_REP */

/* Define if NET_RT_IFLIST exists in sys/socket.h. */
#ifndef HAVE_NET_RT_IFLIST
#define HAVE_NET_RT_IFLIST
#endif /* HAVE_NET_RT_IFLIST */

/* Define if interface aliases don't have distinct indeces */
/* #undef HAVE_BROKEN_ALIASES */

/* PAM support */
/* #undef USE_PAM */

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif /* HAVE_SOCKLEN_T */


/* Define if you have the getaddrinfo function.  */
/* #define HAVE_GETADDRINFO 1 */

/* Define if you have the getifaddrs function.  */
/* #undef HAVE_GETIFADDRS */

/* Define if you have the inet_aton function.  */
#ifndef HAVE_INET_ATON 
#define HAVE_INET_ATON 1
#endif /* HAVE_INET_ATON */

/* Define if you have the snprintf function.  */
/*#define HAVE_SNPRINTF 1*/

/* Define if you have the strerror function.  */
#ifndef HAVE_STRERROR 
#define HAVE_STRERROR 1
#endif /* HAVE_STRERROR */

/* Define if you have the strlcpy function.  */
/* #undef HAVE_STRLCPY */

/* Define if you have the <netdb.h> header file.  */
#ifndef HAVE_NETDB_H 
#define HAVE_NETDB_H 1
#endif /* HAVE_NETDB_H */

/* Define if you have the <netinet/in.h> header file.  */
#ifndef HAVE_NETINET_IN_H 
#define HAVE_NETINET_IN_H 1
#endif /* HAVE_NETINET_IN_H */

/* Define if you have the <netinet/in_var.h> header file.  */
/* #undef HAVE_NETINET_IN_VAR_H */

/* Define if you have the <string.h> header file.  */
#ifndef HAVE_STRING_H 
#define HAVE_STRING_H 1
#endif /* HAVE_STRING_H */

/* Define if you have the <sys/select.h> header file.  */
#ifndef HAVE_SYS_SELECT_H 
#define HAVE_SYS_SELECT_H 1
#endif /* HAVE_SYS_SELECT_H */

/* Define if you have the <sys/sockio.h> header file.  */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define if you have the <sys/sysctl.h> header file.  */
#ifndef HAVE_SYS_SYSCTL_H 
#define HAVE_SYS_SYSCTL_H 1
#endif /* HAVE_SYS_SYSCTL_H */

/* Define if you have the <sys/time.h> header file.  */
#ifndef HAVE_SYS_TIME_H 
#define HAVE_SYS_TIME_H 1
#endif /* HAVE_SYS_TIME_H */

/* Define if you have the <sys/times.h> header file.  */
#ifndef HAVE_SYS_TIMES_H 
#define HAVE_SYS_TIMES_H 1
#endif /* HAVE_SYS_TIMES_H */

/* Define if you have the <sys/types.h> header file.  */
#ifndef HAVE_SYS_TYPES_H 
#define HAVE_SYS_TYPES_H 1
#endif /* HAVE_SYS_TYPES_H */

#endif /* _BGPSDN_CONFIG_H */
