#
# #Configure template file for BGP-SDN.
## autoconf will generate configure script.
##
##  Copyright (c) 2013 IP Infusion Inc.
##
AC_PREREQ([2.63])

AC_INIT([BGP-SDN], [1.0])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE
AC_GNU_SOURCE

dnl 	$Id: configure.ac,v 1.276.4.14 2013/01/15 19:46:34 bob.macgill Exp $	

dnl -----------------------------------
dnl Get hostname and other information.
dnl -----------------------------------
AC_CANONICAL_HOST

dnl ------------
dnl Check CFLAGS
dnl ------------
if test -n "$CFLAGS" ; then
   cflags_specified=yes
else
   CFLAGS="-g -O"
fi

dnl --------
dnl Check CC
dnl --------
AC_PROG_CC
# Check and see if these compiler options are supported....
if test "x$GCC" = "xyes" ; then
   echo "main() {}" >conftest.c
   # Check -Wno-pointer-sign
   AC_MSG_CHECKING([if gcc accepts -Wno-pointer-sign option])
   if AC_TRY_COMMAND($CC -Wno-pointer-sign conftest.c) > /dev/null 2>&1 ; then
      nopointersign=yes
      AC_MSG_RESULT([yes])
   else
        nopointersign=no
        AC_MSG_RESULT([no])
   fi
   # Check -fno-working-directory
   AC_MSG_CHECKING([if gcc acceps -fno-working-directory option])
   if AC_TRY_COMMAND($CC -fno-working-directory conftest.c) > /dev/null 2>&1 ; then
      noworkingdirectory=yes
      AC_MSG_RESULT([yes])
   else
        noworkingdirectory=no
        AC_MSG_RESULT([no])
   fi
fi


dnl ------------------------------------------
dnl If CLFAGS doesn\'t exist set default value
dnl ------------------------------------------
if test "x$cflags_specified" = "x"
then
CFLAGS="$CFLAGS"
fi

dnl --------------
dnl Check programs
dnl --------------
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CHECK_TOOL(AR, ar)
AC_CHECK_TOOL(RANLIB, ranlib, :)


dnl ----------------------
dnl Packages configuration
dnl ----------------------
AC_ARG_ENABLE(ipv6,
[  --disable-ipv6          turn off IPv6 related features and daemons])
AC_ARG_ENABLE(bgpd,
[  --disable-bgpd          do not build bgpd])
AC_ARG_ENABLE(order-nexthop,
[ --disable-order-nexthop	disable order-nextop])
AC_ARG_ENABLE(bgpd-extasn,
[  --disable-bgpd-extasn  Disable bgp extended-asn capability])
AC_ARG_ENABLE(64bit-support,
[  --enable-64bit-support    Enable 64bit_support functionality])
AC_ARG_ENABLE(snmp,
[  --disable-snmp          disable SNMP support])
AC_ARG_ENABLE(agentx,
[  --enable-agentx         enable AGENTX feature])
AC_ARG_WITH(libpam,
[  --with-libpam           use libpam for PAM support in vtysh])
AC_ARG_ENABLE(all-in-one,
[  --enable-all-in-one     make all program linked verion])
AC_ARG_ENABLE(static,
[  --enable-static         enable static library linking feature])
AC_ARG_ENABLE(memmgr,
[  --disable-memmgr        disable memory manager feature])
AC_ARG_ENABLE(efence,
[  --enable-efence         Link all exes with Efence Library except IMI/IMISH])
AC_ARG_ENABLE(bgp-dump,
[  --enable-bgp-dump       enable BGP dump feature])
AC_ARG_ENABLE(bigendian,
[ --enable-bigendian      enable Big Endian support])
AC_ARG_ENABLE(agentx-unix-domain,
[  --enable-agentx-unix-domain      enable Unix domain socket for Agentx])
AC_ARG_ENABLE(bgp_sdn,
[  --enable-bgp-sdn      enable BGP SDN])

dnl Some systems (Solaris 2.x) require libnsl (Network Services Library)
case "$host" in
  *-linux-*)
      opsys=gnu-linux
      OPSYSDIR=platform/linux
      AC_DEFINE(GNU_LINUX,,GNU/Linux)
      AC_DEFINE(HAVE_MULTIPATH,,Multipath)
  dnl -ldl lib required for static linking of -lcrypto
      LDL=-ldl
  ;;
esac

case "$target" in
  *-linux-*)
      opsys=gnu-linux
      OPSYSDIR=platform/linux
      AC_DEFINE(GNU_LINUX,,GNU/Linux)
      AC_DEFINE(HAVE_MULTIPATH,,Multipath)
  dnl -ldl lib required for static linking of -lcrypto
      LDL=-ldl
  ;;
esac

case "${IPI_BGPSDN_PLATFORM}" in
  *linux*)
      OPSYSDIR=platform/linux
  ;;
esac

AC_DEFINE_UNQUOTED(HOST_NAME, "$host",Host name)
AC_CONFIG_HEADER($OPSYSDIR/config.h:config.h.in)

dnl ------------------
dnl Rules.options file
dnl ------------------
OPTIONS_FILE=$OPSYSDIR/Rules.options
>$OPTIONS_FILE

dnl --------------------------------------------------
dnl Default option settings.
dnl If set to "yes" use disable--option to disable it.
dnl If set to "no" use enable-option to enable it.
dnl --------------------------------------------------

ENABLE_IPV6=yes
ENABLE_BGPD=yes
ENABLE_BGPD_EXTASN=yes
ENABLE_SNMP=yes
ENABLE_AGENTX=no
ENABLE_MEMMGR=no
ENABLE_MEMLIMIT=no
ENABLE_MEMACCT=no
ENABLE_MEMACCT_DETAIL=no
ENABLE_MEMCHK=no
ENABLE_MEMLOG=no
ENABLE_BIGENDIAN=no
ENABLE_ORDER_NEXTHOP=yes
ENABLE_BGP_SDN=yes

dnl ---------------------------------------------------------------------------
dnl                              Platform checks START
dnl ---------------------------------------------------------------------------

dnl -------------------
dnl Check header files.
dnl -------------------
AC_STDC_HEADERS
AC_CHECK_HEADERS([string.h stropts.h sys/conf.h sys/ksym.h sys/time.h sys/times.h sys/select.h sys/sysctl.h sys/sockio.h sys/types.h netpacket/packet.h net/ethernet.h net/if.h net/if_ether.h netinet/if_ether.h net/if_dl.h net/if_var.h net/route.h linux/version.h kvm.h netdb.h netinet/in.h net/netopt.h netinet/in_var.h netinet/in_systm.h netinet/in6_var.h netinet/in6.h inet/nd.h asm/types.h netinet/icmp6.h netinet6/nd6.h netinet6/mip6.h libutil.h getopt.h sys/md5.h linux/if.h linux/route.h linux/tcp_md5.h netinet/ip6.h linux/mroute6.h], [], [],
[[#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
]])

dnl Check for location of autoconf.h
AC_CHECK_HEADER(
  [linux/autoconf.h],
  [AC_DEFINE(HAVE_LINUX_AUTOCONF_H,,[linux/autoconf.h])
  AUTOCONF=linux/autoconf.h],
  [AC_CHECK_HEADER([generated/autoconf.h],
    [AC_DEFINE(HAVE_GENERATED_AUTOCONF_H,,[generated/autoconf.h])
    AUTOCONF=generated/autoconf.h], [],
  )]
)


dnl check some types
AC_C_CONST
dnl AC_TYPE_PID_T
AC_TYPE_SIGNAL

AC_SUBST(OPSYSDIR)

dnl ------------------------------------------
dnl Check for support of ISO varargs in macros.
dnl ------------------------------------------
AC_MSG_CHECKING(whether ISO varargs in macros are supported)
AC_TRY_COMPILE([#include <stdio.h>],[
#define TEST_VARARG(...)  printf(__VA_ARGS__);
TEST_VARARG("%s", "ISO vararg works");],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_ISO_MACRO_VARARGS,,ISO varargs in macros)],
AC_MSG_RESULT(no))

dnl -------------------------------
dnl Endian-ness check
dnl -------------------------------
dnl Use detected endian-ness
if test "$enable_bigendian" = "" ; then
   AC_WORDS_BIGENDIAN	    
   if test "${ac_cv_c_bigendian}" = "yes" ; then
      AC_DEFINE(WORDS_BIGENDIAN,1,bigendian)
    else
      AC_DEFINE(WORDS_LITTLEENDIAN,1,littleendian)
   fi
   ENABLE_BIGENDIAN=${ac_cv_c_bigendian}
fi

dnl Check for user override of endian-ness
if test "$enable_bigendian" = "yes" ; then
   AC_DEFINE(WORDS_BIGENDIAN,1,bigendian)
   ENABLE_BIGENDIAN=yes
   ac_cv_c_bigendian=yes
fi
if test "$enable_bigendian" = "no" ; then
   AC_DEFINE(WORDS_LITTLEENDIAN,1,littleendian)
   ac_cv_c_bigendian=no
   ENABLE_BIGENDIAN=no
fi

dnl -------------------------------
dnl check the size in byte of the C
dnl -------------------------------
dnl AC_CHECK_SIZEOF(char)
dnl AC_CHECK_SIZEOF(int)
dnl AC_CHECK_SIZEOF(short)
dnl AC_CHECK_SIZEOF(long)

dnl ----------------------------
dnl check existance of functions
dnl ----------------------------
if test "$cross_compiling" = "no";then
AC_CHECK_FUNCS(bcopy bzero strerror inet_aton daemon snprintf vsnprintf strlcat strlcpy if_nametoindex if_indextoname getifaddrs strcasecmp strncasecmp)
dnl AC_REPLACE_FUNCS(vsnprintf)
AC_CHECK_FUNCS(setproctitle, ,[AC_CHECK_LIB(util, setproctitle, [LIBS="$LIBS -lutil"; AC_DEFINE(HAVE_SETPROCTITLE)])])
fi

dnl ------------------------------------
dnl Determine routing get and set method
dnl ------------------------------------
AC_MSG_CHECKING(bgpsdn between kernel interface method)
if test x"$opsys" = x"gnu-linux"; then
  if test "${enable_netlink}" = "yes";then
    AC_MSG_RESULT(netlink)
    RT_METHOD=rt_netlink.o
    AC_DEFINE(HAVE_NETLINK,,netlink)
    ENABLE_NETLINK=yes
    netlink=yes
  elif test "${enable_netlink}" = "no"; then
    AC_MSG_RESULT(ioctl)
    RT_METHOD=rt_ioctl.o
    netlink=no
  else
    AC_MSG_RESULT(netlink)
    RT_METHOD=rt_netlink.o
    AC_DEFINE(HAVE_NETLINK,,netlink)
    ENABLE_NETLINK=yes
    netlink=yes
  fi
else
  AC_TRY_RUN([#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

main ()
{
  int ac_sock;

  ac_sock = socket (AF_ROUTE, SOCK_RAW, 0);
  if (ac_sock < 0 && errno == EINVAL)
    exit (1);
  exit (0);
}],
  [KERNEL_METHOD=kernel_socket.o
   RT_METHOD=rt_socket.o
   AC_MSG_RESULT(socket)],
  [RT_METHOD=rt_ioctl.o
   AC_MSG_RESULT(ioctl)],
  [KERNEL_METHOD=kernel_socket.o
   RT_METHOD=rt_socket.o
   AC_MSG_RESULT(socket)])
fi
AC_SUBST(RT_METHOD)
AC_SUBST(KERNEL_METHOD)
AC_SUBST(OTHER_METHOD)

if test "$opsys" = "gnu-linux" ; then
  dnl Check for TCP MD5 support in linux kernel

  AC_MSG_CHECKING(TCP MD5 enabled in kernel)
  AC_EGREP_CPP(CONFIG_TCP_MD5SIG,[#include <linux/autoconf.h>
  CONFIG_TCP_MD5SIG],AC_MSG_RESULT(no),
  [AC_MSG_RESULT(yes)
  AC_MSG_CHECKING(TCP MD5 enabled on target)
  AC_EGREP_CPP(TCP_MD5SIG,[#include <netinet/tcp.h>
  TCP_MD5SIG],AC_MSG_RESULT(no),
  [AC_DEFINE(HAVE_TCP_MD5SIG,,TCP MD5SIG)
  AC_MSG_RESULT(yes)])])

fi

dnl See if -D_GNU_SOURCE is required for IPV6
AC_EGREP_CPP(in6_pktinfo,
[#include <netinet/in.h>],,
[CFLAGS="${CFLAGS} -D_GNU_SOURCE"])


dnl ------------------------------
dnl check kernel route read method
dnl ------------------------------
AC_CACHE_CHECK(route read method check, bgpsdn_cv_rtread,
[if test "$netlink" = yes; then
  RTREAD_METHOD="rtread_netlink.o"
  bgpsdn_rtread="netlink"
else
for bgpsdn_rtread in /proc/net/route /dev/ip /dev/null;
do
  test x`ls $bgpsdn_rtread 2>/dev/null` = x"$bgpsdn_rtread" && break
done
case $bgpsdn_rtread in
  "/proc/net/route") RTREAD_METHOD="rtread_proc.o"
                     bgpsdn_rtread="proc";;
  "/dev/ip")         RTREAD_METHOD="rtread_getmsg.o"
                     bgpsdn_rtread="getmsg";;
  *)                 RTREAD_METHOD="rtread_sysctl.o"
                     bgpsdn_rtread="sysctl";;
esac
fi])
AC_SUBST(RTREAD_METHOD)

dnl -----------------------------
dnl check interface lookup method
dnl -----------------------------
AC_MSG_CHECKING(interface looking up method)
if test "$netlink" = yes; then
  AC_MSG_RESULT(netlink)
  IF_METHOD=if_netlink.o
else
  if grep NET_RT_IFLIST /usr/include/sys/socket.h >/dev/null 2>&1; then
    AC_MSG_RESULT(sysctl)
    IF_METHOD=if_sysctl.o
    AC_DEFINE(HAVE_NET_RT_IFLIST,,NET_RT_IFLIST ioctl)
  else
    AC_MSG_RESULT(ioctl)
    IF_METHOD=if_ioctl.o
  fi
fi
AC_SUBST(IF_METHOD)

dnl -----------------------
dnl check proc file system.
dnl -----------------------
if test -r /proc/net/dev; then
  AC_DEFINE(HAVE_PROC_NET_DEV,,/proc/net/dev)
  IF_PROC=if_proc.o
fi

if test -r /proc/net/if_inet6; then
  AC_DEFINE(HAVE_PROC_NET_IF_INET6,,/proc/net/if_inet6)
  IF_PROC=if_proc.o
fi
AC_SUBST(IF_PROC)

dnl -----------------------------
dnl check ipforward detect method
dnl -----------------------------
AC_CACHE_CHECK(ipforward method check, bgpsdn_cv_ipforward_path,
[for bgpsdn_ipforward_path in /proc/net/snmp /dev/ip /dev/null;
do
  test x`ls $bgpsdn_ipforward_path 2>/dev/null` = x"$bgpsdn_ipforward_path" && break
done
case $bgpsdn_ipforward_path in
  "/proc/net/snmp")  IPFORWARD=ipforward_proc.o
                     bgpsdn_ipforward_path="proc";;
  *)
                     IPFORWARD=ipforward_sysctl.o
                     bgpsdn_ipforward_path="sysctl";;
esac])
AC_SUBST(IPFORWARD)

dnl ----------
dnl IPv6 check
dnl ----------
AC_MSG_CHECKING(whether does this OS have IPv6 stack)
if test "${enable_ipv6}" = "no"; then
  bgpsdn_cv_ipv6=no
  AC_MSG_RESULT(disabled)
fi

dnl ----------
dnl Linux IPv6
dnl ----------
if test "${enable_ipv6}" = "yes"; then
   AC_EGREP_CPP(yes, [
   #include <linux/version.h>
   /* 2.1.128 or later */
   #if LINUX_VERSION_CODE >= 0x020180
   yes
   #endif],
   [bgpsdn_cv_ipv6=yes; bgpsdn_cv_linux_ipv6=yes;AC_MSG_RESULT(IPv6)])
else
   if test x`ls /proc/net/ipv6_route 2>/dev/null` = x"/proc/net/ipv6_route"; then
      bgpsdn_cv_ipv6=yes
      bgpsdn_cv_linux_ipv6=yes
      AC_MSG_RESULT(Linux IPv6)
   fi
fi

if test "$bgpsdn_cv_linux_ipv6" = "yes";then
   AC_DEFINE(HAVE_IPV6)
   AC_MSG_CHECKING(for GNU libc 2.1)
   AC_EGREP_CPP(yes, [
#include <features.h>
#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
  yes
#endif], [glibc=yes; AC_MSG_RESULT(yes)], AC_MSG_RESULT(no))
   AC_DEFINE(HAVE_IPV6,,IPv6)
   if test "$glibc" != "yes"; then
      INCLUDES="-I/usr/inet6/include"
      if test x`ls /usr/inet6/lib/libinet6.a 2>/dev/null` != x;then
         LIB_IPV6="-L/usr/inet6/lib -linet6"
      fi
   fi
fi

if test "${bgpsdn_cv_ipv6}" != yes; then
  AC_MSG_RESULT(IPv4 only)
fi

dnl -----------------------
dnl Set IPv6 related values
dnl -----------------------
if test "${bgpsdn_cv_ipv6}" = yes; then
  LIBS="$LIB_IPV6 $LIBS"
  AC_SUBST(LIB_IPV6)
  ENABLE_IPV6=yes
else
  ENABLE_IPV6=no
fi

dnl -----------------------
dnl Set Efence
dnl -----------------------
if test "${enable_efence}" = "yes"; then
  AC_CHECK_LIB(efence, memalign, [EFENCE_LIB="-lefence"])
  dnl if test -f /usr/lib/libefence.a; then
    dnl EFENCE_LIB="/usr/lib/libefence.a"
  dnl fi
  ENABLE_EFENCE=yes
fi
AC_SUBST(EFENCE_LIB)

if test x"$opsys" != x"" ; then
AC_CHECK_LIB(c, inet_ntop, [AC_DEFINE(HAVE_INET_NTOP,,inet_ntop)])
AC_CHECK_LIB(c, inet_pton, [AC_DEFINE(HAVE_INET_PTON,,inet_pton)])
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(resolv, res_init)
AC_CHECK_LIB(m, main)
AC_CHECK_LIB(md, MD5Init)
AC_CHECK_LIB(md5, MD5Init)

dnl -------------------------
dnl OpenSSL MD5 library check
dnl -------------------------
if test "${HAVE_SYS_MD5_H}" != "yes"; then
  for ac_ssl_md5 in /usr/ssl/include/openssl/md5.h /usr/local/ssl/include/openssl/md5.h /usr/include/openssl/md5.h /dev/null
  do
    test -f "${ac_ssl_md5}" && break
  done

  AC_CHECK_LIB(crypto, MD5_Init, [HAVE_CRYPTO=yes])

  case ${ac_ssl_md5} in
    /usr/ssl/include/openssl/*)
      if test "${HAVE_CRYPTO}" = "yes"; then
        AC_DEFINE(HAVE_OPENSSL_MD5_H,,OpenSSL MD5)
        LIBS="${LIBS} -lcrypto"
        CFLAGS="${CFLAGS} -I/usr/ssl/include"
      fi
      ;;
    /usr/local/ssl/include/openssl/*)
      if test "${HAVE_CRYPTO}" = "yes"; then
        AC_DEFINE(HAVE_OPENSSL_MD5_H,,OpenSSL MD5)
        LIBS="${LIBS} -lcrypto"
        CFLAGS="${CFLAGS} -I/usr/local/ssl/include"
      fi
      ;;
    /usr/include/openssl/*)
      if test "${HAVE_CRYPTO}" = "yes"; then
        AC_DEFINE(HAVE_OPENSSL_MD5_H,,OpenSSL MD5)
        LIBS="${LIBS} -lcrypto"
      fi
      ;;
    *)
      ac_cv_lib_crypto_MD5_Init="no"
      ;;
  esac
fi


dnl -------------------------
dnl OpenSSL HMAC library check
dnl -------------------------
if test "${HAVE_SYS_HMAC_H}" != "yes"; then
  for ac_ssl_hmac in /usr/ssl/include/openssl/hmac.h /usr/local/ssl/include/openssl/hmac.h /usr/include/openssl/hmac.h /dev/null
  do
    test -f "${ac_ssl_hmac}" && break
  done

  AC_CHECK_LIB(crypto, HMAC_Init, [HAVE_CRYPTO=yes])

  case ${ac_ssl_hmac} in
    /usr/ssl/include/openssl/*)
      if test "${HAVE_CRYPTO}" = "yes"; then
        AC_DEFINE(HAVE_OPENSSL_HMAC_H,,OpenSSL HMAC)
        LIBS="${LIBS} -lcrypto"
        CFLAGS="${CFLAGS} -I/usr/ssl/include"
      fi
      ;;
    /usr/local/ssl/include/openssl/*)
      if test "${HAVE_CRYPTO}" = "yes"; then
        AC_DEFINE(HAVE_OPENSSL_HMAC_H,,OpenSSL HMAC)
        LIBS="${LIBS} -lcrypto"
        CFLAGS="${CFLAGS} -I/usr/local/ssl/include"
      fi
      ;;
    /usr/include/openssl/*)
      if test "${HAVE_CRYPTO}" = "yes"; then
        AC_DEFINE(HAVE_OPENSSL_HMAC_H,,OpenSSL HMAC) 
        LIBS="${LIBS} -lcrypto"
      fi
      ;;
    *)
      ac_cv_lib_crypto_HMAC_Init="no"
      ;;
  esac
fi


dnl -------------------------
dnl OpenSSL SHA library check
dnl -------------------------
if test "${HAVE_SYS_SHA_H}" != "yes"; then
  for ac_ssl_sha in /usr/ssl/include/openssl/sha.h /usr/local/ssl/include/openssl/sha.h /usr/include/openssl/sha.h /dev/null
  do
    test -f "${ac_ssl_sha}" && break
  done

  AC_CHECK_LIB(crypto, SHA1_Init, [HAVE_CRYPTO=yes])

  case ${ac_ssl_sha} in
    /usr/ssl/include/openssl/*)
      if test "${HAVE_CRYPTO}" = "yes"; then
        AC_DEFINE(HAVE_OPENSSL_SHA_H,,OpenSSL SHA) 
        LIBS="${LIBS} -lcrypto"
        CFLAGS="${CFLAGS} -I/usr/ssl/include"
      fi
      ;;
    /usr/local/ssl/include/openssl/*)
      if test "${HAVE_CRYPTO}" = "yes"; then
        AC_DEFINE(HAVE_OPENSSL_SHA_H,,OpenSSL SHA) 
        LIBS="${LIBS} -lcrypto"
        CFLAGS="${CFLAGS} -I/usr/local/ssl/include"
      fi
      ;;
    /usr/include/openssl/*)
      if test "${HAVE_CRYPTO}" = "yes"; then
        AC_DEFINE(HAVE_OPENSSL_SHA_H,,OpenSSL SHA) 
        LIBS="${LIBS} -lcrypto"
      fi
      ;;
    *)
      ac_cv_lib_crypto_SHA1_Init="no"
      ;;
  esac
fi

dnl ---------------------------------------------------
dnl BSD/OS 4.1 define inet_XtoY function as __inet_XtoY
dnl ---------------------------------------------------
AC_CHECK_FUNC(__inet_ntop, AC_DEFINE(HAVE_INET_NTOP))
AC_CHECK_FUNC(__inet_pton, AC_DEFINE(HAVE_INET_PTON))
AC_CHECK_FUNC(__inet_aton, AC_DEFINE(HAVE_INET_ATON))

dnl ---------------------------
dnl check system has GNU regexp
dnl ---------------------------
dnl AC_MSG_CHECKING(whether system has GNU regex)
AC_CHECK_LIB(c, regexec,
[AC_DEFINE(HAVE_GNU_REGEX,,Have GNU regexp)
LIB_REGEX=""],
[LIB_REGEX="regex.o"])
AC_SUBST(LIB_REGEX)

dnl AC_MSG_CHECKING(whether system has GNU regex)
dnl if grep RE_NO_GNU_OPS /usr/include/regex.h >/dev/null 2>&1; then
dnl   AC_MSG_RESULT(yes)
dnl   AC_DEFINE(HAVE_GNU_REGEX)
dnl   LIB_REGEX=""
dnl else
dnl   AC_MSG_RESULT(no)
dnl   LIB_REGEX="regex.o"
dnl fi
dnl AC_SUBST(LIB_REGEX)

dnl ----------------------------
dnl check sa_len of sockaddr
dnl ----------------------------
AC_MSG_CHECKING(whether struct sockaddr has a sa_len field)
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
],[static struct sockaddr ac_i;int ac_j = sizeof (ac_i.sa_len);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SA_LEN,,sa_len)],
 AC_MSG_RESULT(no))

dnl ----------------------------
dnl check sin_len of sockaddr_in
dnl ----------------------------
AC_MSG_CHECKING(whether struct sockaddr_in has a sin_len field)
AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>
],[static struct sockaddr_in ac_i;int ac_j = sizeof (ac_i.sin_len);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SIN_LEN,,sin_len)],
 AC_MSG_RESULT(no))

dnl ----------------------------
dnl check sun_len of sockaddr_un
dnl ----------------------------
AC_MSG_CHECKING(whether struct sockaddr_un has a sun_len field)
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/un.h>
],[static struct sockaddr_un ac_i;int ac_j = sizeof (ac_i.sun_len);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SUN_LEN,,sun_len)],
 AC_MSG_RESULT(no))

dnl -----------------------------------
dnl check sin6_scope_id of sockaddr_in6
dnl -----------------------------------
if test "$bgpsdn_cv_ipv6" = yes; then
  AC_MSG_CHECKING(whether struct sockaddr_in6 has a sin6_scope_id field)
  AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>
],[static struct sockaddr_in6 ac_i;int ac_j = sizeof (ac_i.sin6_scope_id);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SIN6_SCOPE_ID,,sin6_scope_id)],
 AC_MSG_RESULT(no))
fi

dnl ----------------------------
dnl check socklen_t exist or not
dnl ----------------------------
AC_MSG_CHECKING(whther socklen_t is defined)
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
],[socklen_t ac_x;],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SOCKLEN_T,,socklen_t)],
 AC_MSG_RESULT(no))

dnl ------------------------
dnl check struct sockaddr_dl
dnl ------------------------
AC_MSG_CHECKING(whether struct sockaddr_dl exist)
AC_EGREP_HEADER(sockaddr_dl,
net/if_dl.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SOCKADDR_DL,,sockaddr_dl)],
 AC_MSG_RESULT(no))

dnl --------------------------
dnl check structure ifaliasreq
dnl --------------------------
AC_MSG_CHECKING(whether struct ifaliasreq exist)
AC_EGREP_HEADER(ifaliasreq,
net/if.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_IFALIASREQ,,ifaliasreq)],
 AC_MSG_RESULT(no))

dnl ----------------------------
dnl check structure in6_aliasreq
dnl ----------------------------
AC_MSG_CHECKING(whether struct if6_aliasreq exist)
AC_EGREP_HEADER(in6_aliasreq,
netinet6/in6_var.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_IN6_ALIASREQ,,if6_aliasreq)],
 AC_MSG_RESULT(no))

dnl ---------------------------
dnl check structure rt_addrinfo
dnl ---------------------------
AC_MSG_CHECKING(whether struct rt_addrinfo exist)
AC_EGREP_HEADER(rt_addrinfo,
net/route.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_RT_ADDRINFO,,rt_addrinfo)],
 AC_MSG_RESULT(no))

dnl -----------------------------
dnl check structure in_pktinfo
dnl -----------------------------
AC_MSG_CHECKING(whether struct in_pktinfo exit)
AC_TRY_COMPILE([#include <netinet/in.h>
],[struct in_pktinfo ac_i;],
[AC_MSG_RESULT(yes)
AC_DEFINE(HAVE_IN_PKTINFO,,IN PKTINFO)],
AC_MSG_RESULT(no))

fi

dnl ---------------------------------------------------------------------------
dnl                              Platform checks END
dnl ---------------------------------------------------------------------------

dnl --------------------------------------------------------------------------
dnl                              BGP-SDN checks START
dnl --------------------------------------------------------------------------

dnl -------------------------------------
dnl BGP SDN
dnl -------------------------------------
AC_MSG_CHECKING(for BGP SDN)
if test "$enable_bgp_sdn" = "yes" ; then
    AC_DEFINE(HAVE_BGP_SDN,,bgp_sdn)
    ENABLE_BGP_SDN=yes
    LIBS="${LIBS} -lcurl"
else
    ENABLE_BGP_SDN=no
fi
AC_SUBST(BGP_SDN)

dnl --------------
dnl Memory Manager
dnl --------------
if test "${enable_memmgr}" = "no"; then
  ENABLE_MEMMGR=no
else
  ENABLE_MEMMGR=yes
  AC_DEFINE(MEMMGR,,Memory manager enabled)
fi

dnl ------------------
dnl check SNMP library
dnl ------------------
if test "${enable_snmp}" != "no";then
  AC_DEFINE(HAVE_SNMP,,SNMP)
  ENABLE_SNMP="yes"
else
    ENABLE_SNMP="no"
fi

dnl ------------------
dnl check AGENTX library
dnl ------------------
if test "${enable_agentx}" = "yes";then
  AC_DEFINE(HAVE_AGENTX,,AGENTX)
  ENABLE_AGENTX="yes"
else
  ENABLE_AGENTX="no"
fi

dnl ---------------------
dnl Figure out build date
dnl ---------------------
BUILDDATE="`date +%x` `date | awk '{print $4}'`"
AC_DEFINE_UNQUOTED(BUILDDATE, "${BUILDDATE}",Build Number)

dnl -------------
dnl Platform data
dnl -------------
if test "${BGPSDN_PLATFORM}" != ""; then
  AC_DEFINE_UNQUOTED(BGPSDN_PLATFORM, "${BGPSDN_PLATFORM}", Platform)
fi
if test "${BGPSDN_CURR_RELEASE}" != ""; then
  AC_DEFINE_UNQUOTED(BGPSDN_CURR_RELEASE, "${BGPSDN_CURR_RELEASE}", Curr Release)
fi

dnl ---------------------------------------------------------
dnl Use static crypto library when license manager is enabled
dnl ---------------------------------------------------------
if test "${ENABLE_LICMGR}" = "yes";then
  if test -f /usr/lib/libcrypto.a; then
     LIBCRYPTO=/usr/lib/libcrypto.a
  elif test -f /usr/local/lib/libcrypto.a; then
     LIBCRYPTO=/usr/local/lib/libcrypto.a
  elif test -f /usr/local/ssl/lib/libcrypto.a; then
     LIBCRYPTO=/usr/local/ssl/lib/libcrypto.a
  fi
  if test -n "${LIBCRYPTO}"; then
      LIBST=`echo ${LIBS} | sed 's/-lcrypto//g'`
      LIBS="${LIBST} ${LIBCRYPTO}"
  fi
fi

dnl -------------
dnl Enable static
dnl -------------
if test "${enable_static}" = "yes"; then
  ENABLE_STATIC=yes
  LIBS="${LIBS} ${LDL}"
fi

dnl --------------------
dnl Daemon disable check
dnl --------------------
if test "${enable_bgpd}" = "no";then
  BGPD=""
  ENABLE_BGPD=no
  ENABLE_BGPD_EXTASN=no
  ENABLE_ORDER_NEXTHOP=no
else
  BGPD="bgpd"
  ENABLE_BGPD=yes
  AC_DEFINE(HAVE_BGPD,,bgpd)
dnl check for --disable-bgpd-extasn
dnl turn on by default if not explictly disabled
  if test "${enable_bgpd_extasn}" != "no" ; then
     ENABLE_BGPD_EXTASN=yes
     AC_DEFINE(HAVE_EXT_CAP_ASN)
  fi
dnl check for --disable-order-nexthop
dnl turn on by default if not explicitly disabled
  if test "${enable_order_nexthop}" != "no" ; then
     ENABLE_ORDER_NEXTHOP=yes
     AC_DEFINE(HAVE_ORDER_NEXTHOP,,BGP Order NextHop)
  fi
fi

dnl----------------------------
dnl BGP Extended ASN capability
dnl-----------------------------
if test "${enable_bgpd_extasn}" = "yes";then
    ENABLE_BGPD=yes
    ENABLE_BGPD_EXTASN=yes
    AC_DEFINE(HAVE_BGPD,,bgpd)
    AC_DEFINE(HAVE_EXT_CAP_ASN,,BGP extasn)
fi

AC_SUBST(BGPD_EXTASN)

dnl------------------
dnl BGP Order NextHop
dnl------------------
if test "${enable_order_nexthop}" = "yes" ; then
   ENABLE_BGPD=yes
   ENABLE_ORDER_NEXTHOP=yes
   AC_DEFINE(HAVE_BGPD,,bgpd)
   AC_DEFINE(HAVE_ORDER_NEXTHOP,,BGP Order NextHop)
fi
if test "${enable_order_nexthop}" = "no" ; then
   ENABLE_ORDER_NEXTHOP=no
fi

AC_SUBST(ORDER_NEXTHOP)

if test "${enable_64bit_support}" = "yes"; then
  AC_DEFINE(HAVE_64BIT_SUPPORT,,64BIT_SUPPORT)
  ENABLE_64BIT_SUPPORT=yes
fi

if test "${enable_bgp_dump}" = "yes"; then
  AC_DEFINE(HAVE_BGP_DUMP,,BGP Dump)
  ENABLE_BGP_DUMP=yes
fi

if test "${enable_agentx_unix_domain}" = "yes";then
  ENABLE_AGENTX_UNIX_DOMAIN=yes
  AC_DEFINE(HAVE_AGENTX_UNIX_DOMAIN,,Agentx Unix Domain)
else
  ENABLE_AGENTX_UNIX_DOMAIN=no
fi

AC_SUBST(BGPD)

dnl -------------
dnl check version
dnl -------------
file="${srcdir}/lib/version.h"
VERSION=`sed -ne 's/^#.*BGPSDN_VERSION.*\"\([^\"]*\)\"$/\1/p' $file`
AC_SUBST(VERSION)

dnl ------------------------------
dnl set paths for process id files
dnl ------------------------------
AC_CACHE_CHECK(pid file directory,ac_cv_piddir,
[for BGPSDN_PID_DIR in /var/run  dnl
                   /var/adm     dnl
                   /etc         dnl
                   /dev/null;
do
  test -d $BGPSDN_PID_DIR && break
done
ac_piddir=$BGPSDN_PID_DIR

if test $BGPSDN_PID_DIR = "/dev/null"; then
  echo "PID DIRECTORY NOT FOUND!"
fi])
AC_DEFINE(HAVE_PID,,PID)
AC_DEFINE_UNQUOTED(PATH_BGPD_PID, "$ac_piddir/bgpd.pid",bgpd PID)

dnl ---------------------------
dnl Check htonl works correctly
dnl ---------------------------
AC_MSG_CHECKING(for working htonl)
AC_CACHE_VAL(ac_cv_htonl_works, [
AC_TRY_LINK([#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif],
[htonl (0);],
ac_cv_htonl_works=yes,
ac_cv_htonl_works=no)])
AC_MSG_RESULT($ac_cv_htonl_works)


dnl ---------------------------------
dnl Creating options in Rules.options
dnl ---------------------------------

echo "creating platform options file"

if test "${IPI_BGPSDN_PLATFORM}" = "dummy";then
echo "LIBS=" >> $OPTIONS_FILE
echo "EXTRA_CFLAGS=" >> $OPTIONS_FILE
else
echo "LIBS=${LIBS}" >> $OPTIONS_FILE
echo "EXTRA_CFLAGS=${CFLAGS}" >> $OPTIONS_FILE
fi

if test "$ENABLE_EFENCE" = "yes";then
  echo "EFENCE_LIB=${EFENCE_LIB}" >> $OPTIONS_FILE
fi

if test "${prefix}" != "NONE" ; then
  echo "PREFIX=${prefix}" >> $OPTIONS_FILE
  AC_DEFINE_UNQUOTED(PATH_PREFIX, "${prefix}", "")
else
  echo "PREFIX=/usr/local" >> $OPTIONS_FILE
  AC_DEFINE_UNQUOTED(PATH_PREFIX, "/usr/local", "")
fi

if test "x${INSTALL}" == "x"; then
  echo "INSTALL=/usr/bin/install -c" >> $OPTIONS_FILE
else
  echo "INSTALL=${INSTALL}" >> $OPTIONS_FILE
fi

if test "${sysconfdir}" != "NONE" ; then
  if test "${sysconfdir}" = \$\{prefix\}/etc ; then
    if test "${prefix}" != "NONE" ; then
      echo "SYSCONFDIR=${prefix}/etc" >> $OPTIONS_FILE
      AC_DEFINE_UNQUOTED(PATH_SYSCONFDIR, "${prefix}/etc", "")
    else
      echo "SYSCONFDIR=/usr/local/etc" >> $OPTIONS_FILE
      AC_DEFINE_UNQUOTED(PATH_SYSCONFDIR, "/usr/local/etc", "")
    fi
  else
    echo "SYSCONFDIR=${sysconfdir}" >> $OPTIONS_FILE
    AC_DEFINE_UNQUOTED(PATH_SYSCONFDIR, "${sysconfdir}", "")
  fi
else
  echo "SYSCONFDIR=/usr/local/etc" >> $OPTIONS_FILE
  AC_DEFINE_UNQUOTED(PATH_SYSCONFDIR, "/usr/local/etc", "")
fi

dnl ----------------------------------------
dnl Set L3 if anyone of L3 protocols enabled
dnl ----------------------------------------
if test "${ENABLE_BGPD}" = "yes"; then
 ENABLE_L3=yes
 echo "ENABLE_L3=yes" >> $OPTIONS_FILE
 AC_DEFINE(HAVE_L3,,Layer 3)
else
 ENABLE_L3=no
 echo "ENABLE_L3=no" >> $OPTIONS_FILE
fi

if test "${ENABLE_IPV6}" = "yes";then
   echo "ENABLE_IPV6=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_IPV6=no" >> $OPTIONS_FILE
fi

if test "${ENABLE_BGPD}" = "yes";then
   echo "ENABLE_BGPD=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_BGPD=no" >> $OPTIONS_FILE
fi

if test "${ENABLE_ORDER_NEXTHOP}" = "yes" ; then
   echo "ENABLE_ORDER_NEXTHOP=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_ORDER_NEXTHOP=no" >> $OPTIONS_FILE
fi

if test "${ENABLE_BGPD_EXTASN}" = "yes";then
   echo "ENABLE_BGPD_EXTASN=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_BGPD_EXTASN=no" >> $OPTIONS_FILE
fi

if test "$ENABLE_NETLINK" = "yes";then
   echo "ENABLE_NETLINK=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_NETLINK=no" >> $OPTIONS_FILE
fi

if test "$ENABLE_DEV_TEST" = "yes";then
   echo "ENABLE_DEV_TEST=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_DEV_TEST=no" >> $OPTIONS_FILE
fi

if test "$ENABLE_MEMMGR" = "yes";then
   echo "ENABLE_MEMMGR=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_MEMMGR=no" >> $OPTIONS_FILE
fi

if test "$ENABLE_SNMP" = "yes";then
   echo "ENABLE_SNMP=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_SNMP=no" >> $OPTIONS_FILE
fi

if test "$ENABLE_AGENTX" = "yes";then
   echo "ENABLE_AGENTX=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_AGENTX=no" >> $OPTIONS_FILE
fi

if test "$ENABLE_STATIC" = "yes";then
   dnl echo "LDFLAGS=-static"  >> $OPTIONS_FILE
   echo "ENABLE_STATIC=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_STATIC=no" >> $OPTIONS_FILE
fi

if test "$ENABLE_64BIT_SUPPORT" = "yes";then
   echo "ENABLE_64BIT_SUPPORT=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_64BIT_SUPPORT=no" >> $OPTIONS_FILE
fi

if test "$ENABLE_BGP_SDN" = "yes";then
   echo "ENABLE_BGP_SDN=yes" >> $OPTIONS_FILE
else
   echo "ENABLE_BGP_SDN=no" >> $OPTIONS_FILE
fi

dnl Compiler option(s)

if test "$nopointersign" = "yes" ; then
   echo "COPT_NO_POINTER_SIGN=yes" >> $OPTIONS_FILE
fi

if test "$noworkingdirectory" = "yes" ; then
   echo "COPT_NO_WORKING_DIRECTORY=yes" >> $OPTIONS_FILE
fi

echo "AUTOCONF=$AUTOCONF" >> $OPTIONS_FILE
echo "SWFWDR_DIR=$SWFWDR_DIR" >> $OPTIONS_FILE

AC_OUTPUT(Makefile)

dnl ---------------------------------------------------------------------------
dnl                              BGP-SDN checks END
dnl ---------------------------------------------------------------------------

echo "
BGP-SDN configuration
-------------------
BGP-SDN version           : ${VERSION}
Build date              : ${BUILDDATE}
host operating system   : ${host_os}
source code location    : ${srcdir}
compiler                : ${CC}
compiler flags          : ${CFLAGS}
directory for pid files : ${ac_piddir}
"
