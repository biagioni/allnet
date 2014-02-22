#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

m4_define([allnet_api_version], [0.3])

AC_PREREQ([2.68])
AC_INIT([allnet],[allnet_api_version],[esb@hawaii.edu])
AM_INIT_AUTOMAKE(foreign)
AM_SILENT_RULES
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/ad.c])
AC_CONFIG_HEADERS([config.h])
LT_INIT

ALLNET_API_VERSION=allnet_api_version
ALLNET_SRCDIR=\$\(top_srcdir\)/src
ALLNET_LIBDIR=\$\(top_builddir\)/src/lib
AC_SUBST(ALLNET_API_VERSION)
AC_SUBST(ALLNET_LIBDIR)
AC_SUBST(ALLNET_SRCDIR)

# Checks for programs.
AC_PROG_CC
AC_PROG_LN_S

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STRCOLL
AC_CHECK_FUNCS([bzero dup2 getcwd gethostbyname gethostname gettimeofday inet_ntoa localtime_r memset mkdir select socket strstr strtol tzset])

AC_CONFIG_FILES([Makefile src/Makefile src/ahra/Makefile src/lib/Makefile src/mgmt/Makefile src/xchat/Makefile src/xtime/Makefile doc/Makefile])
AC_OUTPUT
