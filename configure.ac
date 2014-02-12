#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([allnet],[0.3],[esb@hawaii.edu])
AM_INIT_AUTOMAKE(foreign)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/ad.c])
AC_CONFIG_HEADERS([config.h])
LT_INIT

# Checks for programs.
AC_PROG_CC

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

AC_CONFIG_FILES([Makefile src/Makefile src/mgmt/Makefile src/xchat/Makefile src/xtime/Makefile doc/Makefile])
AC_OUTPUT
