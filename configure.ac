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
ALLNET_BINDIR=\$\(top_srcdir\)/bin
ALLNET_SRCDIR=\$\(top_srcdir\)/src
ALLNET_LIBDIR=\$\(top_builddir\)/src/lib
AC_SUBST(ALLNET_API_VERSION)
AC_SUBST(ALLNET_BINDIR)
AC_SUBST(ALLNET_LIBDIR)
AC_SUBST(ALLNET_SRCDIR)

# Checks for programs.
AC_PROG_CC
AC_PROG_LN_S

# Checks for libraries.
PKG_CHECK_MODULES(OPENSSL, [openssl >= 1.0])

AC_ARG_ENABLE(network-manager,
  AC_HELP_STRING([--disable-network-manager],
  [turn off NetworkManager support]),[enable_network_manager=$enableval],[enable_network_manager="auto"])
if test "x$enable_network_manager" = "xauto"; then
  PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.6, [
      enable_network_manager="yes"
      have_dbus="yes"
      AC_DEFINE(HAVE_DBUS,1,[libdbus-1 used to connect to NetworkManager])
    ], [
      enable_network_manager="no"
      have_dbus="no"
    ])
elif test "x$enable_network_manager" = "xyes"; then
  PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.6, [
      have_dbus="yes"
      AC_DEFINE(HAVE_DBUS,1,[libdbus-1 used to connect to NetworkManager])
    ], [
      enable_network_manager="no"
      have_dbus="no"
    ])
  if test "x$have_dbus" = "xno"; then
    AC_MSG_ERROR([Could not find libdbus-1 needed for NetworkManager support.])
  fi
fi
if test "x$enable_network_manager" = "xyes"; then
  AC_DEFINE(USE_NETWORK_MANAGER, [], [Enable NetworkManager support])
fi
AM_CONDITIONAL(USE_NETWORK_MANAGER, test "x$enable_network_manager" = "xyes")

build_gui="auto"
build_gui_flag_set="no"
AC_ARG_ENABLE(gui,
  AC_HELP_STRING([--disable-gui],
  [do not build GUI (building requires java)]),[
    build_gui=$enableval
    build_gui_flag_set="yes"
  ],[])
if test "x$build_gui" != "xno"; then
  AX_PROG_JAVAC
  AX_PROG_JAR
  if (test "x$JAVAC" = "x" || test "x$JAR" = "x"); then
    if test "x$build_gui" != "xauto"; then
      AC_MSG_ERROR([Could not find a suitable java compiler needed to build GUI support.])
    else
      AC_MSG_NOTICE([Could not find a suitable java compiler needed to build GUI support -- disabling GUI build.])
    fi
    build_gui="no"
  else
    build_gui="yes"
  fi
fi
AM_CONDITIONAL([ENABLE_GUI], [test "x$build_gui" = "xyes"])

install_precompiled_gui="auto"
AC_ARG_ENABLE(precompiled-gui,
  AC_HELP_STRING([--disable-precompiled-gui],
  [do not install precompiled GUI when java compiler is not available]),[install_precompiled_gui=$enableval],[])

if (test "x$install_precompiled_gui" != "xno" && test "x$build_gui" = "xno" && test "x$build_gui_flag_set" = "xno"); then
  # only install precompiled GUI if we don't build it ourselves and the --enable-gui/--disable-gui isn't set
  AX_PROG_JAVA
  if test "x$JAVA" = "x"; then
    if test "x$install_precompiled_gui" = "xyes"; then
      AC_MSG_WARN([Could not find a suitable java runtime needed to run GUI.])
      install_precompiled_gui="yes"
    else
      AC_MSG_WARN([Could not find a suitable java runtime needed to run GUI. Use --enable-precompiled-gui to force installation.])
      install_precompiled_gui="no"
    fi
  else
    install_precompiled_gui="yes"
  fi
else
  install_precompiled_gui="no"
fi
AM_CONDITIONAL([PRECOMP_GUI], [test "x$install_precompiled_gui" = "xyes"])

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

AC_CONFIG_FILES([Makefile src/Makefile src/abc/Makefile src/ahra/Makefile src/lib/Makefile src/mgmt/Makefile src/xchat/Makefile src/xchat_ui/Makefile src/xtime/Makefile doc/Makefile])
AC_OUTPUT

echo ""
echo "  AllNet v${ALLNET_API_VERSION}"
echo ""
echo "  Prefix                 : ${prefix}"
echo "  Compiler flags         : ${CFLAGS}"
echo "  NetworkManager support : ${enable_network_manager}"
echo "  Build User Interface   : ${build_gui}"
if test "x$build_gui" = "xno"; then
echo "  Install precompiled UI : ${install_precompiled_gui} (only available when Build User Interface is \"no\")"
fi
echo ""
