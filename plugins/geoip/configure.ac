#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])

AC_INIT([geoip], [0.9.3], [andy@tranalyzer.com])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src])

AM_INIT_AUTOMAKE([foreign])

case $OSTYPE in
    darwin*)
        # macOS specific
        apple=true
        ;;
    linux*)
        # Linux specific
        ;;
esac

AM_CONDITIONAL([APPLE], [test x$apple = xtrue])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX
LT_INIT

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.

AC_MSG_CHECKING(whether to use internal libmaxminddb)
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#include "geoip.h"
#if GEOIP_LIB != 2
#error
#endif
])], [LOCAL_MMDB="yes"], [LOCAL_MMDB="no"])
AC_MSG_RESULT($LOCAL_MMDB)
AM_CONDITIONAL([LOCAL_MMDB], [test x$LOCAL_MMDB = xyes])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_CONFIG_SUBDIRS([src/MMDB])
AC_OUTPUT
