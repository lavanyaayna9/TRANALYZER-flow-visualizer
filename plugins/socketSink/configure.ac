#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])

AC_INIT([socketSink], [0.9.3], [andy@tranalyzer.com])

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
AC_CHECK_HEADERS([netdb.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname gettimeofday memset socket strerror uname])

# If SKS_GZ_COMPRESS is set, we need to include gz2txt.c (see src/Makefile.am)
SKS_GZ_COMPRESS=`perl -nle 'print $1 if /^#define\s+SKS_GZ_COMPRESS\s+(\d+).*$/' $ac_abs_confdir/src/socketSink.h`
AM_CONDITIONAL([SKS_GZ_COMPRESS_SET], [test x$SKS_GZ_COMPRESS = x1])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
