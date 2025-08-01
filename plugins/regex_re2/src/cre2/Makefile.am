## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS		= -I meta/autotools
AUTOMAKE_OPTIONS	= foreign
EXTRA_DIST		= INSTALL configure.sh prepare.sh
dist_doc_DATA		= README COPYING LICENSE.re2 RELEASE-NOTES
AM_CFLAGS		= -I$(srcdir)/src -Wall

## --------------------------------------------------------------------

EXTRA_DIST		+= meta/scripts/cre2.pc.in
pkgconfigdir		= $(libdir)/pkgconfig
nodist_pkgconfig_DATA	= meta/scripts/cre2.pc

## --------------------------------------------------------------------

cre2_CURRENT		= @cre2_VERSION_INTERFACE_CURRENT@
cre2_REVISION		= @cre2_VERSION_INTERFACE_REVISION@
cre2_AGE		= @cre2_VERSION_INTERFACE_AGE@

include_HEADERS		= src/cre2.h

lib_LTLIBRARIES		= libcre2.la
libcre2_la_CFLAGS	= $(RE2_CFLAGS)
libcre2_la_CXXFLAGS	= $(RE2_CFLAGS)
libcre2_la_LDFLAGS	= -version-info $(cre2_CURRENT):$(cre2_REVISION):$(cre2_AGE) $(RE2_LIBS)
libcre2_la_SOURCES	= src/cre2.cpp
