if LOCAL_MMDB
SUBDIRS = MMDB
endif

lib_LTLIBRARIES = libgeoip.la

libgeoip_la_SOURCES = geoip.c

libgeoip_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libgeoip_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libgeoip_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libgeoip_la_CFLAGS += -D_GNU_SOURCE
endif

libgeoip_la_LDFLAGS = -shrext .so  # extension for shared library

if LOCAL_MMDB
libgeoip_la_LIBADD = $(top_builddir)/src/MMDB/libmaxminddb.la
endif
