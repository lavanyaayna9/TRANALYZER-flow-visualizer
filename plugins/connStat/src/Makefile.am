lib_LTLIBRARIES = libconnStat.la

libconnStat_la_SOURCES = connStat.c

libconnStat_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libconnStat_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libconnStat_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libconnStat_la_CFLAGS += -D_GNU_SOURCE
endif

libconnStat_la_LDFLAGS = -shrext .so  # extension for shared library
