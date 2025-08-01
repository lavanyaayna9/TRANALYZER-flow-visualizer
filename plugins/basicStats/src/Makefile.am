lib_LTLIBRARIES = libbasicStats.la

libbasicStats_la_SOURCES = basicStats.c

libbasicStats_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libbasicStats_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libbasicStats_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libbasicStats_la_CFLAGS += -D_GNU_SOURCE
endif

libbasicStats_la_LDFLAGS = -shrext .so  # extension for shared library
