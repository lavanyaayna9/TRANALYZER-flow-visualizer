lib_LTLIBRARIES = libdescriptiveStats.la

libdescriptiveStats_la_SOURCES = descriptiveStats.c

libdescriptiveStats_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/../pktSIATHisto/src

libdescriptiveStats_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libdescriptiveStats_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libdescriptiveStats_la_CFLAGS += -D_GNU_SOURCE
endif

libdescriptiveStats_la_LDFLAGS = -shrext .so  # extension for shared library
