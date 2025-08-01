lib_LTLIBRARIES = libfindexer.la

libfindexer_la_SOURCES = findexer.c

libfindexer_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libfindexer_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libfindexer_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libfindexer_la_CFLAGS += -D_GNU_SOURCE
endif

libfindexer_la_LDFLAGS = -shrext .so  # extension for shared library
