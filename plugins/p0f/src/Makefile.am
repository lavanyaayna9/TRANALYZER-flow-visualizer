lib_LTLIBRARIES = libp0f.la

libp0f_la_SOURCES = p0f.c

libp0f_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/../sslDecode/src/

libp0f_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libp0f_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libp0f_la_CFLAGS += -D_GNU_SOURCE
endif

libp0f_la_LDFLAGS = -shrext .so  # extension for shared library
