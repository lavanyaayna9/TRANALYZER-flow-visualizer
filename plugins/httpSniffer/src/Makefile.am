lib_LTLIBRARIES = libhttpSniffer.la

libhttpSniffer_la_SOURCES = httpSniffer.c

libhttpSniffer_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libhttpSniffer_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libhttpSniffer_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libhttpSniffer_la_CFLAGS += -D_GNU_SOURCE
endif

libhttpSniffer_la_LDFLAGS = -shrext .so  # extension for shared library
                                         # (without this flag, would be '.dylib' on macOS)
