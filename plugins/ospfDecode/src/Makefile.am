lib_LTLIBRARIES = libospfDecode.la

libospfDecode_la_SOURCES = ospfDecode.c

libospfDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libospfDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libospfDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libospfDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libospfDecode_la_LDFLAGS = -shrext .so  # extension for shared library
