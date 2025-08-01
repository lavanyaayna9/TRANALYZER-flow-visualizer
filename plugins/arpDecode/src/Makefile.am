lib_LTLIBRARIES = libarpDecode.la

libarpDecode_la_SOURCES = arpDecode.c

libarpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libarpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libarpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libarpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libarpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
