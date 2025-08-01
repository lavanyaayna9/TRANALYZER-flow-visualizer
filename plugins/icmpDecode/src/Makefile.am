lib_LTLIBRARIES = libicmpDecode.la

libicmpDecode_la_SOURCES = icmpDecode.c

libicmpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libicmpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libicmpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libicmpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libicmpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
