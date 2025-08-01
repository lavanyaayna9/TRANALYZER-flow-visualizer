lib_LTLIBRARIES = libntpDecode.la

libntpDecode_la_SOURCES = ntpDecode.c

libntpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libntpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libntpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libntpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libntpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
