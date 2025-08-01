lib_LTLIBRARIES = libsyslogDecode.la

libsyslogDecode_la_SOURCES = syslogDecode.c

libsyslogDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libsyslogDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libsyslogDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libsyslogDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libsyslogDecode_la_LDFLAGS = -shrext .so  # extension for shared library
