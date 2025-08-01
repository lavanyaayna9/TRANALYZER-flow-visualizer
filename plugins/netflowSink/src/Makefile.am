lib_LTLIBRARIES = libnetflowSink.la

libnetflowSink_la_SOURCES = netflowSink.c

libnetflowSink_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/../basicFlow/src \
	-I$(top_srcdir)/../basicStats/src \
	-I$(top_srcdir)/../macRecorder/src \
	-I$(top_srcdir)/../tcpFlags/src

libnetflowSink_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libnetflowSink_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libnetflowSink_la_CFLAGS += -D_GNU_SOURCE
endif

libnetflowSink_la_LDFLAGS = -shrext .so  # extension for shared library
