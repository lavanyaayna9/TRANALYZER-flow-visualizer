lib_LTLIBRARIES = libcovertChannels.la

libcovertChannels_la_SOURCES = covertChannels.c

libcovertChannels_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libcovertChannels_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libcovertChannels_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libcovertChannels_la_CFLAGS += -D_GNU_SOURCE
endif

libcovertChannels_la_LDFLAGS = -shrext .so  # extension for shared library
