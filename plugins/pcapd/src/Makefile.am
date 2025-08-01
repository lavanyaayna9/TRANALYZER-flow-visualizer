lib_LTLIBRARIES = libpcapd.la

libpcapd_la_SOURCES = pcapd.c ../../../utils/chksum.c

libpcapd_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libpcapd_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libpcapd_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libpcapd_la_CFLAGS += -D_GNU_SOURCE
endif

libpcapd_la_LDFLAGS = -shrext .so  # extension for shared library
