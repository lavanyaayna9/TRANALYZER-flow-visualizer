lib_LTLIBRARIES = libtelegram.la

libtelegram_la_SOURCES = telegram.c

libtelegram_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/../basicFlow/src

libtelegram_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libtelegram_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libtelegram_la_CFLAGS += -D_GNU_SOURCE
endif

libtelegram_la_LDFLAGS = -shrext .so  # extension for shared library
