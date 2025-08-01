lib_LTLIBRARIES = libwavelet.la

libwavelet_la_SOURCES = \
	dwt.c \
	wavelet.c

libwavelet_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libwavelet_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libwavelet_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libwavelet_la_CFLAGS += -D_GNU_SOURCE
endif

libwavelet_la_LDFLAGS = -shrext .so  # extension for shared library
