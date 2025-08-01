lib_LTLIBRARIES = libbasicFlow.la

libbasicFlow_la_SOURCES = basicFlow.c

libbasicFlow_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libbasicFlow_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libbasicFlow_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libbasicFlow_la_CFLAGS += -D_GNU_SOURCE
endif

libbasicFlow_la_LDFLAGS = -shrext .so  # extension for shared library
