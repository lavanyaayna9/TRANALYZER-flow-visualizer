lib_LTLIBRARIES = libpktSIATHisto.la

libpktSIATHisto_la_SOURCES = \
	pktSIATHisto.c \
	../../../utils/rbTree.c

libpktSIATHisto_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libpktSIATHisto_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libpktSIATHisto_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libpktSIATHisto_la_CFLAGS += -D_GNU_SOURCE
endif

libpktSIATHisto_la_LDFLAGS = -shrext .so  # extension for shared library
