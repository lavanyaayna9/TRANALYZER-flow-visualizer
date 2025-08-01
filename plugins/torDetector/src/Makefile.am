lib_LTLIBRARIES = libtorDetector.la

libtorDetector_la_SOURCES = \
	torDetector.c \
	../../../utils/t2buf.c

libtorDetector_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/../tcpFlags/src

libtorDetector_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libtorDetector_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libtorDetector_la_CFLAGS += -D_GNU_SOURCE
endif

libtorDetector_la_LDFLAGS = -shrext .so  # extension for shared library
