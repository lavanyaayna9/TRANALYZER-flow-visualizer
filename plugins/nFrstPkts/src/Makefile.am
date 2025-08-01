lib_LTLIBRARIES = libnFrstPkts.la

libnFrstPkts_la_SOURCES = nFrstPkts.c

libnFrstPkts_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libnFrstPkts_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libnFrstPkts_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libnFrstPkts_la_CFLAGS += -D_GNU_SOURCE
endif

libnFrstPkts_la_LDFLAGS = -shrext .so  # extension for shared library
