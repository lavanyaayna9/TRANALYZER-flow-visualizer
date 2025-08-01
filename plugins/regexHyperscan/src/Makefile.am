lib_LTLIBRARIES = libregexHyperscan.la

libregexHyperscan_la_SOURCES = regexHyperscan.c

libregexHyperscan_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/src/hyperscan/src

libregexHyperscan_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libregexHyperscan_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libregexHyperscan_la_CFLAGS += -D_GNU_SOURCE
endif

libregexHyperscan_la_LDFLAGS = -shrext .so  # extension for shared library

if APPLE
libregexHyperscan_la_LDFLAGS += -Wl,-all_load,$(top_srcdir)/src/hyperscan/build/lib/libhs.a,-noall_load
else
libregexHyperscan_la_LDFLAGS += -Wl,--whole-archive,$(top_srcdir)/src/hyperscan/build/lib/libhs.a,-no-whole-archive
endif

#libregexHyperscan_la_LIBADD = $(top_srcdir)/hyperscan/build/lib/libhs.a
