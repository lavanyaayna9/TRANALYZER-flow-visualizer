lib_LTLIBRARIES = libdnsDecode.la

libdnsDecode_la_SOURCES = \
	dnsDecode.c \
	malsite.c

libdnsDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libdnsDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libdnsDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libdnsDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libdnsDecode_la_LDFLAGS = -shrext .so  # extension for shared library
