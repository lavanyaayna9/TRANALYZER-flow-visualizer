lib_LTLIBRARIES = libdfft.la

libdfft_la_SOURCES = \
	@PACKAGE_NAME@.c

libdfft_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/../nFrstPkts/src

libdfft_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libdfft_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libdfft_la_CFLAGS += -D_GNU_SOURCE
endif

libdfft_la_LDFLAGS = -shrext .so  # extension for shared library
                                     # (without this flag, would be '.dylib' on macOS)
