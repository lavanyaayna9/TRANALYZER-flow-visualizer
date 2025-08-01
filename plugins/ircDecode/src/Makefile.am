lib_LTLIBRARIES = libircDecode.la

libircDecode_la_SOURCES = ircDecode.c

libircDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libircDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libircDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libircDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libircDecode_la_LDFLAGS = -shrext .so  # extension for shared library
