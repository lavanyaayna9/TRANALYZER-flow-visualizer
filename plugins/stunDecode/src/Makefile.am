lib_LTLIBRARIES = libstunDecode.la

libstunDecode_la_SOURCES = stunDecode.c

libstunDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libstunDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libstunDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libstunDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libstunDecode_la_LDFLAGS = -shrext .so  # extension for shared library
