lib_LTLIBRARIES = libcdpDecode.la

libcdpDecode_la_SOURCES = \
	cdpDecode.c \
	../../../utils/t2buf.c

libcdpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libcdpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libcdpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libcdpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libcdpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
