lib_LTLIBRARIES = libigmpDecode.la

libigmpDecode_la_SOURCES = \
	igmpDecode.c \
	../../../utils/chksum.c

libigmpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libigmpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libigmpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libigmpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libigmpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
