lib_LTLIBRARIES = libsctpDecode.la

libsctpDecode_la_SOURCES = \
	sctpDecode.c \
	../../../utils/chksum.c

libsctpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libsctpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libsctpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libsctpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libsctpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
