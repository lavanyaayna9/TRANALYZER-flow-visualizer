lib_LTLIBRARIES = libsnmpDecode.la

libsnmpDecode_la_SOURCES = \
	snmpDecode.c \
	../../../utils/t2buf.c

libsnmpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libsnmpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libsnmpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libsnmpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libsnmpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
