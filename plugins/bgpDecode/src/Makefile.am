lib_LTLIBRARIES = libbgpDecode.la

libbgpDecode_la_SOURCES = \
	bgpDecode.c \
	../../../utils/t2buf.c

libbgpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libbgpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libbgpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libbgpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libbgpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
