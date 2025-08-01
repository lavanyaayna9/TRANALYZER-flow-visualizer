lib_LTLIBRARIES = liblldpDecode.la

liblldpDecode_la_SOURCES = \
	lldpDecode.c \
	../../../utils/t2buf.c

liblldpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

liblldpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
liblldpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
liblldpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

liblldpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
