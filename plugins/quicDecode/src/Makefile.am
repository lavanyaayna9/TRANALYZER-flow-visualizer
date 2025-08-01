lib_LTLIBRARIES = libquicDecode.la

libquicDecode_la_SOURCES = \
	quicDecode.c \
	quic_utils.c \
	sslcompat.c \
	../../../utils/t2buf.c

libquicDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libquicDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libquicDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libquicDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libquicDecode_la_LDFLAGS = -shrext .so  # extension for shared library
