lib_LTLIBRARIES = libsslDecode.la

libsslDecode_la_SOURCES = \
	sslDecode.c \
	sslBlist.c \
	../../../utils/t2buf.c \
	../../../utils/t2crypto.c

libsslDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/../quicDecode/src

libsslDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libsslDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libsslDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libsslDecode_la_LDFLAGS = -shrext .so  # extension for shared library
