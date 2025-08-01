lib_LTLIBRARIES = libsshDecode.la

libsshDecode_la_SOURCES = \
	sshDecode.c \
	../../../utils/t2buf.c \
	../../../utils/t2crypto.c \
	../../sslDecode/src/sslBlist.c

libsshDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/../sslDecode/src/

libsshDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libsshDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libsshDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libsshDecode_la_LDFLAGS = -shrext .so  # extension for shared library
