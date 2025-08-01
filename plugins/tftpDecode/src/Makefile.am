lib_LTLIBRARIES = libtftpDecode.la

libtftpDecode_la_SOURCES = tftpDecode.c

libtftpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libtftpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libtftpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libtftpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libtftpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
