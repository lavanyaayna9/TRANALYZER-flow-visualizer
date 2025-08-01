lib_LTLIBRARIES = libftpDecode.la

libftpDecode_la_SOURCES = ftpDecode.c

libftpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libftpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libftpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libftpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libftpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
