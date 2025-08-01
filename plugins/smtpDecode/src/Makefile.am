lib_LTLIBRARIES = libsmtpDecode.la

libsmtpDecode_la_SOURCES = smtpDecode.c

libsmtpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libsmtpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libsmtpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libsmtpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libsmtpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
