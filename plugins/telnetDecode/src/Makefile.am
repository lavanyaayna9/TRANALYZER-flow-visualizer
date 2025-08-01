lib_LTLIBRARIES = libtelnetDecode.la

libtelnetDecode_la_SOURCES = \
	telnetDecode.c \
	telnet_utils.c

libtelnetDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libtelnetDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libtelnetDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libtelnetDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libtelnetDecode_la_LDFLAGS = -shrext .so  # extension for shared library
