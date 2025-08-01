lib_LTLIBRARIES = libtcpFlags.la

libtcpFlags_la_SOURCES = \
	tcpFlags.c \
	../../../utils/chksum.c

libtcpFlags_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libtcpFlags_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libtcpFlags_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libtcpFlags_la_CFLAGS += -D_GNU_SOURCE
endif

libtcpFlags_la_LDFLAGS = -shrext .so  # extension for shared library
