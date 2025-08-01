lib_LTLIBRARIES = libdhcpDecode.la

libdhcpDecode_la_SOURCES = \
	dhcpDecode.c \
	dhcp_utils.c \
	../../../utils/t2buf.c

libdhcpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libdhcpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libdhcpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libdhcpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libdhcpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
