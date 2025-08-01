lib_LTLIBRARIES = libvrrpDecode.la

libvrrpDecode_la_SOURCES = \
	vrrpDecode.c \
	../../../utils/chksum.c

libvrrpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libvrrpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libvrrpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libvrrpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libvrrpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
