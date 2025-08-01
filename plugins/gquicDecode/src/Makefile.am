lib_LTLIBRARIES = libgquicDecode.la

libgquicDecode_la_SOURCES = \
	gquicDecode.c \
	../../../utils/t2buf.c

libgquicDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libgquicDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libgquicDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libgquicDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libgquicDecode_la_LDFLAGS = -shrext .so  # extension for shared library
