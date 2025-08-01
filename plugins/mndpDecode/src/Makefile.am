lib_LTLIBRARIES = libmndpDecode.la

libmndpDecode_la_SOURCES = \
	mndpDecode.c \
 	../../../utils/t2buf.c

libmndpDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libmndpDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libmndpDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libmndpDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libmndpDecode_la_LDFLAGS = -shrext .so  # extension for shared library
                                        # (without this flag, would be '.dylib' on macOS)
