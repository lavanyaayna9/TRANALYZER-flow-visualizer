lib_LTLIBRARIES = libtxtSink.la

libtxtSink_la_SOURCES = \
	txtSink.c \
	../../../utils/bin2txt.c

if TFS_GZ_COMPRESS_SET
libtxtSink_la_SOURCES += ../../../utils/gz2txt.c
endif

libtxtSink_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libtxtSink_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libtxtSink_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libtxtSink_la_CFLAGS += -D_GNU_SOURCE
endif

libtxtSink_la_LDFLAGS = -shrext .so  # extension for shared library
