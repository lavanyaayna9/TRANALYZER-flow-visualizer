lib_LTLIBRARIES = libbinSink.la

libbinSink_la_SOURCES = \
	binSink.c \
	../../../utils/bin2txt.c \
	../../../utils/chksum.c

if BFS_GZ_COMPRESS_SET
libbinSink_la_SOURCES += ../../../utils/gz2txt.c
endif

libbinSink_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libbinSink_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libbinSink_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libbinSink_la_CFLAGS += -D_GNU_SOURCE
endif

libbinSink_la_LDFLAGS = -shrext .so  # extension for shared library
