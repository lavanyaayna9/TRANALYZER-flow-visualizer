lib_LTLIBRARIES = libsocketSink.la

libsocketSink_la_SOURCES = \
	socketSink.c \
	../../../utils/bin2txt.c \
	../../../utils/chksum.c

if SKS_GZ_COMPRESS_SET
libsocketSink_la_SOURCES += ../../../utils/gz2txt.c
endif

if APPLE
libsocketSink_la_SOURCES += ../../../utils/missing/open_memstream.c
endif

libsocketSink_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libsocketSink_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libsocketSink_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libsocketSink_la_CFLAGS += -D_GNU_SOURCE
endif

libsocketSink_la_LDFLAGS = -shrext .so  # extension for shared library
