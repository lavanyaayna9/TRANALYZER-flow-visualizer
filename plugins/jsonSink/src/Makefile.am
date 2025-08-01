lib_LTLIBRARIES = libjsonSink.la

libjsonSink_la_SOURCES = \
	jsonSink.c \
	../../../utils/bin2txt.c

if JSON_GZ_COMPRESS_SET
libjsonSink_la_SOURCES += ../../../utils/gz2txt.c
endif

libjsonSink_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libjsonSink_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libjsonSink_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libjsonSink_la_CFLAGS += -D_GNU_SOURCE
endif

libjsonSink_la_LDFLAGS = -shrext .so  # extension for shared library
