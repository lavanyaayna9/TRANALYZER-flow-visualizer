lib_LTLIBRARIES = libmacRecorder.la

libmacRecorder_la_SOURCES = \
	macLbl.c \
	macRecorder.c

libmacRecorder_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libmacRecorder_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libmacRecorder_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libmacRecorder_la_CFLAGS += -D_GNU_SOURCE
endif

libmacRecorder_la_LDFLAGS = -shrext .so  # extension for shared library
