lib_LTLIBRARIES = libvoipDetector.la

libvoipDetector_la_SOURCES = voipDetector.c

libvoipDetector_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libvoipDetector_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libvoipDetector_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libvoipDetector_la_CFLAGS += -D_GNU_SOURCE
endif

libvoipDetector_la_LDFLAGS = -shrext .so  # extension for shared library
