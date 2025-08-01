lib_LTLIBRARIES = libportClassifier.la

libportClassifier_la_SOURCES = portClassifier.c

libportClassifier_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libportClassifier_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libportClassifier_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libportClassifier_la_CFLAGS += -D_GNU_SOURCE
endif

libportClassifier_la_LDFLAGS = -shrext .so  # extension for shared library
