lib_LTLIBRARIES = libentropy.la

libentropy_la_SOURCES = entropy.c

libentropy_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libentropy_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libentropy_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libentropy_la_CFLAGS += -D_GNU_SOURCE
endif

libentropy_la_LDFLAGS = -shrext .so  # extension for shared library
