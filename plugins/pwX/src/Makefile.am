lib_LTLIBRARIES = libpwX.la

libpwX_la_SOURCES = \
	cdecode.c \
	pwX.c

libpwX_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libpwX_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libpwX_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libpwX_la_CFLAGS += -D_GNU_SOURCE
endif

libpwX_la_LDFLAGS = -shrext .so  # extension for shared library
