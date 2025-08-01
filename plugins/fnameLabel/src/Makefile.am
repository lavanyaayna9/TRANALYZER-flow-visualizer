lib_LTLIBRARIES = libfnameLabel.la

libfnameLabel_la_SOURCES = fnameLabel.c

libfnameLabel_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libfnameLabel_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libfnameLabel_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libfnameLabel_la_CFLAGS += -D_GNU_SOURCE
endif

libfnameLabel_la_LDFLAGS = -shrext .so  # extension for shared library
