lib_LTLIBRARIES = libtp0f.la

libtp0f_la_SOURCES = \
	tp0f.c \
	tp0flist.c

libtp0f_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libtp0f_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libtp0f_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libtp0f_la_CFLAGS += -D_GNU_SOURCE
endif

libtp0f_la_LDFLAGS = -shrext .so  # extension for shared library
