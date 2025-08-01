lib_LTLIBRARIES = libliveXtr.la

libliveXtr_la_SOURCES = \
	liveXtr.c

libliveXtr_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libliveXtr_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libliveXtr_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libliveXtr_la_CFLAGS += -D_GNU_SOURCE
endif

libliveXtr_la_LDFLAGS = -shrext .so  # extension for shared library
