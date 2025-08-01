lib_LTLIBRARIES = libradiusDecode.la

libradiusDecode_la_SOURCES = radiusDecode.c

libradiusDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libradiusDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libradiusDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libradiusDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libradiusDecode_la_LDFLAGS = -shrext .so  # extension for shared library
