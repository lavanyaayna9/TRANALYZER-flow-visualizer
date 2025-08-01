SUBDIRS = nDPI

lib_LTLIBRARIES = libnDPI.la

libnDPI_la_SOURCES = nDPI.c

libnDPI_la_CFLAGS = \
	-I$(top_srcdir)/src/nDPI/src/include \
	-I$(top_builddir)/src/nDPI/src/include \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libnDPI_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libnDPI_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libnDPI_la_CFLAGS += -D_GNU_SOURCE
endif

#libnDPI_la_LDFLAGS = \
#	-Wl,--whole-archive,$(top_builddir)/src/nDPI/src/lib/libndpi.a,--no-whole-archive

libnDPI_la_LIBADD = $(top_builddir)/src/nDPI/src/lib/libndpi.la

libnDPI_la_LDFLAGS = -shrext .so  # extension for shared library
