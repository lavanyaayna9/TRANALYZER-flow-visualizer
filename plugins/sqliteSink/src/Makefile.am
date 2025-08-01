lib_LTLIBRARIES = libsqliteSink.la

libsqliteSink_la_SOURCES = sqliteSink.c

libsqliteSink_la_CFLAGS = \
	$(LIBSQLITE_CFLAGS) \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libsqliteSink_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libsqliteSink_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libsqliteSink_la_CFLAGS += -D_GNU_SOURCE
endif

libsqliteSink_la_LIBADD = $(LIBSQLITE_LIBS)

libsqliteSink_la_LDFLAGS = -shrext .so  # extension for shared library
