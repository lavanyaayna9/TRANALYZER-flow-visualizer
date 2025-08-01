lib_LTLIBRARIES = libmysqlSink.la

libmysqlSink_la_SOURCES = mysqlSink.c

libmysqlSink_la_CFLAGS = \
	$(LIBMYSQL_CFLAGS) \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libmysqlSink_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libmysqlSink_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libmysqlSink_la_CFLAGS += -D_GNU_SOURCE
endif

libmysqlSink_la_LIBADD = $(LIBMYSQL_LIBS)

libmysqlSink_la_LDFLAGS = -shrext .so  # extension for shared library
