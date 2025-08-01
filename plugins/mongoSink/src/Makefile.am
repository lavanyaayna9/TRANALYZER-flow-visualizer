lib_LTLIBRARIES = libmongoSink.la

libmongoSink_la_SOURCES = mongoSink.c

libmongoSink_la_CFLAGS = \
	$(LIBBSON_CFLAGS) \
	$(LIBMONGOC_CFLAGS) \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libmongoSink_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libmongoSink_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libmongoSink_la_CFLAGS += -D_GNU_SOURCE
endif

libmongoSink_la_LIBADD = $(LIBMONGOC_LIBS) $(LIBBSON_LIBS)

libmongoSink_la_LDFLAGS = -shrext .so  # extension for shared library
