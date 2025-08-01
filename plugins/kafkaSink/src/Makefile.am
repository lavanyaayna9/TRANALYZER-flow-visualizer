lib_LTLIBRARIES = libkafkaSink.la

libkafkaSink_la_SOURCES = \
	@PACKAGE_NAME@.c
#	../../../utils/t2buf.c  # if you uncomment this line, do not
#	                        # forget to append a backslash above!

libkafkaSink_la_CFLAGS = \
	$(RDKAFKA_CFLAGS) \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src
#	-I$(top_srcdir)/../tcpFlags/src         # tell the compiler where to find header
#	                                        # files from dependent plugins
#	                                        # !!! if you uncomment this line, do not
#	                                        # !!! forget to append a backslash above

libkafkaSink_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libkafkaSink_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libkafkaSink_la_CFLAGS += -D_GNU_SOURCE
endif

libkafkaSink_la_LIBADD = $(RDKAFKA_LIBS)

libkafkaSink_la_LDFLAGS = -shrext .so  # extension for shared library
                                     # (without this flag, would be '.dylib' on macOS)
