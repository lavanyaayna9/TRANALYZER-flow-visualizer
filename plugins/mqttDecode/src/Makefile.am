lib_LTLIBRARIES = libmqttDecode.la

libmqttDecode_la_SOURCES = \
	mqttDecode.c \
	../../../utils/t2buf.c

libmqttDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src
#	-I$(top_srcdir)/../tcpFlags/src         # tell the compiler where to find header
#	                                        # files from dependent plugins
#	                                        # !!! if you uncomment this line, do not
#	                                        # !!! forget to append a backslash above

libmqttDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libmqttDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libmqttDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libmqttDecode_la_LDFLAGS = -shrext .so  # extension for shared library
                                     # (without this flag, would be '.dylib' on macOS)
