lib_LTLIBRARIES = libmodbus.la

libmodbus_la_SOURCES = modbus.c

libmodbus_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libmodbus_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libmodbus_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libmodbus_la_CFLAGS += -D_GNU_SOURCE
endif

libmodbus_la_LDFLAGS = -shrext .so  # extension for shared library
