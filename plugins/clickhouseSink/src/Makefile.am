lib_LTLIBRARIES = libclickhouseSink.la

libclickhouseSink_la_SOURCES = \
	clickhouseSink.cpp

libclickhouseSink_la_CXXFLAGS = \
	-std=c++17 \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libclickhouseSink_la_CXXFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.hpp\""

if APPLE
libclickhouseSink_la_CXXFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libclickhouseSink_la_CXXFLAGS += -D_GNU_SOURCE
endif

libclickhouseSink_la_LDFLAGS = -shrext .so  # extension for shared library
                                     # (without this flag, would be '.dylib' on macOS)
