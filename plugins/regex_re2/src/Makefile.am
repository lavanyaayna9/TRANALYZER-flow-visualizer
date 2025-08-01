lib_LTLIBRARIES = libregex_re2.la

libregex_re2_la_SOURCES = \
	murmur.c \
	regex_re2.c

libregex_re2_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/src/cre2/src

libregex_re2_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libregex_re2_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libregex_re2_la_CFLAGS += -D_GNU_SOURCE
endif

libregex_re2_la_LDFLAGS = -shrext .so  # extension for shared library

libregex_re2_la_LIBADD = $(top_srcdir)/src/cre2/build/libcre2.la
