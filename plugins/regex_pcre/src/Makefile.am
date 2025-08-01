lib_LTLIBRARIES = libregex_pcre.la

libregex_pcre_la_SOURCES = \
	regex_pcre.c \
	regfile_pcre.c

libregex_pcre_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/../tcpFlags/src

libregex_pcre_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libregex_pcre_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
libregex_pcre_la_CFLAGS += -I/usr/local/opt/pcre/include
else
libregex_pcre_la_CFLAGS += -D_GNU_SOURCE
endif

libregex_pcre_la_LDFLAGS = -shrext .so  # extension for shared library

if APPLE
libregex_pcre_la_LDFLAGS += -L/usr/local/opt/pcre/lib
endif
