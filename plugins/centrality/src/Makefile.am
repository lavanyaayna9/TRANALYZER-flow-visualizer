lib_LTLIBRARIES = libcentrality.la

libcentrality_la_SOURCES = \
	centrality.c \
	csparse/cs_add.c \
	csparse/cs_compress.c \
	csparse/cs_cumsum.c \
	csparse/cs_entry.c \
	csparse/cs_malloc.c \
	csparse/cs_multiply.c \
	csparse/cs_norm.c \
	csparse/cs_print.c \
	csparse/cs_scatter.c \
	csparse/cs_util.c

libcentrality_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libcentrality_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libcentrality_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libcentrality_la_CFLAGS += -D_GNU_SOURCE
endif

libcentrality_la_LDFLAGS = -shrext .so  # extension for shared library
