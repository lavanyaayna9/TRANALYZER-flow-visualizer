lib_LTLIBRARIES = libwechatDecode.la

libwechatDecode_la_SOURCES = \
	wechatDecode.c \
	jce.c \
	lib/frozen/frozen.c \
	../../../utils/t2buf.c

libwechatDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libwechatDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libwechatDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libwechatDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libwechatDecode_la_LDFLAGS = -shrext .so  # extension for shared library
