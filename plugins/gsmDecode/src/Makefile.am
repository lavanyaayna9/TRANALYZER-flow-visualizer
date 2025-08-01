lib_LTLIBRARIES = libgsmDecode.la

libgsmDecode_la_SOURCES = \
	@PACKAGE_NAME@.c \
	e164_list.c \
	gsm_a_rp.c \
	gsm_a_dtap.c \
	gsm_amr.c \
	gsm_lapd.c \
	gsm_lapdm.c \
	gsm_osmocore.c \
	gsm_rsl.c \
	gsm_sms.c \
	gsm_utils.c \
	gsmtap.c \
	mcc_list.c \
	tac_list.c \
	../../../utils/t2buf.c

libgsmDecode_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src

libgsmDecode_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libgsmDecode_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libgsmDecode_la_CFLAGS += -D_GNU_SOURCE
endif

libgsmDecode_la_LDFLAGS = -shrext .so  # extension for shared library
                                    # (without this flag, would be '.dylib' on macOS)
