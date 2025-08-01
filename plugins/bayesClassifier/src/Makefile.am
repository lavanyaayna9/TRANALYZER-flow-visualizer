lib_LTLIBRARIES = libbayesClassifier.la

libbayesClassifier_la_SOURCES = \
	bayesClassifier.c \
	libs/naivebayes/src/naivebayes.c

libbayesClassifier_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src \
	-I$(top_srcdir)/../nFrstPkts/src \
	-I$(top_srcdir)/src/libs/naivebayes/include

libbayesClassifier_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""

if APPLE
libbayesClassifier_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libbayesClassifier_la_CFLAGS += -D_GNU_SOURCE
endif

libbayesClassifier_la_LDFLAGS = -shrext .so  # extension for shared library
