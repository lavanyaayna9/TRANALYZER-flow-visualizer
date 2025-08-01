CC             = gcc
RM             = rm -f
CFLAGS_DEFAULT = -pipe -Wall -fPIC
CFLAGS         = $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   = $(CFLAGS_DEFAULT) -O0 -g3 -ggdb
CPPFLAGS       = -I"./include"
LIBNAME        = libnaivebayes
LIBFILE        = $(LIBNAME).la
LIBSRC         = $(wildcard src/*.c)
LIBOBJ         = $(LIBSRC:.c=.lo)

LIBHDR = naivebayes.h

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
LIBTOOL = glibtool
SHA1SUM = gsha1sum
else
LIBTOOL = libtool
SHA1SUM = sha1sum
endif

.DEFAULT_GOAL:=all
.PHONY: all debug

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: CPPFLAGS+=$(CPPFLAGS_DEBUG)
debug: $(LIBFILE)

all:  $(LIBFILE)

$(LIBFILE): $(LIBOBJ)
	$(LIBTOOL) --tag=CC --mode=link $(CC) -static -o $@ $(LIBOBJ)

%.lo: %.c
	$(LIBTOOL) --tag=CC --mode=compile $(CC) -static $(CFLAGS) $(CPPFLAGS) -c $^ -o $@

clean:
	$(LIBTOOL) --mode=clean rm -Rf $(LIBNAME).a $(LIBOBJ)

install: $(LIBFILE)
	cp .libs/$(LIBNAME).a /usr/local/lib
	cp include/$(LIBHDR) /usr/local/include
