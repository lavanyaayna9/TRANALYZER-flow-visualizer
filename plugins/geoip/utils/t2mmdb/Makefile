CC             ?= gcc

RM             := rm -f
UNAME_S        := $(shell uname -s)

ifeq ($(shell hash pkg-config && pkg-config libmaxminddb && echo true), true)
PKG_CONFIG     := $(shell which pkg-config)
endif

#GEOIP_LIB      := $(shell ../../../../scripts/t2conf/t2conf geoip -G GEOIP_LIB | cut -d' ' -f3)
GEOIP_LIB      := $(shell perl -nle 'print $$1 if /^\#define\s+GEOIP_LIB\s+(\d+).*$$/' ../../src/geoip.h)

CFLAGS_DEFAULT := -pipe -Wall -Wextra -Wundef -std=gnu99 -MMD -MP -I../../src \
                  -I../../../../tranalyzer2/src -I../../../../utils

ifeq ($(UNAME_S), Darwin)
CFLAGS_DEFAULT += -D_DARWIN_C_SOURCE
else
CFLAGS_DEFAULT += -D_GNU_SOURCE
endif

ifeq ($(GEOIP_LIB), 2)
CFLAGS_DEFAULT += -I../../src/MMDB
else  # GEOIP_LIB != 2
ifneq ($(PKG_CONFIG), )
CFLAGS_DEFAULT += $(shell $(PKG_CONFIG) --cflags libmaxminddb)
endif
endif  # GEOIP_LIB

CFLAGS         := $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   := $(CFLAGS_DEFAULT) -O0 -g3 -ggdb

LDFLAGS        :=
LDLIBS         := -lm

ifeq ($(GEOIP_LIB), 2)
ifneq ($(shell find ../.. -type f -name libmaxminddb.a),)
LIBMAXMINDDB_A := $(shell find ../.. -type f -name libmaxminddb.a | xargs ls -t1 | head -1)
LDLIBS         += $(LIBMAXMINDDB_A)
endif
else  # GEOIP_LIB != 2
ifneq ($(PKG_CONFIG), )
LDFLAGS        += $(shell $(PKG_CONFIG) --libs-only-L libmaxminddb)
LDLIBS         += $(shell $(PKG_CONFIG) --libs-only-l --libs-only-other libmaxminddb)
else
LDLIBS         += -lmaxminddb
endif
endif  # GEOIP_LIB

EXEC           := t2mmdb
SRC            := src/$(EXEC).c \
                  ../../../../utils/t2utils.c
OBJS           := $(SRC:.c=.o)
DEPS           := $(OBJS:.o=.d)

.PHONY: all debug

all: check_libmaxminddb_a $(EXEC)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

check_libmaxminddb_a:
ifeq ($(GEOIP_LIB), 2)
ifeq ($(LIBMAXMINDDB_A), )
	$(error "Could not find 'libmaxminddb.a'. Try building geoip with GEOIP_LIB != 0 first")
endif
endif  # GEOIP_LIB

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

-include $(DEPS)

.PHONY: install

install:
	install $(EXEC) /usr/bin

.PHONY: clean mrproper distclean

clean:
	$(RM) $(OBJS) $(DEPS)

mrproper: clean
	$(RM) $(EXEC)

distclean: mrproper
