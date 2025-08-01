CC             ?= gcc

RM             := rm -f
UNAME_S        := $(shell uname -s)

CFLAGS_DEFAULT := -w -pipe -Wall -Wextra -Wundef -std=gnu99 -MMD -MP \
                  -I../src/nDPI/src/include

ifeq ($(UNAME_S), Darwin)
CFLAGS_DEFAULT += -D_DARWIN_C_SOURCE
else
CFLAGS_DEFAULT += -D_GNU_SOURCE
endif

# Include directory for automatically generated files
NDPI_INC       := $(shell find .. -type d -name include | grep "[^\.]/src/nDPI/src/include" | xargs ls -td1 | head -1)

ifneq ($(NDPI_INC), )
CFLAGS_DEFAULT += -I$(NDPI_INC)
endif

CFLAGS         := $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   := $(CFLAGS_DEFAULT) -O0 -g3 -ggdb

LDFLAGS        :=
LDLIBS         :=

ifneq ($(shell find .. -type f -name libndpi.a),)
LIBNDPI_A      := $(shell find .. -type f -name libndpi.a | xargs ls -t1 | head -1)
LDLIBS         += $(LIBNDPI_A) -lgcrypt -lm
endif

EXEC           := prototex
SRC            := main.c
OBJS           := $(SRC:.c=.o)
DEPS           := $(OBJS:.o=.d)

.PHONY: all debug

all: check_libndpi_a $(EXEC)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

check_libndpi_a:
ifeq ($(LIBNDPI_A), )
	$(error "Could not find 'libndpi.a'. Please run ./autogen.sh in the parent directory first to build the nDPI library")
endif

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

-include $(DEPS)

.PHONY: install

install:
	@echo "Nothing to install"

.PHONY: clean mrproper distclean

clean:
	$(RM) $(OBJS) $(DEPS)

mrproper: clean
	$(RM) $(EXEC)

distclean: mrproper
