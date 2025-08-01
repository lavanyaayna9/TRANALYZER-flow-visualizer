CC             ?= gcc

RM             := rm -f
UNAME_S        := $(shell uname -s)

CFLAGS_DEFAULT := -pipe -Wall -Wextra -Wundef -std=gnu99 -MMD -MP \
                  -DUSE_ZLIB=1 -I.. -I../../tranalyzer2/src/

ifeq ($(UNAME_S), Darwin)
CFLAGS_DEFAULT += -D_DARWIN_C_SOURCE
else
CFLAGS_DEFAULT += -D_GNU_SOURCE
endif

CFLAGS         := $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   := $(CFLAGS_DEFAULT) -O0 -g3 -ggdb

LDFLAGS        :=
LDLIBS         := -lm -lz

EXEC           := t2b2t
SRC            := src/$(EXEC).c \
                  ../../tranalyzer2/src/binaryValue.c \
                  ../bin2txt.c \
                  ../gz2txt.c \
                  ../t2utils.c
OBJS           := $(SRC:.c=.o)
DEPS           := $(OBJS:.o=.d)

.PHONY: all debug

all: $(EXEC)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

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
