CC             ?= gcc

RM             := rm -f
UNAME_S        := $(shell uname -s)

CFLAGS_DEFAULT := -pipe -Wall -Wextra -Wundef -std=gnu99 -MMD -MP \
                  -I../src/ -I../../../utils/ -I../../../tranalyzer2/src/

ifeq ($(UNAME_S), Darwin)
CFLAGS_DEFAULT += -D_DARWIN_C_SOURCE
else
CFLAGS_DEFAULT += -D_GNU_SOURCE
endif

CFLAGS         := $(CFLAGS_DEFAULT) -O2
CFLAGS_DEBUG   := $(CFLAGS_DEFAULT) -O0 -g2 -ggdb

LDFLAGS        :=
LDLIBS         :=

EXEC           := mbm
SRC            := $(EXEC).c
OBJS           := $(SRC:.c=.o)
DEPS           := $(OBJS:.o=.d)

EXEC1           := ucv
SRC1            := $(EXEC1).c
OBJS1           := $(SRC1:.c=.o)
DEPS1           := $(OBJS1:.o=.d)

.PHONY: all debug

all: $(EXEC) $(EXEC1)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(EXEC1): $(OBJS1)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

-include $(DEPS)

.PHONY: install

install:
	@echo "Nothing to install"

.PHONY: clean mrproper distclean

clean:
	$(RM) $(OBJS) $(DEPS) $(OBJS1) $(DEPS1)

mrproper: clean
	$(RM) $(EXEC) $(EXEC1)

distclean: mrproper
