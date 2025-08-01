CC             ?= gcc

RM             := rm -f
UNAME_S        := $(shell uname -s)

CFLAGS_DEFAULT := -pipe -Wall -Wextra -Wundef -std=gnu99 -MMD -MP \
                  -I../../../tranalyzer2/src/ -I../../../utils/

ifeq ($(UNAME_S), Darwin)
CFLAGS_DEFAULT += -D_DARWIN_C_SOURCE
else
CFLAGS_DEFAULT += -D_GNU_SOURCE
endif

CFLAGS         := $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   := $(CFLAGS_DEFAULT) -O0 -g3 -ggdb

LDFLAGS        :=
LDLIBS         :=

EXEC           := pfb
SRC            := $(EXEC).c
OBJS           := $(SRC:.c=.o)
DEPS           := $(OBJS:.o=.d)

.PHONY: all debug

all: $(EXEC)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

-include $(DEPS)

.PHONY: clean mrproper distclean

clean:
	$(RM) $(OBJS) $(DEPS)

mrproper: clean
	$(RM) $(EXEC)

distclean: mrproper
