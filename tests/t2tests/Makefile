CC             ?= gcc

RM             := rm -f
UNAME_S        := $(shell uname -s)

CFLAGS_DEFAULT := -pipe -Wall -Wextra -Wundef -std=gnu99 -MMD -MP \
                  -I../../utils -I../../tranalyzer2/src/

ifeq ($(UNAME_S), Darwin)
CFLAGS_DEFAULT += -D_DARWIN_C_SOURCE
else
CFLAGS_DEFAULT += -D_GNU_SOURCE
endif

CFLAGS         := $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   := $(CFLAGS_DEFAULT) -O0 -g3 -ggdb

LDFLAGS        :=
LDLIBS         := -lm

EXEC           := t2tests
SRC            := src/$(EXEC).c \
                  src/test_iputils.c \
                  src/test_t2base64.c \
                  src/test_t2log.c \
                  src/test_t2utils.c \
                  ../../utils/iputils.c \
                  ../../utils/t2base64.c \
                  ../../utils/t2log.c \
                  ../../utils/t2utils.c
OBJS           := $(SRC:.c=.o)
DEPS           := $(OBJS:.o=.d)

.PHONY: all debug

all: $(EXEC)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

-include $(DEPS)

.PHONY: run

run:
	./t2tests 0

.PHONY: clean mrproper distclean

clean:
	$(RM) $(OBJS) $(DEPS)

mrproper: clean
	$(RM) $(EXEC)

distclean: mrproper
