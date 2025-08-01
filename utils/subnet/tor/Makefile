CC             ?= gcc

RM             := rm -f
UNAME_S        := $(shell uname -s)

CFLAGS_DEFAULT := -pipe -Wall -Wextra -Wundef -std=gnu99 -MMD -MP \
                  -I../.. -I../../../tranalyzer2/src/

ifeq ($(UNAME_S), Darwin)
CFLAGS_DEFAULT += -D_DARWIN_C_SOURCE
else
CFLAGS_DEFAULT += -D_GNU_SOURCE
endif

CFLAGS         := $(CFLAGS_DEFAULT) -O2
CFLAGS_DEBUG   := $(CFLAGS_DEFAULT) -O0 -g2 -ggdb

LDLIBS         := -lm

EXEC4          := bsHL4
SRC4           := bsHL4.c ../../subnetHL4.c ../../t2utils.c
OBJS4          := $(SRC4:.c=.o)
DEPS4          := $(OBJS4:.o=.d)

EXEC6          := bsHL6
SRC6           := bsHL6.c ../../subnetHL6.c ../../t2utils.c
OBJS6          := $(SRC6:.c=.o)
DEPS6          := $(OBJS6:.o=.d)

EXECTJX        := tjx
SRCTJX         := tjx.c
OBJTJX         := $(SRCTJX:.c=.o)
DEPTJX         := $(OBJTJX:.o=.d)

EXEC           := $(EXEC4) $(EXEC6) $(EXECTJX)
SRC            := $(SRC4) $(SRC6) $(SRCTJX)
OBJS           := $(SRC:.c=.o)
DEPS           := $(OBJS:.o=.d)

.PHONY: all debug utils_v4 utils_v6 utils_tjx

all: utils_v4 utils_v6 utils_tjx

utils_v4: $(EXEC4)

utils_v6: $(EXEC6)

utils_tjx: $(EXECTJX)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

$(EXEC4): $(OBJS4)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(EXEC6): $(OBJS6)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(EXECTJX): $(OBJTJX)
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
