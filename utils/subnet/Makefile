CC             ?= gcc

RM             := rm -f
UNAME_S        := $(shell uname -s)

CFLAGS_DEFAULT := -pipe -Wall -Wextra -Wundef -std=gnu99 -MMD -MP \
                  -I.. -I../../tranalyzer2/src

ifeq ($(UNAME_S), Darwin)
CFLAGS_DEFAULT += -D_DARWIN_C_SOURCE
else
CFLAGS_DEFAULT += -D_GNU_SOURCE
endif

CFLAGS         := $(CFLAGS_DEFAULT) -O2
CFLAGS_DEBUG   := $(CFLAGS_DEFAULT) -O0 -g2 -ggdb

LDLIBS_EXTRA   := -lm

# IPv4 utilities
SRC4           := ext4.c nett4.c sbm4.c vect4.c
EXEC4          := $(SRC4:.c=)
OBJS4          := $(SRC4:.c=.o)
DEPS4          := $(OBJS4:.o=.d)

# IPv6 utilities
SRC6           := ext6.c nett6.c sbm6.c vect6.c
EXEC6          := $(SRC6:.c=)
EXTRA6_2       := corr6 rng6
OBJS6          := $(SRC6:.c=.o) corr6.o rng6.o
DEPS6          := $(OBJS6:.o=.d) corr6.d rng6.d

EXEC           := $(EXEC4) $(EXEC6) $(EXTRA4) $(EXTRA6) $(EXTRA6_2)
SRC            := $(wildcard *.c)
OBJS           := $(SRC:.c=.o)
DEPS           := $(OBJS:.o=.d)

.PHONY: all debug utils_v4 utils_v6

all: utils_v4 utils_v6

utils_v4: $(EXEC4)

utils_v6: $(EXEC6)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all


# SRC4

ext4: ext4.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

nett4: nett4.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

sbm4: sbm4.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

vect4: vect4.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# SRC6

ext6: ext6.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

nett6: nett6.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

sbm6: sbm6.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

vect6: vect6.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)


# EXTRA6_2

corr6: corr6.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

rng6: rng6.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

-include $(DEPS)

.PHONY: clean clean_v4 clean_v6

clean:
	make -C tor clean
	$(RM) $(OBJS) $(DEPS)

clean_v4:
	$(RM) $(OBJS4) $(DEPS4)

clean_v6:
	$(RM) $(OBJS6) $(DEPS6)

.PHONY: mrproper mrproper_v4 mrproper_v6

mrproper: clean
	make -C tor mrproper
	$(RM) $(EXEC)

mrproper_v4: clean_v4
	$(RM) $(EXEC4) $(EXTRA4)

mrproper_v6: clean_v6
	$(RM) $(EXEC6) $(EXTRA6)

.PHONY: distclean distclean_v4 distclean_v6

distclean: mrproper
	make -C tor distclean

distclean_v4: mrproper_v4

distclean_v6: mrproper_v6
