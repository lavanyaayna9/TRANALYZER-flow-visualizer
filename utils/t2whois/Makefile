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

CFLAGS         := $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   := $(CFLAGS_DEFAULT) -O0 -g3 -ggdb

LDFLAGS        :=
LDLIBS         := -lm -lpthread -lreadline

ifneq ($(UNAME_S), Darwin)
NEED_LIBBSD    := $(shell perl -nle 'print $$1 if /^\#define\s+T2WHOIS_RANDOM\s+(\d+).*$$/' src/t2whois.h)
ifeq ($(NEED_LIBBSD), 1)
# -lbsd is required for arc4random()
LDLIBS         += -lbsd
endif
endif  # Darwin

EXEC           := t2whois
SRC            := src/$(EXEC).c \
                  src/$(EXEC)-prompt.c \
                  src/$(EXEC)-server.c \
                  src/$(EXEC)-utils.c \
                  ../iputils.c \
                  ../subnetHL4.c \
                  ../subnetHL6.c \
                  ../t2utils.c
OBJS           := $(SRC:.c=.o)
DEPS           := $(OBJS:.o=.d)

.PHONY: all debug

all: $(EXEC)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

subnets: subnet4 subnet6

subnet4:
	bzip2 -dfk ../subnet/subnets4.txt.bz2 || exit 1
	../subnet/subconv -t subnets4.txt || exit 1
	mkdir -p ~/.tranalyzer/plugins/
	cp ../subnet/subnets4_HLP.bin ~/.tranalyzer/plugins/

subnet6:
	bzip2 -dfk ../subnet/subnets6.txt.bz2 || exit 1
	../subnet/subconv -t subnets6.txt || exit 1
	mkdir -p ~/.tranalyzer/plugins/
	cp ../subnet/subnets6_HLP.bin ~/.tranalyzer/plugins/

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
