CC             = gcc
RM             = rm -f
CFLAGS_DEFAULT = -pipe -Wall
CFLAGS         = $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   = $(CFLAGS_DEFAULT) -O0 -g3 -ggdb
CPPFLAGS       = -I".../include" 
LDFLAGS        = -L../.libs -lnaivebayes -ljansson -lm
SRC            = $(wildcard src/*.c)
EXEC           = nb-tester

all:
	$(CC) $(SRC) -o $(EXEC) $(CFLAGS) $(LDFLAGS)

debug:
	$(CC) $(SRC) -o $(EXEC) $(CFLAGS_DEBUG) $(LDFLAGS)

clean:
	$(RM) $(EXEC)
