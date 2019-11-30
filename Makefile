CC=gcc
CFLAGS=-DDEBUG -g -ljansson -lnftables
TARGRT_PATH=bin/
SRC_PATH=tests/
SOURCES=$(wildcard tests/*.c)
TARGETS=$(basename $(SOURCES))
LIB=nft_json_api

.PHONY : all clean

all : $(TARGETS)

$(TARGETS) : mkdir
	$(CC) $@.c $(CFLAGS) $(LIB).c -o $(TARGRT_PATH)$(notdir $@)

mkdir :
	mkdir bin
	mkdir json

clean :
	rm -rf bin
	rm -rf json