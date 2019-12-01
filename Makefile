CC=gcc
CFLAGS=-DDEBUG -g -ljansson -lnftables
EXAM_PATH=examples/
BIN_PATH=bin/
SRC_PATH=src/
JSON_PATH=json/
LIB=nft_json_api
SOURCES=$(wildcard $(wildcard $(EXAM_PATH)$(SRC_PATH))*.c)
TARGETS=$(basename $(SOURCES))

.PHONY : all clean mkdir

all : $(TARGETS)

$(TARGETS) : mkdir $(LIB).a
	$(CC) $@.c $(CFLAGS) -L. -l$(LIB) -o $(EXAM_PATH)$(BIN_PATH)$(notdir $@)

$(LIB).a : $(LIB).o
	ar rc lib$@ $(LIB).o
	ranlib lib$(LIB).a

$(LIB).o :
	$(CC) $(CFLAGS) -c $(LIB).c -o $@

mkdir :
	mkdir $(EXAM_PATH)$(BIN_PATH)
	mkdir $(EXAM_PATH)$(JSON_PATH)

clean :
	rm -rf $(EXAM_PATH)$(BIN_PATH)
	rm -rf $(EXAM_PATH)$(JSON_PATH)
	rm -r *.o
	rm -r *.a