PATH_TO_SRC=../..
PATH_TO_ROOT=../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=tem/$(basename $(CPATH))

include ../../flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)

CFLAGS+=-g -I. -I../../erim -I../../common -fno-inline -I/usr/include

LDFLAGS=-L$(PATH_TO_BIN)/../../erim -lerim -ldl

all: createoutput $(PATH_TO_BIN)/libtem-ptrace.so $(PATH_TO_BIN)/libtem-lsm.so

libtem_trampsignal.o: libtem_trampsignal.asm
	nasm -felf64 -o libtem_trampsignal.o libtem_trampsignal.asm

$(PATH_TO_BIN)/libtem-lsm.so: libtem_memmap-pic.o libtem_signals-pic.o libtem-pic.o libtem_lsm-pic.o libtem_trampsignal.o
	$(CC) $(LDFLAGS) -shared -o $@ $^

$(PATH_TO_BIN)/libtem-ptrace.so: libtem_memmap-pic.o libtem_signals-pic.o libtem-pic.o libtem_ptrace-pic.o libtem_trampsignal.o
	$(CC) $(LDFLAGS) -shared -o $@ $^

distclean:
	rm *.o

include ../../common.mk

clean:
	rm -f *.o
	find $(PATH_TO_BIN)/ -maxdepth 1 -type f -exec rm -f {} \;
