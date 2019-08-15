PATH_TO_SRC=../..
PATH_TO_ROOT=../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=tem/$(basename $(CPATH))

include ../../flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)

CFLAGS+=-g -I. -I../../erim -I../../common -fno-inline -I/usr/include

LDLIBS=

all: createoutput $(LIBRARIES) $(PATH_TO_BIN)/erimptrace

$(PATH_TO_BIN)/../../erim/liberim.a:
	make -C ../../erim

$(PATH_TO_BIN)/../../common/libswscommon.a:
	make -C ../../common/

$(PATH_TO_BIN)/erimptrace: erimptrace.o
	$(CC) $(CLFAGS) -lunwind-ptrace -lunwind-x86_64 -lunwind -o $@ $^

test:
	make -C test test

include ../../common.mk

clean:
	rm -f *.o
	find $(PATH_TO_BIN)/ -maxdepth 1 -type f -exec rm -f {} \;
