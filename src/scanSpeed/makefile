PATH_TO_SRC=..
PATH_TO_ROOT=../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=$(basename $(CPATH))

include $(PATH_TO_SRC)/flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)

CFLAGS+=-g -I. -I../common -I../erim -lm

TESTCASES=scanSpeed

all: createoutput allbinaries #test

allbinaries: $(addprefix $(PATH_TO_BIN)/, $(TESTCASES)) 

scanSpeed: scanSpeed.c $(PATH_TO_BIN)/../erim/liberim.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(PATH_TO_BIN)/../erim/liberim.a

$(PATH_TO_BIN)/scanSpeed: scanSpeed
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/scanToFile: scanToFile           
	mv $< $(PATH_TO_BIN)

test:
	cp $(PATH_TO_BIN)/scanSpeed testbinary
	LD_LIBRARY_PATH=$(PATH_TO_BIN)/../erim/ $(PATH_TO_BIN)/scanSpeed testbinary

bench:
	LD_LIBRARY_PATH=$(PATH_TO_BIN)/../erim find bin2 -type f | xargs $(PATH_TO_BIN)/scanSpeed


include $(PATH_TO_SRC)/common.mk

clean:
	rm -f *.o
	rm -f $(PATH_TO_BIN)/*
