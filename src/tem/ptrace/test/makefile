PATH_TO_SRC=../../..
PATH_TO_ROOT=../../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=tem/ptrace/$(basename $(CPATH))

include $(PATH_TO_SRC)/flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)

CFLAGS+=-g -I. $(addprefix -I$(PATH_TO_SRC)/, erim common) -fno-inline -I/usr/include

TESTCASES=test_application test_ptracespeed
TESTBINARIES=$(addprefix $(PATH_TO_BIN)/, $(TESTCASES)) 

LDLIBS=

all: createoutput $(TESTBINARIES) run

$(PATH_TO_BIN)/../erimptrace:
	make -C ../

$(PATH_TO_BIN)/test_application: test_application
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_ptracespeed: test_ptracespeed
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/returns: returns
	cp $^ $@

run: $(PATH_TO_BIN)/test_ptracespeed $(PATH_TO_BIN)/../erimptrace 
	echo "No ptrace:" 
	$(PATH_TO_BIN)/test_ptracespeed
	echo "With ptrae:"
	$(PATH_TO_BIN)/../erimptrace LD_LIBRARY_PATH="$(PATH_TO_BIN)/..:$(PATH_TO_BIN)/../../libtem:$(PATH_TO_BIN)/../../../erim" $(PATH_TO_BIN)/test_ptracespeed

test: $(PATH_TO_BIN)/test_application $(PATH_TO_BIN)/../erimptrace $(PATH_TO_BIN)/returns
	echo "Run without protection - should not break:"
	$(PATH_TO_BIN)/test_application
	echo "Run with protection - should break:"
	$(PATH_TO_BIN)/../erimptrace LD_LIBRARY_PATH="$(PATH_TO_BIN)/..:$(PATH_TO_BIN)/../../libtem:$(PATH_TO_BIN)/../../../erim" $(PATH_TO_BIN)/test_application

dbg:
	LD_LIBRARY_PATH="$(PATH_TO_BIN)/..:$(PATH_TO_BIN)/../../libtem:$(PATH_TO_BIN)/../../../erim" LD_PRELOAD="$(PATH_TO_BIN)/../../libtem/libtem-ptrace.so" $(PATH_TO_BIN)/test_application

include $(PATH_TO_SRC)/common.mk

clean:
	rm -f *.o
	rm -f $(PATH_TO_BIN)/*
