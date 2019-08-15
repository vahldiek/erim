PATH_TO_SRC=../../..
PATH_TO_ROOT=../../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=tem/kernelmodule/$(basename $(CPATH))

include $(PATH_TO_SRC)/flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)

CFLAGS+=-g -I. $(addprefix -I$(PATH_TO_SRC)/, erim common) -fno-inline -I/usr/include -L$(PATH_TO_ROOT)/bin/erim -lerim

TESTCASES=test_application test_kernelspeed
TESTBINARIES=$(addprefix $(PATH_TO_BIN)/, $(TESTCASES)) 

LDLIBS=

all: createoutput $(TESTBINARIES) run

$(PATH_TO_BIN)/../erimptrace:
	make -C ../

$(PATH_TO_BIN)/test_application: test_application
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_kernelspeed: test_kernelspeed
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/returns: returns
	cp $^ $@

run: $(PATH_TO_BIN)/test_kernelspeed 
	echo "No protection:" 
	LD_LIBRARY_PATH=$(PATH_TO_BIN)/../../../erim $(PATH_TO_BIN)/test_kernelspeed
	echo "With protection:"
	LD_LIBRARY_PATH=$(PATH_TO_BIN)/../../../erim $(PATH_TO_BIN)/test_kernelspeed WITH_PROTECTION

test: $(PATH_TO_BIN)/test_application $(PATH_TO_BIN)/returns
	echo "ATTENTION: Assumes kernel booted and lsm insmod successfull!!!"
	echo "Run without protection - should not break:"
	LD_LIBRARY_PATH=$(PATH_TO_BIN)/../../../erim:$(PATH_TO_BIN)/../../libtem $(PATH_TO_BIN)/test_application
	echo "Run with protection - should break:"
	LD_LIBRARY_PATH=$(PATH_TO_BIN)/../../../erim:$(PATH_TO_BIN)/../../libtem LD_PRELOAD="libtem-lsm.so" $(PATH_TO_BIN)/test_application WITH_PROTECTION

include $(PATH_TO_SRC)/common.mk

clean:
	rm -f *.o
	rm -f $(PATH_TO_BIN)/*
