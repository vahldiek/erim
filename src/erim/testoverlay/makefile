PATH_TO_SRC=../..
PATH_TO_ROOT=../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=erim/$(basename $(CPATH))

include ../../flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)

CFLAGS+=-g -I. -I../ -I../../common -fno-inline

TESTCASES=test_application test_application_integrity
TESTBINARIES=$(addprefix $(PATH_TO_BIN)/, $(TESTCASES)) 

LIBRARIES=$(PATH_TO_BIN)/../../common/libswscommon.a $(PATH_TO_BIN)/../liberim.a
LDLIBS= -lm $(LIBRARIES)

all: createoutput $(LIBRARIES) $(TESTBINARIES) run

$(PATH_TO_BIN)/../liberim.a:
	make -C ../

$(PATH_TO_BIN)/../../common/libswscommon.a:
	make -C ../../common/

$(PATH_TO_BIN)/test_application_integrity: test_application_integrity
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_application: test_application
	mv $< $(PATH_TO_BIN)

run: $(TESTBINARIES)
	for test in $(TESTBINARIES); do \
		tmp=`mktemp /tmp/testcase-XXXXXXXXXX`; \
		./$$test > $$tmp 2>&1; \
		result=`cat $$tmp | tail -n 2 | md5sum | cut -d ' ' -f 1`; \
		expected="31df8f1686ebecf6f211688be59df168"; \
		basename=`basename $$test`;\
		if [ $$result = $$expected ]; then \
			echo "[$$basename] Succesful";\
		else \
			echo "[$$basename] FAILED $$result";\
		fi; \
		rm $$tmp; \
	done

include ../../common.mk

clean:
	rm -f *.o
	rm -f $(PATH_TO_BIN)/*
