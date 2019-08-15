PATH_TO_SRC=../..
PATH_TO_ROOT=../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=erim/$(basename $(CPATH))

include ../../flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)

CFLAGS+=-g -I. -I../ -I../../common -fno-inline 

TESTCASES=test_application test_application_integrity
TESTBINARIES=$(addprefix $(PATH_TO_BIN)/, $(TESTCASES)) 

LDLIBS= -lm -L$(PATH_TO_BIN) -ltest -ldl
SECRETLIBS=$(PATH_TO_BIN)/libtest.so $(PATH_TO_BIN)/libtesterimized.so $(PATH_TO_BIN)/libtesterimizedint.so

all: createoutput $(LIBRARIES) $(SECRETLIBS) $(TESTBINARIES) run

$(PATH_TO_BIN)/../liberim.a:
	make -C ../

$(PATH_TO_BIN)/../../common/libswscommon.a:
	make -C ../../common/

$(PATH_TO_BIN)/libtest.so: test_libtest-pic.o
	$(CC) -shared -o $@ $^ 

$(PATH_TO_BIN)/libtesterimized.so: test_libtesterimized-pic.o
	$(CC) -shared -L$(PATH_TO_BIN) -ltest -L$(PATH_TO_BIN)/../ -lerim -o $@ $^ 

$(PATH_TO_BIN)/libtesterimizedint.so: test_libtesterimizedint-pic.o
	$(CC) -shared -L$(PATH_TO_BIN) -ltest -L$(PATH_TO_BIN)/../ -lerim -o $@ $^ 

$(PATH_TO_BIN)/test_application_integrity: test_application_integrity
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_application: test_application
	mv $< $(PATH_TO_BIN)

run: 
	tmp=`mktemp /tmp/testcase-XXXXXXXXXX`; \
	LD_PRELOAD=$(PATH_TO_BIN)/libtesterimized.so LD_LIBRARY_PATH=$(PATH_TO_BIN):$(PATH_TO_BIN)/../ $(PATH_TO_BIN)/test_application > $$tmp 2>&1; \
	result=`cat $$tmp | tail -n 2 | md5sum | cut -d ' ' -f 1`; \
	expected="31df8f1686ebecf6f211688be59df168"; \
	basename="test_application";\
	if [ $$result = $$expected ]; then \
		echo "[$$basename] Succesful";\
	else \
		echo "[$$basename] FAILED $$result";\
	fi; \
	rm $$tmp; \
	tmp=`mktemp /tmp/testcase-XXXXXXXXXX`; \
	LD_PRELOAD=$(PATH_TO_BIN)/libtesterimizedint.so LD_LIBRARY_PATH=$(PATH_TO_BIN):$(PATH_TO_BIN)/../ $(PATH_TO_BIN)/test_application_integrity > $$tmp 2>&1; \
	result=`cat $$tmp | tail -n 2 | md5sum | cut -d ' ' -f 1`; \
	expected="31df8f1686ebecf6f211688be59df168"; \
	basename="test_application_integrity";\
	if [ $$result = $$expected ]; then \
		echo "[$$basename] Succesful";\
	else \
		echo "[$$basename] FAILED $$result";\
	fi; \
	rm $$tmp;

dbg:
	LD_PRELOAD=$(PATH_TO_BIN)/libtesterimized.so LD_LIBRARY_PATH=$(PATH_TO_BIN):$(PATH_TO_BIN)/../ $(PATH_TO_BIN)/test_application


include ../../common.mk

clean:
	rm -f *.o
	rm -f $(PATH_TO_BIN)/*
