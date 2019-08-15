\1;3409;0cPATH_TO_SRC=../..
PATH_TO_ROOT=../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=apilwc/$(basename $(CPATH))

include ../../flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)
PATH_TO_RES=$(PATH_TO_ROOT)/$(RESULT)/$(CURRENT_FOLDER)

CFLAGS+=-g -I. -I../../api -I../../common -fno-inline

TESTCASES=test_application test_speed test_speed_0 test_speed_4 test_speed_8 test_speed_12 test_speed_16 test_size

LDLIBS=$(PATH_TO_BIN)/../liberimapi.a $(PATH_TO_BIN)/../../common/libswscommon.a -lm ../../../../snap/libs/liblwc.a

all: createoutput createresult allbinaries #run

allbinaries: $(addprefix $(PATH_TO_BIN)/, $(TESTCASES)) 

$(PATH_TO_BIN)/../liberimapi.a:
	make -C ../

$(PATH_TO_BIN)/test_application: test_application $(PATH_TO_BIN)/../liberimapi.a ../../../../snap/libs/liblwc.a
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_speed_%: test_speed.c $(PATH_TO_BIN)/../liberimapi_%.a $(PATH_TO_BIN)/../../common/libswscommon.a  ../../../../snap/libs/liblwc.a
	$(CC) $(CFLAGS) -D WRPKRUCOST=$* -o $@ $^ -lm

$(PATH_TO_BIN)/test_speed_%: test_speed_%
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_speed: test_speed $(PATH_TO_BIN)/../liberimapi.a ../../../../snap/libs/liblwc.a
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_size: test_size $(PATH_TO_BIN)/../liberimapi.a ../../../../snap/libs/liblwc.a
	mv $< $(PATH_TO_BIN)

run: $(PATH_TO_BIN)/test_application $(PATH_TO_BIN)/test_speed $(PATH_TO_BIN)/test_size 
	$(PATH_TO_BIN)/test_application
	$(PATH_TO_BIN)/test_speed_0 100000 100000000 >$(PATH_TO_RES)/test_speed_0.txt 
	$(PATH_TO_BIN)/test_speed_4 100000 100000000 > $(PATH_TO_RES)/test_speed_4.txt
	$(PATH_TO_BIN)/test_speed_8 100000 100000000 > $(PATH_TO_RES)/test_speed_8.txt
	$(PATH_TO_BIN)/test_speed_12 100000 100000000 > $(PATH_TO_RES)/test_speed_12.txt
	$(PATH_TO_BIN)/test_speed_16 100000 100000000 > $(PATH_TO_RES)/test_speed_16.txt
	$(PATH_TO_BIN)/test_size "0"  > $(PATH_TO_RES)/test_size_0.txt
	$(PATH_TO_BIN)/test_size "4096"  > $(PATH_TO_RES)/test_size_4096.txt
	$(PATH_TO_BIN)/test_size "32768"  > $(PATH_TO_RES)/test_size_32768.txt
	$(PATH_TO_BIN)/test_size "262144"  > $(PATH_TO_RES)/test_size_262144.txt
	$(PATH_TO_BIN)/test_size "2097152"  > $(PATH_TO_RES)/test_size_2097152.txt
	$(PATH_TO_BIN)/test_size "16777216"  > $(PATH_TO_RES)/test_size_16777216.txt
	$(PATH_TO_BIN)/test_size "134217728"  > $(PATH_TO_RES)/test_size_134217728.txt
	git add $(PATH_TO_RES)/*
	git commit -a -m "new test_speed test_size results"

include ../../common.mk

clean:
	rm -f *.o
	rm -f $(PATH_TO_BIN)/*
