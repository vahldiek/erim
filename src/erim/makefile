PATH_TO_SRC=..
PATH_TO_ROOT=../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=$(basename $(CPATH))

include $(PATH_TO_SRC)/flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)
INCLUDE_PATH=-I. -I../common
LIBRARY_PATH=
DEP_LIBS=
EXEC_SOURCE=erim_printstats erim_processmappings erim_shmem shared_malloc erim

CFLAGS+=$(INCLUDE_PATH) -g 

BUILD_LIBS=$(PATH_TO_BIN)/liberim

#CC=clang

all: createoutput $(addsuffix .a, $(BUILD_LIBS)) $(addsuffix .so, $(BUILD_LIBS)) $(addsuffix simu.a, $(BUILD_LIBS)) $(addsuffix simu.so, $(BUILD_LIBS)) #$(PATH_TO_BIN)/liberimfinal.so


$(PATH_TO_BIN)/liberim.a: $(addsuffix .o, $(EXEC_SOURCE))
	ar -cq $@ $^

$(PATH_TO_BIN)/liberimsimu.a: $(addsuffix simu.o, $(EXEC_SOURCE))
	ar -cq $@ $^

$(PATH_TO_BIN)/liberim.so: $(addsuffix -pic.o, $(EXEC_SOURCE))
	$(CC) -shared -o $@ $^ # -Wl,-init,erim_soInit # if erim autoinit 

$(PATH_TO_BIN)/liberimsimu.so: $(addsuffix simupic.o, $(EXEC_SOURCE))
	$(CC) -shared -o $@ $^

%simu.o: %.c
	$(CC) -c $*.c $(CFLAGS) -DSIMULATE_PKRU $(INCLUDE_PATH) -o $*simu.o

%simupic.o: %.c
	$(CC) -c $*.c -fPIC $(CFLAGS) -DSIMULATE_PKRU $(INCLUDE_PATH) -o $*simupic.o

$(PATH_TO_BIN)/liberimfinal.so:  $(PATH_TO_BIN)/liberim.so
	ln -s  $^ $@

include $(PATH_TO_SRC)/common.mk

test: $(PATH_TO_BIN)/liberim.a
	make -C testinlined/ -is
	CC=clang make -C testinlined/ -is
	make -C testoverlay/ -is
	CC=clang make -C testoverlay/ -is
	make -C testsharedobject/ -is
	CC=clang make -C testsharedobject/ -is

distclean:
	rm -f *.o

clean: distclean
	find $(PATH_TO_BIN)/ -maxdepth 1 -type f -exec rm -f {} \;
	find $(PATH_TO_BIN)/ -name *.a -type f -exec rm -f {} \;	
