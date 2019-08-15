PATH_TO_SRC=../..
PATH_TO_ROOT=../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=$(basename $(CPATH))

include $(PATH_TO_SRC)/flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/erim/$(CURRENT_FOLDER)
INCLUDE_PATH=-I../api -I../common -I../../../snap/libs/include
LIBRARY_PATH=-L$(PATH_TO_BIN)/
DEP_LIBS=../../../snap/libs/liblwc.a
EXEC_SOURCE=eapi_createmonitor eapi_createsct eapi_print_stats eapi_processmappings

CFLAGS+=-g $(INCLUDE_PATH) -fPIC

BUILD_LIBS=$(PATH_TO_BIN)/liberimapi $(PATH_TO_BIN)/liberimapi_0 $(PATH_TO_BIN)/liberimapi_4 $(PATH_TO_BIN)/liberimapi_8 $(PATH_TO_BIN)/liberimapi_12 $(PATH_TO_BIN)/liberimapi_16 $(PATH_TO_BIN)/liberimapi_64 $(PATH_TO_BIN)/liberimapi_256 $(PATH_TO_BIN)/liberimapi_1024

CC=clang

all: createoutput  $(addsuffix .a, $(BUILD_LIBS)) $(addsuffix .so, $(BUILD_LIBS))

eapi_sctcall_%.o: eapi_sctcall.c
	$(CC) $(CFLAGS) -D WRPKRUCOST=$* -o $@ -c $^ 

$(PATH_TO_BIN)/liberimapi.a: $(addsuffix .o, $(EXEC_SOURCE)) eapi_sctcall.o $(DEP_LIBS)
	ar -cq $@ $^

$(PATH_TO_BIN)/liberimapi_%.a: $(addsuffix .o, $(EXEC_SOURCE)) eapi_sctcall_%.o $(DEP_LIBS)
	ar -cq $@ $^

$(PATH_TO_BIN)/liberimapi.so: $(addsuffix .o, $(EXEC_SOURCE)) eapi_sctcall.o $(DEP_LIBS)
	$(CC) -shared -o $@ $^

$(PATH_TO_BIN)/liberimapi_%.so: $(addsuffix .o, $(EXEC_SOURCE)) eapi_sctcall_%.o $(DEP_LIBS)
	$(CC) -shared -o $@ $^

include $(PATH_TO_SRC)/common.mk

test: $(PATH_TO_BIN)/liberimapi.a
	make -C test/

clean:
	rm -f *.o
	rm -f $(PATH_TO_BIN)/liberimapi*.a
	rm -f $(PATH_TO_BIN)/liberimapi*.so
