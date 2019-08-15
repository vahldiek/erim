PATH_TO_SRC=..
PATH_TO_ROOT=../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=$(basename $(CPATH))

include $(PATH_TO_SRC)/flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)
INCLUDE_PATH=-I. -I../common
LIBRARY_PATH=-L$(PATH_TO_BIN)/
DEP_LIBS=
EXEC_SOURCE=statistics

CFLAGS+=-g $(INCLUDE_PATH) -fPIC

all: createoutput  $(PATH_TO_BIN)/libswscommon.a

$(PATH_TO_BIN)/libswscommon.a: $(addsuffix .o, $(EXEC_SOURCE))
	ar -cq $@ $^

include $(PATH_TO_SRC)/common.mk

clean:
	rm -f *.o
	rm -f $(PATH_TO_BIN)/*
