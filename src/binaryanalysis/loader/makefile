PATH_TO_SRC=../..
PATH_TO_ROOT=../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=$(basename $(CPATH))

include $(PATH_TO_SRC)/flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)
INCLUDE_PATH=-I. -I$(PATH_TO_SRC)/common
LIBRARY_PATH=-L$(PATH_TO_BIN)/
DEP_LIBS= 
EXEC_SOURCE=

CFLAGS=-g -O0

all: createoutput elf_object.o

include $(PATH_TO_SRC)/common.mk

clean:
	rm *.o
