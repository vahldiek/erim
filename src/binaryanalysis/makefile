PATH_TO_SRC=..
PATH_TO_ROOT=../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=$(basename $(CPATH))

include $(PATH_TO_SRC)/flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)
PATH_TO_DYNINST=dyninst
INCLUDE_PATH=-I. -I$(PATH_TO_SRC)/common -Iloader -I$(PATH_TO_ROOT)/includes -Imod_disas_cpp/
DEP_LIBS=

CFLAGS=-g -O0

all: createoutput dyninst-9.2.0/README $(PATH_TO_BIN)/ba_erim test

$(PATH_TO_BIN)/ba_erim: ba_erim.o mod_disas.o mod_disas_capstone.o mod_disas_cpp/mod_disas_dyninst.a loader/elf_object.o 
	g++ -o $@ -lasan -Llibs/ -ldynElf -ldynDwarf -lstackwalk -lboost_system -lboost_thread -ldyninstAPI -ldwarf -lsymtabAPI -lcommon -lpcontrol -lparseAPI -linstructionAPI -lpatchAPI -lcapstone -std=c++0x $^ 

mod_disas_cpp/mod_disas_dyninst.a: mod_disas_cpp/mod_disas_dyninst.cpp
	make -C mod_disas_cpp

loader/elf_object.o:
	make -C loader

dyninst-9.2.0/README: v9.2.0.tar.gz
	tar xvfz v9.2.0.tar.gz

v9.2.0.tar.gz:
	wget https://github.com/dyninst/dyninst/archive/v9.2.0.tar.gz

include $(PATH_TO_SRC)/common.mk

clean:
	rm -f *.o
	rm -f $(PATH_TO_BIN)/erim
	make clean -C mod_disas_cpp
	make clean -C loader

test:
	make clean -C test
	make -C test
