PATH_TO_SRC=../..
PATH_TO_ROOT=../../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=$(basename $(CPATH))

include flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)
DYNINST_ROOT=../dyninst-9.2.0
INCLUDE_PATH=-I. -I/usr/local/include/ -I../ -I$(PATH_TO_SRC)/common -I../loader -I$(DYNINST_ROOT) -I$(DYNINST_ROOT)/dyninstAPI/h/ -I$(DYNINST_ROOT)/parseAPI/h -I$(DYNINST_ROOT)/instructionAPI/h -I$(DYNINST_ROOT)/symtabAPI/h/ -I$(DYNINST_ROOT)/common/h -I$(DYNINST_ROOT)/proccontrol/h -I$(DYNINST_ROOT)/dataflowAPI/h -I$(DYNINST_ROOT)/include -I$(DYNINST_ROOT)/patchAPI/h -I$(DYNINST_ROOT)/dyninst -I$(DYNINST_ROOT)/dyninstAPI/src -I$(DYNINST_ROOT)/patchAPI/src -I$(DYNINST_ROOT)/patchAPI/src/dyninst -I$(DYNINST_ROOT)/dyninstAPI/src/Relocation -I$(DYNINST_ROOT)/dyninstAPI/src -I$(DYNINST_ROOT)/libdwarf/include -I$(DYNINST_ROOT)/dynC_API/h -I../
LIBRARY_PATH=-L/usr/local/lib/
DEP_LIBS=
EXEC_SOURCE=

CFLAGS+=$(INCLUDE_PATH) -Dos_linux -Darch_x86_64 -Darch_64bit -Dx86_64_unknown_linux2_4  -Dcap_ptrace -Dcap_stripped_binaries -Dcap_async_events -Dcap_threads -Dcap_dynamic_heap -Dcap_relocation -Dcap_dwarf -Dcap_32_64 -Dcap_liveness -Dcap_fixpoint_gen -Dcap_noaddr_gen -Dcap_mutatee_traps -Dcap_binary_rewriter -Dcap_registers -Dcap_instruction_api -Dcap_serialization -Dcap_instruction_replacement -Dcap_tramp_liveness -Dbug_syscall_changepc_rewind -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -g -O0
CXXFLAGS+=-Dos_linux -Darch_x86_64 -Darch_64bit -Dx86_64_unknown_linux2_4  -Dcap_ptrace -Dcap_stripped_binaries -Dcap_async_events -Dcap_threads -Dcap_dynamic_heap -Dcap_relocation -Dcap_dwarf -Dcap_32_64 -Dcap_liveness -Dcap_fixpoint_gen -Dcap_noaddr_gen -Dcap_mutatee_traps -Dcap_binary_rewriter -Dcap_registers -Dcap_instruction_api -Dcap_serialization -Dcap_instruction_replacement -Dcap_tramp_liveness -Dbug_syscall_changepc_rewind -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -g -O0

all: mod_disas_dyninst.a

mod_disas_dyninst.a: mod_disas_dyninst.o
	ar cfr mod_disas_dyninst.a mod_disas_dyninst.o

include common.mk


clean:
	rm -f *.o
	rm -f *.a
