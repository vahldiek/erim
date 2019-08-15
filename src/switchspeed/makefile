PATH_TO_SRC=../
PATH_TO_ROOT=../../
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=$(basename $(CPATH))

include $(PATH_TO_SRC)/flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)

CFLAGS+=-O2 -g -I. -I../erim -I../common -I../dune -fno-inline -fno-reorder-blocks 

TESTCASES=test_inlined test_direct test_indirect test_wrpkruinlined test_wrpkrudirect test_wrpkruindirect test_vmfunc

LDLIBS=$(PATH_TO_BIN)/../erim/liberim.a $(PATH_TO_BIN)/../common/libswscommon.a ../dune/libdune/libdune.a

all: createoutput allbinaries run

allbinaries: $(addprefix $(PATH_TO_BIN)/, $(TESTCASES)) 

$(PATH_TO_BIN)/test_inlined: test_inlined
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_direct: test_direct
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_indirect: test_indirect
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_wrpkruinlined: test_wrpkruinlined
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_wrpkrudirect: test_wrpkrudirect
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_wrpkruindirect: test_wrpkruindirect
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/test_vmfunc: test_vmfunc
	mv $< $(PATH_TO_BIN)

run: $(addprefix $(PATH_TO_BIN)/, $(TESTCASES))
	$(PATH_TO_BIN)/test_inlined 100000 >speed.txt
	$(PATH_TO_BIN)/test_direct 100000 >>speed.txt	
	$(PATH_TO_BIN)/test_indirect 100000 >>speed.txt
	$(PATH_TO_BIN)/test_vmfunc 100000 >>speed.txt
#	$(PATH_TO_BIN)/test_wrpkruinlined 100000 >>speed.txt	
#	$(PATH_TO_BIN)/test_wrpkrudirect 100000 >>speed.txt
#	$(PATH_TO_BIN)/test_wrpkruindirect 100000 >>speed.txt

include $(PATH_TO_SRC)/common.mk

clean:
	rm -f *.o
	rm -f $(PATH_TO_BIN)/*
