PATH_TO_SRC=../..
PATH_TO_ROOT=../../..
CPATH=$(shell basename `pwd`)
CURRENT_FOLDER=binaryanalysis/$(basename $(CPATH))

include $(PATH_TO_SRC)/flags.mk

PATH_TO_BIN=$(PATH_TO_ROOT)/$(OUTPUT)/$(CURRENT_FOLDER)

CFLAGS=-O0 -g

TESTCASES=split_wrpkru moverip_wrpkru xrstor inadxrstor inadxrstor2 inadxrstor3

all: createoutput allbinaries allbinanalysis allerimanalysis checkresults

allbinaries: $(addprefix $(PATH_TO_BIN)/, $(TESTCASES)) 

allbinanalysis: $(addsuffix .dis, $(TESTCASES)) $(addsuffix .hex, $(TESTCASES)) $(addsuffix .ea, $(TESTCASES)) $(addsuffix .erim, $(TESTCASES)) $(addsuffix .elf, $(TESTCASES))

allerimanalysis: $(addsuffix .erim.hex, $(TESTCASES)) $(addsuffix .erim.dis, $(TESTCASES)) $(addsuffix .erim.elf, $(TESTCASES)) $(addsuffix .erim.ea, $(TESTCASES))

checkresults: 
	./checkresults.sh split_wrpkru
	./checkresults.sh moverip_wrpkru

#%: %.c
#	$(CC) $(CFLAGS) $< -o $@

$(PATH_TO_BIN)/split_wrpkru: split_wrpkru
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/moverip_wrpkru: moverip_wrpkru
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/xrstor: xrstor
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/inadxrstor: inadxrstor
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/inadxrstor2: inadxrstor2
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/inadxrstor3: inadxrstor3
	mv $< $(PATH_TO_BIN)

$(PATH_TO_BIN)/%: %
	mv $< $(PATH_TO_BIN)

%.hex: $(PATH_TO_BIN)/%
	hexdump $< > $@

%.dis: $(PATH_TO_BIN)/%
	objdump -d $< > $@

%.elf: $(PATH_TO_BIN)/%
	readelf -a $< > $@

%.ea: $(PATH_TO_BIN)/%
	LD_LIBRARY_PATH=../libs DYNINSTAPI_RT_LIB=../libs/libdyninstAPI_RT.so $(PATH_TO_BIN)/../ba_erim $< 0F01EF 1 analysis >$@

%.erim: $(PATH_TO_BIN)/%
	LD_LIBRARY_PATH=../libs DYNINSTAPI_RT_LIB=../libs/libdyninstAPI_RT.so $(PATH_TO_BIN)/../ba_erim $< 0F01EF 1 full >/dev/null
	mv $<.erim .

%.erim.ea: $(PATH_TO_BIN)/%.erim
	LD_LIBRARY_PATH=../libs DYNINSTAPI_RT_LIB=../libs/libdyninstAPI_RT.so $(PATH_TO_BIN)/../ba_erim $< 0F01EF 1 location >$@

include $(PATH_TO_SRC)/common.mk

clean:
	rm -f *.o *.hex *.dis *.ea *.erim *.elf
	rm -f $(PATH_TO_BIN)/*
