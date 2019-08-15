obj-m+=tem_lsm.o

all: clean tem_lsm

#CFLAGS_lsm_mod.o := # -DERIM_DBG

tem_lsm:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
