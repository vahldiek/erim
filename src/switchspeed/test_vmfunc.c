#include <stdio.h>
#include <stdlib.h>

#include "libdune/dune.h"
#include "libdune/cpu-x86.h"

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <timer.h>
#include <compute.h>

#define VMFUNC_NORMAL_DOMAIN 0
#define VMFUNC_SECURE_DOMAIN 1

#define vmfunc_switch(mapping)						\
  __asm__ __volatile__ (						\
			"mov $0, %%eax \n\t" /* vmfunc number (0=eptp switch) */ \
			"mov %0, %%ecx \n\t" /* eptp index */		\
			"vmfunc \n\t"					\
			:						\
			: "irm"(mapping)				\
			: "%rax", "%rcx", "memory");

static size_t _pageground(size_t sz) {
    int pgz = sysconf(_SC_PAGESIZE);
    return (sz & ~(pgz - 1)) + pgz;
}

void * vmfunc_malloc(size_t size) {

  unsigned int sz = _pageground(size);
  void * pages = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	       -1, 0);
  if (pages == MAP_FAILED)
    {
        perror("_vmfunc_alloc");
        return NULL;
    }

  syscall(DUNE_VMCALL_SECRET_MAPPING_ADD, pages, sz);
  
  return pages;
}

int * _compute_h_f = NULL;

int main(int argc, char *argv[])
{
	volatile int ret;
	int num_it = 0;
             
	if(argc < 2)   exit(EXIT_FAILURE);
	
	num_it = atol(argv[1]);
             
	ret = dune_init_and_enter();
	if (ret) {
        	printf("failed to initialize dune\n");
		return ret;
       	}


	vmfunc_switch(VMFUNC_SECURE_DOMAIN);

	_compute_h_f = vmfunc_malloc(sizeof(int)*COMPUTE_IT+1);
	COMPUTE_INIT;

	vmfunc_switch(VMFUNC_NORMAL_DOMAIN);


  {
    int it = 0;
    SWS_INIT_TIMER(time);    
    for (it = 1; it < num_it; it*=2) {
      int it2 = 0;
      SWS_START_TIMER(time);
      for (it2 = 0; it2 < it; it2++) {
	vmfunc_switch(VMFUNC_SECURE_DOMAIN);

	{COMPUTE;}

	vmfunc_switch(VMFUNC_NORMAL_DOMAIN);
	
      }
      SWS_END_TIMER(time);
      printf("VMFUNC INLINED %d %f\n", it2, (double) SWS_SPEND_TIME(time)/it2);
    }
  }

	
	return 0;
}

