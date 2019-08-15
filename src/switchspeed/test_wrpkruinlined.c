#include <stdio.h>
#include <stdlib.h>
#include <timer.h>
#include "compute.h"
#undef SYS_pkey_alloc
#undef SYS_pkey_free
#include "erim.h"

COMPUTE_ALLOC;

int main(int argc, char ** argv) {
  int num_it = 0;

  if(argc < 2)
    exit(EXIT_FAILURE);
  
  COMPUTE_INIT;

  num_it = atoll(argv[1]);
  
  {
    int it = 0;
    SWS_INIT_TIMER(time);    
    for (it = 1; it < num_it; it*=2) {
      int it2 = 0;
      SWS_START_TIMER(time);
      for (it2 = 0; it2 < it; it2++) {
        __wrpkru(0x55555550);
	{COMPUTE;}
	__wrpkru(0x55555554);
      }
      SWS_END_TIMER(time);
      printf("WRPKRU INLINED %d %f\n", it2, (double) SWS_SPEND_TIME(time)/it2);
    }
  }

  return 0;
}
