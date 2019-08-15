#include <stdio.h>
#include <stdlib.h>
#include <timer.h>
#include "compute.h"

COMPUTE_ALLOC;

typedef int (*f)(int a);

int dummy(int a) {
  return a;
}

int compute_indirect2(int a) {\
  {COMPUTE;}
  
  return a;
}

f func = NULL;

int compute_indirect1(int a) {\
 
  return func(a);
}

int main(int argc, char ** argv) {
  int num_it = 0;

  if(argc < 2)
    exit(EXIT_FAILURE);
  
  COMPUTE_INIT;

  num_it = atoll(argv[1]);

  func = dummy;
  compute_indirect1(1);

  func = compute_indirect2;
  
  {
    int it = 0;
    SWS_INIT_TIMER(time);    
    for (it = 1; it < num_it; it*=2) {
      int it2 = 0;
      SWS_START_TIMER(time);
      for (it2 = 0; it2 < it; it2++) {
	if(compute_indirect1(it2)!= it2)
	  return 1;
      }
      SWS_END_TIMER(time);
      printf("INDIRECT %d %f\n", it2, (double) SWS_SPEND_TIME(time)/it2);
    }
  }

  func = NULL;

  return 0;
}
