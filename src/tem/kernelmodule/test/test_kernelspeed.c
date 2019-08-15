/*
 * test_application.c
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <erim.h>

#include <timer.h>

int myvar = 0;

void mapUntrusted() {
  
  void * addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
		     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if(addr == MAP_FAILED) {
    printf("%d\n", errno);
    exit(1);
  }

  myvar = ((int*)addr)[0];
}

void mapTrusted() {
  erim_switch_to_trusted;
  mapUntrusted();
  erim_switch_to_untrusted;
}

int main(int argc, char **argv) {
  int i=0;
  SWS_INIT_TIMER(unt);
  SWS_INIT_TIMER(tus);

  if(argc > 1) {
    erim_switch_to_trusted;
    syscall(332, 0);
    erim_switch_to_untrusted;
  }
  
  for(i = 0; i < 10000; i++)
    mapUntrusted();
  
  for(i = 0; i < 10000; i++)
    mapTrusted();

  SWS_START_TIMER(unt);
  for(i = 0; i < 10000; i++)
    mapUntrusted();
  SWS_END_TIMER(unt);

  SWS_START_TIMER(tus);
  for(i = 0; i < 10000; i++)
    mapTrusted();
  SWS_END_TIMER(tus);

  printf("iterations;untrusted;trusted\n%d;%lld;%lld\n", 10000, SWS_SPEND_TIME(unt), SWS_SPEND_TIME(tus));

  return myvar;
}
