/*
 * test_application.c
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

#include <erim.h>

#include <timer.h>

void * mapUntrusted(int f) {

  
  void * addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
		     MAP_PRIVATE, f, 0);
  if(addr == MAP_FAILED) {
    printf("%d\n", errno);
    exit(1);
  }

  return addr;
}

void * mapTrusted(int f) {
  erim_switch_to_trusted;
  void * addr = mapUntrusted(f);
  erim_switch_to_untrusted;
  return addr;
}

int main(int argc, char **argv) {
  void (*fct)() = NULL;
  int fwoWRPKRU = 0;
  int fWRPKRU = 0;

  if((fwoWRPKRU = open("returns", O_RDONLY)) < 0) {
    perror("failed to open returns");
    exit(1);
  }

  if((fWRPKRU = open("returnsWRPKRU", O_RDONLY)) < 0) {
    perror("failed to open returnsWRPKRU");
    exit(1);
  }

  fprintf(stderr, "running TRUSTD MMAP without WPKRU\n");
  fct = (void (*)()) mapTrusted(fwoWRPKRU);
  fct();
  fprintf(stderr, "SUCCESS\n--------------------\n");

  fprintf(stderr, "running TRUSTD MMAP WITH WRPKRU\n");
  fct = (void (*)()) mapTrusted(fWRPKRU);
  fct();
  fprintf(stderr, "SUCCESS\n--------------------\n");

 
  fprintf(stderr, "running UNTUSTED MMAP, without WRPKRU\n");
  fct = (void (*)()) mapUntrusted(fwoWRPKRU)+1;
  fct();
  fprintf(stderr, "SUCCESS\n--------------------\n");
  
  fprintf(stderr, "running UNTUSTED MMAP, WITH WRPKRU (should not print SUCCESS)\n");
  fct = (void (*)()) mapUntrusted(fWRPKRU);
  fct();
  fprintf(stderr, "SUCCESS\n--------------------\n");

  close(fwoWRPKRU);
  close(fWRPKRU);
  
  return 0;
}
