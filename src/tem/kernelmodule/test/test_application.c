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
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <erim.h>

void * mapUntrusted() {

  int f = 0;

  if((f = open("returns", O_RDONLY)) < 0) {
    perror("failed to open testret.o");
    exit(1);
  }
  
  void * addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
		     MAP_PRIVATE, f, 0);
  if(addr == MAP_FAILED) {
    printf("%d\n", errno);
    exit(1);
  }

  close(f);

  return addr;
}

void * mapTrusted() {
  erim_switch_to_trusted;
  void * addr = mapUntrusted();
  erim_switch_to_untrusted;
  return addr;
}

int main(int argc, char **argv) {
  void (*fct)() = NULL;
  
  fct = (void (*)()) mapTrusted();
  fct();
  
  fct = (void (*)()) mapUntrusted();
  fprintf(stderr, "should segfault:\n");
  fct();

  fprintf(stderr, "shouldn't run this far\n");
  
  return 0;
}
