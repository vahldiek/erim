/*
 * test_application_integrity.c
 *
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <common.h>

#include <test_libtest.h>

#define secretvar (0x55500000000)

int main(int argc, char **argv) {
  unsigned long var = 0;
  
  // monitor stuff should work
  set_var(&var);

  // monitor stuff should work
  fprintf(stderr, "read var %ld\n", read_var(&var, 0));

  // try to read, shouldn't work (not trusted)
  void * sym = dlopen("libtest.so", RTLD_NOW);
  void * secretsym = dlopen("libtesterimizedint.so", RTLD_NOW);
  if(sym && secretsym){ // test if you can access it from the regular library (otherwise you're done)
    unsigned long (*unprotect_read)(unsigned long * s, unsigned long a) = dlsym(sym, "read_var");
    if(unprotect_read) {
      fprintf(stderr, "should work:\n");
      fprintf(stderr, "var: %lx\n", unprotect_read((unsigned long *) secretvar, 0));
    }

    void (*unprotect_set)(unsigned long * s) = dlsym(sym, "set_var");
    if(unprotect_set) {
      fprintf(stderr, "should segfault:\n");
      unprotect_set((unsigned long *) secretvar);
    }
  }

  return 1;
  
}
