/*
 * test_application.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <common.h>

//#define ERIM_DBG 1
#define ERIM_INTEGRITY_ONLY
#include <erim.h>

void erim_pkru_failure() {
  fprintf(stderr, "PKRU FAILED");
  exit(144);
}

void set_var(unsigned long * var) {
  *var = 0xAAAAAAAA;
}

unsigned long read_var(unsigned long * var) {
  return *var;
}

ERIM_BUILD_BRIDGE1(unsigned long, read_var, unsigned long *);
ERIM_BUILD_BRIDGE_VOID1(set_var, unsigned long *);

unsigned long * create_secret_var() {
  // init isolation and sh mem
  if(erim_init(8192, ERIM_FLAG_ISOLATE_TRUSTED | ERIM_FLAG_INTEGRITY_ONLY)) {
    exit(EXIT_FAILURE);
  }
  // scanmem for wrpkru
  if(erim_memScan(NULL, NULL, ERIM_UNTRUSTED_PKRU)) {
    exit(EXIT_FAILURE);
  }
  // allocate secret
  unsigned long * var = (unsigned long *) erim_malloc(sizeof(unsigned long));
  if(var == NULL) {
    printf("allocation of secret failed\n");
    exit(EXIT_FAILURE);
  }
  erim_switch_to_untrusted;
  return var;
}

int main(int argc, char **argv) {
  unsigned long * var = create_secret_var();

  fprintf(stderr, "var located at %p\n", var);

  ERIM_BRIDGE_CALL(set_var,var);
  fprintf(stderr, "var: %lx\n", ERIM_BRIDGE_CALL(read_var, var));

  fprintf(stderr, "should not segfault: %x\n", __rdpkru());
  fprintf(stderr, "var: %lx\n", read_var(var));

  fprintf(stderr, "should segfault:\n");
  set_var(var);
  
  return SWS_SUCCESS;
}
