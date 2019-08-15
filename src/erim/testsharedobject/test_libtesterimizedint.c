#define _GNU_SOURCE
#include <dlfcn.h>
#define ERIM_INTEGRITY_ONLY
#include <erim.h>

#define secretvar (0x55500000000)
#define fcttable  (0x44400000000)

struct fcttable_s {
  void (*set_var)(unsigned long * var);
  unsigned long (*read_var)(unsigned long * var, unsigned long add);
};

__attribute__ ((constructor)) void ermized_init() {
  // init isolation and sh mem
  if(erim_init(0, ERIM_FLAG_ISOLATE_TRUSTED | ERIM_FLAG_INTEGRITY_ONLY)) {
    exit(EXIT_FAILURE);
  }
  // scanmem for wrpkru
  if(erim_memScan(NULL, NULL, ERIM_UNTRUSTED_PKRU)) {
    exit(EXIT_FAILURE);
  }
  // allocate secret
  void* mapret = erim_mmap_isolated((void*)secretvar, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(mapret == MAP_FAILED) {
    printf("allocation of secret failed\n");
    exit(EXIT_FAILURE);
  }
  
  mapret = erim_mmap_isolated((void*)fcttable, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(mapret == MAP_FAILED) {
    printf("allocation of secret failed\n");
    exit(EXIT_FAILURE);
  }

  struct fcttable_s *t = (struct fcttable_s*) fcttable;
  t->set_var = dlsym(RTLD_NEXT, "set_var");
  t->read_var = dlsym(RTLD_NEXT, "read_var");

  if(t->set_var == NULL || t->read_var == NULL) {
    fprintf(stderr, "couldn't find set/read_var\n");
    exit(EXIT_FAILURE);
  }  
  
  erim_switch_to_untrusted;
}

void set_var(unsigned long * var) {
  erim_switch_to_trusted;
  ((struct fcttable_s*)fcttable)->set_var((unsigned long *)secretvar);
  erim_switch_to_untrusted;
}

unsigned long read_var(unsigned long * var, unsigned long add) {
  unsigned long ret = 0;
  erim_switch_to_trusted;
  ret = ((struct fcttable_s*)fcttable)->read_var((unsigned long *)secretvar, 0xAAAAAAAAA);
  erim_switch_to_untrusted;
  return ret;
}
