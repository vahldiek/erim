
/*
 * memsep.c
 *
 *  Created on: Oct 7, 2017
 *      Author: vahldiek
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <memsep.h>
#include <shared_malloc.h>
#include <crypto.h>
#include <libdune/dune.h>
#include <libdune/cpu-x86.h>

#define MB32  (32768)
#define MB128 (131072)
#define MB256 ((MB128)*2)
#define MB512 ((MB256)*2)
#define MB1024 ((MB512)*2)
#define MB2048 ((MB1024)*2)

#define ERIM_POOL_LOCATION NULL//((void*)0x7f6e3b333000)
#define ERIM_POOL poolloc//((struct sh_memory_pool*)ERIM_POOL_LOCATION)

struct sh_memory_pool * pool = NULL;

static size_t _pageground(size_t sz) {
    int pgz = sysconf(_SC_PAGESIZE);
  return (sz & ~(pgz - 1)) + pgz;
}

void * vmfunc_malloc(void *ptr, size_t size) {

  unsigned int sz = _pageground(size);
  void * pages = mmap(ptr, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
		      -1, 0);
  if (pages == MAP_FAILED)
    {
      perror("_vmfunc_alloc");
      return MAP_FAILED;
    }

  syscall(DUNE_VMCALL_SECRET_MAPPING_ADD, pages, sz);

  //printf("allocated secret at %p to %p\n", pages, ((char*)pages) + size);

  return pages;
}

void * memsep_malloc(size_t size) {
	return sh_malloc(size, pool);
}

void * memsep_zalloc(size_t size) {
  void * ptr = sh_malloc(size, pool);
  memset(ptr, 0, size);
  return ptr;
}

void * memsep_realloc(void * ptr, size_t size) {
  return sh_realloc(ptr, size, pool);
}

void memsep_free(void *ptr) {
	sh_free(ptr, pool);
}

void erim_printStats() {
	return ;
}

int erim_memsep_init() {

  int ret = dune_init_and_enter();
  if(ret) {
	 printf("failed to init dune");
	 exit(1);
  }

  vmfunc_switch(VMFUNC_SECURE_DOMAIN);

  pool = vmfunc_malloc(ERIM_POOL_LOCATION, MB1024);
  if(pool == MAP_FAILED
     || memset(pool, 0, MB1024) == NULL
     || init_sh_mempool(pool, MB1024) != pool) {
	  printf("shared malloc init failed");
	  exit(2);
  }

  vmfunc_switch(VMFUNC_NORMAL_DOMAIN);
  
  return 0;
}
