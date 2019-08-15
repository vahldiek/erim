/*
 * erim_shmem.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <erim.h>

#include <shared_malloc.h>

#define ERIM_POOL_LOCATION ((void *) (1ull<<45))
#define ERIM_POOL (struct sh_memory_pool *)(ERIM_POOL_LOCATION)

unsigned long long erim_shmemSize = 0;

int erim_shmem_init(unsigned long long shmemSize, int trustedDomain) {

  if(shmemSize == 0) {
    ERIM_DBM("Shared Memory allocation empty - DON'T USE erim_malloc!");
    return 0;
  }

  // at least allocate 2 pages (otherwise shmem library will fail)
  if (shmemSize < 8192) {
    shmemSize = 8192;
  }
  
  erim_shmemSize = shmemSize;

  ERIM_DBM("allocate shmem pool at %p size %lld", ERIM_POOL_LOCATION, shmemSize);
  void * loc = erim_mmap_domain(ERIM_POOL_LOCATION, shmemSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, trustedDomain);

  if(loc == MAP_FAILED) {
    ERIM_ERR("Could not allocate shared memory");
    return 1;
  }    

  memset(ERIM_POOL_LOCATION, 0, shmemSize);
  
  if(init_sh_mempool(ERIM_POOL_LOCATION, shmemSize) == (ERIM_POOL)) {
    ERIM_DBM("Allocated shared memory at %p of size %lld", ERIM_POOL, shmemSize);
    return 0;
  } else {
    ERIM_ERR("Failed to allocate shared memory");
    return 1;
  }  
}

int erim_shmem_fini() {
  return erim_munmap(ERIM_POOL_LOCATION, erim_shmemSize);
}
  
void * erim_mallocIsolated(size_t size) {
  ERIM_DBM("allocate isolated memory size %zd", size);
  return sh_malloc(size, ERIM_POOL);
}

void * erim_zallocIsolated(size_t size) {
  ERIM_DBM("zallocate isolated memory size %zd", size);
  void * ptr = sh_malloc(size, ERIM_POOL);
  memset(ptr, 0, size);
  return ptr;
}

void * erim_reallocIsolated(void * ptr, size_t size) {
  ERIM_DBM("reallocate isolated memory size %zd at %p", size, ptr);
  return sh_realloc(ptr, size, ERIM_POOL);
}

void * erim_malloc(size_t size) {
  if(!ERIM_EXEC_DOMAIN(__rdpkru())) {
    ERIM_DBM("allocate regular memory size %zd", size);
    return malloc(size);
  } else {
    return erim_mallocIsolated(size);
  }
}

void * erim_zalloc(size_t size) {
  void * ptr = erim_malloc(size);
  memset(ptr, 0, size);
  return ptr;
}

void * erim_realloc(void* ptr, size_t size) {
  if(!ERIM_EXEC_DOMAIN(__rdpkru())) {
    ERIM_DBM("reallocate regular memory size %zd at %p", size, ptr);
    return realloc(ptr, size);
  } else {
    return erim_reallocIsolated(ptr, size);
  }
}

void erim_freeIsolated(void * ptr) {
  ERIM_DBM("freed isolated memory at %p", ptr);
  sh_free(ptr, ERIM_POOL);
}

void erim_free(void * ptr) {
  if(!ERIM_EXEC_DOMAIN(__rdpkru())) {
    ERIM_DBM("freed regular memory at %p", ptr);
    free(ptr);
  } else {
    erim_freeIsolated(ptr);
  }
}
