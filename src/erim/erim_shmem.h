/*
 * erim_shmem.h
 */

#ifndef ERIM_SHMEM_H_
#define ERIM_SHMEM_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/mman.h>
#include <erim_api_overlay.h>
  
// mmap memory in secure region
#define erim_mmap_domain(addr, length, prot, flags, fd, offset, trustedDomain) \
  ( {									\
    void * __tmp = NULL;						\
    __tmp = ((__tmp = mmap(addr, length, prot, flags, fd, offset)) == MAP_FAILED\
	     || pkey_mprotect(__tmp, length, prot, trustedDomain) == -1) ? (void *) -1 : __tmp; \
    __tmp;								\
  } )
  
  // mmap memory in secure region
#define erim_mmap_isolated(addr, length, prot, flags, fd, offset)	\
  ( {									\
    erim_mmap_domain(addr, length, prot, flags, fd, offset, ERIM_ISOLATED_DOMAIN); \
  } )
  
#define erim_munmap(addr, length)                      \
  ( {                                                  \
    munmap(addr, length);                              \
  } )

int erim_shmem_init(unsigned long long shmemSize, int trustedDomain);
int erim_shmem_fini();
  
void * erim_malloc(size_t size);
void * erim_mallocIsolated(size_t size);
  
void * erim_zalloc(size_t size);
void * erim_zallocIsolated(size_t size);
  
void * erim_realloc(void* ptr, size_t s);
void * erim_reallocIsolated(void* ptr, size_t s);

void erim_free(void * ptr);
void erim_freeIsolated(void * ptr);
   
#ifdef __cplusplus
}
#endif

#endif /* ERIM_H_ */
