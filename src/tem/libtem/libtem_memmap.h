/*
 * libtem_memmap.h
 */

#ifndef __LIBTEM_MEMMAP_H_
#define __LIBTEM_MEMMAP_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <erim_processmappings.h>
#include <sys/mman.h>

typedef struct ltem_memmap_entry_s {

  unsigned long long start;
  unsigned long long end;
  unsigned int prot;
  char name[256];
  
} ltem_memmap_entry_t;

int libtem_memmap_init(erim_procmaps * pmaps);

int libtem_memmap_fini();

int libtem_memmap_add(void * addr, size_t length, int prot, int flags,
		       int fd, off_t offset);

int libtem_memmap_update(void * addr, size_t len, int prot, int pkey);

int libtem_memmap_find(void * addr, ltem_memmap_entry_t * entry);

#ifdef __cplusplus
}
#endif

#endif // __LIBTEM_MEMMAP_H_
