/* 
 * libtem.h
 */

#ifndef __LIBTEM_H_
#define __LIBTEM_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/types.h>

#define gettid() syscall(SYS_gettid)

typedef struct ltem_public_s {
  void *(*mmap)(void *addr, size_t length, int prot, int flags,
		int fd, off_t offset);
  int (*mprotect)(void *addr, size_t len, int prot);
  int (*mprotect_pkey)(void * addr, size_t len, int prot, int pkey);
} ltem_public_t;

ltem_public_t ltem_pub;
  
typedef void (*ltem_markfct)(pid_t p);

typedef struct ltem_secrets_s {

  ltem_markfct trusted;
  ltem_markfct untrusted;

  void * ltem_memmap;
  
} ltem_secrets_t;

#define LTEM_SEC_LOC (0x88880000)
#define LTEM_SEC ((ltem_secrets_t *) LTEM_SEC_LOC)

int libtem_init(ltem_markfct trusted, ltem_markfct untrusted, int erimFlags);

#define LTEM_DBG

/*
 * Debug prints
 */
#ifdef LTEM_DBG
  #define LTEM_DBM(...)				\
    do {					\
      fprintf(stderr, __VA_ARGS__);		\
      fprintf(stderr, "\n");			\
      fflush(stderr);				\
    } while(0)
#else // disable debug
   #define LTEM_DBM(...)
#endif

/*
 * Error prints
 */
#define LTEM_ERR(...)				\
    do {					\
      fprintf(stderr, __VA_ARGS__);		\
      fprintf(stderr, "\n");			\
    } while(0)

#ifdef __cplusplus
}
#endif
  
#endif // __LIBTEM_H_
