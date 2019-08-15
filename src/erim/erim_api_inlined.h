/*
 * erim_api_inlined.h
 * 
 * Provides interface for switching and initlization of ERIM to be
 * used directly in functions.
 * 
 */

#ifndef ERIM_API_INLINED_H_
#define ERIM_API_INLINED_H_

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Debug prints
 */
#ifdef ERIM_DBG
  #define ERIM_DBM(...)				\
    do {					\
      fprintf(stderr, __VA_ARGS__);		\
      fprintf(stderr, "\n");			\
    } while(0)
#else // disable debug
   #define ERIM_DBM(...)
#endif

/*
 * Error prints
 */
#define ERIM_ERR(...)				\
    do {					\
      fprintf(stderr, __VA_ARGS__);		\
      fprintf(stderr, "\n");			\
    } while(0)
  
#include <stdint.h>
#include "pkeys.h"

#define ERIM_ISOLATED_DOMAIN 1

#define ERIM_TRUSTED_DOMAIN_IDENT_LOC ((void*)(1ull<<44))
#define ERIM_TRUSTED_DOMAIN_IDENT (*(int*)ERIM_TRUSTED_DOMAIN_IDENT_LOC)
#define ERIM_TRUSTED_FLAGS (*((int*)ERIM_TRUSTED_DOMAIN_IDENT_LOC+1))
#define ERIM_PKRU_VALUE_UNTRUSTED (*((int*)ERIM_TRUSTED_DOMAIN_IDENT_LOC+2))
  
#define ERIM_PKRU_ISOTRS_UNTRUSTED_CI (0x5555555C)
#define ERIM_PKRU_ISOTRS_UNTRUSTED_IO (0x55555558)
#define ERIM_PKRU_ISOUTS_UNTRUSTED_CI (0x55555553)
#define ERIM_PKRU_ISOUTS_UNTRUSTED_IO (0x55555552)

// Get currently executing domain
//                                ISO Trusted (exec U)      ISO Untrusted (exec U)  ISO TRUSTED 
#define ERIM_EXEC_DOMAIN(pkru) ((0x0000000C & pkru) ? 0 : (0x00000003 & pkru) ? 1 : ERIM_TRUSTED_DOMAIN_IDENT )
  
#ifndef ERIM_ISOLATE_UNTRUSTED
  // trusted -> domain 1, untrusted -> domain 0
  #define ERIM_TRUSTED_DOMAIN 1
   #ifdef ERIM_INTEGRITY_ONLY
  // read(trusted = allowed, write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOTRS_UNTRUSTED_IO
   #else
      // read(trusted = write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOTRS_UNTRUSTED_CI
   #endif
#else
// trusted -> domain 0, untrusted -> domain 1
  #define ERIM_TRUSTED_DOMAIN 0
   #ifdef ERIM_INTEGRITY_ONLY
      // read(trusted = allowed, write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOUTS_UNTRUSTED_IO
   #else
      // read(trusted = write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOUTS_UNTRUSTED_CI
   #endif
#endif

// PKRU when running trusted (access to both domain 0 and 1)
#define ERIM_TRUSTED_PKRU (0x55555550)

  // accessing stack values
#define erim_get_stackptr(ptr)				\
  do {							\
    asm volatile("movq %%rsp, %0" : "+m" (ptr));	\
  } while(0)


#ifdef ERIM_SWAP_STACKS
  // stack locations
#define ERIM_ISOLATED_STACK_LOC ((void*)(11ull<<43))
#define ERIM_ISOLATED_STACK ((char *) ERIM_SIOLATED_STACK_LOC)
extern char * ERIM_REGULAR_STACK;  
#define ERIM_SWITCH_TO_ISOLATED_STACK					\
  do {									\
    erim_get_stackptr(ERIM_REGULAR_STACK);					\
    memcpy(ERIM_ISOLATED_STACK, ERIM_REGULAR_STACK, 128);		\
    asm volatile("movq %0, %%rsp" : "n" (ERIM_ISOLATED_STACK));	\
  } while(0)
  
#define ERIM_SWITCH_TO_REGULAR_STACK					\
  do {									\
    asm volatile("movq %0, %%rsp\n" : "=m" (ERIM_REGULAR_STACK));	\
  } while(0)

#if ERIM_TRUSTED_DOMAIN == 1
  #define ERIM_SWITCH_TO_TRUSTED_STACK ERIM_SWITCH_TO_ISOLATED_STACK
  #define ERIM_SWITCH_TO_UNTRUSTED_STACK ERIM_SWITCH_TO_REGULAR_STACK
#else
  #define ERIM_SWITCH_TO_TRUSTED_STACK ERIM_SWITCH_TO_REGULAR_STACK
  #define ERIM_SWITCH_TO_UNTRUSTED_STACK ERIM_SWITCH_TO_ISOLATED_STACK
#endif
  
#else // ifdef ERIM_SWAP_STACKS
  #define ERIM_SWITCH_TO_TRUSTED_STACK 
  #define ERIM_SWITCH_TO_UNTRUSTED_STACK 
#endif
  
  
// Switching between isolated and application
#define erim_switch_to_trusted						\
  do {                                                                  \
    __wrpkru(ERIM_TRUSTED_PKRU);					\
    ERIM_SWITCH_TO_TRUSTED_STACK;					\
    ERIM_DBM("pkru: %x", __rdpkru());					\
    ERIM_INCR_CNT(1);							\
  } while(0)
  
#define erim_switch_to_untrusted					\
  do {                                                                  \
    ERIM_SWITCH_TO_UNTRUSTED_STACK;					\
    __wrpkrucheck(ERIM_UNTRUSTED_PKRU);					\
    ERIM_DBM("pkru: %x", __rdpkru());					\
    ERIM_INCR_CNT(1);							\
  } while(0)    
  
  // switch to untrustd based on trusted flags
#define erim_switch_to_untrusted_flags					\
  do {									\
    if(ERIM_TRUSTED_DOMAIN_IDENT == 1){					\
      ERIM_SWITCH_TO_REGULAR_STACK;					\
    } else {								\
      ERIM_SWITCH_TO_ISOLATED_STACK;					\
    }									\
    __wrpkrumem(ERIM_PKRU_VALUE_UNTRUSTED);				\
    ERIM_DBM("pkru: %s", __rdpkru());					\
    ERIM_INCR_CNT(1);							\
  } while(0)

  // switch to untrustd based on trusted flags
#define erim_switch_to_trusted_flags					\
  do {									\
    __wrpkru(ERIM_TRUSTED_PKRU);					\
    if(ERIM_TRUSTED_DOMAIN_IDENT == 1) {				\
      ERIM_SWITCH_TO_ISOLATED_STACK;					\
    } else {								\
      ERIM_SWITCH_TO_REGULAR_STACK;					\
    }									\
    ERIM_DBM("pkru: %s", __rdpkru());					\
    ERIM_INCR_CNT(1);							\
  } while(0)
  
#define uint8ptr(ptr) ((uint8_t *)ptr)
  
#define erim_isWRPKRU(ptr)				\
  ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0x01	\
   && uint8ptr(ptr)[2] == 0xef)?			\
  1 : 0)

#define erim_isXRSTOR(ptr) \
   ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0xae \
    && (uint8ptr(ptr)[2] & 0xC0) != 0xC0 \
    && (uint8ptr(ptr)[2] & 0x38) == 0x28) ? 1 : 0)
  
#ifdef __cplusplus
}
#endif
 
#endif
