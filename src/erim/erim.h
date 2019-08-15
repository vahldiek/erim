/*
 * erim.h
 *
 * Defines interface to isolate secrets using ERIM. Applications are
 * split into a trusted component (tc) and an untrusted application
 * (app). To transfer between the two compartments, one has to
 * explicitly call a switch. The interface offers two ways to insert
 * these switches, inlined or overlayed. Inlined provides the
 * interface to inline the switches using erim_switch_to_isolated and
 * erim_switch_to_application. Whereas overlayed, provides the
 * interface to wrap entire functions with switch code and provide a
 * defines to make functions calls including the switch code.
 *
 * Lifecycle of ERIMized Application:
 *   During compilation:
 *     - Insert where necessary switches between application and
 *       tc
 *     - Insert initliazation code somewhere before application start
 *       -> e.g. via DL_PRELOAD
 *
 * Arguments to this header file:
 * ERIM_DBG -> 0, 1 (default 0)
 *  Adds print statements to switch calls and initilization code
 *
 * ERIM_STATS -> 0, 1 (default 0)
 *  Adds code to count the number of switches in a global variable
 *  Print counter by calling print_****
 *
 * ERIM_INTEGRITY_ONLY -> defined, undefined (default undefined)
 *  If defined, assures that untrusted application may read the memory
 *  of the tc.
 *  If undefined, assures that the untrusted application may never
 *  read or write the tc.
 *  (providing confidentiality and integrity)
 *
 * ERIM_ISOLATE_UNTRUSTED -> defined, undefined (default undefined) 
 *  If defined, trusted runs in domain 0. (application runs in domain 1)
 *  If undefined, trusted runs in domain 1. (application runs in
 *  domain 0) Without changes everything runs in domain 0 including
 *  libc. When the tc needs to take control over libc, it also needs
 *  to run in domain 0. When the tc only protects a small and
 *  limited set of functions which do not require libc access
 *  (e.g. the cryptographic functions of OpenSSL), then the tc can
 *  run in domain 1 without chainging the app.
 *
 * SIMULATE_PKRU -> defined, undefined (default undefined
 *  If defined, emulates the cost of WRPKRU instruction
 *  If undefined, uses RD/WRPKRU
 */

#ifndef ERIM_H_
#define ERIM_H_

#ifdef __cplusplus
extern "C"
{
#endif

//#define ERIM_DBG
  
/*
 * ERIM stats
 */
#include <erim_printstats.h>
#include <erim_processmappings.h>
#include <erim_shmem.h>

/*
 * ERIM API (inlined or overlayed)
 */
#include "erim_api_inlined.h"
#include "erim_api_overlay.h"

/*
 * Initilization and Finalization functions of ERIM
 */
typedef void (*erim_getWhitelist) (erim_procmaps * pentry, unsigned long long ** whitelist, unsigned int * numEntries);

#define ERIM_FLAG_ISOLATE_TRUSTED    (1<<0)
#define ERIM_FLAG_ISOLATE_UNTRUSTED  (1<<1)
#define ERIM_FLAG_INTEGRITY_ONLY     (1<<2)
#define ERIM_FLAG_SWAP_STACK      (1<<3)

#define ERIM_TRUSTED_DOMAIN_ID(flag) ((flag & ERIM_FLAG_ISOLATE_TRUSTED) ? 1 : 0)
  
int erim_init(unsigned long long shmemSize, int flags);
unsigned long long erim_scanMemForWRPKRUXRSTOR(char * mem_start, unsigned long length);
int erim_memScanRegion(uint32_t untrsutedPKRU, char * start,
		       unsigned long long length, unsigned long long * whitelist,
		       unsigned int wlEntries, char * pathname);
int erim_memScan(erim_procmaps * maps, erim_getWhitelist getWhitelist,
		  uint32_t untrustedPKRU);
int erim_moveLibraryToIsolted(erim_procmaps * maps, char * libName);
int erim_fini();



#ifdef __cplusplus
}
#endif

#endif /* ERIM_H_ */
