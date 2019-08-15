/*
 * libtem_inputs.h
 */

#ifndef __LIBTEM_INPUTS_H_
#define __LIBTEM_INPUTS_H_

#ifdef __cplusplus
extern "C"
{
#endif

  // weakly defined functions, to be changed, if different than std. values
  // via LD_PRELOAD

  // generate a whitelist
  // standart implementation returns NULL
  // function needs to allocate memory and store pointer in *whitelist
  // caller needs to free memory when not used any more
  extern void libtem_getWhitelist(const char * name,
				  unsigned long long ** whitelist,
				  unsigned int * numEntries)
    __attribute__((weak));
  
  // contains all library paths to be moved to isolated domain
  // each library is separated by :
  extern char libtem_moveLibraryNames[4096];

  // ERIM"s shared memory size
  extern unsigned int libtem_erimShmemSize;

  // ERIM's isolate untrusted
  extern char libtem_erimTrustedDomain;

  // ERIM's integrity only
  extern char libtem_erimIntegrityOnly;
  
  
#ifdef __cplusplus
}
#endif

#endif // __LIBTEM_INPUTS_H_
