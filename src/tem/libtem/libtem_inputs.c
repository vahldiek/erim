/*
 * libtem_inputs.c
 *
 * Holds input parameters for libtem and ERIM
 */

// generate a whitelist
// standart implementation returns NULL
// function needs to allocate memory and store pointer in *whitelist
// caller needs to free memory when not used any more
void libtem_getWhitelist(const char * name,
			 unsigned long long ** whitelist,
			 unsigned int * numEntries)
  __attribute__((weak)) {
  *whitelist = NULL;
  *numEntries = 0;
  return;
}
  
// contains all library paths to be moved to isolated domain
// each library is separated by :
char libtem_moveLibraryNames[4096];

// ERIM"s shared memory size
unsigned int libtem_erimShmemSize;

// ERIM's flags to set isolate untrusted, integrity only,
// trusted domain id, switch stacks 
char libtem_erimFlags;
