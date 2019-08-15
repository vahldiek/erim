/*
 * erim.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <erim.h>

char * ERIM_REGULAR_STACK = NULL;

/*
 * Scan for WRPKRU sequence in memory segment
 */
unsigned long long erim_scanMemForWRPKRUXRSTOR(char * mem_start, unsigned long length)
{
  uint8_t* ptr = (uint8_t*)mem_start;
  unsigned int it = 0;
  unsigned long long ret = 0;
  for(it=0; it < length; it++) {
    if(erim_isWRPKRU(&ptr[it])) {
      ret = it;break;
    }
    if(erim_isXRSTOR(&ptr[it])) {
      ret = it; break;
    }
  }
  return ret;
}

static int checkWhitelistedWRPKRU(unsigned long long offset,
				  unsigned long long whitelist) {
  if(offset == whitelist) {
      return 0; // appears on the whitelist
    } else {
      return 1; // does not appear on the whitelist
    }
}

/*
 * Check if WRPKRU starting at addr is benign
 * a) check that it follows the structure of a switch
 * b) check that it is whitelisted
* 
 * Return: 0 -> not benign
 *         1 -> benign
 */
int isBenignWRPKRU(uint32_t untrustedPKRU,
			  char* loc) {
  uint8_t * addr = uint8ptr(loc);

  addr -= 9; // length of prefix of before WRPKRU
  
  // test for swith from isolated to app
  if(addr[0] == 0x31 && //first xor opcode
     addr[1] == 0xc9 && //register ecx xored
     addr[2] == 0x31 && //second xor opcode
     addr[3] == 0xd2 && //register edx xored
     addr[4] == 0xb8 && //mov opcode
     *((uint32_t*) &addr[5]) == untrustedPKRU && // new PKRU value is application
     addr[5] == addr[13] && //first bit of pkrus in mov and cmp
     addr[6] == addr[14] && //second bit of pkrus in mov and cmp
     addr[7] == addr[15] && //third bit of pkrus in mov and cmp
     addr[8] == addr[16] && //fourth bit of pkrus in mov and cmp
     erim_isWRPKRU(&addr[9]) && //wpkru sequence
     addr[12] == 0x3d && //cmp opcode
     (
      (addr[17] == 0x75 //jmp opcode gcc (short opcode)
       && (0xff - addr[18]) == 0x12) // addr for short jmp code
      || 
      (addr[17] == 0x0f && addr[18] == 0x85 &&  // jmp opcode clang (long opcode)
       (0xffffffff - *((uint32_t*)&addr[19])) == 0x16) // addr clalc
     ))
    {     
      return 1;
      
      // might be a switch to isolation
    } else if(addr[0] == 0x31 && //first xor opcode
	      addr[1] == 0xc9 && //register ecx xored
	      addr[2] == 0x31 && //second xor opcode
	      addr[3] == 0xd2 && //register edx xored
	      addr[4] == 0xb8 && //mov opcode
	      *((uint32_t*) &addr[5]) == ERIM_TRUSTED_PKRU && // new PKRU value is application
	      //	    addr[5] == addr[13] && //first bit of pkrus in mov and cmp
	      //	    addr[6] == addr[14] && //second bit of pkrus in mov and cmp
	      //	    addr[7] == addr[15] && //third bit of pkrus in mov and cmp
	      //	    addr[8] == addr[16] && //fourth bit of pkrus in mov and cmp
	      erim_isWRPKRU(&addr[9])) { //wpkru sequence
    
    return 1;
    
  } else { // no benign WRPKRU found
    
    return 0;
  }
}

static int markReadOnly(char * addr) {
  void * page = (void *) ((unsigned long long)(addr)
				     & ~(PAGE_SIZE-1));

  return mprotect(page, PAGE_SIZE, PROT_READ);
}

int erim_memScanRegion(uint32_t untrustedPKRU, char * origstart,
		       unsigned long long origlength,
		       unsigned long long * whitelist,
		       unsigned int wlEntries,
		       char * pathname) {
  unsigned long long skip = 0;
  unsigned int wlIt = 0;
  char * start = origstart;
  unsigned long long length = origlength;
      
  // iterate over every byte and check for WRPKRU sequence
  while (length > 0) {

    // scan for wprkru
    unsigned long long found = erim_scanMemForWRPKRUXRSTOR(start, length);
    if (found) {// found a sequence at found
      ERIM_DBM("found WPPKRU at %lld", skip + found);
      if(whitelist && wlEntries > 0 && wlIt == wlEntries) { // its a WRPKRU
	// no more whitelisted entries
	ERIM_ERR("found additional WRPKRU in %s, but exhausted all entries in whitelist already", pathname);
	return 1;
      }      

      // check whitelist (if provied) for a WRPKRU (second byte is 01)
      if((whitelist && start[skip+found+1] == 0x01 && checkWhitelistedWRPKRU(skip + found, whitelist[wlIt]))
	 || (found < 9 || // cannot be benign due to prefix
	     !isBenignWRPKRU(untrustedPKRU, start + found)) ){ 
	 // TODO: Add check for benignXRSTOR
	 //|| (1)) {	    
	// faulty wrpkru found - stop - either not whitelisted or not benign
	ERIM_ERR("found non benign WRPKRU at %p offset in library %lld library name %s", start+found, skip + found, pathname);

	// try to mark it read only -> otherwise fail
#ifndef ERIM_NO_PAGEPROTECT
	if(markReadOnly(start+found))
	  return 1;
#endif
      }
      
      // increment whitelist
      if(whitelist) 
	wlIt++;
      
      length -= (found + 3);
      start += found + 3;
      skip += found + 3;
      // continue if length > 0
      
    } else { // (!found)
      length = 0; // break loop
    } 
  } // while (length > 0)

  return 0;
}

int erim_memScan(erim_procmaps * maps, erim_getWhitelist getWhitelist,
		  uint32_t untrustedPKRU) {
  erim_procmaps * tmp = NULL;
  unsigned int i = 0;

  if(!maps) {
    maps = erim_pmapsParse(-1);
  }    

  // iterate over all map entries
  for (i = 0, tmp = maps; tmp;
       i++, tmp = erim_pmapsNext(tmp)) {
    // check all executable and readable entries
    if (tmp->is_x && tmp->is_r && tmp->pathname[0] != '[') {
      char * start = tmp->addr_start;
      unsigned long long length = tmp->addr_end - tmp->addr_start;
      unsigned long long * whitelist = NULL;
      unsigned int wlEntries = 0;

      ERIM_DBM("Scanning %s", tmp->pathname);
      
      // get whitelist for this procmap entry
      if(getWhitelist)
	getWhitelist(maps, &whitelist, &wlEntries);

      if(erim_memScanRegion(untrustedPKRU, start, length, whitelist, wlEntries, tmp->pathname))
	return 1;
      
    } // if(X & R & ! '['
  } // hasNextProcMaps

  return 0;
} 

/* checks for seq in executable memory
 * allocate domain 1 (erim currently only works on domain 1)
 * init PKRU to app only memory
 * use only once at application start
 * exits on failure
 */
int erim_init(unsigned long long shmemSize, int flags) {
  int monpkey = 0;

  ERIM_DBM("INIT erim with shmemSize %lld trustedDomain %d", shmemSize,
	   flags);
  
  if((monpkey = pkey_alloc(0, 0)) != 1) {
    ERIM_ERR("couldn't allocate pkey %d", 1);
    return 1;
  }

  ERIM_DBM("monpkey:%d pkru: %x", monpkey, __rdpkru());

  void * mapret = erim_mmap_domain(ERIM_TRUSTED_DOMAIN_IDENT_LOC, 4096,
				   PROT_READ|PROT_WRITE,
				   MAP_ANONYMOUS | MAP_PRIVATE,
				   -1, 0, ERIM_TRUSTED_DOMAIN_ID(flags));
  if(mapret != MAP_FAILED) {
    ERIM_TRUSTED_DOMAIN_IDENT = ERIM_TRUSTED_DOMAIN_ID(flags);
    ERIM_TRUSTED_FLAGS = flags;
    if(ERIM_FLAG_ISOLATE_TRUSTED & flags) {
      if(ERIM_FLAG_INTEGRITY_ONLY & flags)
	ERIM_PKRU_VALUE_UNTRUSTED = ERIM_PKRU_ISOTRS_UNTRUSTED_IO;
      else
	ERIM_PKRU_VALUE_UNTRUSTED = ERIM_PKRU_ISOTRS_UNTRUSTED_CI;
    } else {
      if(ERIM_FLAG_INTEGRITY_ONLY & flags)
	ERIM_PKRU_VALUE_UNTRUSTED = ERIM_PKRU_ISOUTS_UNTRUSTED_IO;
      else
	ERIM_PKRU_VALUE_UNTRUSTED = ERIM_PKRU_ISOUTS_UNTRUSTED_CI;
    }
    
    ERIM_DBM("set trusted domain to %d, flags %d, untrusted pkru %llx", ERIM_TRUSTED_DOMAIN_IDENT, ERIM_TRUSTED_FLAGS, (unsigned long long)ERIM_PKRU_VALUE_UNTRUSTED);
  } else {
    ERIM_ERR("DOMAIN IDENT MMAP FAILED");
    return 1;
  }

  // shared memory alloc
  if(shmemSize > 0)
    return erim_shmem_init(shmemSize, ERIM_TRUSTED_DOMAIN_ID(flags));

  return 0;
}

int erim_soInit() {
  erim_init(8129, ERIM_FLAG_ISOLATE_UNTRUSTED);
  erim_memScan(NULL, NULL, ERIM_PKRU_ISOTRS_UNTRUSTED_CI);
  return 0;
}

int erim_moveLibraryToIsolated(erim_procmaps * maps, char * libName) {
  
  if(!maps) {
    maps = erim_pmapsParse(-1);
  }

  // TODO: IMPLEMENT based on browser code

  return 0;
}

/* frees pkey 0
 * unmap all prev mmap memory before
 * exits on failure
 */
int erim_fini() {
  pkey_free(0);

  return erim_shmem_fini();
}
