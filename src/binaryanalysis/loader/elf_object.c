/*
 * elf_object.c
 *
 *  Created on: Nov 27, 2015
 *      Author: vahldiek
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf_object.h>
#include <sys/mman.h>
#include <libgen.h>
#include <assert.h>

#define __ELF_NATIVE_CLASS	64
#define ElfW(type)      _ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)    _ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)  e##w##t

Elf64_Addr * eo_addr_from_offset(elfObject * eo, Elf64_Off off) {
  return (Elf64_Addr *) (eo->baseAddr + off);
}

int eo_prt_symbol(elfObject* eo, int it, Elf64_Sym * sym, void * not_used) {

  printf("%d: %s\n", it, &eo->dynsymStrings[sym->st_name]);

  return 0;
}

/**
 * eo_load_to_memory
 * Args:
 * 	filename - name of elf obeject to be loaded to main memory
 * 	eo - elf object to be filled by this function
 *
 * loads specified elf object to memory and sets the baseAddr in eo,
 * if the baseAddr was not previously set.
 */
static int eo_load_to_memory(FILE * elf, elfObject * eo) {
  // load only loadable sections
  Elf64_Ehdr hdrSpace;
  Elf64_Ehdr * hdr = (Elf64_Ehdr *) &hdrSpace;
  char * addr = NULL;
  SWS_IO_RET_CHK(fread(hdr, sizeof(Elf64_Ehdr), 1, elf) != 1);

  if(hdr->e_phnum == 0) {
    return EO_NO_PHDR;
  }
  
  addr = mmap(NULL, hdr->e_phentsize * hdr->e_phnum,
	      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0,
	      0);
  SWS_CHK(addr == MAP_FAILED, "mmap failed");
  SWS_IO_RET_CHK(fseek(elf, hdr->e_phoff, SEEK_SET));
  SWS_IO_RET_CHK(fread(addr, hdr->e_phentsize * hdr->e_phnum, 1, elf) != 1);
  eo->programHdr = (Elf64_Phdr*) addr;
  addr = NULL;

  mprotect(eo->programHdr, hdr->e_phentsize * hdr->e_phnum, PROT_READ);

  eo->numSections = hdr->e_shnum;
  eo->loadedSegmentPtr = malloc(sizeof(void *) * hdr->e_phnum);

  unsigned int i = 0;
  for (i = 0; i < hdr->e_phnum; ++i) {
    Elf64_Phdr * phdr = &(eo->programHdr[i]);

    // load to main memory
    if (phdr->p_type != PT_LOAD) {
      continue;
    }
    // program hdr has no size
    if (!phdr->p_filesz) {
      continue;
    }

    // calculate address of current program load
    char * calcAddr = (char *) eo_addr_from_offset(eo, phdr->p_vaddr);
    uint64_t alignmentGap = 0;
    if((uint64_t)calcAddr > 0x7fffffffffff) { // virtual address is outside of userspace memory -> its some kernel obj
       alignmentGap = (((uint64_t) calcAddr) & 0x000000000fff); // allocate at a random addr instead of the provided addr
       calcAddr = NULL;
       // create hdr
       eo->hdr = malloc(sizeof(Elf64_Ehdr));
       memcpy(eo->hdr, hdr, sizeof(Elf64_Ehdr));
    } else {
    // aling calcAddr	
	calcAddr = (char *) (((unsigned long long) calcAddr) & 0xfffffffff000);
        alignmentGap = (uint64_t) (((char *) eo_addr_from_offset(eo,
							     phdr->p_vaddr)) - calcAddr);
    }

    // allocate memory
    addr = mmap(calcAddr, phdr->p_memsz + alignmentGap,
		PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
		0, 0);

    if (addr == MAP_FAILED) {
      return EO_MMAP_ERROR;
    }

    // copy memory
    memset(addr, 0x0, phdr->p_memsz + alignmentGap);
    SWS_IO_RET_CHK(fseek(elf, phdr->p_offset, SEEK_SET));
    SWS_IO_RET_CHK(fread(addr + alignmentGap, phdr->p_filesz, 1, elf) != 1);

    eo->loadedSegmentPtr[i] = addr + alignmentGap;
    //		printf("seg %d at %p size %d\n", i, addr + alignmentGap,
    //				(int) phdr->p_filesz);

    if (!eo->baseAddr) {
      eo->baseAddr = addr;
    }

    int prot = PROT_READ;
    if (phdr->p_flags & PF_W) {
      prot |= PROT_WRITE;
    }

    if (phdr->p_flags & PF_X) {
      // Executable.
      prot |= PROT_EXEC;
    }

    mprotect((unsigned char *) addr, phdr->p_memsz, prot);
  }
  // close file (not needed any more)

  return EO_SUCCESS;
}

static void setup_hash(elfObject * eo, eoGnuHash * gh) {
  if (eo->gnuHash->sh_addr) {
    Elf32_Word *hash32 = (void *) eo_addr_from_offset(eo,
						      eo->gnuHash->sh_addr);
    gh->nbuckets = *hash32++;
    Elf32_Word symbias = *hash32++;
    Elf32_Word bitmask_nwords = *hash32++;
    /* Must be a power of two.  */
    assert((bitmask_nwords & (bitmask_nwords - 1)) == 0);
    gh->bitmask_idxbits = bitmask_nwords - 1;
    gh->shift = *hash32++;

    gh->bitmask = (Elf64_Word *) hash32;
    hash32 += 64 / 32 * bitmask_nwords;

    gh->buckets = hash32;
    hash32 += gh->nbuckets;
    gh->chain_zero = hash32 - symbias;

    return;
  }
}

static int eo_load_section(FILE * elf, elfObject * eo, int sidx,
			   ElfW(Addr) ** returnValue) {

  ElfW(Shdr) * section = &eo->sectionHdr[sidx];
  ElfW(Addr) * addr = mmap(eo_addr_from_offset(eo, section->sh_addr),
			   section->sh_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  if (!addr)
    return EO_MMAP_ERROR;

  SWS_IO_RET_CHK(fseek(elf, section->sh_offset, SEEK_SET) != 0);
  SWS_IO_RET_CHK(fread(addr, section->sh_size, 1, elf) != 1);

  *returnValue = (ElfW(Addr) *) addr;

  return EO_SUCCESS;
}

/**
 *
 */
static int eo_load_setup_eo(FILE * elf, elfObject * eo) {

  // setup pointer in eo
  if(!eo->hdr) {
      eo->hdr = (Elf64_Ehdr *) eo->baseAddr;
  }
  
  int shdr_size = eo->hdr->e_shnum * eo->hdr->e_shentsize;
  
  eo->sectionHdr = mmap(NULL, shdr_size, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  if (!eo->sectionHdr)
    return EO_MMAP_ERROR;
  
  SWS_IO_RET_CHK(fseek(elf, eo->hdr->e_shoff, SEEK_SET) != 0);
  SWS_IO_RET_CHK(fread(eo->sectionHdr, eo->hdr->e_shnum * eo->hdr->e_shentsize, 1, elf) != 1);
  
  if (eo_load_section(elf, eo, eo->hdr->e_shstrndx,
		      (ElfW(Addr) **) &eo->sectionHdrStrings) != EO_SUCCESS)
    return EO_ARG_ERROR;
  
  return EO_SUCCESS;
}

static uint_fast32_t eo_new_hash(const char *s) {
  uint_fast32_t h = 5381;
  unsigned char c = 0;
  for (c = *s; c != '\0'; c = *++s)
    h = ((h << 5) + h) + c;

  return h & 0xffffffff;
}

static int eo_iterate_internal(elfObject * eo, char * section,
			       unsigned int numEntries, unsigned int entrySize, eo_iterator it,
			       void * pass) {
  unsigned int i = 0;

  for (i = 0; i < numEntries; i++) {
    int ret = EO_SUCCESS;
    if ((ret = it(eo, i, (void *) &section[i * entrySize], pass))) {
      return ret;
    }
  }

  return EO_SUCCESS;
}

static int eo_iterate_section_elements(elfObject * eo, Elf64_Shdr * shdr,
				       eo_iterator it, void * pass) {

  Elf64_Addr * section = eo_addr_from_offset(eo, shdr->sh_addr);
  unsigned int numEntries = shdr->sh_size / shdr->sh_entsize;
  return eo_iterate_internal(eo, (char *) section, numEntries,
			     shdr->sh_entsize, (eo_iterator) it, pass);
}

/**
 * eo_load
 *
 * loading an elf object to memory. in case eo->baseAddr is set,
 * the mmap tries to allocate the memory starting from this address.
 */
int eo_load(const char * filename, elfObject * eo) {

  char fname[64];
  int fnIdx = 0;
  int ret = EO_SUCCESS;
  char * bname = NULL;

  SWS_ARG_CHK(
	      filename == NULL || eo == NULL || strnlen(filename, 255) < 1 || (((unsigned long long)eo->baseAddr) & 0xfffffffff000));

  fnIdx = strnlen(filename, 255);
  fnIdx = (fnIdx < 63) ? 0 : fnIdx - 63;
  strncpy(fname, &filename[fnIdx], 64);
  bname = basename(fname);
  strncpy(eo->name, bname, strnlen(bname, 64));

  FILE * elf = fopen(filename, "rb");
  if (!elf) {
    return EO_IO_ERROR;
  }

  if ((ret = eo_load_to_memory(elf, eo)))
    return ret;

  if ((ret = eo_load_setup_eo(elf, eo)))
    return ret;

  SWS_IO_RET_CHK(fclose(elf) != 0);

  return EO_SUCCESS;
}

int eo_iterate_segments(elfObject * eo, eo_segment_iterator it, void * pass) {
  SWS_ARG_CHK(!eo || !it);

  Elf64_Addr * section = (Elf64_Addr *) eo->programHdr;
  return eo_iterate_internal(eo, (char *) section, eo->hdr->e_phnum,
			     sizeof(Elf64_Phdr), (eo_iterator) it, pass);
}

int eo_iterate_sections(elfObject * eo, eo_section_iterator it, void * pass) {

  Elf64_Addr * section = eo_addr_from_offset(eo, eo->sectionHdr->sh_addr);
  return eo_iterate_internal(eo, (char *) section, eo->hdr->e_shnum,
			     sizeof(ElfW(Shdr)), (eo_iterator) it, pass);
}

int eo_iterate_symbols(elfObject * eo, eo_symbol_iterator it, void * pass) {
  SWS_ARG_CHK(!eo || !it);

  return eo_iterate_section_elements(eo, eo->dynamic_symbols,
				     (eo_iterator) it, pass);
}

int eo_iterate_rela_dyn(elfObject * eo, eo_rela_iterator it, void * pass) {
  SWS_ARG_CHK(!eo || !it);

  return eo_iterate_section_elements(eo, eo->relDyn, (eo_iterator) it, pass);
}

int eo_iterate_rela_plt(elfObject * eo, eo_rela_iterator it, void * pass) {
  SWS_ARG_CHK(!eo || !it);

  return eo_iterate_section_elements(eo, eo->relPlt, (eo_iterator) it, pass);
}

int eo_iterate_dynamic(elfObject * eo, eo_dynamic_iterator it, void * pass) {
  SWS_ARG_CHK(!eo || !it);

  return eo_iterate_section_elements(eo, eo->dynamic, (eo_iterator) it, pass);
}

int eo_set_lazy_resolution_fct(elfObject * eo, void (*fct)()) {

  SWS_ARG_CHK(!eo || !fct);

  // not gotplt section or section too small
  if (!eo->gotPlt || eo->gotPlt->sh_size / eo->gotPlt->sh_entsize < 2)
    return EO_ARG_ERROR;

  // get first entry
  Elf64_Addr * gotEntries = eo_addr_from_offset(eo, eo->gotPlt->sh_addr);
  // set 3rd entry
  gotEntries[2] = (Elf64_Addr) fct;

  return EO_SUCCESS;
}

int eo_memcmp(const char * ptr1, const char * ptr2, unsigned int length) {

  if (length == 0 || !ptr1 || !ptr2) {
    return 0;
  }

  int it = 0;
  int sum = 0;
  for (it = 0; it < length; it++) {
    sum += ptr1[it] - ptr2[it];
  }

  return sum;
}

int eo_strlen(const char * s) {
  if (!s)
    return 0;

  int len = 0;
  for (len = 0; s[len] != '\0'; len++)
    ;

  return len;
}

ElfW(Sym) * check_match(elfObject * eo, ElfW(Sym) * symbol,
			const char * symname) {

  if (!eo || !symbol) {
    return NULL ;
  }

  char * lookedupName = &eo->dynsymStrings[symbol->st_name];

  if (eo_memcmp(symname, lookedupName, eo_strlen(symname)) != 0)
    return NULL ;

  return symbol;
}

Elf64_Addr eo_find_sym(elfObject * eo, const char * symname) {
  if (!eo || !eo->gnuHash)
    return 0;

  const ElfW(Sym) *sym;
  const eoGnuHash * gh = &eo->gh;
  const ElfW(Addr) *bitmask = (ElfW(Addr)*) gh->bitmask;
  Elf64_Word new_hash = eo_new_hash(symname);
  Elf64_Word symidx = 0;
  ElfW(Sym) * symtab = (ElfW(Sym) *) eo_addr_from_offset(eo,
							 eo->dynamic_symbols->sh_addr);
  unsigned char found_it = 0;

  if (bitmask != NULL ) {
    ElfW(Addr) bitmask_word = bitmask[(new_hash / __ELF_NATIVE_CLASS)
				      & gh->bitmask_idxbits];

    unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
    unsigned int hashbit2 = ((new_hash >> gh->shift)
			     & (__ELF_NATIVE_CLASS - 1));

    if (__builtin_expect(
			 (bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1,
			 0)) {
      Elf32_Word bucket = gh->buckets[new_hash % gh->nbuckets];
      if (bucket != 0) {
	const Elf32_Word *hasharr = &gh->chain_zero[bucket];

	do
	  if (((*hasharr ^ new_hash) >> 1) == 0) {
	    symidx = hasharr - gh->chain_zero;
	    sym = check_match(eo, &symtab[symidx], symname);
	    if (sym != NULL ) {
	      found_it++;
	      break;
	    }
	  } while ((*hasharr++ & 1u) == 0);
      }
    }
  }

  if (sym != NULL && found_it) {
    printf("found it %p\n", eo_addr_from_offset(eo, sym->st_value));
    return (Elf64_Addr) (eo_addr_from_offset(eo, sym->st_value));
  }

  return 0;
}

//
//Elf64_Addr eo_find_sym(elfObject *eo, const char *symname) {
//	Elf64_Word c = 0;
//	Elf64_Word h1 = 0, h2 = 0;
//	Elf64_Word n = 0;
//	Elf64_Xword bitmask = 0;
//	const Elf64_Sym *sym;
//	Elf64_Word *hashval;
//
//	/*
//	 * Hash the name, generate the "second" hash
//	 * from it for the Bloom filter.
//	 */
//	h1 = eo_new_hash(symname);
//	h2 = h1 >> eo->gh.shift2;
//
//	/* Test against the Bloom filter */
//	c = sizeof(Elf64_Xword) * 8;
//	n = (h1 / c) & eo->gh.maskwords_bm;
//	bitmask = (1 << (h1 % c)) | (1 << (h2 % c));
//	if ((eo->gh.bloom[n] & bitmask) != bitmask)
//		return 0;
//
//	/* Locate the hash chain, and corresponding hash value element */
//	n = eo->gh.buckets[h1 % eo->gh.nbuckets];
//	if (n == 0) /* Empty hash chain, symbol not present */
//		return 0;
//	sym =
//			&((Elf64_Sym*) eo_addr_from_offset(eo, eo->dynamic_symbols->sh_addr))[n];
//	hashval = &eo->gh.hashval[n - eo->gh.symndx];
//
//	/*
//	 * Walk the chain until the symbol is found or
//	 * the chain is exhausted.
//	 */
//	for (h1 &= ~1; 1; sym++) {
//		h2 = *hashval++;
//
//		/*
//		 * Compare the strings to verify match. Note that
//		 * a given hash chain can contain different hash
//		 * values. We'd get the right result by comparing every
//		 * string, but comparing the hash values first lets us
//		 * screen obvious mismatches at very low cost and avoid
//		 * the relatively expensive string compare.
//		 *
//		 * We are intentionally glossing over some things here:
//		 *
//		 *    -  We could test sym->st_name for 0, which indicates
//		 *	 a NULL string, and avoid a strcmp() in that case.
//		 *
//		 *    - The real runtime linker must also take symbol
//		 * 	versioning into account. This is an orthogonal
//		 *	issue to hashing, and is left out of this
//		 *	example for simplicity.
//		 *
//		 * A real implementation might test (h1 == (h2 & ~1), and then
//		 * call a (possibly inline) function to validate the rest.
//		 */
//		if ((h1 == (h2 & ~1))
//				&& !strcmp(symname, eo->dynsymStrings + sym->st_name))
//			return (Elf64_Addr) (eo_addr_from_offset(eo, sym->st_value));
//
//		/* Done if at end of chain */
//		if (h2 & 1)
//			break;
//	}
//
//	/* This object does not have the desired symbol */
//	return 0;
//}
