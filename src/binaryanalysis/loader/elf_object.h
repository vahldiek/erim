/*
 * elf_object.h
 *
 *  Created on: Nov 27, 2015
 *      Author: vahldiek
 */

#ifndef ELF_OBJECT_H_
#define ELF_OBJECT_H_


#ifdef __cplusplus
extern "C"
{
#endif

#include <elf.h>
#include <common.h>

typedef enum {

	EO_GNU_HASH = 0,
	EO_DYN_SYM,
	EO_DYN_STR,
	EO_GNU_VERSION,
	EO_GNU_VERSION_R,
	EO_RELA_DYN,
	EO_RELA_PLT,
	EO_INIT,
	EO_PLT,
	EO_TEXT,
	EO_FINI,
	EO_EH_FRAME_HDR,
	EO_EH_FRAME,
	EO_INIT_ARRAY,
	EO_FINI_ARRAY,
	EO_JCR,
	EO_DYNAMIC,
	EO_GOT,
	EO_GOT_PLT,
	EO_DATA,
	EO_BSS,
	EO_COMMENT,
	EO_SHSTRTAB,
	EO_SYMTAB,
	EO_STRTAB,
	EO_NUM_SECTIONS

} eoSectionIt;

/**
 * based on implementation from https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
 * for gnu hash sections
 */
typedef struct {
	Elf64_Word nbuckets;/* # hash buckets */
	Elf64_Word bitmask_idxbits;
	Elf64_Word shift;
	Elf64_Word * bitmask;
	Elf64_Word * buckets;/* Hash buckets */
	Elf64_Word * chain_zero; /* Hash value array */
} eoGnuHash;

typedef struct {

	char name[64];

	char * baseAddr; // base memory address of loaded elf object
	Elf64_Ehdr * hdr;
	Elf64_Shdr * sectionHdr;
	unsigned int numSections;
	Elf64_Phdr * programHdr;

	// String tables
	char * sectionHdrStrings;
	char * dynsymStrings;

	// sections
	Elf64_Shdr * dynamic;
	Elf64_Shdr * dynamic_symbols;
	Elf64_Shdr * relDyn;
	Elf64_Shdr * relPlt;
	Elf64_Shdr * got;
	Elf64_Shdr * gotPlt;
	Elf64_Shdr * gnuHash;
	Elf64_Shdr * symtab;
	//Elf64_Shdr * ;

	char ** loadedSegmentPtr;

	eoGnuHash gh;
} elfObject;

typedef int (*eo_iterator)(elfObject *, int it, void *, void *);
typedef int (*eo_segment_iterator)(elfObject*, int it, Elf64_Phdr *, void *);
typedef int (*eo_section_iterator)(elfObject*, int it, Elf64_Shdr *, void *);
typedef int (*eo_symbol_iterator)(elfObject*, int it, Elf64_Sym *, void *);
typedef int (*eo_rela_iterator)(elfObject*, int it, Elf64_Rela *, void *);
typedef int (*eo_dynamic_iterator)(elfObject*, int it, Elf64_Dyn *, void *);

Elf64_Addr * eo_addr_from_offset(elfObject * eo, Elf64_Off off);
int eo_load(const char * filename, elfObject * eo);
int eo_set_lazy_resolution_fct(elfObject * eo, void (*fct)());

int eo_iterate_segments(elfObject * eo, eo_segment_iterator it, void * pass);
int eo_iterate_sections(elfObject * eo, eo_section_iterator it, void * pass);
int eo_iterate_symbols(elfObject * eo, eo_symbol_iterator it, void * pass);
int eo_iterate_rela(elfObject * eo, eo_rela_iterator it, void * pass);
int eo_iterate_dynamic(elfObject * eo, eo_dynamic_iterator it, void * pass);

Elf64_Addr eo_find_sym(elfObject *eo, const char *symname);

// Error codes
#define EO_SUCCESS		SWS_SUCCESS
#define EO_ARG_ERROR	SWS_ARG_ERROR
#define EO_IO_ERROR		SWS_IO_ERROR
#define EO_MMAP_ERROR	16
#define EO_NO_PHDR      17

#ifdef __cplusplus
}
#endif

#endif /* ELF_OBJECT_H_ */
