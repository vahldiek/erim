#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

#include "simpletable.h"
#define ERIM_INTEGRITY_ONLY
#include "erim.h"
#include "libtem_lsm.h"
#include <stdio.h>

//-----------------------------------------------
// Globals
//-----------------------------------------------
#if defined(__gnu_linux__)
# include <asm/prctl.h>
# include <sys/prctl.h>
#elif defined(__FreeBSD__)
# include <machine/sysarch.h>
#endif

int __llvm__cpi_inited = 0;
void* __llvm__cpi_table = 0;

// =============================================
// Initialization
// =============================================

/*** Interface function ***/
__attribute__((constructor(0)))
__CPI_EXPORT
void __llvm__cpi_init() {
  if (__llvm__cpi_inited)
    return;

  __llvm__cpi_inited = 1;
  
#if (!defined(ERIM) || defined(SIMULATE_PKRU)) 
  __llvm__cpi_table = mmap((void*) CPI_TABLE_ADDR,
                      CPI_TABLE_NUM_ENTRIES*sizeof(tbl_entry),
                      PROT_READ | PROT_WRITE,
                      CPI_MMAP_FLAGS, -1, 0);
#elif defined(ERIM)
  erim_init(0, ERIM_FLAG_ISOLATE_TRUSTED | ERIM_FLAG_INTEGRITY_ONLY);
  libtem_lsmSyscall();
  fprintf(stderr, "starting memscan");
  erim_memScan(NULL, NULL, ERIM_UNTRUSTED_PKRU);
  fprintf(stderr, "finished memscan");
  __llvm__cpi_table = erim_mmap_isolated((void*) CPI_TABLE_ADDR,
                      CPI_TABLE_NUM_ENTRIES*sizeof(tbl_entry),
                      PROT_READ | PROT_WRITE,
                      CPI_MMAP_FLAGS, -1, 0);
#endif
  
  if (__llvm__cpi_table == (void*) -1) {
    perror("Cannot map __llvm__cpi_dir");
    abort();
  }

#ifndef CPI_DIRECT_ACCESS
  # if defined(__gnu_linux__)
  int res = arch_prctl(ARCH_SET_GS, (unsigned long)__llvm__cpi_table);
  if (res != 0) {
    perror("arch_prctl failed");
    abort();
  } 
  #elif defined(__FreeBSD__)
  int res = amd64_set_gsbase(__llvm__cpi_table);
  if (res != 0) {
    perror("arch_prctl failed");
    abort();
  }
  #endif
# endif

  DEBUG("[CPI] Initialization completed\n");

  // JUMP TO trusted
#if defined(ERIM)
  erim_switch_to_untrusted;
#endif

  return;
}

__attribute__((destructor(0)))
__CPI_EXPORT
void __llvm__cpi_destroy(void) {
#ifdef CPI_PROFILE_STATS
    __llvm__cpi_profile_statistic();
#endif
#ifdef ERIM_STATS
  printf("switch cnt:%lld\n", erim_cnt);
#endif
  DEBUG("[CPI] Finalizatoin completed\n");
}

// =============================================
// Debug functions
// =============================================

/*** Interface function ***/
__CPI_EXPORT
void __llvm__cpi_dump(void **ptr_address) {

  tbl_entry *entry = tbl_address(ptr_address);

  // JUMP TO trusted
#if defined(ERIM)
  erim_switch_to_trusted;
#endif

  fprintf(stderr, "Pointer  address: %p\n", ptr_address);
  if (ptr_address)
    fprintf(stderr, "Pointer  value  : %p\n", *ptr_address);

  if (!entry) {
    fprintf(stderr, "No entry for address: %p\n", ptr_address);
  } else {
    fprintf(stderr, "Metadata address: %p\n", entry);
    fprintf(stderr, "Metadata value  : %p\n", entry->ptr_value);
#ifdef CPI_BOUNDS
    fprintf(stderr, "Lower bound:    : 0x%lx\n", entry->bounds[0]);
    fprintf(stderr, "Upper bound:    : 0x%lx\n", entry->bounds[1]);
#endif

  }

  // JUMP TO trusted
#if defined(ERIM)
  erim_switch_to_untrusted;
#endif
}

// =============================================
// Deletion functions
// =============================================
static __attribute__((always_inline))
void __llvm__cpi_do_delete_range(unsigned char *src, size_t size) {
  DEBUG("[CPI] Do delete [%p, %p)\n", src, src + size);

  unsigned char *end = (unsigned char*)
      ((((size_t)src) + size + pointer_size-1) & pointer_mask);

  src = (void*) (((size_t) src) & pointer_mask);
  memset(tbl_address(src), 0, (end - src) * tbl_entry_size_mult);

}

/*** Interface function ***/
__CPI_EXPORT
void __llvm__cpi_delete_range(unsigned char *src, size_t size) {
  DEBUG("[CPI] Delete [%p, %p)%s%s\n", src, src + size,
        (((size_t)src)&(pointer_size-1)) ? " src misaligned":"",
        (size&(pointer_size-1)) ? " size misaligned":"");

  // JUMP TO truted
#if defined(ERIM)
		erim_switch_to_trusted;
#endif

#ifdef CPI_DO_DELETE
  __llvm__cpi_do_delete_range(src, size);
#endif // CPI_DO_DELETE

  // JUMP TO untrusted
#if defined(ERIM)
		erim_switch_to_untrusted;
#endif
}

// =============================================
// Data movement functions
// =============================================

/*** Interface function ***/
__CPI_EXPORT
void __llvm__cpi_copy_range(unsigned char *dst, unsigned char *src,
                            size_t size) {
  DEBUG("[CPI] memcpy [%p, %p) -> [%p, %p)%s%s%s\n",
        src, src + size, dst, dst + size,
        (((size_t)src)&(pointer_size-1)) ? " src misaligned":"",
        (((size_t)dst)&(pointer_size-1)) ? " dst misaligned":"",
        (size&(pointer_size-1)) ? " size misaligned":"");

#if defined(ERIM)
		erim_switch_to_trusted;
#endif
  
  if (CPI_EXPECTNOT((dst-src) & (pointer_size-1))) {
    // Misaligned copy; we can't support it so let's just delete dst
    __llvm__cpi_do_delete_range(dst, size);
    return;
  }

  // FIXME: in case of misaligned copy, we should clobber first and last entry
  unsigned char *src_end = (unsigned char*)
      ((((size_t)src) + size + pointer_size-1) & pointer_mask);

  src = (void*) (((size_t) src) & pointer_mask);
  memcpy(tbl_address(dst), tbl_address(src),
         (src_end - src) * tbl_entry_size_mult);

  // JUMP TO REFMON
#if defined(ERIM)
		erim_switch_to_untrusted;
#endif
}

// ---------------------------------------------

/*** Interface function ***/
__CPI_EXPORT
void __llvm__cpi_move_range(unsigned char *dst, unsigned char *src,
                            size_t size) {
  DEBUG("[CPI] memmove [%p, %p) -> [%p, %p)%s%s%s\n",
        src, src + size, dst, dst + size,
        (((size_t)src)&(pointer_size-1)) ? " src misaligned":"",
        (((size_t)dst)&(pointer_size-1)) ? " dst misaligned":"",
        (size&(pointer_size-1)) ? " size misaligned":"");

#if defined(ERIM)
  erim_switch_to_trusted;
#endif

  if (CPI_EXPECTNOT((dst-src) & (pointer_size-1))) {
    // Misaligned copy; we can't support it so let's just delete dst
    __llvm__cpi_do_delete_range(dst, size);
    return;
  }

  // FIXME: in case of misaligned copy, we should clobber first and last entry
  unsigned char *src_end = (unsigned char*)
      ((((size_t)src) + size + pointer_size-1) & pointer_mask);

  src = (void*) (((size_t) src) & pointer_mask);
  memmove(tbl_address(dst), tbl_address(src),
          (src_end - src) * tbl_entry_size_mult);

  // JUMP TO trusted
#if defined(ERIM)
  erim_switch_to_untrusted;
#endif
}

// ---------------------------------------------
