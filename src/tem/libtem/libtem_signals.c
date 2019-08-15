#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <erim.h>
#include <libtem.h>
#include <libtem_memmap.h>

extern void libtem_trampoline_handle_signal(int signal, siginfo_t *si, void *ptr);

void libtem_handle_signal(int signal, siginfo_t *si, void *ptr) {

  write(2, "invoked signal handler\n", 24);
  
  if(signal == SIGSEGV) {
    // oh shoot we have a segfault

    erim_switch_to_trusted;

    //    write(2, "sigsegv at %p\n", si->si_addr);

    unsigned long long pagesize = sysconf(_SC_PAGESIZE);
    ltem_memmap_entry_t mentry;

    write(2, "SIGSEGV\n", 9);
    
    // is it related to memory that we took away the execute bit?
    if(si && si->si_addr && libtem_memmap_find(si->si_addr, &mentry)) {
      void * alignedAddr = (void *) ((unsigned long long)(si->si_addr)
				     & ~(pagesize-1));
      // it is! - lets scan it
      char * start = alignedAddr; // page(addr) - 2 byte (if prev page was mapped as well)
      unsigned long long length = pagesize; // length = page + 2 byte if next page is mapped)
      unsigned long long * whitelist = NULL;
      unsigned int wlEntries = 0;
      write(2, "memScan\n", 9);
      /*      if(erim_memScanRegion(ERIM_PKRU_VALUE_UNTRUSTED, start,
			    length, whitelist, wlEntries, NULL)) {
	write(2, "WRPKRU - EXIT\n", 15);
	// as a result we let the program crash
	exit(EXIT_FAILURE);
      } 
      */      

      // mprotect the page with execute permission
      //      write(2, "mprotect %p size %lld prot %d\n", alignedAddr, pagesize, mentry.prot);
      write(2, "mprotect\n", 10);
      if(mprotect(alignedAddr, pagesize, PROT_READ|PROT_EXEC) != 0) {
        //write(2, "remprotecting with execute bit didn't work\n");
      }

      // continue application - kernel will reset the PKRU register to its exeuction
      // xsafe state
      return;
    }
  }

  write(2, "finished handler\n", 18);

  return;
}

int libtem_reg_signals(int erimFlags) {
  LTEM_DBM("reg signals");

  if(ERIM_TRUSTED_DOMAIN_IDENT == ERIM_ISOLATED_DOMAIN) {
    char *sigstack = NULL;
    LTEM_DBM("allocate isolated stack");
    sigstack = erim_mmap_isolated(NULL, SIGSTKSZ, PROT_READ | PROT_WRITE
				  | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    if(sigstack == MAP_FAILED) {
      LTEM_ERR("could not allocate signal stack");
      return 1;
    }
    
    stack_t ss = {
      .ss_size = SIGSTKSZ,
      .ss_sp = sigstack
    };
    
    if(sigaltstack(&ss, NULL) == -1) {
      LTEM_ERR("Could not install signal stack");
      return 1;
    }

    LTEM_DBM("installed isolated stack");
  }

  struct sigaction sa;
  sa.sa_sigaction = (ERIM_TRUSTED_DOMAIN_IDENT != ERIM_ISOLATED_DOMAIN) ?
    (void(*)(int, siginfo_t*, void*))&libtem_handle_signal :
    (void(*)(int, siginfo_t*, void*))&libtem_trampoline_handle_signal;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigfillset(&sa.sa_mask);
  
  if(sigaction(SIGSEGV, &sa, NULL) == -1) {
    LTEM_ERR("Signal handler couldn't be installed\n");
    return 1;
  }

  LTEM_DBM("signals registered %p from %p %p",
	   sa.sa_sigaction, libtem_handle_signal,
	   libtem_trampoline_handle_signal);
  
  return 0;
}


void printHello() {
  //  unsigned long long pkru = __rdpkru();
  //write(2, pkru, 8);
  write(2, "hello\n", 7);
  //printf("stack %p", ptr);
}
