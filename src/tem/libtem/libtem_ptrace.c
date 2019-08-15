#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <common.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stddef.h>

#include <libtem_ptrace.h>
#include <libtem.h>
#include <erim.h> // only for syscall numbers & ERIM_ISOLATED_DOMAIN

#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define syscall_nr (offsetof(struct seccomp_data, nr))

int start_seccomp() {
  
  // allocate secret for communication
  void * mapret = mmap((void*)LTEM_PT_INF, LTEM_MAX_PID, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(mapret == MAP_FAILED || mapret != (void *)LTEM_PT_INF) {
    LTEM_ERR("allocation of secret failed");
    return 1;
  }
  if(pkey_mprotect((void*)LTEM_PT_INF, LTEM_MAX_PID, PROT_READ|PROT_WRITE, ERIM_TRUSTED_DOMAIN)) {
    return 1;
  }
  erim_switch_to_trusted;
  memset((void*)LTEM_PT_INF, 0, LTEM_MAX_PID);
  erim_switch_to_untrusted;
    
  /* If open syscall, trace */
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_mmap, 3, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_mprotect, 2, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_mprotect_key, 1, 0), // SYS_mprotect_key instead of __NR_mprotect, as not defined in header sources
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_rt_sigaction, 3, 6), // jmp over mmap like calls or end
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(2)), // map like calls
    BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, PROT_EXEC, 0, 4),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),	    
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(0)), // signal calls
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SIGSEGV, 0, 1),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
    .filter = filter,
    .len = (unsigned short) (sizeof(filter)/sizeof(filter[0])),
  };
  
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    perror("seccomp");
    LTEM_ERR("Error when setting seccomp filter\n");
    return 1;
  }

  return 0;
}

void markTrusted(pid_t p) {
  LTEM_SET_BIT(p);
}

void markUntrusted(pid_t p) {
  LTEM_CLEAR_BIT(p);
}

__attribute__((constructor)) void libtem_ptrace() {
  LTEM_DBM("ltem ptrace start init");
  
  if(libtem_init(markTrusted, markUntrusted, ERIM_FLAG_ISOLATE_TRUSTED) || start_seccomp()) {
    LTEM_ERR("initialization failed - exit");
    exit(EXIT_FAILURE);
  }

  erim_switch_to_untrusted;
}
