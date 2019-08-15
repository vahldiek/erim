#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <libunwind-ptrace.h>
#include <fcntl.h>

#include "../libtem/libtem_ptrace.h"
#include "../libtem/libtem.h"

#ifdef LTEM_DBG
extern char **environ;

static const int nerrors_max = 100;

int nerrors;
int verbose;
int print_names = 1;

enum
  {
    INSTRUCTION,
    SYSCALL,
        TRIGGER
  }
  trace_mode = SYSCALL;

#define panic(args...)\
  do { fprintf (stderr, args); ++nerrors; } while (0)

static unw_addr_space_t as;
static struct UPT_info *ui;

void do_backtrace (pid_t target_pid)
{
  unw_word_t ip, sp, start_ip = 0, off;
  int n = 0, ret;
  unw_proc_info_t pi;
  unw_cursor_t c;
  char buf[512];
  size_t len;
  
  ret = unw_init_remote (&c, as, ui);
  if (ret < 0)
    panic ("unw_init_remote() failed: ret=%d\n", ret);

    do
      {
	if ((ret = unw_get_reg (&c, UNW_REG_IP, &ip)) < 0
	    || (ret = unw_get_reg (&c, UNW_REG_SP, &sp)) < 0)
	  panic ("unw_get_reg/unw_get_proc_name() failed: ret=%d\n", ret);

	if (n == 0)
	  start_ip = ip;

	buf[0] = '\0';
	if (print_names)
	  unw_get_proc_name (&c, buf, sizeof (buf), &off);

	if (verbose)
	  {
	    if (off)
	      {
		len = strlen (buf);
		if (len >= sizeof (buf) - 32)
		  len = sizeof (buf) - 32;
		sprintf (buf + len, "+0x%lx", (unsigned long) off);
	      }
	    printf ("%016lx %-32s (sp=%016lx)\n", (long) ip, buf, (long) sp);
	  }

	if ((ret = unw_get_proc_info (&c, &pi)) < 0)
	  panic ("unw_get_proc_info(ip=0x%lx) failed: ret=%d\n", (long) ip, ret);
	else if (verbose)
	  printf ("\tproc=%016lx-%016lx\n\thandler=%lx lsda=%lx",
		  (long) pi.start_ip, (long) pi.end_ip,
		  (long) pi.handler, (long) pi.lsda);

	#if UNW_TARGET_IA64
	{
	  unw_word_t bsp;

	  if ((ret = unw_get_reg (&c, UNW_IA64_BSP, &bsp)) < 0)
	    panic ("unw_get_reg() failed: ret=%d\n", ret);
	  else if (verbose)
	    printf (" bsp=%lx", bsp);
	}
	#endif
	if (verbose)
	  printf ("\n");

	ret = unw_step (&c);
	if (ret < 0)
	  {
	    unw_get_reg (&c, UNW_REG_IP, &ip);
	    panic ("FAILURE: unw_step() returned %d for ip=%lx (start ip=%lx)\n",
		   ret, (long) ip, (long) start_ip);
	  }

	if (++n > 64)
	  {
	    /* guard against bad unwind info in old libraries... */
	    panic ("too deeply nested---assuming bogus unwind (start ip=%lx)\n",
		   (long) start_ip);
	    break;
	  }
	if (nerrors > nerrors_max)
	  {
	    panic ("Too many errors (%d)!\n", nerrors);
	    break;
	  }
      }
    while (ret > 0);

    if (ret < 0)
      panic ("unwind failed with ret=%d\n", ret);
}
#endif

void process_signals(pid_t pid) {
  int status = 0;
  while(1) {
    ptrace(PTRACE_CONT, pid, 0, 0);
    pid = waitpid(pid, &status, 0);
    if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) { // seccomp event
      LTEM_DBM("event seccomp");
      struct user_regs_struct regs;
      ptrace(PTRACE_GETREGS, pid, 0, &regs);
      if(regs.rax == __NR_rt_sigaction) { // disallow sigaction

	LTEM_DBM("sigaction");
	// kill process
	kill(pid, SIGKILL);
	
      } else { // we are in an mmap/mprotect-like system call
	LTEM_DBM("mmap/mrptoect like call pid %d loc %p", pid, LTEM_LOC_BIT(pid));
	long data = ptrace(PTRACE_PEEKTEXT, pid, LTEM_LOC_BIT(pid), NULL); // peek at signal trusted buffer of this thread
	LTEM_DBM("test int bit %x data %lx", (unsigned int) LTEM_TEST_INT(pid), (unsigned long)data);
	if(!(data & LTEM_TEST_INT(pid))) { 
	  // we're in untrusted land
	  regs.rdx &= ~PROT_EXEC;
	  ptrace(PTRACE_SETREGS, pid, 0, &regs);
	  LTEM_DBM("removed exec protection");
	} else {
	  // we're in trusted land -> continue
	}
      }
    } else if (WIFSTOPPED(status)) { // handle application signals
      switch(WSTOPSIG(status)){
      case SIGSEGV:
	LTEM_DBM("received SIGSEGV");
#ifdef LTEM_DBG
	ui = _UPT_create (pid);
	do_backtrace(pid);
#endif
      default:
	LTEM_DBM("signaled %d", WSTOPSIG(status));
	ptrace(PTRACE_CONT, pid, 0, SIGSEGV);	
      }
    } else if(WIFEXITED(status) || WIFSIGNALED(status) ) {

      LTEM_DBM("APP exit");
      // tracee exit - nothing to trace
      exit(0); 
    }

    // Continue for forks/clones/etc and keep ptracing
  }
}

int main(int argc, char **argv) {
  pid_t pid;
  int status = 0;

  if(argc < 3) {
    printf("Usage: <LD_LIBRARY_PATH> <program> <arguments>\n");
    exit(1);
  }
  
#ifdef LTEM_DBG
  as = unw_create_addr_space (&_UPT_accessors, 0);
  if (!as)
    panic ("unw_create_addr_space() failed");
#endif
  
  if ((pid = fork()) == 0) {
    // tracee please continue
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
      perror("prctl(PR_SET_NO_NEW_PRIVS)");
      exit(1);
    }

    
  } else {
    // tracer please wait for child to show up
    pid = waitpid(pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE);
    process_signals(pid);
  }  
  
  char *const envs[] = {argv[1], "LD_PRELOAD=libtem-ptrace.so",NULL};
  execve(argv[2], argv+2, envs);

  return 0;
}
