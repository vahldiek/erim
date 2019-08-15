

#ifndef __LIBTEM_LSM_H_
#define __LIBTEM_LSM_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <unistd.h>
  
// Needs to run in trusted domain
#define libtem_lsmSyscall()				\
  do {							\
    syscall(332,0);					\
  } while(0)

  
#ifdef __cplusplus
}
#endif

#endif // __LIBTEM_LSM_H_
