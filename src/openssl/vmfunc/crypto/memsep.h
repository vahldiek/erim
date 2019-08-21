/*
 * memsep.h
 *
 *  Created on: Oct 7, 2017
 *      Author: vahldiek
 */

#ifndef MEMSEP_H_
#define MEMSEP_H_

#include <stdio.h>
#include <stdlib.h> 


/*
 * Interface to memsep
 */

int erim_memsep_init();
void * memsep_malloc(size_t size);
void * memsep_zalloc(size_t size);
void * memsep_realloc(void * ptr, size_t size);
void memsep_free(void * ptr);



#define VMFUNC_NORMAL_DOMAIN (0)
#define VMFUNC_SECURE_DOMAIN (1)

#define vmfunc_switch(mapping)                                          \
{ \	
	__asm__ __volatile__ (                                                \
  "mov $0, %%eax \n\t" /* vmfunc number (0=eptp switch) */ \
  "mov %0, %%ecx \n\t" /* eptp index */           \
                          "vmfunc \n\t"                                   \
  :                                               \
  : "irm"(mapping)                                \
  : "%rax", "%rcx", "memory"); \
}

#define ERIM_BRIDGE_NAME(f)                     \
    erim_bridge_##f

/* ERIM_BRIDGE_CALL - call function f through ERIM Bridge
 */
#define ERIM_BRIDGE_CALL(f, ...)                \
  ({ /*printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);*/ \
   ERIM_BRIDGE_NAME(f)(__VA_ARGS__); \
   })

/* ERIM_BRIDGE_FCTPTR - access to fct pointer of ERIM
 * Bridge calling f
 */
#define ERIM_BRIDGE_FCTPTR(f)                   \
  ERIM_BRIDGE_NAME(f)

/* ERIM_DEFINE_BRIDGE - provides header file define
 * to be used by outside functions/referred to
 */
#define ERIM_DEFINE_BRIDGE0(ret, f)             \
  ret ERIM_BRIDGE_NAME(f)()
#define ERIM_DEFINE_BRIDGE1(ret, f, type1)   \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1)
#define ERIM_DEFINE_BRIDGE2(ret, f, type1, type2)       \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2)
#define ERIM_DEFINE_BRIDGE3(ret, f, type1, type2, type3)        \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3)
#define ERIM_DEFINE_BRIDGE4(ret, f, type1, type2, type3, type4)         \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4)
#define ERIM_DEFINE_BRIDGE5(ret, f, type1, type2, type3, type4, type5)  \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5)
#define ERIM_DEFINE_BRIDGE6(ret, f, type1, type2, type3, type4, type5, type6) \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6)
#define ERIM_DEFINE_BRIDGE7(ret, f, type1, type2, type3, type4, type5, type6, type7) \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7)
#define ERIM_DEFINE_BRIDGE8(ret, f, type1, type2, type3, type4, type5, type6, type7, type8) \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7, type8 arg8)

#define ERIM_DEFINE_BRIDGEARGSS0(ret, f)             \
  ret ERIM_BRIDGE_NAME(f)()
#define ERIM_DEFINE_BRIDGEARGS1(ret, f, type1, arg1)    \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1)
#define ERIM_DEFINE_BRIDGEARGS2(ret, f, type1, arg1, type2, arg2)       \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2)
#define ERIM_DEFINE_BRIDGEARGS3(ret, f, type1, arg1, type2, arg2, type3, arg3) \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3)
#define ERIM_DEFINE_BRIDGEARGS4(ret, f, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4)
#define ERIM_DEFINE_BRIDGEARGS5(ret, f, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5)
#define ERIM_DEFINE_BRIDGEARGS6(ret, f, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6) \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6)
#define ERIM_DEFINE_BRIDGEARGS7(ret, f, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7) \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7)
#define ERIM_DEFINE_BRIDGEARGS8(ret, f, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8) \
  ret ERIM_BRIDGE_NAME(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7, type8 arg8)

/*
 * Depending on isolation domain switches need to go to trusted or untrusted
 */
#define ERIM_SWITCH_IN  vmfunc_switch(VMFUNC_SECURE_DOMAIN)
#define ERIM_SWITCH_OUT vmfunc_switch(VMFUNC_NORMAL_DOMAIN)

/* ERIM_BUILD_BRIDGE - defines function which
 * switches to refmon, calls function and switches
 * back to refmon
 */
#define ERIM_BUILD_FULLBRIDGE0(ret, f, fint)                   \
  ret f() {                                                    \
  ret ret_val;                                               \
  ERIM_SWITCH_IN;                                            \
  ret_val = fint();                                          \
  ERIM_SWITCH_OUT;                                           \
  return ret_val;                                            \
  }
#define ERIM_BUILD_FULLBRIDGE1(ret, f, fint, type1)                 \
  ret f(type1 arg1) {                                               \
  ret ret_val;                                                    \
  ERIM_SWITCH_IN;                                                 \
  ret_val = fint(arg1);                                           \
  ERIM_SWITCH_OUT;                                                \
  return ret_val;                                                 \
  }

#define ERIM_BUILD_FULLBRIDGE2(ret, f, fint, type1, type2)              \
  ret f(type1 arg1, type2 arg2) {                                       \
  ret ret_val;                                                        \
  ERIM_SWITCH_IN;                                                     \
  ret_val = fint(arg1, arg2);                                         \
  ERIM_SWITCH_OUT;                                                    \
  return ret_val;                                                     \
  }
#define ERIM_BUILD_FULLBRIDGE3(ret, f, fint, type1, type2, type3)       \
  ret f(type1 arg1, type2 arg2, type3 arg3) {                           \
  ret ret_val;                                                        \
  ERIM_SWITCH_IN;                                                     \
  ret_val = fint(arg1, arg2, arg3);                                   \
  ERIM_SWITCH_OUT;                                                    \
  return ret_val;                                                     \
  }
#define ERIM_BUILD_FULLBRIDGE4(ret, f, fint, type1, type2, type3, type4) \
  ret f(type1 arg1, type2 arg2, type3 arg3, type4 arg4) {               \
  ret ret_val;                                                        \
  ERIM_SWITCH_IN;                                                     \
  ret_val = fint(arg1, arg2, arg3, arg4);                             \
  ERIM_SWITCH_OUT;                                                    \
  return ret_val;                                                     \
  }
#define ERIM_BUILD_FULLBRIDGE5(ret, f, fint, type1, type2, type3, type4, type5) \
  ret f(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) {   \
  ret ret_val;                                                        \
  ERIM_SWITCH_IN;                                                     \
  ret_val = fint(arg1, arg2, arg3, arg4, arg5);                       \
  ERIM_SWITCH_OUT;                                                    \
  return ret_val;                                                     \
  }
#define ERIM_BUILD_FULLBRIDGE6(ret, f, fint, type1, type2, type3, type4, type5, type6) \
  ret f(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6) { \
    ret ret_val;                                                        \
    ERIM_SWITCH_IN;                                                     \
    ret_val = fint(arg1, arg2, arg3, arg4, arg5, arg6);                 \
    ERIM_SWITCH_OUT;                                                    \
    return ret_val;                                                     \
   }
#define ERIM_BUILD_FULLBRIDGE7(ret, f, fint, type1, type2, type3, type4, type5, type6, type7) \
  ret f(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7) { \
  ret ret_val;                                                        \
  ERIM_SWITCH_IN;                                                     \
  ret_val = fint(arg1, arg2, arg3, arg4, arg5, arg6, arg7);           \
  ERIM_SWITCH_OUT;                                                    \
  return ret_val;                                                     \
  }
#define ERIM_BUILD_FULLBRIDGE8(ret, f, fint, type1, type2, type3, type4, type5, type6, type7, type8) \
  ret f(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7, type8 arg8) { \
  ret ret_val;                                                        \
  ERIM_SWITCH_IN;                                                     \
  ret_val = fint(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);     \
  ERIM_SWITCH_OUT;                                                    \
  return ret_val;                                                     \
  }

#define ERIM_BUILD_BRIDGE0(ret, f) ERIM_BUILD_FULLBRIDGE0(ret, ERIM_BRIDGE_NAME(f), f)
#define ERIM_BUILD_BRIDGE1(ret, f, ...) ERIM_BUILD_FULLBRIDGE1(ret, ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE2(ret, f, ...) ERIM_BUILD_FULLBRIDGE2(ret, ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE3(ret, f, ...) ERIM_BUILD_FULLBRIDGE3(ret, ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE4(ret, f, ...) ERIM_BUILD_FULLBRIDGE4(ret, ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE5(ret, f, ...) ERIM_BUILD_FULLBRIDGE5(ret, ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE6(ret, f, ...) ERIM_BUILD_FULLBRIDGE6(ret, ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE7(ret, f, ...) ERIM_BUILD_FULLBRIDGE7(ret, ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE8(ret, f, ...) ERIM_BUILD_FULLBRIDGE8(ret, ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)

#define ERIM_BUILD_FULLBRIDGE_VOID0(f, fint)                   \
  void f() {                                                   \
  ERIM_SWITCH_IN;                                            \
  fint();                                                    \
  ERIM_SWITCH_OUT;                                           \
  }
#define ERIM_BUILD_FULLBRIDGE_VOID1(f, fint, type1)                 \
  void f(type1 arg1) {                                              \
  ERIM_SWITCH_IN;                                                 \
  fint(arg1);                                                     \
  ERIM_SWITCH_OUT;                                                \
  }
#define ERIM_BUILD_FULLBRIDGE_VOID2(f, fint, type1, type2)              \
  void f(type1 arg1, type2 arg2) {                                      \
  ERIM_SWITCH_IN;                                                     \
  fint(arg1, arg2);                                                   \
  ERIM_SWITCH_OUT;                                                    \
  }
#define ERIM_BUILD_FULLBRIDGE_VOID3(f, fint, type1, type2, type3)       \
  void f(type1 arg1, type2 arg2, type3 arg3) {                          \
  ERIM_SWITCH_IN;                                                     \
  fint(arg1, arg2, arg3);                                             \
  ERIM_SWITCH_OUT;                                                    \
  }
#define ERIM_BUILD_FULLBRIDGE_VOID4(f, fint, type1, type2, type3, type4) \
  void f(type1 arg1, type2 arg2, type3 arg3, type4 arg4) {              \
  ERIM_SWITCH_IN;                                                     \
  fint(arg1, arg2, arg3, arg4);                                       \
  ERIM_SWITCH_OUT;                                                    \
  }
#define ERIM_BUILD_FULLBRIDGE_VOID5(f, fint, type1, type2, type3, type4, type5) \
  void f(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) {  \
  ERIM_SWITCH_IN;                                                     \
  fint(arg1, arg2, arg3, arg4, arg5);                                 \
  ERIM_SWITCH_OUT;                                                    \
  }
#define ERIM_BUILD_FULLBRIDGE_VOID6(f, fint, type1, type2, type3, type4, type5, type6) \
  void f(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6) { \
  ERIM_SWITCH_IN;                                                     \
  fint(arg1, arg2, arg3, arg4, arg5, arg6);                           \
  ERIM_SWITCH_OUT;                                                    \
  }
#define ERIM_BUILD_FULLBRIDGE_VOID7(f, fint, type1, type2, type3, type4, type5, type6, type7) \
  void f(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7) { \
  ERIM_SWITCH_IN;                                                     \
  fint(arg1, arg2, arg3, arg4, arg5, arg6, arg7);                     \
  ERIM_SWITCH_OUT;                                                    \
  }
#define ERIM_BUILD_FULLBRIDGE_VOID8(f, fint, type1, type2, type3, type4, type5, type6, type7, type8) \
  void f(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7, type8 arg8) { \
  ERIM_SWITCH_IN;                                                     \
  fint(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);               \
  ERIM_SWITCH_OUT;                                                    \
  }

#define ERIM_BUILD_BRIDGE_VOID0(f) ERIM_BUILD_FULLBRIDGE_VOID0(ERIM_BRIDGE_NAME(f), f)
#define ERIM_BUILD_BRIDGE_VOID1(f, ...) ERIM_BUILD_FULLBRIDGE_VOID1(ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE_VOID2(f, ...) ERIM_BUILD_FULLBRIDGE_VOID2(ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE_VOID3(f, ...) ERIM_BUILD_FULLBRIDGE_VOID3(ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE_VOID4(f, ...) ERIM_BUILD_FULLBRIDGE_VOID4(ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE_VOID5(f, ...) ERIM_BUILD_FULLBRIDGE_VOID5(ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE_VOID6(f, ...) ERIM_BUILD_FULLBRIDGE_VOID6(ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE_VOID7(f, ...) ERIM_BUILD_FULLBRIDGE_VOID7(ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)
#define ERIM_BUILD_BRIDGE_VOID8(f, ...) ERIM_BUILD_FULLBRIDGE_VOID8(ERIM_BRIDGE_NAME(f), f, __VA_ARGS__)


#endif /* MEMSEP_H_ */
