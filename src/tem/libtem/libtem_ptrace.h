
#ifndef __LIBTEM_PTRACE_H_
#define __LIBTEM_PTRACE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#define LTEM_PT_INF  ((unsigned int *)(0x44440000))
#define LTEM_MAX_PID 32768 // must be power of 2
#define LTEM_SET_BIT(bit) do { LTEM_PT_INF[(bit/32)] |= 1 << (bit%32); } while(0)
#define LTEM_CLEAR_BIT(bit) do { LTEM_PT_INF[(bit/32)] &= ~(1 << (bit%32)); } while(0)
#define LTEM_LOC_BIT(bit) &(LTEM_PT_INF[(bit/32)])
#define LTEM_TEST_INT(bit) (1 << (bit % 32))
#define LTEM_TEST_BIT(bit) (LTEM_PT_INF[(bit/32)] & (1 << (bit%32)))

#ifdef __cplusplus
}
#endif

#endif // __LIBTEM_PTRACE_H_
