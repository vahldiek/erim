#ifndef _TIMER_H_
#define _TIMER_H_

//#define CPU_SPEED ((double)3093254)

typedef unsigned long long CYCLES;

#define getCCP(name)	do { unsigned long long rax=0,rdx=0;\
	asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx): : "%ecx" );\
	name = (rdx << 32) + rax; \
 	 } while(0)

#define getCC(name)	do { unsigned long long rax=0,rdx=0;\
		asm volatile ( "rdtsc\n" : "=a" (rax), "=d" (rdx): : "%ecx" );\
		name = (rdx << 32) + rax; \
 } while(0)

#define SWS_INIT_TIMER(name) CYCLES sws_t_start_##name = 0.0, sws_t_end_##name = 0.0
#define SWS_START_TIMER(name) getCCP(sws_t_start_##name)
#define SWS_END_TIMER(name) getCCP(sws_t_end_##name)
#define SWS_START_TIME(name) (sws_t_start_##name)
#define SWS_END_TIME(name) (sws_t_end_##name)
#define SWS_SPEND_TIME(name) (SWS_END_TIME(name) - SWS_START_TIME(name))

#endif // _TIMER_H_
