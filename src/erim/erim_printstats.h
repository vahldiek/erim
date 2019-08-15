/*
 * erim_printstats.h
 *
 */

#ifndef ERIM_PRINTSTATS_H_
#define ERIM_PRINTSTATS_H_

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef ERIM_STATS
#define ERIM_INCR_CNT(i)
#else
#define ERIM_INCR_CNT(i) erim_cnt += i;
#endif

extern unsigned long long erim_cnt;

void erim_printStats();

#ifdef __cplusplus
}
#endif

#endif
