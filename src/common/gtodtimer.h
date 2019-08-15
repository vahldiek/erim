/*
 * gtodtimer.h
 *
 */

#ifndef GTODTIMER_H_
#define GTODTIMER_H_

#include <stdio.h>
#include <sys/time.h>

static inline double sws_get_time() {
  struct timeval t;
  gettimeofday(&t, NULL);
  return (double)t.tv_sec * 1000.0 + (double) t.tv_usec/1000.0;
}
#define SWS_INIT_GTODTIMER(name) double sws_t_start_##name = 0.0, sws_t_end_##name = 0.0
#define SWS_START_GTODTIMER(name) sws_t_start_##name = sws_get_time()
#define SWS_END_GTODTIMER(name) sws_t_end_##name = sws_get_time()
#define SWS_START_GTODTIME(name) (sws_t_start_##name)
#define SWS_END_GTODTIME(name) (sws_t_end_##name)
#define SWS_SPEND_GTODTIME(name) (SWS_END_GTODTIME(name) - SWS_START_GTODTIME(name))


#endif /* GTODTIMER_H_ */
