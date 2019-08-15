
#ifndef STATISTICS_H_
#define STATISTICS_H_

#include <stdio.h>
#include <stdlib.h>

typedef struct stat_s
{
  char name[64]; //variable name

  double start;
  double end;
  double step;

  double sum, sqr_sum;
  unsigned long long total_count;

  double min;
  double max;

  int bucket_count;
  unsigned long long *distribution; //the distribution
} stat_t;

void
stat_add_data_point(stat_t *stats, double value);

void
stat_init(stat_t *stats, char* name, double start, double end, double step);

void stat_get_smmary (stat_t *stats, double * avg, double * stddev);

void
stat_print_summary(stat_t *stats, FILE * fd);

void
stat_print_distribution(stat_t *stats, FILE * fd);

void
stat_reset(stat_t *stats);

void
stat_destroy(stat_t *stats);

#define INIT_TIMER(name) double t_start_##name = 0.0, t_end_##name = 0.0
#define START_TIMER(name) t_start_##name = get_time()
#define END_TIMER(name) t_end_##name = get_time()
#define START_TIME(name) (t_start_##name)
#define END_TIME(name) (t_end_##name)
#define SPENT_TIME(name) (END_TIME(name) - START_TIME(name))

#define DECL_STAT_EXTERN(name)	extern stat_t *stats_##name;
#define DECL_STAT(name)	stat_t *stats_##name = NULL;
#define STAT_NAME(name)	stats_##name

#define INIT_STAT(name, desc, sta, end, st)			\
	stats_##name = malloc(sizeof(stat_t));			\
	stat_init(stats_##name, desc, sta, end, st)

#define DEST_STAT(name)					\
	if(stats_##name != NULL) {				\
		stat_destroy(stats_##name);			\
		free(stats_##name);				\
		stats_##name = NULL;	\
	}

#define RESET_STAT(name)					\
	if(stats_##name != NULL) {				\
		stat_reset(stats_##name);			\
	}

#define ADD_TIME_POINT(name)					\
	if(stats_##name != NULL) {				\
	    (stat_add_data_point(stats_##name, SPENT_TIME(name))); \
	}

#define ADD_COUNT_POINT(name, val)				\
	if(stats_##name != NULL) {				\
	    (stat_add_data_point(stats_##name, val));		\
	}

#define STAT_START_TIMER(name)	\
	INIT_TIMER(name); START_TIMER(name)

#define STAT_END_TIMER(name)	\
	END_TIMER(name); ADD_TIME_POINT(name)

#define PRINT_STAT(name, f, full)	\
	do {	\
		if (full)	\
			stat_print_distribution(stats_##name, f);	\
		else	\
			stat_print_summary(stats_##name, f);	\
	} while (0)

#endif /* STATISTICS_H_ */
