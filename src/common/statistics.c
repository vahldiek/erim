/*
 * statistics.c
 *
 *  Created on: Mar 23, 2012
 *      Author: vahldiek/elnikety
 */

#include <statistics.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

void
stat_init (stat_t *stats, char* name, double start, double end, double step)
{
  memset (stats, 0, sizeof(stat_t));

  strncpy (stats->name, name, 64);
  stats->start = start;
  stats->end = end;
  stats->step = step;

  stats->sum = 0;
  stats->sqr_sum = 0;

  stats->total_count = 0;

  stats->min = 999999999999999;
  stats->max = 0;

  stats->bucket_count = (stats->end - stats->start) / stats->step;
  stats->distribution = malloc (sizeof(unsigned long long) * stats->bucket_count);

  memset (stats->distribution, 0, stats->bucket_count * sizeof(unsigned long long));
}

void
stat_add_data_point (stat_t *stats, double value)
{
  if (value > stats->max)
    stats->max = value;
  if (value < stats->min)
    stats->min = value;

  int index = (value - stats->start) / stats->step;

  if (value >= stats->end)
    {

      //append to the last bucket
      index = ((stats->end - stats->start) / stats->step) - 1;
    }
  else if (value < stats->start)
    {

      //append to the first bucket
      index = 0;
    }

  //assert that index is in bounds
  if (index < 0)
  {
    index = 0;
  }
  else if (index >= stats->bucket_count)
  {
    index = stats->bucket_count - 1;
  }

  stats->distribution[index]++;
  stats->sum += value;
  stats->sqr_sum += value * value;
  stats->total_count++;
}

void stat_get_smmary (stat_t *stats, double * avg, double * stddev) {

  if(avg) {
    *avg = stats->sum / stats->total_count;
  }

  if(stddev) {
    
    double total = stats->sum;
    double count = stats->total_count;
    double avg = total / count;
    *stddev = sqrt (
			  (stats->sqr_sum - 2 * avg * stats->sum + stats->total_count * avg * avg)
	  / stats->total_count);
  }
}

void
stat_print_summary (stat_t *stats, FILE *fd)
{

  if (!fd)
    return;

  if (stats->total_count <= 0)
    {
      return;
    }

  double total = stats->sum;
  double count = stats->total_count;
  double avg = total / count;

  fprintf (fd, "%s [%llu] avg: %f\n", stats->name, stats->total_count, avg);

  fflush (fd);
}

void
stat_print_distribution (stat_t *stats, FILE *fd)
{
  if (!fd || !stats)
    return;

  if (stats->total_count <= 0)
    {
      return;
    }

  double total = stats->sum;
  double count = stats->total_count;
  double avg = total / count;
  double stddev = sqrt (
      (stats->sqr_sum - 2 * avg * stats->sum + stats->total_count * avg * avg)
	  / stats->total_count);

  fprintf (fd, "\n%s (%f, %f, %f):\n-----------------------------------\n",
	   stats->name, stats->start, stats->end, stats->step);
  fprintf (fd, "%s Total cout: %lld\n", stats->name, stats->total_count);

  if (stats->total_count > 0)
    {
      fprintf (fd, "%s Total sum: %f\n", stats->name, stats->sum);
      fprintf (fd, "%s Average: %f\n", stats->name, avg);
      fprintf (fd, "%s Std.dev : %f\n", stats->name, stddev);
      fprintf (fd, "%s Minimum: %f\n", stats->name, stats->min);
      fprintf (fd, "%s Maximum: %f\n", stats->name, stats->max);

      int i;
      double acc_percent = 0.0;
      for (i = 0; i < (stats->end - stats->start) / stats->step // do not overflow the # of steps
      && acc_percent + 0.000000001 < 1.0;
      // and if the acc percentage reached 1 or close to one, its enough
	  ++i)
	{
	  double bucket = stats->start + ((double) i) * stats->step;
	  unsigned long long count = stats->distribution[i];
	  double percent = (double) count / stats->total_count;

	  // do not print empty rows
	  if (count == 0)
	    continue;

	  acc_percent += percent;

	  total += count * bucket;

	  fprintf (fd, "%f\t%lli\t%f\t%f\n", bucket, count, percent,
		   acc_percent);
	}
    }

  fflush (fd);
}

void
stat_reset (stat_t *stats)
{
  stats->sum = 0.0;
  stats->sqr_sum = 0.0;
  stats->total_count = 0;
  stats->min = 999999999999999;
  stats->max = 0;

  int bucket_count = (stats->end - stats->start) / stats->step;
  memset (stats->distribution, 0, bucket_count * sizeof(unsigned long long));
}

void
stat_destroy (stat_t *stats)
{
  if (stats->distribution)
    {
      free (stats->distribution);
      stats->distribution = NULL;
    }
  stats->distribution = NULL;
}
