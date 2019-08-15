/*
 * erim_printstats.c
 *
 */

#include <stdio.h>
#include <stdlib.h>

unsigned long long erim_cnt = 0;

void erim_printStats() {

#ifdef ERM_SCT_STATS
	if (mon == NULL )
		mon = global_erm;

	int i = 0;
	char tmpstr[255];
	pid_t pid = getpid();
	snprintf(tmpstr, 255, "erim.stat.%d", pid);
	FILE * out = fopen(tmpstr, "w");
	if (out) {
	  fprintf(out, "%lld\n", erim_cnt);
	}
#endif

}
