/*
 * eapi_print_stats.c
 *
 *  Created on: Aug 30, 2017
 *      Author: vahldiek
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <erim_api.h>
#include <gtodtimer.h>

void erim_print_stats(erm * mon) {

#ifdef ERM_SCT_STATS
	if (mon == NULL )
		mon = global_erm;

	erm_sct * sct = mon->scts;
	int i = 0;
	char tmpstr[255];
	pid_t pid = getpid();
	snprintf(tmpstr, 255, "erim.stat.%d", pid);
	//	printf("opening %s\n", tmpstr);
	FILE * out = fopen(tmpstr, "w");
	if (out) {
		fprintf(out, "mon %p, %p: Per SCT statistics:\n", mon, global_erm);
		for (i = 0; sct; sct = sct->next, i++) {
			fprintf(out, "cur stc %p:", sct);
			char * name = NULL;
			if (sct->name) {
				name = sct->name;
			} else { // try to print at least some name
				void *buffer[1] = { sct->fct };
				char **strings = NULL;
				//				strings = backtrace_symbols(buffer, 1);
				if (strings == NULL ) {
					name = "";
				} else {
					name = strings[0];
				}
			}
			fprintf(out, "%s %d: count=%lld\n", name, i, sct->num_used);
		}

		fclose(out);
	}
#endif

}
