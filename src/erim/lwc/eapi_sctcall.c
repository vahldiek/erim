/*
 * eapi_sctcall.c
 *
 *  Created on: Aug 24, 2017
 *      Author: vahldiek
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <lwc.h>
#include <erim_api.h>
#include <common.h>

void * erim_sctCall(erm_sct * sct, ...) {

#ifdef ERM_NO_ARG_CHKS
	if(sct == NULL) {

		if(global_erm == NULL) {
			global_erm = erim_createRefernceMonitor();
		}

		global_erm->numtotalsct++;

		return NULL;
	}
#endif

#ifdef ERM_SCT_STATS
	sct->num_used++;
#endif

	va_list argptr;
	int num = 1;
	int srclwc = 0;
	va_start(argptr, sct);

	// jump into refmon
	//	fprintf(stderr, "jumping to %d\n", secret_lwc);	
	lwcsuspendswitch(secret_lwc, NULL, 0, NULL, 0, NULL);
	erm_pkru = 1;
	
	//	fprintf(stderr, "calling fct %p arg %p\n", sct->fct, (void*)argptr);
	void * ret = sct->fct(argptr);
	
	// jump out of refmon
	erm_pkru = 0;
	//	fprintf(stderr, "jumping to %d\n", srclwc);
	lwcsuspendswitch(srclwc, NULL, 0, NULL, 0, NULL);

	va_end(argptr);
	//	fprintf(stderr, "returned with arg %p\n", (void*)ret);

	return (void*) ret;
}
