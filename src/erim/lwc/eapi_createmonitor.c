/*
 * eapi_createmonitor.c
 *
 *  Created on: Aug 24, 2017
 *      Author: vahldiek
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <erim_api.h>
#include <common.h>
#include <eapi_processmappings.h>
#include <timer.h>
#include <lwc.h>

erm * global_erm = NULL;
int secret_lwc = 0;
int __thread erm_pkru = 0;

// return SWS_COND_ERROR when sequence is found
static void * erim_scan_for_seq(unsigned char * mem_start,
		unsigned long long length, unsigned char * sequence,
		unsigned int seq_length) {

	unsigned long long memit = 0;
	unsigned long long seqit = 0;

	for (memit = 0; memit < length; memit++) {
		for (seqit = 0;
				seqit < seq_length
						&& mem_start[memit + seqit] == sequence[seqit]; seqit++)
			;

		if (seqit == seq_length) {
			// found sequence
			return (void *) (mem_start + memit);
		}
	}

	return NULL ;
}

erm * erim_createRefernceMonitor() {

	static unsigned char WRPKRU_SEQ[3] = { 0x0F, 0x01, 0xEF };
	erm * mon = NULL;
	int new_lwc = 0;

	if (global_erm)
		return NULL ;

	SWS_NCHK((mon = malloc(sizeof(erm))),
			"createReferenceMonitor failed to allocate memory");
	memset(mon, 0, sizeof(erm));


//	procmaps_t * maps = eapi_pmaps_parse(-1);
//	procmaps_t * tmp = NULL;
//	unsigned int i = 0;
//	for (i = 0; maps;
//			i++, tmp = maps, maps = eapi_pmaps_next(maps), free(tmp)) {
//		if (maps->is_x && maps->is_r) {
//			void * start = maps->addr_start;
//			unsigned long long length = maps->addr_end - maps->addr_start;
//
////			fprintf(stderr, "%p %p %s \n", maps->addr_start, maps->addr_end,
////					maps->pathname);
//
//			while (length > 0) {
//				void * found = erim_scan_for_seq(start, length, WRPKRU_SEQ, 3);
//				if (found) {
////					printf("install fallback at %p\n", found);
//
//					mon->numtotalsct = 0;
//					mon->fallback = 1;
//					// TODO: install fallback for addr found
//
//					length -= ((char *) found + 3) - (char *) start;
//					start = (void *) ((char *) found + 3);
//				} else {
////				printf("fallback not required\n");
//
//					mon->fallback = 0;
//					length = 0;
//				}
//			}
//		}
//	}
//

	if (global_erm == NULL )
		global_erm = mon;

	// **** CREATE LARGE PILE OF MEMORY (PREALLOCATE)

	struct lwc_resource_specifier specs[3];

	/* share the file table */
	specs[0].flags = LWC_RESOURCE_MEMORY | LWC_RESOURCE_SHARE;
	specs[0].sub.memory.start = specs[0].sub.memory.end = -1;
	specs[1].flags = LWC_RESOURCE_FILES | LWC_RESOURCE_SHARE;
	specs[1].sub.descriptors.from = specs[1].sub.descriptors.to = -1;
	specs[2].flags = LWC_RESOURCE_CREDENT | LWC_RESOURCE_SHARE;
	specs[2].sub.credentials.padding[0] = 0;

	new_lwc = lwccreate(specs, 3, NULL, 0, 0, LWC_SUSPEND_ONLY);

	if (new_lwc >= 0) { // created a snap
		secret_lwc = new_lwc;
		//		fprintf(stderr, "created new lwc %d\n", secret_lwc);
	} else if (new_lwc == LWC_SWITCHED) {
		fprintf(stderr, "should never come here");
		exit(255);
	} else if (new_lwc == LWC_FAILED) {
		fprintf(stderr, "error doing snap create / jump to snap create\n");
		exit(255);
	}

	return mon;
}
