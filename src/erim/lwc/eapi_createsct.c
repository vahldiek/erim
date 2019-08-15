/*
 * eapi_createsct.c
 *
 *  Created on: Aug 24, 2017
 *      Author: vahldiek
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <erim_api.h>
#include <common.h>

erm_sct * erim_createSCT(erm * mon, erm_fct fct, char * name) {

	erm_sct * newSCT = NULL;

	if(mon == NULL)
		mon = global_erm;

	SWS_NCHK(fct, "createSCT fct NULL");

	SWS_NCHK((newSCT = malloc(sizeof(erm_sct))), "failed to create new sct");
	memset(newSCT, 0, sizeof(erm_sct));

	newSCT->fct = fct;
#ifdef ERM_SCT_STAT
	newSCT->num_used = 0;

	if(name) {
		size_t len = strnlen(name, 255);
		newSCT->name = malloc(len + 1);
		memcpy(newSCT->name, name, len + 1);
	}
#endif

	newSCT->next = mon->scts;
	mon->scts = newSCT;

	return newSCT;
}
