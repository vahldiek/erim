/*
 * mod_disas.c
 *
 *  Created on: Jan 23, 2017
 *      Author: vahldiek
 */

#include <stdlib.h>
#include <common.h>
#include <mod_disas.h>
#include <mod_disas_capstone.h>
#include <mod_disas_dyninst.h>

mod_disas_t * disas_init(mod_disas_instances_t i) {

	mod_disas_t * md = malloc(sizeof(mod_disas_t));

	if (!md)
		return NULL ;

	switch (i) {
		case MOD_DISAS_CAPSTONE:
		  //		SWS_NCHK(mod_disas_cap_init(md) == SWS_SUCCESS && md, "Cap init failed");
		break;

		case MOD_DISAS_DYNINST:
		SWS_NCHK(mod_disas_dyn_init(md) == SWS_SUCCESS && md, "Dyninst init failed");
		break;

		default:
		SWS_LOG("Disas module identifier wrong %d (range %d to %d)", i,
				MOD_DISAS_CAPSTONE, MOD_DISAS_DYNINST);
		return NULL;
	}

	return md;
}

int disas_fini(mod_disas_t * md) {

	return md->fini(md);
}
