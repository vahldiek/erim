/*
 * mod_disas_helper.h
 *
 *  Created on: May 23, 2017
 *      Author: vahldiek
 */

#ifndef MOD_DISAS_HELPER_H_
#define MOD_DISAS_HELPER_H_

#include <ba_erim_ds.h>

typedef int (*mod_disas_check)(void * md, erim_input_t* in, erim_result_t* res);
typedef int (*mod_disas_rewrite)(void * md, erim_input_t * in, erim_result_t * res);
typedef int (*mod_disas_writeFile)(void * md, char * filename);
typedef int (*mod_disas_fini)(void * md);

typedef struct mod_disas {

	mod_disas_check check;
	mod_disas_rewrite rewrite;
	mod_disas_writeFile writeFile;
	mod_disas_fini fini;

	void * mod_specific;

} mod_disas_t;

typedef enum {
	MOD_DISAS_CAPSTONE = 0,
	MOD_DISAS_DYNINST,
	MOD_DISAS_NUM_MODS
} mod_disas_instances_t;

#endif /* MOD_DISAS_HELPER_H_ */
