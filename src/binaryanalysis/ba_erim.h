/*
 * erim.h
 *
 *  Created on: Jan 23, 2017
 *      Author: vahldiek
 */

#ifndef ERIM_H_
#define ERIM_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <elf_object.h>
#include <ba_erim_ds.h>
#include <mod_disas_helper.h>

typedef struct erim {
	erim_input_t in;
	erim_result_t * res;

	int eo_load_return;
	unsigned long long executable_memory;
	unsigned int inspected_segments;

	mod_disas_t * md;
} erim_t;

#ifdef __cplusplus
}
#endif

#endif /* ERIM_H_ */
