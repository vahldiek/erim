/*
 * mod_disas.h
 *
 *  Created on: Jan 23, 2017
 *      Author: vahldiek
 */

#ifndef MOD_DISAS_H
#define MOD_DISAS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <ba_erim.h>
#include <mod_disas_helper.h>

extern mod_disas_t * disas_init(mod_disas_instances_t i);
extern int disas_fini(mod_disas_t * md);

#ifdef __cplusplus
}
#endif

#endif /* MOD_DISAS_H */
