/*
 * mod_disas_DYNINST.h
 *
 *  Created on: Jan 23, 2017
 *      Author: vahldiek
 */

#ifndef MOD_DISAS_DYNINST_H_
#define MOD_DISAS_DYNINST_H_

#ifdef __cplusplus
extern "C"
{
#endif

extern int mod_disas_dyn_init(mod_disas_t * md);
extern int mod_disas_dyn_fini(mod_disas_t * md);
int mod_disas_dyn_rewrite(mod_disas_t * md, erim_t * e);

#ifdef __cplusplus
}
#endif

#endif /* MOD_DISAS_DYNINST_H_ */
