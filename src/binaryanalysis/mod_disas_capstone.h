/*
 * mod_disas_capstone.h
 *
 *  Created on: Jan 23, 2017
 *      Author: vahldiek
 */

#ifndef MOD_DISAS_CAPSTONE_H_
#define MOD_DISAS_CAPSTONE_H_

#ifdef __cplusplus
extern "C"
{
#endif

extern int mod_disas_cap_init(mod_disas_t * md);
extern int mod_disas_cap_check(mod_disas_t * md);
extern int mod_disas_cap_fini(mod_disas_t * md);

#ifdef __cplusplus
}
#endif

#endif /* MOD_DISAS_CAPSTONE_H_ */
