
/*
 * memsep.c
 *
 *  Created on: Oct 7, 2017
 *      Author: vahldiek
 */

#include <stdio.h>
#include <string.h>

#include <memsep.h>

#include <crypto.h>

#include <libtem_lsm.h>

#define MB32  (32768)
#define MB128 (131072)
#define MB256 ((MB128)*2)
#define MB512 ((MB256)*2)
#define MB1024 ((MB512)*2)
#define MB2048 ((MB1024)*2)

int erim_memsep_init() {

  erim_init(MB2048, ERIM_FLAG_ISOLATE_TRUSTED | ERIM_FLAG_INTEGRITY_ONLY);
//  erim_memScan(NULL, NULL, ERIM_UNTRUSTED_PKRU);

//  libtem_lsmSyscall();
  
  erim_switch_to_untrusted;
  
  return 0;
}
