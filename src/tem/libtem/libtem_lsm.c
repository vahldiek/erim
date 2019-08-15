#include <libtem.h>
#include <libtem_lsm.h>
#include <erim.h>

__attribute__((constructor)) void libtem_lsm() {
  LTEM_DBM("ltem lsm start init");
  
  if(libtem_init(NULL, NULL, ERIM_FLAG_ISOLATE_TRUSTED)) {
    LTEM_ERR("initialization failed - exit");
    exit(EXIT_FAILURE);
  }

  libtem_lsmSyscall();

  erim_switch_to_trusted;
}
