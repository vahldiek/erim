#include "cpi.h"

#define ERIM_INTEGRITY_ONLY
#include "erim/erim.h"

#include "erim/erim_printstats.c"
#include "erim/erim_processmappings.c"
#include "erim/erim.c"

#include "common_inlines.c"
#include "common.c"

#if defined(CPI_LOOKUP_TABLE)
# include "lookuptable_inlines.c"
# include "lookuptable.c"
#elif defined(CPI_SIMPLE_TABLE)
# include "simpletable_inlines.c"
# include "simpletable.c"
#else
# include "hashtable_inlines.c"
# include "hashtable.c"
#endif
