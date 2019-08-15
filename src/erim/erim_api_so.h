/*
 *
 */

#ifndef ERIM_API_SO_H_
#define ERIM_API_SO_H_

#include <stdarg.h>

#define ERM_NO_ARG_CHKS

#ifdef ERIM_STATS
#define ERM_SCT_STATS
#endif

typedef void * (*erm_fct)(va_list argptr);

typedef struct erm_sct {

	erm_fct fct;

#ifdef ERM_SCT_STATS
	unsigned long long num_used;
	char * name;
#endif

	struct erm_sct * next;

} erm_sct;

typedef struct erm {

	int fallback;

	unsigned long long numtotalsct;

	erm_sct * scts;

} erm;

extern erm * global_erm;
extern __thread int erm_pkru;
extern int secret_lwc;

#endif
