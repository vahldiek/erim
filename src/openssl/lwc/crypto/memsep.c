/*
 * memsep.c
 *
 *  Created on: Oct 7, 2017
 *      Author: vahldiek
 */

#include <stdio.h>
#include <string.h>

#include <memsep.h>
#include <memsep_secmem.h>
#include <erim_api.h>

#include <crypto.h>

#define MB32  (32768)
#define MB128 (131072)
#define MB256 ((MB128)*2)
#define MB512 ((MB256)*2)

static void * memsep_malloc(size_t num, const char *file, int line) {

	if (num == 0)
		return NULL ;

	if (erm_pkru == 0)
		return malloc(num);
	else
		return (void*) MEMSEP_secure_malloc(num, file, line) ;
}

static void memsep_free(void *str, const char *file, int line) {

	if (str == NULL )
		return;

	if (erm_pkru == 0)
		free(str);
	else
		(void) MEMSEP_secure_free(str, file, line);

}

static void * secure_realloc(void * str, size_t num, const char * file,
		int line) {
	size_t size = CRYPTO_secure_actual_size(str);
	void * tmp = MEMSEP_secure_malloc(num, file, line);
	memcpy(tmp, str, size);
	MEMSEP_secure_free(str, file, line);

	return tmp;
}

static void * memsep_realloc(void *str, size_t num, const char *file, int line) {

	if (str == NULL )
		return CRYPTO_malloc(num, file, line);

	if (num == 0) {
		memsep_free(str, file, line);
		return NULL ;
	}

	if (erm_pkru == 0)
		return realloc(str, num);
	else {
		return secure_realloc(str, num, file, line) ;
	}

}

MEMSEP_BUILD_BRIDGE(void *, MEMSEP_secure_malloc, RET, 3, size_t, const char *,
		int)
MEMSEP_BUILD_BRIDGE(void *, MEMSEP_secure_zalloc, RET, 3, size_t, const char *,
		int)
MEMSEP_BUILD_BRIDGE(void *, secure_realloc, RET, 4, void*, size_t, const char *,
		int)
MEMSEP_BUILD_BRIDGE(void, MEMSEP_secure_free, VOID, 3, void *, const char *,
		int)

extern int memsep_init_eaes(erm * mon);

int memsep_init(erm * mon) {

	if (!mon)
		return 1;

	MEMSEP_CREATE_BRIDGE(mon, MEMSEP_secure_zalloc);
	MEMSEP_CREATE_BRIDGE(mon, MEMSEP_secure_malloc);
	MEMSEP_CREATE_BRIDGE(mon, secure_realloc);
	MEMSEP_CREATE_BRIDGE(mon, MEMSEP_secure_free);

	memsep_init_eaes(mon);

	if (MEMSEP_secure_malloc_init(MB128, 64) == 0)
		exit(255);

	CRYPTO_set_mem_functions(memsep_malloc, memsep_realloc, memsep_free);

	return 1;
}
