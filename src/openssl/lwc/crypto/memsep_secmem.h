/*
 * memsep_secmem.h
 *
 *  Created on: Oct 23, 2017
 *      Author: vahldiek
 */

#ifndef MEMSEP_SECMEM_H_
#define MEMSEP_SECMEM_H_

int MEMSEP_secure_malloc_init(size_t size, int minsize);

void *MEMSEP_secure_malloc(size_t num, const char *file, int line);

void *MEMSEP_secure_zalloc(size_t num, const char *file, int line);

void MEMSEP_secure_free(void *ptr, const char *file, int line);

int MEMSEP_secure_allocated(const void *ptr);

size_t MEMSEP_secure_actual_size(void *ptr);

#endif /* MEMSEP_SECMEM_H_ */
