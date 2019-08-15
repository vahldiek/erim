/*
 * test_application.c
 *
 *  Created on: Aug 25, 2017
 *      Author: vahldiek
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <common.h>
#include <erim_api.h>

void * mysecretaddition(va_list argptr) {
	int a = va_arg(argptr, int);
	return (void *) ((long long int) a + 500);
}

int mysecretaddition_direct(int a) {
	return a + 500;
}

/*int jmptoaddtion(int a) {
	asm ("jmpq *%0" : : "m" (mysecretaddition_direct) : );

	return 0;
	}*/

int main(int argc, char **argv) {

	erm * mon = NULL;
	erm_sct * sct = NULL;

	if(!(mon = erim_createRefernceMonitor())){
		fprintf(stderr, "creating ref mon failed");
		return SWS_COND_ERROR;
	}

	if(!(sct = erim_createSCT(mon, mysecretaddition, "mysecretaddition"))){
		fprintf(stderr, "creating sct mysecretaddition failed");
		return SWS_COND_ERROR;
	}

	void * ret = erim_sctCall(sct, 100);

//	int ret2 = jmptoaddtion(200);
//	printf("%d\n", ret2);

	erim_print_stats(mon);

	if(((long long int)ret) == 600)
		printf("test_application: Successful\n");
	else
		printf("test_application: FAILED\n");

	return SWS_SUCCESS;
}
