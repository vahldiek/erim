/*
 * common.h
 *
 */

#ifndef COMMON_H_
#define COMMON_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>

// IF SWS_NO_RTCHK is set, all run-time checks will be removed for arguments, function return codes
#ifdef SWS_NO_RTCHK
	#define SWS_NO_ARG_CHK
	#define SWS_NO_IO_CHK
#endif

#ifndef SWS_NO_ARG_CHK
	#define SWS_ARG_CHK(...)		if(__VA_ARGS__) { return SWS_ARG_ERROR; } while (0)
#else
	#define SWS_ARG_CHK(...)
#endif

#ifndef SWS_NO_IO_CHK
	#define SWS_IO_RET_CHK(...)  if(__VA_ARGS__) { perror("IO: "); return SWS_IO_ERROR; } while (0)
#else
	#define SWS_IO_RET_CHK(...)
#endif

#ifndef SWS_NO_COND_CHK
	#define SWS_CHK(cond, ...) if(cond) \
			{fprintf(stderr, __VA_ARGS__); return SWS_COND_ERROR;} while(0)
	#define SWS_NCHK(cond, ...) if(cond == NULL) \
			{fprintf(stderr, __VA_ARGS__); return NULL;} while(0)
#else
	#define SWS_CHK(...)
	#define SWS_NCHK(...)
#endif

#ifndef SWS_NO_COND_ECHK
	#define SWS_ECHK(cond, ...) if(cond) \
			{fprintf(stderr, __VA_ARGS__); exit(SWS_COND_ERROR);} while(0)
#else
	#define SWS_ECHK(...)
#endif

#ifndef SWS_NO_LOG
	#define SWS_LOG(...) fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");
#else
	#define SWS_LOG(...)
#endif

#define SWS_SUCCESS		0
#define SWS_ARG_ERROR	1
#define SWS_IO_ERROR	2
#define SWS_COND_ERROR	3

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H_ */
