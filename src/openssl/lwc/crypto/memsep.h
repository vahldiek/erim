/*
 * memsep.h
 *
 *  Created on: Oct 7, 2017
 *      Author: vahldiek
 */

#ifndef MEMSEP_H_
#define MEMSEP_H_

#include <stdio.h>
#include <erim_api.h>

#define MEMSEP_DEFINE_SCT(f) \
	extern erm_sct * memsep_scts_##f

#define MEMSEP_DECLARE_SCT(f) \
	erm_sct * memsep_scts_##f = NULL

#define MEMSEP_CREATE_SCT(mon, f, func) \
	do { if(!memsep_scts_##f) memsep_scts_##f = erim_createSCT(mon, (erm_fct) func, #func); } while (0)

#define MEMSEP_GET_SCT(f)	memsep_scts_##f

#define MEMSEP_DEFINE_FCT(f) \
	static int memsep_##f(va_list argptr)
#define MEMSEP_DEFINE_RETFCT(ret, f)\
	static ret memsep_##f(va_list argptr)
#define MEMSEP_DEFINE_VOIDFCT(f) \
	static void memsep_##f(va_list argptr)

#define MEMSEP_DEFINE_SCT_ARGUMENT(type, name)\
	type name = va_arg(argptr, type)

//#define MEMSEP_BUILD_SCT(f)

#define MEMSEP_CALL_SCT(f, ...) \
		(long) erim_sctCall(memsep_scts_##f, ##__VA_ARGS__)

/*
 * BRIDGE INTERFACE
 *
 * BRIDGE -> erim_sctCall -> Inner Bridge -> FCT
 *
 * BRIDGE defines function interface translates it to SCTCALL
 * INNER Bridge gets arguments and makes FCT
 *
 * To define a Bridge use MEMSEP_BUILD_BRIDGE (creates code at compile time)
 * To define globally known interface MEMSEP_DEFINE_BRIDGE
  			(creates external ref. to sct created in prev line)
 * To setup the SCT do MEMSEP_CREATE_BRIDGE (initiates sct at runtime before first call)
 * To call a bridge do MEMSEP_CALL_SCT_BRIDGE (after prev. line)
 */

#define MEMSEP_DEFINE_BRIDGE(f) \
	MEMSEP_DEFINE_SCT(f)

#define MEMSEP_CALL_SCT_BRIDGE(f) \
	memsep_bridge_##f

#define MEMSEP_DEFINE_BRIDGEFCT0(ret, f) \
	MEMSEP_DEFINE_BRIDGE(f);\
	extern ret MEMSEP_CALL_SCT_BRIDGE(f)();
#define MEMSEP_DEFINE_BRIDGEFCT1(ret, f, type1) \
	MEMSEP_DEFINE_BRIDGE(f);\
	extern ret MEMSEP_CALL_SCT_BRIDGE(f)(type1 arg1);
#define MEMSEP_DEFINE_BRIDGEFCT2(ret, f, type1, type2) \
	MEMSEP_DEFINE_BRIDGE(f);\
	extern ret MEMSEP_CALL_SCT_BRIDGE(f)(type1 arg1, type2 arg2);
#define MEMSEP_DEFINE_BRIDGEFCT3(ret, f, type1, type2, type3) \
	MEMSEP_DEFINE_BRIDGE(f);\
	extern ret MEMSEP_CALL_SCT_BRIDGE(f)(type1 arg1, type2 arg2, type3 arg3);
#define MEMSEP_DEFINE_BRIDGEFCT4(ret, f, type1, type2, type3, type4) \
	MEMSEP_DEFINE_BRIDGE(f);\
	extern ret MEMSEP_CALL_SCT_BRIDGE(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4);
#define MEMSEP_DEFINE_BRIDGEFCT5(ret, f, type1, type2, type3, type4, type5) \
	MEMSEP_DEFINE_BRIDGE(f);\
	extern ret MEMSEP_CALL_SCT_BRIDGE(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5);
#define MEMSEP_DEFINE_BRIDGEFCT6(ret, f, type1, type2, type3, type4, type5, type6) \
	MEMSEP_DEFINE_BRIDGE(f);\
	extern ret MEMSEP_CALL_SCT_BRIDGE(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6);
#define MEMSEP_DEFINE_BRIDGEFCT7(ret, f, type1, type2, type3, type4, type5, type6, type7) \
	MEMSEP_DEFINE_BRIDGE(f);\
	extern ret MEMSEP_CALL_SCT_BRIDGE(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7);
#define MEMSEP_DEFINE_BRIDGEFCT8(ret, f, type1, type2, type3, type4, type5, type6, type7, type8) \
	MEMSEP_DEFINE_BRIDGE(f);\
	extern ret MEMSEP_CALL_SCT_BRIDGE(f)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7, type8 arg8);

#define MEMSEP_CREATE_BRIDGE(mon, f) \
	do { if(!memsep_scts_##f) memsep_scts_##f = erim_createSCT(mon, (erm_fct) memsep_inner_bridge_##f, #f); } while (0)

#define MEMSEP_EXEC_SCT_BRIDGE(f, ...) \
	MEMSEP_CALL_SCT(f, ##__VA_ARGS__)

/*
 * Define sct bridge function (function which calls sct to transfer to f)
 */
#define MEMSEP_DEFINE_SCT_BRIDGE_RET0(ret, f)\
	ret memsep_bridge_##f () {\
		if(MEMSEP_GET_SCT(f) == NULL) {\
			MEMSEP_CREATE_BRIDGE(NULL, f);\
		}\
		return (ret) MEMSEP_CALL_SCT(f);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_RET1(ret, f, type1)\
	ret memsep_bridge_##f (type1 arg1) {\
		if(MEMSEP_GET_SCT(f) == NULL) {\
			MEMSEP_CREATE_BRIDGE(NULL, f);\
		}\
		return (ret) MEMSEP_CALL_SCT(f, arg1);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_RET2(ret, f, type1, type2)\
	ret memsep_bridge_##f (type1 arg1, type2 arg2) {\
		if(MEMSEP_GET_SCT(f) == NULL) {\
			MEMSEP_CREATE_BRIDGE(NULL, f);\
		}\
		return (ret) MEMSEP_CALL_SCT(f, arg1, arg2);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_RET3(ret, f, type1, type2, type3)\
	ret memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3) {\
		if(MEMSEP_GET_SCT(f) == NULL) {\
			MEMSEP_CREATE_BRIDGE(NULL, f);\
		}\
		return (ret) MEMSEP_CALL_SCT(f, arg1, arg2, arg3);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_RET4(ret, f, type1, type2, type3, type4)\
	ret memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3, type4 arg4) {\
		if(MEMSEP_GET_SCT(f) == NULL) {\
			MEMSEP_CREATE_BRIDGE(NULL, f);\
		}\
		return (ret) MEMSEP_CALL_SCT(f, arg1, arg2, arg3, arg4);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_RET5(ret, f, type1, type2, type3, type4, type5)\
	ret memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) {\
		if(MEMSEP_GET_SCT(f) == NULL) {\
			MEMSEP_CREATE_BRIDGE(NULL, f);\
		}\
		return (ret) MEMSEP_CALL_SCT(f, arg1, arg2, arg3, arg4, arg5);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_RET6(ret, f, type1, type2, type3, type4, type5, type6)\
	ret memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6) {\
		if(MEMSEP_GET_SCT(f) == NULL) {\
			MEMSEP_CREATE_BRIDGE(NULL, f);\
		}\
		return (ret) MEMSEP_CALL_SCT(f, arg1, arg2, arg3, arg4, arg5, arg6);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_RET7(ret, f, type1, type2, type3, type4, type5, type6, type7)\
	ret memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7) {\
		return (ret) MEMSEP_CALL_SCT(f, arg1, arg2, arg3, arg4, arg5, arg6, arg7);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_RET8(ret, f, type1, type2, type3, type4, type5, type6, type7, type8)\
	ret memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7, type8 arg8) {\
		return (ret) MEMSEP_CALL_SCT(f, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_VOID0(ret, f)\
	void memsep_bridge_##f () {\
		(void) MEMSEP_CALL_SCT(f);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_VOID1(ret, f, type1)\
	void memsep_bridge_##f (type1 arg1) {\
		(void) MEMSEP_CALL_SCT(f, arg1);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_VOID2(ret, f, type1, type2)\
	void memsep_bridge_##f (type1 arg1, type2 arg2) {\
		(void) MEMSEP_CALL_SCT(f, arg1, arg2);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_VOID3(ret, f, type1, type2, type3)\
	void memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3) {\
		(void) MEMSEP_CALL_SCT(f, arg1, arg2, arg3);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_VOID4(ret, f, type1, type2, type3, type4)\
	void memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3, type4 arg4) {\
		(void) MEMSEP_CALL_SCT(f, arg1, arg2, arg3, arg4);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_VOID5(ret, f, type1, type2, type3, type4, type5)\
	void memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) {\
		(void) MEMSEP_CALL_SCT(f, arg1, arg2, arg3, arg4, arg5);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_VOID6(ret, f, type1, type2, type3, type4, type5, type6)\
	void memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6) {\
		if(MEMSEP_GET_SCT(f) == NULL) {\
			MEMSEP_CREATE_BRIDGE(NULL, f);\
		}\
		(void) MEMSEP_CALL_SCT(f, arg1, arg2, arg3, arg4, arg5, arg6);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_VOID7(ret, f, type1, type2, type3, type4, type5, type6, type7)\
	void memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7) {\
		if(MEMSEP_GET_SCT(f) == NULL) {\
			MEMSEP_CREATE_BRIDGE(NULL, f);\
		}\
		(void) MEMSEP_CALL_SCT(f, arg1, arg2, arg3, arg4, arg5, arg6, arg7);\
	}
#define MEMSEP_DEFINE_SCT_BRIDGE_VOID8(ret, f, type1, type2, type3, type4, type5, type6, type7, type8)\
	void memsep_bridge_##f (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6, type7 arg7, type8 arg8) {\
		if(MEMSEP_GET_SCT(f) == NULL) {\
			MEMSEP_CREATE_BRIDGE(NULL, f);\
		}\
		(void) MEMSEP_CALL_SCT(f, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);\
	}

/*
 * Define inner bridge function (which calls f)
 * exists for void and return functions
 */
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_RET0(ret, f) \
	MEMSEP_DEFINE_RETFCT(ret, inner_bridge_##f) {\
		return f();\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_RET1(ret, f, type1) \
	MEMSEP_DEFINE_RETFCT(ret, inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		return f(arg1);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_RET2(ret, f, type1, type2) \
	MEMSEP_DEFINE_RETFCT(ret, inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		return f(arg1, arg2);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_RET3(ret, f, type1, type2, type3) \
	MEMSEP_DEFINE_RETFCT(ret, inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		return f(arg1, arg2, arg3);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_RET4(ret, f, type1, type2, type3, type4) \
	MEMSEP_DEFINE_RETFCT(ret, inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type4, arg4);\
		return f(arg1, arg2, arg3, arg4);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_RET5(ret, f, type1, type2, type3, type4, type5) \
	MEMSEP_DEFINE_RETFCT(ret, inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type4, arg4);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type5, arg5);\
		return f(arg1, arg2, arg3, arg4, arg5);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_RET6(ret, f, type1, type2, type3, type4, type5, type6) \
	MEMSEP_DEFINE_RETFCT(ret, inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type4, arg4);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type5, arg5);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type6, arg6);\
		return f(arg1, arg2, arg3, arg4, arg5, arg6);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_RET7(ret, f, type1, type2, type3, type4, type5, type6, type7) \
	MEMSEP_DEFINE_RETFCT(ret, inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type4, arg4);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type5, arg5);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type6, arg6);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type7, arg7);\
		return f(arg1, arg2, arg3, arg4, arg5, arg6, arg7);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_RET8(ret, f, type1, type2, type3, type4, type5, type6, type7, type8) \
	MEMSEP_DEFINE_RETFCT(ret, inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type4, arg4);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type5, arg5);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type6, arg6);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type7, arg7);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type8, arg8);\
		return f(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);\
	}

#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_VOID0(ret, f) \
	MEMSEP_DEFINE_VOIDFCT(inner_bridge_##f) {\
		(void) f();\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_VOID1(ret, f, type1) \
	MEMSEP_DEFINE_VOIDFCT(inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		(void) f(arg1);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_VOID2(ret, f, type1, type2) \
	MEMSEP_DEFINE_VOIDFCT(inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		(void) f(arg1, arg2);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_VOID3(ret, f, type1, type2, type3) \
	MEMSEP_DEFINE_VOIDFCT(inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		(void) f(arg1, arg2, arg3);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_VOID4(ret, f, type1, type2, type3, type4) \
	MEMSEP_DEFINE_VOIDFCT(inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type4, arg4);\
		(void) f(arg1, arg2, arg3, arg4);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_VOID5(ret, f, type1, type2, type3, type4, type5) \
	MEMSEP_DEFINE_VOIDFCT(inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type4, arg4);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type5, arg5);\
		(void) f(arg1, arg2, arg3, arg4, arg5);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_VOID6(ret, f, type1, type2, type3, type4, type5, type6) \
	MEMSEP_DEFINE_VOIDFCT(inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type4, arg4);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type5, arg5);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type6, arg6);\
		(void) f(arg1, arg2, arg3, arg4, arg5, arg6);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_VOID7(ret, f, type1, type2, type3, type4, type5, type6, type7) \
	MEMSEP_DEFINE_VOIDFCT(inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type4, arg4);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type5, arg5);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type6, arg6);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type7, arg7);\
		(void) f(arg1, arg2, arg3, arg4, arg5, arg6, arg7);\
	}
#define MEMSEP_DEFINE_SCT_INNER_BRIDGE_VOID8(ret, f, type1, type2, type3, type4, type5, type6, type7, type8) \
	MEMSEP_DEFINE_VOIDFCT(inner_bridge_##f) {\
		MEMSEP_DEFINE_SCT_ARGUMENT(type1, arg1);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type2, arg2);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type3, arg3);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type4, arg4);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type5, arg5);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type6, arg6);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type7, arg7);\
		MEMSEP_DEFINE_SCT_ARGUMENT(type8, arg8);\
		(void) f(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);\
	}

/*
 * Define and Declare necessary a bridge and its necessary function and erm_sct
 * ret - type of return
 * f - function name to be called
 * v - VOID or RET defines if it returns value
 * num - number of arguments
 * ... - list of arguments and their type (type, argumentname)
 */
#define MEMSEP_BUILD_BRIDGE(ret, f, v, num, ...)\
		MEMSEP_DECLARE_SCT(f);\
		\
		MEMSEP_DEFINE_SCT_INNER_BRIDGE_##v##num(ret, f, __VA_ARGS__)\
		\
		MEMSEP_DEFINE_SCT_BRIDGE_##v##num(ret, f, __VA_ARGS__)

/*
 * Interface to memsep
 */

int memsep_init(erm * mon);

MEMSEP_DEFINE_BRIDGE(MEMSEP_secure_zalloc);
MEMSEP_DEFINE_BRIDGE(MEMSEP_secure_malloc);
MEMSEP_DEFINE_BRIDGE(secure_realloc);
MEMSEP_DEFINE_BRIDGE(MEMSEP_secure_free);

#endif /* MEMSEP_H_ */
