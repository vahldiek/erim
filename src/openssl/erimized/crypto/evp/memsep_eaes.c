/*
 * memsep_e_aes.c
 *
 *  Created on: Oct 7, 2017
 *      Author: vahldiek
 */

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include "internal/evp_int.h"
#include "modes_lcl.h"
#include <openssl/rand.h>
#include "evp_locl.h"

#include "e_aes.h"
#include "memsep.h"
#include "memsep_eaes.h"

/*#ifdef ERIM_DBG

FILE * f = NULL;

#define DBG_PRT(...) \
	do { \
		if(f == NULL)\
			f = fopen("run.out", "a");\
		fprintf(f, __VA_ARGS__);\
		fflush(f);\
	} while(0)

void
prt_stack_trace(const char * name, void * data)
{
	int j, nptrs;
	void *buffer[100];
	char **strings;

	nptrs = backtrace(buffer, 100);

	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		return;
	}

	if(!f)
	f = fopen("run.out", "a");

	DBG_PRT("stack trace for %s(%p):\n", name, data);
	for (j = 0; j < nptrs; j++)
	DBG_PRT("%s\n", strings[j]);

	free(strings);
}

#else
*/
#define DBG_PRT(...)
#define prt_stack_trace(...)

//#endif

#if     defined(AES_ASM) && !defined(I386_ONLY) &&      (  \
        ((defined(__i386)       || defined(__i386__)    || \
          defined(_M_IX86)) && defined(OPENSSL_IA32_SSE2))|| \
        defined(__x86_64)       || defined(__x86_64__)  || \
        defined(_M_AMD64)       || defined(_M_X64)      )

extern unsigned int OPENSSL_ia32cap_P[];

# ifdef VPAES_ASM
#  define VPAES_CAPABLE   (OPENSSL_ia32cap_P[1]&(1<<(41-32)))
# endif
# ifdef BSAES_ASM
#  define BSAES_CAPABLE   (OPENSSL_ia32cap_P[1]&(1<<(41-32)))
# endif
/*
 * AES-NI section
 */
# define AESNI_CAPABLE   (OPENSSL_ia32cap_P[1]&(1<<(57-32)))

/*
 * ALWAYS IN REFMON
 */
int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
		AES_KEY *key);
int aesni_set_decrypt_key(const unsigned char *userKey, int bits,
		AES_KEY *key);
/*
 * ALWAYS OUTSIDE REFMON
 */

void aesni_encrypt(const unsigned char *in, unsigned char *out,
		const AES_KEY *key);
void aesni_decrypt(const unsigned char *in, unsigned char *out,
		const AES_KEY *key);

void aesni_ecb_encrypt(const unsigned char *in,
		unsigned char *out,
		size_t length, const AES_KEY *key, int enc);
void aesni_cbc_encrypt(const unsigned char *in,
		unsigned char *out,
		size_t length,
		const AES_KEY *key, unsigned char *ivec, int enc);

void aesni_ctr32_encrypt_blocks(const unsigned char *in,
		unsigned char *out,
		size_t blocks,
		const void *key, const unsigned char *ivec);

void aesni_xts_encrypt(const unsigned char *in,
		unsigned char *out,
		size_t length,
		const AES_KEY *key1, const AES_KEY *key2,
		const unsigned char iv[16]);

void aesni_xts_decrypt(const unsigned char *in,
		unsigned char *out,
		size_t length,
		const AES_KEY *key1, const AES_KEY *key2,
		const unsigned char iv[16]);

void aesni_ccm64_encrypt_blocks(const unsigned char *in,
		unsigned char *out,
		size_t blocks,
		const void *key,
		const unsigned char ivec[16],
		unsigned char cmac[16]);

void aesni_ccm64_decrypt_blocks(const unsigned char *in,
		unsigned char *out,
		size_t blocks,
		const void *key,
		const unsigned char ivec[16],
		unsigned char cmac[16]);

# if defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
size_t aesni_gcm_encrypt(const unsigned char *in,
		unsigned char *out,
		size_t len,
		const void *key, unsigned char ivec[16], u64 *Xi);
#  define AES_gcm_encrypt aesni_gcm_encrypt
size_t aesni_gcm_decrypt(const unsigned char *in,
		unsigned char *out,
		size_t len,
		const void *key, unsigned char ivec[16], u64 *Xi);
#  define AES_gcm_decrypt aesni_gcm_decrypt
void gcm_ghash_avx(u64 Xi[2], const u128 Htable[16], const u8 *in,
		size_t len);

#endif

// set enc/dec key
ERIM_BUILD_BRIDGE3(int, aesni_set_encrypt_key, const unsigned char *, int, AES_KEY *)
ERIM_BUILD_BRIDGE3(int, aesni_set_decrypt_key, const unsigned char *, int, AES_KEY *)

// enc/dec
ERIM_BUILD_BRIDGE_VOID3(aesni_encrypt, unsigned char *, unsigned char *, const AES_KEY *)
ERIM_BUILD_BRIDGE_VOID3(aesni_decrypt, unsigned char *, unsigned char *, const AES_KEY *)
ERIM_BUILD_BRIDGE_VOID5(aesni_ctr32_encrypt_blocks, unsigned char *,
		    unsigned char *, size_t, const void *, const unsigned char *)

// gcm
ERIM_BUILD_BRIDGE6(size_t, aesni_gcm_encrypt, const unsigned char *, unsigned char *, size_t, void *, unsigned char *, u64 *);
ERIM_BUILD_BRIDGE6(size_t, aesni_gcm_decrypt, const unsigned char *, unsigned char *, size_t, void *, unsigned char *, u64 *);

// cbc/ebc enc
ERIM_BUILD_BRIDGE_VOID6(aesni_cbc_encrypt, const unsigned char *,
			unsigned char *, size_t, const AES_KEY *, unsigned char *, int)
ERIM_BUILD_BRIDGE_VOID5(aesni_ecb_encrypt, const unsigned char *, unsigned char *, size_t, const AES_KEY *, int)

// xts enc/dec
ERIM_BUILD_BRIDGE_VOID6(aesni_xts_encrypt, const unsigned char *, unsigned char *, size_t, const AES_KEY *, const AES_KEY *, const unsigned char *)
ERIM_BUILD_BRIDGE_VOID6(aesni_xts_decrypt, const unsigned char *, unsigned char *, size_t, const AES_KEY *, const AES_KEY *, const unsigned char *)

// ccm
ERIM_BUILD_BRIDGE_VOID6(aesni_ccm64_encrypt_blocks, const unsigned char *,
			unsigned char *, size_t, const void *, const unsigned char *, unsigned char *)

ERIM_BUILD_BRIDGE_VOID6(aesni_ccm64_decrypt_blocks, const unsigned char *, 
			unsigned char *, size_t,  const void *, const unsigned char *,  unsigned char *)

# ifndef OPENSSL_NO_OCB
void aesni_ocb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t blocks, const void *key,
                       size_t start_block_num,
                       unsigned char offset_i[16],
                       const unsigned char L_[][16],
                       unsigned char checksum[16]);
void aesni_ocb_decrypt(const unsigned char *in, unsigned char *out,
                       size_t blocks, const void *key,
                       size_t start_block_num,
                       unsigned char offset_i[16],
                       const unsigned char L_[][16],
                       unsigned char checksum[16]);

void erim_bridge_aesni_ocb_encrypt(const unsigned char * in, unsigned char * out, size_t len, const void * addr, size_t len2, unsigned char * addr2, const unsigned char addr3[][16], unsigned char * addr4) {
  erim_switch_to_trusted;
  aesni_ocb_encrypt(in, out, len, addr, len2, addr2, addr3, addr4);
  erim_switch_to_untrusted;
}
void erim_bridge_aesni_ocb_decrypt(const unsigned char * in, unsigned char * out, size_t len, const void * addr, size_t len2, unsigned char * addr2, const unsigned char addr3[][16], unsigned char * addr4) {
  erim_switch_to_trusted;
  aesni_ocb_decrypt(in, out, len, addr, len2, addr2, addr3, addr4);
  erim_switch_to_untrusted;
}


#endif

#endif
