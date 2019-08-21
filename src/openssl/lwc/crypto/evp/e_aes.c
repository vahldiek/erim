/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <execinfo.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include "internal/evp_int.h"
#include "modes_lcl.h"
#include <openssl/rand.h>
#include "evp_locl.h"
#include <erim_api.h>
#include "e_aes.h"
#include <memsep.h>
#include "memsep_eaes.h"


#ifdef ERIM_DBG

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

#define DBG_PRT(...)
#define prt_stack_trace(...)

#endif





#define MAXBITCHUNK     ((size_t)1<<(sizeof(size_t)*8-4))

#ifdef VPAES_ASM
int vpaes_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
int vpaes_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);

void vpaes_encrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void vpaes_decrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);

void vpaes_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);
#endif
#ifdef BSAES_ASM
void bsaes_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const AES_KEY *key,
                       unsigned char ivec[16], int enc);
void bsaes_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t len, const AES_KEY *key,
                                const unsigned char ivec[16]);
void bsaes_xts_encrypt(const unsigned char *inp, unsigned char *out,
                       size_t len, const AES_KEY *key1,
                       const AES_KEY *key2, const unsigned char iv[16]);
void bsaes_xts_decrypt(const unsigned char *inp, unsigned char *out,
                       size_t len, const AES_KEY *key1,
                       const AES_KEY *key2, const unsigned char iv[16]);
#endif
#ifdef AES_CTR_ASM
void AES_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                       size_t blocks, const AES_KEY *key,
                       const unsigned char ivec[AES_BLOCK_SIZE]);
#endif
#ifdef AES_XTS_ASM
void AES_xts_encrypt(const unsigned char *inp, unsigned char *out, size_t len,
                     const AES_KEY *key1, const AES_KEY *key2,
                     const unsigned char iv[16]);
void AES_xts_decrypt(const unsigned char *inp, unsigned char *out, size_t len,
                     const AES_KEY *key1, const AES_KEY *key2,
                     const unsigned char iv[16]);
#endif

#if defined(OPENSSL_CPUID_OBJ) && (defined(__powerpc__) || defined(__ppc__) || defined(_ARCH_PPC))
# include "ppc_arch.h"
# ifdef VPAES_ASM
#  define VPAES_CAPABLE (OPENSSL_ppccap_P & PPC_ALTIVEC)
# endif
# define HWAES_CAPABLE  (OPENSSL_ppccap_P & PPC_CRYPTO207)
# define HWAES_set_encrypt_key aes_p8_set_encrypt_key
# define HWAES_set_decrypt_key aes_p8_set_decrypt_key
# define HWAES_encrypt aes_p8_encrypt
# define HWAES_decrypt aes_p8_decrypt
# define HWAES_cbc_encrypt aes_p8_cbc_encrypt
# define HWAES_ctr32_encrypt_blocks aes_p8_ctr32_encrypt_blocks
# define HWAES_xts_encrypt aes_p8_xts_encrypt
# define HWAES_xts_decrypt aes_p8_xts_decrypt
#endif

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

int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
int aesni_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);

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
#  define AES_GCM_ASM(gctx)       (gctx->ctr==(ctr128_f)MEMSEP_CALL_SCT_BRIDGE(aesni_ctr32_encrypt_blocks) && \
                                 gctx->gcm.ghash==gcm_ghash_avx)
#  define AES_GCM_ASM2(gctx)      (gctx->gcm.block==(block128_f)MEMSEP_CALL_SCT_BRIDGE(aesni_encrypt) && \
                                 gctx->gcm.ghash==gcm_ghash_avx)
#  undef AES_GCM_ASM2          /* minor size optimization */
# endif

static int aesni_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                          const unsigned char *iv, int enc)
{
    /*
	 * MEMSEP get key allocation
	 */
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);
	int ret = 0, mode;

	/*
	 * TODO CALL TO MEMSEP ALLOC BRIDGE
	 */
	dat->ks = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	DBG_PRT("allocated %p len %d\n", dat->ks, ctx->key_len);
	if (dat->ks == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	prt_stack_trace(__FUNCTION__, dat);
	mode = EVP_CIPHER_CTX_mode(ctx);
	if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
		ret = MEMSEP_EXEC_SCT_BRIDGE(aesni_set_decrypt_key, key, EVP_CIPHER_CTX_key_length(ctx) * 8,
				dat->ks);
		dat->block = (block128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_decrypt);
		dat->stream.cbc =
		mode == EVP_CIPH_CBC_MODE ? (cbc128_f) aesni_cbc_encrypt : NULL;
	} else {
		ret = MEMSEP_EXEC_SCT_BRIDGE(aesni_set_encrypt_key, key, EVP_CIPHER_CTX_key_length(ctx) * 8,
				dat->ks);
		dat->block = (block128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_encrypt);
		if (mode == EVP_CIPH_CBC_MODE)
		dat->stream.cbc = (cbc128_f) aesni_cbc_encrypt;
		else if (mode == EVP_CIPH_CTR_MODE)
		dat->stream.ctr = (ctr128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_ctr32_encrypt_blocks);
		else
		dat->stream.cbc = NULL;
	}

    if (ret < 0) {
        EVPerr(EVP_F_AESNI_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

static int aesni_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t len)
{
	(void) MEMSEP_EXEC_SCT_BRIDGE(aesni_cbc_encrypt, in, out, len, EVP_C_DATA(EVP_AES_KEY,ctx)->ks,
			                      EVP_CIPHER_CTX_iv_noconst(ctx),
			                      EVP_CIPHER_CTX_encrypting(ctx));

    return 1;
}

static int aesni_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t len)
{
    size_t bl = EVP_CIPHER_CTX_block_size(ctx);

    if (len < bl)
        return 1;

    (void) MEMSEP_EXEC_SCT_BRIDGE(aesni_ecb_encrypt, in, out, len, EVP_C_DATA(EVP_AES_KEY,ctx)->ks,
    		                      EVP_CIPHER_CTX_encrypting(ctx));

    return 1;
}

# define aesni_ofb_cipher aes_ofb_cipher
static int aesni_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

# define aesni_cfb_cipher aes_cfb_cipher
static int aesni_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

# define aesni_cfb8_cipher aes_cfb8_cipher
static int aesni_cfb8_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aesni_cfb1_cipher aes_cfb1_cipher
static int aesni_cfb1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aesni_ctr_cipher aes_ctr_cipher
static int aesni_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

static int aesni_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                              const unsigned char *iv, int enc)
{
    EVP_AES_GCM_CTX *gctx = EVP_C_DATA(EVP_AES_GCM_CTX,ctx);

    prt_stack_trace(__FUNCTION__, gctx);
    if (!iv && !key)
        return 1;
    /*
	 * MEMSEP get key allocation
	 */
	gctx->ks = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	if (gctx->ks == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key) {
    	(void) MEMSEP_EXEC_SCT_BRIDGE(aesni_set_encrypt_key, key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                              gctx->ks);
        CRYPTO_gcm128_init(&gctx->gcm, gctx->ks, (block128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_encrypt));
        gctx->ctr = (ctr128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_ctr32_encrypt_blocks);
        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (gctx->key_set)
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }

    return 1;
}

# define aesni_gcm_cipher aes_gcm_cipher
static int aesni_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

static int aesni_xts_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                              const unsigned char *iv, int enc)
{
    EVP_AES_XTS_CTX *xctx = EVP_C_DATA(EVP_AES_XTS_CTX,ctx);

    prt_stack_trace(__FUNCTION__, xctx);
    if (!iv && !key)
        return 1;

    /*
	 * MEMSEP get key allocation
	 */
	xctx->ks1 = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	if (xctx->ks1 == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	/*
	 * MEMSEP get key allocation
	 */
	xctx->ks2 = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	if (xctx->ks2 == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key) {
        /* key_len is two AES keys */
        if (enc) {
        	(void) MEMSEP_EXEC_SCT_BRIDGE(aesni_set_encrypt_key, key, EVP_CIPHER_CTX_key_length(ctx) * 4,
                                  xctx->ks1);
            xctx->xts.block1 = (block128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_encrypt);
            xctx->stream = aesni_xts_encrypt;
        } else {
        	(void) MEMSEP_EXEC_SCT_BRIDGE(aesni_set_decrypt_key, key, EVP_CIPHER_CTX_key_length(ctx) * 4,
                                  xctx->ks1);
            xctx->xts.block1 = (block128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_decrypt);
            xctx->stream = aesni_xts_decrypt;
        }

        (void) MEMSEP_EXEC_SCT_BRIDGE(aesni_set_encrypt_key, key + EVP_CIPHER_CTX_key_length(ctx) / 2,
                              EVP_CIPHER_CTX_key_length(ctx) * 4,
                              xctx->ks2);
        xctx->xts.block2 = (block128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_encrypt);

        xctx->xts.key1 = xctx->ks1;
    }

    if (iv) {
        xctx->xts.key2 = xctx->ks2;
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 16);
    }

    return 1;
}

# define aesni_xts_cipher aes_xts_cipher
static int aesni_xts_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

static int aesni_ccm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                              const unsigned char *iv, int enc)
{
    EVP_AES_CCM_CTX *cctx = EVP_C_DATA(EVP_AES_CCM_CTX,ctx);

    prt_stack_trace(__FUNCTION__, cctx);
    if (!iv && !key)
        return 1;
    /*
	 * MEMSEP get key allocation
	 */
	cctx->ks = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	if (cctx->ks == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key) {
    	(void) MEMSEP_EXEC_SCT_BRIDGE(aesni_set_encrypt_key, key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                              cctx->ks);
        CRYPTO_ccm128_init(&cctx->ccm, cctx->M, cctx->L,
                           cctx->ks, (block128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_encrypt));
        cctx->str = enc ? (ccm128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_ccm64_encrypt_blocks) :
            (ccm128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_ccm64_decrypt_blocks);
        cctx->key_set = 1;
    }

    if (iv) {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 15 - cctx->L);
        cctx->iv_set = 1;
    }
    return 1;
}

# define aesni_ccm_cipher aes_ccm_cipher
static int aesni_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);

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

static int aesni_ocb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                              const unsigned char *iv, int enc)
{
    EVP_AES_OCB_CTX *octx = EVP_C_DATA(EVP_AES_OCB_CTX,ctx);

    prt_stack_trace(__FUNCTION__, octx);
    if (!iv && !key)
        return 1;

    if(key) {
		/*
		 * MEMSEP
		 */
//		return (int) MEMSEP_CALL_SCT(aesni_ocb_init_key, octx);
    	/*
		 * MEMSEP get key allocation
		 */
		octx->ksenc = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
		if (octx->ksenc == NULL ) {
			EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);

			return 0;
		}
		/*
		 * MEMSEP get key allocation
		 */
		octx->ksdec = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
		if (octx->ksdec == NULL ) {
			EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
			return 0;
		}

		do {
			/*
			 * We set both the encrypt and decrypt key here because decrypt
			 * needs both. We could possibly optimise to remove setting the
			 * decrypt for an encryption operation.
			 */
			(void) MEMSEP_EXEC_SCT_BRIDGE(aesni_set_encrypt_key, key, EVP_CIPHER_CTX_key_length(ctx) * 8,
					octx->ksenc);
			(void) MEMSEP_EXEC_SCT_BRIDGE(aesni_set_decrypt_key, key, EVP_CIPHER_CTX_key_length(ctx) * 8,
					octx->ksdec);
			if (!CRYPTO_ocb128_init(&octx->ocb, octx->ksenc, octx->ksdec,
							(block128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_encrypt),
							(block128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_decrypt),
							enc ? (ocb128_f) MEMSEP_CALL_SCT_BRIDGE(aesni_ocb_encrypt)
									: (ocb128_f)MEMSEP_CALL_SCT_BRIDGE(aesni_ocb_decrypt)))
			return 0;
		}while (0);

		/*
		 * If we have an iv we can set it directly, otherwise use saved IV.
		 */
		if (iv == NULL && octx->iv_set)
		iv = octx->iv;
		if (iv) {
			if (CRYPTO_ocb128_setiv(&octx->ocb, iv, octx->ivlen, octx->taglen)
					!= 1) {
				return 0;
			}
			octx->iv_set = 1;
		}
		octx->key_set = 1;

		return 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (octx->key_set)
            CRYPTO_ocb128_setiv(&octx->ocb, iv, octx->ivlen, octx->taglen);
        else
            memcpy(octx->iv, iv, octx->ivlen);
        octx->iv_set = 1;
    }

    return 1;
}

#  define aesni_ocb_cipher aes_ocb_cipher
static int aesni_ocb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t len);
# endif                        /* OPENSSL_NO_OCB */

# define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aesni_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aesni_init_key,                 \
        aesni_##mode##_cipher,          \
        aes_cleanup,                           \
        sizeof(EVP_AES_KEY),            \
        NULL,NULL,aes_ctrl,NULL }; \
static const EVP_CIPHER aes_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,     \
        keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_init_key,                   \
        aes_##mode##_cipher,            \
        aes_cleanup,                           \
        sizeof(EVP_AES_KEY),            \
        NULL,NULL,aes_ctrl,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return AESNI_CAPABLE?&aesni_##keylen##_##mode:&aes_##keylen##_##mode; }

# define BLOCK_CIPHER_custom(nid,keylen,blocksize,ivlen,mode,MODE,flags) \
static const EVP_CIPHER aesni_##keylen##_##mode = { \
        nid##_##keylen##_##mode,blocksize, \
        (EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aesni_##mode##_init_key,        \
        aesni_##mode##_cipher,          \
        aes_##mode##_cleanup,           \
        sizeof(EVP_AES_##MODE##_CTX),   \
        NULL,NULL,aes_##mode##_ctrl,NULL }; \
static const EVP_CIPHER aes_##keylen##_##mode = { \
        nid##_##keylen##_##mode,blocksize, \
        (EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_##mode##_init_key,          \
        aes_##mode##_cipher,            \
        aes_##mode##_cleanup,           \
        sizeof(EVP_AES_##MODE##_CTX),   \
        NULL,NULL,aes_##mode##_ctrl,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return AESNI_CAPABLE?&aesni_##keylen##_##mode:&aes_##keylen##_##mode; }

#elif   defined(AES_ASM) && (defined(__sparc) || defined(__sparc__))

# include "sparc_arch.h"

extern unsigned int OPENSSL_sparcv9cap_P[];

/*
 * Initial Fujitsu SPARC64 X support
 */
# define HWAES_CAPABLE           (OPENSSL_sparcv9cap_P[0] & SPARCV9_FJAESX)
# define HWAES_set_encrypt_key aes_fx_set_encrypt_key
# define HWAES_set_decrypt_key aes_fx_set_decrypt_key
# define HWAES_encrypt aes_fx_encrypt
# define HWAES_decrypt aes_fx_decrypt
# define HWAES_cbc_encrypt aes_fx_cbc_encrypt
# define HWAES_ctr32_encrypt_blocks aes_fx_ctr32_encrypt_blocks

# define SPARC_AES_CAPABLE       (OPENSSL_sparcv9cap_P[1] & CFR_AES)

void aes_t4_set_encrypt_key(const unsigned char *key, int bits, AES_KEY *ks);
void aes_t4_set_decrypt_key(const unsigned char *key, int bits, AES_KEY *ks);
void aes_t4_encrypt(const unsigned char *in, unsigned char *out,
                    const AES_KEY *key);
void aes_t4_decrypt(const unsigned char *in, unsigned char *out,
                    const AES_KEY *key);
/*
 * Key-length specific subroutines were chosen for following reason.
 * Each SPARC T4 core can execute up to 8 threads which share core's
 * resources. Loading as much key material to registers allows to
 * minimize references to shared memory interface, as well as amount
 * of instructions in inner loops [much needed on T4]. But then having
 * non-key-length specific routines would require conditional branches
 * either in inner loops or on subroutines' entries. Former is hardly
 * acceptable, while latter means code size increase to size occupied
 * by multiple key-length specific subroutines, so why fight?
 */
void aes128_t4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec);
void aes128_t4_cbc_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec);
void aes192_t4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec);
void aes192_t4_cbc_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec);
void aes256_t4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec);
void aes256_t4_cbc_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec);
void aes128_t4_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                             size_t blocks, const AES_KEY *key,
                             unsigned char *ivec);
void aes192_t4_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                             size_t blocks, const AES_KEY *key,
                             unsigned char *ivec);
void aes256_t4_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                             size_t blocks, const AES_KEY *key,
                             unsigned char *ivec);
void aes128_t4_xts_encrypt(const unsigned char *in, unsigned char *out,
                           size_t blocks, const AES_KEY *key1,
                           const AES_KEY *key2, const unsigned char *ivec);
void aes128_t4_xts_decrypt(const unsigned char *in, unsigned char *out,
                           size_t blocks, const AES_KEY *key1,
                           const AES_KEY *key2, const unsigned char *ivec);
void aes256_t4_xts_encrypt(const unsigned char *in, unsigned char *out,
                           size_t blocks, const AES_KEY *key1,
                           const AES_KEY *key2, const unsigned char *ivec);
void aes256_t4_xts_decrypt(const unsigned char *in, unsigned char *out,
                           size_t blocks, const AES_KEY *key1,
                           const AES_KEY *key2, const unsigned char *ivec);

static int aes_t4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc)
{
    int ret, mode, bits;
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    /*
	 * MEMSEP get key allocation
	 */
	dat->ks = OPENSSL_zalloc(sizeof(AES_KEY));
	if (dat->ks == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    mode = EVP_CIPHER_CTX_mode(ctx);
    bits = EVP_CIPHER_CTX_key_length(ctx) * 8;
    if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE)
        && !enc) {
        ret = 0;
        aes_t4_set_decrypt_key(key, bits, dat->ks);
        dat->block = (block128_f) aes_t4_decrypt;
        switch (bits) {
        case 128:
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) aes128_t4_cbc_decrypt : NULL;
            break;
        case 192:
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) aes192_t4_cbc_decrypt : NULL;
            break;
        case 256:
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) aes256_t4_cbc_decrypt : NULL;
            break;
        default:
            ret = -1;
        }
    } else {
        ret = 0;
        aes_t4_set_encrypt_key(key, bits, dat->ks);
        dat->block = (block128_f) aes_t4_encrypt;
        switch (bits) {
        case 128:
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) aes128_t4_cbc_encrypt;
            else if (mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f) aes128_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        case 192:
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) aes192_t4_cbc_encrypt;
            else if (mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f) aes192_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        case 256:
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) aes256_t4_cbc_encrypt;
            else if (mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f) aes256_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        default:
            ret = -1;
        }
    }

    if (ret < 0) {
        EVPerr(EVP_F_AES_T4_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

# define aes_t4_cbc_cipher aes_cbc_cipher
static int aes_t4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_ecb_cipher aes_ecb_cipher
static int aes_t4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_ofb_cipher aes_ofb_cipher
static int aes_t4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_cfb_cipher aes_cfb_cipher
static int aes_t4_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# define aes_t4_cfb8_cipher aes_cfb8_cipher
static int aes_t4_cfb8_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

# define aes_t4_cfb1_cipher aes_cfb1_cipher
static int aes_t4_cfb1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

# define aes_t4_ctr_cipher aes_ctr_cipher
static int aes_t4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

static int aes_t4_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                               const unsigned char *iv, int enc)
{
    EVP_AES_GCM_CTX *gctx = EVP_C_DATA(EVP_AES_GCM_CTX,ctx);
    if (!iv && !key)
        return 1;

    /*
	 * MEMSEP get key allocation
	 */
	gctx->ks = OPENSSL_zalloc(sizeof(AES_KEY));
	if (gctx->ks == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key) {
        int bits = EVP_CIPHER_CTX_key_length(ctx) * 8;
        aes_t4_set_encrypt_key(key, bits, gctx->ks);
        CRYPTO_gcm128_init(&gctx->gcm, gctx->ks,
                           (block128_f) aes_t4_encrypt);
        switch (bits) {
        case 128:
            gctx->ctr = (ctr128_f) aes128_t4_ctr32_encrypt;
            break;
        case 192:
            gctx->ctr = (ctr128_f) aes192_t4_ctr32_encrypt;
            break;
        case 256:
            gctx->ctr = (ctr128_f) aes256_t4_ctr32_encrypt;
            break;
        default:
            return 0;
        }
        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (gctx->key_set)
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
}

# define aes_t4_gcm_cipher aes_gcm_cipher
static int aes_t4_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

static int aes_t4_xts_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                               const unsigned char *iv, int enc)
{
    EVP_AES_XTS_CTX *xctx = EVP_C_DATA(EVP_AES_XTS_CTX,ctx);
    if (!iv && !key)
        return 1;

    /*
	 * MEMSEP get key allocation
	 */
	xctx->ks1 = OPENSSL_zalloc(sizeof(AES_KEY));
	if (xctx->ks1 == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	/*
	 * MEMSEP get key allocation
	 */
	xctx->ks2 = OPENSSL_zalloc(sizeof(AES_KEY));
	if (xctx->ks2 == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key) {
        int bits = EVP_CIPHER_CTX_key_length(ctx) * 4;
        xctx->stream = NULL;
        /* key_len is two AES keys */
        if (enc) {
            aes_t4_set_encrypt_key(key, bits, xctx->ks1);
            xctx->xts.block1 = (block128_f) aes_t4_encrypt;
            switch (bits) {
            case 128:
                xctx->stream = aes128_t4_xts_encrypt;
                break;
            case 256:
                xctx->stream = aes256_t4_xts_encrypt;
                break;
            default:
                return 0;
            }
        } else {
            aes_t4_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 4,
                                   xctx->ks1);
            xctx->xts.block1 = (block128_f) aes_t4_decrypt;
            switch (bits) {
            case 128:
                xctx->stream = aes128_t4_xts_decrypt;
                break;
            case 256:
                xctx->stream = aes256_t4_xts_decrypt;
                break;
            default:
                return 0;
            }
        }

        aes_t4_set_encrypt_key(key + EVP_CIPHER_CTX_key_length(ctx) / 2,
                               EVP_CIPHER_CTX_key_length(ctx) * 4,
                               xctx->ks2);
        xctx->xts.block2 = (block128_f) aes_t4_encrypt;

        xctx->xts.key1 = &xctx->ks1;
    }

    if (iv) {
        xctx->xts.key2 = xctx->ks2;
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 16);
    }

    return 1;
}

# define aes_t4_xts_cipher aes_xts_cipher
static int aes_t4_xts_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

static int aes_t4_ccm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                               const unsigned char *iv, int enc)
{
    EVP_AES_CCM_CTX *cctx = EVP_C_DATA(EVP_AES_CCM_CTX,ctx);
    if (!iv && !key)
        return 1;

    /*
	 * MEMSEP get key allocation
	 */
	cctx->ks = OPENSSL_zalloc(sizeof(AES_KEY));
	if (cctx->ks == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key) {
        int bits = EVP_CIPHER_CTX_key_length(ctx) * 8;
        aes_t4_set_encrypt_key(key, bits, cctx->ks);
        CRYPTO_ccm128_init(&cctx->ccm, cctx->M, cctx->L,
                           cctx->ks, (block128_f) aes_t4_encrypt);
        cctx->str = NULL;
        cctx->key_set = 1;
    }
    if (iv) {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 15 - cctx->L);
        cctx->iv_set = 1;
    }
    return 1;
}

# define aes_t4_ccm_cipher aes_ccm_cipher
static int aes_t4_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);

# ifndef OPENSSL_NO_OCB
static int aes_t4_ocb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                               const unsigned char *iv, int enc)
{
    EVP_AES_OCB_CTX *octx = EVP_C_DATA(EVP_AES_OCB_CTX,ctx);
    if (!iv && !key)
        return 1;

    /*
	 * MEMSEP get key allocation
	 */
	octx->ksenc = OPENSSL_zalloc(sizeof(AES_KEY));
	if (octx->ksenc == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	/*
	 * MEMSEP get key allocation
	 */
	octx->ksdec = OPENSSL_zalloc(sizeof(AES_KEY));
	if (octx->ksdec == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key) {
        do {
            /*
             * We set both the encrypt and decrypt key here because decrypt
             * needs both. We could possibly optimise to remove setting the
             * decrypt for an encryption operation.
             */
            aes_t4_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                   octx->ksenc);
            aes_t4_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                   octx->ksdec);
            if (!CRYPTO_ocb128_init(&octx->ocb,
                                    octx->ksenc, octx->ksdec,
                                    (block128_f) aes_t4_encrypt,
                                    (block128_f) aes_t4_decrypt,
                                    NULL))
                return 0;
        }
        while (0);

        /*
         * If we have an iv we can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && octx->iv_set)
            iv = octx->iv;
        if (iv) {
            if (CRYPTO_ocb128_setiv(&octx->ocb, iv, octx->ivlen, octx->taglen)
                != 1)
                return 0;
            octx->iv_set = 1;
        }
        octx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (octx->key_set)
            CRYPTO_ocb128_setiv(&octx->ocb, iv, octx->ivlen, octx->taglen);
        else
            memcpy(octx->iv, iv, octx->ivlen);
        octx->iv_set = 1;
    }
    return 1;
}

#  define aes_t4_ocb_cipher aes_ocb_cipher
static int aes_t4_ocb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t len);
# endif                        /* OPENSSL_NO_OCB */

# define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aes_t4_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_t4_init_key,                \
        aes_t4_##mode##_cipher,         \
        aes_cleanup,                           \
        sizeof(EVP_AES_KEY),            \
        NULL,NULL,aes_ctrl,NULL }; \
static const EVP_CIPHER aes_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,     \
        keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_init_key,                   \
        aes_##mode##_cipher,            \
        aes_cleanup,                           \
        sizeof(EVP_AES_KEY),            \
        NULL,NULL,aes_ctrl,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return SPARC_AES_CAPABLE?&aes_t4_##keylen##_##mode:&aes_##keylen##_##mode; }

# define BLOCK_CIPHER_custom(nid,keylen,blocksize,ivlen,mode,MODE,flags) \
static const EVP_CIPHER aes_t4_##keylen##_##mode = { \
        nid##_##keylen##_##mode,blocksize, \
        (EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_t4_##mode##_init_key,       \
        aes_t4_##mode##_cipher,         \
        aes_##mode##_cleanup,           \
        sizeof(EVP_AES_##MODE##_CTX),   \
        NULL,NULL,aes_##mode##_ctrl,NULL }; \
static const EVP_CIPHER aes_##keylen##_##mode = { \
        nid##_##keylen##_##mode,blocksize, \
        (EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_##mode##_init_key,          \
        aes_##mode##_cipher,            \
        aes_##mode##_cleanup,           \
        sizeof(EVP_AES_##MODE##_CTX),   \
        NULL,NULL,aes_##mode##_ctrl,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return SPARC_AES_CAPABLE?&aes_t4_##keylen##_##mode:&aes_##keylen##_##mode; }

#else

# define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aes_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_init_key,                   \
        aes_##mode##_cipher,            \
        aes_cleanup,                           \
        sizeof(EVP_AES_KEY),            \
        NULL,NULL,aes_ctrl,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return &aes_##keylen##_##mode; }

# define BLOCK_CIPHER_custom(nid,keylen,blocksize,ivlen,mode,MODE,flags) \
static const EVP_CIPHER aes_##keylen##_##mode = { \
        nid##_##keylen##_##mode,blocksize, \
        (EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_##mode##_init_key,          \
        aes_##mode##_cipher,            \
        aes_##mode##_cleanup,           \
        sizeof(EVP_AES_##MODE##_CTX),   \
        NULL,NULL,aes_##mode##_ctrl,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return &aes_##keylen##_##mode; }

#endif

#if defined(OPENSSL_CPUID_OBJ) && (defined(__arm__) || defined(__arm) || defined(__aarch64__))
# include "arm_arch.h"
# if __ARM_MAX_ARCH__>=7
#  if defined(BSAES_ASM)
#   define BSAES_CAPABLE (OPENSSL_armcap_P & ARMV7_NEON)
#  endif
#  if defined(VPAES_ASM)
#   define VPAES_CAPABLE (OPENSSL_armcap_P & ARMV7_NEON)
#  endif
#  define HWAES_CAPABLE (OPENSSL_armcap_P & ARMV8_AES)
#  define HWAES_set_encrypt_key aes_v8_set_encrypt_key
#  define HWAES_set_decrypt_key aes_v8_set_decrypt_key
#  define HWAES_encrypt aes_v8_encrypt
#  define HWAES_decrypt aes_v8_decrypt
#  define HWAES_cbc_encrypt aes_v8_cbc_encrypt
#  define HWAES_ctr32_encrypt_blocks aes_v8_ctr32_encrypt_blocks
# endif
#endif

#if defined(HWAES_CAPABLE)
int HWAES_set_encrypt_key(const unsigned char *userKey, const int bits,
                          AES_KEY *key);
int HWAES_set_decrypt_key(const unsigned char *userKey, const int bits,
                          AES_KEY *key);
void HWAES_encrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void HWAES_decrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void HWAES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const AES_KEY *key,
                       unsigned char *ivec, const int enc);
void HWAES_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t len, const AES_KEY *key,
                                const unsigned char ivec[16]);
void HWAES_xts_encrypt(const unsigned char *inp, unsigned char *out,
                       size_t len, const AES_KEY *key1,
                       const AES_KEY *key2, const unsigned char iv[16]);
void HWAES_xts_decrypt(const unsigned char *inp, unsigned char *out,
                       size_t len, const AES_KEY *key1,
                       const AES_KEY *key2, const unsigned char iv[16]);
#endif

#define BLOCK_CIPHER_generic_pack(nid,keylen,flags)             \
        BLOCK_CIPHER_generic(nid,keylen,16,16,cbc,cbc,CBC,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)     \
        BLOCK_CIPHER_generic(nid,keylen,16,0,ecb,ecb,ECB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)      \
        BLOCK_CIPHER_generic(nid,keylen,1,16,ofb128,ofb,OFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)   \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb128,cfb,CFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)   \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb1,cfb1,CFB,flags)       \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb8,cfb8,CFB,flags)       \
        BLOCK_CIPHER_generic(nid,keylen,1,16,ctr,ctr,CTR,flags)

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    int ret, mode;
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    prt_stack_trace(__FUNCTION__, dat);
    /*
     * MEMSEP get key allocation
     */
    dat->ks = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
    if (dat->ks == NULL) {
    	EVPerr(EVP_F_AES_INIT_KEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    mode = EVP_CIPHER_CTX_mode(ctx);
    if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE)
        && !enc) {
#ifdef HWAES_CAPABLE
        if (HWAES_CAPABLE) {
            ret = HWAES_set_decrypt_key(key,
                                        EVP_CIPHER_CTX_key_length(ctx) * 8,
                                        dat->ks);
            dat->block = (block128_f) HWAES_decrypt;
            dat->stream.cbc = NULL;
# ifdef HWAES_cbc_encrypt
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) HWAES_cbc_encrypt;
# endif
        } else
#endif
#ifdef BSAES_CAPABLE
        if (BSAES_CAPABLE && mode == EVP_CIPH_CBC_MODE) {
            ret = AES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      dat->ks);
            dat->block = (block128_f) AES_decrypt;
            dat->stream.cbc = (cbc128_f) bsaes_cbc_encrypt;
        } else
#endif
#ifdef VPAES_CAPABLE
        if (VPAES_CAPABLE) {
            ret = vpaes_set_decrypt_key(key,
                                        EVP_CIPHER_CTX_key_length(ctx) * 8,
                                        dat->ks);
            dat->block = (block128_f) vpaes_decrypt;
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) vpaes_cbc_encrypt : NULL;
        } else
#endif
        {
            ret = AES_set_decrypt_key(key,
                                      EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      dat->ks);
            dat->block = (block128_f) AES_decrypt;
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) AES_cbc_encrypt : NULL;
        }
    } else
#ifdef HWAES_CAPABLE
    if (HWAES_CAPABLE) {
        ret = HWAES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                    dat->ks);
        dat->block = (block128_f) HWAES_encrypt;
        dat->stream.cbc = NULL;
# ifdef HWAES_cbc_encrypt
        if (mode == EVP_CIPH_CBC_MODE)
            dat->stream.cbc = (cbc128_f) HWAES_cbc_encrypt;
        else
# endif
# ifdef HWAES_ctr32_encrypt_blocks
        if (mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f) HWAES_ctr32_encrypt_blocks;
        else
# endif
            (void)0;            /* terminate potentially open 'else' */
    } else
#endif
#ifdef BSAES_CAPABLE
    if (BSAES_CAPABLE && mode == EVP_CIPH_CTR_MODE) {
        ret = AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                  dat->ks);
        dat->block = (block128_f) AES_encrypt;
        dat->stream.ctr = (ctr128_f) bsaes_ctr32_encrypt_blocks;
    } else
#endif
#ifdef VPAES_CAPABLE
    if (VPAES_CAPABLE) {
        ret = vpaes_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                   dat->ks);
        dat->block = (block128_f) vpaes_encrypt;
        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) vpaes_cbc_encrypt : NULL;
    } else
#endif
    {
        ret = AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                  dat->ks);
        dat->block = (block128_f) AES_encrypt;
        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) AES_cbc_encrypt : NULL;
#ifdef AES_CTR_ASM
        if (mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f) AES_ctr32_encrypt;
#endif
    }

    if (ret < 0) {
        EVPerr(EVP_F_AES_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

static int aes_cleanup(EVP_CIPHER_CTX * ctx) {
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    if(dat->ks != NULL) {
    	DBG_PRT("freeing %p\n", dat->ks);
    	(void) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_free, dat->ks, __FILE__, __LINE__);
    	dat->ks = NULL;
    }

	return 1;
}

static int aes_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
	EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,c);
    switch (type) {

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_AES_KEY *dat_out = EVP_C_DATA(EVP_AES_KEY,out);
            if (dat->ks) {
                /* Memsep allocate new key */
                dat_out->ks = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
                if(dat_out->ks == NULL) {
                	return 0;
                }
                memcpy(dat_out->ks, dat->ks, sizeof(AES_KEY));
            }
            return 1;
        }

    default:
        return 1;

    }
}

static int aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    if (dat->stream.cbc)
        (*dat->stream.cbc) (in, out, len, dat->ks,
                            EVP_CIPHER_CTX_iv_noconst(ctx),
                            EVP_CIPHER_CTX_encrypting(ctx));
    else if (EVP_CIPHER_CTX_encrypting(ctx))
        CRYPTO_cbc128_encrypt(in, out, len, dat->ks,
                              EVP_CIPHER_CTX_iv_noconst(ctx), dat->block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, dat->ks,
                              EVP_CIPHER_CTX_iv_noconst(ctx), dat->block);

    return 1;
}

static int aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    size_t bl = EVP_CIPHER_CTX_block_size(ctx);
    size_t i;
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    if (len < bl)
        return 1;

    for (i = 0, len -= bl; i <= len; i += bl)
        (*dat->block) (in + i, out + i, dat->ks);

    return 1;
}

static int aes_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    int num = EVP_CIPHER_CTX_num(ctx);
    CRYPTO_ofb128_encrypt(in, out, len, dat->ks,
                          EVP_CIPHER_CTX_iv_noconst(ctx), &num, dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static int aes_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    int num = EVP_CIPHER_CTX_num(ctx);
    CRYPTO_cfb128_encrypt(in, out, len, dat->ks,
                          EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                          EVP_CIPHER_CTX_encrypting(ctx), dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static int aes_cfb8_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    int num = EVP_CIPHER_CTX_num(ctx);
    CRYPTO_cfb128_8_encrypt(in, out, len, dat->ks,
                            EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                            EVP_CIPHER_CTX_encrypting(ctx), dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static int aes_cfb1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    if (EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS)) {
        int num = EVP_CIPHER_CTX_num(ctx);
        CRYPTO_cfb128_1_encrypt(in, out, len, dat->ks,
                                EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                                EVP_CIPHER_CTX_encrypting(ctx), dat->block);
        EVP_CIPHER_CTX_set_num(ctx, num);
        return 1;
    }

    while (len >= MAXBITCHUNK) {
        int num = EVP_CIPHER_CTX_num(ctx);
        CRYPTO_cfb128_1_encrypt(in, out, MAXBITCHUNK * 8, dat->ks,
                                EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                                EVP_CIPHER_CTX_encrypting(ctx), dat->block);
        EVP_CIPHER_CTX_set_num(ctx, num);
        len -= MAXBITCHUNK;
    }
    if (len) {
        int num = EVP_CIPHER_CTX_num(ctx);
        CRYPTO_cfb128_1_encrypt(in, out, len * 8, dat->ks,
                                EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                                EVP_CIPHER_CTX_encrypting(ctx), dat->block);
        EVP_CIPHER_CTX_set_num(ctx, num);
    }

    return 1;
}

static int aes_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    unsigned int num = EVP_CIPHER_CTX_num(ctx);
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    if (dat->stream.ctr)
        CRYPTO_ctr128_encrypt_ctr32(in, out, len, dat->ks,
                                    EVP_CIPHER_CTX_iv_noconst(ctx),
                                    EVP_CIPHER_CTX_buf_noconst(ctx),
                                    &num, dat->stream.ctr);
    else
        CRYPTO_ctr128_encrypt(in, out, len, dat->ks,
                              EVP_CIPHER_CTX_iv_noconst(ctx),
                              EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                              dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

BLOCK_CIPHER_generic_pack(NID_aes, 128, 0)
    BLOCK_CIPHER_generic_pack(NID_aes, 192, 0)
    BLOCK_CIPHER_generic_pack(NID_aes, 256, 0)

static int aes_gcm_cleanup(EVP_CIPHER_CTX *c)
{
    EVP_AES_GCM_CTX *gctx = EVP_C_DATA(EVP_AES_GCM_CTX,c);
    if (gctx == NULL)
        return 0;
    if(gctx->ks != NULL) {
    	(void) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_free, gctx->ks, __FILE__, __LINE__);
    	gctx->ks = NULL;
    }
    OPENSSL_cleanse(&gctx->gcm, sizeof(gctx->gcm));
    if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(c))
        OPENSSL_free(gctx->iv);
    return 1;
}

/* increment counter (64-bit int) by 1 */
static void ctr64_inc(unsigned char *counter)
{
    int n = 8;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

static int aes_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_AES_GCM_CTX *gctx = EVP_C_DATA(EVP_AES_GCM_CTX,c);
    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_CTX_iv_length(c);
        gctx->iv = EVP_CIPHER_CTX_iv_noconst(c);
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        gctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;
        /* Allocate memory for IV if needed */
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(c))
            	(void) OPENSSL_free(gctx->iv);
            gctx->iv = OPENSSL_malloc(arg);
            if (gctx->iv == NULL)
                return 0;
        }
        gctx->ivlen = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(c))
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        gctx->taglen = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(c)
            || gctx->taglen < 0)
            return 0;
        memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(c), arg);
        return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
        /* Special case: -1 length restores whole IV */
        if (arg == -1) {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
        }
        /*
         * Fixed field must be at least 4 bytes and invocation field at least
         * 8.
         */
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (EVP_CIPHER_CTX_encrypting(c)
            && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;

    case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        /*
         * Invocation field will be at least 8 bytes in size and so no need
         * to check wrap around or increment more than last 8 bytes.
         */
        ctr64_inc(gctx->iv + gctx->ivlen - 8);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0
            || EVP_CIPHER_CTX_encrypting(c))
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        gctx->tls_aad_len = arg;
        {
            unsigned int len =
                EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8
                | EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
            /* Correct length for explicit IV */
            if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
                return 0;
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!EVP_CIPHER_CTX_encrypting(c)) {
                if (len < EVP_GCM_TLS_TAG_LEN)
                    return 0;
                len -= EVP_GCM_TLS_TAG_LEN;
            }
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
        }
        /* Extra padding: tag appended to record */
        return EVP_GCM_TLS_TAG_LEN;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_AES_GCM_CTX *gctx_out = EVP_C_DATA(EVP_AES_GCM_CTX,out);
            if (gctx->gcm.key) {
                if (gctx->gcm.key != gctx->ks)
                    return 0;
                /* Memsep allocate new key */
                gctx_out->ks = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);;
                if(gctx_out->ks == NULL) {
                	return 0;
                }
                memcpy(gctx_out->ks, gctx->ks, sizeof(AES_KEY));
                gctx_out->gcm.key = gctx_out->ks;
            }
            if (gctx->iv == EVP_CIPHER_CTX_iv_noconst(c))
                gctx_out->iv = EVP_CIPHER_CTX_iv_noconst(out);
            else {
                gctx_out->iv = OPENSSL_malloc(gctx->ivlen);
                if (gctx_out->iv == NULL)
                    return 0;
                memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
            }
            return 1;
        }

    default:
        return -1;

    }
}


static int aes_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    EVP_AES_GCM_CTX *gctx = EVP_C_DATA(EVP_AES_GCM_CTX,ctx);
    prt_stack_trace(__FUNCTION__, gctx);
    if (!iv && !key)
        return 1;

    /*
	 * MEMSEP get key allocation
	 */
	gctx->ks = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);;
	if (gctx->ks == NULL ) {
		EVPerr(EVP_F_AES_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key) {
        do {
#ifdef HWAES_CAPABLE
            if (HWAES_CAPABLE) {
                HWAES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      gctx->ks);
                CRYPTO_gcm128_init(gctx->gcm, gctx->ks,
                                   (block128_f) HWAES_encrypt);
# ifdef HWAES_ctr32_encrypt_blocks
                gctx->ctr = (ctr128_f) HWAES_ctr32_encrypt_blocks;
# else
                gctx->ctr = NULL;
# endif
                break;
            } else
#endif
#ifdef BSAES_CAPABLE
            if (BSAES_CAPABLE) {
                AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                    gctx->ks);
                CRYPTO_gcm128_init(&gctx->gcm, gctx->ks,
                                   (block128_f) AES_encrypt);
                gctx->ctr = (ctr128_f) bsaes_ctr32_encrypt_blocks;
                break;
            } else
#endif
#ifdef VPAES_CAPABLE
            if (VPAES_CAPABLE) {
                vpaes_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      gctx->ks);
                CRYPTO_gcm128_init(&gctx->gcm, gctx->ks,
                                   (block128_f) vpaes_encrypt);
                gctx->ctr = NULL;
                break;
            } else
#endif
                (void)0;        /* terminate potentially open 'else' */

            AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                gctx->ks);
            CRYPTO_gcm128_init(&gctx->gcm, gctx->ks,
                               (block128_f) AES_encrypt);
#ifdef AES_CTR_ASM
            gctx->ctr = (ctr128_f) AES_ctr32_encrypt;
#else
            gctx->ctr = NULL;
#endif
        } while (0);

        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (gctx->key_set)
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
}

/*
 * Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */

static int aes_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    EVP_AES_GCM_CTX *gctx = EVP_C_DATA(EVP_AES_GCM_CTX,ctx);
    int rv = -1;
    /* Encrypt/decrypt must be performed in place */
    if (out != in
        || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        return -1;
    /*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CIPHER_CTX_encrypting(ctx) ?
                            EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
        goto err;
    /* Use saved AAD */
    if (CRYPTO_gcm128_aad(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx),
                          gctx->tls_aad_len))
        goto err;
    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        /* Encrypt payload */
        if (gctx->ctr) {
            size_t bulk = 0;
#if defined(AES_GCM_ASM)
            if (len >= 32 && AES_GCM_ASM(gctx)) {
                if (CRYPTO_gcm128_encrypt(&gctx->gcm, NULL, NULL, 0))
                    return -1;

                bulk = AES_gcm_encrypt(in, out, len,
                                       gctx->gcm.key,
                                       gctx->gcm.Yi.c, gctx->gcm.Xi.u);
                gctx->gcm.len.u[1] += bulk;
            }
#endif
            if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
#if defined(AES_GCM_ASM2)
            if (len >= 32 && AES_GCM_ASM2(gctx)) {
                if (CRYPTO_gcm128_encrypt(&gctx->gcm, NULL, NULL, 0))
                    return -1;

                bulk = AES_gcm_encrypt(in, out, len,
                                       gctx->gcm.key,
                                       gctx->gcm.Yi.c, gctx->gcm.Xi.u);
                gctx->gcm.len.u[1] += bulk;
            }
#endif
            if (CRYPTO_gcm128_encrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        out += len;
        /* Finally write tag */
        CRYPTO_gcm128_tag(&gctx->gcm, out, EVP_GCM_TLS_TAG_LEN);
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    } else {
        /* Decrypt */
        if (gctx->ctr) {
            size_t bulk = 0;
#if defined(AES_GCM_ASM)
            if (len >= 16 && AES_GCM_ASM(gctx)) {
                if (CRYPTO_gcm128_decrypt(&gctx->gcm, NULL, NULL, 0))
                    return -1;

                bulk = AES_gcm_decrypt(in, out, len,
                                       gctx->gcm.key,
                                       gctx->gcm.Yi.c, gctx->gcm.Xi.u);
                gctx->gcm.len.u[1] += bulk;
            }
#endif
            if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
#if defined(AES_GCM_ASM2)
            if (len >= 16 && AES_GCM_ASM2(gctx)) {
                if (CRYPTO_gcm128_decrypt(&gctx->gcm, NULL, NULL, 0))
                    return -1;

                bulk = AES_gcm_decrypt(in, out, len,
                                       gctx->gcm.key,
                                       gctx->gcm.Yi.c, gctx->gcm.Xi.u);
                gctx->gcm.len.u[1] += bulk;
            }
#endif
            if (CRYPTO_gcm128_decrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        /* Retrieve tag */
        CRYPTO_gcm128_tag(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx),
                          EVP_GCM_TLS_TAG_LEN);
        /* If tag mismatch wipe buffer */
        if (CRYPTO_memcmp(EVP_CIPHER_CTX_buf_noconst(ctx), in + len,
                          EVP_GCM_TLS_TAG_LEN)) {
            OPENSSL_cleanse(out, len);
            goto err;
        }
        rv = len;
    }

 err:
    gctx->iv_set = 0;
    gctx->tls_aad_len = -1;
    return rv;
}

static int aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_AES_GCM_CTX *gctx = EVP_C_DATA(EVP_AES_GCM_CTX,ctx);
    /* If not set up, return error */
    if (!gctx->key_set)
        return -1;

    if (gctx->tls_aad_len >= 0)
        return aes_gcm_tls_cipher(ctx, out, in, len);

    if (!gctx->iv_set)
        return -1;
    if (in) {
        if (out == NULL) {
            if (CRYPTO_gcm128_aad(&gctx->gcm, in, len))
                return -1;
        } else if (EVP_CIPHER_CTX_encrypting(ctx)) {
            if (gctx->ctr) {
                size_t bulk = 0;
#if defined(AES_GCM_ASM)
                if (len >= 32 && AES_GCM_ASM(gctx)) {
                    size_t res = (16 - gctx->gcm.mres) % 16;

                    if (CRYPTO_gcm128_encrypt(&gctx->gcm, in, out, res))
                        return -1;

                    bulk = AES_gcm_encrypt(in + res,
                                           out + res, len - res,
                                           gctx->gcm.key, gctx->gcm.Yi.c,
                                           gctx->gcm.Xi.u);
                    gctx->gcm.len.u[1] += bulk;
                    bulk += res;
                }
#endif
                if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
                                                in + bulk,
                                                out + bulk,
                                                len - bulk, gctx->ctr))
                    return -1;
            } else {
                size_t bulk = 0;
#if defined(AES_GCM_ASM2)
                if (len >= 32 && AES_GCM_ASM2(gctx)) {
                    size_t res = (16 - gctx->gcm.mres) % 16;

                    if (CRYPTO_gcm128_encrypt(&gctx->gcm, in, out, res))
                        return -1;

                    bulk = AES_gcm_encrypt(in + res,
                                           out + res, len - res,
                                           gctx->gcm.key, gctx->gcm.Yi.c,
                                           gctx->gcm.Xi.u);
                    gctx->gcm.len.u[1] += bulk;
                    bulk += res;
                }
#endif
                if (CRYPTO_gcm128_encrypt(&gctx->gcm,
                                          in + bulk, out + bulk, len - bulk))
                    return -1;
            }
        } else {
            if (gctx->ctr) {
                size_t bulk = 0;
#if defined(AES_GCM_ASM)
                if (len >= 16 && AES_GCM_ASM(gctx)) {
                    size_t res = (16 - gctx->gcm.mres) % 16;

                    if (CRYPTO_gcm128_decrypt(&gctx->gcm, in, out, res))
                        return -1;

                    bulk = AES_gcm_decrypt(in + res,
                                           out + res, len - res,
                                           gctx->gcm.key,
                                           gctx->gcm.Yi.c, gctx->gcm.Xi.u);
                    gctx->gcm.len.u[1] += bulk;
                    bulk += res;
                }
#endif
                if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
                                                in + bulk,
                                                out + bulk,
                                                len - bulk, gctx->ctr))
                    return -1;
            } else {
                size_t bulk = 0;
#if defined(AES_GCM_ASM2)
                if (len >= 16 && AES_GCM_ASM2(gctx)) {
                    size_t res = (16 - gctx->gcm.mres) % 16;

                    if (CRYPTO_gcm128_decrypt(&gctx->gcm, in, out, res))
                        return -1;

                    bulk = AES_gcm_decrypt(in + res,
                                           out + res, len - res,
                                           gctx->gcm.key,
                                           gctx->gcm.Yi.c, gctx->gcm.Xi.u);
                    gctx->gcm.len.u[1] += bulk;
                    bulk += res;
                }
#endif
                if (CRYPTO_gcm128_decrypt(&gctx->gcm,
                                          in + bulk, out + bulk, len - bulk))
                    return -1;
            }
        }
        return len;
    } else {
        if (!EVP_CIPHER_CTX_encrypting(ctx)) {
            if (gctx->taglen < 0)
                return -1;
            if (CRYPTO_gcm128_finish(&gctx->gcm,
                                     EVP_CIPHER_CTX_buf_noconst(ctx),
                                     gctx->taglen) != 0)
                return -1;
            gctx->iv_set = 0;
            return 0;
        }
        CRYPTO_gcm128_tag(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx), 16);
        gctx->taglen = 16;
        /* Don't reuse the IV */
        gctx->iv_set = 0;
        return 0;
    }

}

#define CUSTOM_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY)

BLOCK_CIPHER_custom(NID_aes, 128, 1, 12, gcm, GCM,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
    BLOCK_CIPHER_custom(NID_aes, 192, 1, 12, gcm, GCM,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
    BLOCK_CIPHER_custom(NID_aes, 256, 1, 12, gcm, GCM,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)

static int aes_xts_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_AES_XTS_CTX *xctx = EVP_C_DATA(EVP_AES_XTS_CTX,c);
    if (type == EVP_CTRL_COPY) {
        EVP_CIPHER_CTX *out = ptr;
        EVP_AES_XTS_CTX *xctx_out = EVP_C_DATA(EVP_AES_XTS_CTX,out);
        if (xctx->xts.key1) {
            if (xctx->xts.key1 != xctx->ks1)
                return 0;
			/* Memsep allocate new key */
            xctx_out->ks1 = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
			if (xctx_out->ks1 == NULL ) {
				return 0;
			}
			memcpy(xctx_out->ks1, xctx->ks1, sizeof(AES_KEY));
			xctx_out->xts.key1 = xctx_out->ks1;
        }
        if (xctx->xts.key2) {
            if (xctx->xts.key2 != xctx->ks2)
                return 0;
            /* Memsep allocate new key */
            xctx_out->ks2 = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
			if (xctx_out->ks2 == NULL ) {
				return 0;
			}
			memcpy(xctx_out->ks2, xctx->ks2, sizeof(AES_KEY));
			xctx_out->xts.key2 = xctx_out->ks2;
        }
        return 1;
    } else if (type != EVP_CTRL_INIT)
        return -1;
    /* key1 and key2 are used as an indicator both key and IV are set */
    xctx->xts.key1 = NULL;
    xctx->xts.key2 = NULL;
    return 1;
}

static int aes_xts_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    EVP_AES_XTS_CTX *xctx = EVP_C_DATA(EVP_AES_XTS_CTX,ctx);

    prt_stack_trace(__FUNCTION__, xctx);
    if (!iv && !key)
        return 1;

    /*
	 * MEMSEP get key allocation
	 */
	xctx->ks1 = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	if (xctx->ks1 == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	/*
	 * MEMSEP get key allocation
	 */
	xctx->ks2 = (AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	if (xctx->ks2 == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key)
        do {
#ifdef AES_XTS_ASM
            xctx->stream = enc ? AES_xts_encrypt : AES_xts_decrypt;
#else
            xctx->stream = NULL;
#endif
            /* key_len is two AES keys */
#ifdef HWAES_CAPABLE
            if (HWAES_CAPABLE) {
                if (enc) {
                    HWAES_set_encrypt_key(key,
                                          EVP_CIPHER_CTX_key_length(ctx) * 4,
                                          xctx->ks1);
                    xctx->xts.block1 = (block128_f) HWAES_encrypt;
# ifdef HWAES_xts_encrypt
                    xctx->stream = HWAES_xts_encrypt;
# endif
                } else {
                    HWAES_set_decrypt_key(key,
                                          EVP_CIPHER_CTX_key_length(ctx) * 4,
                                          xctx->ks1);
                    xctx->xts.block1 = (block128_f) HWAES_decrypt;
# ifdef HWAES_xts_decrypt
                    xctx->stream = HWAES_xts_decrypt;
#endif
                }

                HWAES_set_encrypt_key(key + EVP_CIPHER_CTX_key_length(ctx) / 2,
                                      EVP_CIPHER_CTX_key_length(ctx) * 4,
                                      xctx->ks2);
                xctx->xts.block2 = (block128_f) HWAES_encrypt;

                xctx->xts.key1 = xctx->ks1;
                break;
            } else
#endif
#ifdef BSAES_CAPABLE
            if (BSAES_CAPABLE)
                xctx->stream = enc ? bsaes_xts_encrypt : bsaes_xts_decrypt;
            else
#endif
#ifdef VPAES_CAPABLE
            if (VPAES_CAPABLE) {
                if (enc) {
                    vpaes_set_encrypt_key(key,
                                          EVP_CIPHER_CTX_key_length(ctx) * 4,
                                          xctx->ks1);
                    xctx->xts.block1 = (block128_f) vpaes_encrypt;
                } else {
                    vpaes_set_decrypt_key(key,
                                          EVP_CIPHER_CTX_key_length(ctx) * 4,
                                          xctx->ks1);
                    xctx->xts.block1 = (block128_f) vpaes_decrypt;
                }

                vpaes_set_encrypt_key(key + EVP_CIPHER_CTX_key_length(ctx) / 2,
                                      EVP_CIPHER_CTX_key_length(ctx) * 4,
                                      xctx->ks2);
                xctx->xts.block2 = (block128_f) vpaes_encrypt;

                xctx->xts.key1 = xctx->ks1;
                break;
            } else
#endif
                (void)0;        /* terminate potentially open 'else' */

            if (enc) {
                AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 4,
                                    xctx->ks1);
                xctx->xts.block1 = (block128_f) AES_encrypt;
            } else {
                AES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 4,
                                    xctx->ks1);
                xctx->xts.block1 = (block128_f) AES_decrypt;
            }

            AES_set_encrypt_key(key + EVP_CIPHER_CTX_key_length(ctx) / 2,
                                EVP_CIPHER_CTX_key_length(ctx) * 4,
                                xctx->ks2);
            xctx->xts.block2 = (block128_f) AES_encrypt;

            xctx->xts.key1 = xctx->ks1;
        } while (0);

    if (iv) {
        xctx->xts.key2 = xctx->ks2;
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 16);
    }

    return 1;
}

static int aes_xts_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_AES_XTS_CTX *xctx = EVP_C_DATA(EVP_AES_XTS_CTX,ctx);
    if (!xctx->xts.key1 || !xctx->xts.key2)
        return 0;
    if (!out || !in || len < AES_BLOCK_SIZE)
        return 0;
    if (xctx->stream)
        (*xctx->stream) (in, out, len,
                         xctx->xts.key1, xctx->xts.key2,
                         EVP_CIPHER_CTX_iv_noconst(ctx));
    else if (CRYPTO_xts128_encrypt(&xctx->xts, EVP_CIPHER_CTX_iv_noconst(ctx),
                                   in, out, len,
                                   EVP_CIPHER_CTX_encrypting(ctx)))
        return 0;
    return 1;
}

static int aes_xts_cleanup(EVP_CIPHER_CTX * ctx) {

	EVP_AES_XTS_CTX * xctx = EVP_C_DATA(EVP_AES_XTS_CTX,ctx);
	if(xctx->ks1 != NULL) {
		(void) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_free, xctx->ks1, __FILE__, __LINE__);
		xctx->ks1 = NULL;
	}
	if(xctx->ks2 != NULL) {
		(void) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_free, xctx->ks2, __FILE__, __LINE__);
		xctx->ks2 = NULL;
	}

	return 1;
}

#define XTS_FLAGS       (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV \
                         | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                         | EVP_CIPH_CUSTOM_COPY)

BLOCK_CIPHER_custom(NID_aes, 128, 1, 16, xts, XTS, XTS_FLAGS)
    BLOCK_CIPHER_custom(NID_aes, 256, 1, 16, xts, XTS, XTS_FLAGS)

static int aes_ccm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_AES_CCM_CTX *cctx = EVP_C_DATA(EVP_AES_CCM_CTX,c);
    switch (type) {
    case EVP_CTRL_INIT:
        cctx->key_set = 0;
        cctx->iv_set = 0;
        cctx->L = 8;
        cctx->M = 12;
        cctx->tag_set = 0;
        cctx->len_set = 0;
        cctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        cctx->tls_aad_len = arg;
        {
            uint16_t len =
                EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8
                | EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
            /* Correct length for explicit IV */
            if (len < EVP_CCM_TLS_EXPLICIT_IV_LEN)
                return 0;
            len -= EVP_CCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!EVP_CIPHER_CTX_encrypting(c)) {
                if (len < cctx->M)
                    return 0;
                len -= cctx->M;
            }
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
        }
        /* Extra padding: tag appended to record */
        return cctx->M;

    case EVP_CTRL_CCM_SET_IV_FIXED:
        /* Sanity check length */
        if (arg != EVP_CCM_TLS_FIXED_IV_LEN)
            return 0;
        /* Just copy to first part of IV */
        memcpy(EVP_CIPHER_CTX_iv_noconst(c), ptr, arg);
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        arg = 15 - arg;
        /* fall thru */
    case EVP_CTRL_CCM_SET_L:
        if (arg < 2 || arg > 8)
            return 0;
        cctx->L = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if ((arg & 1) || arg < 4 || arg > 16)
            return 0;
        if (EVP_CIPHER_CTX_encrypting(c) && ptr)
            return 0;
        if (ptr) {
            cctx->tag_set = 1;
            memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        }
        cctx->M = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (!EVP_CIPHER_CTX_encrypting(c) || !cctx->tag_set)
            return 0;
        if (!CRYPTO_ccm128_tag(&cctx->ccm, ptr, (size_t)arg))
            return 0;
        cctx->tag_set = 0;
        cctx->iv_set = 0;
        cctx->len_set = 0;
        return 1;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_AES_CCM_CTX *cctx_out = EVP_C_DATA(EVP_AES_CCM_CTX,out);
            if (cctx->ccm.key) {
                if (cctx->ccm.key != cctx->ks)
                    return 0;
				/* Memsep allocate new key */
				cctx_out->ks =
						(AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
				if (cctx_out->ks == NULL ) {
					return 0;
				}
				memcpy(cctx_out->ks, cctx->ks, sizeof(AES_KEY));
				cctx_out->ccm.key = cctx_out->ks;
            }
            return 1;
        }

    default:
        return -1;

    }
}

static int aes_ccm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    EVP_AES_CCM_CTX *cctx = EVP_C_DATA(EVP_AES_CCM_CTX,ctx);

    prt_stack_trace(__FUNCTION__, cctx);
    if (!iv && !key)
        return 1;
    /*
	 * MEMSEP get key allocation
	 */
	cctx->ks =
			(AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	if (cctx->ks == NULL ) {
		EVPerr(EVP_F_AES_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key)
        do {
#ifdef HWAES_CAPABLE
            if (HWAES_CAPABLE) {
                HWAES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      cctx->ks);

                CRYPTO_ccm128_init(&cctx->ccm, cctx->M, cctx->L,
                                  cctx->ks, (block128_f) HWAES_encrypt);
                cctx->str = NULL;
                cctx->key_set = 1;
                break;
            } else
#endif
#ifdef VPAES_CAPABLE
            if (VPAES_CAPABLE) {
                vpaes_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      cctx->ks);
                CRYPTO_ccm128_init(&cctx->ccm, cctx->M, cctx->L,
                                   cctx->ks, (block128_f) vpaes_encrypt);
                cctx->str = NULL;
                cctx->key_set = 1;
                break;
            }
#endif
            AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                cctx->ks);
            CRYPTO_ccm128_init(&cctx->ccm, cctx->M, cctx->L,
                               cctx->ks, (block128_f) AES_encrypt);
            cctx->str = NULL;
            cctx->key_set = 1;
        } while (0);
    if (iv) {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 15 - cctx->L);
        cctx->iv_set = 1;
    }
    return 1;
}

static int aes_ccm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    EVP_AES_CCM_CTX *cctx = EVP_C_DATA(EVP_AES_CCM_CTX,ctx);
    CCM128_CONTEXT *ccm = &cctx->ccm;
    /* Encrypt/decrypt must be performed in place */
    if (out != in || len < (EVP_CCM_TLS_EXPLICIT_IV_LEN + (size_t)cctx->M))
        return -1;
    /* If encrypting set explicit IV from sequence number (start of AAD) */
    if (EVP_CIPHER_CTX_encrypting(ctx))
        memcpy(out, EVP_CIPHER_CTX_buf_noconst(ctx),
               EVP_CCM_TLS_EXPLICIT_IV_LEN);
    /* Get rest of IV from explicit IV */
    memcpy(EVP_CIPHER_CTX_iv_noconst(ctx) + EVP_CCM_TLS_FIXED_IV_LEN, in,
           EVP_CCM_TLS_EXPLICIT_IV_LEN);
    /* Correct length value */
    len -= EVP_CCM_TLS_EXPLICIT_IV_LEN + cctx->M;
    if (CRYPTO_ccm128_setiv(ccm, EVP_CIPHER_CTX_iv_noconst(ctx), 15 - cctx->L,
                            len))
            return -1;
    /* Use saved AAD */
    CRYPTO_ccm128_aad(ccm, EVP_CIPHER_CTX_buf_noconst(ctx), cctx->tls_aad_len);
    /* Fix buffer to point to payload */
    in += EVP_CCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_CCM_TLS_EXPLICIT_IV_LEN;
    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        if (cctx->str ? CRYPTO_ccm128_encrypt_ccm64(ccm, in, out, len,
                                                    cctx->str) :
            CRYPTO_ccm128_encrypt(ccm, in, out, len))
            return -1;
        if (!CRYPTO_ccm128_tag(ccm, out + len, cctx->M))
            return -1;
        return len + EVP_CCM_TLS_EXPLICIT_IV_LEN + cctx->M;
    } else {
        if (cctx->str ? !CRYPTO_ccm128_decrypt_ccm64(ccm, in, out, len,
                                                     cctx->str) :
            !CRYPTO_ccm128_decrypt(ccm, in, out, len)) {
            unsigned char tag[16];
            if (CRYPTO_ccm128_tag(ccm, tag, cctx->M)) {
                if (!CRYPTO_memcmp(tag, in + len, cctx->M))
                    return len;
            }
        }
        OPENSSL_cleanse(out, len);
        return -1;
    }
}

static int aes_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_AES_CCM_CTX *cctx = EVP_C_DATA(EVP_AES_CCM_CTX,ctx);
    CCM128_CONTEXT *ccm = &cctx->ccm;
    /* If not set up, return error */
    if (!cctx->key_set)
        return -1;

    if (cctx->tls_aad_len >= 0)
        return aes_ccm_tls_cipher(ctx, out, in, len);

    /* EVP_*Final() doesn't return any data */
    if (in == NULL && out != NULL)
        return 0;

    if (!cctx->iv_set)
        return -1;

    if (!EVP_CIPHER_CTX_encrypting(ctx) && !cctx->tag_set)
        return -1;
    if (!out) {
        if (!in) {
            if (CRYPTO_ccm128_setiv(ccm, EVP_CIPHER_CTX_iv_noconst(ctx),
                                    15 - cctx->L, len))
                return -1;
            cctx->len_set = 1;
            return len;
        }
        /* If have AAD need message length */
        if (!cctx->len_set && len)
            return -1;
        CRYPTO_ccm128_aad(ccm, in, len);
        return len;
    }
    /* If not set length yet do it */
    if (!cctx->len_set) {
        if (CRYPTO_ccm128_setiv(ccm, EVP_CIPHER_CTX_iv_noconst(ctx),
                                15 - cctx->L, len))
            return -1;
        cctx->len_set = 1;
    }
    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        if (cctx->str ? CRYPTO_ccm128_encrypt_ccm64(ccm, in, out, len,
                                                    cctx->str) :
            CRYPTO_ccm128_encrypt(ccm, in, out, len))
            return -1;
        cctx->tag_set = 1;
        return len;
    } else {
        int rv = -1;
        if (cctx->str ? !CRYPTO_ccm128_decrypt_ccm64(ccm, in, out, len,
                                                     cctx->str) :
            !CRYPTO_ccm128_decrypt(ccm, in, out, len)) {
            unsigned char tag[16];
            if (CRYPTO_ccm128_tag(ccm, tag, cctx->M)) {
                if (!CRYPTO_memcmp(tag, EVP_CIPHER_CTX_buf_noconst(ctx),
                                   cctx->M))
                    rv = len;
            }
        }
        if (rv == -1)
            OPENSSL_cleanse(out, len);
        cctx->iv_set = 0;
        cctx->tag_set = 0;
        cctx->len_set = 0;
        return rv;
    }
}

static int aes_ccm_cleanup(EVP_CIPHER_CTX * ctx) {
    EVP_AES_CCM_CTX *cctx = EVP_C_DATA(EVP_AES_CCM_CTX,ctx);

    if(cctx->ks != NULL) {

    	(void) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_free, cctx->ks, __FILE__, __LINE__);
    	cctx->ks = NULL;
    }

	return 1;
}

BLOCK_CIPHER_custom(NID_aes, 128, 1, 12, ccm, CCM,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
    BLOCK_CIPHER_custom(NID_aes, 192, 1, 12, ccm, CCM,
                        EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
    BLOCK_CIPHER_custom(NID_aes, 256, 1, 12, ccm, CCM,
                        EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)

typedef struct {
    AES_KEY * ks;
    /* Indicates if IV has been set */
    unsigned char *iv;
} EVP_AES_WRAP_CTX;

static int aes_wrap_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    EVP_AES_WRAP_CTX *wctx = EVP_C_DATA(EVP_AES_WRAP_CTX,ctx);
    /*
	 * MEMSEP get key allocation
	 */
	wctx->ks =
			(AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	if (wctx->ks == NULL ) {
		EVPerr(EVP_F_AESNI_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
    prt_stack_trace(__FUNCTION__, wctx);
    if (!iv && !key)
        return 1;
    if (key) {
        if (EVP_CIPHER_CTX_encrypting(ctx))
            AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                wctx->ks);
        else
            AES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                wctx->ks);
        if (!iv)
            wctx->iv = NULL;
    }
    if (iv) {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, EVP_CIPHER_CTX_iv_length(ctx));
        wctx->iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    }
    return 1;
}

static int aes_wrap_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inlen)
{
    EVP_AES_WRAP_CTX *wctx = EVP_C_DATA(EVP_AES_WRAP_CTX,ctx);
    size_t rv;
    /* AES wrap with padding has IV length of 4, without padding 8 */
    int pad = EVP_CIPHER_CTX_iv_length(ctx) == 4;
    /* No final operation so always return zero length */
    if (!in)
        return 0;
    /* Input length must always be non-zero */
    if (!inlen)
        return -1;
    /* If decrypting need at least 16 bytes and multiple of 8 */
    if (!EVP_CIPHER_CTX_encrypting(ctx) && (inlen < 16 || inlen & 0x7))
        return -1;
    /* If not padding input must be multiple of 8 */
    if (!pad && inlen & 0x7)
        return -1;
    if (is_partially_overlapping(out, in, inlen)) {
        EVPerr(EVP_F_AES_WRAP_CIPHER, EVP_R_PARTIALLY_OVERLAPPING);
        return 0;
    }
    if (!out) {
        if (EVP_CIPHER_CTX_encrypting(ctx)) {
            /* If padding round up to multiple of 8 */
            if (pad)
                inlen = (inlen + 7) / 8 * 8;
            /* 8 byte prefix */
            return inlen + 8;
        } else {
            /*
             * If not padding output will be exactly 8 bytes smaller than
             * input. If padding it will be at least 8 bytes smaller but we
             * don't know how much.
             */
            return inlen - 8;
        }
    }
    if (pad) {
        if (EVP_CIPHER_CTX_encrypting(ctx))
            rv = CRYPTO_128_wrap_pad(wctx->ks, wctx->iv,
                                     out, in, inlen,
                                     (block128_f) AES_encrypt);
        else
            rv = CRYPTO_128_unwrap_pad(wctx->ks, wctx->iv,
                                       out, in, inlen,
                                       (block128_f) AES_decrypt);
    } else {
        if (EVP_CIPHER_CTX_encrypting(ctx))
            rv = CRYPTO_128_wrap(wctx->ks, wctx->iv,
                                 out, in, inlen, (block128_f) AES_encrypt);
        else
            rv = CRYPTO_128_unwrap(wctx->ks, wctx->iv,
                                   out, in, inlen, (block128_f) AES_decrypt);
    }
    return rv ? (int)rv : -1;
}

#define WRAP_FLAGS      (EVP_CIPH_WRAP_MODE \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1)

static const EVP_CIPHER aes_128_wrap = {
    NID_id_aes128_wrap,
    8, 16, 8, WRAP_FLAGS,
    aes_wrap_init_key, aes_wrap_cipher,
    NULL,
    sizeof(EVP_AES_WRAP_CTX),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_aes_128_wrap(void)
{
    return &aes_128_wrap;
}

static const EVP_CIPHER aes_192_wrap = {
    NID_id_aes192_wrap,
    8, 24, 8, WRAP_FLAGS,
    aes_wrap_init_key, aes_wrap_cipher,
    NULL,
    sizeof(EVP_AES_WRAP_CTX),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_aes_192_wrap(void)
{
    return &aes_192_wrap;
}

static const EVP_CIPHER aes_256_wrap = {
    NID_id_aes256_wrap,
    8, 32, 8, WRAP_FLAGS,
    aes_wrap_init_key, aes_wrap_cipher,
    NULL,
    sizeof(EVP_AES_WRAP_CTX),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_aes_256_wrap(void)
{
    return &aes_256_wrap;
}

static const EVP_CIPHER aes_128_wrap_pad = {
    NID_id_aes128_wrap_pad,
    8, 16, 4, WRAP_FLAGS,
    aes_wrap_init_key, aes_wrap_cipher,
    NULL,
    sizeof(EVP_AES_WRAP_CTX),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_aes_128_wrap_pad(void)
{
    return &aes_128_wrap_pad;
}

static const EVP_CIPHER aes_192_wrap_pad = {
    NID_id_aes192_wrap_pad,
    8, 24, 4, WRAP_FLAGS,
    aes_wrap_init_key, aes_wrap_cipher,
    NULL,
    sizeof(EVP_AES_WRAP_CTX),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_aes_192_wrap_pad(void)
{
    return &aes_192_wrap_pad;
}

static const EVP_CIPHER aes_256_wrap_pad = {
    NID_id_aes256_wrap_pad,
    8, 32, 4, WRAP_FLAGS,
    aes_wrap_init_key, aes_wrap_cipher,
    NULL,
    sizeof(EVP_AES_WRAP_CTX),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_aes_256_wrap_pad(void)
{
    return &aes_256_wrap_pad;
}

#ifndef OPENSSL_NO_OCB
static int aes_ocb_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_AES_OCB_CTX *octx = EVP_C_DATA(EVP_AES_OCB_CTX,c);
    EVP_CIPHER_CTX *newc;
    EVP_AES_OCB_CTX *new_octx;

    switch (type) {
    case EVP_CTRL_INIT:
        octx->key_set = 0;
        octx->iv_set = 0;
        octx->ivlen = EVP_CIPHER_CTX_iv_length(c);
        octx->iv = EVP_CIPHER_CTX_iv_noconst(c);
        octx->taglen = 16;
        octx->data_buf_len = 0;
        octx->aad_buf_len = 0;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        /* IV len must be 1 to 15 */
        if (arg <= 0 || arg > 15)
            return 0;

        octx->ivlen = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (!ptr) {
            /* Tag len must be 0 to 16 */
            if (arg < 0 || arg > 16)
                return 0;

            octx->taglen = arg;
            return 1;
        }
        if (arg != octx->taglen || EVP_CIPHER_CTX_encrypting(c))
            return 0;
        memcpy(octx->tag, ptr, arg);
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg != octx->taglen || !EVP_CIPHER_CTX_encrypting(c))
            return 0;

        memcpy(ptr, octx->tag, arg);
        return 1;

    case EVP_CTRL_COPY:
        newc = (EVP_CIPHER_CTX *)ptr;
        new_octx = EVP_C_DATA(EVP_AES_OCB_CTX,newc);
        /* Memsep allocate new key */
        new_octx->ksenc =
        		(AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
		if (new_octx->ksenc == NULL ) {
			return 0;
		}
		memcpy(new_octx->ksenc, octx->ksenc, sizeof(AES_KEY));
        /* Memsep allocate new key */
        new_octx->ksdec =
        		(AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
		if (new_octx->ksdec == NULL ) {
			return 0;
		}
		memcpy(new_octx->ksdec, octx->ksdec, sizeof(AES_KEY));

        return CRYPTO_ocb128_copy_ctx(&new_octx->ocb, &octx->ocb,
                                      new_octx->ksenc,
                                      new_octx->ksdec);

    default:
        return -1;

    }
}

# ifdef HWAES_CAPABLE
#  ifdef HWAES_ocb_encrypt
void HWAES_ocb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t blocks, const void *key,
                       size_t start_block_num,
                       unsigned char offset_i[16],
                       const unsigned char L_[][16],
                       unsigned char checksum[16]);
#  else
#    define HWAES_ocb_encrypt ((ocb128_f)NULL)
#  endif
#  ifdef HWAES_ocb_decrypt
void HWAES_ocb_decrypt(const unsigned char *in, unsigned char *out,
                       size_t blocks, const void *key,
                       size_t start_block_num,
                       unsigned char offset_i[16],
                       const unsigned char L_[][16],
                       unsigned char checksum[16]);
#  else
#    define HWAES_ocb_decrypt ((ocb128_f)NULL)
#  endif
# endif

static int aes_ocb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    EVP_AES_OCB_CTX *octx = EVP_C_DATA(EVP_AES_OCB_CTX,ctx);

    prt_stack_trace(__FUNCTION__, octx);
    if (!iv && !key)
        return 1;

    /*
	 * MEMSEP get key allocation
	 */
	octx->ksenc =
			(AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	if (octx->ksenc == NULL ) {
		EVPerr(EVP_F_AES_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	/*
	 * MEMSEP get key allocation
	 */
	octx->ksdec =
			(AES_KEY*) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_zalloc, sizeof(AES_KEY), __FILE__, __LINE__);
	if (octx->ksdec == NULL ) {
		EVPerr(EVP_F_AES_INIT_KEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}

    if (key) {
        do {
            /*
             * We set both the encrypt and decrypt key here because decrypt
             * needs both. We could possibly optimise to remove setting the
             * decrypt for an encryption operation.
             */
# ifdef HWAES_CAPABLE
            if (HWAES_CAPABLE) {
                HWAES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      octx->ksenc);
                HWAES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      octx->ksdec);
                if (!CRYPTO_ocb128_init(&octx->ocb,
                                        octx->ksenc, octx->ksdec,
                                        (block128_f) HWAES_encrypt,
                                        (block128_f) HWAES_decrypt,
                                        enc ? HWAES_ocb_encrypt
                                            : HWAES_ocb_decrypt))
                    return 0;
                break;
            }
# endif
# ifdef VPAES_CAPABLE
            if (VPAES_CAPABLE) {
                vpaes_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      octx->ksenc);
                vpaes_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      octx->ksdec);
                if (!CRYPTO_ocb128_init(&octx->ocb,
                                        octx->ksenc, octx->ksdec,
                                        (block128_f) vpaes_encrypt,
                                        (block128_f) vpaes_decrypt,
                                        NULL))
                    return 0;
                break;
            }
# endif
            AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                octx->ksenc);
            AES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                octx->ksdec);
            if (!CRYPTO_ocb128_init(&octx->ocb,
                                    octx->ksenc, octx->ksdec,
                                    (block128_f) AES_encrypt,
                                    (block128_f) AES_decrypt,
                                    NULL))
                return 0;
        }
        while (0);

        /*
         * If we have an iv we can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && octx->iv_set)
            iv = octx->iv;
        if (iv) {
            if (CRYPTO_ocb128_setiv(&octx->ocb, iv, octx->ivlen, octx->taglen)
                != 1)
                return 0;
            octx->iv_set = 1;
        }
        octx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (octx->key_set)
            CRYPTO_ocb128_setiv(&octx->ocb, iv, octx->ivlen, octx->taglen);
        else
            memcpy(octx->iv, iv, octx->ivlen);
        octx->iv_set = 1;
    }
    return 1;
}

static int aes_ocb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    unsigned char *buf;
    int *buf_len;
    int written_len = 0;
    size_t trailing_len;
    EVP_AES_OCB_CTX *octx = EVP_C_DATA(EVP_AES_OCB_CTX,ctx);

    /* If IV or Key not set then return error */
    if (!octx->iv_set)
        return -1;

    if (!octx->key_set)
        return -1;

    if (in != NULL) {
        /*
         * Need to ensure we are only passing full blocks to low level OCB
         * routines. We do it here rather than in EVP_EncryptUpdate/
         * EVP_DecryptUpdate because we need to pass full blocks of AAD too
         * and those routines don't support that
         */

        /* Are we dealing with AAD or normal data here? */
        if (out == NULL) {
            buf = octx->aad_buf;
            buf_len = &(octx->aad_buf_len);
        } else {
            buf = octx->data_buf;
            buf_len = &(octx->data_buf_len);

            if (is_partially_overlapping(out + *buf_len, in, len)) {
                EVPerr(EVP_F_AES_OCB_CIPHER, EVP_R_PARTIALLY_OVERLAPPING);
                return 0;
            }
        }

        /*
         * If we've got a partially filled buffer from a previous call then
         * use that data first
         */
        if (*buf_len > 0) {
            unsigned int remaining;

            remaining = AES_BLOCK_SIZE - (*buf_len);
            if (remaining > len) {
                memcpy(buf + (*buf_len), in, len);
                *(buf_len) += len;
                return 0;
            }
            memcpy(buf + (*buf_len), in, remaining);

            /*
             * If we get here we've filled the buffer, so process it
             */
            len -= remaining;
            in += remaining;
            if (out == NULL) {
                if (!CRYPTO_ocb128_aad(&octx->ocb, buf, AES_BLOCK_SIZE))
                    return -1;
            } else if (EVP_CIPHER_CTX_encrypting(ctx)) {
                if (!CRYPTO_ocb128_encrypt(&octx->ocb, buf, out,
                                           AES_BLOCK_SIZE))
                    return -1;
            } else {
                if (!CRYPTO_ocb128_decrypt(&octx->ocb, buf, out,
                                           AES_BLOCK_SIZE))
                    return -1;
            }
            written_len = AES_BLOCK_SIZE;
            *buf_len = 0;
            if (out != NULL)
                out += AES_BLOCK_SIZE;
        }

        /* Do we have a partial block to handle at the end? */
        trailing_len = len % AES_BLOCK_SIZE;

        /*
         * If we've got some full blocks to handle, then process these first
         */
        if (len != trailing_len) {
            if (out == NULL) {
                if (!CRYPTO_ocb128_aad(&octx->ocb, in, len - trailing_len))
                    return -1;
            } else if (EVP_CIPHER_CTX_encrypting(ctx)) {
                if (!CRYPTO_ocb128_encrypt
                    (&octx->ocb, in, out, len - trailing_len))
                    return -1;
            } else {
                if (!CRYPTO_ocb128_decrypt
                    (&octx->ocb, in, out, len - trailing_len))
                    return -1;
            }
            written_len += len - trailing_len;
            in += len - trailing_len;
        }

        /* Handle any trailing partial block */
        if (trailing_len > 0) {
            memcpy(buf, in, trailing_len);
            *buf_len = trailing_len;
        }

        return written_len;
    } else {
        /*
         * First of all empty the buffer of any partial block that we might
         * have been provided - both for data and AAD
         */
        if (octx->data_buf_len > 0) {
            if (EVP_CIPHER_CTX_encrypting(ctx)) {
                if (!CRYPTO_ocb128_encrypt(&octx->ocb, octx->data_buf, out,
                                           octx->data_buf_len))
                    return -1;
            } else {
                if (!CRYPTO_ocb128_decrypt(&octx->ocb, octx->data_buf, out,
                                           octx->data_buf_len))
                    return -1;
            }
            written_len = octx->data_buf_len;
            octx->data_buf_len = 0;
        }
        if (octx->aad_buf_len > 0) {
            if (!CRYPTO_ocb128_aad
                (&octx->ocb, octx->aad_buf, octx->aad_buf_len))
                return -1;
            octx->aad_buf_len = 0;
        }
        /* If decrypting then verify */
        if (!EVP_CIPHER_CTX_encrypting(ctx)) {
            if (octx->taglen < 0)
                return -1;
            if (CRYPTO_ocb128_finish(&octx->ocb,
                                     octx->tag, octx->taglen) != 0)
                return -1;
            octx->iv_set = 0;
            return written_len;
        }
        /* If encrypting then just get the tag */
        if (CRYPTO_ocb128_tag(&octx->ocb, octx->tag, 16) != 1)
            return -1;
        /* Don't reuse the IV */
        octx->iv_set = 0;
        return written_len;
    }
}

static int aes_ocb_cleanup(EVP_CIPHER_CTX *c)
{
    EVP_AES_OCB_CTX *octx = EVP_C_DATA(EVP_AES_OCB_CTX,c);
    if(octx->ksenc != NULL) {

    	(void) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_free, octx->ksenc, __FILE__, __LINE__);
        	octx->ksenc = NULL;
        }
    if(octx->ksdec != NULL) {
    	(void) MEMSEP_EXEC_SCT_BRIDGE(MEMSEP_secure_free, octx->ksdec, __FILE__, __LINE__);
    	octx->ksdec = NULL;
    }
    CRYPTO_ocb128_cleanup(&octx->ocb);
    return 1;
}

BLOCK_CIPHER_custom(NID_aes, 128, 16, 12, ocb, OCB,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
BLOCK_CIPHER_custom(NID_aes, 192, 16, 12, ocb, OCB,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
BLOCK_CIPHER_custom(NID_aes, 256, 16, 12, ocb, OCB,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
#endif                         /* OPENSSL_NO_OCB */
