/*
 * memsep_eaes.h
 *
 *  Created on: Oct 7, 2017
 *      Author: vahldiek
 */

#ifndef MEMSEP_EAES_H_
#define MEMSEP_EAES_H_

#include <memsep.h>
#include <openssl/aes.h>

#if     defined(AES_ASM) && !defined(I386_ONLY) &&      (  \
        ((defined(__i386)       || defined(__i386__)    || \
          defined(_M_IX86)) && defined(OPENSSL_IA32_SSE2))|| \
        defined(__x86_64)       || defined(__x86_64__)  || \
        defined(_M_AMD64)       || defined(_M_X64)      )

// set enc/dec key
MEMSEP_DEFINE_BRIDGEFCT3(int, aesni_set_encrypt_key, const unsigned char *, int, AES_KEY *);
MEMSEP_DEFINE_BRIDGEFCT3(int, aesni_set_decrypt_key, const unsigned char *, int, AES_KEY *);

// aesni enc/dec
MEMSEP_DEFINE_BRIDGEFCT3(void, aesni_encrypt, unsigned char *, unsigned char *, const AES_KEY*);
MEMSEP_DEFINE_BRIDGEFCT3(void, aesni_decrypt, unsigned char *, unsigned char *, const AES_KEY*);
MEMSEP_DEFINE_BRIDGEFCT5(void, aesni_ctr32_encrypt_blocks, unsigned char *, unsigned char *,
		size_t, const void *, const unsigned char *);

// cbc ecb enc
MEMSEP_DEFINE_BRIDGEFCT6(void, aesni_cbc_encrypt, const unsigned char *,
		unsigned char *, size_t, const AES_KEY *, unsigned char *, int);
MEMSEP_DEFINE_BRIDGEFCT5(void, aesni_ecb_encrypt, const unsigned char *,
		unsigned char *, size_t, const AES_KEY *, int);

// xts enc/dec
MEMSEP_DEFINE_BRIDGEFCT6(void, aesni_xts_encrypt, const unsigned char *, unsigned char *,
		size_t, const AES_KEY *, const AES_KEY *, const unsigned char *);
MEMSEP_DEFINE_BRIDGEFCT6(void, aesni_xts_decrypt, const unsigned char *, unsigned char *,
		size_t, const AES_KEY *, const AES_KEY *, const unsigned char *);

// ccm
MEMSEP_DEFINE_BRIDGEFCT6(void, aesni_ccm64_encrypt_blocks, const unsigned char *,
		unsigned char *, size_t, const void *, const unsigned char *, unsigned char *);
MEMSEP_DEFINE_BRIDGEFCT6(void, aesni_ccm64_decrypt_blocks, const unsigned char *,
		unsigned char *, size_t, const void *, const unsigned char *, unsigned char *);

// ocb
MEMSEP_DEFINE_BRIDGEFCT8(void, aesni_ocb_encrypt, const unsigned char *, unsigned char *,
        size_t, const void *, size_t , unsigned char *, const unsigned char *,
        unsigned char *)
MEMSEP_DEFINE_BRIDGEFCT8(void, aesni_ocb_decrypt, const unsigned char *, unsigned char *,
        size_t, const void *, size_t , unsigned char *, const unsigned char *,
        unsigned char *)


#endif

/* aesni_ocb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                              const unsigned char *iv, int enc)  */
//MEMSEP_DEFINE_SCT(aesni_ocb_init_key);

#endif /* MEMSEP_EAES_H_ */
