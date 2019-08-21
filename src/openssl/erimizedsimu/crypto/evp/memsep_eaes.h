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
ERIM_DEFINE_BRIDGE3(int, aesni_set_encrypt_key, const unsigned char *, int, AES_KEY *);
ERIM_DEFINE_BRIDGE3(int, aesni_set_decrypt_key, const unsigned char *, int, AES_KEY *);

// aesni enc/dec
ERIM_DEFINE_BRIDGE3(void, aesni_encrypt, unsigned char *, unsigned char *, const AES_KEY*);
ERIM_DEFINE_BRIDGE3(void, aesni_decrypt, unsigned char *, unsigned char *, const AES_KEY*);
ERIM_DEFINE_BRIDGE5(void, aesni_ctr32_encrypt_blocks, unsigned char *, unsigned char *, size_t, const void *, const unsigned char *);

// gcm
ERIM_DEFINE_BRIDGE6(size_t, aesni_gcm_encrypt, const unsigned char *, unsigned char *, size_t, void *, unsigned char *, u64 *);
ERIM_DEFINE_BRIDGE6(size_t, aesni_gcm_decrypt, const unsigned char *, unsigned char *, size_t, void *, unsigned char *, u64 *);


// cbc ecb enc
ERIM_DEFINE_BRIDGE6(void, aesni_cbc_encrypt, const unsigned char *, 
		    unsigned char *, size_t, const AES_KEY *, unsigned char *, int);
ERIM_DEFINE_BRIDGE5(void, aesni_ecb_encrypt, const unsigned char *,
		    unsigned char *, size_t, const AES_KEY *, int);

// xts enc/dec
ERIM_DEFINE_BRIDGE6(void, aesni_xts_encrypt, const unsigned char *, unsigned char *, size_t, const AES_KEY *, const AES_KEY *, const unsigned char *);
ERIM_DEFINE_BRIDGE6(void, aesni_xts_decrypt, const unsigned char *, unsigned char *, size_t, const AES_KEY *, const AES_KEY *, const unsigned char *);

// ccm
ERIM_DEFINE_BRIDGE6(void, aesni_ccm64_encrypt_blocks, const unsigned char *, unsigned char *, size_t, const void *, const unsigned char *, unsigned char *);
ERIM_DEFINE_BRIDGE6(void, aesni_ccm64_decrypt_blocks, const unsigned char *, unsigned char *, size_t, const void *, const unsigned char *, unsigned char *);

// ocb
ERIM_DEFINE_BRIDGEARGS8(void, aesni_ocb_encrypt, const unsigned char *, in, unsigned char *, out, size_t, len, const void *, addr, size_t , len2, unsigned char *, addr2, const unsigned char, addr3[][16], unsigned char *, addr4);
ERIM_DEFINE_BRIDGEARGS8(void, aesni_ocb_decrypt, const unsigned char *, in, unsigned char *, out, size_t, len, const void *, addr, size_t , len2, unsigned char *, addr2, const unsigned char, addr3[][16], unsigned char *, addr4);

#endif

#endif /* MEMSEP_EAES_H_ */
