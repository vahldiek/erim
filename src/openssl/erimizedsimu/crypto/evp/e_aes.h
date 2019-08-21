/*
 * e_aes.h
 *
 *  Created on: Oct 9, 2017
 *      Author: vahldiek
 */

#ifndef E_AES_H_
#define E_AES_H_

#include <openssl/aes.h>
#include <openssl/modes.h>

typedef struct {
    AES_KEY * ks;             /* AES key schedule to use */
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EVP_AES_KEY;

typedef struct {
    AES_KEY * ks;             /* AES key schedule to use */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    GCM128_CONTEXT gcm;
    unsigned char *iv;          /* Temporary IV store */
    int ivlen;                  /* IV length */
    int taglen;
    int iv_gen;                 /* It is OK to generate IVs */
    int tls_aad_len;            /* TLS AAD length */
    ctr128_f ctr;
} EVP_AES_GCM_CTX;

typedef struct {
    AES_KEY * ks1;             /* AES key schedule to use */
    AES_KEY * ks2;             /* AES key schedule to use */
    XTS128_CONTEXT xts;
    void (*stream) (const unsigned char *in,
                    unsigned char *out, size_t length,
                    const AES_KEY *key1, const AES_KEY *key2,
                    const unsigned char iv[16]);
} EVP_AES_XTS_CTX;

typedef struct {

    AES_KEY * ks;             /* AES key schedule to use */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    int tag_set;                /* Set if tag is valid */
    int len_set;                /* Set if message length set */
    int L, M;                   /* L and M parameters from RFC3610 */
    int tls_aad_len;            /* TLS AAD length */
    CCM128_CONTEXT ccm;
    ccm128_f str;
} EVP_AES_CCM_CTX;

#ifndef OPENSSL_NO_OCB
typedef struct {
    AES_KEY * ksenc;             /* AES key encryption*/
    AES_KEY * ksdec;             /* AES key decryption*/
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    OCB128_CONTEXT ocb;
    unsigned char *iv;          /* Temporary IV store */
    unsigned char tag[16];
    unsigned char data_buf[16]; /* Store partial data blocks */
    unsigned char aad_buf[16];  /* Store partial AAD blocks */
    int data_buf_len;
    int aad_buf_len;
    int ivlen;                  /* IV length */
    int taglen;
} EVP_AES_OCB_CTX;
#endif

#endif /* E_AES_H_ */
