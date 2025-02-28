/* api.c API unit tests
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* For AES-CBC, input lengths can optionally be validated to be a
 * multiple of the block size, by defining WOLFSSL_AES_CBC_LENGTH_CHECKS,
 * also available via the configure option --enable-aescbc-length-checks.
 */


/*----------------------------------------------------------------------------*
 | Includes
 *----------------------------------------------------------------------------*/

#include <tests/unit.h>

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/hash.h>

#if defined(WOLFSSL_STATIC_MEMORY)
    #include <wolfssl/wolfcrypt/memory.h>
#endif
#ifdef WOLFSSL_ASNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>   /* wc_ecc_fp_free */
    #ifdef WOLFSSL_SM2
        #include <wolfssl/wolfcrypt/sm2.h>
    #endif
#endif
#ifndef NO_ASN
    #include <wolfssl/wolfcrypt/asn_public.h>
#endif

#include <stdlib.h>
#include <wolfssl/ssl.h>  /* compatibility layer */
#include <wolfssl/error-ssl.h>

#include <wolfssl/test.h>
#include <tests/utils.h>
#include <testsuite/utils.h>

/* for testing compatibility layer callbacks */
#include "examples/server/server.h"

#ifndef NO_MD5
    #include <wolfssl/wolfcrypt/md5.h>
#endif
#ifndef NO_SHA
    #include <wolfssl/wolfcrypt/sha.h>
#endif
#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#ifdef WOLFSSL_SHA512
    #include <wolfssl/wolfcrypt/sha512.h>
#endif
#ifdef WOLFSSL_SHA384
    #include <wolfssl/wolfcrypt/sha512.h>
#endif
#ifdef WOLFSSL_SHA3
    #include <wolfssl/wolfcrypt/sha3.h>
#endif
#ifdef WOLFSSL_SM3
    #include <wolfssl/wolfcrypt/sm3.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
    #ifdef HAVE_AES_DECRYPT
        #include <wolfssl/wolfcrypt/wc_encrypt.h>
    #endif
#endif
#ifdef WOLFSSL_SM4
    #include <wolfssl/wolfcrypt/sm4.h>
#endif
#ifdef WOLFSSL_RIPEMD
    #include <wolfssl/wolfcrypt/ripemd.h>
#endif
#ifndef NO_DES3
    #include <wolfssl/wolfcrypt/des3.h>
    #include <wolfssl/wolfcrypt/wc_encrypt.h>
#endif
#ifdef WC_RC2
    #include <wolfssl/wolfcrypt/rc2.h>
#endif

#ifndef NO_HMAC
    #include <wolfssl/wolfcrypt/hmac.h>
#endif

#ifdef HAVE_CHACHA
    #include <wolfssl/wolfcrypt/chacha.h>
#endif

#ifdef HAVE_POLY1305
    #include <wolfssl/wolfcrypt/poly1305.h>
#endif

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif

#ifdef HAVE_CAMELLIA
    #include <wolfssl/wolfcrypt/camellia.h>
#endif

#ifndef NO_RC4
    #include <wolfssl/wolfcrypt/arc4.h>
#endif

#ifdef HAVE_BLAKE2
    #include <wolfssl/wolfcrypt/blake2.h>
#endif

#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif

#ifndef NO_SIG_WRAPPER
    #include <wolfssl/wolfcrypt/signature.h>
#endif

#ifdef HAVE_AESCCM
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#ifdef HAVE_PKCS7
    #include <wolfssl/wolfcrypt/pkcs7.h>
    #include <wolfssl/wolfcrypt/asn.h>
    #ifdef HAVE_LIBZ
        #include <wolfssl/wolfcrypt/compress.h>
    #endif
#endif

#ifdef WOLFSSL_SMALL_CERT_VERIFY
    #include <wolfssl/wolfcrypt/asn.h>
#endif

#ifndef NO_DSA
    #include <wolfssl/wolfcrypt/dsa.h>
#endif

#ifdef WOLFSSL_CMAC
    #include <wolfssl/wolfcrypt/cmac.h>
#endif

#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_CURVE25519
    #include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef HAVE_CURVE448
    #include <wolfssl/wolfcrypt/curve448.h>
#endif

#ifdef WOLFSSL_HAVE_KYBER
    #include <wolfssl/wolfcrypt/kyber.h>
#ifdef WOLFSSL_WC_KYBER
    #include <wolfssl/wolfcrypt/wc_kyber.h>
#endif
#endif
#ifdef HAVE_DILITHIUM
    #include <wolfssl/wolfcrypt/dilithium.h>
#endif

#ifdef HAVE_PKCS12
    #include <wolfssl/wolfcrypt/pkcs12.h>
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(OPENSSL_ALL)
    #include <wolfssl/openssl/ssl.h>
    #ifndef NO_ASN
        /* for ASN_COMMON_NAME DN_tags enum */
        #include <wolfssl/wolfcrypt/asn.h>
    #endif
    #ifdef HAVE_OCSP
        #include <wolfssl/openssl/ocsp.h>
    #endif
#endif
#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/cmac.h>
    #include <wolfssl/openssl/x509v3.h>
    #include <wolfssl/openssl/asn1.h>
    #include <wolfssl/openssl/crypto.h>
    #include <wolfssl/openssl/pkcs12.h>
    #include <wolfssl/openssl/evp.h>
    #include <wolfssl/openssl/dh.h>
    #include <wolfssl/openssl/bn.h>
    #include <wolfssl/openssl/buffer.h>
    #include <wolfssl/openssl/pem.h>
    #include <wolfssl/openssl/ec.h>
    #include <wolfssl/openssl/ecdh.h>
    #include <wolfssl/openssl/engine.h>
    #include <wolfssl/openssl/hmac.h>
    #include <wolfssl/openssl/objects.h>
    #include <wolfssl/openssl/rand.h>
    #include <wolfssl/openssl/modes.h>
    #include <wolfssl/openssl/fips_rand.h>
    #include <wolfssl/openssl/kdf.h>
    #include <wolfssl/openssl/x509_vfy.h>
#ifdef OPENSSL_ALL
    #include <wolfssl/openssl/txt_db.h>
    #include <wolfssl/openssl/lhash.h>
#endif
#ifndef NO_AES
    #include <wolfssl/openssl/aes.h>
#endif
#ifndef NO_DES3
    #include <wolfssl/openssl/des.h>
#endif
#ifndef NO_RC4
    #include <wolfssl/openssl/rc4.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/openssl/ecdsa.h>
#endif
#ifdef HAVE_PKCS7
    #include <wolfssl/openssl/pkcs7.h>
#endif
#ifdef HAVE_CURVE25519
    #include <wolfssl/openssl/ec25519.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/openssl/ed25519.h>
#endif
#ifdef HAVE_CURVE448
    #include <wolfssl/openssl/ec448.h>
#endif
#ifdef HAVE_ED448
    #include <wolfssl/openssl/ed448.h>
#endif
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) && defined(WOLFCRYPT_HAVE_SRP) && \
    !defined(NO_SHA256) && !defined(RC_NO_RNG)
        #include <wolfssl/wolfcrypt/srp.h>
#endif

#if (defined(SESSION_CERTS) && defined(TEST_PEER_CERT_CHAIN)) || \
    defined(HAVE_SESSION_TICKET) || (defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_CERT_GEN)) || \
    defined(WOLFSSL_TEST_STATIC_BUILD) || defined(WOLFSSL_DTLS) || \
    defined(HAVE_ECH) || defined(HAVE_EX_DATA) || !defined(NO_SESSION_CACHE) \
    || !defined(WOLFSSL_NO_TLS12) || defined(WOLFSSL_TLS13)
    /* for testing SSL_get_peer_cert_chain, or SESSION_TICKET_HINT_DEFAULT,
     * for setting authKeyIdSrc in WOLFSSL_X509, or testing DTLS sequence
     * number tracking */
    #include "wolfssl/internal.h"
#endif

/* force enable test buffers */
#ifndef USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_2048
#endif
#ifndef USE_CERT_BUFFERS_256
    #define USE_CERT_BUFFERS_256
#endif
#include <wolfssl/certs_test.h>

/* include misc.c here regardless of NO_INLINE, because misc.c implementations
 * have default (hidden) visibility, and in the absence of visibility, it's
 * benign to mask out the library implementation.
 */
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>

#include <tests/api/api.h>

/* Gather test declarations to include them in the testCases array */
#include <tests/api/test_md5.h>
#include <tests/api/test_sha.h>
#include <tests/api/test_sha256.h>
#include <tests/api/test_sha512.h>
#include <tests/api/test_sha3.h>
#include <tests/api/test_evp.h>
#include <tests/api/test_blake2.h>
#include <tests/api/test_sm3.h>
#include <tests/api/test_ripemd.h>
#include <tests/api/test_hash.h>
#include <tests/api/test_hmac.h>
#include <tests/api/test_cmac.h>
#include <tests/api/test_des3.h>
#include <tests/api/test_chacha.h>
#include <tests/api/test_poly1305.h>
#include <tests/api/test_chacha20_poly1305.h>
#include <tests/api/test_camellia.h>
#include <tests/api/test_arc4.h>
#include <tests/api/test_rc2.h>
#include <tests/api/test_aes.h>
#include <tests/api/test_ascon.h>
#include <tests/api/test_sm4.h>
#include <tests/api/test_wc_encrypt.h>
#include <tests/api/test_mlkem.h>
#include <tests/api/test_dtls.h>
#include <tests/api/test_ocsp.h>

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_TLS) && \
    !defined(NO_RSA)        && !defined(SINGLE_THREADED) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_WOLFSSL_CLIENT)
    #define HAVE_IO_TESTS_DEPENDENCIES
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_TLS) && \
    !defined(NO_RSA) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_TIRTOS)
    #define HAVE_SSL_MEMIO_TESTS_DEPENDENCIES
#endif

#if !defined(NO_RSA) && !defined(NO_SHA) && !defined(NO_FILESYSTEM) && \
    !defined(NO_CERTS) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH))
    #define HAVE_CERT_CHAIN_VALIDATION
#endif

#ifndef WOLFSSL_HAVE_ECC_KEY_GET_PRIV
    /* FIPS build has replaced ecc.h. */
    #define wc_ecc_key_get_priv(key) (&((key)->k))
    #define WOLFSSL_HAVE_ECC_KEY_GET_PRIV
#endif

#if defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFCRYPT_ONLY)
    #if (defined(HAVE_ECC) && !defined(ALT_ECC_SIZE)) || defined(SESSION_CERTS)
        #ifdef OPENSSL_EXTRA
            #define TEST_TLS_STATIC_MEMSZ (400000)
        #else
            #define TEST_TLS_STATIC_MEMSZ (320000)
        #endif
    #else
            #define TEST_TLS_STATIC_MEMSZ (80000)
    #endif
#endif

#ifdef HAVE_ECC
    #ifndef ECC_ASN963_MAX_BUF_SZ
        #define ECC_ASN963_MAX_BUF_SZ 133
    #endif
    #ifndef ECC_PRIV_KEY_BUF
        #define ECC_PRIV_KEY_BUF 66  /* For non user defined curves. */
    #endif
    /* ecc key sizes: 14, 16, 20, 24, 28, 30, 32, 40, 48, 64 */
    /* logic to choose right key ECC size */
    #if (defined(HAVE_ECC112) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 112
        #define KEY14 14
    #else
        #define KEY14 32
    #endif
    #if (defined(HAVE_ECC128) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 128
        #define KEY16 16
    #else
        #define KEY16 32
    #endif
    #if (defined(HAVE_ECC160) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 160
        #define KEY20 20
    #else
        #define KEY20 32
    #endif
    #if (defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 192
        #define KEY24 24
    #else
        #define KEY24 32
    #endif
    #if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
        #define KEY28 28
    #else
        #define KEY28 32
    #endif
    #if defined(HAVE_ECC239) || defined(HAVE_ALL_CURVES)
        #define KEY30 30
    #else
        #define KEY30 32
    #endif
    #define KEY32 32
    #if defined(HAVE_ECC320) || defined(HAVE_ALL_CURVES)
        #define KEY40 40
    #else
        #define KEY40 32
    #endif
    #if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
        #define KEY48 48
    #else
        #define KEY48 32
    #endif
    #if defined(HAVE_ECC512) || defined(HAVE_ALL_CURVES)
        #define KEY64 64
    #else
        #define KEY64 32
    #endif

    #if !defined(HAVE_COMP_KEY)
        #if !defined(NOCOMP)
            #define NOCOMP 0
        #endif
    #else
        #if !defined(COMP)
            #define COMP 1
        #endif
    #endif
    #if !defined(DER_SZ)
        #define DER_SZ(ks) ((ks) * 2 + 1)
    #endif
#endif /* HAVE_ECC */

#ifndef NO_DSA
    #ifndef DSA_SIG_SIZE
        #define DSA_SIG_SIZE 40
    #endif
    #ifndef MAX_DSA_PARAM_SIZE
        #define MAX_DSA_PARAM_SIZE 256
    #endif
#endif

#ifndef NO_RSA
    #define GEN_BUF  294
#endif

#ifndef ONEK_BUF
    #define ONEK_BUF 1024
#endif
#ifndef TWOK_BUF
    #define TWOK_BUF 2048
#endif
#ifndef FOURK_BUF
    #define FOURK_BUF 4096
#endif


#if defined(HAVE_PKCS7)
    typedef struct {
        const byte* content;
        word32      contentSz;
        int         contentOID;
        int         encryptOID;
        int         keyWrapOID;
        int         keyAgreeOID;
        byte*       cert;
        size_t      certSz;
        byte*       privateKey;
        word32      privateKeySz;
    } pkcs7EnvelopedVector;

    #ifndef NO_PKCS7_ENCRYPTED_DATA
        typedef struct {
            const byte*     content;
            word32          contentSz;
            int             contentOID;
            int             encryptOID;
            byte*           encryptionKey;
            word32          encryptionKeySz;
        } pkcs7EncryptedVector;
    #endif
#endif /* HAVE_PKCS7 */

#ifdef WOLFSSL_DUMP_MEMIO_STREAM
const char* currentTestName;
char tmpDirName[16];
int tmpDirNameSet = 0;
#endif

/*----------------------------------------------------------------------------*
 | Constants
 *----------------------------------------------------------------------------*/

#ifndef NO_RSA
#if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 4)) && \
    (defined(RSA_MIN_SIZE) && (RSA_MIN_SIZE <= 1024))
#define TEST_RSA_BITS 1024
#else
#define TEST_RSA_BITS 2048
#endif
#define TEST_RSA_BYTES (TEST_RSA_BITS/8)
#endif /* !NO_RSA */

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_TLS) && \
    (!defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT))
    static const char* bogusFile  =
    #ifdef _WIN32
        "NUL"
    #else
        "/dev/null"
    #endif
    ;
#endif /* !NO_FILESYSTEM && !NO_CERTS && (!NO_WOLFSSL_SERVER || !NO_WOLFSSL_CLIENT) */

enum {
    TESTING_RSA = 1,
    TESTING_ECC = 2
};

#ifdef WOLFSSL_QNX_CAAM
#include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>
int testDevId = WOLFSSL_CAAM_DEVID;
#else
int testDevId = INVALID_DEVID;
#endif

/*----------------------------------------------------------------------------*
 | BIO with fixed read/write size
 *----------------------------------------------------------------------------*/

#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)

static int wolfssl_bio_s_fixed_mem_write(WOLFSSL_BIO* bio, const char* data,
    int len)
{
    if ((bio == NULL) || (bio->ptr.mem_buf_data == NULL) || (data == NULL)) {
        len = 0;
    }
    else {
        if (bio->wrSz - bio->wrIdx < len) {
            len = bio->wrSz - bio->wrIdx;
        }
        XMEMCPY(bio->ptr.mem_buf_data + bio->wrIdx, data, (size_t)len);
        bio->wrIdx += len;
    }

    return len;
}

static int wolfssl_bio_s_fixed_mem_read(WOLFSSL_BIO* bio, char* data, int len)
{
    if ((bio == NULL) || (bio->ptr.mem_buf_data == NULL) || (data == NULL)) {
        len = 0;
    }
    else {
        if (bio->wrSz - bio->rdIdx < len) {
            len = bio->wrSz - bio->rdIdx;
        }
        XMEMCPY(data, bio->ptr.mem_buf_data + bio->rdIdx, (size_t)len);
        bio->rdIdx += len;
    }

    return len;
}

static WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_fixed_mem(void)
{
    static WOLFSSL_BIO_METHOD meth;

    meth.type = WOLFSSL_BIO_BIO;
    XMEMCPY(meth.name, "Fixed Memory Size", 18);
    meth.writeCb = wolfssl_bio_s_fixed_mem_write;
    meth.readCb = wolfssl_bio_s_fixed_mem_read;

    return &meth;
}

#endif

/*----------------------------------------------------------------------------*
 | Setup
 *----------------------------------------------------------------------------*/

static int test_wolfSSL_Init(void)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_Init(), WOLFSSL_SUCCESS);
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #endif
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
         NID_aes_128_ctr,
    #endif
    #ifndef NO_DES3
         NID_des_cbc,
         NID_des_ede3_cbc,
    #endif
    };
    int iv_lengths[] = {
    #ifdef HAVE_AES_CBC
         AES_BLOCK_SIZE,
    #endif
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
         GCM_NONCE_MID_SZ,
    #endif
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
         AES_BLOCK_SIZE,
    #endif
    #ifndef NO_DES3
         DES_BLOCK_SIZE,
         DES_BLOCK_SIZE,
    #endif
    };
    int nidsLen = (sizeof(nids)/sizeof(int));

    for (i = 0; i < nidsLen; i++) {
        const EVP_CIPHER* init = wolfSSL_EVP_get_cipherbynid(nids[i]);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        wolfSSL_EVP_CIPHER_CTX_init(ctx);

        ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_iv_length(ctx), iv_lengths[i]);

        EVP_CIPHER_CTX_free(ctx);
    }

    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_CIPHER_CTX_key_length(void)
{
    EXPECT_DECLS;
    byte key[AES_256_KEY_SIZE] = {0};
    byte iv[AES_BLOCK_SIZE] = {0};
    int i;
    int nids[] = {
    #ifdef HAVE_AES_CBC
         NID_aes_128_cbc,
         NID_aes_256_cbc,
    #endif
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
         NID_aes_128_gcm,
         NID_aes_256_gcm,
    #endif
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
         NID_aes_128_ctr,
         NID_aes_256_ctr,
    #endif
    #ifndef NO_DES3
         NID_des_cbc,
         NID_des_ede3_cbc,
    #endif
    };
    int key_lengths[] = {
    #ifdef HAVE_AES_CBC
        AES_128_KEY_SIZE,
        AES_256_KEY_SIZE,
    #endif
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
        AES_128_KEY_SIZE,
        AES_256_KEY_SIZE,
    #endif
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
        AES_128_KEY_SIZE,
        AES_256_KEY_SIZE,
    #endif
    #ifndef NO_DES3
         DES_KEY_SIZE,
         DES3_KEY_SIZE,
    #endif
    };
    int nidsLen = (sizeof(nids)/sizeof(int));

    for (i = 0; i < nidsLen; i++) {
        const EVP_CIPHER *init = wolfSSL_EVP_get_cipherbynid(nids[i]);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        wolfSSL_EVP_CIPHER_CTX_init(ctx);

        ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_key_length(ctx), key_lengths[i]);

        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_key_length(ctx, key_lengths[i]),
            WOLFSSL_SUCCESS);

        EVP_CIPHER_CTX_free(ctx);
    }

    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_CIPHER_CTX_set_iv(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AESGCM) && !defined(NO_DES3)
    int ivLen, keyLen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
#ifdef HAVE_AESGCM
    byte key[AES_128_KEY_SIZE] = {0};
    byte iv[AES_BLOCK_SIZE] = {0};
    const EVP_CIPHER *init = EVP_aes_128_gcm();
#else
    byte key[DES3_KEY_SIZE] = {0};
    byte iv[DES_BLOCK_SIZE] = {0};
    const EVP_CIPHER *init = EVP_des_ede3_cbc();
#endif

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);

    ivLen = wolfSSL_EVP_CIPHER_CTX_iv_length(ctx);
    keyLen = wolfSSL_EVP_CIPHER_CTX_key_length(ctx);

    /* Bad cases */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(NULL, iv, ivLen),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, NULL, ivLen),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, iv, 0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(NULL, NULL, 0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, iv, keyLen),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* Good case */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, iv, ivLen), 1);

    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_PKEY_CTX_new_id(void)
{
    EXPECT_DECLS;
    WOLFSSL_ENGINE* e = NULL;
    int id = 0;
    EVP_PKEY_CTX *ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_EVP_PKEY_CTX_new_id(id, e));

    EVP_PKEY_CTX_free(ctx);

    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_rc4(void)
{
    EXPECT_DECLS;
#if !defined(NO_RC4)
    ExpectNotNull(wolfSSL_EVP_rc4());
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_enc_null(void)
{
    EXPECT_DECLS;
    ExpectNotNull(wolfSSL_EVP_enc_null());
    return EXPECT_RESULT();
}
static int test_wolfSSL_EVP_rc2_cbc(void)

{
    EXPECT_DECLS;
#if defined(WOLFSSL_QT) && !defined(NO_WOLFSSL_STUB)
    ExpectNull(wolfSSL_EVP_rc2_cbc());
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_mdc2(void)
{
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_STUB)
    ExpectNull(wolfSSL_EVP_mdc2());
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_md4(void)
{
    EXPECT_DECLS;
#if !defined(NO_MD4)
    ExpectNotNull(wolfSSL_EVP_md4());
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_aes_256_gcm(void)
{
    EXPECT_DECLS;
#ifdef HAVE_AESGCM
    ExpectNotNull(wolfSSL_EVP_aes_256_gcm());
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_aes_192_gcm(void)
{
    EXPECT_DECLS;
#ifdef HAVE_AESGCM
    ExpectNotNull(wolfSSL_EVP_aes_192_gcm());
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_aes_256_ccm(void)
{
    EXPECT_DECLS;
#ifdef HAVE_AESCCM
    ExpectNotNull(wolfSSL_EVP_aes_256_ccm());
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_aes_192_ccm(void)
{
    EXPECT_DECLS;
#ifdef HAVE_AESCCM
    ExpectNotNull(wolfSSL_EVP_aes_192_ccm());
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_aes_128_ccm(void)
{
    EXPECT_DECLS;
#ifdef HAVE_AESCCM
    ExpectNotNull(wolfSSL_EVP_aes_128_ccm());
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_ripemd160(void)
{
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_STUB)
    ExpectNull(wolfSSL_EVP_ripemd160());
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_get_digestbynid(void)
{
    EXPECT_DECLS;

#ifndef NO_MD5
    ExpectNotNull(wolfSSL_EVP_get_digestbynid(NID_md5));
#endif
#ifndef NO_SHA
    ExpectNotNull(wolfSSL_EVP_get_digestbynid(NID_sha1));
#endif
#ifndef NO_SHA256
    ExpectNotNull(wolfSSL_EVP_get_digestbynid(NID_sha256));
#endif
    ExpectNull(wolfSSL_EVP_get_digestbynid(0));

    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_MD_nid(void)
{
    EXPECT_DECLS;

#ifndef NO_MD5
    ExpectIntEQ(EVP_MD_nid(EVP_md5()), NID_md5);
#endif
#ifndef NO_SHA
    ExpectIntEQ(EVP_MD_nid(EVP_sha1()), NID_sha1);
#endif
#ifndef NO_SHA256
    ExpectIntEQ(EVP_MD_nid(EVP_sha256()), NID_sha256);
#endif
    ExpectIntEQ(EVP_MD_nid(NULL), NID_undef);

    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_PKEY_get0_EC_KEY(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC)
    WOLFSSL_EVP_PKEY* pkey = NULL;

    ExpectNull(EVP_PKEY_get0_EC_KEY(NULL));

    ExpectNotNull(pkey = EVP_PKEY_new());
    ExpectNull(EVP_PKEY_get0_EC_KEY(pkey));
    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_X_STATE(void)
{
    EXPECT_DECLS;
#if !defined(NO_DES3) && !defined(NO_RC4)
    byte key[DES3_KEY_SIZE] = {0};
    byte iv[DES_IV_SIZE] = {0};
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *init = NULL;

    /* Bad test cases */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectNotNull(init = EVP_des_ede3_cbc());

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);

    ExpectNull(wolfSSL_EVP_X_STATE(NULL));
    ExpectNull(wolfSSL_EVP_X_STATE(ctx));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Good test case */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectNotNull(init = wolfSSL_EVP_rc4());

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);

    ExpectNotNull(wolfSSL_EVP_X_STATE(ctx));
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}
static int test_wolfSSL_EVP_X_STATE_LEN(void)
{
    EXPECT_DECLS;
#if !defined(NO_DES3) && !defined(NO_RC4)
    byte key[DES3_KEY_SIZE] = {0};
    byte iv[DES_IV_SIZE] = {0};
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *init = NULL;

    /* Bad test cases */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectNotNull(init = EVP_des_ede3_cbc());

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_EVP_X_STATE_LEN(NULL), 0);
    ExpectIntEQ(wolfSSL_EVP_X_STATE_LEN(ctx), 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Good test case */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectNotNull(init = wolfSSL_EVP_rc4());

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_EVP_X_STATE_LEN(ctx), sizeof(Arc4));
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_CIPHER_block_size(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AES_CBC) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_COUNTER) || defined(HAVE_AES_ECB) || \
    defined(WOLFSSL_AES_OFB) || !defined(NO_RC4) || \
    (defined(HAVE_CHACHA) && defined(HAVE_POLY1305))

#ifdef HAVE_AES_CBC
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_cbc()), AES_BLOCK_SIZE);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_cbc()), AES_BLOCK_SIZE);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_cbc()), AES_BLOCK_SIZE);
    #endif
#endif

#ifdef HAVE_AESGCM
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_gcm()), 1);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_gcm()), 1);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_gcm()), 1);
    #endif
#endif

#ifdef HAVE_AESCCM
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_ccm()), 1);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_ccm()), 1);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_ccm()), 1);
    #endif
#endif

#ifdef WOLFSSL_AES_COUNTER
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_ctr()), 1);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_ctr()), 1);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_ctr()), 1);
    #endif
#endif

#ifdef HAVE_AES_ECB
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_ecb()), AES_BLOCK_SIZE);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_ecb()), AES_BLOCK_SIZE);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_ecb()), AES_BLOCK_SIZE);
    #endif
#endif

#ifdef WOLFSSL_AES_OFB
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_ofb()), 1);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_ofb()), 1);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_ofb()), 1);
    #endif
#endif

#ifndef NO_RC4
    ExpectIntEQ(EVP_CIPHER_block_size(wolfSSL_EVP_rc4()), 1);
#endif

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    ExpectIntEQ(EVP_CIPHER_block_size(wolfSSL_EVP_chacha20_poly1305()), 1);
#endif
#endif

#ifdef WOLFSSL_SM4_ECB
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_sm4_ecb()), SM4_BLOCK_SIZE);
#endif
#ifdef WOLFSSL_SM4_CBC
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_sm4_cbc()), SM4_BLOCK_SIZE);
#endif
#ifdef WOLFSSL_SM4_CTR
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_sm4_ctr()), 1);
#endif
#ifdef WOLFSSL_SM4_GCM
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_sm4_gcm()), 1);
#endif
#ifdef WOLFSSL_SM4_CCM
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_sm4_ccm()), 1);
#endif

    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_CIPHER_iv_length(void)
{
    EXPECT_DECLS;
    int nids[] = {
    #if defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT)
    #ifdef WOLFSSL_AES_128
        NID_aes_128_cbc,
    #endif
    #ifdef WOLFSSL_AES_192
        NID_aes_192_cbc,
    #endif
    #ifdef WOLFSSL_AES_256
        NID_aes_256_cbc,
    #endif
    #endif /* HAVE_AES_CBC || WOLFSSL_AES_DIRECT */
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
        #ifdef WOLFSSL_AES_128
            NID_aes_128_gcm,
        #endif
        #ifdef WOLFSSL_AES_192
            NID_aes_192_gcm,
        #endif
        #ifdef WOLFSSL_AES_256
            NID_aes_256_gcm,
        #endif
    #endif /* HAVE_AESGCM */
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
    #ifdef WOLFSSL_AES_128
         NID_aes_128_ctr,
    #endif
    #ifdef WOLFSSL_AES_192
        NID_aes_192_ctr,
    #endif
    #ifdef WOLFSSL_AES_256
        NID_aes_256_ctr,
    #endif
    #endif
    #ifndef NO_DES3
         NID_des_cbc,
         NID_des_ede3_cbc,
    #endif
    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
         NID_chacha20_poly1305,
    #endif
    };
    int iv_lengths[] = {
    #if defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT)
    #ifdef WOLFSSL_AES_128
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_192
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_256
            AES_BLOCK_SIZE,
    #endif
    #endif /* HAVE_AES_CBC || WOLFSSL_AES_DIRECT */
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
        #ifdef WOLFSSL_AES_128
            GCM_NONCE_MID_SZ,
        #endif
        #ifdef WOLFSSL_AES_192
            GCM_NONCE_MID_SZ,
        #endif
        #ifdef WOLFSSL_AES_256
            GCM_NONCE_MID_SZ,
        #endif
    #endif /* HAVE_AESGCM */
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
    #ifdef WOLFSSL_AES_128
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_192
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_256
            AES_BLOCK_SIZE,
    #endif
    #endif
    #ifndef NO_DES3
            DES_BLOCK_SIZE,
            DES_BLOCK_SIZE,
    #endif
    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            CHACHA20_POLY1305_AEAD_IV_SIZE,
    #endif
    };
    int i;
    int nidsLen = (sizeof(nids)/sizeof(int));

    for (i = 0; i < nidsLen; i++) {
        const EVP_CIPHER *c = EVP_get_cipherbynid(nids[i]);
        ExpectIntEQ(EVP_CIPHER_iv_length(c), iv_lengths[i]);
    }

    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_SignInit_ex(void)
{
    EXPECT_DECLS;
    WOLFSSL_EVP_MD_CTX mdCtx;
    WOLFSSL_ENGINE*    e = 0;
    const EVP_MD*      md = EVP_sha256();

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_SignInit_ex(&mdCtx, md, e), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_DigestFinalXOF(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_SHAKE256) && defined(OPENSSL_ALL)
    WOLFSSL_EVP_MD_CTX mdCtx;
    unsigned char      shake[256];
    unsigned char      zeros[10];
    unsigned char      data[] = "Test data";
    unsigned int sz;

    XMEMSET(zeros, 0, sizeof(zeros));
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(EVP_DigestInit(&mdCtx, EVP_shake256()), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_MD_flags(EVP_shake256()), EVP_MD_FLAG_XOF);
    ExpectIntEQ(EVP_MD_flags(EVP_sha3_256()), 0);
    ExpectIntEQ(EVP_DigestUpdate(&mdCtx, data, 1), WOLFSSL_SUCCESS);
    XMEMSET(shake, 0, sizeof(shake));
    ExpectIntEQ(EVP_DigestFinalXOF(&mdCtx, shake, 10), WOLFSSL_SUCCESS);

    /* make sure was only size of 10 */
    ExpectIntEQ(XMEMCMP(&shake[11], zeros, 10), 0);
    ExpectIntEQ(EVP_MD_CTX_cleanup(&mdCtx), WOLFSSL_SUCCESS);

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(EVP_DigestInit(&mdCtx, EVP_shake256()), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(&mdCtx, data, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestFinal(&mdCtx, shake, &sz), WOLFSSL_SUCCESS);
    ExpectIntEQ(sz, 32);
    ExpectIntEQ(EVP_MD_CTX_cleanup(&mdCtx), WOLFSSL_SUCCESS);

    #if defined(WOLFSSL_SHAKE128)
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(EVP_DigestInit(&mdCtx, EVP_shake128()), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(&mdCtx, data, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestFinal(&mdCtx, shake, &sz), WOLFSSL_SUCCESS);
    ExpectIntEQ(sz, 16);
    ExpectIntEQ(EVP_MD_CTX_cleanup(&mdCtx), WOLFSSL_SUCCESS);
    #endif
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_DigestFinal_ex(void)
{
    EXPECT_DECLS;
#if !defined(NO_SHA256)
    WOLFSSL_EVP_MD_CTX mdCtx;
    unsigned int       s = 0;
    unsigned char      md[WC_SHA256_DIGEST_SIZE];
    unsigned char      md2[WC_SHA256_DIGEST_SIZE];

    /* Bad Case */
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION > 2))
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestFinal_ex(&mdCtx, md, &s), 0);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

#else
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestFinal_ex(&mdCtx, md, &s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), WOLFSSL_SUCCESS);

#endif

    /* Good Case */
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, EVP_sha256()), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_DigestFinal_ex(&mdCtx, md2, &s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), WOLFSSL_SUCCESS);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_QT_EVP_PKEY_CTX_free(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    EVP_PKEY*     pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;

    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* void */
    EVP_PKEY_CTX_free(ctx);
#else
    /* int */
    ExpectIntEQ(EVP_PKEY_CTX_free(ctx), WOLFSSL_SUCCESS);
#endif

    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_PKEY_param_check(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA) && !defined(NO_FILESYSTEM)

    DH       *dh    = NULL;
    DH       *setDh = NULL;
    EVP_PKEY *pkey  = NULL;
    EVP_PKEY_CTX*   ctx = NULL;

    FILE* f = NULL;
    unsigned char buf[512];
    const unsigned char* pt = buf;
    const char* dh2048 = "./certs/dh2048.der";
    long len = 0;
    int code = -1;

    XMEMSET(buf, 0, sizeof(buf));

    ExpectTrue((f = XFOPEN(dh2048, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    /* Load dh2048.der into DH with internal format */
    ExpectNotNull(setDh = d2i_DHparams(NULL, &pt, len));
    ExpectIntEQ(DH_check(setDh, &code), WOLFSSL_SUCCESS);
    ExpectIntEQ(code, 0);
    code = -1;

    pkey = wolfSSL_EVP_PKEY_new();
    /* Set DH into PKEY */
    ExpectIntEQ(EVP_PKEY_set1_DH(pkey, setDh), WOLFSSL_SUCCESS);
    /* create ctx from pkey */
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_param_check(ctx), 1/* valid */);

    /* TODO: more invalid cases */
    ExpectIntEQ(EVP_PKEY_param_check(NULL), 0);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    DH_free(setDh);
    setDh = NULL;
    DH_free(dh);
    dh = NULL;
#endif
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_BytesToKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    byte                key[AES_BLOCK_SIZE] = {0};
    byte                iv[AES_BLOCK_SIZE] = {0};
    int                 count = 0;
    const               EVP_MD* md = EVP_sha256();
    const EVP_CIPHER    *type;
    const unsigned char *salt = (unsigned char *)"salt1234";
    int                 sz = 5;
    const byte data[] = {
        0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f,
        0x72,0x6c,0x64
    };

    type = wolfSSL_EVP_get_cipherbynid(NID_aes_128_cbc);

    /* Bad cases */
    ExpectIntEQ(EVP_BytesToKey(NULL, md, salt, data, sz, count, key, iv),
                 0);
    ExpectIntEQ(EVP_BytesToKey(type, md, salt, NULL, sz, count, key, iv),
                16);
    md = "2";
    ExpectIntEQ(EVP_BytesToKey(type, md, salt, data, sz, count, key, iv),
                 WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* Good case */
    md = EVP_sha256();
    ExpectIntEQ(EVP_BytesToKey(type, md, salt, data, sz, count, key, iv),
                 16);
#endif
    return EXPECT_RESULT();
}


    return EXPECT_RESULT();
#if defined(HAVE_AESGCM) && ((!defined(HAVE_FIPS) && \
        sizeof(plainText1),
        sizeof(plainText2),
        sizeof(plainText3)
    };
    static const byte aad1[AAD_SIZE] = {
        0x00, 0x00, 0x00, 0x01
    };
    static const byte aad2[AAD_SIZE] = {
        0x00, 0x00, 0x00, 0x10
    };
    static const byte aad3[AAD_SIZE] = {
        0x00, 0x00, 0x01, 0x00
    };
    static const byte* aads[NUM_ENCRYPTIONS] = {
        aad1,
        aad2,
        aad3
    };
    const byte iv[GCM_NONCE_MID_SZ] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
    };
    byte currentIv[GCM_NONCE_MID_SZ];
    const byte key[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    const byte expIvs[NUM_ENCRYPTIONS][GCM_NONCE_MID_SZ] = {
        {
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
            0xEF
        },
        {
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
            0xF0
        },
        {
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
            0xF1
        }
    };
    const byte expTags[NUM_ENCRYPTIONS][AES_BLOCK_SIZE] = {
        {
            0x65, 0x4F, 0xF7, 0xA0, 0xBB, 0x7B, 0x90, 0xB7, 0x9C, 0xC8, 0x14,
            0x3D, 0x32, 0x18, 0x34, 0xA9
        },
        {
            0x50, 0x3A, 0x13, 0x8D, 0x91, 0x1D, 0xEC, 0xBB, 0xBA, 0x5B, 0x57,
            0xA2, 0xFD, 0x2D, 0x6B, 0x7F
        },
        {
            0x3B, 0xED, 0x18, 0x9C, 0xB3, 0xE3, 0x61, 0x1E, 0x11, 0xEB, 0x13,
            0x5B, 0xEC, 0x52, 0x49, 0x32,
        }
    };
    static const byte expCipherText1[] = {
        0xCB, 0x93, 0x4F, 0xC8, 0x22, 0xE2, 0xC0, 0x35, 0xAA, 0x6B, 0x41, 0x15,
        0x17, 0x30, 0x2F, 0x97, 0x20, 0x74, 0x39, 0x28, 0xF8, 0xEB, 0xC5, 0x51,
        0x7B, 0xD9, 0x8A, 0x36, 0xB8, 0xDA, 0x24, 0x80, 0xE7, 0x9E, 0x09, 0xDE
    };
    static const byte expCipherText2[] = {
        0xF9, 0x32, 0xE1, 0x87, 0x37, 0x0F, 0x04, 0xC1, 0xB5, 0x59, 0xF0, 0x45,
        0x3A, 0x0D, 0xA0, 0x26, 0xFF, 0xA6, 0x8D, 0x38, 0xFE, 0xB8, 0xE5, 0xC2,
        0x2A, 0x98, 0x4A, 0x54, 0x8F, 0x1F, 0xD6, 0x13, 0x03, 0xB2, 0x1B, 0xC0
    };
    static const byte expCipherText3[] = {
        0xD0, 0x37, 0x59, 0x1C, 0x2F, 0x85, 0x39, 0x4D, 0xED, 0xC2, 0x32, 0x5B,
        0x80, 0x5E, 0x6B,
    };
    static const byte* expCipherTexts[NUM_ENCRYPTIONS] = {
        expCipherText1,
        expCipherText2,
        expCipherText3
    };
    byte* cipherText = NULL;
    byte* calcPlainText = NULL;
    byte tag[AES_BLOCK_SIZE];
    EVP_CIPHER_CTX* encCtx = NULL;
    EVP_CIPHER_CTX* decCtx = NULL;
    int i, j, outl;

    /****************************************************/
    for (i = 0; i < 3; ++i) {
        ExpectNotNull(encCtx = EVP_CIPHER_CTX_new());
        ExpectNotNull(decCtx = EVP_CIPHER_CTX_new());

        /* First iteration, set key before IV. */
        if (i == 0) {
            ExpectIntEQ(EVP_CipherInit(encCtx, EVP_aes_256_gcm(), key, NULL, 1),
                        SSL_SUCCESS);

            /*
             * The call to EVP_CipherInit below (with NULL key) should clear the
             * authIvGenEnable flag set by EVP_CTRL_GCM_SET_IV_FIXED. As such, a
             * subsequent EVP_CTRL_GCM_IV_GEN should fail. This matches OpenSSL
             * behavior.
             */
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_SET_IV_FIXED, -1,
                    (void*)iv), SSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(encCtx, NULL, NULL, iv, 1),
                        SSL_SUCCESS);
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_IV_GEN, -1,
                        currentIv), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

            ExpectIntEQ(EVP_CipherInit(decCtx, EVP_aes_256_gcm(), key, NULL, 0),
                        SSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(decCtx, NULL, NULL, iv, 0),
                        SSL_SUCCESS);
        }
        /* Second iteration, IV before key. */
        else {
            ExpectIntEQ(EVP_CipherInit(encCtx, EVP_aes_256_gcm(), NULL, iv, 1),
                        SSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(encCtx, NULL, key, NULL, 1),
                        SSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(decCtx, EVP_aes_256_gcm(), NULL, iv, 0),
                        SSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(decCtx, NULL, key, NULL, 0),
                        SSL_SUCCESS);
        }

        /*
         * EVP_CTRL_GCM_IV_GEN should fail if EVP_CTRL_GCM_SET_IV_FIXED hasn't
         * been issued first.
         */
        ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_IV_GEN, -1,
                        currentIv), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

        ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_SET_IV_FIXED, -1,
                    (void*)iv), SSL_SUCCESS);
        ExpectIntEQ(EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_SET_IV_FIXED, -1,
                    (void*)iv), SSL_SUCCESS);

        for (j = 0; j < NUM_ENCRYPTIONS; ++j) {
            /*************** Encrypt ***************/
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_IV_GEN, -1,
                        currentIv), SSL_SUCCESS);
            /* Check current IV against expected. */
            ExpectIntEQ(XMEMCMP(currentIv, expIvs[j], GCM_NONCE_MID_SZ), 0);

            /* Add AAD. */
            if (i == 2) {
                /* Test streaming API. */
                ExpectIntEQ(EVP_CipherUpdate(encCtx, NULL, &outl, aads[j],
                                             AAD_SIZE), SSL_SUCCESS);
            }
            else {
                ExpectIntEQ(EVP_Cipher(encCtx, NULL, (byte *)aads[j], AAD_SIZE),
                                       AAD_SIZE);
            }

            ExpectNotNull(cipherText = (byte*)XMALLOC(plainTextSzs[j], NULL,
                          DYNAMIC_TYPE_TMP_BUFFER));

            /* Encrypt plaintext. */
            if (i == 2) {
                ExpectIntEQ(EVP_CipherUpdate(encCtx, cipherText, &outl,
                                             plainTexts[j], plainTextSzs[j]),
                            SSL_SUCCESS);
            }
            else {
                ExpectIntEQ(EVP_Cipher(encCtx, cipherText, (byte *)plainTexts[j],
                            plainTextSzs[j]), plainTextSzs[j]);
            }

            if (i == 2) {
                ExpectIntEQ(EVP_CipherFinal(encCtx, cipherText, &outl),
                            SSL_SUCCESS);
            }
            else {
                /*
                 * Calling EVP_Cipher with NULL input and output for AES-GCM is
                 * akin to calling EVP_CipherFinal.
                 */
                ExpectIntGE(EVP_Cipher(encCtx, NULL, NULL, 0), 0);
            }

            /* Check ciphertext against expected. */
            ExpectIntEQ(XMEMCMP(cipherText, expCipherTexts[j], plainTextSzs[j]),
                        0);

            /* Get and check tag against expected. */
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_GET_TAG,
                        sizeof(tag), tag), SSL_SUCCESS);
            ExpectIntEQ(XMEMCMP(tag, expTags[j], sizeof(tag)), 0);

            /*************** Decrypt ***************/
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_IV_GEN, -1,
                        currentIv), SSL_SUCCESS);
            /* Check current IV against expected. */
            ExpectIntEQ(XMEMCMP(currentIv, expIvs[j], GCM_NONCE_MID_SZ), 0);

            /* Add AAD. */
            if (i == 2) {
                /* Test streaming API. */
                ExpectIntEQ(EVP_CipherUpdate(decCtx, NULL, &outl, aads[j],
                                             AAD_SIZE), SSL_SUCCESS);
            }
            else {
                ExpectIntEQ(EVP_Cipher(decCtx, NULL, (byte *)aads[j], AAD_SIZE),
                            AAD_SIZE);
            }

            /* Set expected tag. */
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_SET_TAG,
                        sizeof(tag), tag), SSL_SUCCESS);

            /* Decrypt ciphertext. */
            ExpectNotNull(calcPlainText = (byte*)XMALLOC(plainTextSzs[j], NULL,
                          DYNAMIC_TYPE_TMP_BUFFER));
            if (i == 2) {
                ExpectIntEQ(EVP_CipherUpdate(decCtx, calcPlainText, &outl,
                                             cipherText, plainTextSzs[j]),
                            SSL_SUCCESS);
            }
            else {
                /* This first EVP_Cipher call will check the tag, too. */
                ExpectIntEQ(EVP_Cipher(decCtx, calcPlainText, cipherText,
                        plainTextSzs[j]), plainTextSzs[j]);
            }

            if (i == 2) {
                ExpectIntEQ(EVP_CipherFinal(decCtx, calcPlainText, &outl),
                            SSL_SUCCESS);
            }
            else {
                ExpectIntGE(EVP_Cipher(decCtx, NULL, NULL, 0), 0);
            }

            /* Check plaintext against expected. */
            ExpectIntEQ(XMEMCMP(calcPlainText, plainTexts[j], plainTextSzs[j]),
                        0);

            XFREE(cipherText, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            cipherText = NULL;
            XFREE(calcPlainText, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            calcPlainText = NULL;
        }

        EVP_CIPHER_CTX_free(encCtx);
        encCtx = NULL;
        EVP_CIPHER_CTX_free(decCtx);
        decCtx = NULL;
    }
#endif
    return EXPECT_RESULT();
}
static int test_wolfSSL_OBJ_ln(void)
{
    EXPECT_DECLS;
    const int nid_set[] = {
            NID_commonName,
            NID_serialNumber,
            NID_countryName,
            NID_localityName,
            NID_stateOrProvinceName,
            NID_organizationName,
            NID_organizationalUnitName,
            NID_domainComponent,
            NID_businessCategory,
            NID_jurisdictionCountryName,
            NID_jurisdictionStateOrProvinceName,
            NID_emailAddress
    };
    const char* ln_set[] = {
            "commonName",
            "serialNumber",
            "countryName",
            "localityName",
            "stateOrProvinceName",
            "organizationName",
            "organizationalUnitName",
            "domainComponent",
            "businessCategory",
            "jurisdictionCountryName",
            "jurisdictionStateOrProvinceName",
            "emailAddress",
    };
    size_t i = 0, maxIdx = sizeof(ln_set)/sizeof(char*);

    ExpectIntEQ(OBJ_ln2nid(NULL), NID_undef);

#ifdef HAVE_ECC
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    {
        EC_builtin_curve r[27];
        size_t nCurves = sizeof(r) / sizeof(r[0]);
        nCurves = EC_get_builtin_curves(r, nCurves);

        for (i = 0; i < nCurves; i++) {
            /* skip ECC_CURVE_INVALID */
            if (r[i].nid != ECC_CURVE_INVALID) {
                ExpectIntEQ(OBJ_ln2nid(r[i].comment), r[i].nid);
                ExpectStrEQ(OBJ_nid2ln(r[i].nid), r[i].comment);
            }
        }
    }
#endif
#endif

    for (i = 0; i < maxIdx; i++) {
        ExpectIntEQ(OBJ_ln2nid(ln_set[i]), nid_set[i]);
        ExpectStrEQ(OBJ_nid2ln(nid_set[i]), ln_set[i]);
    }

    return EXPECT_RESULT();
}

static int test_wolfSSL_OBJ_sn(void)
{
    EXPECT_DECLS;
    int i = 0, maxIdx = 7;
    const int nid_set[] = {NID_commonName,NID_countryName,NID_localityName,
                           NID_stateOrProvinceName,NID_organizationName,
                           NID_organizationalUnitName,NID_emailAddress};
    const char* sn_open_set[] = {"CN","C","L","ST","O","OU","emailAddress"};

    ExpectIntEQ(wolfSSL_OBJ_sn2nid(NULL), NID_undef);
    for (i = 0; i < maxIdx; i++) {
        ExpectIntEQ(wolfSSL_OBJ_sn2nid(sn_open_set[i]), nid_set[i]);
        ExpectStrEQ(wolfSSL_OBJ_nid2sn(nid_set[i]), sn_open_set[i]);
    }

    return EXPECT_RESULT();
}

#if !defined(NO_BIO)
static word32 TXT_DB_hash(const WOLFSSL_STRING *s)
{
    return (word32)lh_strhash(s[3]);
}

static int TXT_DB_cmp(const WOLFSSL_STRING *a, const WOLFSSL_STRING *b)
{
    return XSTRCMP(a[3], b[3]);
}
#endif

static int test_wolfSSL_TXT_DB(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_BIO)
    BIO *bio = NULL;
    TXT_DB *db = NULL;
    const int columns = 6;
    const char *fields[6] = {
        "V",
        "320926161116Z",
        "",
        "12BD",
        "unknown",
        "/CN=rsa doe",
    };
    char** fields_copy = NULL;

    /* Test read */
    ExpectNotNull(bio = BIO_new(BIO_s_file()));
    ExpectIntGT(BIO_read_filename(bio, "./tests/TXT_DB.txt"), 0);
    ExpectNotNull(db = TXT_DB_read(bio, columns));
    ExpectNotNull(fields_copy = (char**)XMALLOC(sizeof(fields), NULL,
        DYNAMIC_TYPE_OPENSSL));
    if (fields_copy != NULL) {
        XMEMCPY(fields_copy, fields, sizeof(fields));
    }
    ExpectIntEQ(TXT_DB_insert(db, fields_copy), 1);
    if (EXPECT_FAIL()) {
        XFREE(fields_copy, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    BIO_free(bio);
    bio = NULL;

    /* Test write */
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(TXT_DB_write(bio, db), 1484);
    BIO_free(bio);

    /* Test index */
    ExpectIntEQ(TXT_DB_create_index(db, 3, NULL,
        (wolf_sk_hash_cb)(long unsigned int)TXT_DB_hash,
        (wolf_lh_compare_cb)TXT_DB_cmp), 1);
    ExpectNotNull(TXT_DB_get_by_index(db, 3, (WOLFSSL_STRING*)fields));
    fields[3] = "12DA";
    ExpectNotNull(TXT_DB_get_by_index(db, 3, (WOLFSSL_STRING*)fields));
    fields[3] = "FFFF";
    ExpectNull(TXT_DB_get_by_index(db, 3, (WOLFSSL_STRING*)fields));
    fields[3] = "";
    ExpectNull(TXT_DB_get_by_index(db, 3, (WOLFSSL_STRING*)fields));

    TXT_DB_free(db);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_NCONF(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_BIO)
    const char* confFile = "./tests/NCONF_test.cnf";
    CONF* conf = NULL;
    long eline = 0;
    long num = 0;

    ExpectNotNull(conf = NCONF_new(NULL));

    ExpectIntEQ(NCONF_load(conf, confFile, &eline), 1);
    ExpectIntEQ(NCONF_get_number(conf, NULL, "port", &num), 1);
    ExpectIntEQ(num, 1234);
    ExpectIntEQ(NCONF_get_number(conf, "section2", "port", &num), 1);
    ExpectIntEQ(num, 4321);
    ExpectStrEQ(NCONF_get_string(conf, NULL, "dir"), "./test-dir");
    ExpectStrEQ(NCONF_get_string(conf, "section1", "file1_copy"),
        "./test-dir/file1");
    ExpectStrEQ(NCONF_get_string(conf, "section2", "file_list"),
        "./test-dir/file1:./test-dir/file2:./section1:file2");

    NCONF_free(conf);
#endif
    return EXPECT_RESULT();
}
#endif /* OPENSSL_ALL */

static int test_wolfSSL_X509V3_set_ctx(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ)
    WOLFSSL_X509V3_CTX ctx;
    WOLFSSL_X509* issuer = NULL;
    WOLFSSL_X509* subject = NULL;
    WOLFSSL_X509 req;
    WOLFSSL_X509_CRL crl;

    XMEMSET(&ctx, 0, sizeof(ctx));
    ExpectNotNull(issuer = wolfSSL_X509_new());
    ExpectNotNull(subject = wolfSSL_X509_new());
    XMEMSET(&req, 0, sizeof(req));
    XMEMSET(&crl, 0, sizeof(crl));

    wolfSSL_X509V3_set_ctx(NULL, NULL, NULL, NULL, NULL, 0);
    wolfSSL_X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
    wolfSSL_X509_free(ctx.x509);
    ctx.x509 = NULL;
    wolfSSL_X509V3_set_ctx(&ctx, issuer, NULL, NULL, NULL, 0);
    wolfSSL_X509_free(ctx.x509);
    ctx.x509 = NULL;
    wolfSSL_X509V3_set_ctx(&ctx, NULL, subject, NULL, NULL, 0);
    wolfSSL_X509_free(ctx.x509);
    ctx.x509 = NULL;
    wolfSSL_X509V3_set_ctx(&ctx, NULL, NULL, &req, NULL, 0);
    wolfSSL_X509_free(ctx.x509);
    ctx.x509 = NULL;
    wolfSSL_X509V3_set_ctx(&ctx, NULL, NULL, NULL, &crl, 0);
    wolfSSL_X509_free(ctx.x509);
    ctx.x509 = NULL;
    wolfSSL_X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 1);
    /* X509 allocated in context results in 'failure' (but not return). */
    wolfSSL_X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
    wolfSSL_X509_free(ctx.x509);
    ctx.x509 = NULL;

    wolfSSL_X509_free(subject);
    wolfSSL_X509_free(issuer);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509V3_EXT_get(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    XFILE f = XBADFILE;
    int numOfExt =0;
    int extNid = 0;
    int i = 0;
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    const WOLFSSL_v3_ext_method* method = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;

    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    /* No object in extension. */
    ExpectNull(wolfSSL_X509V3_EXT_get(ext));
    ExpectNotNull(obj = wolfSSL_ASN1_OBJECT_new());
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    /* NID is zero. */
    ExpectNull(wolfSSL_X509V3_EXT_get(ext));
    /* NID is not known. */
    if (ext != NULL && ext->obj != NULL) {
        ext->obj->nid = 1;
    }
    ExpectNull(wolfSSL_X509V3_EXT_get(ext));

    /* NIDs not in certificate. */
    if (ext != NULL && ext->obj != NULL) {
        ext->obj->nid = NID_certificate_policies;
    }
    ExpectNotNull(method = wolfSSL_X509V3_EXT_get(ext));
    ExpectIntEQ(method->ext_nid, NID_certificate_policies);
    if (ext != NULL && ext->obj != NULL) {
        ext->obj->nid = NID_crl_distribution_points;
    }
    ExpectNotNull(method = wolfSSL_X509V3_EXT_get(ext));
    ExpectIntEQ(method->ext_nid, NID_crl_distribution_points);

    wolfSSL_ASN1_OBJECT_free(obj);
    wolfSSL_X509_EXTENSION_free(ext);
    ext = NULL;

    ExpectTrue((f = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE)
        XFCLOSE(f);

    /* wolfSSL_X509V3_EXT_get() return struct and nid test */
    ExpectIntEQ((numOfExt = wolfSSL_X509_get_ext_count(x509)), 5);
    for (i = 0; i < numOfExt; i++) {
        ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, i));
        ExpectIntNE((extNid = ext->obj->nid), NID_undef);
        ExpectNotNull(method = wolfSSL_X509V3_EXT_get(ext));
        ExpectIntEQ(method->ext_nid, extNid);
        if (method->ext_nid == NID_subject_key_identifier) {
            ExpectNotNull(method->i2s);
        }
    }

    /* wolfSSL_X509V3_EXT_get() NULL argument test */
    ExpectNull(method = wolfSSL_X509V3_EXT_get(NULL));

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509V3_EXT_nconf(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    const char *ext_names[] = {
        "subjectKeyIdentifier",
        "authorityKeyIdentifier",
        "subjectAltName",
        "keyUsage",
        "extendedKeyUsage",
    };
    size_t ext_names_count = sizeof(ext_names)/sizeof(*ext_names);
    int ext_nids[] = {
        NID_subject_key_identifier,
        NID_authority_key_identifier,
        NID_subject_alt_name,
        NID_key_usage,
        NID_ext_key_usage,
    };
    size_t ext_nids_count = sizeof(ext_nids)/sizeof(*ext_nids);
    const char *ext_values[] = {
        "hash",
        "hash",
        "DNS:example.com, IP:127.0.0.1",
        "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,"
            "keyAgreement,keyCertSign,cRLSign,encipherOnly,decipherOnly",
        "serverAuth,clientAuth,codeSigning,emailProtection,timeStamping,"
            "OCSPSigning",
    };
    size_t i;
    X509_EXTENSION* ext = NULL;
    X509* x509 = NULL;
    unsigned int keyUsageFlags;
    unsigned int extKeyUsageFlags;
    WOLFSSL_CONF conf;
    WOLFSSL_X509V3_CTX ctx;
#ifndef NO_WOLFSSL_STUB
    WOLFSSL_LHASH lhash;
#endif

    ExpectNotNull(x509 = X509_new());
    ExpectNull(X509V3_EXT_nconf(NULL, NULL, ext_names[0], NULL));
    ExpectNull(X509V3_EXT_nconf_nid(NULL, NULL, ext_nids[0], NULL));
    ExpectNull(X509V3_EXT_nconf(NULL, NULL, "", ext_values[0]));
    ExpectNull(X509V3_EXT_nconf_nid(NULL, NULL, 0, ext_values[0]));

    /* conf and ctx ignored. */
    ExpectNull(X509V3_EXT_nconf_nid(&conf, NULL, 0, ext_values[0]));
    ExpectNull(X509V3_EXT_nconf_nid(NULL , &ctx, 0, ext_values[0]));
    ExpectNull(X509V3_EXT_nconf_nid(&conf, &ctx, 0, ext_values[0]));

    /* keyUsage / extKeyUsage should match string above */
    keyUsageFlags = KU_DIGITAL_SIGNATURE
                  | KU_NON_REPUDIATION
                  | KU_KEY_ENCIPHERMENT
                  | KU_DATA_ENCIPHERMENT
                  | KU_KEY_AGREEMENT
                  | KU_KEY_CERT_SIGN
                  | KU_CRL_SIGN
                  | KU_ENCIPHER_ONLY
                  | KU_DECIPHER_ONLY;
    extKeyUsageFlags = XKU_SSL_CLIENT
                     | XKU_SSL_SERVER
                     | XKU_CODE_SIGN
                     | XKU_SMIME
                     | XKU_TIMESTAMP
                     | XKU_OCSP_SIGN;

    for (i = 0; i < ext_names_count; i++) {
        ExpectNotNull(ext = X509V3_EXT_nconf(NULL, NULL, ext_names[i],
            ext_values[i]));
        X509_EXTENSION_free(ext);
        ext = NULL;
    }

    for (i = 0; i < ext_nids_count; i++) {
        ExpectNotNull(ext = X509V3_EXT_nconf_nid(NULL, NULL, ext_nids[i],
            ext_values[i]));
        X509_EXTENSION_free(ext);
        ext = NULL;
    }

    /* Test adding extension to X509 */
    for (i = 0; i < ext_nids_count; i++) {
        ExpectNotNull(ext = X509V3_EXT_nconf(NULL, NULL, ext_names[i],
            ext_values[i]));
        ExpectIntEQ(X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);

        if (ext_nids[i] == NID_key_usage) {
            ExpectIntEQ(X509_get_key_usage(x509), keyUsageFlags);
        }
        else if (ext_nids[i] == NID_ext_key_usage) {
            ExpectIntEQ(X509_get_extended_key_usage(x509), extKeyUsageFlags);
        }
        X509_EXTENSION_free(ext);
        ext = NULL;
    }
    X509_free(x509);

#ifndef NO_WOLFSSL_STUB
    ExpectIntEQ(wolfSSL_X509V3_EXT_add_nconf(NULL, NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    ExpectNull(wolfSSL_X509V3_EXT_conf_nid(NULL, NULL, 0, NULL));
    ExpectNull(wolfSSL_X509V3_EXT_conf_nid(&lhash, NULL, 0, NULL));
    wolfSSL_X509V3_set_ctx_nodb(NULL);
#endif
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509V3_EXT_bc(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    WOLFSSL_BASIC_CONSTRAINTS* bc = NULL;
    WOLFSSL_ASN1_INTEGER* pathLen = NULL;

    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectNotNull(obj = wolfSSL_ASN1_OBJECT_new());
    ExpectNotNull(pathLen = wolfSSL_ASN1_INTEGER_new());
    if (pathLen != NULL) {
        pathLen->length = 2;
    }

    if (obj != NULL) {
        obj->type = NID_basic_constraints;
        obj->nid = NID_basic_constraints;
    }
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    ExpectNotNull(wolfSSL_X509V3_EXT_get(ext));
    /* No pathlen set. */
    ExpectNotNull(bc = (WOLFSSL_BASIC_CONSTRAINTS*)wolfSSL_X509V3_EXT_d2i(ext));
    wolfSSL_BASIC_CONSTRAINTS_free(bc);
    bc = NULL;

    if ((ext != NULL) && (ext->obj != NULL)) {
        ext->obj->pathlen = pathLen;
        pathLen = NULL;
    }
    /* pathlen set. */
    ExpectNotNull(bc = (WOLFSSL_BASIC_CONSTRAINTS*)wolfSSL_X509V3_EXT_d2i(ext));

    wolfSSL_ASN1_INTEGER_free(pathLen);
    wolfSSL_BASIC_CONSTRAINTS_free(bc);
    wolfSSL_ASN1_OBJECT_free(obj);
    wolfSSL_X509_EXTENSION_free(ext);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509V3_EXT_san(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    WOLFSSL_STACK* sk = NULL;

    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectNotNull(obj = wolfSSL_ASN1_OBJECT_new());

    if (obj != NULL) {
        obj->type = NID_subject_alt_name;
        obj->nid = NID_subject_alt_name;
    }
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    ExpectNotNull(wolfSSL_X509V3_EXT_get(ext));
    /* No extension stack set. */
    ExpectNull(wolfSSL_X509V3_EXT_d2i(ext));

    ExpectNotNull(sk = wolfSSL_sk_new_null());
    if (ext != NULL) {
        ext->ext_sk = sk;
        sk = NULL;
    }
    /* Extension stack set. */
    ExpectNull(wolfSSL_X509V3_EXT_d2i(ext));

    wolfSSL_sk_free(sk);
    wolfSSL_ASN1_OBJECT_free(obj);
    wolfSSL_X509_EXTENSION_free(ext);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509V3_EXT_aia(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    WOLFSSL_STACK* sk = NULL;
    WOLFSSL_STACK* node = NULL;
    WOLFSSL_AUTHORITY_INFO_ACCESS* aia = NULL;
    WOLFSSL_ASN1_OBJECT* entry = NULL;

    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectNotNull(obj = wolfSSL_ASN1_OBJECT_new());

    if (obj != NULL) {
        obj->type = NID_info_access;
        obj->nid = NID_info_access;
    }
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    ExpectNotNull(wolfSSL_X509V3_EXT_get(ext));
    /* No extension stack set. */
    ExpectNull(wolfSSL_X509V3_EXT_d2i(ext));

    ExpectNotNull(sk = wolfSSL_sk_new_null());
    if (ext != NULL) {
        ext->ext_sk = sk;
        sk = NULL;
    }
    /* Extension stack set but empty. */
    ExpectNotNull(aia = (WOLFSSL_AUTHORITY_INFO_ACCESS *)wolfSSL_X509V3_EXT_d2i(ext));
    wolfSSL_AUTHORITY_INFO_ACCESS_free(aia);
    aia = NULL;

    ExpectNotNull(entry = wolfSSL_ASN1_OBJECT_new());
    if (entry != NULL) {
        entry->nid = WC_NID_ad_OCSP;
        entry->obj = (const unsigned char*)"http://127.0.0.1";
        entry->objSz = 16;
    }
    ExpectNotNull(node = wolfSSL_sk_new_node(NULL));
    if ((node != NULL) && (ext != NULL)) {
        node->type = STACK_TYPE_OBJ;
        node->data.obj = entry;
        entry = NULL;
        ExpectIntEQ(wolfSSL_sk_push_node(&ext->ext_sk, node), WOLFSSL_SUCCESS);
        if (EXPECT_SUCCESS()) {
            node = NULL;
        }
    }
    ExpectNotNull(aia = (WOLFSSL_AUTHORITY_INFO_ACCESS *)wolfSSL_X509V3_EXT_d2i(ext));
    wolfSSL_ACCESS_DESCRIPTION_free(NULL);

    wolfSSL_AUTHORITY_INFO_ACCESS_pop_free(aia,
        wolfSSL_ACCESS_DESCRIPTION_free);
    wolfSSL_ASN1_OBJECT_free(entry);
    wolfSSL_sk_free(node);
    wolfSSL_ASN1_OBJECT_free(obj);
    wolfSSL_X509_EXTENSION_free(ext);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509V3_EXT(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    XFILE f = XBADFILE;
    int numOfExt = 0, nid = 0, i = 0, expected, actual = 0;
    char* str = NULL;
    unsigned char* data = NULL;
    const WOLFSSL_v3_ext_method* method = NULL;
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_X509_EXTENSION* ext2 = NULL;
    WOLFSSL_ASN1_OBJECT *obj = NULL;
    WOLFSSL_ASN1_OBJECT *adObj = NULL;
    WOLFSSL_ASN1_STRING* asn1str = NULL;
    WOLFSSL_AUTHORITY_KEYID* aKeyId = NULL;
    WOLFSSL_AUTHORITY_INFO_ACCESS* aia = NULL;
    WOLFSSL_BASIC_CONSTRAINTS* bc = NULL;
    WOLFSSL_ACCESS_DESCRIPTION* ad = NULL;
    WOLFSSL_GENERAL_NAME* gn = NULL;

    /* Check NULL argument */
    ExpectNull(wolfSSL_X509V3_EXT_d2i(NULL));

    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectNotNull(obj = wolfSSL_ASN1_OBJECT_new());

    ExpectNull(wolfSSL_X509V3_EXT_d2i(ext));
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    ExpectNull(wolfSSL_X509V3_EXT_d2i(ext));
    if (ext != NULL && ext->obj != NULL) {
        ext->obj->nid = ext->obj->type = NID_ext_key_usage;
    }
    ExpectNull(wolfSSL_X509V3_EXT_d2i(ext));
    if (ext != NULL && ext->obj != NULL) {
        ext->obj->nid = ext->obj->type = NID_certificate_policies;
    }
    ExpectNull(wolfSSL_X509V3_EXT_d2i(ext));
    if (ext != NULL && ext->obj != NULL) {
        ext->obj->nid = ext->obj->type = NID_crl_distribution_points;
    }
    ExpectNull(wolfSSL_X509V3_EXT_d2i(ext));
    if (ext != NULL && ext->obj != NULL) {
        ext->obj->nid = ext->obj->type = NID_subject_alt_name;
    }
    ExpectNull(wolfSSL_X509V3_EXT_d2i(ext));

    wolfSSL_ASN1_OBJECT_free(obj);
    obj = NULL;
    wolfSSL_X509_EXTENSION_free(ext);
    ext = NULL;

    /* Using OCSP cert with X509V3 extensions */
    ExpectTrue((f = XFOPEN("./certs/ocsp/root-ca-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectIntEQ((numOfExt = wolfSSL_X509_get_ext_count(x509)), 5);

    /* Basic Constraints */
    ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, i));
    ExpectNotNull(obj = wolfSSL_X509_EXTENSION_get_object(ext));
    ExpectIntEQ((nid = wolfSSL_OBJ_obj2nid(obj)), NID_basic_constraints);
    ExpectNotNull(bc = (WOLFSSL_BASIC_CONSTRAINTS*)wolfSSL_X509V3_EXT_d2i(ext));

    ExpectIntEQ(bc->ca, 1);
    ExpectNull(bc->pathlen);
    wolfSSL_BASIC_CONSTRAINTS_free(bc);
    bc = NULL;
    i++;

    /* Subject Key Identifier */
    ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, i));
    ExpectNotNull(obj = wolfSSL_X509_EXTENSION_get_object(ext));
    ExpectIntEQ((nid = wolfSSL_OBJ_obj2nid(obj)), NID_subject_key_identifier);

    ExpectNotNull(asn1str = (WOLFSSL_ASN1_STRING*)wolfSSL_X509V3_EXT_d2i(ext));
    ExpectNotNull(ext2 = wolfSSL_X509V3_EXT_i2d(NID_subject_key_identifier, 0,
        asn1str));
    X509_EXTENSION_free(ext2);
    ext2 = NULL;
    ExpectNotNull(method = wolfSSL_X509V3_EXT_get(ext));
    ExpectNotNull(method->i2s);
    ExpectNotNull(str = method->i2s((WOLFSSL_v3_ext_method*)method, asn1str));
    wolfSSL_ASN1_STRING_free(asn1str);
    asn1str = NULL;
    if (str != NULL) {
        actual = strcmp(str,
            "73:B0:1C:A4:2F:82:CB:CF:47:A5:38:D7:B0:04:82:3A:7E:72:15:21");
    }
    ExpectIntEQ(actual, 0);
    XFREE(str, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    str = NULL;
    i++;

    /* Authority Key Identifier */
    ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, i));
    ExpectNotNull(obj = wolfSSL_X509_EXTENSION_get_object(ext));
    ExpectIntEQ((nid = wolfSSL_OBJ_obj2nid(obj)), NID_authority_key_identifier);

    ExpectNotNull(aKeyId = (WOLFSSL_AUTHORITY_KEYID*)wolfSSL_X509V3_EXT_d2i(
        ext));
    ExpectNotNull(method = wolfSSL_X509V3_EXT_get(ext));
    ExpectNotNull(asn1str = aKeyId->keyid);
    ExpectNotNull(str = wolfSSL_i2s_ASN1_STRING((WOLFSSL_v3_ext_method*)method,
        asn1str));
    asn1str = NULL;
    if (str != NULL) {
        actual = strcmp(str,
            "73:B0:1C:A4:2F:82:CB:CF:47:A5:38:D7:B0:04:82:3A:7E:72:15:21");
    }
    ExpectIntEQ(actual, 0);
    XFREE(str, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    str = NULL;
    wolfSSL_AUTHORITY_KEYID_free(aKeyId);
    aKeyId = NULL;
    i++;

    /* Key Usage */
    ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, i));
    ExpectNotNull(obj = wolfSSL_X509_EXTENSION_get_object(ext));
    ExpectIntEQ((nid = wolfSSL_OBJ_obj2nid(obj)), NID_key_usage);

    ExpectNotNull(asn1str = (WOLFSSL_ASN1_STRING*)wolfSSL_X509V3_EXT_d2i(ext));
#if defined(WOLFSSL_QT)
    ExpectNotNull(data = (unsigned char*)ASN1_STRING_get0_data(asn1str));
#else
    ExpectNotNull(data = wolfSSL_ASN1_STRING_data(asn1str));
#endif
    expected = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN;
    if (data != NULL) {
    #ifdef BIG_ENDIAN_ORDER
        actual = data[1];
    #else
        actual = data[0];
    #endif
    }
    ExpectIntEQ(actual, expected);
    wolfSSL_ASN1_STRING_free(asn1str);
    asn1str = NULL;
    ExpectIntEQ(wolfSSL_X509_get_keyUsage(NULL), 0);
    ExpectIntEQ(wolfSSL_X509_get_keyUsage(x509), expected);
    i++;

    /* Authority Info Access */
    ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, i));
    ExpectNotNull(obj = wolfSSL_X509_EXTENSION_get_object(ext));
    ExpectIntEQ((nid = wolfSSL_OBJ_obj2nid(obj)), NID_info_access);
    ExpectNotNull(aia = (WOLFSSL_AUTHORITY_INFO_ACCESS*)wolfSSL_X509V3_EXT_d2i(
        ext));
#if defined(WOLFSSL_QT)
    ExpectIntEQ(OPENSSL_sk_num(aia), 1); /* Only one URI entry for this cert */
#else
    ExpectIntEQ(wolfSSL_sk_num(aia), 1); /* Only one URI entry for this cert */
#endif
    /* URI entry is an ACCESS_DESCRIPTION type */
#if defined(WOLFSSL_QT)
    ExpectNotNull(ad = (WOLFSSL_ACCESS_DESCRIPTION*)wolfSSL_sk_value(aia, 0));
#else
    ExpectNotNull(ad = (WOLFSSL_ACCESS_DESCRIPTION*)OPENSSL_sk_value(aia, 0));
#endif
    ExpectNotNull(adObj = ad->method);
    /* Make sure nid is OCSP */
    ExpectIntEQ(wolfSSL_OBJ_obj2nid(adObj), NID_ad_OCSP);

    /* GENERAL_NAME stores URI as an ASN1_STRING */
    ExpectNotNull(gn = ad->location);
    ExpectIntEQ(gn->type, GEN_URI); /* Type should always be GEN_URI */
    ExpectNotNull(asn1str = gn->d.uniformResourceIdentifier);
    ExpectIntEQ(wolfSSL_ASN1_STRING_length(asn1str), 22);
#if defined(WOLFSSL_QT)
    ExpectNotNull(str = (char*)ASN1_STRING_get0_data(asn1str));
#else
    ExpectNotNull(str = (char*)wolfSSL_ASN1_STRING_data(asn1str));
#endif
    if (str != NULL) {
         actual = strcmp(str, "http://127.0.0.1:22220");
    }
    ExpectIntEQ(actual, 0);

    ExpectIntEQ(wolfSSL_sk_ACCESS_DESCRIPTION_num(NULL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_sk_ACCESS_DESCRIPTION_num(aia), 1);
    ExpectNull(wolfSSL_sk_ACCESS_DESCRIPTION_value(NULL, 0));
    ExpectNull(wolfSSL_sk_ACCESS_DESCRIPTION_value(aia, 1));
    ExpectNotNull(wolfSSL_sk_ACCESS_DESCRIPTION_value(aia, 0));
    wolfSSL_sk_ACCESS_DESCRIPTION_pop_free(aia, NULL);
    aia = NULL;

#ifndef NO_WOLFSSL_STUB
    ExpectNull(wolfSSL_X509_delete_ext(x509, 0));
#endif

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_get_extension_flags(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_RSA)
    XFILE f = XBADFILE;
    X509* x509 = NULL;
    unsigned int extFlags;
    unsigned int keyUsageFlags;
    unsigned int extKeyUsageFlags;

    ExpectIntEQ(X509_get_extension_flags(NULL), 0);
    ExpectIntEQ(X509_get_key_usage(NULL), 0);
    ExpectIntEQ(X509_get_extended_key_usage(NULL), 0);
    ExpectNotNull(x509 = wolfSSL_X509_new());
    ExpectIntEQ(X509_get_extension_flags(x509), 0);
    ExpectIntEQ(X509_get_key_usage(x509), -1);
    ExpectIntEQ(X509_get_extended_key_usage(x509), 0);
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* client-int-cert.pem has the following extension flags. */
    extFlags = EXFLAG_KUSAGE | EXFLAG_XKUSAGE;
    /* and the following key usage flags. */
    keyUsageFlags = KU_DIGITAL_SIGNATURE
                  | KU_NON_REPUDIATION
                  | KU_KEY_ENCIPHERMENT;
    /* and the following extended key usage flags. */
    extKeyUsageFlags = XKU_SSL_CLIENT | XKU_SMIME;

    ExpectTrue((f = XFOPEN("./certs/intermediate/client-int-cert.pem", "rb")) !=
        XBADFILE);
    ExpectNotNull(x509 = PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }
    ExpectIntEQ(X509_get_extension_flags(x509), extFlags);
    ExpectIntEQ(X509_get_key_usage(x509), keyUsageFlags);
    ExpectIntEQ(X509_get_extended_key_usage(x509), extKeyUsageFlags);
    X509_free(x509);
    x509 = NULL;

    /* client-cert-ext.pem has the following extension flags. */
    extFlags = EXFLAG_KUSAGE;
    /* and the following key usage flags. */
    keyUsageFlags = KU_DIGITAL_SIGNATURE
                  | KU_KEY_CERT_SIGN
                  | KU_CRL_SIGN;

    ExpectTrue((f = fopen("./certs/client-cert-ext.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE)
        XFCLOSE(f);
    ExpectIntEQ(X509_get_extension_flags(x509), extFlags);
    ExpectIntEQ(X509_get_key_usage(x509), keyUsageFlags);
    X509_free(x509);
#endif /* OPENSSL_ALL */
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_get_ext(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    int ret = 0;
    XFILE f = XBADFILE;
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509_EXTENSION* foundExtension;

    ExpectTrue((f = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE)
        XFCLOSE(f);
    ExpectIntEQ((ret = wolfSSL_X509_get_ext_count(x509)), 5);

    /* wolfSSL_X509_get_ext() valid input */
    ExpectNotNull(foundExtension = wolfSSL_X509_get_ext(x509, 0));

    /* wolfSSL_X509_get_ext() valid x509, idx out of bounds */
    ExpectNull(foundExtension = wolfSSL_X509_get_ext(x509, -1));
    ExpectNull(foundExtension = wolfSSL_X509_get_ext(x509, 100));

    /* wolfSSL_X509_get_ext() NULL x509, idx out of bounds */
    ExpectNull(foundExtension = wolfSSL_X509_get_ext(NULL, -1));
    ExpectNull(foundExtension = wolfSSL_X509_get_ext(NULL, 100));

    /* wolfSSL_X509_get_ext() NULL x509, valid idx */
    ExpectNull(foundExtension = wolfSSL_X509_get_ext(NULL, 0));

    ExpectNull(wolfSSL_X509_get0_extensions(NULL));

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_get_ext_by_NID(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_RSA)
    int rc = 0;
    XFILE f = XBADFILE;
    WOLFSSL_X509* x509 = NULL;
    ASN1_OBJECT* obj = NULL;

    ExpectNotNull(x509 = wolfSSL_X509_new());
    ExpectIntEQ(wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints, -1),
        WOLFSSL_FATAL_ERROR);
    wolfSSL_X509_free(x509);
    x509 = NULL;

    ExpectTrue((f = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectIntGE(rc = wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints,
        -1), 0);
    ExpectIntGE(wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints, 20),
        -1);

    /* Start search from last location (should fail) */
    ExpectIntGE(rc = wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints,
        rc), -1);

    ExpectIntGE(rc = wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints,
        -2), -1);

    ExpectIntEQ(rc = wolfSSL_X509_get_ext_by_NID(NULL, NID_basic_constraints,
        -1), -1);

    ExpectIntEQ(rc = wolfSSL_X509_get_ext_by_NID(x509, NID_undef, -1), -1);

    /* NID_ext_key_usage, check also its nid and oid */
    ExpectIntGT(rc = wolfSSL_X509_get_ext_by_NID(x509, NID_ext_key_usage, -1),
        -1);
    ExpectNotNull(obj = wolfSSL_X509_EXTENSION_get_object(wolfSSL_X509_get_ext(
        x509, rc)));
    ExpectIntEQ(obj->nid, NID_ext_key_usage);
    ExpectIntEQ(obj->type, EXT_KEY_USAGE_OID);

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_get_ext_subj_alt_name(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_RSA)
    int rc = 0;
    XFILE f = XBADFILE;
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_STRING* sanString = NULL;
    byte* sanDer = NULL;

    const byte expectedDer[] = {
        0x30, 0x13, 0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
        0x63, 0x6f, 0x6d, 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01};

    ExpectTrue((f = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectIntNE(rc = X509_get_ext_by_NID(x509, NID_subject_alt_name, -1), -1);
    ExpectNotNull(ext = X509_get_ext(x509, rc));
    ExpectNotNull(sanString = X509_EXTENSION_get_data(ext));
    ExpectIntEQ(ASN1_STRING_length(sanString), sizeof(expectedDer));
    ExpectNotNull(sanDer = ASN1_STRING_data(sanString));
    ExpectIntEQ(XMEMCMP(sanDer, expectedDer, sizeof(expectedDer)), 0);

    X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_set_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_RSA)
    WOLFSSL_X509* x509 = NULL;
    XFILE f = XBADFILE;
    int loc;

    ExpectNull(wolfSSL_X509_set_ext(NULL, 0));

    ExpectNotNull(x509 = wolfSSL_X509_new());
    /* Location too small. */
    ExpectNull(wolfSSL_X509_set_ext(x509, -1));
    /* Location too big. */
    ExpectNull(wolfSSL_X509_set_ext(x509, 1));
    /* No DER encoding. */
    ExpectNull(wolfSSL_X509_set_ext(x509, 0));
    wolfSSL_X509_free(x509);
    x509 = NULL;

    ExpectTrue((f = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE) {
        XFCLOSE(f);
    }
    for (loc = 0; loc < wolfSSL_X509_get_ext_count(x509); loc++) {
        ExpectNotNull(wolfSSL_X509_set_ext(x509, loc));
    }

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_ALL)
static int test_X509_add_basic_constraints(WOLFSSL_X509* x509)
{
    EXPECT_DECLS;
    const byte basicConsObj[] = { 0x06, 0x03, 0x55, 0x1d, 0x13 };
    const byte* p;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    ASN1_INTEGER* pathLen = NULL;

    p = basicConsObj;
    ExpectNotNull(obj = wolfSSL_d2i_ASN1_OBJECT(NULL, &p,
        sizeof(basicConsObj)));
    if (obj != NULL) {
        obj->type = NID_basic_constraints;
    }
    ExpectNotNull(pathLen = wolfSSL_ASN1_INTEGER_new());
    if (pathLen != NULL) {
        pathLen->length = 2;
    }
    if (obj != NULL) {
        obj->ca = 0;
    }
    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    if (ext != NULL && ext->obj != NULL) {
        ext->obj->ca = 0;
        ext->obj->pathlen = pathLen;
    }
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(x509->isCa, 0);
    ExpectIntEQ(x509->pathLength, 2);
    if (ext != NULL && ext->obj != NULL) {
        /* Add second time to without path length. */
        ext->obj->ca = 1;
        ext->obj->pathlen = NULL;
    }
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(x509->isCa, 1);
    ExpectIntEQ(x509->pathLength, 2);
    ExpectIntEQ(wolfSSL_X509_get_isSet_pathLength(NULL), 0);
    ExpectIntEQ(wolfSSL_X509_get_isSet_pathLength(x509), 1);
    ExpectIntEQ(wolfSSL_X509_get_pathLength(NULL), 0);
    ExpectIntEQ(wolfSSL_X509_get_pathLength(x509), 2);

    wolfSSL_ASN1_INTEGER_free(pathLen);
    wolfSSL_ASN1_OBJECT_free(obj);
    wolfSSL_X509_EXTENSION_free(ext);

    return EXPECT_RESULT();
}

static int test_X509_add_key_usage(WOLFSSL_X509* x509)
{
    EXPECT_DECLS;
    const byte objData[] = { 0x06, 0x03, 0x55, 0x1d, 0x0f };
    const byte data[] = { 0x04, 0x02, 0x01, 0x80 };
    const byte emptyData[] = { 0x04, 0x00 };
    const char* strData = "digitalSignature,keyCertSign";
    const byte* p;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    WOLFSSL_ASN1_STRING* str = NULL;

    p = objData;
    ExpectNotNull(obj = wolfSSL_d2i_ASN1_OBJECT(NULL, &p, sizeof(objData)));
    if (obj != NULL) {
        obj->type = NID_key_usage;
    }
    p = data;
    ExpectNotNull(str = d2i_ASN1_OCTET_STRING(NULL, &p, (long)sizeof(data)));
    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    /* No Data - no change. */
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, str), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(x509->keyUsage, KEYUSE_DECIPHER_ONLY | KEYUSE_ENCIPHER_ONLY);

    /* Add second time with string to interpret. */
    wolfSSL_ASN1_STRING_free(str);
    str = NULL;
    ExpectNotNull(str = wolfSSL_ASN1_STRING_new());
    ExpectIntEQ(ASN1_STRING_set(str, strData, (word32)XSTRLEN(strData) + 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, str), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(x509->keyUsage, KEYUSE_DIGITAL_SIG | KEYUSE_KEY_CERT_SIGN);

    /* Empty data. */
    wolfSSL_ASN1_STRING_free(str);
    str = NULL;
    p = emptyData;
    ExpectNotNull(str = d2i_ASN1_OCTET_STRING(NULL, &p,
        (long)sizeof(emptyData)));
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, str), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_FAILURE);

    /* Invalid string to parse. */
    wolfSSL_ASN1_STRING_free(str);
    str = NULL;
    ExpectNotNull(str = wolfSSL_ASN1_STRING_new());
    ExpectIntEQ(ASN1_STRING_set(str, "bad", 4), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, str), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_FAILURE);

    wolfSSL_ASN1_STRING_free(str);
    wolfSSL_ASN1_OBJECT_free(obj);
    wolfSSL_X509_EXTENSION_free(ext);

    return EXPECT_RESULT();
}

static int test_X509_add_ext_key_usage(WOLFSSL_X509* x509)
{
    EXPECT_DECLS;
    const byte objData[] = { 0x06, 0x03, 0x55, 0x1d, 0x25 };
    const byte data[] = { 0x04, 0x01, 0x01 };
    const byte emptyData[] = { 0x04, 0x00 };
    const char* strData = "serverAuth,codeSigning";
    const byte* p;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    WOLFSSL_ASN1_STRING* str = NULL;

    p = objData;
    ExpectNotNull(obj = wolfSSL_d2i_ASN1_OBJECT(NULL, &p, sizeof(objData)));
    if (obj != NULL) {
        obj->type = NID_ext_key_usage;
    }
    p = data;
    ExpectNotNull(str = d2i_ASN1_OCTET_STRING(NULL, &p, (long)sizeof(data)));
    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    /* No Data - no change. */
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, str), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(x509->extKeyUsage, EXTKEYUSE_ANY);

    /* Add second time with string to interpret. */
    wolfSSL_ASN1_STRING_free(str);
    str = NULL;
    ExpectNotNull(str = wolfSSL_ASN1_STRING_new());
    ExpectIntEQ(ASN1_STRING_set(str, strData, (word32)XSTRLEN(strData) + 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, str), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(x509->extKeyUsage, EXTKEYUSE_SERVER_AUTH | EXTKEYUSE_CODESIGN);

    /* Empty data. */
    wolfSSL_ASN1_STRING_free(str);
    str = NULL;
    p = emptyData;
    ExpectNotNull(str = d2i_ASN1_OCTET_STRING(NULL, &p,
        (long)sizeof(emptyData)));
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, str), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_FAILURE);

    /* Invalid string to parse. */
    wolfSSL_ASN1_STRING_free(str);
    str = NULL;
    ExpectNotNull(str = wolfSSL_ASN1_STRING_new());
    ExpectIntEQ(ASN1_STRING_set(str, "bad", 4), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, str), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_FAILURE);

    wolfSSL_ASN1_STRING_free(str);
    wolfSSL_ASN1_OBJECT_free(obj);
    wolfSSL_X509_EXTENSION_free(ext);

    return EXPECT_RESULT();
}

static int test_x509_add_auth_key_id(WOLFSSL_X509* x509)
{
    EXPECT_DECLS;
    const byte objData[] = { 0x06, 0x03, 0x55, 0x1d, 0x23 };
    const byte data[] = {
        0x04, 0x81, 0xcc, 0x30, 0x81, 0xc9, 0x80, 0x14,
        0x27, 0x8e, 0x67, 0x11, 0x74, 0xc3, 0x26, 0x1d,
        0x3f, 0xed, 0x33, 0x63, 0xb3, 0xa4, 0xd8, 0x1d,
        0x30, 0xe5, 0xe8, 0xd5, 0xa1, 0x81, 0x9a, 0xa4,
        0x81, 0x97, 0x30, 0x81, 0x94, 0x31, 0x0b, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x55, 0x53, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
        0x55, 0x04, 0x08, 0x0c, 0x07, 0x4d, 0x6f, 0x6e,
        0x74, 0x61, 0x6e, 0x61, 0x31, 0x10, 0x30, 0x0e,
        0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x42,
        0x6f, 0x7a, 0x65, 0x6d, 0x61, 0x6e, 0x31, 0x11,
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
        0x08, 0x53, 0x61, 0x77, 0x74, 0x6f, 0x6f, 0x74,
        0x68, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
        0x04, 0x0b, 0x0c, 0x0a, 0x43, 0x6f, 0x6e, 0x73,
        0x75, 0x6c, 0x74, 0x69, 0x6e, 0x67, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
        0x0f, 0x77, 0x77, 0x77, 0x2e, 0x77, 0x6f, 0x6c,
        0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d,
        0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16,
        0x10, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x77, 0x6f,
        0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f,
        0x6d, 0x82, 0x14, 0x33, 0x44, 0x1a, 0xa8, 0x6c,
        0x01, 0xec, 0xf6, 0x60, 0xf2, 0x70, 0x51, 0x0a,
        0x4c, 0xd1, 0x14, 0xfa, 0xbc, 0xe9, 0x44
    };
    const byte* p;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    WOLFSSL_ASN1_STRING* str = NULL;

    p = objData;
    ExpectNotNull(obj = wolfSSL_d2i_ASN1_OBJECT(NULL, &p, sizeof(objData)));
    if (obj != NULL) {
        obj->type = NID_authority_key_identifier;
    }
    p = data;
    ExpectNotNull(str = d2i_ASN1_OCTET_STRING(NULL, &p, (long)sizeof(data)));
    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, str), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);

    /* Add second time with string to interpret. */
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);

    wolfSSL_ASN1_STRING_free(str);
    wolfSSL_ASN1_OBJECT_free(obj);
    wolfSSL_X509_EXTENSION_free(ext);

    return EXPECT_RESULT();
}

static int test_x509_add_subj_key_id(WOLFSSL_X509* x509)
{
    EXPECT_DECLS;
    const byte objData[] = { 0x06, 0x03, 0x55, 0x1d, 0x0e };
    const byte data[] = {
        0x04, 0x16, 0x04, 0x14, 0xb3, 0x11, 0x32, 0xc9,
        0x92, 0x98, 0x84, 0xe2, 0xc9, 0xf8, 0xd0, 0x3b,
        0x6e, 0x03, 0x42, 0xca, 0x1f, 0x0e, 0x8e, 0x3c
    };
    const byte* p;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    WOLFSSL_ASN1_STRING* str = NULL;

    p = objData;
    ExpectNotNull(obj = wolfSSL_d2i_ASN1_OBJECT(NULL, &p, sizeof(objData)));
    if (obj != NULL) {
        obj->type = NID_subject_key_identifier;
    }
    p = data;
    ExpectNotNull(str = d2i_ASN1_OCTET_STRING(NULL, &p, (long)sizeof(data)));
    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, str), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);
    /* Add second time with string to interpret. */
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);

    wolfSSL_ASN1_STRING_free(str);
    wolfSSL_ASN1_OBJECT_free(obj);
    wolfSSL_X509_EXTENSION_free(ext);

    return EXPECT_RESULT();
}
#endif

static int test_wolfSSL_X509_add_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL)
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509_EXTENSION* ext_empty = NULL;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    WOLFSSL_ASN1_STRING* data = NULL;
    const byte* p;
    const byte subjAltNameObj[] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };
    const byte subjAltName[] = {
        0x04, 0x15, 0x30, 0x13, 0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01
    };

    ExpectNotNull(x509 = wolfSSL_X509_new());

    /* Create extension: Subject Alternative Name */
    ExpectNotNull(ext_empty = wolfSSL_X509_EXTENSION_new());
    p = subjAltName;
    ExpectNotNull(data = d2i_ASN1_OCTET_STRING(NULL, &p,
        (long)sizeof(subjAltName)));
    p = subjAltNameObj;
    ExpectNotNull(obj = wolfSSL_d2i_ASN1_OBJECT(NULL, &p,
        sizeof(subjAltNameObj)));
    if (obj != NULL) {
        obj->type = NID_subject_alt_name;
    }
    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_EXTENSION_set_data(ext, data), WOLFSSL_SUCCESS);

    /* Failure cases. */
    ExpectIntEQ(wolfSSL_X509_add_ext(NULL, NULL, 0),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, NULL, 0),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_X509_add_ext(NULL, ext, 0),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_X509_add_ext(NULL, NULL, -1),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_X509_add_ext(NULL, ext, -1),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, NULL, -1),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, 0),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext_empty, -1),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* Add: Subject Alternative Name */
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);
    /* Add second time to ensure no memory leaks. */
    ExpectIntEQ(wolfSSL_X509_add_ext(x509, ext, -1), WOLFSSL_SUCCESS);

    wolfSSL_X509_EXTENSION_free(ext);
    wolfSSL_ASN1_OBJECT_free(obj);
    wolfSSL_ASN1_STRING_free(data);
    wolfSSL_X509_EXTENSION_free(ext_empty);

    EXPECT_TEST(test_X509_add_basic_constraints(x509));
    EXPECT_TEST(test_X509_add_key_usage(x509));
    EXPECT_TEST(test_X509_add_ext_key_usage(x509));
    EXPECT_TEST(test_x509_add_auth_key_id(x509));
    EXPECT_TEST(test_x509_add_subj_key_id(x509));

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_EXTENSION_new(void)
{
    EXPECT_DECLS;
#if defined (OPENSSL_ALL)
    WOLFSSL_X509_EXTENSION* ext = NULL;

    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectNotNull(ext->obj = wolfSSL_ASN1_OBJECT_new());

    wolfSSL_X509_EXTENSION_free(NULL);
    wolfSSL_X509_EXTENSION_free(ext);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_EXTENSION_dup(void)
{
    EXPECT_DECLS;
#if defined (OPENSSL_ALL)
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_X509_EXTENSION* dup = NULL;

    ExpectNull(wolfSSL_X509_EXTENSION_dup(NULL));
    ExpectNotNull(ext = wolfSSL_X509_EXTENSION_new());
    ExpectNotNull(dup = wolfSSL_X509_EXTENSION_dup(ext));

    wolfSSL_X509_EXTENSION_free(dup);
    wolfSSL_X509_EXTENSION_free(ext);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_EXTENSION_get_object(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_X509_EXTENSION* dup = NULL;
    WOLFSSL_ASN1_OBJECT* o = NULL;
    XFILE file = XBADFILE;

    ExpectTrue((file = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(file, NULL, NULL, NULL));
    if (file != XBADFILE)
        XFCLOSE(file);

    /* wolfSSL_X509_EXTENSION_get_object() testing ext idx 0 */
    ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, 0));
    ExpectNull(wolfSSL_X509_EXTENSION_get_object(NULL));
    ExpectNotNull(o = wolfSSL_X509_EXTENSION_get_object(ext));
    ExpectIntEQ(o->nid, 128);
    ExpectNotNull(dup = wolfSSL_X509_EXTENSION_dup(ext));
    wolfSSL_X509_EXTENSION_free(dup);

    /* wolfSSL_X509_EXTENSION_get_object() NULL argument */
    ExpectNull(o = wolfSSL_X509_EXTENSION_get_object(NULL));

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_EXTENSION_get_data(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_STRING* str = NULL;
    XFILE file = XBADFILE;

    ExpectTrue((file = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(file, NULL, NULL, NULL));
    if (file != XBADFILE)
        XFCLOSE(file);
    ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, 0));

    ExpectNull(str = wolfSSL_X509_EXTENSION_get_data(NULL));
    ExpectNotNull(str = wolfSSL_X509_EXTENSION_get_data(ext));

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_EXTENSION_get_critical(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    XFILE file = XBADFILE;
    int crit = 0;

    ExpectTrue((file = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(file, NULL, NULL, NULL));
    if (file != XBADFILE)
        XFCLOSE(file);
    ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, 0));

    ExpectIntEQ(crit = wolfSSL_X509_EXTENSION_get_critical(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(crit = wolfSSL_X509_EXTENSION_get_critical(ext), 0);

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_EXTENSION_create_by_OBJ(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    XFILE file = XBADFILE;
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509* empty = NULL;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_X509_EXTENSION* ext2 = NULL;
    WOLFSSL_X509_EXTENSION* ext3 = NULL;
    WOLFSSL_ASN1_OBJECT* o = NULL;
    int crit = 0;
    WOLFSSL_ASN1_STRING* str = NULL;

    ExpectTrue((file = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(file, NULL, NULL, NULL));
    if (file != XBADFILE)
        XFCLOSE(file);
    ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, 0));

    ExpectNotNull(o = wolfSSL_X509_EXTENSION_get_object(ext));
    ExpectIntEQ(crit = wolfSSL_X509_EXTENSION_get_critical(ext), 0);
    ExpectNotNull(str = wolfSSL_X509_EXTENSION_get_data(ext));

    ExpectNull(wolfSSL_X509_EXTENSION_create_by_OBJ(NULL, NULL, 0, NULL));
    ExpectNull(wolfSSL_X509_EXTENSION_create_by_OBJ(NULL, o, 0, NULL));
    ExpectNull(wolfSSL_X509_EXTENSION_create_by_OBJ(NULL, NULL, 0, str));
    ExpectNotNull(ext2 = wolfSSL_X509_EXTENSION_create_by_OBJ(NULL, o, crit,
        str));
    ExpectNotNull(ext3 = wolfSSL_X509_EXTENSION_create_by_OBJ(ext2, o, crit,
        str));
    if (ext3 == NULL) {
        wolfSSL_X509_EXTENSION_free(ext2);
    }
    wolfSSL_X509_EXTENSION_free(ext3);

    ExpectIntEQ(wolfSSL_X509_get_ext_by_OBJ(NULL, NULL, -1),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_X509_get_ext_by_OBJ(NULL, o, -1),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectNotNull(empty = wolfSSL_X509_new());
    ExpectIntEQ(wolfSSL_X509_get_ext_by_OBJ(empty, NULL, -1),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_X509_get_ext_by_OBJ(empty, o, -1),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    wolfSSL_X509_free(empty);
    empty = NULL;
    ExpectIntEQ(wolfSSL_X509_get_ext_by_OBJ(x509, o, -2), 0);
    ExpectIntEQ(wolfSSL_X509_get_ext_by_OBJ(x509, o, 0),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509V3_EXT_print(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_BIO) && \
    !defined(NO_RSA)

    {
        XFILE f = XBADFILE;
        WOLFSSL_X509* x509 = NULL;
        X509_EXTENSION * ext = NULL;
        int loc = 0;
        BIO *bio = NULL;

        ExpectTrue((f = XFOPEN(svrCertFile, "rb")) != XBADFILE);
        ExpectNotNull(x509 = wolfSSL_PEM_read_X509(f, NULL, NULL, NULL));
        if (f != XBADFILE)
            fclose(f);

        ExpectNotNull(bio = wolfSSL_BIO_new(BIO_s_mem()));

        ExpectIntGT(loc = wolfSSL_X509_get_ext_by_NID(x509,
            NID_basic_constraints, -1), -1);
        ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, loc));

        /* Failure cases. */
        ExpectIntEQ(wolfSSL_X509V3_EXT_print(NULL, NULL, 0, 0),
            WOLFSSL_FAILURE);
        ExpectIntEQ(wolfSSL_X509V3_EXT_print(bio , NULL, 0, 0),
            WOLFSSL_FAILURE);
        ExpectIntEQ(wolfSSL_X509V3_EXT_print(NULL, ext , 0, 0),
            WOLFSSL_FAILURE);
        /* Good case. */
        ExpectIntEQ(wolfSSL_X509V3_EXT_print(bio, ext, 0, 0), WOLFSSL_SUCCESS);

        ExpectIntGT(loc = wolfSSL_X509_get_ext_by_NID(x509,
            NID_subject_key_identifier, -1), -1);
        ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, loc));
        ExpectIntEQ(wolfSSL_X509V3_EXT_print(bio, ext, 0, 0), WOLFSSL_SUCCESS);

        ExpectIntGT(loc = wolfSSL_X509_get_ext_by_NID(x509,
            NID_authority_key_identifier, -1), -1);
        ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, loc));
        ExpectIntEQ(wolfSSL_X509V3_EXT_print(bio, ext, 0, 0), WOLFSSL_SUCCESS);

        wolfSSL_BIO_free(bio);
        wolfSSL_X509_free(x509);
    }

    {
        X509 *x509 = NULL;
        BIO *bio = NULL;
        X509_EXTENSION *ext = NULL;
        unsigned int i = 0;
        unsigned int idx = 0;
        /* Some NIDs to test with */
        int nids[] = {
                /* NID_key_usage, currently X509_get_ext returns this as a bit
                 * string, which messes up X509V3_EXT_print */
                /* NID_ext_key_usage, */
                NID_subject_alt_name,
        };
        int* n = NULL;

        ExpectNotNull(bio = BIO_new_fp(stderr, BIO_NOCLOSE));

        ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(cliCertFileExt,
            WOLFSSL_FILETYPE_PEM));

        ExpectIntGT(fprintf(stderr, "\nPrinting extension values:\n"), 0);

        for (i = 0, n = nids; i<(sizeof(nids)/sizeof(int)); i++, n++) {
            /* X509_get_ext_by_NID should return 3 for now. If that changes then
             * update the index */
            ExpectIntEQ((idx = X509_get_ext_by_NID(x509, *n, -1)), 3);
            ExpectNotNull(ext = X509_get_ext(x509, (int)idx));
            ExpectIntEQ(X509V3_EXT_print(bio, ext, 0, 0), 1);
            ExpectIntGT(fprintf(stderr, "\n"), 0);
        }

        BIO_free(bio);
        X509_free(x509);
    }

    {
        BIO* bio = NULL;
        X509_EXTENSION* ext = NULL;
        WOLFSSL_ASN1_OBJECT* obj = NULL;

        ExpectNotNull(bio = BIO_new_fp(stderr, BIO_NOCLOSE));
        ExpectNotNull(ext = X509_EXTENSION_new());

        /* No object. */
        ExpectIntEQ(wolfSSL_X509V3_EXT_print(bio, ext, 0, 0), WOLFSSL_FAILURE);

        ExpectNotNull(obj = wolfSSL_ASN1_OBJECT_new());
        ExpectIntEQ(wolfSSL_X509_EXTENSION_set_object(ext, obj),
            WOLFSSL_SUCCESS);

        /* NID not supported yet - just doesn't write anything. */
        if (ext != NULL && ext->obj != NULL) {
            ext->obj->nid = AUTH_INFO_OID;
            ExpectIntEQ(wolfSSL_X509V3_EXT_print(bio, ext, 0, 0),
                WOLFSSL_SUCCESS);
            ext->obj->nid = CERT_POLICY_OID;
            ExpectIntEQ(wolfSSL_X509V3_EXT_print(bio, ext, 0, 0),
                WOLFSSL_SUCCESS);
            ext->obj->nid = CRL_DIST_OID;
            ExpectIntEQ(wolfSSL_X509V3_EXT_print(bio, ext, 0, 0),
                WOLFSSL_SUCCESS);
            ext->obj->nid = KEY_USAGE_OID;
            ExpectIntEQ(wolfSSL_X509V3_EXT_print(bio, ext, 0, 0),
                WOLFSSL_SUCCESS);

            ext->obj->nid = EXT_KEY_USAGE_OID;
            ExpectIntEQ(wolfSSL_X509V3_EXT_print(bio, ext, 0, 0),
                WOLFSSL_SUCCESS);
        }

        wolfSSL_ASN1_OBJECT_free(obj);
        X509_EXTENSION_free(ext);
        BIO_free(bio);
    }
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_cmp(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_RSA)
    XFILE file1 = XBADFILE;
    XFILE file2 = XBADFILE;
    WOLFSSL_X509* cert1 = NULL;
    WOLFSSL_X509* cert2 = NULL;
    WOLFSSL_X509* empty = NULL;

    ExpectTrue((file1 = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectTrue((file2 = XFOPEN("./certs/3072/client-cert.pem", "rb")) !=
        XBADFILE);

    ExpectNotNull(cert1 = wolfSSL_PEM_read_X509(file1, NULL, NULL, NULL));
    ExpectNotNull(cert2 = wolfSSL_PEM_read_X509(file2, NULL, NULL, NULL));
    if (file1 != XBADFILE)
        fclose(file1);
    if (file2 != XBADFILE)
        fclose(file2);

    ExpectNotNull(empty = wolfSSL_X509_new());

    /* wolfSSL_X509_cmp() testing matching certs */
    ExpectIntEQ(0, wolfSSL_X509_cmp(cert1, cert1));

    /* wolfSSL_X509_cmp() testing mismatched certs */
    ExpectIntEQ(-1, wolfSSL_X509_cmp(cert1, cert2));

    /* wolfSSL_X509_cmp() testing NULL, valid args */
    ExpectIntEQ(WC_NO_ERR_TRACE(BAD_FUNC_ARG), wolfSSL_X509_cmp(NULL, cert2));

    /* wolfSSL_X509_cmp() testing valid, NULL args */
    ExpectIntEQ(WC_NO_ERR_TRACE(BAD_FUNC_ARG), wolfSSL_X509_cmp(cert1, NULL));

    /* wolfSSL_X509_cmp() testing NULL, NULL args */
    ExpectIntEQ(WC_NO_ERR_TRACE(BAD_FUNC_ARG), wolfSSL_X509_cmp(NULL, NULL));

    /* wolfSSL_X509_cmp() testing empty cert */
    ExpectIntEQ(WOLFSSL_FATAL_ERROR, wolfSSL_X509_cmp(empty, cert2));
    ExpectIntEQ(WOLFSSL_FATAL_ERROR, wolfSSL_X509_cmp(cert1, empty));

    wolfSSL_X509_free(empty);
    wolfSSL_X509_free(cert2);
    wolfSSL_X509_free(cert1);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_PKEY_up_ref(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL)
    EVP_PKEY* pkey;

    pkey = EVP_PKEY_new();
    ExpectNotNull(pkey);
    ExpectIntEQ(EVP_PKEY_up_ref(NULL), 0);
    ExpectIntEQ(EVP_PKEY_up_ref(pkey), 1);
    EVP_PKEY_free(pkey);
    ExpectIntEQ(EVP_PKEY_up_ref(pkey), 1);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_d2i_and_i2d_PublicKey(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    EVP_PKEY* pkey = NULL;
    const unsigned char* p;
    unsigned char *der = NULL;
    unsigned char *tmp = NULL;
    int derLen;

    p = client_keypub_der_2048;
    /* Check that key can be successfully decoded. */
    ExpectNotNull(pkey = wolfSSL_d2i_PublicKey(EVP_PKEY_RSA, NULL, &p,
        sizeof_client_keypub_der_2048));
    /* Check that key can be successfully encoded. */
    ExpectIntGE((derLen = wolfSSL_i2d_PublicKey(pkey, &der)), 0);
    /* Ensure that the encoded version matches the original. */
    ExpectIntEQ(derLen, sizeof_client_keypub_der_2048);
    ExpectIntEQ(XMEMCMP(der, client_keypub_der_2048, derLen), 0);

    /* Do same test except with pre-allocated buffer to ensure the der pointer
     * is advanced. */
    tmp = der;
    ExpectIntGE((derLen = wolfSSL_i2d_PublicKey(pkey, &tmp)), 0);
    ExpectIntEQ(derLen, sizeof_client_keypub_der_2048);
    ExpectIntEQ(XMEMCMP(der, client_keypub_der_2048, derLen), 0);
    ExpectTrue(der + derLen == tmp);

    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_d2i_and_i2d_PublicKey_ecc(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && !defined(NO_CERTS) && \
    !defined(NO_ASN) && !defined(NO_PWDBASED)
    EVP_PKEY* pkey = NULL;
    const unsigned char* p;
    unsigned char *der = NULL;
    unsigned char *tmp = NULL;
    int derLen;
    unsigned char pub_buf[65];
    const int pub_len = 65;
    BN_CTX* ctx = NULL;
    EC_GROUP* curve = NULL;
    EC_KEY* ephemeral_key = NULL;
    const EC_POINT* h = NULL;

    /* Generate an x963 key pair and get public part into pub_buf */
    ExpectNotNull(ctx = BN_CTX_new());
    ExpectNotNull(curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectNotNull(ephemeral_key = EC_KEY_new_by_curve_name(
        NID_X9_62_prime256v1));
    ExpectIntEQ(EC_KEY_generate_key(ephemeral_key), 1);
    ExpectNotNull(h = EC_KEY_get0_public_key(ephemeral_key));
    ExpectIntEQ(pub_len, EC_POINT_point2oct(curve, h,
        POINT_CONVERSION_UNCOMPRESSED, pub_buf, pub_len, ctx));
    /* Prepare the EVP_PKEY */
    ExpectNotNull(pkey = EVP_PKEY_new());

    p = pub_buf;
    /* Check that key can be successfully decoded. */
    ExpectNotNull(wolfSSL_d2i_PublicKey(EVP_PKEY_EC, &pkey, &p,
        pub_len));

    /* Check that key can be successfully encoded. */
    ExpectIntGE((derLen = wolfSSL_i2d_PublicKey(pkey, &der)), 0);
    /* Ensure that the encoded version matches the original. */
    ExpectIntEQ(derLen, pub_len);
    ExpectIntEQ(XMEMCMP(der, pub_buf, derLen), 0);

    /* Do same test except with pre-allocated buffer to ensure the der pointer
     * is advanced. */
    tmp = der;
    ExpectIntGE((derLen = wolfSSL_i2d_PublicKey(pkey, &tmp)), 0);
    ExpectIntEQ(derLen, pub_len);
    ExpectIntEQ(XMEMCMP(der, pub_buf, derLen), 0);
    ExpectTrue(der + derLen == tmp);

    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
    EVP_PKEY_free(pkey);
    EC_KEY_free(ephemeral_key);
    EC_GROUP_free(curve);
    BN_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_d2i_and_i2d_DSAparams(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DSA)
    DSA* dsa = NULL;
    byte derIn[] = {
        0x30, 0x82, 0x01, 0x1f, 0x02, 0x81, 0x81, 0x00,
        0xcd, 0xde, 0x25, 0x68, 0x80, 0x53, 0x0d, 0xe5,
        0x77, 0xd6, 0xd2, 0x90, 0x39, 0x3f, 0x90, 0xa2,
        0x3f, 0x33, 0x94, 0x6e, 0xe8, 0x4f, 0x2b, 0x63,
        0xab, 0x30, 0xab, 0x15, 0xba, 0x11, 0xea, 0x8a,
        0x5d, 0x8d, 0xcc, 0xb8, 0xd4, 0xa1, 0xd5, 0xc1,
        0x47, 0x9d, 0x5a, 0x73, 0x6a, 0x62, 0x49, 0xd1,
        0x06, 0x07, 0x67, 0xf6, 0x2f, 0xa3, 0x39, 0xbd,
        0x4e, 0x0d, 0xb4, 0xd3, 0x22, 0x23, 0x84, 0xec,
        0x93, 0x26, 0x5a, 0x49, 0xee, 0x7c, 0x89, 0x48,
        0x66, 0x4d, 0xe8, 0xe8, 0xd8, 0x50, 0xfb, 0xa5,
        0x71, 0x9f, 0x22, 0x18, 0xe5, 0xe6, 0x0b, 0x46,
        0x87, 0x66, 0xee, 0x52, 0x8f, 0x46, 0x4f, 0xb5,
        0x03, 0xce, 0xed, 0xe3, 0xbe, 0xe5, 0xb5, 0x81,
        0xd2, 0x59, 0xe9, 0xc0, 0xad, 0x4d, 0xd0, 0x4d,
        0x26, 0xf7, 0xba, 0x50, 0xe8, 0xc9, 0x8f, 0xfe,
        0x24, 0x19, 0x3d, 0x2e, 0xa7, 0x52, 0x3c, 0x6d,
        0x02, 0x15, 0x00, 0xfb, 0x47, 0xfb, 0xec, 0x81,
        0x20, 0xc8, 0x1c, 0xe9, 0x4a, 0xba, 0x04, 0x6f,
        0x19, 0x9b, 0x94, 0xee, 0x82, 0x67, 0xd3, 0x02,
        0x81, 0x81, 0x00, 0x9b, 0x95, 0xbb, 0x85, 0xc5,
        0x58, 0x4a, 0x32, 0x9c, 0xaa, 0x44, 0x85, 0xd6,
        0x68, 0xdc, 0x3e, 0x14, 0xf4, 0xce, 0x6d, 0xa3,
        0x49, 0x38, 0xea, 0xd6, 0x61, 0x48, 0x92, 0x5a,
        0x40, 0x95, 0x49, 0x38, 0xaa, 0xe1, 0x39, 0x29,
        0x68, 0x58, 0x47, 0x8a, 0x4b, 0x01, 0xe1, 0x2e,
        0x8e, 0x6c, 0x63, 0x6f, 0x40, 0xca, 0x50, 0x3f,
        0x8c, 0x0b, 0x99, 0xe4, 0x72, 0x42, 0xb8, 0xb1,
        0xc2, 0x26, 0x48, 0xf1, 0x9c, 0x83, 0xc6, 0x37,
        0x2e, 0x5a, 0xae, 0x11, 0x09, 0xd9, 0xf3, 0xad,
        0x1f, 0x6f, 0xad, 0xad, 0x50, 0xe3, 0x78, 0x32,
        0xe6, 0xde, 0x8e, 0xaa, 0xbf, 0xd1, 0x00, 0x9f,
        0xb3, 0x02, 0x12, 0x19, 0xa2, 0x15, 0xec, 0x14,
        0x18, 0x5c, 0x0e, 0x26, 0xce, 0xf9, 0xae, 0xcc,
        0x7b, 0xb5, 0xd1, 0x26, 0xfc, 0x85, 0xfe, 0x14,
        0x93, 0xb6, 0x9d, 0x7d, 0x76, 0xe3, 0x35, 0x97,
        0x1e, 0xde, 0xc4
    };
    int derInLen = sizeof(derIn);
    byte* derOut = NULL;
    int derOutLen;
    byte* p = derIn;

    /* Check that params can be successfully decoded. */
    ExpectNotNull(dsa = d2i_DSAparams(NULL, (const byte**)&p, derInLen));
    /* Check that params can be successfully encoded. */
    ExpectIntGE((derOutLen = i2d_DSAparams(dsa, &derOut)), 0);
    /* Ensure that the encoded version matches the original. */
    ExpectIntEQ(derInLen, derOutLen);
    ExpectIntEQ(XMEMCMP(derIn, derOut, derInLen), 0);

    XFREE(derOut, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
    DSA_free(dsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_i2d_PrivateKey(void)
{
    EXPECT_DECLS;
#if (!defined(NO_RSA) || defined(HAVE_ECC)) && defined(OPENSSL_EXTRA) && \
    !defined(NO_ASN) && !defined(NO_PWDBASED)

#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
    {
        EVP_PKEY* pkey = NULL;
        const unsigned char* server_key =
            (const unsigned char*)server_key_der_2048;
        unsigned char buf[FOURK_BUF];
        unsigned char* pt = NULL;
        int bufSz = 0;

        ExpectNotNull(pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &server_key,
            (long)sizeof_server_key_der_2048));
        ExpectIntEQ(i2d_PrivateKey(pkey, NULL), 1193);
        pt = buf;
        ExpectIntEQ((bufSz = i2d_PrivateKey(pkey, &pt)), 1193);
        ExpectIntNE((pt - buf), 0);
        ExpectIntEQ(XMEMCMP(buf, server_key_der_2048, bufSz), 0);
        EVP_PKEY_free(pkey);
    }
#endif
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
    {
        EVP_PKEY* pkey = NULL;
        const unsigned char* client_key =
            (const unsigned char*)ecc_clikey_der_256;
        unsigned char buf[FOURK_BUF];
        unsigned char* pt = NULL;
        int bufSz = 0;

        ExpectNotNull((pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &client_key,
            (long)sizeof_ecc_clikey_der_256)));
        ExpectIntEQ(i2d_PrivateKey(pkey, NULL), 121);
        pt = buf;
        ExpectIntEQ((bufSz = i2d_PrivateKey(pkey, &pt)), 121);
        ExpectIntNE((pt - buf), 0);
        ExpectIntEQ(XMEMCMP(buf, ecc_clikey_der_256, bufSz), 0);
        EVP_PKEY_free(pkey);
    }
#endif
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_OCSP_id_get0_info(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_HAPROXY)) && \
    defined(HAVE_OCSP) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    !defined(WOLFSSL_SM2) && !defined(WOLFSSL_SM3)
    X509* cert = NULL;
    X509* issuer = NULL;
    OCSP_CERTID* id = NULL;
    OCSP_CERTID* id2 = NULL;

    ASN1_STRING* name = NULL;
    ASN1_OBJECT* pmd  = NULL;
    ASN1_STRING* keyHash = NULL;
    ASN1_INTEGER* serial = NULL;
    ASN1_INTEGER* x509Int = NULL;

    ExpectNotNull(cert = wolfSSL_X509_load_certificate_file(svrCertFile,
        SSL_FILETYPE_PEM));
    ExpectNotNull(issuer = wolfSSL_X509_load_certificate_file(caCertFile,
        SSL_FILETYPE_PEM));

    ExpectNotNull(id = OCSP_cert_to_id(NULL, cert, issuer));
    ExpectNotNull(id2 = OCSP_cert_to_id(NULL, cert, issuer));

    ExpectIntEQ(OCSP_id_get0_info(NULL, NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(OCSP_id_get0_info(NULL, NULL, NULL, NULL, id), 1);

    /* name, pmd, keyHash not supported yet, expect failure if not NULL */
    ExpectIntEQ(OCSP_id_get0_info(&name, NULL, NULL, NULL, id), 0);
    ExpectIntEQ(OCSP_id_get0_info(NULL, &pmd, NULL, NULL, id), 0);
    ExpectIntEQ(OCSP_id_get0_info(NULL, NULL, &keyHash, NULL, id), 0);

    ExpectIntEQ(OCSP_id_get0_info(NULL, NULL, NULL, &serial, id), 1);
    ExpectNotNull(serial);

    /* compare serial number to one in cert, should be equal */
    ExpectNotNull(x509Int = X509_get_serialNumber(cert));
    ExpectIntEQ(x509Int->length, serial->length);
    ExpectIntEQ(XMEMCMP(x509Int->data, serial->data, serial->length), 0);
    ExpectNotNull(x509Int = X509_get_serialNumber(cert));

    /* test OCSP_id_cmp */
    ExpectIntNE(OCSP_id_cmp(NULL, NULL), 0);
    ExpectIntNE(OCSP_id_cmp(id, NULL), 0);
    ExpectIntNE(OCSP_id_cmp(NULL, id2), 0);
    ExpectIntEQ(OCSP_id_cmp(id, id2), 0);
    if (id != NULL) {
        id->issuerHash[0] = ~id->issuerHash[0];
    }
    ExpectIntNE(OCSP_id_cmp(id, id2), 0);

    OCSP_CERTID_free(id);
    OCSP_CERTID_free(id2);
    X509_free(cert); /* free's x509Int */
    X509_free(issuer);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_i2d_OCSP_CERTID(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_HAPROXY)) && defined(HAVE_OCSP)
    WOLFSSL_OCSP_CERTID certId;
    byte* targetBuffer = NULL;
    byte* p;
    /* OCSP CertID bytes taken from PCAP */
    byte rawCertId[] = {
        0x30, 0x49, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
        0x00, 0x04, 0x14, 0x80, 0x51, 0x06, 0x01, 0x32, 0xad, 0x9a, 0xc2, 0x7d,
        0x51, 0x87, 0xa0, 0xe8, 0x87, 0xfb, 0x01, 0x62, 0x01, 0x55, 0xee, 0x04,
        0x14, 0x03, 0xde, 0x50, 0x35, 0x56, 0xd1, 0x4c, 0xbb, 0x66, 0xf0, 0xa3,
        0xe2, 0x1b, 0x1b, 0xc3, 0x97, 0xb2, 0x3d, 0xd1, 0x55, 0x02, 0x10, 0x01,
        0xfd, 0xa3, 0xeb, 0x6e, 0xca, 0x75, 0xc8, 0x88, 0x43, 0x8b, 0x72, 0x4b,
        0xcf, 0xbc, 0x91
    };
    int ret = 0;
    int i;

    XMEMSET(&certId, 0, sizeof(WOLFSSL_OCSP_CERTID));
    certId.rawCertId = rawCertId;
    certId.rawCertIdSize = sizeof(rawCertId);

    ExpectNotNull(targetBuffer = (byte*)XMALLOC(sizeof(rawCertId), NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    p = targetBuffer;
    /* Function returns the size of the encoded data. */
    ExpectIntEQ(ret = wolfSSL_i2d_OCSP_CERTID(&certId, &p), sizeof(rawCertId));
    /* If target buffer is not null, function increments targetBuffer to point
     * just past the end of the encoded data. */
    ExpectPtrEq(p, (targetBuffer + sizeof(rawCertId)));
    for (i = 0; EXPECT_SUCCESS() && i < ret; ++i) {
        ExpectIntEQ(targetBuffer[i], rawCertId[i]);
    }
    XFREE(targetBuffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    targetBuffer = NULL;

    /* If target buffer is null, function allocates memory for a buffer and
     * copies the encoded data into it. targetBuffer then points to the start of
     * this newly allocate buffer. */
    ExpectIntEQ(ret = wolfSSL_i2d_OCSP_CERTID(&certId, &targetBuffer),
        sizeof(rawCertId));
    for (i = 0; EXPECT_SUCCESS() && i < ret; ++i) {
        ExpectIntEQ(targetBuffer[i], rawCertId[i]);
    }
    XFREE(targetBuffer, NULL, DYNAMIC_TYPE_OPENSSL);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_d2i_OCSP_CERTID(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_HAPROXY)) && defined(HAVE_OCSP)
    WOLFSSL_OCSP_CERTID* certIdGood;
    WOLFSSL_OCSP_CERTID* certIdBad;
    const unsigned char* rawCertIdPtr;

    const unsigned char rawCertId[] = {
        0x30, 0x49, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
        0x00, 0x04, 0x14, 0x80, 0x51, 0x06, 0x01, 0x32, 0xad, 0x9a, 0xc2, 0x7d,
        0x51, 0x87, 0xa0, 0xe8, 0x87, 0xfb, 0x01, 0x62, 0x01, 0x55, 0xee, 0x04,
        0x14, 0x03, 0xde, 0x50, 0x35, 0x56, 0xd1, 0x4c, 0xbb, 0x66, 0xf0, 0xa3,
        0xe2, 0x1b, 0x1b, 0xc3, 0x97, 0xb2, 0x3d, 0xd1, 0x55, 0x02, 0x10, 0x01,
        0xfd, 0xa3, 0xeb, 0x6e, 0xca, 0x75, 0xc8, 0x88, 0x43, 0x8b, 0x72, 0x4b,
        0xcf, 0xbc, 0x91
    };

    rawCertIdPtr = &rawCertId[0];

    /* If the cert ID is NULL the function should allocate it and copy the
     * data to it. */
    {
        WOLFSSL_OCSP_CERTID* certId = NULL;
        ExpectNotNull(certId = wolfSSL_d2i_OCSP_CERTID(&certId, &rawCertIdPtr,
                                                       sizeof(rawCertId)));
        if (certId != NULL) {
            XFREE(certId->rawCertId, NULL, DYNAMIC_TYPE_OPENSSL);
            wolfSSL_OCSP_CERTID_free(certId);
        }
    }

    /* If the cert ID is not NULL the function will just copy the data to it. */
    {
        WOLFSSL_OCSP_CERTID* certId = NULL;
        ExpectNotNull(certId = (WOLFSSL_OCSP_CERTID*)XMALLOC(sizeof(*certId), NULL,
                                                             DYNAMIC_TYPE_TMP_BUFFER));
        ExpectNotNull(certId);
        if (certId != NULL)
            XMEMSET(certId, 0, sizeof(*certId));

        /* Reset rawCertIdPtr since it was push forward in the previous call. */
        rawCertIdPtr = &rawCertId[0];
        ExpectNotNull(certIdGood = wolfSSL_d2i_OCSP_CERTID(&certId, &rawCertIdPtr,
                                                           sizeof(rawCertId)));
        ExpectPtrEq(certIdGood, certId);
        if (certId != NULL) {
            XFREE(certId->rawCertId, NULL, DYNAMIC_TYPE_OPENSSL);
            wolfSSL_OCSP_CERTID_free(certId);
            certId = NULL;
        }
    }

    /* The below tests should fail when passed bad parameters. NULL should
     * always be returned. */
    {
        WOLFSSL_OCSP_CERTID* certId = NULL;
        ExpectNull(certIdBad = wolfSSL_d2i_OCSP_CERTID(&certId, NULL,
                                                       sizeof(rawCertId)));
        ExpectNull(certIdBad = wolfSSL_d2i_OCSP_CERTID(&certId, &rawCertIdPtr, 0));
    }
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_OCSP_id_cmp(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_OCSP)
    OCSP_CERTID id1;
    OCSP_CERTID id2;

    XMEMSET(&id1, 0, sizeof(id1));
    XMEMSET(&id2, 0, sizeof(id2));
    ExpectIntEQ(OCSP_id_cmp(&id1, &id2), 0);
    ExpectIntNE(OCSP_id_cmp(NULL, NULL), 0);
    ExpectIntNE(OCSP_id_cmp(&id1, NULL), 0);
    ExpectIntNE(OCSP_id_cmp(NULL, &id2), 0);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_OCSP_SINGLERESP_get0_id(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && defined(OPENSSL_EXTRA)
    WOLFSSL_OCSP_SINGLERESP single;
    const WOLFSSL_OCSP_CERTID* certId;

    XMEMSET(&single, 0, sizeof(single));

    certId = wolfSSL_OCSP_SINGLERESP_get0_id(&single);
    ExpectPtrEq(&single, certId);

    ExpectNull(wolfSSL_OCSP_SINGLERESP_get0_id(NULL));
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_OCSP_single_get0_status(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_OCSP_PARSE_STATUS)
    WOLFSSL_OCSP_SINGLERESP single;
    CertStatus certStatus;
    WOLFSSL_ASN1_TIME* thisDate;
    WOLFSSL_ASN1_TIME* nextDate;
    int ret, i;

    XMEMSET(&single,     0, sizeof(WOLFSSL_OCSP_SINGLERESP));
    XMEMSET(&certStatus, 0, sizeof(CertStatus));

    /* Fill the date fields with some dummy data. */
    for (i = 0; i < CTC_DATE_SIZE; ++i) {
        certStatus.thisDateParsed.data[i] = i;
        certStatus.nextDateParsed.data[i] = i;
    }
    certStatus.status = CERT_GOOD;
    single.status = &certStatus;

    ret = wolfSSL_OCSP_single_get0_status(&single, NULL, NULL, &thisDate,
                                          &nextDate);
    ExpectIntEQ(ret, CERT_GOOD);
    ExpectPtrEq(thisDate, &certStatus.thisDateParsed);
    ExpectPtrEq(nextDate, &certStatus.nextDateParsed);

    ExpectIntEQ(wolfSSL_OCSP_single_get0_status(NULL, NULL, NULL, NULL, NULL),
        CERT_GOOD);
    ExpectIntEQ(wolfSSL_OCSP_single_get0_status(&single, NULL, NULL, NULL,
        NULL), CERT_GOOD);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_OCSP_resp_count(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && defined(OPENSSL_EXTRA)
    WOLFSSL_OCSP_BASICRESP basicResp;
    WOLFSSL_OCSP_SINGLERESP singleRespOne;
    WOLFSSL_OCSP_SINGLERESP singleRespTwo;

    XMEMSET(&basicResp,     0, sizeof(WOLFSSL_OCSP_BASICRESP));
    XMEMSET(&singleRespOne, 0, sizeof(WOLFSSL_OCSP_SINGLERESP));
    XMEMSET(&singleRespTwo, 0, sizeof(WOLFSSL_OCSP_SINGLERESP));

    ExpectIntEQ(wolfSSL_OCSP_resp_count(&basicResp), 0);
    basicResp.single = &singleRespOne;
    ExpectIntEQ(wolfSSL_OCSP_resp_count(&basicResp), 1);
    singleRespOne.next = &singleRespTwo;
    ExpectIntEQ(wolfSSL_OCSP_resp_count(&basicResp), 2);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_OCSP_resp_get0(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && defined(OPENSSL_EXTRA)
    WOLFSSL_OCSP_BASICRESP basicResp;
    WOLFSSL_OCSP_SINGLERESP singleRespOne;
    WOLFSSL_OCSP_SINGLERESP singleRespTwo;

    XMEMSET(&basicResp,     0, sizeof(WOLFSSL_OCSP_BASICRESP));
    XMEMSET(&singleRespOne, 0, sizeof(WOLFSSL_OCSP_SINGLERESP));
    XMEMSET(&singleRespTwo, 0, sizeof(WOLFSSL_OCSP_SINGLERESP));

    basicResp.single = &singleRespOne;
    singleRespOne.next = &singleRespTwo;
    ExpectPtrEq(wolfSSL_OCSP_resp_get0(&basicResp, 0), &singleRespOne);
    ExpectPtrEq(wolfSSL_OCSP_resp_get0(&basicResp, 1), &singleRespTwo);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_OCSP_parse_url(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_OCSP)
#define CK_OPU_OK(u, h, po, pa, s) do { \
    char* host = NULL; \
    char* port = NULL; \
    char* path = NULL; \
    int isSsl = 0; \
    ExpectIntEQ(OCSP_parse_url(u, &host, &port, &path, &isSsl), 1); \
    ExpectStrEQ(host, h); \
    ExpectStrEQ(port, po); \
    ExpectStrEQ(path, pa); \
    ExpectIntEQ(isSsl, s); \
    XFREE(host, NULL, DYNAMIC_TYPE_OPENSSL); \
    XFREE(port, NULL, DYNAMIC_TYPE_OPENSSL); \
    XFREE(path, NULL, DYNAMIC_TYPE_OPENSSL); \
} while(0)

#define CK_OPU_FAIL(u) do { \
    char* host = NULL; \
    char* port = NULL; \
    char* path = NULL; \
    int isSsl = 0; \
    ExpectIntEQ(OCSP_parse_url(u, &host, &port, &path, &isSsl), 0); \
    XFREE(host, NULL, DYNAMIC_TYPE_OPENSSL); \
    XFREE(port, NULL, DYNAMIC_TYPE_OPENSSL); \
    XFREE(path, NULL, DYNAMIC_TYPE_OPENSSL); \
} while(0)

    CK_OPU_OK("http://localhost", "localhost", "80", "/", 0);
    CK_OPU_OK("https://wolfssl.com", "wolfssl.com", "443", "/", 1);
    CK_OPU_OK("https://www.wolfssl.com/fips-140-3-announcement-to-the-world/",
         "www.wolfssl.com", "443", "/fips-140-3-announcement-to-the-world/", 1);
    CK_OPU_OK("http://localhost:1234", "localhost", "1234", "/", 0);
    CK_OPU_OK("https://localhost:1234", "localhost", "1234", "/", 1);

    CK_OPU_FAIL("ftp://localhost");
    /* two strings to cppcheck doesn't mark it as a c++ style comment */
    CK_OPU_FAIL("http/""/localhost");
    CK_OPU_FAIL("http:/localhost");
    CK_OPU_FAIL("https://localhost/path:1234");

#undef CK_OPU_OK
#undef CK_OPU_FAIL
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_ALL) && defined(HAVE_OCSP) && \
    defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM) && \
    !defined(NO_ASN_TIME)
static time_t test_wolfSSL_OCSP_REQ_CTX_time_cb(time_t* t)
{
    if (t != NULL) {
        *t = 1722006780;
    }

    return 1722006780;
}
#endif

static int test_wolfSSL_OCSP_REQ_CTX(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_OCSP) && \
    defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM)
    /* This buffer was taken from the ocsp-stapling.test test case 1. The ocsp
     * response was captured in wireshark. It contains both the http and binary
     * parts. The time test_wolfSSL_OCSP_REQ_CTX_time_cb is set exactly so that
     * the time check passes. */
    unsigned char ocspRespBin[] = {
      0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x20, 0x32, 0x30, 0x30,
      0x20, 0x4f, 0x4b, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
      0x2d, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69,
      0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2d,
      0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
      0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68,
      0x3a, 0x20, 0x31, 0x38, 0x32, 0x31, 0x0d, 0x0a, 0x0d, 0x0a, 0x30, 0x82,
      0x07, 0x19, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x07, 0x12, 0x30, 0x82, 0x07,
      0x0e, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
      0x04, 0x82, 0x06, 0xff, 0x30, 0x82, 0x06, 0xfb, 0x30, 0x82, 0x01, 0x19,
      0xa1, 0x81, 0xa1, 0x30, 0x81, 0x9e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
      0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06,
      0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e,
      0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
      0x07, 0x0c, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x31, 0x10,
      0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x77, 0x6f, 0x6c,
      0x66, 0x53, 0x53, 0x4c, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
      0x0b, 0x0c, 0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65, 0x72, 0x69,
      0x6e, 0x67, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
      0x16, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x20, 0x4f, 0x43, 0x53,
      0x50, 0x20, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x31,
      0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
      0x09, 0x01, 0x16, 0x10, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c,
      0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x18, 0x0f, 0x32, 0x30,
      0x32, 0x34, 0x30, 0x37, 0x32, 0x36, 0x31, 0x35, 0x31, 0x32, 0x30, 0x35,
      0x5a, 0x30, 0x62, 0x30, 0x60, 0x30, 0x38, 0x30, 0x07, 0x06, 0x05, 0x2b,
      0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14, 0x71, 0x4d, 0x82, 0x23, 0x40, 0x59,
      0xc0, 0x96, 0xa1, 0x37, 0x43, 0xfa, 0x31, 0xdb, 0xba, 0xb1, 0x43, 0x18,
      0xda, 0x04, 0x04, 0x14, 0x83, 0xc6, 0x3a, 0x89, 0x2c, 0x81, 0xf4, 0x02,
      0xd7, 0x9d, 0x4c, 0xe2, 0x2a, 0xc0, 0x71, 0x82, 0x64, 0x44, 0xda, 0x0e,
      0x02, 0x01, 0x05, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x34, 0x30,
      0x37, 0x32, 0x36, 0x31, 0x35, 0x31, 0x32, 0x30, 0x35, 0x5a, 0xa0, 0x11,
      0x18, 0x0f, 0x32, 0x30, 0x32, 0x34, 0x30, 0x37, 0x32, 0x36, 0x31, 0x35,
      0x31, 0x33, 0x30, 0x35, 0x5a, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
      0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01,
      0x00, 0x89, 0x7a, 0xe9, 0x6b, 0x66, 0x47, 0x8e, 0x52, 0x16, 0xf9, 0x8a,
      0x5a, 0x1e, 0x7a, 0x35, 0xbb, 0x1d, 0x6c, 0xd8, 0x31, 0xbb, 0x24, 0xd2,
      0xd7, 0xa4, 0x30, 0x27, 0x06, 0x17, 0x66, 0xd1, 0xf9, 0x8d, 0x24, 0xb0,
      0x49, 0x37, 0x62, 0x13, 0x78, 0x5e, 0xa6, 0x6d, 0xea, 0xe3, 0xd0, 0x30,
      0x82, 0x7d, 0xb6, 0xf6, 0x55, 0x82, 0x11, 0xdc, 0xe7, 0x0f, 0xd6, 0x24,
      0xb4, 0x80, 0x23, 0x4f, 0xfd, 0xa7, 0x9a, 0x4b, 0xac, 0xf2, 0xd3, 0xde,
      0x42, 0x10, 0xfb, 0x4b, 0x29, 0x06, 0x02, 0x7b, 0x47, 0x36, 0x70, 0x75,
      0x45, 0x38, 0x8d, 0x3e, 0x55, 0x9c, 0xce, 0x78, 0xd8, 0x18, 0x45, 0x47,
      0x2d, 0x2a, 0x46, 0x65, 0x13, 0x93, 0x1a, 0x98, 0x90, 0xc6, 0x2d, 0xd5,
      0x05, 0x2a, 0xfc, 0xcb, 0xac, 0x53, 0x73, 0x93, 0x42, 0x4e, 0xdb, 0x17,
      0x91, 0xcb, 0xe1, 0x08, 0x03, 0xd1, 0x33, 0x57, 0x4b, 0x1d, 0xb8, 0x71,
      0x84, 0x01, 0x04, 0x47, 0x6f, 0x06, 0xfa, 0x76, 0x7d, 0xd9, 0x37, 0x64,
      0x57, 0x37, 0x3a, 0x8f, 0x4d, 0x88, 0x11, 0xa5, 0xd4, 0xaa, 0xcb, 0x49,
      0x47, 0x86, 0xdd, 0xcf, 0x46, 0xa6, 0xfa, 0x8e, 0xf2, 0x62, 0x0f, 0xc9,
      0x25, 0xf2, 0x39, 0x62, 0x3e, 0x2d, 0x35, 0xc4, 0x76, 0x7b, 0xae, 0xd5,
      0xe8, 0x85, 0xa1, 0xa6, 0x2d, 0x41, 0xd6, 0x8e, 0x3c, 0xfa, 0xdc, 0x6c,
      0x66, 0xe2, 0x61, 0xe7, 0xe5, 0x90, 0xa1, 0xfd, 0x7f, 0xdb, 0x18, 0xd0,
      0xeb, 0x6d, 0x73, 0x08, 0x5f, 0x6a, 0x65, 0x44, 0x50, 0xad, 0x38, 0x9d,
      0xb6, 0xfb, 0xbf, 0x28, 0x55, 0x84, 0x65, 0xfa, 0x0e, 0x34, 0xfc, 0x43,
      0x19, 0x80, 0x5c, 0x7d, 0x2d, 0x5b, 0xd8, 0x60, 0xec, 0x0e, 0xf9, 0x1e,
      0x6e, 0x32, 0x3f, 0x35, 0xf7, 0xec, 0x7e, 0x47, 0xba, 0xb5, 0xd2, 0xaa,
      0x5a, 0x9d, 0x07, 0x2c, 0xc5, 0xa0, 0x82, 0x04, 0xc6, 0x30, 0x82, 0x04,
      0xc2, 0x30, 0x82, 0x04, 0xbe, 0x30, 0x82, 0x03, 0xa6, 0xa0, 0x03, 0x02,
      0x01, 0x02, 0x02, 0x01, 0x04, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
      0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x81, 0x97, 0x31,
      0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
      0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x57,
      0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30,
      0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x53, 0x65, 0x61, 0x74,
      0x74, 0x6c, 0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a,
      0x0c, 0x07, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x31, 0x14, 0x30,
      0x12, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0b, 0x45, 0x6e, 0x67, 0x69,
      0x6e, 0x65, 0x65, 0x72, 0x69, 0x6e, 0x67, 0x31, 0x18, 0x30, 0x16, 0x06,
      0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53,
      0x4c, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x1f, 0x30,
      0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01,
      0x16, 0x10, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73,
      0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x34,
      0x30, 0x37, 0x32, 0x36, 0x31, 0x35, 0x31, 0x32, 0x30, 0x34, 0x5a, 0x17,
      0x0d, 0x32, 0x37, 0x30, 0x34, 0x32, 0x32, 0x31, 0x35, 0x31, 0x32, 0x30,
      0x34, 0x5a, 0x30, 0x81, 0x9e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
      0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
      0x55, 0x04, 0x08, 0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67,
      0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07,
      0x0c, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x31, 0x10, 0x30,
      0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x77, 0x6f, 0x6c, 0x66,
      0x53, 0x53, 0x4c, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0b,
      0x0c, 0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65, 0x72, 0x69, 0x6e,
      0x67, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16,
      0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x20, 0x4f, 0x43, 0x53, 0x50,
      0x20, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x31, 0x1f,
      0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
      0x01, 0x16, 0x10, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66,
      0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x82, 0x01, 0x22, 0x30,
      0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
      0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02,
      0x82, 0x01, 0x01, 0x00, 0xb8, 0xba, 0x23, 0xb4, 0xf6, 0xc3, 0x7b, 0x14,
      0xc3, 0xa4, 0xf5, 0x1d, 0x61, 0xa1, 0xf5, 0x1e, 0x63, 0xb9, 0x85, 0x23,
      0x34, 0x50, 0x6d, 0xf8, 0x7c, 0xa2, 0x8a, 0x04, 0x8b, 0xd5, 0x75, 0x5c,
      0x2d, 0xf7, 0x63, 0x88, 0xd1, 0x07, 0x7a, 0xea, 0x0b, 0x45, 0x35, 0x2b,
      0xeb, 0x1f, 0xb1, 0x22, 0xb4, 0x94, 0x41, 0x38, 0xe2, 0x9d, 0x74, 0xd6,
      0x8b, 0x30, 0x22, 0x10, 0x51, 0xc5, 0xdb, 0xca, 0x3f, 0x46, 0x2b, 0xfe,
      0xe5, 0x5a, 0x3f, 0x41, 0x74, 0x67, 0x75, 0x95, 0xa9, 0x94, 0xd5, 0xc3,
      0xee, 0x42, 0xf8, 0x8d, 0xeb, 0x92, 0x95, 0xe1, 0xd9, 0x65, 0xb7, 0x43,
      0xc4, 0x18, 0xde, 0x16, 0x80, 0x90, 0xce, 0x24, 0x35, 0x21, 0xc4, 0x55,
      0xac, 0x5a, 0x51, 0xe0, 0x2e, 0x2d, 0xb3, 0x0a, 0x5a, 0x4f, 0x4a, 0x73,
      0x31, 0x50, 0xee, 0x4a, 0x16, 0xbd, 0x39, 0x8b, 0xad, 0x05, 0x48, 0x87,
      0xb1, 0x99, 0xe2, 0x10, 0xa7, 0x06, 0x72, 0x67, 0xca, 0x5c, 0xd1, 0x97,
      0xbd, 0xc8, 0xf1, 0x76, 0xf8, 0xe0, 0x4a, 0xec, 0xbc, 0x93, 0xf4, 0x66,
      0x4c, 0x28, 0x71, 0xd1, 0xd8, 0x66, 0x03, 0xb4, 0x90, 0x30, 0xbb, 0x17,
      0xb0, 0xfe, 0x97, 0xf5, 0x1e, 0xe8, 0xc7, 0x5d, 0x9b, 0x8b, 0x11, 0x19,
      0x12, 0x3c, 0xab, 0x82, 0x71, 0x78, 0xff, 0xae, 0x3f, 0x32, 0xb2, 0x08,
      0x71, 0xb2, 0x1b, 0x8c, 0x27, 0xac, 0x11, 0xb8, 0xd8, 0x43, 0x49, 0xcf,
      0xb0, 0x70, 0xb1, 0xf0, 0x8c, 0xae, 0xda, 0x24, 0x87, 0x17, 0x3b, 0xd8,
      0x04, 0x65, 0x6c, 0x00, 0x76, 0x50, 0xef, 0x15, 0x08, 0xd7, 0xb4, 0x73,
      0x68, 0x26, 0x14, 0x87, 0x95, 0xc3, 0x5f, 0x6e, 0x61, 0xb8, 0x87, 0x84,
      0xfa, 0x80, 0x1a, 0x0a, 0x8b, 0x98, 0xf3, 0xe3, 0xff, 0x4e, 0x44, 0x1c,
      0x65, 0x74, 0x7c, 0x71, 0x54, 0x65, 0xe5, 0x39, 0x02, 0x03, 0x01, 0x00,
      0x01, 0xa3, 0x82, 0x01, 0x0a, 0x30, 0x82, 0x01, 0x06, 0x30, 0x09, 0x06,
      0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d, 0x06, 0x03,
      0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x32, 0x67, 0xe1, 0xb1, 0x79,
      0xd2, 0x81, 0xfc, 0x9f, 0x23, 0x0c, 0x70, 0x40, 0x50, 0xb5, 0x46, 0x56,
      0xb8, 0x30, 0x36, 0x30, 0x81, 0xc4, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
      0x81, 0xbc, 0x30, 0x81, 0xb9, 0x80, 0x14, 0x73, 0xb0, 0x1c, 0xa4, 0x2f,
      0x82, 0xcb, 0xcf, 0x47, 0xa5, 0x38, 0xd7, 0xb0, 0x04, 0x82, 0x3a, 0x7e,
      0x72, 0x15, 0x21, 0xa1, 0x81, 0x9d, 0xa4, 0x81, 0x9a, 0x30, 0x81, 0x97,
      0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
      0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a,
      0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10,
      0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x53, 0x65, 0x61,
      0x74, 0x74, 0x6c, 0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
      0x0a, 0x0c, 0x07, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x31, 0x14,
      0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0b, 0x45, 0x6e, 0x67,
      0x69, 0x6e, 0x65, 0x65, 0x72, 0x69, 0x6e, 0x67, 0x31, 0x18, 0x30, 0x16,
      0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x6f, 0x6c, 0x66, 0x53,
      0x53, 0x4c, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x1f,
      0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
      0x01, 0x16, 0x10, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66,
      0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x01, 0x63, 0x30, 0x13,
      0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b,
      0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x30, 0x0d, 0x06, 0x09, 0x2a,
      0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
      0x01, 0x01, 0x00, 0x37, 0xb9, 0x66, 0xd3, 0xa1, 0x08, 0xfc, 0x37, 0x58,
      0x4e, 0xe0, 0x8c, 0xd3, 0x7f, 0xa6, 0x0f, 0x59, 0xd3, 0x14, 0xf7, 0x4b,
      0x36, 0xf7, 0x2e, 0x98, 0xeb, 0x7c, 0x03, 0x3f, 0x3a, 0xd6, 0x9c, 0xcd,
      0xb4, 0x9e, 0x8d, 0x5f, 0x92, 0xa6, 0x6f, 0x63, 0x87, 0x34, 0xe8, 0x83,
      0xfd, 0x6d, 0x34, 0x64, 0xb5, 0xf0, 0x9c, 0x71, 0x02, 0xb8, 0xf6, 0x2f,
      0x10, 0xa0, 0x92, 0x8f, 0x3f, 0x86, 0x3e, 0xe2, 0x01, 0x5a, 0x56, 0x39,
      0x0a, 0x8d, 0xb1, 0xbe, 0x03, 0xf7, 0xf8, 0xa7, 0x88, 0x46, 0xef, 0x81,
      0xa0, 0xad, 0x86, 0xc9, 0xe6, 0x23, 0x89, 0x1d, 0xa6, 0x24, 0x45, 0xf2,
      0x6a, 0x83, 0x2d, 0x8e, 0x92, 0x17, 0x1e, 0x44, 0x19, 0xfa, 0x0f, 0x47,
      0x6b, 0x8f, 0x4a, 0xa2, 0xda, 0xab, 0xd5, 0x2b, 0xcd, 0xcb, 0x14, 0xf0,
      0xb5, 0xcf, 0x7c, 0x76, 0x42, 0x32, 0x90, 0x21, 0xdc, 0xdd, 0x52, 0xfc,
      0x53, 0x7e, 0xff, 0x7f, 0xd9, 0x58, 0x6b, 0x1f, 0x73, 0xee, 0x83, 0xf4,
      0x67, 0xfa, 0x4a, 0x4f, 0x24, 0xe4, 0x2b, 0x10, 0x74, 0x89, 0x52, 0x9a,
      0xf7, 0xa4, 0xe0, 0xaf, 0xf5, 0x63, 0xd7, 0xfa, 0x0b, 0x2c, 0xc9, 0x39,
      0x5d, 0xbd, 0x44, 0x93, 0x69, 0xa4, 0x1d, 0x01, 0xe2, 0x66, 0xe7, 0xc1,
      0x11, 0x44, 0x7d, 0x0a, 0x7e, 0x5d, 0x1d, 0x26, 0xc5, 0x4a, 0x26, 0x2e,
      0xa3, 0x58, 0xc4, 0xf7, 0x10, 0xcb, 0xba, 0xe6, 0x27, 0xfc, 0xdb, 0x54,
      0xe2, 0x60, 0x08, 0xc2, 0x0e, 0x4b, 0xd4, 0xaa, 0x22, 0x23, 0x93, 0x9f,
      0xe1, 0xcb, 0x85, 0xa4, 0x41, 0x6f, 0x26, 0xa7, 0x77, 0x8a, 0xef, 0x66,
      0xd0, 0xf8, 0x33, 0xf6, 0xfd, 0x6d, 0x37, 0x7a, 0x89, 0xcc, 0x88, 0x3b,
      0x82, 0xd0, 0xa9, 0xdf, 0xf1, 0x3d, 0xdc, 0xb0, 0x06, 0x1c, 0xe4, 0x4b,
      0x57, 0xb4, 0x0c, 0x65, 0xb9, 0xb4, 0x6c
    };
    OCSP_REQ_CTX *ctx = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_CERTID *cid = NULL;
    OCSP_RESPONSE *rsp = NULL;
    BIO* bio1 = NULL;
    BIO* bio2 = NULL;
    X509* cert = NULL;
    X509* empty = NULL;
    X509 *issuer = NULL;
    X509_LOOKUP *lookup = NULL;
    X509_STORE *store = NULL;
    STACK_OF(X509_OBJECT) *str_objs = NULL;
    X509_OBJECT *x509_obj = NULL;
    STACK_OF(WOLFSSL_STRING) *skStr = NULL;

    ExpectNotNull(bio1 = BIO_new(BIO_s_bio()));
    ExpectNotNull(bio2 = BIO_new(BIO_s_bio()));
    ExpectIntEQ(BIO_make_bio_pair(bio1, bio2), WOLFSSL_SUCCESS);

    /* Load the leaf cert */
    ExpectNotNull(cert = wolfSSL_X509_load_certificate_file(
            "certs/ocsp/server1-cert.pem", WOLFSSL_FILETYPE_PEM));
    ExpectNull(wolfSSL_X509_get1_ocsp(NULL));
    ExpectNotNull(skStr = wolfSSL_X509_get1_ocsp(cert));
    wolfSSL_X509_email_free(NULL);
    wolfSSL_X509_email_free(skStr);
    ExpectNotNull(empty = wolfSSL_X509_new());
    ExpectNull(wolfSSL_X509_get1_ocsp(empty));
    wolfSSL_X509_free(empty);

    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()));
    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/ocsp/server1-cert.pem",
            X509_FILETYPE_PEM), 1);
    ExpectNotNull(str_objs = X509_STORE_get0_objects(store));
    ExpectNull(X509_OBJECT_retrieve_by_subject(NULL, X509_LU_X509, NULL));
    ExpectNull(X509_OBJECT_retrieve_by_subject(str_objs, X509_LU_X509, NULL));
    ExpectNull(X509_OBJECT_retrieve_by_subject(NULL, X509_LU_X509,
            X509_get_issuer_name(cert)));
    ExpectNull(X509_OBJECT_retrieve_by_subject(str_objs,
            X509_LU_CRL, X509_get_issuer_name(cert)));
    ExpectNotNull(x509_obj = X509_OBJECT_retrieve_by_subject(str_objs,
            X509_LU_X509, X509_get_issuer_name(cert)));
    ExpectNotNull(issuer = X509_OBJECT_get0_X509(x509_obj));
    ExpectTrue(wolfSSL_X509_OBJECT_get_type(NULL) == WOLFSSL_X509_LU_NONE);
#ifndef NO_WOLFSSL_STUB
    /* Not implemented and not in OpenSSL 1.1.0+ */
    wolfSSL_X509_OBJECT_free_contents(x509_obj);
#endif
    wolfSSL_X509_OBJECT_free(NULL);

    ExpectNotNull(req = OCSP_REQUEST_new());
    ExpectNotNull(cid = OCSP_cert_to_id(EVP_sha1(), cert, issuer));
    ExpectNotNull(OCSP_request_add0_id(req, cid));
    ExpectIntEQ(OCSP_request_add1_nonce(req, NULL, -1), 1);

    ExpectNotNull(ctx = OCSP_sendreq_new(bio1, "/", NULL, -1));
    ExpectIntEQ(OCSP_REQ_CTX_add1_header(ctx, "Host", "127.0.0.1"), 1);
    ExpectIntEQ(OCSP_REQ_CTX_set1_req(ctx, req), 1);
    ExpectIntEQ(OCSP_sendreq_nbio(&rsp, ctx), -1);
    ExpectIntEQ(BIO_write(bio2, ocspRespBin, sizeof(ocspRespBin)),
            sizeof(ocspRespBin));
#ifndef NO_ASN_TIME
    ExpectIntEQ(wc_SetTimeCb(test_wolfSSL_OCSP_REQ_CTX_time_cb), 0);
    ExpectIntEQ(OCSP_sendreq_nbio(&rsp, ctx), 1);
    ExpectIntEQ(wc_SetTimeCb(NULL), 0);
    ExpectNotNull(rsp);
#endif

    OCSP_REQ_CTX_free(ctx);
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(rsp);
    BIO_free(bio1);
    BIO_free(bio2);
    X509_free(cert);
    X509_STORE_free(store);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_PKEY_derive(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT) || defined(WOLFSSL_OPENSSH)
#if (!defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)) || defined(HAVE_ECC)
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *skey = NULL;
    size_t skeylen;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peerkey = NULL;
    const unsigned char* key;

#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    /* DH */
    key = dh_key_der_2048;
    ExpectNotNull((pkey = d2i_PrivateKey(EVP_PKEY_DH, NULL, &key,
        sizeof_dh_key_der_2048)));
    ExpectIntEQ(DH_generate_key(EVP_PKEY_get0_DH(pkey)), 1);
    key = dh_key_der_2048;
    ExpectNotNull((peerkey = d2i_PrivateKey(EVP_PKEY_DH, NULL, &key,
        sizeof_dh_key_der_2048)));
    ExpectIntEQ(DH_generate_key(EVP_PKEY_get0_DH(peerkey)), 1);
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_derive_init(ctx), 1);
    ExpectIntEQ(EVP_PKEY_derive_set_peer(ctx, peerkey), 1);
    ExpectIntEQ(EVP_PKEY_derive(ctx, NULL, &skeylen), 1);
    ExpectNotNull(skey = (unsigned char*)XMALLOC(skeylen, NULL,
        DYNAMIC_TYPE_OPENSSL));
    ExpectIntEQ(EVP_PKEY_derive(ctx, skey, &skeylen), 1);

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    EVP_PKEY_free(peerkey);
    peerkey = NULL;
    EVP_PKEY_free(pkey);
    pkey = NULL;
    XFREE(skey, NULL, DYNAMIC_TYPE_OPENSSL);
    skey = NULL;
#endif

#ifdef HAVE_ECC
    /* ECDH */
    key = ecc_clikey_der_256;
    ExpectNotNull((pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &key,
        sizeof_ecc_clikey_der_256)));
    key = ecc_clikeypub_der_256;
    ExpectNotNull((peerkey = d2i_PUBKEY(NULL, &key,
        sizeof_ecc_clikeypub_der_256)));
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_derive_init(ctx), 1);
    ExpectIntEQ(EVP_PKEY_derive_set_peer(ctx, peerkey), 1);
    ExpectIntEQ(EVP_PKEY_derive(ctx, NULL, &skeylen), 1);
    ExpectNotNull(skey = (unsigned char*)XMALLOC(skeylen, NULL,
        DYNAMIC_TYPE_OPENSSL));
    ExpectIntEQ(EVP_PKEY_derive(ctx, skey, &skeylen), 1);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(pkey);
    XFREE(skey, NULL, DYNAMIC_TYPE_OPENSSL);
#endif /* HAVE_ECC */
#endif /* (!NO_DH && WOLFSSL_DH_EXTRA) || HAVE_ECC */
#endif /* OPENSSL_ALL || WOLFSSL_QT || WOLFSSL_OPENSSH */
    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_PBE_scrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_SCRYPT) && defined(HAVE_PBKDF2) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 5))
#if !defined(NO_PWDBASED) &&  !defined(NO_SHA256)
    int ret;

    const char  pwd[]    = {'p','a','s','s','w','o','r','d'};
    int         pwdlen   = sizeof(pwd);
    const byte  salt[]   = {'N','a','C','l'};
    int         saltlen  = sizeof(salt);
    byte        key[80];
    word64      numOvr32 = (word64)INT32_MAX + 1;

    /* expected derived key for N:16, r:1, p:1 */
    const byte expectedKey[] = {
        0xAE, 0xC6, 0xB7, 0x48, 0x3E, 0xD2, 0x6E, 0x08, 0x80, 0x2B,
        0x41, 0xF4, 0x03, 0x20, 0x86, 0xA0, 0xE8, 0x86, 0xBE, 0x7A,
        0xC4, 0x8F, 0xCF, 0xD9, 0x2F, 0xF0, 0xCE, 0xF8, 0x10, 0x97,
        0x52, 0xF4, 0xAC, 0x74, 0xB0, 0x77, 0x26, 0x32, 0x56, 0xA6,
        0x5A, 0x99, 0x70, 0x1B, 0x7A, 0x30, 0x4D, 0x46, 0x61, 0x1C,
        0x8A, 0xA3, 0x91, 0xE7, 0x99, 0xCE, 0x10, 0xA2, 0x77, 0x53,
        0xE7, 0xE9, 0xC0, 0x9A};

    /*                                               N  r  p  mx key keylen */
    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 0, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* N must be greater than 1 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 3, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* N must be power of 2 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 0, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* r must be greater than 0 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 1, 0, 0, key, 64);
    ExpectIntEQ(ret, 0); /* p must be greater than 0 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 1, 1, 0, key, 0);
    ExpectIntEQ(ret, 0); /* keylen must be greater than 0 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 9, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* r must be smaller than 9 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 1, 1, 0, NULL, 64);
    ExpectIntEQ(ret, 1); /* should succeed if key is NULL  */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 1); /* should succeed */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, numOvr32, 1, 0,
                                                                    key, 64);
    ExpectIntEQ(ret, 0); /* should fail since r is greater than INT32_MAC */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 1, numOvr32, 0,
                                                                    key, 64);
    ExpectIntEQ(ret, 0); /* should fail since p is greater than INT32_MAC */

    ret = EVP_PBE_scrypt(pwd, pwdlen, NULL, 0, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 1); /* should succeed even if salt is NULL */

    ret = EVP_PBE_scrypt(pwd, pwdlen, NULL, 4, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* if salt is NULL, saltlen must be 0, otherwise fail*/

    ret = EVP_PBE_scrypt(NULL, 0, salt, saltlen, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 1); /* should succeed if pwd is NULL and pwdlen is 0*/

    ret = EVP_PBE_scrypt(NULL, 4, salt, saltlen, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* if pwd is NULL, pwdlen must be 0 */

    ret = EVP_PBE_scrypt(NULL, 0, NULL, 0, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 1); /* should succeed even both pwd and salt are NULL */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 16, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 1);

    ret = XMEMCMP(expectedKey, key, sizeof(expectedKey));
    ExpectIntEQ(ret, 0); /* derived key must be the same as expected-key */
#endif /* !NO_PWDBASED && !NO_SHA256 */
#endif /* OPENSSL_EXTRA && HAVE_SCRYPT && HAVE_PBKDF2 */
    return EXPECT_RESULT();
}

static int test_no_op_functions(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    /* this makes sure wolfSSL can compile and run these no-op functions */
    SSL_load_error_strings();
    ENGINE_load_builtin_engines();
    OpenSSL_add_all_ciphers();
    ExpectIntEQ(CRYPTO_malloc_init(), 0);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_CRYPTO_memcmp(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    char a[] = "wolfSSL (formerly CyaSSL) is a small, fast, portable "
               "implementation of TLS/SSL for embedded devices to the cloud.";
    char b[] = "wolfSSL (formerly CyaSSL) is a small, fast, portable "
               "implementation of TLS/SSL for embedded devices to the cloud.";
    char c[] = "wolfSSL (formerly CyaSSL) is a small, fast, portable "
               "implementation of TLS/SSL for embedded devices to the cloud!";

    ExpectIntEQ(CRYPTO_memcmp(a, b, sizeof(a)), 0);
    ExpectIntNE(CRYPTO_memcmp(a, c, sizeof(a)), 0);
#endif
    return EXPECT_RESULT();
}

/*----------------------------------------------------------------------------*
 | wolfCrypt ASN
 *----------------------------------------------------------------------------*/

static int test_wc_CreateEncryptedPKCS8Key(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS8) && !defined(NO_PWDBASED) && defined(WOLFSSL_AES_256) \
 && !defined(NO_AES_CBC) && !defined(NO_RSA) && !defined(NO_SHA) && \
    !defined(NO_ASN_CRYPT)
    WC_RNG rng;
    byte* encKey = NULL;
    word32 encKeySz = 0;
    word32 decKeySz = 0;
    const char password[] = "Lorem ipsum dolor sit amet";
    word32 passwordSz = (word32)XSTRLEN(password);
    word32 tradIdx = 0;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    PRIVATE_KEY_UNLOCK();
    /* Call with NULL for out buffer to get necessary length. */
    ExpectIntEQ(wc_CreateEncryptedPKCS8Key((byte*)server_key_der_2048,
        sizeof_server_key_der_2048, NULL, &encKeySz, password, (int)passwordSz,
        PKCS5, PBES2, AES256CBCb, NULL, 0, WC_PKCS12_ITT_DEFAULT, &rng, NULL),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectNotNull(encKey = (byte*)XMALLOC(encKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    /* Call with the allocated out buffer. */
    ExpectIntGT(wc_CreateEncryptedPKCS8Key((byte*)server_key_der_2048,
        sizeof_server_key_der_2048, encKey, &encKeySz, password, (int)passwordSz,
        PKCS5, PBES2, AES256CBCb, NULL, 0, WC_PKCS12_ITT_DEFAULT, &rng, NULL),
        0);
    /* Decrypt the encrypted PKCS8 key we just made. */
    ExpectIntGT((decKeySz = (word32)wc_DecryptPKCS8Key(encKey, encKeySz, password,
        (int)passwordSz)), 0);
    /* encKey now holds the decrypted key (decrypted in place). */
    ExpectIntGT(wc_GetPkcs8TraditionalOffset(encKey, &tradIdx, decKeySz), 0);
    /* Check that the decrypted key matches the key prior to encryption. */
    ExpectIntEQ(XMEMCMP(encKey + tradIdx, server_key_der_2048,
        sizeof_server_key_der_2048), 0);
    PRIVATE_KEY_LOCK();

    XFREE(encKey, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

static int test_wc_GetPkcs8TraditionalOffset(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_FILESYSTEM) && defined(HAVE_PKCS8)
    int length;
    int derSz = 0;
    word32 inOutIdx;
    const char* path = "./certs/server-keyPkcs8.der";
    const char* pathAttributes = "./certs/ca-key-pkcs8-attribute.der";
    XFILE file = XBADFILE;
    byte der[2048];

    ExpectTrue((file = XFOPEN(path, "rb")) != XBADFILE);
    ExpectIntGT(derSz = (int)XFREAD(der, 1, sizeof(der), file), 0);
    if (file != XBADFILE)
        XFCLOSE(file);
    file = XBADFILE; /* reset file to avoid warning of use after close */

    /* valid case */
    inOutIdx = 0;
    ExpectIntGT(length = wc_GetPkcs8TraditionalOffset(der, &inOutIdx, (word32)derSz),
        0);

    /* inOutIdx > sz */
    inOutIdx = 4000;
    ExpectIntEQ(length = wc_GetPkcs8TraditionalOffset(der, &inOutIdx, (word32)derSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* null input */
    inOutIdx = 0;
    ExpectIntEQ(length = wc_GetPkcs8TraditionalOffset(NULL, &inOutIdx, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* invalid input, fill buffer with 1's */
    XMEMSET(der, 1, sizeof(der));
    inOutIdx = 0;
    ExpectIntEQ(length = wc_GetPkcs8TraditionalOffset(der, &inOutIdx, (word32)derSz),
        WC_NO_ERR_TRACE(ASN_PARSE_E));

    /* test parsing with attributes */
    ExpectTrue((file = XFOPEN(pathAttributes, "rb")) != XBADFILE);
    ExpectIntGT(derSz = (int)XFREAD(der, 1, sizeof(der), file), 0);
    if (file != XBADFILE)
        XFCLOSE(file);

    inOutIdx = 0;
    ExpectIntGT(length = wc_GetPkcs8TraditionalOffset(der, &inOutIdx,
        (word32)derSz), 0);
#endif /* NO_ASN */
    return EXPECT_RESULT();
}

static int test_wc_SetSubjectRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && !defined(NO_RSA)
    const char* joiCertFile = "./certs/test/cert-ext-joi.der";
    WOLFSSL_X509* x509 = NULL;
    int peerCertSz;
    const byte* peerCertBuf = NULL;
    Cert forgedCert;

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(joiCertFile,
        WOLFSSL_FILETYPE_ASN1));

    ExpectNotNull(peerCertBuf = wolfSSL_X509_get_der(x509, &peerCertSz));

    ExpectIntEQ(0, wc_InitCert(&forgedCert));

    ExpectIntEQ(0, wc_SetSubjectRaw(&forgedCert, peerCertBuf, peerCertSz));

    wolfSSL_FreeX509(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wc_GetSubjectRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT)
    Cert cert;
    byte *subjectRaw;

    ExpectIntEQ(0, wc_InitCert(&cert));
    ExpectIntEQ(0, wc_GetSubjectRaw(&subjectRaw, &cert));
#endif
    return EXPECT_RESULT();
}

static int test_wc_SetIssuerRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && !defined(NO_RSA)
    const char* joiCertFile = "./certs/test/cert-ext-joi.der";
    WOLFSSL_X509* x509 = NULL;
    int peerCertSz;
    const byte* peerCertBuf = NULL;
    Cert forgedCert;

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(joiCertFile,
        WOLFSSL_FILETYPE_ASN1));

    ExpectNotNull(peerCertBuf = wolfSSL_X509_get_der(x509, &peerCertSz));

    ExpectIntEQ(0, wc_InitCert(&forgedCert));

    ExpectIntEQ(0, wc_SetIssuerRaw(&forgedCert, peerCertBuf, peerCertSz));

    wolfSSL_FreeX509(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wc_SetIssueBuffer(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && !defined(NO_RSA)
    const char* joiCertFile = "./certs/test/cert-ext-joi.der";
    WOLFSSL_X509* x509 = NULL;
    int peerCertSz;
    const byte* peerCertBuf = NULL;
    Cert forgedCert;

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(joiCertFile,
        WOLFSSL_FILETYPE_ASN1));

    ExpectNotNull(peerCertBuf = wolfSSL_X509_get_der(x509, &peerCertSz));

    ExpectIntEQ(0, wc_InitCert(&forgedCert));

    ExpectIntEQ(0, wc_SetIssuerBuffer(&forgedCert, peerCertBuf, peerCertSz));

    wolfSSL_FreeX509(x509);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_SetSubjectKeyId
 */
static int test_wc_SetSubjectKeyId(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && defined(HAVE_ECC)
    Cert cert;
    const char* file = "certs/ecc-client-keyPub.pem";

    ExpectIntEQ(0, wc_InitCert(&cert));
    ExpectIntEQ(0, wc_SetSubjectKeyId(&cert, file));

    ExpectIntEQ(WC_NO_ERR_TRACE(BAD_FUNC_ARG), wc_SetSubjectKeyId(NULL, file));
    ExpectIntGT(0, wc_SetSubjectKeyId(&cert, "badfile.name"));
#endif
    return EXPECT_RESULT();
} /* END test_wc_SetSubjectKeyId */

/*
 * Testing wc_SetSubject
 */
static int test_wc_SetSubject(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && defined(HAVE_ECC)
    Cert cert;
    const char* file = "./certs/ca-ecc-cert.pem";

    ExpectIntEQ(0, wc_InitCert(&cert));
    ExpectIntEQ(0, wc_SetSubject(&cert, file));

    ExpectIntEQ(WC_NO_ERR_TRACE(BAD_FUNC_ARG), wc_SetSubject(NULL, file));
    ExpectIntGT(0, wc_SetSubject(&cert, "badfile.name"));
#endif
    return EXPECT_RESULT();
} /* END test_wc_SetSubject */


static int test_CheckCertSignature(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && defined(WOLFSSL_SMALL_CERT_VERIFY)
    WOLFSSL_CERT_MANAGER* cm = NULL;
#if !defined(NO_FILESYSTEM) && (!defined(NO_RSA) || defined(HAVE_ECC))
    XFILE fp = XBADFILE;
    byte  cert[4096];
    int   certSz;
#endif

    ExpectIntEQ(WC_NO_ERR_TRACE(BAD_FUNC_ARG), wc_CheckCertSignature(NULL, 0, NULL, NULL));
    ExpectNotNull(cm = wolfSSL_CertManagerNew_ex(NULL));
    ExpectIntEQ(WC_NO_ERR_TRACE(BAD_FUNC_ARG), wc_CheckCertSignature(NULL, 0, NULL, cm));

#ifndef NO_RSA
#ifdef USE_CERT_BUFFERS_1024
    ExpectIntEQ(WC_NO_ERR_TRACE(ASN_NO_SIGNER_E), wc_CheckCertSignature(server_cert_der_1024,
                sizeof_server_cert_der_1024, NULL, cm));
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CertManagerLoadCABuffer(cm,
                ca_cert_der_1024, sizeof_ca_cert_der_1024,
                WOLFSSL_FILETYPE_ASN1));
    ExpectIntEQ(0, wc_CheckCertSignature(server_cert_der_1024,
                sizeof_server_cert_der_1024, NULL, cm));
#elif defined(USE_CERT_BUFFERS_2048)
    ExpectIntEQ(WC_NO_ERR_TRACE(ASN_NO_SIGNER_E), wc_CheckCertSignature(server_cert_der_2048,
                sizeof_server_cert_der_2048, NULL, cm));
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CertManagerLoadCABuffer(cm,
                ca_cert_der_2048, sizeof_ca_cert_der_2048,
                WOLFSSL_FILETYPE_ASN1));
    ExpectIntEQ(0, wc_CheckCertSignature(server_cert_der_2048,
                sizeof_server_cert_der_2048, NULL, cm));
#endif
#endif

#if defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
    ExpectIntEQ(WC_NO_ERR_TRACE(ASN_NO_SIGNER_E), wc_CheckCertSignature(serv_ecc_der_256,
                sizeof_serv_ecc_der_256, NULL, cm));
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CertManagerLoadCABuffer(cm,
                ca_ecc_cert_der_256, sizeof_ca_ecc_cert_der_256,
                WOLFSSL_FILETYPE_ASN1));
    ExpectIntEQ(0, wc_CheckCertSignature(serv_ecc_der_256, sizeof_serv_ecc_der_256,
                NULL, cm));
#endif

#if !defined(NO_FILESYSTEM)
    wolfSSL_CertManagerFree(cm);
    cm = NULL;
    ExpectNotNull(cm = wolfSSL_CertManagerNew_ex(NULL));
#ifndef NO_RSA
    ExpectTrue((fp = XFOPEN("./certs/server-cert.der", "rb")) != XBADFILE);
    ExpectIntGT((certSz = (int)XFREAD(cert, 1, sizeof(cert), fp)), 0);
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    ExpectIntEQ(WC_NO_ERR_TRACE(ASN_NO_SIGNER_E), wc_CheckCertSignature(cert, certSz, NULL, cm));
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CertManagerLoadCA(cm,
                "./certs/ca-cert.pem", NULL));
    ExpectIntEQ(0, wc_CheckCertSignature(cert, certSz, NULL, cm));
#endif
#ifdef HAVE_ECC
    ExpectTrue((fp = XFOPEN("./certs/server-ecc.der", "rb")) != XBADFILE);
    ExpectIntGT((certSz = (int)XFREAD(cert, 1, sizeof(cert), fp)), 0);
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    ExpectIntEQ(WC_NO_ERR_TRACE(ASN_NO_SIGNER_E), wc_CheckCertSignature(cert, certSz, NULL, cm));
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CertManagerLoadCA(cm,
                "./certs/ca-ecc-cert.pem", NULL));
    ExpectIntEQ(0, wc_CheckCertSignature(cert, certSz, NULL, cm));
#endif
#endif

#if !defined(NO_FILESYSTEM) && (!defined(NO_RSA) || defined(HAVE_ECC))
    (void)fp;
    (void)cert;
    (void)certSz;
#endif

    wolfSSL_CertManagerFree(cm);
#endif
    return EXPECT_RESULT();
}

static int test_wc_ParseCert(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_RSA)
    DecodedCert decodedCert;
    const byte* rawCert = client_cert_der_2048;
    const int rawCertSize = sizeof_client_cert_der_2048;

    wc_InitDecodedCert(&decodedCert, rawCert, rawCertSize, NULL);
    ExpectIntEQ(wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL), 0);
#ifndef IGNORE_NAME_CONSTRAINTS
    /* check that the subjects emailAddress was not put in the alt name list */
    ExpectNotNull(decodedCert.subjectEmail);
    ExpectNull(decodedCert.altEmailNames);
#endif
    wc_FreeDecodedCert(&decodedCert);
#endif
    return EXPECT_RESULT();
}

/* Test wc_ParseCert decoding of various encodings and scenarios ensuring that
 * the API safely errors out on badly-formed ASN input.
 * NOTE: Test not compatible with released FIPS implementations!
 */
static int test_wc_ParseCert_Error(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_RSA) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
    DecodedCert decodedCert;
    int i;

    /* Certificate data */
    const byte c0[] = { 0x30, 0x04, 0x30, 0x02, 0x02, 0x80, 0x00, 0x00};
    const byte c1[] = { 0x30, 0x04, 0x30, 0x04, 0x02, 0x80, 0x00, 0x00};
    const byte c2[] = { 0x30, 0x06, 0x30, 0x04, 0x02, 0x80, 0x00, 0x00};
    const byte c3[] = { 0x30, 0x07, 0x30, 0x05, 0x02, 0x80, 0x10, 0x00, 0x00};
    const byte c4[] = { 0x02, 0x80, 0x10, 0x00, 0x00};

    /* Test data */
    struct testStruct {
        const byte* c;
        word32 cSz;
        int expRet;
    } t[5];
    const int tSz = (int)(sizeof(t) / sizeof(struct testStruct));

    #define INIT_TEST_DATA(i,x,y) \
        t[i].c = x; t[i].cSz = sizeof(x); t[i].expRet = y
    INIT_TEST_DATA(0, c0, WC_NO_ERR_TRACE(ASN_PARSE_E) );
    INIT_TEST_DATA(1, c1, WC_NO_ERR_TRACE(ASN_PARSE_E) );
    INIT_TEST_DATA(2, c2, WC_NO_ERR_TRACE(ASN_PARSE_E) );
    INIT_TEST_DATA(3, c3, WC_NO_ERR_TRACE(ASN_PARSE_E) );
    INIT_TEST_DATA(4, c4, WC_NO_ERR_TRACE(ASN_PARSE_E) );
    #undef INIT_TEST_DATA

    for (i = 0; i < tSz; i++) {
        WOLFSSL_MSG_EX("i == %d", i);
        wc_InitDecodedCert(&decodedCert, t[i].c, t[i].cSz, NULL);
        ExpectIntEQ(wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL), t[i].expRet);
        wc_FreeDecodedCert(&decodedCert);
    }
#endif
    return EXPECT_RESULT();
}

static int test_MakeCertWithPathLen(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CERT_REQ) && !defined(NO_ASN_TIME) && \
    defined(WOLFSSL_CERT_GEN) && defined(HAVE_ECC)
    const byte expectedPathLen = 7;
    Cert cert;
    DecodedCert decodedCert;
    byte der[FOURK_BUF];
    int derSize = 0;
    WC_RNG rng;
    ecc_key key;
    int ret;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&cert, 0, sizeof(Cert));
    XMEMSET(&decodedCert, 0, sizeof(DecodedCert));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_ecc_make_key(&rng, 32, &key), 0);
    ExpectIntEQ(wc_InitCert(&cert), 0);

    (void)XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.state, "state", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.locality, "Bozeman", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.org, "yourOrgNameHere", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.unit, "yourUnitNameHere", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.commonName, "www.yourDomain.com",
        CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.email, "yourEmail@yourDomain.com",
        CTC_NAME_SIZE);

    cert.selfSigned = 1;
    cert.isCA       = 1;
    cert.pathLen    = expectedPathLen;
    cert.pathLenSet = 1;
    cert.sigType    = CTC_SHA256wECDSA;

#ifdef WOLFSSL_CERT_EXT
    cert.keyUsage |= KEYUSE_KEY_CERT_SIGN;
#endif

    ExpectIntGE(wc_MakeCert(&cert, der, FOURK_BUF, NULL, &key, &rng), 0);
    ExpectIntGE(derSize = wc_SignCert(cert.bodySz, cert.sigType, der,
        FOURK_BUF, NULL, &key, &rng), 0);

    wc_InitDecodedCert(&decodedCert, der, (word32)derSize, NULL);
    ExpectIntEQ(wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL), 0);
    ExpectIntEQ(decodedCert.pathLength, expectedPathLen);

    wc_FreeDecodedCert(&decodedCert);
    ret = wc_ecc_free(&key);
    ExpectIntEQ(ret, 0);
    ret = wc_FreeRng(&rng);
    ExpectIntEQ(ret, 0);
#endif
    return EXPECT_RESULT();
}

static int test_MakeCertWith0Ser(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CERT_REQ) && !defined(NO_ASN_TIME) && \
    defined(WOLFSSL_CERT_GEN) && defined(HAVE_ECC) && \
    defined(WOLFSSL_ASN_TEMPLATE)
    Cert cert;
    DecodedCert decodedCert;
    byte der[FOURK_BUF];
    int derSize = 0;
    WC_RNG rng;
    ecc_key key;
    int ret;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&cert, 0, sizeof(Cert));
    XMEMSET(&decodedCert, 0, sizeof(DecodedCert));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_ecc_make_key(&rng, 32, &key), 0);
    ExpectIntEQ(wc_InitCert(&cert), 0);

    (void)XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.state, "state", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.locality, "Bozeman", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.org, "yourOrgNameHere", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.unit, "yourUnitNameHere", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.commonName, "www.yourDomain.com",
        CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.email, "yourEmail@yourDomain.com",
        CTC_NAME_SIZE);

    cert.selfSigned = 1;
    cert.isCA       = 1;
    cert.sigType    = CTC_SHA256wECDSA;

#ifdef WOLFSSL_CERT_EXT
    cert.keyUsage |= KEYUSE_KEY_CERT_SIGN;
#endif

    /* set serial number to 0 */
    cert.serialSz  = 1;
    cert.serial[0] = 0;

    ExpectIntGE(wc_MakeCert(&cert, der, FOURK_BUF, NULL, &key, &rng), 0);
    ExpectIntGE(derSize = wc_SignCert(cert.bodySz, cert.sigType, der,
        FOURK_BUF, NULL, &key, &rng), 0);

    wc_InitDecodedCert(&decodedCert, der, (word32)derSize, NULL);

#if !defined(WOLFSSL_NO_ASN_STRICT) && !defined(WOLFSSL_PYTHON)
    ExpectIntEQ(wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
#else
    ExpectIntEQ(wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL), 0);
#endif

    wc_FreeDecodedCert(&decodedCert);
    ret = wc_ecc_free(&key);
    ExpectIntEQ(ret, 0);
    ret = wc_FreeRng(&rng);
    ExpectIntEQ(ret, 0);
#endif
    return EXPECT_RESULT();
}

static int test_MakeCertWithCaFalse(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ALLOW_ENCODING_CA_FALSE) && defined(WOLFSSL_CERT_REQ) && \
    !defined(NO_ASN_TIME) && defined(WOLFSSL_CERT_GEN) && defined(HAVE_ECC)
    const byte expectedIsCa = 0;
    Cert cert;
    DecodedCert decodedCert;
    byte der[FOURK_BUF];
    int derSize = 0;
    WC_RNG rng;
    ecc_key key;
    int ret;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&cert, 0, sizeof(Cert));
    XMEMSET(&decodedCert, 0, sizeof(DecodedCert));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_ecc_make_key(&rng, 32, &key), 0);
    ExpectIntEQ(wc_InitCert(&cert), 0);

    (void)XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.state, "state", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.locality, "Bozeman", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.org, "yourOrgNameHere", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.unit, "yourUnitNameHere", CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.commonName, "www.yourDomain.com",
        CTC_NAME_SIZE);
    (void)XSTRNCPY(cert.subject.email, "yourEmail@yourDomain.com",
        CTC_NAME_SIZE);

    cert.selfSigned = 1;
    cert.isCA       = expectedIsCa;
    cert.isCaSet    = 1;
    cert.sigType    = CTC_SHA256wECDSA;

    ExpectIntGE(wc_MakeCert(&cert, der, FOURK_BUF, NULL, &key, &rng), 0);
    ExpectIntGE(derSize = wc_SignCert(cert.bodySz, cert.sigType, der,
        FOURK_BUF, NULL, &key, &rng), 0);

    wc_InitDecodedCert(&decodedCert, der, derSize, NULL);
    ExpectIntEQ(wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL), 0);
    ExpectIntEQ(decodedCert.isCA, expectedIsCa);

    wc_FreeDecodedCert(&decodedCert);
    ret = wc_ecc_free(&key);
    ExpectIntEQ(ret, 0);
    ret = wc_FreeRng(&rng);
    ExpectIntEQ(ret, 0);
#endif
    return EXPECT_RESULT();
}

/*----------------------------------------------------------------------------*
 | wolfCrypt ECC
 *----------------------------------------------------------------------------*/

static int test_wc_ecc_get_curve_size_from_name(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    #if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
        ExpectIntEQ(wc_ecc_get_curve_size_from_name("SECP256R1"), 32);
    #endif
    /* invalid case */
    ExpectIntEQ(wc_ecc_get_curve_size_from_name("BADCURVE"), -1);
    /* NULL input */
    ExpectIntEQ(wc_ecc_get_curve_size_from_name(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* HAVE_ECC */
    return EXPECT_RESULT();
}

static int test_wc_ecc_get_curve_id_from_name(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    #if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
        ExpectIntEQ(wc_ecc_get_curve_id_from_name("SECP256R1"),
            ECC_SECP256R1);
    #endif
    /* invalid case */
    ExpectIntEQ(wc_ecc_get_curve_id_from_name("BADCURVE"), -1);
    /* NULL input */
    ExpectIntEQ(wc_ecc_get_curve_id_from_name(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* HAVE_ECC */
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && \
    !defined(HAVE_SELFTEST) && \
    !(defined(HAVE_FIPS) || defined(HAVE_FIPS_VERSION))
static int test_wc_ecc_get_curve_id_from_dp_params(void)
{
    EXPECT_DECLS;
#if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
    ecc_key* key;
    const ecc_set_type* params = NULL;
    int ret;
#endif
    WOLFSSL_EC_KEY *ecKey = NULL;

    #if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
        ExpectIntEQ(wc_ecc_get_curve_id_from_name("SECP256R1"), ECC_SECP256R1);
        ExpectNotNull(ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

        if (EXPECT_SUCCESS()) {
            ret = EC_KEY_generate_key(ecKey);
        } else
            ret = 0;

        if (ret == 1) {
            /* normal test */
            key = (ecc_key*)ecKey->internal;
            if (key != NULL) {
                params = key->dp;
            }

            ExpectIntEQ(wc_ecc_get_curve_id_from_dp_params(params),
                ECC_SECP256R1);
        }
    #endif
    /* invalid case, NULL input*/
    ExpectIntEQ(wc_ecc_get_curve_id_from_dp_params(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_EC_KEY_free(ecKey);

    return EXPECT_RESULT();
}
#endif /* defined(OPENSSL_EXTRA) && defined(HAVE_ECC) */

static int test_wc_ecc_get_curve_id_from_params(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    const byte prime[] =
    {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    };

    const byte primeInvalid[] =
    {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x01,0x01
    };

    const byte Af[] =
    {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC
    };

    const byte Bf[] =
    {
        0x5A,0xC6,0x35,0xD8,0xAA,0x3A,0x93,0xE7,
        0xB3,0xEB,0xBD,0x55,0x76,0x98,0x86,0xBC,
        0x65,0x1D,0x06,0xB0,0xCC,0x53,0xB0,0xF6,
        0x3B,0xCE,0x3C,0x3E,0x27,0xD2,0x60,0x4B
    };

    const byte order[] =
    {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,
        0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51
    };

    const byte Gx[] =
    {
        0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,
        0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,
        0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,
        0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96
    };

    const byte Gy[] =
    {
        0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,
        0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,
        0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,
        0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5
    };

    int cofactor = 1;
    int fieldSize = 256;

    #if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
        ExpectIntEQ(wc_ecc_get_curve_id_from_params(fieldSize,
            prime, sizeof(prime), Af, sizeof(Af), Bf, sizeof(Bf),
            order, sizeof(order), Gx, sizeof(Gx), Gy, sizeof(Gy), cofactor),
            ECC_SECP256R1);
    #endif

    /* invalid case, fieldSize = 0 */
    ExpectIntEQ(wc_ecc_get_curve_id_from_params(0, prime, sizeof(prime),
        Af, sizeof(Af), Bf, sizeof(Bf), order, sizeof(order),
        Gx, sizeof(Gx), Gy, sizeof(Gy), cofactor), ECC_CURVE_INVALID);

    /* invalid case, NULL prime */
    ExpectIntEQ(wc_ecc_get_curve_id_from_params(fieldSize, NULL, sizeof(prime),
        Af, sizeof(Af), Bf, sizeof(Bf), order, sizeof(order),
        Gx, sizeof(Gx), Gy, sizeof(Gy), cofactor), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* invalid case, invalid prime */
    ExpectIntEQ(wc_ecc_get_curve_id_from_params(fieldSize,
        primeInvalid, sizeof(primeInvalid),
        Af, sizeof(Af), Bf, sizeof(Bf), order, sizeof(order),
        Gx, sizeof(Gx), Gy, sizeof(Gy), cofactor), ECC_CURVE_INVALID);
#endif
    return EXPECT_RESULT();
}
static int test_wolfSSL_EVP_PKEY_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    WOLFSSL_RSA* rsa = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;
    WOLFSSL_EVP_PKEY_CTX* ctx = NULL;
    const char* in = "What is easy to do is easy not to do.";
    size_t inlen = XSTRLEN(in);
    size_t outEncLen = 0;
    byte*  outEnc = NULL;
    byte*  outDec = NULL;
    size_t outDecLen = 0;
    size_t rsaKeySz = 2048/8;  /* Bytes */
#if !defined(HAVE_FIPS) && defined(WC_RSA_NO_PADDING)
    byte*  inTmp = NULL;
    byte*  outEncTmp = NULL;
    byte*  outDecTmp = NULL;
#endif

    ExpectNotNull(outEnc = (byte*)XMALLOC(rsaKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (outEnc != NULL) {
        XMEMSET(outEnc, 0, rsaKeySz);
    }
    ExpectNotNull(outDec = (byte*)XMALLOC(rsaKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (outDec != NULL) {
        XMEMSET(outDec, 0, rsaKeySz);
    }

    ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectIntEQ(EVP_PKEY_assign_RSA(pkey, rsa), WOLFSSL_SUCCESS);
    if (EXPECT_FAIL()) {
        RSA_free(rsa);
    }
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_encrypt_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING),
        WOLFSSL_SUCCESS);

    /* Test pkey references count is decremented. pkey shouldn't be destroyed
     since ctx uses it.*/
    ExpectIntEQ(pkey->ref.count, 2);
    EVP_PKEY_free(pkey);
    ExpectIntEQ(pkey->ref.count, 1);

    /* Encrypt data */
    /* Check that we can get the required output buffer length by passing in a
     * NULL output buffer. */
    ExpectIntEQ(EVP_PKEY_encrypt(ctx, NULL, &outEncLen,
                            (const unsigned char*)in, inlen), WOLFSSL_SUCCESS);
    ExpectIntEQ(rsaKeySz, outEncLen);
    /* Now do the actual encryption. */
    ExpectIntEQ(EVP_PKEY_encrypt(ctx, outEnc, &outEncLen,
                            (const unsigned char*)in, inlen), WOLFSSL_SUCCESS);

    /* Decrypt data */
    ExpectIntEQ(EVP_PKEY_decrypt_init(ctx), WOLFSSL_SUCCESS);
    /* Check that we can get the required output buffer length by passing in a
     * NULL output buffer. */
    ExpectIntEQ(EVP_PKEY_decrypt(ctx, NULL, &outDecLen, outEnc, outEncLen),
                                 WOLFSSL_SUCCESS);
    ExpectIntEQ(rsaKeySz, outDecLen);
    /* Now do the actual decryption. */
    ExpectIntEQ(EVP_PKEY_decrypt(ctx, outDec, &outDecLen, outEnc, outEncLen),
                                 WOLFSSL_SUCCESS);

    ExpectIntEQ(XMEMCMP(in, outDec, outDecLen), 0);

#if !defined(HAVE_FIPS) && defined(WC_RSA_NO_PADDING)
    /* The input length must be the same size as the RSA key.*/
    ExpectNotNull(inTmp = (byte*)XMALLOC(rsaKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (inTmp != NULL) {
        XMEMSET(inTmp, 9, rsaKeySz);
    }
    ExpectNotNull(outEncTmp = (byte*)XMALLOC(rsaKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (outEncTmp != NULL) {
        XMEMSET(outEncTmp, 0, rsaKeySz);
    }
    ExpectNotNull(outDecTmp = (byte*)XMALLOC(rsaKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (outDecTmp != NULL) {
        XMEMSET(outDecTmp, 0, rsaKeySz);
    }
    ExpectIntEQ(EVP_PKEY_encrypt_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_encrypt(ctx, outEncTmp, &outEncLen, inTmp, rsaKeySz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_decrypt_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_decrypt(ctx, outDecTmp, &outDecLen, outEncTmp,
        outEncLen), WOLFSSL_SUCCESS);
    ExpectIntEQ(XMEMCMP(inTmp, outDecTmp, outDecLen), 0);
#endif
    EVP_PKEY_CTX_free(ctx);
    XFREE(outEnc, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(outDec, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#if !defined(HAVE_FIPS) && defined(WC_RSA_NO_PADDING)
    XFREE(inTmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(outEncTmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(outDecTmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    #ifndef TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
        #define TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
    #endif
#endif
#endif
#if defined(OPENSSL_EXTRA)
#if !defined (NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN)
    #ifndef TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
        #define TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
    #endif
#endif
#endif
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    #ifndef TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
        #define TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
    #endif
#endif
#endif

#ifdef TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
static int test_wolfSSL_EVP_PKEY_sign_verify(int keyType)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    WOLFSSL_RSA* rsa = NULL;
#endif
#endif
#if !defined (NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN)
    WOLFSSL_DSA* dsa = NULL;
#endif /* !NO_DSA && !HAVE_SELFTEST && WOLFSSL_KEY_GEN */
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    WOLFSSL_EC_KEY* ecKey = NULL;
#endif
#endif
    WOLFSSL_EVP_PKEY* pkey = NULL;
    WOLFSSL_EVP_PKEY_CTX* ctx = NULL;
    WOLFSSL_EVP_PKEY_CTX* ctx_verify = NULL;
    const char* in = "What is easy to do is easy not to do.";
    size_t inlen = XSTRLEN(in);
    byte hash[SHA256_DIGEST_LENGTH] = {0};
    byte zero[SHA256_DIGEST_LENGTH] = {0};
    SHA256_CTX c;
    byte*  sig = NULL;
    byte*  sigVerify = NULL;
    size_t siglen;
    size_t siglenOnlyLen;
    size_t keySz = 2048/8;  /* Bytes */

    ExpectNotNull(sig =
        (byte*)XMALLOC(keySz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(sigVerify =
        (byte*)XMALLOC(keySz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER));

    siglen = keySz;
    ExpectNotNull(XMEMSET(sig, 0, keySz));
    ExpectNotNull(XMEMSET(sigVerify, 0, keySz));

    /* Generate hash */
    SHA256_Init(&c);
    SHA256_Update(&c, in, inlen);
    SHA256_Final(hash, &c);
#ifdef WOLFSSL_SMALL_STACK_CACHE
    /* workaround for small stack cache case */
    wc_Sha256Free((wc_Sha256*)&c);
#endif

    /* Generate key */
    ExpectNotNull(pkey = EVP_PKEY_new());
    switch (keyType) {
        case EVP_PKEY_RSA:
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
        {
            ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
            ExpectIntEQ(EVP_PKEY_assign_RSA(pkey, rsa), WOLFSSL_SUCCESS);
        }
#endif
#endif
            break;
        case EVP_PKEY_DSA:
#if !defined (NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN)
            ExpectNotNull(dsa = DSA_new());
            ExpectIntEQ(DSA_generate_parameters_ex(dsa, 2048,
                NULL, 0, NULL, NULL, NULL), 1);
            ExpectIntEQ(DSA_generate_key(dsa), 1);
            ExpectIntEQ(EVP_PKEY_set1_DSA(pkey, dsa), WOLFSSL_SUCCESS);
#endif /* !NO_DSA && !HAVE_SELFTEST && WOLFSSL_KEY_GEN */
            break;
        case EVP_PKEY_EC:
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
        {
            ExpectNotNull(ecKey = EC_KEY_new());
            ExpectIntEQ(EC_KEY_generate_key(ecKey), 1);
            ExpectIntEQ(
                EVP_PKEY_assign_EC_KEY(pkey, ecKey), WOLFSSL_SUCCESS);
            if (EXPECT_FAIL()) {
                EC_KEY_free(ecKey);
            }
        }
#endif
#endif
            break;
    }
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_sign_init(ctx), WOLFSSL_SUCCESS);
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    if (keyType == EVP_PKEY_RSA)
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING),
                    WOLFSSL_SUCCESS);
#endif
#endif

    /* Check returning only length */
    ExpectIntEQ(EVP_PKEY_sign(ctx, NULL, &siglenOnlyLen, hash,
        SHA256_DIGEST_LENGTH), WOLFSSL_SUCCESS);
    ExpectIntGT(siglenOnlyLen, 0);
    /* Sign data */
    ExpectIntEQ(EVP_PKEY_sign(ctx, sig, &siglen, hash,
        SHA256_DIGEST_LENGTH), WOLFSSL_SUCCESS);
    ExpectIntGE(siglenOnlyLen, siglen);

    /* Verify signature */
    ExpectNotNull(ctx_verify = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_verify_init(ctx_verify), WOLFSSL_SUCCESS);
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    if (keyType == EVP_PKEY_RSA)
        ExpectIntEQ(
            EVP_PKEY_CTX_set_rsa_padding(ctx_verify, RSA_PKCS1_PADDING),
            WOLFSSL_SUCCESS);
#endif
#endif
    ExpectIntEQ(EVP_PKEY_verify(
        ctx_verify, sig, siglen, hash, SHA256_DIGEST_LENGTH),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_verify(
        ctx_verify, sig, siglen, zero, SHA256_DIGEST_LENGTH),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    if (keyType == EVP_PKEY_RSA) {
    #if defined(WC_RSA_NO_PADDING) || defined(WC_RSA_DIRECT)
        /* Try RSA sign/verify with no padding. */
        ExpectIntEQ(EVP_PKEY_sign_init(ctx), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_sign(ctx, sigVerify, &siglen, sig,
            siglen), WOLFSSL_SUCCESS);
        ExpectIntGE(siglenOnlyLen, siglen);
        ExpectIntEQ(EVP_PKEY_verify_init(ctx_verify), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx_verify,
            RSA_NO_PADDING), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_verify(ctx_verify, sigVerify, siglen, sig,
            siglen), WOLFSSL_SUCCESS);
    #endif

        /* Wrong padding schemes. */
        ExpectIntEQ(EVP_PKEY_sign_init(ctx), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx,
            RSA_PKCS1_OAEP_PADDING), WOLFSSL_SUCCESS);
        ExpectIntNE(EVP_PKEY_sign(ctx, sigVerify, &siglen, sig,
            siglen), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_verify_init(ctx_verify), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx_verify,
            RSA_PKCS1_OAEP_PADDING), WOLFSSL_SUCCESS);
        ExpectIntNE(EVP_PKEY_verify(ctx_verify, sigVerify, siglen, sig,
            siglen), WOLFSSL_SUCCESS);

        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx_verify,
            RSA_PKCS1_PADDING), WOLFSSL_SUCCESS);
    }
#endif
#endif

    /* error cases */
    siglen = keySz; /* Reset because sig size may vary slightly */
    ExpectIntNE(EVP_PKEY_sign_init(NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_sign_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntNE(EVP_PKEY_sign(NULL, sig, &siglen, (byte*)in, inlen),
                              WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_sign(ctx, sig, &siglen, (byte*)in, inlen),
                              WOLFSSL_SUCCESS);

    EVP_PKEY_free(pkey);
    pkey = NULL;
#if !defined (NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN)
    DSA_free(dsa);
    dsa = NULL;
#endif /* !NO_DSA && !HAVE_SELFTEST && WOLFSSL_KEY_GEN */
    EVP_PKEY_CTX_free(ctx_verify);
    ctx_verify = NULL;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sigVerify, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}
#endif

static int test_wolfSSL_EVP_PKEY_sign_verify_rsa(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    ExpectIntEQ(test_wolfSSL_EVP_PKEY_sign_verify(EVP_PKEY_RSA), TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}
static int test_wolfSSL_EVP_PKEY_sign_verify_dsa(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
#if !defined (NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN)
    ExpectIntEQ(test_wolfSSL_EVP_PKEY_sign_verify(EVP_PKEY_DSA), TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}
static int test_wolfSSL_EVP_PKEY_sign_verify_ec(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    ExpectIntEQ(test_wolfSSL_EVP_PKEY_sign_verify(EVP_PKEY_EC), TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}

static int test_EVP_PKEY_rsa(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    WOLFSSL_RSA* rsa = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;

    ExpectNotNull(rsa = wolfSSL_RSA_new());
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectIntEQ(EVP_PKEY_assign_RSA(NULL, rsa), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_assign_RSA(pkey, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_assign_RSA(pkey, rsa), WOLFSSL_SUCCESS);
    if (EXPECT_FAIL()) {
        wolfSSL_RSA_free(rsa);
    }
    ExpectPtrEq(EVP_PKEY_get0_RSA(pkey), rsa);
    wolfSSL_EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

static int test_EVP_PKEY_ec(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    WOLFSSL_EC_KEY* ecKey = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;

    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectIntEQ(EVP_PKEY_assign_EC_KEY(NULL, ecKey), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_assign_EC_KEY(pkey, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Should fail since ecKey is empty */
    ExpectIntEQ(EVP_PKEY_assign_EC_KEY(pkey, ecKey), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);
    ExpectIntEQ(EVP_PKEY_assign_EC_KEY(pkey, ecKey), WOLFSSL_SUCCESS);
    if (EXPECT_FAIL()) {
        wolfSSL_EC_KEY_free(ecKey);
    }
    wolfSSL_EVP_PKEY_free(pkey);
#endif
#endif
    return EXPECT_RESULT();
}

static int test_EVP_PKEY_cmp(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    EVP_PKEY *a = NULL;
    EVP_PKEY *b = NULL;
    const unsigned char *in;

#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
    in = client_key_der_2048;
    ExpectNotNull(a = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
        &in, (long)sizeof_client_key_der_2048));
    in = client_key_der_2048;
    ExpectNotNull(b = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
        &in, (long)sizeof_client_key_der_2048));

    /* Test success case RSA */
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    ExpectIntEQ(EVP_PKEY_cmp(a, b), 1);
#else
    ExpectIntEQ(EVP_PKEY_cmp(a, b), 0);
#endif /* WOLFSSL_ERROR_CODE_OPENSSL */

    EVP_PKEY_free(b);
    b = NULL;
    EVP_PKEY_free(a);
    a = NULL;
#endif

#if defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
    in = ecc_clikey_der_256;
    ExpectNotNull(a = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, NULL,
        &in, (long)sizeof_ecc_clikey_der_256));
    in = ecc_clikey_der_256;
    ExpectNotNull(b = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, NULL,
        &in, (long)sizeof_ecc_clikey_der_256));

    /* Test success case ECC */
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    ExpectIntEQ(EVP_PKEY_cmp(a, b), 1);
#else
    ExpectIntEQ(EVP_PKEY_cmp(a, b), 0);
#endif /* WOLFSSL_ERROR_CODE_OPENSSL */

    EVP_PKEY_free(b);
    b = NULL;
    EVP_PKEY_free(a);
    a = NULL;
#endif

    /* Test failure cases */
#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048) && \
     defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)

    in = client_key_der_2048;
    ExpectNotNull(a = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
        &in, (long)sizeof_client_key_der_2048));
    in = ecc_clikey_der_256;
    ExpectNotNull(b = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, NULL,
        &in, (long)sizeof_ecc_clikey_der_256));

#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    ExpectIntEQ(EVP_PKEY_cmp(a, b), -1);
#else
    ExpectIntNE(EVP_PKEY_cmp(a, b), 0);
#endif /* WOLFSSL_ERROR_CODE_OPENSSL */
    EVP_PKEY_free(b);
    b = NULL;
    EVP_PKEY_free(a);
    a = NULL;
#endif

    /* invalid or empty failure cases */
    a = EVP_PKEY_new();
    b = EVP_PKEY_new();
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    ExpectIntEQ(EVP_PKEY_cmp(NULL, NULL), 0);
    ExpectIntEQ(EVP_PKEY_cmp(a, NULL), 0);
    ExpectIntEQ(EVP_PKEY_cmp(NULL, b), 0);
#ifdef NO_RSA
    /* Type check will fail since RSA is the default EVP key type */
    ExpectIntEQ(EVP_PKEY_cmp(a, b), -2);
#else
    ExpectIntEQ(EVP_PKEY_cmp(a, b), 0);
#endif
#else
    ExpectIntNE(EVP_PKEY_cmp(NULL, NULL), 0);
    ExpectIntNE(EVP_PKEY_cmp(a, NULL), 0);
    ExpectIntNE(EVP_PKEY_cmp(NULL, b), 0);
    ExpectIntNE(EVP_PKEY_cmp(a, b), 0);
#endif
    EVP_PKEY_free(b);
    EVP_PKEY_free(a);

    (void)in;
#endif
    return EXPECT_RESULT();
}

static int test_ERR_load_crypto_strings(void)
{
#if defined(OPENSSL_ALL)
    ERR_load_crypto_strings();
    return TEST_SUCCESS;
#else
    return TEST_SKIPPED;
#endif
}

#if defined(OPENSSL_ALL) && !defined(NO_CERTS)
static WOLFSSL_X509 x1;
static WOLFSSL_X509 x2;
static void free_x509(X509* x)
{
    AssertIntEQ((x == &x1 || x == &x2), 1);
}
#endif

static int test_sk_X509(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS)
    {
        STACK_OF(X509)* s = NULL;

        ExpectNotNull(s = wolfSSL_sk_X509_new(NULL));
        ExpectIntEQ(sk_X509_num(s), 0);
        sk_X509_pop_free(s, NULL);

        ExpectNotNull(s = sk_X509_new_null());
        ExpectIntEQ(sk_X509_num(s), 0);
        sk_X509_pop_free(s, NULL);

        ExpectNotNull(s = sk_X509_new_null());

        /* Test invalid parameters. */
        ExpectIntEQ(sk_X509_push(NULL, NULL), WOLFSSL_FAILURE);
        ExpectIntEQ(sk_X509_push(s, NULL), WOLFSSL_FAILURE);
        ExpectIntEQ(sk_X509_push(NULL, (X509*)1), WOLFSSL_FAILURE);
        ExpectNull(sk_X509_pop(NULL));
        ExpectNull(sk_X509_value(NULL, 0));
        ExpectNull(sk_X509_value(NULL, 1));

        sk_X509_push(s, &x1);
        ExpectIntEQ(sk_X509_num(s), 1);
        ExpectIntEQ((sk_X509_value(s, 0) == &x1), 1);
        sk_X509_push(s, &x2);
        ExpectIntEQ(sk_X509_num(s), 2);
        ExpectNull(sk_X509_value(s, 2));
        ExpectIntEQ((sk_X509_value(s, 0) == &x2), 1);
        ExpectIntEQ((sk_X509_value(s, 1) == &x1), 1);
        sk_X509_push(s, &x2);

        sk_X509_pop_free(s, free_x509);
    }

    {
        /* Push a list of 10 X509s onto stack, then verify that
         * value(), push(), shift(), and pop() behave as expected. */
        STACK_OF(X509)* s = NULL;
        X509*     xList[10];
        int       i = 0;
        const int len = (sizeof(xList) / sizeof(xList[0]));

        for (i = 0; i < len; ++i) {
            xList[i] = NULL;
            ExpectNotNull(xList[i] = X509_new());
        }

        /* test push, pop, and free */
        ExpectNotNull(s = sk_X509_new_null());

        for (i = 0; i < len; ++i) {
            sk_X509_push(s, xList[i]);
            ExpectIntEQ(sk_X509_num(s), i + 1);
            ExpectIntEQ((sk_X509_value(s, 0) == xList[i]), 1);
            ExpectIntEQ((sk_X509_value(s, i) == xList[0]), 1);
        }

        /* pop returns and removes last pushed on stack, which is index 0
         * in sk_x509_value */
        for (i = 0; i < len; ++i) {
            X509 * x = sk_X509_value(s, 0);
            X509 * y = sk_X509_pop(s);
            X509 * z = xList[len - 1 - i];

            ExpectIntEQ((x == y), 1);
            ExpectIntEQ((x == z), 1);
            ExpectIntEQ(sk_X509_num(s), len - 1 - i);
        }

        sk_free(s);
        s = NULL;

        /* test push, shift, and free */
        ExpectNotNull(s = sk_X509_new_null());

        for (i = 0; i < len; ++i) {
            sk_X509_push(s, xList[i]);
            ExpectIntEQ(sk_X509_num(s), i + 1);
            ExpectIntEQ((sk_X509_value(s, 0) == xList[i]), 1);
            ExpectIntEQ((sk_X509_value(s, i) == xList[0]), 1);
        }

        /* shift returns and removes first pushed on stack, which is index i
         * in sk_x509_value() */
        for (i = 0; i < len; ++i) {
            X509 * x = sk_X509_value(s, len - 1 - i);
            X509 * y = sk_X509_shift(s);
            X509 * z = xList[i];

            ExpectIntEQ((x == y), 1);
            ExpectIntEQ((x == z), 1);
            ExpectIntEQ(sk_X509_num(s), len - 1 - i);
        }
        ExpectNull(sk_X509_shift(NULL));
        ExpectNull(sk_X509_shift(s));

        sk_free(s);

        for (i = 0; i < len; ++i)
            X509_free(xList[i]);
    }
#endif
    return EXPECT_RESULT();
}

static int test_sk_X509_CRL(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && defined(HAVE_CRL)
    X509_CRL* crl = NULL;
    XFILE fp = XBADFILE;
    STACK_OF(X509_CRL)* s = NULL;
#ifndef NO_BIO
    BIO* bio = NULL;
#endif
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
    RevokedCert* rev = NULL;
    byte buff[1024];
    int len = 0;
#endif
#if (!defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)) || \
    !defined(NO_BIO)
    X509_CRL empty;
#endif
    WOLFSSL_X509_REVOKED revoked;
    WOLFSSL_ASN1_INTEGER* asnInt = NULL;
    const WOLFSSL_ASN1_INTEGER* sn;

#if (!defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)) || \
    !defined(NO_BIO)
    XMEMSET(&empty, 0, sizeof(X509_CRL));
#endif

#ifndef NO_BIO
    ExpectNotNull(bio = BIO_new_file("./certs/crl/crl.der", "rb"));
    ExpectNull(wolfSSL_d2i_X509_CRL_bio(NULL, NULL));
    ExpectNotNull(crl = wolfSSL_d2i_X509_CRL_bio(bio, NULL));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(wolfSSL_X509_CRL_print(NULL, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_CRL_print(bio, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_CRL_print(NULL, crl), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_CRL_print(bio, &empty), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_CRL_print(bio, crl), WOLFSSL_SUCCESS);
#ifndef NO_ASN_TIME
    ExpectIntEQ(BIO_get_mem_data(bio, NULL), 1466);
#else
    ExpectIntEQ(BIO_get_mem_data(bio, NULL), 1324);
#endif
    BIO_free(bio);

    wolfSSL_X509_CRL_free(crl);
    crl = NULL;
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
    ExpectTrue((fp = XFOPEN("./certs/crl/crl.der", "rb")) != XBADFILE);
    ExpectNotNull(crl = d2i_X509_CRL_fp(fp, (X509_CRL **)NULL));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    wolfSSL_X509_CRL_free(crl);
    crl = NULL;

    ExpectTrue((fp = XFOPEN("./certs/crl/crl.der", "rb")) != XBADFILE);
    ExpectIntEQ(len = (int)XFREAD(buff, 1, sizeof(buff), fp), 520);
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    ExpectNull(crl = d2i_X509_CRL((X509_CRL **)NULL, NULL, len));
    ExpectNotNull(crl = d2i_X509_CRL((X509_CRL **)NULL, buff, len));
    ExpectNotNull(rev = crl->crlList->certs);

    ExpectNull(wolfSSL_X509_CRL_get_issuer_name(NULL));
    ExpectNull(wolfSSL_X509_CRL_get_issuer_name(&empty));
    ExpectIntEQ(wolfSSL_X509_CRL_version(NULL), 0);
    ExpectIntEQ(wolfSSL_X509_CRL_version(&empty), 0);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature_type(NULL), 0);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature_type(&empty), 0);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature_nid(NULL), 0);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature_nid(&empty), 0);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature(NULL, NULL, NULL), BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature(crl , NULL, NULL), BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature(NULL, NULL, &len), BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature(&empty, NULL, &len),
        BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_X509_REVOKED_get_serial_number(NULL, NULL, NULL),
        BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_X509_REVOKED_get_serial_number(rev , NULL, NULL),
        BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_X509_REVOKED_get_serial_number(NULL, NULL, &len),
        BAD_FUNC_ARG);
    ExpectNull(wolfSSL_X509_CRL_get_lastUpdate(NULL));
    ExpectNull(wolfSSL_X509_CRL_get_lastUpdate(&empty));
    ExpectNull(wolfSSL_X509_CRL_get_nextUpdate(NULL));
    ExpectNull(wolfSSL_X509_CRL_get_nextUpdate(&empty));

    ExpectNotNull(wolfSSL_X509_CRL_get_issuer_name(crl));
    ExpectIntEQ(wolfSSL_X509_CRL_version(crl), 2);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature_type(crl), CTC_SHA256wRSA);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature_nid(crl),
        WC_NID_sha256WithRSAEncryption);
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature(crl, NULL, &len),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(len, 256);
    len--;
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature(crl, buff, &len), BUFFER_E);
    len += 2;
    ExpectIntEQ(wolfSSL_X509_CRL_get_signature(crl, buff, &len),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(len, 256);
    ExpectNotNull(wolfSSL_X509_CRL_get_lastUpdate(crl));
    ExpectNotNull(wolfSSL_X509_CRL_get_nextUpdate(crl));

    ExpectIntEQ(wolfSSL_X509_REVOKED_get_serial_number(rev, NULL, &len),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(len, 1);
    len--;
    ExpectIntEQ(wolfSSL_X509_REVOKED_get_serial_number(rev, buff, &len),
        BUFFER_E);
    len += 2;
    ExpectIntEQ(wolfSSL_X509_REVOKED_get_serial_number(rev, buff, &len),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(len, 1);

#ifndef NO_WOLFSSL_STUB
    ExpectIntEQ(wolfSSL_sk_X509_REVOKED_num(NULL), 0);
    ExpectIntEQ(wolfSSL_sk_X509_REVOKED_num(&revoked), 0);
    ExpectNull(wolfSSL_X509_CRL_get_REVOKED(NULL));
    ExpectNull(wolfSSL_X509_CRL_get_REVOKED(crl));
    ExpectNull(wolfSSL_sk_X509_REVOKED_value(NULL, 0));
    ExpectNull(wolfSSL_sk_X509_REVOKED_value(&revoked, 0));
    ExpectIntEQ(wolfSSL_X509_CRL_verify(NULL, NULL), 0);
    ExpectIntEQ(X509_OBJECT_set1_X509_CRL(NULL, NULL), 0);
    ExpectIntEQ(X509_OBJECT_set1_X509(NULL, NULL), 0);
#endif

    wolfSSL_X509_CRL_free(crl);
    crl = NULL;
#endif

    ExpectNotNull(asnInt = wolfSSL_ASN1_INTEGER_new());
    ExpectIntEQ(wolfSSL_ASN1_INTEGER_set(asnInt, 1), 1);
    revoked.serialNumber = asnInt;
    ExpectNull(wolfSSL_X509_REVOKED_get0_serial_number(NULL));
    ExpectNotNull(sn = wolfSSL_X509_REVOKED_get0_serial_number(&revoked));
    ExpectPtrEq(sn, asnInt);
#ifndef NO_WOLFSSL_STUB
    ExpectNull(wolfSSL_X509_REVOKED_get0_revocation_date(NULL));
    ExpectNull(wolfSSL_X509_REVOKED_get0_revocation_date(&revoked));
#endif
    wolfSSL_ASN1_INTEGER_free(asnInt);

    ExpectTrue((fp = XFOPEN("./certs/crl/crl.pem", "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL*)PEM_read_X509_CRL(fp, (X509_CRL **)NULL,
        NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);

    ExpectNotNull(s = sk_X509_CRL_new());

    ExpectIntEQ(sk_X509_CRL_push(NULL, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(sk_X509_CRL_push(NULL, crl), WOLFSSL_FAILURE);
    ExpectIntEQ(sk_X509_CRL_push(s, NULL), WOLFSSL_FAILURE);
    ExpectNull(sk_X509_CRL_value(NULL, 0));
    ExpectIntEQ(sk_X509_CRL_num(NULL), 0);

    ExpectIntEQ(sk_X509_CRL_num(s), 0);
    ExpectIntEQ(sk_X509_CRL_push(s, crl), 1);
    if (EXPECT_FAIL()) {
        X509_CRL_free(crl);
    }
    ExpectIntEQ(sk_X509_CRL_num(s), 1);
    ExpectPtrEq(sk_X509_CRL_value(s, 0), crl);

    sk_X509_CRL_free(s);
#endif
    return EXPECT_RESULT();
}

static int test_X509_get_signature_nid(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509*   x509 = NULL;

    ExpectIntEQ(X509_get_signature_nid(NULL), 0);
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(svrCertFile,
        SSL_FILETYPE_PEM));
    ExpectIntEQ(X509_get_signature_nid(x509), NID_sha256WithRSAEncryption);
    X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_X509_REQ(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ) && !defined(NO_BIO)
    X509_NAME* name = NULL;
#ifndef NO_RSA
    X509_NAME* subject = NULL;
#endif
#if !defined(NO_RSA) || defined(HAVE_ECC)
    X509_REQ* req = NULL;
    EVP_PKEY* priv = NULL;
    EVP_PKEY* pub = NULL;
    unsigned char* der = NULL;
    int len;
#endif
#ifndef NO_RSA
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pkctx = NULL;
    #ifdef USE_CERT_BUFFERS_1024
    const unsigned char* rsaPriv = (const unsigned char*)client_key_der_1024;
    const unsigned char* rsaPub = (unsigned char*)client_keypub_der_1024;
    #elif defined(USE_CERT_BUFFERS_2048)
    const unsigned char* rsaPriv = (const unsigned char*)client_key_der_2048;
    const unsigned char* rsaPub = (unsigned char*)client_keypub_der_2048;
    #endif
#endif
#ifdef HAVE_ECC
    const unsigned char* ecPriv = (const unsigned char*)ecc_clikey_der_256;
    const unsigned char* ecPub = (unsigned char*)ecc_clikeypub_der_256;
    BIO* bio = NULL;
#endif
    unsigned char tooLongPassword[WC_CTC_NAME_SIZE + 1];

    XMEMSET(tooLongPassword, 0, sizeof(tooLongPassword));

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
        (byte*)"wolfssl.com", 11, 0, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_UTF8,
        (byte*)"support@wolfssl.com", 19, -1, 1), WOLFSSL_SUCCESS);

#ifndef NO_RSA
    ExpectNotNull(priv = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &rsaPriv,
        (long)sizeof_client_key_der_2048));
    ExpectNotNull(pub = d2i_PUBKEY(NULL, &rsaPub,
        (long)sizeof_client_keypub_der_2048));
    ExpectNotNull(req = X509_REQ_new());
    ExpectIntEQ(X509_REQ_set_subject_name(NULL, name), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_REQ_set_subject_name(req, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_REQ_set_subject_name(req, name), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_set_pubkey(NULL, pub), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_REQ_set_pubkey(req, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_REQ_set_pubkey(req, pub), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_sign(NULL, priv, EVP_sha256()), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_REQ_sign(req, NULL, EVP_sha256()), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_REQ_sign(req, priv, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_REQ_sign(req, priv, EVP_sha256()), WOLFSSL_SUCCESS);
    ExpectIntEQ(i2d_X509_REQ(NULL, NULL), BAD_FUNC_ARG);
    ExpectIntEQ(i2d_X509_REQ(req, NULL), BAD_FUNC_ARG);
    ExpectIntEQ(i2d_X509_REQ(NULL, &der), BAD_FUNC_ARG);
    len = i2d_X509_REQ(req, &der);
    DEBUG_WRITE_DER(der, len, "req.der");
#ifdef USE_CERT_BUFFERS_1024
    ExpectIntEQ(len, 381);
#else
    ExpectIntEQ(len, 643);
#endif
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    der = NULL;

    mctx = EVP_MD_CTX_new();
    ExpectIntEQ(EVP_DigestSignInit(mctx, &pkctx, EVP_sha256(), NULL, priv),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_sign_ctx(NULL, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_sign_ctx(req, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_sign_ctx(NULL, mctx), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_sign_ctx(req, mctx), WOLFSSL_SUCCESS);

    EVP_MD_CTX_free(mctx);
    mctx = NULL;
    X509_REQ_free(NULL);
    X509_REQ_free(req);
    req = NULL;

    /* Test getting the subject from a newly created X509_REQ */
    ExpectNotNull(req = X509_REQ_new());
    ExpectNotNull(subject = X509_REQ_get_subject_name(req));
    ExpectIntEQ(X509_NAME_add_entry_by_NID(subject, NID_commonName,
        MBSTRING_UTF8, (unsigned char*)"www.wolfssl.com", -1, -1, 0), 1);
    ExpectIntEQ(X509_NAME_add_entry_by_NID(subject, NID_countryName,
        MBSTRING_UTF8, (unsigned char*)"US", -1, -1, 0), 1);
    ExpectIntEQ(X509_NAME_add_entry_by_NID(subject, NID_localityName,
        MBSTRING_UTF8, (unsigned char*)"Bozeman", -1, -1, 0), 1);
    ExpectIntEQ(X509_NAME_add_entry_by_NID(subject, NID_stateOrProvinceName,
        MBSTRING_UTF8, (unsigned char*)"Montana", -1, -1, 0), 1);
    ExpectIntEQ(X509_NAME_add_entry_by_NID(subject, NID_organizationName,
        MBSTRING_UTF8, (unsigned char*)"wolfSSL", -1, -1, 0), 1);
    ExpectIntEQ(X509_NAME_add_entry_by_NID(subject, NID_organizationalUnitName,
        MBSTRING_UTF8, (unsigned char*)"Testing", -1, -1, 0), 1);
    ExpectIntEQ(X509_REQ_set_pubkey(req, pub), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_sign(req, priv, EVP_sha256()), WOLFSSL_SUCCESS);
    len = i2d_X509_REQ(req, &der);
    DEBUG_WRITE_DER(der, len, "req2.der");
#ifdef USE_CERT_BUFFERS_1024
    ExpectIntEQ(len, 435);
#else
    ExpectIntEQ(len, 696);
#endif
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    der = NULL;

    EVP_PKEY_free(pub);
    pub = NULL;
    EVP_PKEY_free(priv);
    priv = NULL;
    X509_REQ_free(req);
    req = NULL;
#endif
#ifdef HAVE_ECC
    ExpectNotNull(priv = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, NULL, &ecPriv,
        sizeof_ecc_clikey_der_256));
    ExpectNotNull(pub = wolfSSL_d2i_PUBKEY(NULL, &ecPub,
        sizeof_ecc_clikeypub_der_256));
    ExpectNotNull(req = X509_REQ_new());
    ExpectIntEQ(X509_REQ_set_subject_name(req, name), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_set_pubkey(req, pub), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_sign(req, priv, EVP_sha256()), WOLFSSL_SUCCESS);
    /* Signature is random and may be shorter or longer. */
    ExpectIntGE((len = i2d_X509_REQ(req, &der)), 245);
    ExpectIntLE(len, 253);
    ExpectNotNull(bio = BIO_new_fp(stderr, BIO_NOCLOSE));
    ExpectIntEQ(X509_REQ_print(bio, req), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_print(bio, NULL), WOLFSSL_FAILURE);
    BIO_free(bio);
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    X509_REQ_free(req);
    req = NULL;
    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif /* HAVE_ECC */

    X509_NAME_free(name);

    ExpectNull(wolfSSL_X509_REQ_get_extensions(NULL));
    /* Stub function. */
    ExpectNull(wolfSSL_X509_to_X509_REQ(NULL, NULL, NULL));

    ExpectNotNull(req = X509_REQ_new());
#ifdef HAVE_LIBEST
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(NULL, NULL,
        WOLFSSL_MBSTRING_UTF8, NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(req, NULL,
        WOLFSSL_MBSTRING_UTF8, NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(NULL, "name",
        WOLFSSL_MBSTRING_UTF8, NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(NULL, NULL,
        WOLFSSL_MBSTRING_ASC, NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(NULL, NULL,
        WOLFSSL_MBSTRING_UTF8, (byte*)"1.3.6.1.1.1.1.22", 16), WOLFSSL_FAILURE);


    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(NULL, "name",
        WOLFSSL_MBSTRING_ASC, (byte*)"1.3.6.1.1.1.1.22", 16), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(req, NULL,
        WOLFSSL_MBSTRING_ASC, (byte*)"1.3.6.1.1.1.1.22", 16), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(req, "name",
        WOLFSSL_MBSTRING_UTF8, (byte*)"1.3.6.1.1.1.1.22", 16), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(req, "name",
        WOLFSSL_MBSTRING_ASC, NULL, 0), WOLFSSL_FAILURE);

    /* Unsupported bytes. */
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(req, "name",
        WOLFSSL_MBSTRING_ASC, (byte*)"1.3.6.1.1.1.1.23", 16), WOLFSSL_FAILURE);

    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(req, "MAC Address",
        WOLFSSL_MBSTRING_ASC, (byte*)"1.3.6.1.1.1.1.22", 16), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(req, "ecpublicKey",
        WOLFSSL_MBSTRING_ASC, (byte*)"1.2.840.10045.2.1", -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(req, "ecdsa-with-SHA384",
        WOLFSSL_MBSTRING_ASC, (byte*)"1.2.840.10045.4.3.3", -1),
        WOLFSSL_SUCCESS);
#else
    /* Stub function. */
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(NULL, NULL,
        WOLFSSL_MBSTRING_UTF8, NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_X509_REQ_add1_attr_by_txt(req, "MAC Address",
        WOLFSSL_MBSTRING_ASC, (byte*)"1.3.6.1.1.1.1.22", 16), WOLFSSL_FAILURE);
#endif

    ExpectIntEQ(X509_REQ_add1_attr_by_NID(NULL, WC_NID_subject_alt_name,
        WOLFSSL_MBSTRING_UTF8, NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_subject_alt_name,
        WOLFSSL_MBSTRING_UTF8, NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(NULL, WC_NID_subject_alt_name,
        WOLFSSL_MBSTRING_ASC, NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(NULL, WC_NID_pkcs9_challengePassword,
        WOLFSSL_MBSTRING_UTF8, NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(NULL, WC_NID_subject_alt_name,
        WOLFSSL_MBSTRING_UTF8, (byte*)"password", 8), WOLFSSL_FAILURE);

    ExpectIntEQ(X509_REQ_add1_attr_by_NID(NULL, WC_NID_pkcs9_challengePassword,
        WOLFSSL_MBSTRING_ASC, (byte*)"password", 8), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_subject_alt_name,
        WOLFSSL_MBSTRING_ASC, (byte*)"password", 8), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_pkcs9_challengePassword,
        WOLFSSL_MBSTRING_UTF8, (byte*)"password", 8), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_pkcs9_challengePassword,
        WOLFSSL_MBSTRING_ASC, NULL, -1), WOLFSSL_FAILURE);

    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_pkcs9_challengePassword,
        WOLFSSL_MBSTRING_ASC, (byte*)"password", -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_pkcs9_challengePassword,
        WOLFSSL_MBSTRING_ASC, tooLongPassword, sizeof(tooLongPassword)),
        WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_serialNumber,
        WOLFSSL_MBSTRING_ASC, (byte*)"123456", -1), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_serialNumber,
        WOLFSSL_MBSTRING_ASC, tooLongPassword, sizeof(tooLongPassword)),
        WOLFSSL_FAILURE);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_pkcs9_unstructuredName,
        WOLFSSL_MBSTRING_ASC, (byte*)"name", 4), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_pkcs9_contentType,
        WOLFSSL_MBSTRING_ASC, (byte*)"type", 4), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_surname,
        WOLFSSL_MBSTRING_ASC, (byte*)"surname", 7), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_initials,
        WOLFSSL_MBSTRING_ASC, (byte*)"s.g", 3), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_givenName,
        WOLFSSL_MBSTRING_ASC, (byte*)"givenname", 9), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_REQ_add1_attr_by_NID(req, WC_NID_dnQualifier,
        WOLFSSL_MBSTRING_ASC, (byte*)"dnQualifier", 11), WOLFSSL_SUCCESS);

    wolfSSL_X509_REQ_free(req);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_REQ_print(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ) && !defined(NO_BIO)
    WOLFSSL_X509* req = NULL;
    XFILE fp = XBADFILE;
    const char* csrFileName = "certs/csr.attr.der";
    const char* csrExtFileName = "certs/csr.ext.der";
    BIO* bio = NULL;

    ExpectTrue((fp = XFOPEN(csrFileName, "rb")) != XBADFILE);
    ExpectNotNull(req = d2i_X509_REQ_fp(fp, NULL));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(wolfSSL_X509_REQ_print(bio, req), WOLFSSL_SUCCESS);
    ExpectIntEQ(BIO_get_mem_data(bio, NULL), 2681);

    BIO_free(bio);
    bio = NULL;
    wolfSSL_X509_REQ_free(req);
    req = NULL;

    ExpectTrue((fp = XFOPEN(csrExtFileName, "rb")) != XBADFILE);
    ExpectNotNull(req = d2i_X509_REQ_fp(fp, NULL));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
    }

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(wolfSSL_X509_REQ_print(bio, req), WOLFSSL_SUCCESS);
    ExpectIntEQ(BIO_get_mem_data(bio, NULL), 1889);

    BIO_free(bio);
    wolfSSL_X509_REQ_free(req);
#endif
    return EXPECT_RESULT();
}

static int test_wolfssl_PKCS7(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_BIO) && \
    !defined(NO_RSA)
    PKCS7* pkcs7 = NULL;
    byte   data[FOURK_BUF];
    word32 len = sizeof(data);
    const byte*  p = data;
    byte   content[] = "Test data to encode.";
#if !defined(NO_RSA) & defined(USE_CERT_BUFFERS_2048)
    BIO*   bio = NULL;
    byte   key[sizeof(client_key_der_2048)];
    word32 keySz = (word32)sizeof(key);
    byte*  out = NULL;
#endif

    ExpectIntGT((len = (word32)CreatePKCS7SignedData(data, (int)len, content,
        (word32)sizeof(content), 0, 0, 0, RSA_TYPE)), 0);

    ExpectNull(pkcs7 = d2i_PKCS7(NULL, NULL, (int)len));
    ExpectNull(pkcs7 = d2i_PKCS7(NULL, &p, 0));
    ExpectNotNull(pkcs7 = d2i_PKCS7(NULL, &p, (int)len));
    ExpectIntEQ(wolfSSL_PKCS7_verify(NULL, NULL, NULL, NULL, NULL,
        PKCS7_NOVERIFY), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* fail case, without PKCS7_NOVERIFY */
    p = data;
    ExpectNotNull(pkcs7 = d2i_PKCS7(NULL, &p, (int)len));
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, NULL, NULL,
        0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* success case, with PKCS7_NOVERIFY */
    p = data;
    ExpectNotNull(pkcs7 = d2i_PKCS7(NULL, &p, (int)len));
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, NULL, NULL,
        PKCS7_NOVERIFY), WOLFSSL_SUCCESS);

#if !defined(NO_RSA) & defined(USE_CERT_BUFFERS_2048)
    /* test i2d */
    XMEMCPY(key, client_key_der_2048, keySz);
    if (pkcs7 != NULL) {
        pkcs7->privateKey = key;
        pkcs7->privateKeySz = (word32)sizeof(key);
        pkcs7->encryptOID = RSAk;
    #ifdef NO_SHA
        pkcs7->hashOID = SHA256h;
    #else
        pkcs7->hashOID = SHAh;
    #endif
    }
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(i2d_PKCS7_bio(bio, pkcs7), 1);
#ifndef NO_ASN_TIME
    ExpectIntEQ(i2d_PKCS7(pkcs7, &out), 655);
#else
    ExpectIntEQ(i2d_PKCS7(pkcs7, &out), 625);
#endif
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    BIO_free(bio);
#endif

    PKCS7_free(NULL);
    PKCS7_free(pkcs7);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_PKCS7_sign(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_BIO) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)

    PKCS7* p7 = NULL;
    PKCS7* p7Ver = NULL;
    byte* out = NULL;
    byte* tmpPtr = NULL;
    int outLen = 0;
    int flags = 0;
    byte data[] = "Test data to encode.";

    const char* cert = "./certs/server-cert.pem";
    const char* key  = "./certs/server-key.pem";
    const char* ca   = "./certs/ca-cert.pem";

    WOLFSSL_BIO* certBio = NULL;
    WOLFSSL_BIO* keyBio = NULL;
    WOLFSSL_BIO* caBio = NULL;
    WOLFSSL_BIO* inBio = NULL;
    X509* signCert = NULL;
    EVP_PKEY* signKey = NULL;
    X509* caCert = NULL;
    X509_STORE* store = NULL;
#ifndef NO_PKCS7_STREAM
    int z;
    int ret;
#endif /* !NO_PKCS7_STREAM */

    /* read signer cert/key into BIO */
    ExpectNotNull(certBio = BIO_new_file(cert, "r"));
    ExpectNotNull(keyBio = BIO_new_file(key, "r"));
    ExpectNotNull(signCert = PEM_read_bio_X509(certBio, NULL, 0, NULL));
    ExpectNotNull(signKey = PEM_read_bio_PrivateKey(keyBio, NULL, 0, NULL));

    /* read CA cert into store (for verify) */
    ExpectNotNull(caBio = BIO_new_file(ca, "r"));
    ExpectNotNull(caCert = PEM_read_bio_X509(caBio, NULL, 0, NULL));
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, caCert), 1);

    /* data to be signed into BIO */
    ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
    ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

    /* PKCS7_sign, bad args: signer NULL */
    ExpectNull(p7 = PKCS7_sign(NULL, signKey, NULL, inBio, 0));
    /* PKCS7_sign, bad args: signer key NULL */
    ExpectNull(p7 = PKCS7_sign(signCert, NULL, NULL, inBio, 0));
    /* PKCS7_sign, bad args: in data NULL without PKCS7_STREAM */
    ExpectNull(p7 = PKCS7_sign(signCert, signKey, NULL, NULL, 0));
    /* PKCS7_sign, bad args: PKCS7_NOCERTS flag not supported */
    ExpectNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, PKCS7_NOCERTS));
    /* PKCS7_sign, bad args: PKCS7_PARTIAL flag not supported */
    ExpectNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, PKCS7_PARTIAL));

    /* TEST SUCCESS: Not detached, not streaming, not MIME */
    {
        flags = PKCS7_BINARY;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectIntGT((outLen = i2d_PKCS7(p7, &out)), 0);

        /* verify with d2i_PKCS7 */
        tmpPtr = out;
        ExpectNotNull(p7Ver = d2i_PKCS7(NULL, (const byte**)&tmpPtr, outLen));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, NULL, NULL, flags), 1);
        PKCS7_free(p7Ver);
        p7Ver = NULL;

        /* verify with wc_PKCS7_VerifySignedData */
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_Init(p7Ver, HEAP_HINT, INVALID_DEVID), 0);
        ExpectIntEQ(wc_PKCS7_VerifySignedData(p7Ver, out, (word32)outLen), 0);

    #ifndef NO_PKCS7_STREAM
        /* verify with wc_PKCS7_VerifySignedData streaming */
        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_Init(p7Ver, HEAP_HINT, INVALID_DEVID), 0);
        /* test for streaming */
        ret = -1;
        for (z = 0; z < outLen && ret != 0; z++) {
            ret = wc_PKCS7_VerifySignedData(p7Ver, out + z, 1);
            if (ret < 0){
                ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
            }
        }
        ExpectIntEQ(ret, 0);
    #endif /* !NO_PKCS7_STREAM */

        /* compare the signer found to expected signer */
        ExpectIntNE(p7Ver->verifyCertSz, 0);
        tmpPtr = NULL;
        ExpectIntEQ(i2d_X509(signCert, &tmpPtr), p7Ver->verifyCertSz);
        ExpectIntEQ(XMEMCMP(tmpPtr, p7Ver->verifyCert, p7Ver->verifyCertSz), 0);
        XFREE(tmpPtr, NULL, DYNAMIC_TYPE_OPENSSL);
        tmpPtr = NULL;

        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;

        ExpectNotNull(out);
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        out = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* TEST SUCCESS: Not detached, streaming, not MIME. Also bad arg
     * tests for PKCS7_final() while we have a PKCS7 pointer to use */
    {
        /* re-populate input BIO, may have been consumed */
        BIO_free(inBio);
        inBio = NULL;
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_BINARY | PKCS7_STREAM;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectIntEQ(PKCS7_final(p7, inBio, flags), 1);
        ExpectIntGT((outLen = i2d_PKCS7(p7, &out)), 0);

        /* PKCS7_final, bad args: PKCS7 null */
        ExpectIntEQ(PKCS7_final(NULL, inBio, 0), 0);
        /* PKCS7_final, bad args: PKCS7 null */
        ExpectIntEQ(PKCS7_final(p7, NULL, 0), 0);

        tmpPtr = out;
        ExpectNotNull(p7Ver = d2i_PKCS7(NULL, (const byte**)&tmpPtr, outLen));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, NULL, NULL, flags), 1);
        PKCS7_free(p7Ver);
        p7Ver = NULL;

        ExpectNotNull(out);
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        out = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* TEST SUCCESS: Detached, not streaming, not MIME */
    {
        /* re-populate input BIO, may have been consumed */
        BIO_free(inBio);
        inBio = NULL;
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_BINARY | PKCS7_DETACHED;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectIntGT((outLen = i2d_PKCS7(p7, &out)), 0);

        /* verify with wolfCrypt, d2i_PKCS7 does not support detached content */
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        if (p7Ver != NULL) {
            p7Ver->content = data;
            p7Ver->contentSz = sizeof(data);
        }
        ExpectIntEQ(wc_PKCS7_VerifySignedData(p7Ver, out, (word32)outLen), 0);
        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;

    #ifndef NO_PKCS7_STREAM
        /* verify with wc_PKCS7_VerifySignedData streaming */
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        if (p7Ver != NULL) {
            p7Ver->content = data;
            p7Ver->contentSz = sizeof(data);
        }
        /* test for streaming */
        ret = -1;
        for (z = 0; z < outLen && ret != 0; z++) {
            ret = wc_PKCS7_VerifySignedData(p7Ver, out + z, 1);
            if (ret < 0){
                ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
            }
        }
        ExpectIntEQ(ret, 0);
        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;
    #endif /* !NO_PKCS7_STREAM */

        /* verify expected failure (NULL return) from d2i_PKCS7, it does not
         * yet support detached content */
        tmpPtr = out;
        ExpectNull(p7Ver = d2i_PKCS7(NULL, (const byte**)&tmpPtr, outLen));
        PKCS7_free(p7Ver);
        p7Ver = NULL;

        ExpectNotNull(out);
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        out = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* TEST SUCCESS: Detached, streaming, not MIME */
    {
        /* re-populate input BIO, may have been consumed */
        BIO_free(inBio);
        inBio = NULL;
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_BINARY | PKCS7_DETACHED | PKCS7_STREAM;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectIntEQ(PKCS7_final(p7, inBio, flags), 1);
        ExpectIntGT((outLen = i2d_PKCS7(p7, &out)), 0);

        /* verify with wolfCrypt, d2i_PKCS7 does not support detached content */
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        if (p7Ver != NULL) {
            p7Ver->content = data;
            p7Ver->contentSz = sizeof(data);
        }
        ExpectIntEQ(wc_PKCS7_VerifySignedData(p7Ver, out, (word32)outLen), 0);
        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;

        ExpectNotNull(out);

    #ifndef NO_PKCS7_STREAM
        /* verify with wc_PKCS7_VerifySignedData streaming */
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        if (p7Ver != NULL) {
            p7Ver->content = data;
            p7Ver->contentSz = sizeof(data);
        }
        /* test for streaming */
        ret = -1;
        for (z = 0; z < outLen && ret != 0; z++) {
            ret = wc_PKCS7_VerifySignedData(p7Ver, out + z, 1);
            if (ret < 0){
                ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
            }
        }
        ExpectIntEQ(ret, 0);
        ExpectNotNull(out);
        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;
    #endif /* !NO_PKCS7_STREAM */

        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        PKCS7_free(p7);
        p7 = NULL;
    }

    X509_STORE_free(store);
    X509_free(caCert);
    X509_free(signCert);
    EVP_PKEY_free(signKey);
    BIO_free(inBio);
    BIO_free(keyBio);
    BIO_free(certBio);
    BIO_free(caBio);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_PKCS7_SIGNED_new(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7)
    PKCS7_SIGNED* pkcs7 = NULL;

    ExpectNotNull(pkcs7 = PKCS7_SIGNED_new());
    ExpectIntEQ(pkcs7->contentOID, SIGNED_DATA);

    PKCS7_SIGNED_free(pkcs7);
#endif
    return EXPECT_RESULT();
}

#ifndef NO_BIO
static int test_wolfSSL_PEM_write_bio_PKCS7(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM)
    PKCS7* pkcs7 = NULL;
    BIO* bio = NULL;
    const byte* cert_buf = NULL;
    int ret = 0;
    WC_RNG rng;
    const byte data[] = { /* Hello World */
        0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f,
        0x72,0x6c,0x64
    };
#ifndef NO_RSA
    #if defined(USE_CERT_BUFFERS_2048)
        byte        key[sizeof(client_key_der_2048)];
        byte        cert[sizeof(client_cert_der_2048)];
        word32      keySz = (word32)sizeof(key);
        word32      certSz = (word32)sizeof(cert);
        XMEMSET(key, 0, keySz);
        XMEMSET(cert, 0, certSz);
        XMEMCPY(key, client_key_der_2048, keySz);
        XMEMCPY(cert, client_cert_der_2048, certSz);
    #elif defined(USE_CERT_BUFFERS_1024)
        byte        key[sizeof_client_key_der_1024];
        byte        cert[sizeof(sizeof_client_cert_der_1024)];
        word32      keySz = (word32)sizeof(key);
        word32      certSz = (word32)sizeof(cert);
        XMEMSET(key, 0, keySz);
        XMEMSET(cert, 0, certSz);
        XMEMCPY(key, client_key_der_1024, keySz);
        XMEMCPY(cert, client_cert_der_1024, certSz);
    #else
        unsigned char   cert[ONEK_BUF];
        unsigned char   key[ONEK_BUF];
        XFILE           fp = XBADFILE;
        int             certSz;
        int             keySz;

        ExpectTrue((fp = XFOPEN("./certs/1024/client-cert.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(certSz = (int)XFREAD(cert, 1, sizeof_client_cert_der_1024,
            fp), 0);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }

        ExpectTrue((fp = XFOPEN("./certs/1024/client-key.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(keySz = (int)XFREAD(key, 1, sizeof_client_key_der_1024, fp),
            0);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }
    #endif
#elif defined(HAVE_ECC)
    #if defined(USE_CERT_BUFFERS_256)
        unsigned char    cert[sizeof(cliecc_cert_der_256)];
        unsigned char    key[sizeof(ecc_clikey_der_256)];
        int              certSz = (int)sizeof(cert);
        int              keySz = (int)sizeof(key);
        XMEMSET(cert, 0, certSz);
        XMEMSET(key, 0, keySz);
        XMEMCPY(cert, cliecc_cert_der_256, sizeof_cliecc_cert_der_256);
        XMEMCPY(key, ecc_clikey_der_256, sizeof_ecc_clikey_der_256);
    #else
        unsigned char   cert[ONEK_BUF];
        unsigned char   key[ONEK_BUF];
        XFILE           fp = XBADFILE;
        int             certSz, keySz;

        ExpectTrue((fp = XFOPEN("./certs/client-ecc-cert.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(certSz = (int)XFREAD(cert, 1, sizeof_cliecc_cert_der_256,
            fp), 0);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }

        ExpectTrue((fp = XFOPEN("./certs/client-ecc-key.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(keySz = (int)XFREAD(key, 1, sizeof_ecc_clikey_der_256, fp),
            0);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }
    #endif
#else
    #error PKCS7 requires ECC or RSA
#endif

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    /* initialize with DER encoded cert */
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte*)cert, (word32)certSz), 0);

    /* init rng */
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    if (pkcs7 != NULL) {
        pkcs7->rng = &rng;
        pkcs7->content   = (byte*)data; /* not used for ex */
        pkcs7->contentSz = (word32)sizeof(data);
        pkcs7->contentOID = SIGNED_DATA;
        pkcs7->privateKey = key;
        pkcs7->privateKeySz = (word32)sizeof(key);
        pkcs7->encryptOID = RSAk;
    #ifdef NO_SHA
        pkcs7->hashOID = SHA256h;
    #else
        pkcs7->hashOID = SHAh;
    #endif
        pkcs7->signedAttribs   = NULL;
        pkcs7->signedAttribsSz = 0;
    }

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    /* Write PKCS#7 PEM to BIO, the function converts the DER to PEM cert*/
    ExpectIntEQ(PEM_write_bio_PKCS7(bio, pkcs7), WOLFSSL_SUCCESS);

    /* Read PKCS#7 PEM from BIO */
    ret = wolfSSL_BIO_get_mem_data(bio, &cert_buf);
    ExpectIntGE(ret, 0);

    BIO_free(bio);
    wc_PKCS7_Free(pkcs7);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

#ifdef HAVE_SMIME
/* // NOLINTBEGIN(clang-analyzer-unix.Stream) */
static int test_wolfSSL_SMIME_read_PKCS7(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA)
    PKCS7* pkcs7 = NULL;
    BIO* bio = NULL;
    BIO* bcont = NULL;
    BIO* out = NULL;
    const byte* outBuf = NULL;
    int outBufLen = 0;
    static const char contTypeText[] = "Content-Type: text/plain\r\n\r\n";
    XFILE smimeTestFile = XBADFILE;

    ExpectTrue((smimeTestFile = XFOPEN("./certs/test/smime-test.p7s", "rb")) !=
        XBADFILE);

    /* smime-test.p7s */
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ExpectNotNull(bio);
    ExpectIntEQ(wolfSSL_BIO_set_fp(bio, smimeTestFile, BIO_CLOSE), SSL_SUCCESS);
    pkcs7 = wolfSSL_SMIME_read_PKCS7(bio, &bcont);
    ExpectNotNull(pkcs7);
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, bcont, NULL,
        PKCS7_NOVERIFY), SSL_SUCCESS);
    if (smimeTestFile != XBADFILE) {
        XFCLOSE(smimeTestFile);
        smimeTestFile = XBADFILE;
    }
    if (bcont) BIO_free(bcont);
    bcont = NULL;
    wolfSSL_PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* smime-test-multipart.p7s */
    smimeTestFile = XFOPEN("./certs/test/smime-test-multipart.p7s", "rb");
    ExpectFalse(smimeTestFile == XBADFILE);
    ExpectIntEQ(wolfSSL_BIO_set_fp(bio, smimeTestFile, BIO_CLOSE), SSL_SUCCESS);
    pkcs7 = wolfSSL_SMIME_read_PKCS7(bio, &bcont);
    ExpectNotNull(pkcs7);
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, bcont, NULL,
        PKCS7_NOVERIFY), SSL_SUCCESS);
    if (smimeTestFile != XBADFILE) {
        XFCLOSE(smimeTestFile);
        smimeTestFile = XBADFILE;
    }
    if (bcont) BIO_free(bcont);
    bcont = NULL;
    wolfSSL_PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* smime-test-multipart-badsig.p7s */
    smimeTestFile = XFOPEN("./certs/test/smime-test-multipart-badsig.p7s",
        "rb");
    ExpectFalse(smimeTestFile == XBADFILE);
    ExpectIntEQ(wolfSSL_BIO_set_fp(bio, smimeTestFile, BIO_CLOSE), SSL_SUCCESS);
    pkcs7 = wolfSSL_SMIME_read_PKCS7(bio, &bcont);
    ExpectNotNull(pkcs7); /* can read in the unverified smime bundle */
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, bcont, NULL,
        PKCS7_NOVERIFY), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    if (smimeTestFile != XBADFILE) {
        XFCLOSE(smimeTestFile);
        smimeTestFile = XBADFILE;
    }
    if (bcont) BIO_free(bcont);
    bcont = NULL;
    wolfSSL_PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* smime-test-canon.p7s */
    smimeTestFile = XFOPEN("./certs/test/smime-test-canon.p7s", "rb");
    ExpectFalse(smimeTestFile == XBADFILE);
    ExpectIntEQ(wolfSSL_BIO_set_fp(bio, smimeTestFile, BIO_CLOSE), SSL_SUCCESS);
    pkcs7 = wolfSSL_SMIME_read_PKCS7(bio, &bcont);
    ExpectNotNull(pkcs7);
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, bcont, NULL,
        PKCS7_NOVERIFY), SSL_SUCCESS);
    if (smimeTestFile != XBADFILE) {
        XFCLOSE(smimeTestFile);
        smimeTestFile = XBADFILE;
    }
    if (bcont) BIO_free(bcont);
    bcont = NULL;
    wolfSSL_PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* Test PKCS7_TEXT, PKCS7_verify() should remove Content-Type: text/plain */
    smimeTestFile = XFOPEN("./certs/test/smime-test-canon.p7s", "rb");
    ExpectFalse(smimeTestFile == XBADFILE);
    ExpectIntEQ(wolfSSL_BIO_set_fp(bio, smimeTestFile, BIO_CLOSE), SSL_SUCCESS);
    pkcs7 = wolfSSL_SMIME_read_PKCS7(bio, &bcont);
    ExpectNotNull(pkcs7);
    out = wolfSSL_BIO_new(BIO_s_mem());
    ExpectNotNull(out);
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, bcont, out,
        PKCS7_NOVERIFY | PKCS7_TEXT), SSL_SUCCESS);
    ExpectIntGT((outBufLen = BIO_get_mem_data(out, &outBuf)), 0);
    /* Content-Type should not show up at beginning of output buffer */
    ExpectIntGT(outBufLen, XSTRLEN(contTypeText));
    ExpectIntGT(XMEMCMP(outBuf, contTypeText, XSTRLEN(contTypeText)), 0);

    BIO_free(out);
    BIO_free(bio);
    if (bcont) BIO_free(bcont);
    wolfSSL_PKCS7_free(pkcs7);
#endif
    return EXPECT_RESULT();
}
/* // NOLINTEND(clang-analyzer-unix.Stream) */

static int test_wolfSSL_SMIME_write_PKCS7(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_RSA)
    PKCS7* p7 = NULL;
    PKCS7* p7Ver = NULL;
    int flags = 0;
    byte data[] = "Test data to encode.";

    const char* cert = "./certs/server-cert.pem";
    const char* key  = "./certs/server-key.pem";
    const char* ca   = "./certs/ca-cert.pem";

    WOLFSSL_BIO* certBio = NULL;
    WOLFSSL_BIO* keyBio  = NULL;
    WOLFSSL_BIO* caBio   = NULL;
    WOLFSSL_BIO* inBio   = NULL;
    WOLFSSL_BIO* outBio  = NULL;
    WOLFSSL_BIO* content = NULL;
    X509* signCert = NULL;
    EVP_PKEY* signKey = NULL;
    X509* caCert = NULL;
    X509_STORE* store = NULL;

    /* read signer cert/key into BIO */
    ExpectNotNull(certBio = BIO_new_file(cert, "r"));
    ExpectNotNull(keyBio = BIO_new_file(key, "r"));
    ExpectNotNull(signCert = PEM_read_bio_X509(certBio, NULL, 0, NULL));
    ExpectNotNull(signKey = PEM_read_bio_PrivateKey(keyBio, NULL, 0, NULL));

    /* read CA cert into store (for verify) */
    ExpectNotNull(caBio = BIO_new_file(ca, "r"));
    ExpectNotNull(caCert = PEM_read_bio_X509(caBio, NULL, 0, NULL));
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, caCert), 1);


    /* generate and verify SMIME: not detached */
    {
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_STREAM;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectNotNull(outBio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(SMIME_write_PKCS7(outBio, p7, inBio, flags), 1);

        /* bad arg: out NULL */
        ExpectIntEQ(SMIME_write_PKCS7(NULL, p7, inBio, flags), 0);
        /* bad arg: pkcs7 NULL */
        ExpectIntEQ(SMIME_write_PKCS7(outBio, NULL, inBio, flags), 0);

        ExpectNotNull(p7Ver = SMIME_read_PKCS7(outBio, &content));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, NULL, NULL, flags), 1);

        BIO_free(content);
        content = NULL;
        BIO_free(inBio);
        inBio = NULL;
        BIO_free(outBio);
        outBio = NULL;
        PKCS7_free(p7Ver);
        p7Ver = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* generate and verify SMIME: not detached, add Content-Type */
    {
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_STREAM | PKCS7_TEXT;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectNotNull(outBio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(SMIME_write_PKCS7(outBio, p7, inBio, flags), 1);

        ExpectNotNull(p7Ver = SMIME_read_PKCS7(outBio, &content));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, NULL, NULL, flags), 1);

        BIO_free(content);
        content = NULL;
        BIO_free(inBio);
        inBio = NULL;
        BIO_free(outBio);
        outBio = NULL;
        PKCS7_free(p7Ver);
        p7Ver = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* generate and verify SMIME: detached */
    {
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_DETACHED | PKCS7_STREAM;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectNotNull(outBio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(SMIME_write_PKCS7(outBio, p7, inBio, flags), 1);

        ExpectNotNull(p7Ver = SMIME_read_PKCS7(outBio, &content));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, content, NULL, flags), 1);

        BIO_free(content);
        content = NULL;
        BIO_free(inBio);
        inBio = NULL;
        BIO_free(outBio);
        outBio = NULL;
        PKCS7_free(p7Ver);
        p7Ver = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* generate and verify SMIME: PKCS7_TEXT to add Content-Type header */
    {
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_STREAM | PKCS7_DETACHED | PKCS7_TEXT;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectNotNull(outBio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(SMIME_write_PKCS7(outBio, p7, inBio, flags), 1);

        ExpectNotNull(p7Ver = SMIME_read_PKCS7(outBio, &content));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, content, NULL, flags), 1);

        BIO_free(content);
        content = NULL;
        BIO_free(inBio);
        inBio = NULL;
        BIO_free(outBio);
        outBio = NULL;
        PKCS7_free(p7Ver);
        p7Ver = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    X509_STORE_free(store);
    X509_free(caCert);
    X509_free(signCert);
    EVP_PKEY_free(signKey);
    BIO_free(keyBio);
    BIO_free(certBio);
    BIO_free(caBio);
#endif
    return EXPECT_RESULT();
}
#endif /* HAVE_SMIME */
#endif /* !NO_BIO */

/* Test of X509 store use outside of SSL context w/ CRL lookup (ALWAYS
 * returns 0) */
static int test_X509_STORE_No_SSL_CTX(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN) && \
    (defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_EXT)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)  && \
    (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) && \
    defined(HAVE_CRL) && !defined(NO_RSA)

    X509_STORE *     store = NULL;
    X509_STORE_CTX * storeCtx = NULL;
    X509_CRL *       crl = NULL;
    X509 *           ca = NULL;
    X509 *           cert = NULL;
    const char       cliCrlPem[] = "./certs/crl/cliCrl.pem";
    const char       srvCert[] = "./certs/server-cert.pem";
    const char       caCert[] = "./certs/ca-cert.pem";
    const char       caDir[] = "./certs/crl/hash_pem";
    XFILE            fp = XBADFILE;
    X509_LOOKUP *    lookup = NULL;

    ExpectNotNull(store = (X509_STORE *)X509_STORE_new());

    /* Set up store with CA */
    ExpectNotNull((ca = wolfSSL_X509_load_certificate_file(caCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);

    /* Add CRL lookup directory to store
     * NOTE: test uses ./certs/crl/hash_pem/0fdb2da4.r0, which is a copy
     * of crl.pem */
    ExpectNotNull((lookup = X509_STORE_add_lookup(store,
        X509_LOOKUP_hash_dir())));
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_ADD_DIR, caDir,
        X509_FILETYPE_PEM, NULL), SSL_SUCCESS);

    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        SSL_SUCCESS);

    /* Add CRL to store NOT containing the verified certificate, which
     * forces use of the CRL lookup directory */
    ExpectTrue((fp = XFOPEN(cliCrlPem, "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL *)PEM_read_X509_CRL(fp, (X509_CRL **)NULL,
        NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectIntEQ(X509_STORE_add_crl(store, crl), SSL_SUCCESS);

    /* Create verification context outside of an SSL session */
    ExpectNotNull((storeCtx = X509_STORE_CTX_new()));
    ExpectNotNull((cert = wolfSSL_X509_load_certificate_file(srvCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);

    /* Perform verification, which should NOT indicate CRL missing due to the
     * store CM's X509 store pointer being NULL */
    ExpectIntNE(X509_verify_cert(storeCtx), WC_NO_ERR_TRACE(CRL_MISSING));

    X509_CRL_free(crl);
    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);
    X509_free(cert);
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}

/* Test of X509 store use outside of SSL context w/ CRL lookup, but
 * with X509_LOOKUP_add_dir and X509_FILETYPE_ASN1. */
static int test_X509_LOOKUP_add_dir(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN) && \
    (defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_EXT)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)  && \
    (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) && \
    defined(HAVE_CRL) && !defined(NO_RSA)

    X509_STORE *     store = NULL;
    X509_STORE_CTX * storeCtx = NULL;
    X509_CRL *       crl = NULL;
    X509 *           ca = NULL;
    X509 *           cert = NULL;
    const char       cliCrlPem[] = "./certs/crl/cliCrl.pem";
    const char       srvCert[] = "./certs/server-cert.pem";
    const char       caCert[] = "./certs/ca-cert.pem";
    const char       caDir[] = "./certs/crl/hash_der";
    XFILE            fp = XBADFILE;
    X509_LOOKUP *    lookup = NULL;

    ExpectNotNull(store = (X509_STORE *)X509_STORE_new());

    /* Set up store with CA */
    ExpectNotNull((ca = wolfSSL_X509_load_certificate_file(caCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);

    /* Add CRL lookup directory to store.
     * Test uses ./certs/crl/hash_der/0fdb2da4.r0, which is a copy
     * of crl.der */
    ExpectNotNull((lookup = X509_STORE_add_lookup(store,
        X509_LOOKUP_hash_dir())));

    ExpectIntEQ(X509_LOOKUP_add_dir(lookup, caDir, X509_FILETYPE_ASN1),
        SSL_SUCCESS);

    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        SSL_SUCCESS);

    /* Add CRL to store NOT containing the verified certificate, which
     * forces use of the CRL lookup directory */
    ExpectTrue((fp = XFOPEN(cliCrlPem, "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL *)PEM_read_X509_CRL(fp, (X509_CRL **)NULL,
        NULL, NULL));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    ExpectIntEQ(X509_STORE_add_crl(store, crl), SSL_SUCCESS);

    /* Create verification context outside of an SSL session */
    ExpectNotNull((storeCtx = X509_STORE_CTX_new()));
    ExpectNotNull((cert = wolfSSL_X509_load_certificate_file(srvCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);

    /* Perform verification, which should NOT return CRL missing */
    ExpectIntNE(X509_verify_cert(storeCtx), WC_NO_ERR_TRACE(CRL_MISSING));

    X509_CRL_free(crl);
    crl = NULL;
    X509_STORE_free(store);
    store = NULL;
    X509_STORE_CTX_free(storeCtx);
    storeCtx = NULL;
    X509_free(cert);
    cert = NULL;
    X509_free(ca);
    ca = NULL;

    /* Now repeat the same, but look for X509_FILETYPE_PEM.
     * We should get CRL_MISSING at the end, because the lookup
     * dir has only ASN1 CRLs. */

    ExpectNotNull(store = (X509_STORE *)X509_STORE_new());

    ExpectNotNull((ca = wolfSSL_X509_load_certificate_file(caCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);

    ExpectNotNull((lookup = X509_STORE_add_lookup(store,
        X509_LOOKUP_hash_dir())));

    ExpectIntEQ(X509_LOOKUP_add_dir(lookup, caDir, X509_FILETYPE_PEM),
        SSL_SUCCESS);

    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        SSL_SUCCESS);

    ExpectTrue((fp = XFOPEN(cliCrlPem, "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL *)PEM_read_X509_CRL(fp, (X509_CRL **)NULL,
        NULL, NULL));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    ExpectIntEQ(X509_STORE_add_crl(store, crl), SSL_SUCCESS);

    ExpectNotNull((storeCtx = X509_STORE_CTX_new()));
    ExpectNotNull((cert = wolfSSL_X509_load_certificate_file(srvCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);

    /* Now we SHOULD get CRL_MISSING, because we looked for PEM
     * in dir containing only ASN1/DER. */
    ExpectIntEQ(X509_verify_cert(storeCtx), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx),
            X509_V_ERR_UNABLE_TO_GET_CRL);

    X509_CRL_free(crl);
    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);
    X509_free(cert);
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}



/*----------------------------------------------------------------------------*
 | Certificate Failure Checks
 *----------------------------------------------------------------------------*/
#if !defined(NO_CERTS) && (!defined(NO_WOLFSSL_CLIENT) || \
                   !defined(WOLFSSL_NO_CLIENT_AUTH)) && !defined(NO_FILESYSTEM)
#if !defined(NO_RSA) || defined(HAVE_ECC)
/* Use the Cert Manager(CM) API to generate the error ASN_SIG_CONFIRM_E */
static int verify_sig_cm(const char* ca, byte* cert_buf, size_t cert_sz,
    int type)
{
    int ret;
    WOLFSSL_CERT_MANAGER* cm = NULL;

    switch (type) {
        case TESTING_RSA:
        #ifdef NO_RSA
            fprintf(stderr, "RSA disabled, skipping test\n");
            return ASN_SIG_CONFIRM_E;
        #else
            break;
        #endif
        case TESTING_ECC:
        #ifndef HAVE_ECC
            fprintf(stderr, "ECC disabled, skipping test\n");
            return ASN_SIG_CONFIRM_E;
        #else
            break;
        #endif
        default:
            fprintf(stderr, "Bad function argument\n");
            return BAD_FUNC_ARG;
    }
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        fprintf(stderr, "wolfSSL_CertManagerNew failed\n");
        return -1;
    }

#ifndef NO_FILESYSTEM
    ret = wolfSSL_CertManagerLoadCA(cm, ca, 0);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CertManagerLoadCA failed\n");
        wolfSSL_CertManagerFree(cm);
        return ret;
    }
#else
    (void)ca;
#endif

    ret = wolfSSL_CertManagerVerifyBuffer(cm, cert_buf, (long int)cert_sz,
        WOLFSSL_FILETYPE_ASN1);
    /* Let ExpectIntEQ handle return code */

    wolfSSL_CertManagerFree(cm);

    return ret;
}
#endif

#if !defined(NO_FILESYSTEM)
static int test_RsaSigFailure_cm(void)
{
    EXPECT_DECLS;
#ifndef NO_RSA
    const char* ca_cert = "./certs/ca-cert.pem";
    const char* server_cert = "./certs/server-cert.der";
    byte* cert_buf = NULL;
    size_t cert_sz = 0;

    ExpectIntEQ(load_file(server_cert, &cert_buf, &cert_sz), 0);
    if ((cert_buf != NULL) && (cert_sz > 0)) {
        /* corrupt DER - invert last byte, which is signature */
        cert_buf[cert_sz-1] = ~cert_buf[cert_sz-1];
        /* test bad cert */
#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
        ExpectIntEQ(verify_sig_cm(ca_cert, cert_buf, cert_sz, TESTING_RSA),
           WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
#elif defined(NO_ASN_CRYPT)
        /* RSA verify is not called when ASN crypt support is disabled */
        ExpectIntEQ(verify_sig_cm(ca_cert, cert_buf, cert_sz, TESTING_RSA),
           WOLFSSL_SUCCESS);
#else
        ExpectIntEQ(verify_sig_cm(ca_cert, cert_buf, cert_sz, TESTING_RSA),
           WC_NO_ERR_TRACE(ASN_SIG_CONFIRM_E));
#endif
    }

    /* load_file() uses malloc. */
    if (cert_buf != NULL) {
        free(cert_buf);
    }
#endif /* !NO_RSA */
    return EXPECT_RESULT();
}

static int test_EccSigFailure_cm(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    /* self-signed ECC cert, so use server cert as CA */
    const char* ca_cert = "./certs/ca-ecc-cert.pem";
    const char* server_cert = "./certs/server-ecc.der";
    byte* cert_buf = NULL;
    size_t cert_sz = 0;

    ExpectIntEQ(load_file(server_cert, &cert_buf, &cert_sz), 0);
    if (cert_buf != NULL && cert_sz > 0) {
        /* corrupt DER - invert last byte, which is signature */
        cert_buf[cert_sz-1] = ~cert_buf[cert_sz-1];

        /* test bad cert */
#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
        ExpectIntEQ(verify_sig_cm(ca_cert, cert_buf, cert_sz, TESTING_ECC),
           WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
#elif defined(NO_ASN_CRYPT)
        /* ECC verify is not called when ASN crypt support is disabled */
        ExpectIntEQ(verify_sig_cm(ca_cert, cert_buf, cert_sz, TESTING_ECC),
           WOLFSSL_SUCCESS);
#else
        ExpectIntEQ(verify_sig_cm(ca_cert, cert_buf, cert_sz, TESTING_ECC),
           WC_NO_ERR_TRACE(ASN_SIG_CONFIRM_E));
#endif
    }

    /* load_file() uses malloc. */
    if (cert_buf != NULL) {
        free(cert_buf);
    }
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif /* HAVE_ECC */
    return EXPECT_RESULT();
}

#endif /* !NO_FILESYSTEM */
#endif /* NO_CERTS */

#ifdef WOLFSSL_TLS13
#if defined(WOLFSSL_SEND_HRR_COOKIE) && !defined(NO_WOLFSSL_SERVER)
#ifdef WC_SHA384_DIGEST_SIZE
    static byte fixedKey[WC_SHA384_DIGEST_SIZE] = { 0, };
#else
    static byte fixedKey[WC_SHA256_DIGEST_SIZE] = { 0, };
#endif
#endif
#ifdef WOLFSSL_EARLY_DATA
static const char earlyData[] = "Early Data";
static       char earlyDataBuffer[1];
#endif

static int test_tls13_apis(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SUPPORTED_CURVES) && defined(HAVE_ECC) && \
    (!defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT))
    int          ret;
#endif
#ifndef WOLFSSL_NO_TLS12
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_CTX* clientTls12Ctx = NULL;
    WOLFSSL*     clientTls12Ssl = NULL;
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_CTX* serverTls12Ctx = NULL;
    WOLFSSL*     serverTls12Ssl = NULL;
#endif
#endif
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_CTX* clientCtx = NULL;
    WOLFSSL*     clientSsl = NULL;
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_CTX* serverCtx = NULL;
    WOLFSSL*     serverSsl = NULL;
#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
#ifndef NO_RSA
    const char*  ourCert = svrCertFile;
    const char*  ourKey  = svrKeyFile;
#elif defined(HAVE_ECC)
    const char*  ourCert = eccCertFile;
    const char*  ourKey  = eccKeyFile;
#endif
#endif
#endif
    int          required;
#ifdef WOLFSSL_EARLY_DATA
    int          outSz;
#endif
#if defined(HAVE_ECC) && defined(HAVE_SUPPORTED_CURVES)
    int          groups[2] = { WOLFSSL_ECC_SECP256R1,
#ifdef WOLFSSL_HAVE_KYBER
#ifdef WOLFSSL_KYBER_ORIGINAL
    #ifndef WOLFSSL_NO_KYBER512
                               WOLFSSL_KYBER_LEVEL1
    #elif !defined(WOLFSSL_NO_KYBER768)
                               WOLFSSL_KYBER_LEVEL3
    #else
                               WOLFSSL_KYBER_LEVEL5
    #endif
#else
    #ifndef WOLFSSL_NO_ML_KEM_512
                               WOLFSSL_ML_KEM_512
    #elif !defined(WOLFSSL_NO_ML_KEM_768)
                               WOLFSSL_ML_KEM_768
    #else
                               WOLFSSL_ML_KEM_1024
    #endif
#endif
#else
                               WOLFSSL_ECC_SECP256R1
#endif
                             };
#if !defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT)
    int          bad_groups[2] = { 0xDEAD, 0xBEEF };
#endif /* !NO_WOLFSSL_SERVER || !NO_WOLFSSL_CLIENT */
    int          numGroups = 2;
#endif
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
    char         groupList[] =
#ifdef HAVE_CURVE25519
            "X25519:"
#endif
#ifdef HAVE_CURVE448
            "X448:"
#endif
#ifndef NO_ECC_SECP
#if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
            "P-521:secp521r1:"
#endif
#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
            "P-384:secp384r1:"
#endif
#if (!defined(NO_ECC256)  || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 256
            "P-256:secp256r1"
#if defined(WOLFSSL_HAVE_KYBER) && !defined(WOLFSSL_KYBER_NO_MALLOC) && \
    !defined(WOLFSSL_KYBER_NO_MAKE_KEY) && \
    !defined(WOLFSSL_KYBER_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_KYBER_NO_DECAPSULATE)
#ifdef WOLFSSL_KYBER_ORIGINAL
    #ifndef WOLFSSL_NO_KYBER512
            ":P256_KYBER_LEVEL1"
    #elif !defined(WOLFSSL_NO_KYBER768)
            ":P256_KYBER_LEVEL3"
    #else
            ":P256_KYBER_LEVEL5"
    #endif
#else
    #ifndef WOLFSSL_NO_KYBER512
            ":P256_ML_KEM_512"
    #elif !defined(WOLFSSL_NO_KYBER768)
            ":P256_ML_KEM_768"
    #else
            ":P256_ML_KEM_1024"
    #endif
#endif
#endif
#endif
#endif /* !defined(NO_ECC_SECP) */
#if defined(WOLFSSL_HAVE_KYBER) && !defined(WOLFSSL_KYBER_NO_MALLOC) && \
    !defined(WOLFSSL_KYBER_NO_MAKE_KEY) && \
    !defined(WOLFSSL_KYBER_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_KYBER_NO_DECAPSULATE)
#ifdef WOLFSSL_KYBER_ORIGINAL
    #ifndef WOLFSSL_NO_KYBER512
            ":KYBER_LEVEL1"
    #elif !defined(WOLFSSL_NO_KYBER768)
            ":KYBER_LEVEL3"
    #else
            ":KYBER_LEVEL5"
    #endif
#else
    #ifndef WOLFSSL_NO_KYBER512
            ":ML_KEM_512"
    #elif !defined(WOLFSSL_NO_KYBER768)
            ":ML_KEM_768"
    #else
            ":ML_KEM_1024"
    #endif
#endif
#endif
            "";
#endif /* defined(OPENSSL_EXTRA) && defined(HAVE_ECC) */
#if defined(WOLFSSL_HAVE_KYBER) && !defined(WOLFSSL_KYBER_NO_MALLOC) && \
    !defined(WOLFSSL_KYBER_NO_MAKE_KEY) && \
    !defined(WOLFSSL_KYBER_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_KYBER_NO_DECAPSULATE)
    int kyberLevel;
#endif

#ifndef WOLFSSL_NO_TLS12
#ifndef NO_WOLFSSL_CLIENT
    clientTls12Ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    clientTls12Ssl = wolfSSL_new(clientTls12Ctx);
#endif
#ifndef NO_WOLFSSL_SERVER
    serverTls12Ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#if !defined(NO_CERTS)
    #if !defined(NO_FILESYSTEM)
    wolfSSL_CTX_use_certificate_chain_file(serverTls12Ctx, ourCert);
    wolfSSL_CTX_use_PrivateKey_file(serverTls12Ctx, ourKey,
        WOLFSSL_FILETYPE_PEM);
    #elif defined(USE_CERT_BUFFERS_2048)
    wolfSSL_CTX_use_certificate_chain_buffer_format(serverTls12Ctx,
        server_cert_der_2048, sizeof_server_cert_der_2048,
        WOLFSSL_FILETYPE_ASN1);
    wolfSSL_CTX_use_PrivateKey_buffer(serverTls12Ctx, server_key_der_2048,
        sizeof_server_key_der_2048, WOLFSSL_FILETYPE_ASN1);
    #elif defined(USE_CERT_BUFFERS_256)
    wolfSSL_CTX_use_certificate_chain_buffer_format(serverTls12Ctx,
        serv_ecc_der_256, sizeof_serv_ecc_der_256, WOLFSSL_FILETYPE_ASN1);
    wolfSSL_CTX_use_PrivateKey_buffer(serverTls12Ctx, ecc_key_der_256,
        sizeof_ecc_key_der_256, WOLFSSL_FILETYPE_ASN1);
    #endif
#endif
    serverTls12Ssl = wolfSSL_new(serverTls12Ctx);
#endif
#endif

#ifndef NO_WOLFSSL_CLIENT
    clientCtx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    clientSsl = wolfSSL_new(clientCtx);
#endif
#ifndef NO_WOLFSSL_SERVER
    serverCtx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
#if !defined(NO_CERTS)
    /* ignore load failures, since we just need the server to have a cert set */
    #if !defined(NO_FILESYSTEM)
    wolfSSL_CTX_use_certificate_chain_file(serverCtx, ourCert);
    wolfSSL_CTX_use_PrivateKey_file(serverCtx, ourKey, WOLFSSL_FILETYPE_PEM);
    #elif defined(USE_CERT_BUFFERS_2048)
    wolfSSL_CTX_use_certificate_chain_buffer_format(serverCtx,
        server_cert_der_2048, sizeof_server_cert_der_2048,
        WOLFSSL_FILETYPE_ASN1);
    wolfSSL_CTX_use_PrivateKey_buffer(serverCtx, server_key_der_2048,
        sizeof_server_key_der_2048, WOLFSSL_FILETYPE_ASN1);
    #elif defined(USE_CERT_BUFFERS_256)
    wolfSSL_CTX_use_certificate_chain_buffer_format(serverCtx, serv_ecc_der_256,
        sizeof_serv_ecc_der_256, WOLFSSL_FILETYPE_ASN1);
    wolfSSL_CTX_use_PrivateKey_buffer(serverCtx, ecc_key_der_256,
        sizeof_ecc_key_der_256, WOLFSSL_FILETYPE_ASN1);
    #endif
#endif
    serverSsl = wolfSSL_new(serverCtx);
    ExpectNotNull(serverSsl);
#endif

#ifdef WOLFSSL_SEND_HRR_COOKIE
    ExpectIntEQ(wolfSSL_send_hrr_cookie(NULL, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_send_hrr_cookie(clientSsl, NULL, 0), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_send_hrr_cookie(serverTls12Ssl, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    ExpectIntEQ(wolfSSL_send_hrr_cookie(serverSsl, NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_send_hrr_cookie(serverSsl, fixedKey, sizeof(fixedKey)),
        WOLFSSL_SUCCESS);
#endif
#endif

#ifdef HAVE_SUPPORTED_CURVES
#ifdef HAVE_ECC
    ExpectIntEQ(wolfSSL_UseKeyShare(NULL, WOLFSSL_ECC_SECP256R1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    do {
        ret = wolfSSL_UseKeyShare(serverSsl, WOLFSSL_ECC_SECP256R1);
    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ret == WC_NO_ERR_TRACE(WC_PENDING_E))
            wolfSSL_AsyncPoll(serverSsl, WOLF_POLL_FLAG_CHECK_HW);
    #endif
    }
    while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    do {
        ret = wolfSSL_UseKeyShare(clientTls12Ssl, WOLFSSL_ECC_SECP256R1);
    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ret == WC_NO_ERR_TRACE(WC_PENDING_E))
            wolfSSL_AsyncPoll(clientTls12Ssl, WOLF_POLL_FLAG_CHECK_HW);
    #endif
    }
    while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif
    do {
        ret = wolfSSL_UseKeyShare(clientSsl, WOLFSSL_ECC_SECP256R1);
    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ret == WC_NO_ERR_TRACE(WC_PENDING_E))
            wolfSSL_AsyncPoll(clientSsl, WOLF_POLL_FLAG_CHECK_HW);
    #endif
    }
    while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif
#elif defined(HAVE_CURVE25519)
    ExpectIntEQ(wolfSSL_UseKeyShare(NULL, WOLFSSL_ECC_X25519), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_UseKeyShare(serverSsl, WOLFSSL_ECC_X25519),
        WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_UseKeyShare(clientTls12Ssl, WOLFSSL_ECC_X25519),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_UseKeyShare(clientSsl, WOLFSSL_ECC_X25519),
        WOLFSSL_SUCCESS);
#endif
#elif defined(HAVE_CURVE448)
    ExpectIntEQ(wolfSSL_UseKeyShare(NULL, WOLFSSL_ECC_X448), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_UseKeyShare(serverSsl, WOLFSSL_ECC_X448),
        WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_UseKeyShare(clientTls12Ssl, WOLFSSL_ECC_X448),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_UseKeyShare(clientSsl, WOLFSSL_ECC_X448),
        WOLFSSL_SUCCESS);
#endif
#else
    ExpectIntEQ(wolfSSL_UseKeyShare(NULL, WOLFSSL_ECC_SECP256R1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_UseKeyShare(clientTls12Ssl, WOLFSSL_ECC_SECP256R1),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
    ExpectIntEQ(wolfSSL_UseKeyShare(clientSsl, WOLFSSL_ECC_SECP256R1),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
#endif

#if defined(WOLFSSL_HAVE_KYBER) && !defined(WOLFSSL_KYBER_NO_MALLOC) && \
    !defined(WOLFSSL_KYBER_NO_MAKE_KEY) && \
    !defined(WOLFSSL_KYBER_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_KYBER_NO_DECAPSULATE)
#ifndef WOLFSSL_NO_ML_KEM
#ifndef WOLFSSL_NO_ML_KEM_768
    kyberLevel = WOLFSSL_ML_KEM_768;
#elif !defined(WOLFSSL_NO_ML_KEM_1024)
    kyberLevel = WOLFSSL_ML_KEM_1024;
#else
    kyberLevel = WOLFSSL_ML_KEM_512;
#endif
#else
#ifndef WOLFSSL_NO_KYBER768
    kyberLevel = WOLFSSL_KYBER_LEVEL3;
#elif !defined(WOLFSSL_NO_KYBER1024)
    kyberLevel = WOLFSSL_KYBER_LEVEL5;
#else
    kyberLevel = WOLFSSL_KYBER_LEVEL1;
#endif
#endif
    ExpectIntEQ(wolfSSL_UseKeyShare(NULL, kyberLevel), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_UseKeyShare(serverSsl, kyberLevel),
        WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_UseKeyShare(clientTls12Ssl, kyberLevel),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_UseKeyShare(clientSsl, kyberLevel),
        WOLFSSL_SUCCESS);
#endif
#endif

    ExpectIntEQ(wolfSSL_NoKeyShares(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_NoKeyShares(serverSsl), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_NoKeyShares(clientTls12Ssl), WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_NoKeyShares(clientSsl), WOLFSSL_SUCCESS);
#endif
#endif /* HAVE_SUPPORTED_CURVES */

    ExpectIntEQ(wolfSSL_CTX_no_ticket_TLSv13(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_CTX_no_ticket_TLSv13(clientCtx), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_CTX_no_ticket_TLSv13(serverTls12Ctx), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_CTX_no_ticket_TLSv13(serverCtx), 0);
#endif

    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(clientSsl), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(serverTls12Ssl), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(serverSsl), 0);
#endif

    ExpectIntEQ(wolfSSL_CTX_no_dhe_psk(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_CTX_no_dhe_psk(clientTls12Ctx), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_CTX_no_dhe_psk(clientCtx), 0);
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_CTX_no_dhe_psk(serverCtx), 0);
#endif

    ExpectIntEQ(wolfSSL_no_dhe_psk(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_no_dhe_psk(clientTls12Ssl), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_no_dhe_psk(clientSsl), 0);
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_no_dhe_psk(serverSsl), 0);
#endif

    ExpectIntEQ(wolfSSL_update_keys(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_update_keys(clientTls12Ssl), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_update_keys(clientSsl), WC_NO_ERR_TRACE(BUILD_MSG_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_update_keys(serverSsl), WC_NO_ERR_TRACE(BUILD_MSG_ERROR));
#endif

    ExpectIntEQ(wolfSSL_key_update_response(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_key_update_response(NULL, &required), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_key_update_response(clientTls12Ssl, &required),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_key_update_response(clientSsl, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_key_update_response(serverSsl, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

#if !defined(NO_CERTS) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    ExpectIntEQ(wolfSSL_CTX_allow_post_handshake_auth(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_CTX_allow_post_handshake_auth(serverCtx), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_CTX_allow_post_handshake_auth(clientTls12Ctx),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_CTX_allow_post_handshake_auth(clientCtx), 0);
#endif

    ExpectIntEQ(wolfSSL_allow_post_handshake_auth(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_allow_post_handshake_auth(serverSsl), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_allow_post_handshake_auth(clientTls12Ssl),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_allow_post_handshake_auth(clientSsl), 0);
#endif

    ExpectIntEQ(wolfSSL_request_certificate(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_request_certificate(clientSsl), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_request_certificate(serverTls12Ssl),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_request_certificate(serverSsl), WC_NO_ERR_TRACE(NOT_READY_ERROR));
#endif
#endif

#ifdef HAVE_ECC
#ifndef WOLFSSL_NO_SERVER_GROUPS_EXT
    ExpectIntEQ(wolfSSL_preferred_group(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_preferred_group(serverSsl), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_preferred_group(clientTls12Ssl), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_preferred_group(clientSsl), WC_NO_ERR_TRACE(NOT_READY_ERROR));
#endif
#endif

#ifdef HAVE_SUPPORTED_CURVES
    ExpectIntEQ(wolfSSL_CTX_set_groups(NULL, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_CTX_set_groups(clientCtx, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_CTX_set_groups(NULL, groups, numGroups), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_CTX_set_groups(clientTls12Ctx, groups, numGroups),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_CTX_set_groups(clientCtx, groups,
        WOLFSSL_MAX_GROUP_COUNT + 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_set_groups(clientCtx, groups, numGroups),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_groups(clientCtx, bad_groups, numGroups),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_CTX_set_groups(serverCtx, groups, numGroups),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_groups(serverCtx, bad_groups, numGroups),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    ExpectIntEQ(wolfSSL_set_groups(NULL, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_set_groups(clientSsl, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_set_groups(NULL, groups, numGroups), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_set_groups(clientTls12Ssl, groups, numGroups),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_set_groups(clientSsl, groups,
        WOLFSSL_MAX_GROUP_COUNT + 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_set_groups(clientSsl, groups, numGroups),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(clientSsl, bad_groups, numGroups),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_set_groups(serverSsl, groups, numGroups),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(serverSsl, bad_groups, numGroups),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

#ifdef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(NULL, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(clientCtx, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(NULL, groupList),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(clientTls12Ctx, groupList),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(clientCtx, groupList),
        WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(serverCtx, groupList),
        WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(wolfSSL_set1_groups_list(NULL, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_set1_groups_list(clientSsl, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif
    ExpectIntEQ(wolfSSL_set1_groups_list(NULL, groupList), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_set1_groups_list(clientTls12Ssl, groupList),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_set1_groups_list(clientSsl, groupList),
        WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_set1_groups_list(serverSsl, groupList),
        WOLFSSL_SUCCESS);
#endif
#endif /* OPENSSL_EXTRA */
#endif /* HAVE_SUPPORTED_CURVES */
#endif /* HAVE_ECC */

#ifdef WOLFSSL_EARLY_DATA
#ifndef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_CTX_set_max_early_data(NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_get_max_early_data(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
    ExpectIntEQ(SSL_CTX_set_max_early_data(NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(SSL_CTX_get_max_early_data(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_CTX_set_max_early_data(clientCtx, 0), WC_NO_ERR_TRACE(SIDE_ERROR));
    ExpectIntEQ(wolfSSL_CTX_get_max_early_data(clientCtx), WC_NO_ERR_TRACE(SIDE_ERROR));
#else
    ExpectIntEQ(SSL_CTX_set_max_early_data(clientCtx, 0), WC_NO_ERR_TRACE(SIDE_ERROR));
    ExpectIntEQ(SSL_CTX_get_max_early_data(clientCtx), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
#ifndef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_CTX_set_max_early_data(serverTls12Ctx, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_get_max_early_data(serverTls12Ctx), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
    ExpectIntEQ(SSL_CTX_set_max_early_data(serverTls12Ctx, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(SSL_CTX_get_max_early_data(serverTls12Ctx), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#endif
#ifndef OPENSSL_EXTRA
#ifdef WOLFSSL_ERROR_CODE_OPENSSL
    ExpectIntEQ(wolfSSL_CTX_set_max_early_data(serverCtx, 32),
        WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(wolfSSL_CTX_set_max_early_data(serverCtx, 32), 0);
#endif
    ExpectIntEQ(wolfSSL_CTX_get_max_early_data(serverCtx), 32);
#else
    ExpectIntEQ(SSL_CTX_set_max_early_data(serverCtx, 32), 1);
    ExpectIntEQ(SSL_CTX_get_max_early_data(serverCtx), 32);
#endif
#endif

#ifndef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_set_max_early_data(NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_max_early_data(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
    ExpectIntEQ(SSL_set_max_early_data(NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(SSL_get_max_early_data(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef OPENSSL_EXTRA
#ifdef WOLFSSL_ERROR_CODE_OPENSSL
    ExpectIntEQ(wolfSSL_set_max_early_data(clientSsl, 17), WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(wolfSSL_set_max_early_data(clientSsl, 17), 0);
#endif
    ExpectIntEQ(wolfSSL_get_max_early_data(clientSsl), 17);
#else
    ExpectIntEQ(SSL_set_max_early_data(clientSsl, 17), WOLFSSL_SUCCESS);
    ExpectIntEQ(SSL_get_max_early_data(clientSsl), 17);
#endif
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
#ifndef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_set_max_early_data(serverTls12Ssl, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_max_early_data(serverTls12Ssl), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
    ExpectIntEQ(SSL_set_max_early_data(serverTls12Ssl, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(SSL_get_max_early_data(serverTls12Ssl), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#endif
#ifndef OPENSSL_EXTRA
#ifdef WOLFSSL_ERROR_CODE_OPENSSL
    ExpectIntEQ(wolfSSL_set_max_early_data(serverSsl, 16), WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(wolfSSL_set_max_early_data(serverSsl, 16), 0);
#endif
    ExpectIntEQ(wolfSSL_get_max_early_data(serverSsl), 16);
#else
    ExpectIntEQ(SSL_set_max_early_data(serverSsl, 16), 1);
    ExpectIntEQ(SSL_get_max_early_data(serverSsl), 16);
#endif
#endif


    ExpectIntEQ(wolfSSL_write_early_data(NULL, earlyData, sizeof(earlyData),
        &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_write_early_data(clientSsl, NULL, sizeof(earlyData),
        &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_write_early_data(clientSsl, earlyData, -1, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_write_early_data(clientSsl, earlyData,
        sizeof(earlyData), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_write_early_data(serverSsl, earlyData,
        sizeof(earlyData), &outSz), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_write_early_data(clientTls12Ssl, earlyData,
        sizeof(earlyData), &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_write_early_data(clientSsl, earlyData,
        sizeof(earlyData), &outSz), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
#endif

    ExpectIntEQ(wolfSSL_read_early_data(NULL, earlyDataBuffer,
        sizeof(earlyDataBuffer), &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_read_early_data(serverSsl, NULL,
        sizeof(earlyDataBuffer), &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_read_early_data(serverSsl, earlyDataBuffer, -1,
        &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_read_early_data(serverSsl, earlyDataBuffer,
        sizeof(earlyDataBuffer), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_read_early_data(clientSsl, earlyDataBuffer,
        sizeof(earlyDataBuffer), &outSz), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_read_early_data(serverTls12Ssl, earlyDataBuffer,
        sizeof(earlyDataBuffer), &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_read_early_data(serverSsl, earlyDataBuffer,
        sizeof(earlyDataBuffer), &outSz), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
#endif
#endif

#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_EARLY_DATA)
    ExpectIntLT(SSL_get_early_data_status(NULL), 0);
#endif


#ifndef NO_WOLFSSL_SERVER
    wolfSSL_free(serverSsl);
    wolfSSL_CTX_free(serverCtx);
#endif
#ifndef NO_WOLFSSL_CLIENT
    wolfSSL_free(clientSsl);
    wolfSSL_CTX_free(clientCtx);
#endif

#ifndef WOLFSSL_NO_TLS12
#ifndef NO_WOLFSSL_SERVER
    wolfSSL_free(serverTls12Ssl);
    wolfSSL_CTX_free(serverTls12Ctx);
#endif
#ifndef NO_WOLFSSL_CLIENT
    wolfSSL_free(clientTls12Ssl);
    wolfSSL_CTX_free(clientTls12Ctx);
#endif
#endif

    return EXPECT_RESULT();
}

#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_ECC) && defined(BUILD_TLS_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_AES_256_GCM_SHA384)
/* Called when writing. */
static int CsSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)sz;
    (void)ctx;

    /* Force error return from wolfSSL_accept_TLSv13(). */
    return WANT_WRITE;
}
/* Called when reading. */
static int CsRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    WOLFSSL_BUFFER_INFO* msg = (WOLFSSL_BUFFER_INFO*)ctx;
    int len = (int)msg->length;

    (void)ssl;
    (void)sz;

    /* Pass back as much of message as will fit in buffer. */
    if (len > sz)
        len = sz;
    XMEMCPY(buf, msg->buffer, len);
    /* Move over returned data. */
    msg->buffer += len;
    msg->length -= len;

    /* Amount actually copied. */
    return len;
}
#endif

static int test_tls13_cipher_suites(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_ECC) && defined(BUILD_TLS_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_AES_256_GCM_SHA384)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL *ssl = NULL;
    int i;
    byte clientHello[] = {
        0x16, 0x03, 0x03, 0x01, 0x9b, 0x01, 0x00, 0x01,
        0x97, 0x03, 0x03, 0xf4, 0x65, 0xbd, 0x22, 0xfe,
        0x6e, 0xab, 0x66, 0xdd, 0xcf, 0xe9, 0x65, 0x55,
        0xe8, 0xdf, 0xc3, 0x8e, 0x4b, 0x00, 0xbc, 0xf8,
        0x23, 0x57, 0x1b, 0xa0, 0xc8, 0xa9, 0xe2, 0x8c,
        0x91, 0x6e, 0xf9, 0x20, 0xf7, 0x5c, 0xc5, 0x5b,
        0x75, 0x8c, 0x47, 0x0a, 0x0e, 0xc4, 0x1a, 0xda,
        0xef, 0x75, 0xe5, 0x21, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        /* Cipher suites: 0x13, 0x01 = TLS13-AES128-GCM-SHA256, twice. */
                                            0x13, 0x01,
        0x13, 0x01, 0x01, 0x00, 0x01, 0x4a, 0x00, 0x2d,
        0x00, 0x03, 0x02, 0x00, 0x01, 0x00, 0x33, 0x00,
        0x47, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04,
        0x90, 0xfc, 0xe2, 0x97, 0x05, 0x7c, 0xb5, 0x23,
        0x5d, 0x5f, 0x5b, 0xcd, 0x0c, 0x1e, 0xe0, 0xe9,
        0xab, 0x38, 0x6b, 0x1e, 0x20, 0x5c, 0x1c, 0x90,
        0x2a, 0x9e, 0x68, 0x8e, 0x70, 0x05, 0x10, 0xa8,
        0x02, 0x1b, 0xf9, 0x5c, 0xef, 0xc9, 0xaf, 0xca,
        0x1a, 0x3b, 0x16, 0x8b, 0xe4, 0x1b, 0x3c, 0x15,
        0xb8, 0x0d, 0xbd, 0xaf, 0x62, 0x8d, 0xa7, 0x13,
        0xa0, 0x7c, 0xe0, 0x59, 0x0c, 0x4f, 0x8a, 0x6d,
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
        0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x03, 0x05,
        0x03, 0x04, 0x03, 0x02, 0x03, 0x08, 0x06, 0x08,
        0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08,
        0x09, 0x06, 0x01, 0x05, 0x01, 0x04, 0x01, 0x03,
        0x01, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x04, 0x00,
        0x02, 0x00, 0x17, 0x00, 0x16, 0x00, 0x00, 0x00,
        0x23, 0x00, 0x00, 0x00, 0x29, 0x00, 0xb9, 0x00,
        0x94, 0x00, 0x8e, 0x0f, 0x12, 0xfa, 0x84, 0x1f,
        0x76, 0x94, 0xd7, 0x09, 0x5e, 0xad, 0x08, 0x51,
        0xb6, 0x80, 0x28, 0x31, 0x8b, 0xfd, 0xc6, 0xbd,
        0x9e, 0xf5, 0x3b, 0x4d, 0x02, 0xbe, 0x1d, 0x73,
        0xea, 0x13, 0x68, 0x00, 0x4c, 0xfd, 0x3d, 0x48,
        0x51, 0xf9, 0x06, 0xbb, 0x92, 0xed, 0x42, 0x9f,
        0x7f, 0x2c, 0x73, 0x9f, 0xd9, 0xb4, 0xef, 0x05,
        0x26, 0x5b, 0x60, 0x5c, 0x0a, 0xfc, 0xa3, 0xbd,
        0x2d, 0x2d, 0x8b, 0xf9, 0xaa, 0x5c, 0x96, 0x3a,
        0xf2, 0xec, 0xfa, 0xe5, 0x57, 0x2e, 0x87, 0xbe,
        0x27, 0xc5, 0x3d, 0x4f, 0x5d, 0xdd, 0xde, 0x1c,
        0x1b, 0xb3, 0xcc, 0x27, 0x27, 0x57, 0x5a, 0xd9,
        0xea, 0x99, 0x27, 0x23, 0xa6, 0x0e, 0xea, 0x9c,
        0x0d, 0x85, 0xcb, 0x72, 0xeb, 0xd7, 0x93, 0xe3,
        0xfe, 0xf7, 0x5c, 0xc5, 0x5b, 0x75, 0x8c, 0x47,
        0x0a, 0x0e, 0xc4, 0x1a, 0xda, 0xef, 0x75, 0xe5,
        0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfb, 0x92, 0xce, 0xaa, 0x00, 0x21, 0x20,
        0xcb, 0x73, 0x25, 0x80, 0x46, 0x78, 0x4f, 0xe5,
        0x34, 0xf6, 0x91, 0x13, 0x7f, 0xc8, 0x8d, 0xdc,
        0x81, 0x04, 0xb7, 0x0d, 0x49, 0x85, 0x2e, 0x12,
        0x7a, 0x07, 0x23, 0xe9, 0x13, 0xa4, 0x6d, 0x8c
    };
    WOLFSSL_BUFFER_INFO msg;
    /* Offset into ClientHello message data of first cipher suite. */
    const int csOff = 78;
    /* Server cipher list. */
    const char* serverCs = "TLS13-AES256-GCM-SHA384:TLS13-AES128-GCM-SHA256";
    /* Suite list with duplicates. */
    const char* dupCs = "TLS13-AES128-GCM-SHA256:"
                        "TLS13-AES128-GCM-SHA256:"
                        "TLS13-AES256-GCM-SHA384:"
                        "TLS13-AES256-GCM-SHA384:"
                        "TLS13-AES128-GCM-SHA256";
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_SET_CIPHER_BYTES)
    const byte dupCsBytes[] = { TLS13_BYTE, TLS_AES_256_GCM_SHA384,
                                TLS13_BYTE, TLS_AES_256_GCM_SHA384,
                                TLS13_BYTE, TLS_AES_128_GCM_SHA256,
                                TLS13_BYTE, TLS_AES_128_GCM_SHA256,
                                TLS13_BYTE, TLS_AES_256_GCM_SHA384 };
#endif

    /* Set up wolfSSL context. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, eccCertFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, eccKeyFile,
        WOLFSSL_FILETYPE_PEM));
    /* Read from 'msg'. */
    wolfSSL_SetIORecv(ctx, CsRecv);
    /* No where to send to - dummy sender. */
    wolfSSL_SetIOSend(ctx, CsSend);

    /* Test cipher suite list with many copies of a cipher suite. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientHello;
    msg.length = (unsigned int)sizeof(clientHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);
    /* Force server to have as many occurrences of same cipher suite as
     * possible. */
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        suites->suiteSz = WOLFSSL_MAX_SUITE_SZ;
        for (i = 0; i < suites->suiteSz; i += 2) {
            suites->suites[i + 0] = TLS13_BYTE;
            suites->suites[i + 1] = TLS_AES_128_GCM_SHA256;
        }
    }
    /* Test multiple occurrences of same cipher suite. */
    ExpectIntEQ(wolfSSL_accept_TLSv13(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Set client order opposite to server order:
     *   TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384 */
    clientHello[csOff + 0] = TLS13_BYTE;
    clientHello[csOff + 1] = TLS_AES_128_GCM_SHA256;
    clientHello[csOff + 2] = TLS13_BYTE;
    clientHello[csOff + 3] = TLS_AES_256_GCM_SHA384;

    /* Test server order negotiation. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientHello;
    msg.length = (unsigned int)sizeof(clientHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);
    /* Server order: TLS13-AES256-GCM-SHA384:TLS13-AES128-GCM-SHA256 */
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl, serverCs), WOLFSSL_SUCCESS);
    /* Negotiate cipher suites in server order: TLS13-AES256-GCM-SHA384 */
    ExpectIntEQ(wolfSSL_accept_TLSv13(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    /* Check refined order - server order. */
    ExpectIntEQ(ssl->suites->suiteSz, 4);
    ExpectIntEQ(ssl->suites->suites[0], TLS13_BYTE);
    ExpectIntEQ(ssl->suites->suites[1], TLS_AES_256_GCM_SHA384);
    ExpectIntEQ(ssl->suites->suites[2], TLS13_BYTE);
    ExpectIntEQ(ssl->suites->suites[3], TLS_AES_128_GCM_SHA256);
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Test client order negotiation. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientHello;
    msg.length = (unsigned int)sizeof(clientHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);
    /* Server order: TLS13-AES256-GCM-SHA384:TLS13-AES128-GCM-SHA256 */
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl, serverCs), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseClientSuites(ssl), 0);
    /* Negotiate cipher suites in client order: TLS13-AES128-GCM-SHA256 */
    ExpectIntEQ(wolfSSL_accept_TLSv13(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    /* Check refined order - client order. */
    ExpectIntEQ(ssl->suites->suiteSz, 4);
    ExpectIntEQ(ssl->suites->suites[0], TLS13_BYTE);
    ExpectIntEQ(ssl->suites->suites[1], TLS_AES_128_GCM_SHA256);
    ExpectIntEQ(ssl->suites->suites[2], TLS13_BYTE);
    ExpectIntEQ(ssl->suites->suites[3], TLS_AES_256_GCM_SHA384);
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Check duplicate detection is working. */
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx, dupCs), WOLFSSL_SUCCESS);
    ExpectIntEQ(ctx->suites->suiteSz, 4);
    ExpectIntEQ(ctx->suites->suites[0], TLS13_BYTE);
    ExpectIntEQ(ctx->suites->suites[1], TLS_AES_128_GCM_SHA256);
    ExpectIntEQ(ctx->suites->suites[2], TLS13_BYTE);
    ExpectIntEQ(ctx->suites->suites[3], TLS_AES_256_GCM_SHA384);

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_SET_CIPHER_BYTES)
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list_bytes(ctx, dupCsBytes,
        sizeof(dupCsBytes)), WOLFSSL_SUCCESS);
    ExpectIntEQ(ctx->suites->suiteSz, 4);
    ExpectIntEQ(ctx->suites->suites[0], TLS13_BYTE);
    ExpectIntEQ(ctx->suites->suites[1], TLS_AES_256_GCM_SHA384);
    ExpectIntEQ(ctx->suites->suites[2], TLS13_BYTE);
    ExpectIntEQ(ctx->suites->suites[3], TLS_AES_128_GCM_SHA256);
#endif

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#endif

#if defined(HAVE_PK_CALLBACKS) && !defined(WOLFSSL_NO_TLS12)
#if !defined(NO_FILESYSTEM) && !defined(NO_DH) && \
        !defined(NO_AES) && defined(HAVE_AES_CBC) && \
         defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
static int my_DhCallback(WOLFSSL* ssl, struct DhKey* key,
        const unsigned char* priv, unsigned int privSz,
        const unsigned char* pubKeyDer, unsigned int pubKeySz,
        unsigned char* out, unsigned int* outlen,
        void* ctx)
{
    int result;
    /* Test fail when context associated with WOLFSSL is NULL */
    if (ctx == NULL) {
        return -1;
    }

    (void)ssl;
    /* return 0 on success */
    PRIVATE_KEY_UNLOCK();
    result = wc_DhAgree(key, out, outlen, priv, privSz, pubKeyDer, pubKeySz);
    PRIVATE_KEY_LOCK();
    return result;
}

static int test_dh_ctx_setup(WOLFSSL_CTX* ctx) {
    EXPECT_DECLS;
    wolfSSL_CTX_SetDhAgreeCb(ctx, my_DhCallback);
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES128-SHA256"),
            WOLFSSL_SUCCESS);
#endif
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256)
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES256-SHA256"),
            WOLFSSL_SUCCESS);
#endif
    return EXPECT_RESULT();
}

static int test_dh_ssl_setup(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    static int dh_test_ctx = 1;
    int ret;

    wolfSSL_SetDhAgreeCtx(ssl, &dh_test_ctx);
    ExpectIntEQ(*((int*)wolfSSL_GetDhAgreeCtx(ssl)), dh_test_ctx);
    ret = wolfSSL_SetTmpDH_file(ssl, dhParamFile, WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS && ret != WC_NO_ERR_TRACE(SIDE_ERROR)) {
        ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    }
    return EXPECT_RESULT();
}

static int test_dh_ssl_setup_fail(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    int ret;

    wolfSSL_SetDhAgreeCtx(ssl, NULL);
    ExpectNull(wolfSSL_GetDhAgreeCtx(ssl));
    ret = wolfSSL_SetTmpDH_file(ssl, dhParamFile, WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS && ret != WC_NO_ERR_TRACE(SIDE_ERROR)) {
        ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    }
    return EXPECT_RESULT();
}
#endif

static int test_DhCallbacks(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_DH) && \
        !defined(NO_AES) && defined(HAVE_AES_CBC) && \
         defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL     *ssl = NULL;
    int  test;
    test_ssl_cbf func_cb_client;
    test_ssl_cbf func_cb_server;

    /* Test that DH callback APIs work. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(NULL, "NONE"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    wolfSSL_CTX_SetDhAgreeCb(ctx, &my_DhCallback);
    /* load client ca cert */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx, caCertFile, 0),
            WOLFSSL_SUCCESS);
    /* test with NULL arguments */
    wolfSSL_SetDhAgreeCtx(NULL, &test);
    ExpectNull(wolfSSL_GetDhAgreeCtx(NULL));
    /* test success case */
    test = 1;
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    wolfSSL_SetDhAgreeCtx(ssl, &test);
    ExpectIntEQ(*((int*)wolfSSL_GetDhAgreeCtx(ssl)), test);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);


    XMEMSET(&func_cb_client, 0, sizeof(func_cb_client));
    XMEMSET(&func_cb_server, 0, sizeof(func_cb_server));

    /* set callbacks to use DH functions */
    func_cb_client.ctx_ready = &test_dh_ctx_setup;
    func_cb_client.ssl_ready = &test_dh_ssl_setup;
    func_cb_client.method = wolfTLSv1_2_client_method;

    func_cb_server.ctx_ready = &test_dh_ctx_setup;
    func_cb_server.ssl_ready = &test_dh_ssl_setup;
    func_cb_server.method = wolfTLSv1_2_server_method;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&func_cb_client,
        &func_cb_server, NULL), TEST_SUCCESS);

    /* Test fail */
    XMEMSET(&func_cb_client, 0, sizeof(func_cb_client));
    XMEMSET(&func_cb_server, 0, sizeof(func_cb_server));

    /* set callbacks to use DH functions */
    func_cb_client.ctx_ready = &test_dh_ctx_setup;
    func_cb_client.ssl_ready = &test_dh_ssl_setup_fail;
    func_cb_client.method = wolfTLSv1_2_client_method;

    func_cb_server.ctx_ready = &test_dh_ctx_setup;
    func_cb_server.ssl_ready = &test_dh_ssl_setup_fail;
    func_cb_server.method = wolfTLSv1_2_server_method;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&func_cb_client,
        &func_cb_server, NULL), -1001);
#endif
    return EXPECT_RESULT();
}
#endif /* HAVE_PK_CALLBACKS */

#ifdef HAVE_HASHDRBG

#ifdef TEST_RESEED_INTERVAL
static int test_wc_RNG_GenerateBlock_Reseed(void)
{
    EXPECT_DECLS;
    int i;
    WC_RNG rng;
    byte key[32];

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    for (i = 0; i < WC_RESEED_INTERVAL + 10; i++) {
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, key, sizeof(key)), 0);
    }
    DoExpectIntEQ(wc_FreeRng(&rng), 0);

    return EXPECT_RESULT();
}
#endif /* TEST_RESEED_INTERVAL */

static int test_wc_RNG_GenerateBlock(void)
{
    EXPECT_DECLS;
    int i;
    WC_RNG rng;
    byte key[32];

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    for (i = 0; i < 10; i++) {
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, key, sizeof(key)), 0);
    }
    DoExpectIntEQ(wc_FreeRng(&rng), 0);

    return EXPECT_RESULT();
}

#endif /* HAVE_HASHDRBG */

/*
 * Testing get_rand_digit
 */
static int test_get_rand_digit(void)
{
    EXPECT_DECLS;
#if !defined(WC_NO_RNG) && defined(WOLFSSL_PUBLIC_MP)
    WC_RNG   rng;
    mp_digit d;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(get_rand_digit(&rng, &d), 0);
    ExpectIntEQ(get_rand_digit(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(get_rand_digit(NULL, &d), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(get_rand_digit(&rng, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* End test_get_rand_digit*/

/*
 * Testing get_digit_count
 */
static int test_get_digit_count(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_SP_MATH) && defined(WOLFSSL_PUBLIC_MP)
    mp_int a;

    XMEMSET(&a, 0, sizeof(mp_int));

    ExpectIntEQ(mp_init(&a), 0);

    ExpectIntEQ(get_digit_count(NULL), 0);
    ExpectIntEQ(get_digit_count(&a), 0);

    mp_clear(&a);
#endif
    return EXPECT_RESULT();
} /* End test_get_digit_count*/

/*
 * Testing mp_cond_copy
 */
static int test_mp_cond_copy(void)
{
    EXPECT_DECLS;
#if (defined(HAVE_ECC) || defined(WOLFSSL_MP_COND_COPY)) && \
    defined(WOLFSSL_PUBLIC_MP)
    mp_int a;
    mp_int b;
    int    copy = 0;

    XMEMSET(&a, 0, sizeof(mp_int));
    XMEMSET(&b, 0, sizeof(mp_int));

    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);

    ExpectIntEQ(mp_cond_copy(NULL, copy, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_cond_copy(NULL, copy, &b), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_cond_copy(&a, copy, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_cond_copy(&a, copy, &b), 0);

    mp_clear(&a);
    mp_clear(&b);
#endif
    return EXPECT_RESULT();
} /* End test_mp_cond_copy*/

/*
 * Testing mp_rand
 */
static int test_mp_rand(void)
{
    EXPECT_DECLS;
#if defined(WC_RSA_BLINDING) && defined(WOLFSSL_PUBLIC_MP)
    mp_int a;
    WC_RNG rng;
    int    digits = 1;

    XMEMSET(&a, 0, sizeof(mp_int));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(mp_rand(&a, digits, NULL), WC_NO_ERR_TRACE(MISSING_RNG_E));
    ExpectIntEQ(mp_rand(NULL, digits, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_rand(&a, 0, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_rand(&a, digits, &rng), 0);

    mp_clear(&a);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* End test_mp_rand*/

/*
 * Testing get_digit
 */
static int test_get_digit(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_PUBLIC_MP)
    mp_int a;
    int    n = 0;

    XMEMSET(&a, 0, sizeof(mp_int));

    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(get_digit(NULL, n), 0);
    ExpectIntEQ(get_digit(&a, n), 0);

    mp_clear(&a);
#endif
    return EXPECT_RESULT();
} /* End test_get_digit*/

/*
 * Testing wc_export_int
 */
static int test_wc_export_int(void)
{
    EXPECT_DECLS;
#if (defined(HAVE_ECC) || defined(WOLFSSL_EXPORT_INT)) && \
    defined(WOLFSSL_PUBLIC_MP)
    mp_int mp;
    byte   buf[32];
    word32 keySz = (word32)sizeof(buf);
    word32 len = (word32)sizeof(buf);

    XMEMSET(&mp, 0, sizeof(mp_int));

    ExpectIntEQ(mp_init(&mp), MP_OKAY);
    ExpectIntEQ(mp_set(&mp, 1234), 0);

    ExpectIntEQ(wc_export_int(NULL, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    len = sizeof(buf)-1;
    ExpectIntEQ(wc_export_int(&mp, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN),
        WC_NO_ERR_TRACE(BUFFER_E));
    len = sizeof(buf);
    ExpectIntEQ(wc_export_int(&mp, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN), 0);
    len = 4; /* test input too small */
    ExpectIntEQ(wc_export_int(&mp, buf, &len, 0, WC_TYPE_HEX_STR), WC_NO_ERR_TRACE(BUFFER_E));
    len = sizeof(buf);
    ExpectIntEQ(wc_export_int(&mp, buf, &len, 0, WC_TYPE_HEX_STR), 0);
    /* hex version of 1234 is 04D2 and should be 4 digits + 1 null */
    ExpectIntEQ(len, 5);

    mp_clear(&mp);
#endif
    return EXPECT_RESULT();

} /* End test_wc_export_int*/

static int test_wc_InitRngNonce(void)
{
    EXPECT_DECLS;
#if !defined(WC_NO_RNG) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
     HAVE_FIPS_VERSION >= 2))
    WC_RNG rng;
    byte   nonce[] = "\x0D\x74\xDB\x42\xA9\x10\x77\xDE"
                     "\x45\xAC\x13\x7A\xE1\x48\xAF\x16";
    word32 nonceSz = sizeof(nonce);

    ExpectIntEQ(wc_InitRngNonce(&rng, nonce, nonceSz), 0);
    ExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* End test_wc_InitRngNonce*/

/*
 * Testing wc_InitRngNonce_ex
 */
static int test_wc_InitRngNonce_ex(void)
{
    EXPECT_DECLS;
#if !defined(WC_NO_RNG) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
     HAVE_FIPS_VERSION >= 2))
    WC_RNG rng;
    byte   nonce[] = "\x0D\x74\xDB\x42\xA9\x10\x77\xDE"
                     "\x45\xAC\x13\x7A\xE1\x48\xAF\x16";
    word32 nonceSz = sizeof(nonce);

    ExpectIntEQ(wc_InitRngNonce_ex(&rng, nonce, nonceSz, HEAP_HINT, testDevId),
        0);
    ExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* End test_wc_InitRngNonce_ex */



static int test_wolfSSL_X509_CRL(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL)
    X509_CRL *crl = NULL;
    char pem[][100] = {
        "./certs/crl/crl.pem",
        "./certs/crl/crl2.pem",
        "./certs/crl/caEccCrl.pem",
        "./certs/crl/eccCliCRL.pem",
        "./certs/crl/eccSrvCRL.pem",
        ""
    };
#ifndef NO_BIO
    BIO *bio = NULL;
#endif

#ifdef HAVE_TEST_d2i_X509_CRL_fp
    char der[][100] = {
        "./certs/crl/crl.der",
        "./certs/crl/crl2.der",
        ""};
#endif

    XFILE fp = XBADFILE;
    int i;

    for (i = 0; pem[i][0] != '\0'; i++)
    {
        ExpectTrue((fp = XFOPEN(pem[i], "rb")) != XBADFILE);
        ExpectNotNull(crl = (X509_CRL *)PEM_read_X509_CRL(fp, (X509_CRL **)NULL,
            NULL, NULL));
        ExpectNotNull(crl);
        X509_CRL_free(crl);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }
        ExpectTrue((fp = XFOPEN(pem[i], "rb")) != XBADFILE);
        ExpectNotNull((X509_CRL *)PEM_read_X509_CRL(fp, (X509_CRL **)&crl, NULL,
            NULL));
        if (EXPECT_FAIL()) {
            crl = NULL;
        }
        ExpectNotNull(crl);
        X509_CRL_free(crl);
        crl = NULL;
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }
    }

#ifndef NO_BIO
    for (i = 0; pem[i][0] != '\0'; i++)
    {
        ExpectNotNull(bio = BIO_new_file(pem[i], "rb"));
        ExpectNotNull(crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL));
        X509_CRL_free(crl);
        crl = NULL;
        BIO_free(bio);
        bio = NULL;
    }
#endif

#ifdef HAVE_TEST_d2i_X509_CRL_fp
    for (i = 0; der[i][0] != '\0'; i++) {
        ExpectTrue((fp = XFOPEN(der[i], "rb")) != XBADFILE);
        ExpectTrue((fp != XBADFILE));
        ExpectNotNull(crl = (X509_CRL *)d2i_X509_CRL_fp((fp, X509_CRL **)NULL));
        ExpectNotNull(crl);
        X509_CRL_free(crl);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }
        fp = XFOPEN(der[i], "rb");
        ExpectTrue((fp != XBADFILE));
        ExpectNotNull((X509_CRL *)d2i_X509_CRL_fp(fp, (X509_CRL **)&crl));
        if (EXPECT_FAIL()) {
            crl = NULL;
        }
        ExpectNotNull(crl);
        X509_CRL_free(crl);
        crl = NULL;
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }
    }
#endif
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_load_crl_file(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM) && !defined(NO_RSA) && !defined(NO_BIO) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
    int i;
    char pem[][100] = {
        "./certs/crl/crl.pem",
        "./certs/crl/crl2.pem",
        "./certs/crl/caEccCrl.pem",
        "./certs/crl/eccCliCRL.pem",
        "./certs/crl/eccSrvCRL.pem",
    #ifdef WC_RSA_PSS
        "./certs/crl/crl_rsapss.pem",
    #endif
        ""
    };
    char der[][100] = {
        "./certs/crl/crl.der",
        "./certs/crl/crl2.der",
        ""
    };
    WOLFSSL_X509_STORE*  store = NULL;
    WOLFSSL_X509_LOOKUP* lookup = NULL;

    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectNotNull(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()));

    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/ca-cert.pem",
        X509_FILETYPE_PEM), 1);
#ifdef WC_RSA_PSS
    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/rsapss/ca-rsapss.pem",
        X509_FILETYPE_PEM), 1);
#endif
    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/server-revoked-cert.pem",
        X509_FILETYPE_PEM), 1);
    if (store) {
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm, svrCertFile,
            WOLFSSL_FILETYPE_PEM), 1);
        /* since store hasn't yet known the revoked cert*/
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm,
            "certs/server-revoked-cert.pem", WOLFSSL_FILETYPE_PEM), 1);
    }

    ExpectIntEQ(X509_load_crl_file(lookup, pem[0], 0), 0);
    for (i = 0; pem[i][0] != '\0'; i++) {
        ExpectIntEQ(X509_load_crl_file(lookup, pem[i], WOLFSSL_FILETYPE_PEM),
            1);
    }

    if (store) {
        /* since store knows crl list */
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm,
            "certs/server-revoked-cert.pem", WOLFSSL_FILETYPE_PEM),
            WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
#ifdef WC_RSA_PSS
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm,
            "certs/rsapss/server-rsapss-cert.pem", WOLFSSL_FILETYPE_PEM),
            WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));
#endif
    }
    /* once feeing store */
    X509_STORE_free(store);
    store = NULL;

    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectNotNull(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()));

    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/ca-cert.pem",
        X509_FILETYPE_PEM), 1);
    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/server-revoked-cert.pem",
        X509_FILETYPE_PEM), 1);
    if (store) {
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm, svrCertFile,
            WOLFSSL_FILETYPE_PEM), 1);
        /* since store hasn't yet known the revoked cert*/
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm,
            "certs/server-revoked-cert.pem", WOLFSSL_FILETYPE_PEM), 1);
    }

    for (i = 0; der[i][0] != '\0'; i++) {
        ExpectIntEQ(X509_load_crl_file(lookup, der[i], WOLFSSL_FILETYPE_ASN1),
            1);
    }

    if (store) {
        /* since store knows crl list */
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm,
            "certs/server-revoked-cert.pem", WOLFSSL_FILETYPE_PEM),
            WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
    }

    /* test for incorrect parameter */
    ExpectIntEQ(X509_load_crl_file(NULL, pem[0], 0), 0);
    ExpectIntEQ(X509_load_crl_file(lookup, NULL, 0), 0);
    ExpectIntEQ(X509_load_crl_file(NULL, NULL, 0), 0);

    X509_STORE_free(store);
    store = NULL;
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_i2d_X509(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(USE_CERT_BUFFERS_2048) && !defined(NO_RSA)
    const unsigned char* cert_buf = server_cert_der_2048;
    unsigned char* out = NULL;
    unsigned char* tmp = NULL;
    const unsigned char* nullPtr = NULL;
    const unsigned char notCert[2] = { 0x30, 0x00 };
    const unsigned char* notCertPtr = notCert;
    X509* cert = NULL;

    ExpectNull(d2i_X509(NULL, NULL, sizeof_server_cert_der_2048));
    ExpectNull(d2i_X509(NULL, &nullPtr, sizeof_server_cert_der_2048));
    ExpectNull(d2i_X509(NULL, &cert_buf, 0));
    ExpectNull(d2i_X509(NULL, &notCertPtr, sizeof(notCert)));
    ExpectNotNull(d2i_X509(&cert, &cert_buf, sizeof_server_cert_der_2048));
    /* Pointer should be advanced */
    ExpectPtrGT(cert_buf, server_cert_der_2048);
    ExpectIntGT(i2d_X509(cert, &out), 0);
    ExpectNotNull(out);
    tmp = out;
    ExpectIntGT(i2d_X509(cert, &tmp), 0);
    ExpectPtrGT(tmp, out);
#if defined(WOLFSSL_CERT_GEN) && !defined(NO_BIO) && !defined(NO_FILESYSTEM)
    ExpectIntEQ(wolfSSL_PEM_write_X509(XBADFILE, NULL), 0);
    ExpectIntEQ(wolfSSL_PEM_write_X509(XBADFILE, cert), 0);
    ExpectIntEQ(wolfSSL_PEM_write_X509(stderr, cert), 1);
#endif

    XFREE(out, NULL, DYNAMIC_TYPE_OPENSSL);
    X509_free(cert);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_d2i_X509_REQ(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CERT_REQ) && !defined(NO_RSA) && !defined(NO_BIO) && \
    (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && \
    !defined(WOLFSSL_SP_MATH)
    /* ./certs/csr.signed.der, ./certs/csr.ext.der, and ./certs/csr.attr.der
     * were generated by libest
     * ./certs/csr.attr.der contains sample attributes
     * ./certs/csr.ext.der contains sample extensions */
    const char* csrFile = "./certs/csr.signed.der";
    const char* csrPopFile = "./certs/csr.attr.der";
    const char* csrExtFile = "./certs/csr.ext.der";
    /* ./certs/csr.dsa.pem is generated using
     * openssl req -newkey dsa:certs/dsaparams.pem \
     *     -keyout certs/csr.dsa.key.pem -keyform PEM -out certs/csr.dsa.pem \
     *     -outform PEM
     * with the passphrase "wolfSSL"
     */
#if !defined(NO_DSA) && !defined(HAVE_SELFTEST)
    const char* csrDsaFile = "./certs/csr.dsa.pem";
    XFILE f = XBADFILE;
#endif
    BIO* bio = NULL;
    X509* req = NULL;
    EVP_PKEY *pub_key = NULL;

    {
        ExpectNotNull(bio = BIO_new_file(csrFile, "rb"));
        ExpectNotNull(d2i_X509_REQ_bio(bio, &req));

        /*
         * Extract the public key from the CSR
         */
        ExpectNotNull(pub_key = X509_REQ_get_pubkey(req));

        /*
         * Verify the signature in the CSR
         */
        ExpectIntEQ(X509_REQ_verify(req, pub_key), 1);

        X509_free(req);
        req = NULL;
        BIO_free(bio);
        bio = NULL;
        EVP_PKEY_free(pub_key);
        pub_key = NULL;
    }
    {
        X509_REQ* empty = NULL;
#ifdef OPENSSL_ALL
        X509_ATTRIBUTE* attr = NULL;
        ASN1_TYPE *at = NULL;
#endif

        ExpectNotNull(empty = wolfSSL_X509_REQ_new());
        ExpectNotNull(bio = BIO_new_file(csrPopFile, "rb"));
        ExpectNotNull(d2i_X509_REQ_bio(bio, &req));

        /*
         * Extract the public key from the CSR
         */
        ExpectNotNull(pub_key = X509_REQ_get_pubkey(req));

        /*
         * Verify the signature in the CSR
         */
        ExpectIntEQ(X509_REQ_verify(req, pub_key), 1);

        ExpectIntEQ(wolfSSL_X509_REQ_get_attr_count(NULL), 0);
        ExpectIntEQ(wolfSSL_X509_REQ_get_attr_count(empty), 0);
#ifdef OPENSSL_ALL
        ExpectIntEQ(wolfSSL_X509_REQ_get_attr_count(req), 2);
#else
        ExpectIntEQ(wolfSSL_X509_REQ_get_attr_count(req), 0);
#endif
#ifdef OPENSSL_ALL
        /*
         * Obtain the challenge password from the CSR
         */
        ExpectIntEQ(X509_REQ_get_attr_by_NID(NULL, NID_pkcs9_challengePassword,
            -1), -1);
        ExpectIntEQ(X509_REQ_get_attr_by_NID(req, NID_pkcs9_challengePassword,
            -1), 1);
        ExpectNull(X509_REQ_get_attr(NULL, 3));
        ExpectNull(X509_REQ_get_attr(req, 3));
        ExpectNull(X509_REQ_get_attr(NULL, 0));
        ExpectNull(X509_REQ_get_attr(empty, 0));
        ExpectNotNull(attr = X509_REQ_get_attr(req, 1));
        ExpectNull(X509_ATTRIBUTE_get0_type(NULL, 1));
        ExpectNull(X509_ATTRIBUTE_get0_type(attr, 1));
        ExpectNull(X509_ATTRIBUTE_get0_type(NULL, 0));
        ExpectNotNull(at = X509_ATTRIBUTE_get0_type(attr, 0));
        ExpectNotNull(at->value.asn1_string);
        ExpectStrEQ((char*)ASN1_STRING_data(at->value.asn1_string),
            "2xIE+qqp/rhyTXP+");
        ExpectIntEQ(X509_get_ext_by_NID(req, NID_subject_alt_name, -1), -1);
#endif

        X509_free(req);
        req = NULL;
        BIO_free(bio);
        bio = NULL;
        EVP_PKEY_free(pub_key);
        pub_key = NULL;
        wolfSSL_X509_REQ_free(empty);
    }
    {
#ifdef OPENSSL_ALL
        X509_ATTRIBUTE* attr = NULL;
        ASN1_TYPE *at = NULL;
        STACK_OF(X509_EXTENSION) *exts = NULL;
#endif
        ExpectNotNull(bio = BIO_new_file(csrExtFile, "rb"));
        /* This CSR contains an Extension Request attribute so
         * we test extension parsing in a CSR attribute here. */
        ExpectNotNull(d2i_X509_REQ_bio(bio, &req));

        /*
         * Extract the public key from the CSR
         */
        ExpectNotNull(pub_key = X509_REQ_get_pubkey(req));

        /*
         * Verify the signature in the CSR
         */
        ExpectIntEQ(X509_REQ_verify(req, pub_key), 1);

#ifdef OPENSSL_ALL
        ExpectNotNull(exts = (STACK_OF(X509_EXTENSION)*)X509_REQ_get_extensions(
            req));
        ExpectIntEQ(sk_X509_EXTENSION_num(exts), 2);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        /*
         * Obtain the challenge password from the CSR
         */
        ExpectIntEQ(X509_REQ_get_attr_by_NID(req, NID_pkcs9_challengePassword,
            -1), 0);
        ExpectNotNull(attr = X509_REQ_get_attr(req, 0));
        ExpectNotNull(at = X509_ATTRIBUTE_get0_type(attr, 0));
        ExpectNotNull(at->value.asn1_string);
        ExpectStrEQ((char*)ASN1_STRING_data(at->value.asn1_string), "IGCu/xNL4/0/wOgo");
        ExpectIntGE(X509_get_ext_by_NID(req, NID_key_usage, -1), 0);
        ExpectIntGE(X509_get_ext_by_NID(req, NID_subject_alt_name, -1), 0);
#endif

        X509_free(req);
        req = NULL;
        BIO_free(bio);
        bio = NULL;
        EVP_PKEY_free(pub_key);
        pub_key = NULL;
    }
#if !defined(NO_DSA) && !defined(HAVE_SELFTEST)
    {
        ExpectNotNull(bio = BIO_new_file(csrDsaFile, "rb"));
        ExpectNotNull(PEM_read_bio_X509_REQ(bio, &req, NULL, NULL));

        /*
         * Extract the public key from the CSR
         */
        ExpectNotNull(pub_key = X509_REQ_get_pubkey(req));

        /*
         * Verify the signature in the CSR
         */
        ExpectIntEQ(X509_REQ_verify(req, pub_key), 1);

        X509_free(req);
        req = NULL;
        BIO_free(bio);

        /* Run the same test, but with a file pointer instead of a BIO.
         * (PEM_read_X509_REQ)*/
        ExpectTrue((f = XFOPEN(csrDsaFile, "rb")) != XBADFILE);
        ExpectNull(PEM_read_X509_REQ(XBADFILE, &req, NULL, NULL));
        if (EXPECT_SUCCESS())
            ExpectNotNull(PEM_read_X509_REQ(f, &req, NULL, NULL));
        else if (f != XBADFILE)
            XFCLOSE(f);
        ExpectIntEQ(X509_REQ_verify(req, pub_key), 1);

        X509_free(req);
        EVP_PKEY_free(pub_key);
    }
#endif /* !NO_DSA && !HAVE_SELFTEST */
#endif /* WOLFSSL_CERT_REQ && (OPENSSL_ALL || OPENSSL_EXTRA) */
    return EXPECT_RESULT();
}

static int test_wolfSSL_PEM_read_X509(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA)
    X509 *x509 = NULL;
    XFILE fp = XBADFILE;

    ExpectTrue((fp = XFOPEN(svrCertFile, "rb")) != XBADFILE);
    ExpectNotNull(x509 = (X509 *)PEM_read_X509(fp, (X509 **)NULL, NULL, NULL));
    X509_free(x509);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_PEM_read(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_BIO)
    const char* filename = "./certs/server-keyEnc.pem";
    XFILE fp = XBADFILE;
    char* name = NULL;
    char* header = NULL;
    byte* data = NULL;
    long len;
    EVP_CIPHER_INFO cipher;
    WOLFSSL_BIO* bio = NULL;
    byte* fileData = NULL;
    size_t fileDataSz = 0;
    byte* out;

    ExpectNotNull(bio = BIO_new_file(filename, "rb"));
    ExpectIntEQ(PEM_read_bio(bio, NULL, &header, &data, &len), 0);
    ExpectIntEQ(PEM_read_bio(bio, &name, NULL, &data, &len), 0);
    ExpectIntEQ(PEM_read_bio(bio, &name, &header, NULL, &len), 0);
    ExpectIntEQ(PEM_read_bio(bio, &name, &header, &data, NULL), 0);

    ExpectIntEQ(PEM_read_bio(bio, &name, &header, &data, &len), 1);
    ExpectIntEQ(XSTRNCMP(name, "RSA PRIVATE KEY", 15), 0);
    ExpectIntGT(XSTRLEN(header), 0);
    ExpectIntGT(len, 0);
    XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    name = NULL;
    XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    header = NULL;
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    data = NULL;
    BIO_free(bio);
    bio = NULL;

    ExpectTrue((fp = XFOPEN(filename, "rb")) != XBADFILE);

    /* Fail cases. */
    ExpectIntEQ(PEM_read(fp, NULL, &header, &data, &len), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_read(fp, &name, NULL, &data, &len), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_read(fp, &name, &header, NULL, &len), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_read(fp, &name, &header, &data, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    ExpectIntEQ(PEM_read(fp, &name, &header, &data, &len), WOLFSSL_SUCCESS);

    ExpectIntEQ(XSTRNCMP(name, "RSA PRIVATE KEY", 15), 0);
    ExpectIntGT(XSTRLEN(header), 0);
    ExpectIntGT(len, 0);

    ExpectIntEQ(XFSEEK(fp, 0, SEEK_END), 0);
    ExpectIntGT((fileDataSz = XFTELL(fp)), 0);
    ExpectIntEQ(XFSEEK(fp, 0, SEEK_SET), 0);
    ExpectNotNull(fileData = (unsigned char*)XMALLOC(fileDataSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(XFREAD(fileData, 1, fileDataSz, fp), fileDataSz);
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));

    /* Fail cases. */
    ExpectIntEQ(PEM_write_bio(NULL, name, header, data, len), 0);
    ExpectIntEQ(PEM_write_bio(bio, NULL, header, data, len), 0);
    ExpectIntEQ(PEM_write_bio(bio, name, NULL, data, len), 0);
    ExpectIntEQ(PEM_write_bio(bio, name, header, NULL, len), 0);

    ExpectIntEQ(PEM_write_bio(bio, name, header, data, len), fileDataSz);
    ExpectIntEQ(wolfSSL_BIO_get_mem_data(bio, &out), fileDataSz);
    ExpectIntEQ(XMEMCMP(out, fileData, fileDataSz), 0);

    /* Fail cases. */
    ExpectIntEQ(PEM_write(XBADFILE, name, header, data, len), 0);
    ExpectIntEQ(PEM_write(stderr, NULL, header, data, len), 0);
    ExpectIntEQ(PEM_write(stderr, name, NULL, data, len), 0);
    ExpectIntEQ(PEM_write(stderr, name, header, NULL, len), 0);
    /* Pass case */
    ExpectIntEQ(PEM_write(stderr, name, header, data, len), fileDataSz);

    XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    name = NULL;
    XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    header = NULL;
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    data = NULL;
    /* Read out of a fixed buffer BIO - forces malloc in PEM_read_bio. */
    ExpectIntEQ(PEM_read_bio(bio, &name, &header, &data, &len), 1);
    ExpectIntEQ(XSTRNCMP(name, "RSA PRIVATE KEY", 15), 0);
    ExpectIntGT(XSTRLEN(header), 0);
    ExpectIntGT(len, 0);

    /* Fail cases. */
    ExpectIntEQ(PEM_get_EVP_CIPHER_INFO(NULL, &cipher), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_get_EVP_CIPHER_INFO(header, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_get_EVP_CIPHER_INFO((char*)"", &cipher), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

#ifndef NO_DES3
    ExpectIntEQ(PEM_get_EVP_CIPHER_INFO(header, &cipher), WOLFSSL_SUCCESS);
#endif

    /* Fail cases. */
    ExpectIntEQ(PEM_do_header(NULL, data, &len, PasswordCallBack,
        (void*)"yassl123"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_do_header(&cipher, NULL, &len, PasswordCallBack,
        (void*)"yassl123"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_do_header(&cipher, data, NULL, PasswordCallBack,
        (void*)"yassl123"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_do_header(&cipher, data, &len, NULL,
        (void*)"yassl123"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    ExpectIntEQ(PEM_do_header(&cipher, data, &len, NoPasswordCallBack,
                              (void*)"yassl123"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#if !defined(NO_DES3) && !defined(NO_MD5)
    ExpectIntEQ(PEM_do_header(&cipher, data, &len, PasswordCallBack,
                              (void*)"yassl123"), WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(PEM_do_header(&cipher, data, &len, PasswordCallBack,
                              (void*)"yassl123"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif

    BIO_free(bio);
    bio = NULL;
    XFREE(fileData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    fileData = NULL;
    XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    name = NULL;
    header = NULL;
    data = NULL;
    ExpectTrue((fp = XFOPEN(svrKeyFile, "rb")) != XBADFILE);
    ExpectIntEQ(PEM_read(fp, &name, &header, &data, &len), WOLFSSL_SUCCESS);
    ExpectIntEQ(XSTRNCMP(name, "RSA PRIVATE KEY", 15), 0);
    ExpectIntEQ(XSTRLEN(header), 0);
    ExpectIntGT(len, 0);

    ExpectIntEQ(XFSEEK(fp, 0, SEEK_END), 0);
    ExpectIntGT((fileDataSz = XFTELL(fp)), 0);
    ExpectIntEQ(XFSEEK(fp, 0, SEEK_SET), 0);
    ExpectNotNull(fileData = (unsigned char*)XMALLOC(fileDataSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(XFREAD(fileData, 1, fileDataSz, fp), fileDataSz);
    if (fp != XBADFILE)
        XFCLOSE(fp);

    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio(bio, name, header, data, len), fileDataSz);
    ExpectIntEQ(wolfSSL_BIO_get_mem_data(bio, &out), fileDataSz);
    ExpectIntEQ(XMEMCMP(out, fileData, fileDataSz), 0);

    BIO_free(bio);
    XFREE(fileData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

static int test_wolfssl_EVP_aes_gcm_AAD_2_parts(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    const byte iv[12] = { 0 };
    const byte key[16] = { 0 };
    const byte cleartext[16] = { 0 };
    const byte aad[] = {
        0x01, 0x10, 0x00, 0x2a, 0x08, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0xdc, 0x4d, 0xad, 0x6b, 0x06, 0x93,
        0x4f
    };
    byte out1Part[16];
    byte outTag1Part[16];
    byte out2Part[16];
    byte outTag2Part[16];
    byte decryptBuf[16];
    int len = 0;
    int tlen;
    EVP_CIPHER_CTX* ctx = NULL;

    /* ENCRYPT */
    /* Send AAD and data in 1 part */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    tlen = 0;
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL),
                1);
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), 1);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad)), 1);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, out1Part, &len, cleartext,
                                  sizeof(cleartext)), 1);
    tlen += len;
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, out1Part, &len), 1);
    tlen += len;
    ExpectIntEQ(tlen, sizeof(cleartext));
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                                    outTag1Part), 1);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* DECRYPT */
    /* Send AAD and data in 1 part */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    tlen = 0;
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL),
                1);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), 1);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad)), 1);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptBuf, &len, out1Part,
                                  sizeof(cleartext)), 1);
    tlen += len;
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                    outTag1Part), 1);
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptBuf, &len), 1);
    tlen += len;
    ExpectIntEQ(tlen, sizeof(cleartext));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    ExpectIntEQ(XMEMCMP(decryptBuf, cleartext, len), 0);

    /* ENCRYPT */
    /* Send AAD and data in 2 parts */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    tlen = 0;
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL),
                1);
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), 1);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, NULL, &len, aad, 1), 1);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, NULL, &len, aad + 1, sizeof(aad) - 1),
                1);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, out2Part, &len, cleartext, 1), 1);
    tlen += len;
    ExpectIntEQ(EVP_EncryptUpdate(ctx, out2Part + tlen, &len, cleartext + 1,
                                  sizeof(cleartext) - 1), 1);
    tlen += len;
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, out2Part + tlen, &len), 1);
    tlen += len;
    ExpectIntEQ(tlen, sizeof(cleartext));
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                                    outTag2Part), 1);

    ExpectIntEQ(XMEMCMP(out1Part, out2Part, sizeof(out1Part)), 0);
    ExpectIntEQ(XMEMCMP(outTag1Part, outTag2Part, sizeof(outTag1Part)), 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* DECRYPT */
    /* Send AAD and data in 2 parts */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    tlen = 0;
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL),
                1);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), 1);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, NULL, &len, aad, 1), 1);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, NULL, &len, aad + 1, sizeof(aad) - 1),
                1);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptBuf, &len, out1Part, 1), 1);
    tlen += len;
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptBuf + tlen, &len, out1Part + 1,
                                  sizeof(cleartext) - 1), 1);
    tlen += len;
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                    outTag1Part), 1);
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptBuf + tlen, &len), 1);
    tlen += len;
    ExpectIntEQ(tlen, sizeof(cleartext));

    ExpectIntEQ(XMEMCMP(decryptBuf, cleartext, len), 0);

    /* Test AAD reuse */
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

static int test_wolfssl_EVP_aes_gcm_zeroLen(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    /* Zero length plain text */
    byte key[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte iv[]  = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte plaintxt[1];
    int ivSz  = 12;
    int plaintxtSz = 0;
    unsigned char tag[16];
    unsigned char tag_kat[] = {
        0x53,0x0f,0x8a,0xfb,0xc7,0x45,0x36,0xb9,
        0xa9,0x63,0xb4,0xf1,0xc4,0xcb,0x73,0x8b
    };

    byte ciphertxt[AES_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[AES_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    ExpectIntEQ(1, EVP_EncryptInit_ex(en, EVP_aes_256_gcm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_EncryptUpdate(en, ciphertxt, &ciphertxtSz , plaintxt,
        plaintxtSz));
    ExpectIntEQ(1, EVP_EncryptFinal_ex(en, ciphertxt, &len));
    ciphertxtSz += len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_GCM_GET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_CIPHER_CTX_cleanup(en));

    ExpectIntEQ(0, ciphertxtSz);
    ExpectIntEQ(0, XMEMCMP(tag, tag_kat, sizeof(tag)));

    EVP_CIPHER_CTX_init(de);
    ExpectIntEQ(1, EVP_DecryptInit_ex(de, EVP_aes_256_gcm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_DecryptUpdate(de, NULL, &len, ciphertxt, len));
    decryptedtxtSz = len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_GCM_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptFinal_ex(de, decryptedtxt, &len));
    decryptedtxtSz += len;
    ExpectIntEQ(0, decryptedtxtSz);

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);
#endif
    return EXPECT_RESULT();
}

static int test_wolfssl_EVP_aes_gcm(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    /* A 256 bit key, AES_128 will use the first 128 bit*/
    byte *key = (byte*)"01234567890123456789012345678901";
    /* A 128 bit IV */
    byte *iv = (byte*)"0123456789012345";
    int ivSz = AES_BLOCK_SIZE;
    /* Message to be encrypted */
    byte *plaintxt = (byte*)"for things to change you have to change";
    /* Additional non-confidential data */
    byte *aad = (byte*)"Don't spend major time on minor things.";

    unsigned char tag[AES_BLOCK_SIZE] = {0};
    int plaintxtSz = (int)XSTRLEN((char*)plaintxt);
    int aadSz = (int)XSTRLEN((char*)aad);
    byte ciphertxt[AES_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[AES_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;
    int i = 0;
    EVP_CIPHER_CTX en[2];
    EVP_CIPHER_CTX de[2];

    for (i = 0; i < 2; i++) {
        EVP_CIPHER_CTX_init(&en[i]);
        if (i == 0) {
            /* Default uses 96-bits IV length */
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_128_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_192_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_256_gcm(), NULL,
                key, iv));
#endif
        }
        else {
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_128_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_192_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_256_gcm(), NULL,
                NULL, NULL));
#endif
             /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
        }
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], ciphertxt, &len, plaintxt,
            plaintxtSz));
        ciphertxtSz = len;
        ExpectIntEQ(1, EVP_EncryptFinal_ex(&en[i], ciphertxt, &len));
        ciphertxtSz += len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_GET_TAG,
            AES_BLOCK_SIZE, tag));
        wolfSSL_EVP_CIPHER_CTX_cleanup(&en[i]);

        EVP_CIPHER_CTX_init(&de[i]);
        if (i == 0) {
            /* Default uses 96-bits IV length */
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_gcm(), NULL,
                key, iv));
#endif
        }
        else {
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_gcm(), NULL,
                NULL, NULL));
#endif
            /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));

        }
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG,
            AES_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        ExpectIntEQ(ciphertxtSz, decryptedtxtSz);
        ExpectIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        /* modify tag*/
        if (i == 0) {
            /* Default uses 96-bits IV length */
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_gcm(), NULL,
                key, iv));
#endif
        }
        else {
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_gcm(), NULL,
                NULL, NULL));
#endif
            /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));

        }
        tag[AES_BLOCK_SIZE-1]+=0xBB;
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG,
            AES_BLOCK_SIZE, tag));
        /* fail due to wrong tag */
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        ExpectIntEQ(0, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        ExpectIntEQ(0, len);

        wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]);
    }
#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AESGCM */
    return EXPECT_RESULT();
}

static int test_wolfssl_EVP_aria_gcm(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ARIA) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)

    /* A 256 bit key, AES_128 will use the first 128 bit*/
    byte *key = (byte*)"01234567890123456789012345678901";
    /* A 128 bit IV */
    byte *iv = (byte*)"0123456789012345";
    int ivSz = ARIA_BLOCK_SIZE;
    /* Message to be encrypted */
    const int plaintxtSz = 40;
    byte plaintxt[WC_ARIA_GCM_GET_CIPHERTEXT_SIZE(plaintxtSz)];
    XMEMCPY(plaintxt,"for things to change you have to change",plaintxtSz);
    /* Additional non-confidential data */
    byte *aad = (byte*)"Don't spend major time on minor things.";

    unsigned char tag[ARIA_BLOCK_SIZE] = {0};
    int aadSz = (int)XSTRLEN((char*)aad);
    byte ciphertxt[WC_ARIA_GCM_GET_CIPHERTEXT_SIZE(plaintxtSz)];
    byte decryptedtxt[plaintxtSz];
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;
    int i = 0;
    #define TEST_ARIA_GCM_COUNT 6
    EVP_CIPHER_CTX en[TEST_ARIA_GCM_COUNT];
    EVP_CIPHER_CTX de[TEST_ARIA_GCM_COUNT];

    for (i = 0; i < TEST_ARIA_GCM_COUNT; i++) {

        EVP_CIPHER_CTX_init(&en[i]);
        switch (i) {
            case 0:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_128_gcm(), NULL, key, iv));
                break;
            case 1:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_192_gcm(), NULL, key, iv));
                break;
            case 2:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_256_gcm(), NULL, key, iv));
                break;
            case 3:
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_128_gcm(), NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
                break;
            case 4:
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_192_gcm(), NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
                break;
            case 5:
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_256_gcm(), NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
                break;
        }
        XMEMSET(ciphertxt,0,sizeof(ciphertxt));
        AssertIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, aad, aadSz));
        AssertIntEQ(1, EVP_EncryptUpdate(&en[i], ciphertxt, &len, plaintxt, plaintxtSz));
        ciphertxtSz = len;
        AssertIntEQ(1, EVP_EncryptFinal_ex(&en[i], ciphertxt, &len));
        AssertIntNE(0, XMEMCMP(plaintxt, ciphertxt, plaintxtSz));
        ciphertxtSz += len;
        AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_GET_TAG, ARIA_BLOCK_SIZE, tag));
        AssertIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&en[i]), 1);

        EVP_CIPHER_CTX_init(&de[i]);
        switch (i) {
            case 0:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_128_gcm(), NULL, key, iv));
                break;
            case 1:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_192_gcm(), NULL, key, iv));
                break;
            case 2:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_256_gcm(), NULL, key, iv));
                break;
            case 3:
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_128_gcm(), NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));
                break;
            case 4:
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_192_gcm(), NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));
                break;
            case 5:
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_256_gcm(), NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));
                break;
        }
        XMEMSET(decryptedtxt,0,sizeof(decryptedtxt));
        AssertIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        AssertIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt, ciphertxtSz));
        decryptedtxtSz = len;
        AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG, ARIA_BLOCK_SIZE, tag));
        AssertIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        AssertIntEQ(plaintxtSz, decryptedtxtSz);
        AssertIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        XMEMSET(decryptedtxt,0,sizeof(decryptedtxt));
        /* modify tag*/
        tag[AES_BLOCK_SIZE-1]+=0xBB;
        AssertIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG, ARIA_BLOCK_SIZE, tag));
        /* fail due to wrong tag */
        AssertIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt, ciphertxtSz));
        AssertIntEQ(0, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        AssertIntEQ(0, len);
        AssertIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]), 1);
    }

    res = TEST_RES_CHECK(1);
#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AESGCM */
    return res;
}

static int test_wolfssl_EVP_aes_ccm_zeroLen(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESCCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    /* Zero length plain text */
    byte key[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte iv[]  = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte plaintxt[1];
    int ivSz  = 12;
    int plaintxtSz = 0;
    unsigned char tag[16];

    byte ciphertxt[AES_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[AES_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    ExpectIntEQ(1, EVP_EncryptInit_ex(en, EVP_aes_256_ccm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_EncryptUpdate(en, ciphertxt, &ciphertxtSz , plaintxt,
                                     plaintxtSz));
    ExpectIntEQ(1, EVP_EncryptFinal_ex(en, ciphertxt, &len));
    ciphertxtSz += len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_GET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_CIPHER_CTX_cleanup(en));

    ExpectIntEQ(0, ciphertxtSz);

    EVP_CIPHER_CTX_init(de);
    ExpectIntEQ(1, EVP_DecryptInit_ex(de, EVP_aes_256_ccm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_DecryptUpdate(de, NULL, &len, ciphertxt, len));
    decryptedtxtSz = len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptFinal_ex(de, decryptedtxt, &len));
    decryptedtxtSz += len;
    ExpectIntEQ(0, decryptedtxtSz);

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);
#endif
    return EXPECT_RESULT();
}

static int test_wolfssl_EVP_aes_ccm(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESCCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    /* A 256 bit key, AES_128 will use the first 128 bit*/
    byte *key = (byte*)"01234567890123456789012345678901";
    /* A 128 bit IV */
    byte *iv = (byte*)"0123456789012";
    int ivSz = (int)XSTRLEN((char*)iv);
    /* Message to be encrypted */
    byte *plaintxt = (byte*)"for things to change you have to change";
    /* Additional non-confidential data */
    byte *aad = (byte*)"Don't spend major time on minor things.";

    unsigned char tag[AES_BLOCK_SIZE] = {0};
    int plaintxtSz = (int)XSTRLEN((char*)plaintxt);
    int aadSz = (int)XSTRLEN((char*)aad);
    byte ciphertxt[AES_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[AES_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;
    int i = 0;
    int ret;
    EVP_CIPHER_CTX en[2];
    EVP_CIPHER_CTX de[2];

    for (i = 0; i < 2; i++) {
        EVP_CIPHER_CTX_init(&en[i]);

        if (i == 0) {
            /* Default uses 96-bits IV length */
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_128_ccm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_192_ccm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_256_ccm(), NULL,
                key, iv));
#endif
        }
        else {
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_128_ccm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_192_ccm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_256_ccm(), NULL,
                NULL, NULL));
#endif
             /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_CCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
        }
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], ciphertxt, &len, plaintxt,
              plaintxtSz));
        ciphertxtSz = len;
        ExpectIntEQ(1, EVP_EncryptFinal_ex(&en[i], ciphertxt, &len));
        ciphertxtSz += len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_CCM_GET_TAG,
            AES_BLOCK_SIZE, tag));
        ret = wolfSSL_EVP_CIPHER_CTX_cleanup(&en[i]);
        ExpectIntEQ(ret, 1);

        EVP_CIPHER_CTX_init(&de[i]);
        if (i == 0) {
            /* Default uses 96-bits IV length */
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_ccm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_ccm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_ccm(), NULL,
                key, iv));
#endif
        }
        else {
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_ccm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_ccm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_ccm(), NULL,
                NULL, NULL));
#endif
            /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));

        }
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            AES_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        ExpectIntEQ(ciphertxtSz, decryptedtxtSz);
        ExpectIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        /* modify tag*/
        tag[AES_BLOCK_SIZE-1]+=0xBB;
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            AES_BLOCK_SIZE, tag));
        /* fail due to wrong tag */
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        ExpectIntEQ(0, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        ExpectIntEQ(0, len);
        ret = wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]);
        ExpectIntEQ(ret, 1);
    }
#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AESCCM */
    return EXPECT_RESULT();
}

static int test_wolfssl_EVP_chacha20_poly1305(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    byte key[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte iv [CHACHA20_POLY1305_AEAD_IV_SIZE];
    byte plainText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte aad[] = {0xAA, 0XBB, 0xCC, 0xDD, 0xEE, 0xFF};
    byte cipherText[sizeof(plainText)];
    byte decryptedText[sizeof(plainText)];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    EVP_CIPHER_CTX* ctx = NULL;
    int outSz;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));

    /* Encrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL,
                NULL), WOLFSSL_SUCCESS);
    /* Invalid IV length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                CHACHA20_POLY1305_AEAD_IV_SIZE-1, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Valid IV length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                CHACHA20_POLY1305_AEAD_IV_SIZE, NULL), WOLFSSL_SUCCESS);
    /* Invalid tag length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE-1, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Valid tag length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, NULL, &outSz, aad, sizeof(aad)),
               WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(aad));
    ExpectIntEQ(EVP_EncryptUpdate(ctx, cipherText, &outSz, plainText,
                sizeof(plainText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, cipherText, &outSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    /* Invalid tag length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE-1, tag), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Valid tag length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, tag), WOLFSSL_SUCCESS);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Decrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL,
                NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                CHACHA20_POLY1305_AEAD_IV_SIZE, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, tag), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, NULL, &outSz, aad, sizeof(aad)),
               WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(aad));
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
                sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Test partial Inits. CipherInit() allow setting of key and iv
     * in separate calls. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, EVP_chacha20_poly1305(),
                key, NULL, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, NULL, NULL, iv, 1),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, NULL, &outSz,
                aad, sizeof(aad)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(aad));
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
                sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

static int test_wolfssl_EVP_chacha20(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CHACHA)
    byte key[CHACHA_MAX_KEY_SZ];
    byte iv [WOLFSSL_EVP_CHACHA_IV_BYTES];
    byte plainText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte cipherText[sizeof(plainText)];
    byte decryptedText[sizeof(plainText)];
    EVP_CIPHER_CTX* ctx = NULL;
    int outSz;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));
    /* Encrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, NULL,
                NULL), WOLFSSL_SUCCESS);
    /* Any tag length must fail - not an AEAD cipher. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                16, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, cipherText, &outSz, plainText,
                sizeof(plainText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, cipherText, &outSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Decrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, NULL,
                NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
                sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Test partial Inits. CipherInit() allow setting of key and iv
     * in separate calls. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, EVP_chacha20(),
                key, NULL, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, NULL, NULL, iv, 1),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
                sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

static int test_wolfssl_EVP_sm4_ecb(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_ECB)
    EXPECT_DECLS;
    byte key[SM4_KEY_SIZE];
    byte plainText[SM4_BLOCK_SIZE] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
    };
    byte cipherText[sizeof(plainText) + SM4_BLOCK_SIZE];
    byte decryptedText[sizeof(plainText) + SM4_BLOCK_SIZE];
    EVP_CIPHER_CTX* ctx;
    int outSz;

    XMEMSET(key, 0, sizeof(key));

    /* Encrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    /* Any tag length must fail - not an AEAD cipher. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, cipherText, &outSz, plainText,
        sizeof(plainText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, cipherText + outSz, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, SM4_BLOCK_SIZE);
    ExpectBufNE(cipherText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    /* Decrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
        sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText + outSz, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufEQ(decryptedText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    res = EXPECT_RESULT();
#endif
    return res;
}

static int test_wolfssl_EVP_sm4_cbc(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_CBC)
    EXPECT_DECLS;
    byte key[SM4_KEY_SIZE];
    byte iv[SM4_BLOCK_SIZE];
    byte plainText[SM4_BLOCK_SIZE] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
    };
    byte cipherText[sizeof(plainText) + SM4_BLOCK_SIZE];
    byte decryptedText[sizeof(plainText) + SM4_BLOCK_SIZE];
    EVP_CIPHER_CTX* ctx;
    int outSz;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));

    /* Encrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    /* Any tag length must fail - not an AEAD cipher. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, cipherText, &outSz, plainText,
        sizeof(plainText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, cipherText + outSz, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, SM4_BLOCK_SIZE);
    ExpectBufNE(cipherText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    /* Decrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
        sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText + outSz, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufEQ(decryptedText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    /* Test partial Inits. CipherInit() allow setting of key and iv
     * in separate calls. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, EVP_sm4_cbc(), key, NULL, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, NULL, NULL, iv, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
         sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText + outSz, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufEQ(decryptedText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    res = EXPECT_RESULT();
#endif
    return res;
}

static int test_wolfssl_EVP_sm4_ctr(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_CTR)
    EXPECT_DECLS;
    byte key[SM4_KEY_SIZE];
    byte iv[SM4_BLOCK_SIZE];
    byte plainText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte cipherText[sizeof(plainText)];
    byte decryptedText[sizeof(plainText)];
    EVP_CIPHER_CTX* ctx;
    int outSz;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));

    /* Encrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_sm4_ctr(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    /* Any tag length must fail - not an AEAD cipher. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, cipherText, &outSz, plainText,
        sizeof(plainText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, cipherText, &outSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufNE(cipherText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    /* Decrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_sm4_ctr(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
        sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufEQ(decryptedText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    /* Test partial Inits. CipherInit() allow setting of key and iv
     * in separate calls. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, EVP_sm4_ctr(), key, NULL, 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, NULL, NULL, iv, 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
         sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufEQ(decryptedText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    res = EXPECT_RESULT();
#endif
    return res;
}

static int test_wolfssl_EVP_sm4_gcm_zeroLen(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_GCM)
    /* Zero length plain text */
    EXPECT_DECLS;
    byte key[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte iv[]  = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte plaintxt[1];
    int ivSz  = 12;
    int plaintxtSz = 0;
    unsigned char tag[16];
    unsigned char tag_kat[16] = {
        0x23,0x2f,0x0c,0xfe,0x30,0x8b,0x49,0xea,
        0x6f,0xc8,0x82,0x29,0xb5,0xdc,0x85,0x8d
    };

    byte ciphertxt[SM4_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[SM4_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    ExpectIntEQ(1, EVP_EncryptInit_ex(en, EVP_sm4_gcm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_EncryptUpdate(en, ciphertxt, &ciphertxtSz , plaintxt,
        plaintxtSz));
    ExpectIntEQ(1, EVP_EncryptFinal_ex(en, ciphertxt, &len));
    ciphertxtSz += len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_GCM_GET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_CIPHER_CTX_cleanup(en));

    ExpectIntEQ(0, ciphertxtSz);
    ExpectIntEQ(0, XMEMCMP(tag, tag_kat, sizeof(tag)));

    EVP_CIPHER_CTX_init(de);
    ExpectIntEQ(1, EVP_DecryptInit_ex(de, EVP_sm4_gcm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_DecryptUpdate(de, NULL, &len, ciphertxt, len));
    decryptedtxtSz = len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_GCM_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptFinal_ex(de, decryptedtxt, &len));
    decryptedtxtSz += len;
    ExpectIntEQ(0, decryptedtxtSz);

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);

    res = EXPECT_RESULT();
#endif /* OPENSSL_EXTRA && WOLFSSL_SM4_GCM */
    return res;
}

static int test_wolfssl_EVP_sm4_gcm(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_GCM)
    EXPECT_DECLS;
    byte *key = (byte*)"0123456789012345";
    /* A 128 bit IV */
    byte *iv = (byte*)"0123456789012345";
    int ivSz = SM4_BLOCK_SIZE;
    /* Message to be encrypted */
    byte *plaintxt = (byte*)"for things to change you have to change";
    /* Additional non-confidential data */
    byte *aad = (byte*)"Don't spend major time on minor things.";

    unsigned char tag[SM4_BLOCK_SIZE] = {0};
    int plaintxtSz = (int)XSTRLEN((char*)plaintxt);
    int aadSz = (int)XSTRLEN((char*)aad);
    byte ciphertxt[SM4_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[SM4_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;
    int i = 0;
    EVP_CIPHER_CTX en[2];
    EVP_CIPHER_CTX de[2];

    for (i = 0; i < 2; i++) {
        EVP_CIPHER_CTX_init(&en[i]);

        if (i == 0) {
            /* Default uses 96-bits IV length */
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_sm4_gcm(), NULL, key,
                iv));
        }
        else {
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_sm4_gcm(), NULL, NULL,
                NULL));
             /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
        }
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], ciphertxt, &len, plaintxt,
            plaintxtSz));
        ciphertxtSz = len;
        ExpectIntEQ(1, EVP_EncryptFinal_ex(&en[i], ciphertxt, &len));
        ciphertxtSz += len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_GET_TAG,
            SM4_BLOCK_SIZE, tag));
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&en[i]), 1);

        EVP_CIPHER_CTX_init(&de[i]);
        if (i == 0) {
            /* Default uses 96-bits IV length */
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_sm4_gcm(), NULL, key,
                iv));
        }
        else {
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_sm4_gcm(), NULL, NULL,
                NULL));
            /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));

        }
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG,
            SM4_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        ExpectIntEQ(ciphertxtSz, decryptedtxtSz);
        ExpectIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        /* modify tag*/
        tag[SM4_BLOCK_SIZE-1]+=0xBB;
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG,
            SM4_BLOCK_SIZE, tag));
        /* fail due to wrong tag */
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        ExpectIntEQ(0, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        ExpectIntEQ(0, len);
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]), 1);
    }

    res = EXPECT_RESULT();
#endif /* OPENSSL_EXTRA && WOLFSSL_SM4_GCM */
    return res;
}

static int test_wolfssl_EVP_sm4_ccm_zeroLen(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_CCM)
    /* Zero length plain text */
    EXPECT_DECLS;
    byte key[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte iv[]  = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte plaintxt[1];
    int ivSz  = 12;
    int plaintxtSz = 0;
    unsigned char tag[16];

    byte ciphertxt[SM4_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[SM4_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    ExpectIntEQ(1, EVP_EncryptInit_ex(en, EVP_sm4_ccm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_EncryptUpdate(en, ciphertxt, &ciphertxtSz , plaintxt,
                                     plaintxtSz));
    ExpectIntEQ(1, EVP_EncryptFinal_ex(en, ciphertxt, &len));
    ciphertxtSz += len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_GET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_CIPHER_CTX_cleanup(en));

    ExpectIntEQ(0, ciphertxtSz);

    EVP_CIPHER_CTX_init(de);
    ExpectIntEQ(1, EVP_DecryptInit_ex(de, EVP_sm4_ccm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_DecryptUpdate(de, NULL, &len, ciphertxt, len));
    decryptedtxtSz = len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptFinal_ex(de, decryptedtxt, &len));
    decryptedtxtSz += len;
    ExpectIntEQ(0, decryptedtxtSz);

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);

    res = EXPECT_RESULT();
#endif /* OPENSSL_EXTRA && WOLFSSL_SM4_CCM */
    return res;
}

static int test_wolfssl_EVP_sm4_ccm(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_CCM)
    EXPECT_DECLS;
    byte *key = (byte*)"0123456789012345";
    byte *iv = (byte*)"0123456789012";
    int ivSz = (int)XSTRLEN((char*)iv);
    /* Message to be encrypted */
    byte *plaintxt = (byte*)"for things to change you have to change";
    /* Additional non-confidential data */
    byte *aad = (byte*)"Don't spend major time on minor things.";

    unsigned char tag[SM4_BLOCK_SIZE] = {0};
    int plaintxtSz = (int)XSTRLEN((char*)plaintxt);
    int aadSz = (int)XSTRLEN((char*)aad);
    byte ciphertxt[SM4_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[SM4_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;
    int i = 0;
    EVP_CIPHER_CTX en[2];
    EVP_CIPHER_CTX de[2];

    for (i = 0; i < 2; i++) {
        EVP_CIPHER_CTX_init(&en[i]);

        if (i == 0) {
            /* Default uses 96-bits IV length */
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_sm4_ccm(), NULL, key,
                iv));
        }
        else {
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_sm4_ccm(), NULL, NULL,
                NULL));
             /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_CCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
        }
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], ciphertxt, &len, plaintxt,
            plaintxtSz));
        ciphertxtSz = len;
        ExpectIntEQ(1, EVP_EncryptFinal_ex(&en[i], ciphertxt, &len));
        ciphertxtSz += len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_CCM_GET_TAG,
            SM4_BLOCK_SIZE, tag));
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&en[i]), 1);

        EVP_CIPHER_CTX_init(&de[i]);
        if (i == 0) {
            /* Default uses 96-bits IV length */
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_sm4_ccm(), NULL, key,
                iv));
        }
        else {
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_sm4_ccm(), NULL, NULL,
                NULL));
            /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));

        }
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            SM4_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        ExpectIntEQ(ciphertxtSz, decryptedtxtSz);
        ExpectIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        /* modify tag*/
        tag[SM4_BLOCK_SIZE-1]+=0xBB;
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            SM4_BLOCK_SIZE, tag));
        /* fail due to wrong tag */
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        ExpectIntEQ(0, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        ExpectIntEQ(0, len);
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]), 1);
    }

    res = EXPECT_RESULT();
#endif /* OPENSSL_EXTRA && WOLFSSL_SM4_CCM */
    return res;
}

static int test_wolfSSL_EVP_PKEY_hkdf(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_HKDF)
    EVP_PKEY_CTX* ctx = NULL;
    byte salt[]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    byte key[]   = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    byte info[]  = {0X01, 0x02, 0x03, 0x04, 0x05};
    byte info2[] = {0X06, 0x07, 0x08, 0x09, 0x0A};
    byte outKey[34];
    size_t outKeySz = sizeof(outKey);
    /* These expected outputs were gathered by running the same test below using
     * OpenSSL. */
    const byte extractAndExpand[] = {
        0x8B, 0xEB, 0x90, 0xA9, 0x04, 0xFF, 0x05, 0x10, 0xE4, 0xB5, 0xB1, 0x10,
        0x31, 0x34, 0xFF, 0x07, 0x5B, 0xE3, 0xC6, 0x93, 0xD4, 0xF8, 0xC7, 0xEE,
        0x96, 0xDA, 0x78, 0x7A, 0xE2, 0x9A, 0x2D, 0x05, 0x4B, 0xF6
    };
    const byte extractOnly[] = {
        0xE7, 0x6B, 0x9E, 0x0F, 0xE4, 0x02, 0x1D, 0x62, 0xEA, 0x97, 0x74, 0x5E,
        0xF4, 0x3C, 0x65, 0x4D, 0xC1, 0x46, 0x98, 0xAA, 0x79, 0x9A, 0xCB, 0x9C,
        0xCC, 0x3E, 0x7F, 0x2A, 0x2B, 0x41, 0xA1, 0x9E
    };
    const byte expandOnly[] = {
        0xFF, 0x29, 0x29, 0x56, 0x9E, 0xA7, 0x66, 0x02, 0xDB, 0x4F, 0xDB, 0x53,
        0x7D, 0x21, 0x67, 0x52, 0xC3, 0x0E, 0xF3, 0xFC, 0x71, 0xCE, 0x67, 0x2B,
        0xEA, 0x3B, 0xE9, 0xFC, 0xDD, 0xC8, 0xCC, 0xB7, 0x42, 0x74
    };
    const byte extractAndExpandAddInfo[] = {
        0x5A, 0x74, 0x79, 0x83, 0xA3, 0xA4, 0x2E, 0xB7, 0xD4, 0x08, 0xC2, 0x6A,
        0x2F, 0xA5, 0xE3, 0x4E, 0xF1, 0xF4, 0x87, 0x3E, 0xA6, 0xC7, 0x88, 0x45,
        0xD7, 0xE2, 0x15, 0xBC, 0xB8, 0x10, 0xEF, 0x6C, 0x4D, 0x7A
    };

    ExpectNotNull((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)));
    ExpectIntEQ(EVP_PKEY_derive_init(ctx), WOLFSSL_SUCCESS);
    /* NULL ctx. */
    ExpectIntEQ(EVP_PKEY_CTX_set_hkdf_md(NULL, EVP_sha256()), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* NULL md. */
    ExpectIntEQ(EVP_PKEY_CTX_set_hkdf_md(ctx, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()), WOLFSSL_SUCCESS);
    /* NULL ctx. */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_salt(NULL, salt, sizeof(salt)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* NULL salt is ok. */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_salt(ctx, NULL, sizeof(salt)),
                WOLFSSL_SUCCESS);
    /* Salt length <= 0. */
    /* Length 0 salt is ok. */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, -1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)),
                WOLFSSL_SUCCESS);
    /* NULL ctx. */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_key(NULL, key, sizeof(key)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* NULL key. */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_key(ctx, NULL, sizeof(key)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Key length <= 0 */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_key(ctx, key, 0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_key(ctx, key, -1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_key(ctx, key, sizeof(key)),
                WOLFSSL_SUCCESS);
    /* NULL ctx. */
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(NULL, info, sizeof(info)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* NULL info is ok. */
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(ctx, NULL, sizeof(info)),
                WOLFSSL_SUCCESS);
    /* Info length <= 0 */
    /* Length 0 info is ok. */
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(ctx, info, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(ctx, info, -1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info)),
                WOLFSSL_SUCCESS);
    /* NULL ctx. */
    ExpectIntEQ(EVP_PKEY_CTX_hkdf_mode(NULL, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Extract and expand (default). */
    ExpectIntEQ(EVP_PKEY_derive(ctx, outKey, &outKeySz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outKeySz, sizeof(extractAndExpand));
    ExpectIntEQ(XMEMCMP(outKey, extractAndExpand, outKeySz), 0);
    /* Extract only. */
    ExpectIntEQ(EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_derive(ctx, outKey, &outKeySz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outKeySz, sizeof(extractOnly));
    ExpectIntEQ(XMEMCMP(outKey, extractOnly, outKeySz), 0);
    outKeySz = sizeof(outKey);
    /* Expand only. */
    ExpectIntEQ(EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_derive(ctx, outKey, &outKeySz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outKeySz, sizeof(expandOnly));
    ExpectIntEQ(XMEMCMP(outKey, expandOnly, outKeySz), 0);
    outKeySz = sizeof(outKey);
    /* Extract and expand with appended additional info. */
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(ctx, info2, sizeof(info2)),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_hkdf_mode(ctx,
                EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_derive(ctx, outKey, &outKeySz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outKeySz, sizeof(extractAndExpandAddInfo));
    ExpectIntEQ(XMEMCMP(outKey, extractAndExpandAddInfo, outKeySz), 0);

    EVP_PKEY_CTX_free(ctx);
#endif /* OPENSSL_EXTRA && HAVE_HKDF */
    return EXPECT_RESULT();
}

#ifndef NO_BIO
static int test_wolfSSL_PEM_X509_INFO_read_bio(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    BIO* bio = NULL;
    X509_INFO* info = NULL;
    STACK_OF(X509_INFO)* sk = NULL;
    STACK_OF(X509_INFO)* sk2 = NULL;
    char* subject = NULL;
    char exp1[] = "/C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting/"
                  "CN=www.wolfssl.com/emailAddress=info@wolfssl.com";
    char exp2[] = "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support/"
                  "CN=www.wolfssl.com/emailAddress=info@wolfssl.com";

    ExpectNotNull(bio = BIO_new(BIO_s_file()));
    ExpectIntGT(BIO_read_filename(bio, svrCertFile), 0);
    ExpectNotNull(sk = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL));
    ExpectIntEQ(sk_X509_INFO_num(sk), 2);

    /* using dereference to maintain testing for Apache port*/
    ExpectNull(sk_X509_INFO_pop(NULL));
    ExpectNotNull(info = sk_X509_INFO_pop(sk));
    ExpectNotNull(subject = X509_NAME_oneline(X509_get_subject_name(info->x509),
        0, 0));

    ExpectIntEQ(0, XSTRNCMP(subject, exp1, sizeof(exp1)));
    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
    subject = NULL;
    X509_INFO_free(info);
    info = NULL;

    ExpectNotNull(info = sk_X509_INFO_pop(sk));
    ExpectNotNull(subject = X509_NAME_oneline(X509_get_subject_name(info->x509),
        0, 0));

    ExpectIntEQ(0, XSTRNCMP(subject, exp2, sizeof(exp2)));
    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
    subject = NULL;
    X509_INFO_free(info);
    ExpectNull(info = sk_X509_INFO_pop(sk));

    sk_X509_INFO_pop_free(sk, X509_INFO_free);
    sk = NULL;
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(sk = wolfSSL_sk_X509_INFO_new_null());
    ExpectNotNull(bio = BIO_new(BIO_s_file()));
    ExpectIntGT(BIO_read_filename(bio, svrCertFile), 0);
    ExpectNotNull(sk2 = PEM_X509_INFO_read_bio(bio, sk, NULL, NULL));
    ExpectPtrEq(sk, sk2);
    if (sk2 != sk) {
        sk_X509_INFO_pop_free(sk, X509_INFO_free);
    }
    sk = NULL;
    BIO_free(bio);
    sk_X509_INFO_pop_free(sk2, X509_INFO_free);

    ExpectNotNull(sk = wolfSSL_sk_X509_INFO_new_null());
    sk_X509_INFO_free(sk);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_PEM_X509_INFO_read(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    XFILE fp = XBADFILE;
    STACK_OF(X509_INFO)* sk = NULL;

    ExpectTrue((fp = XFOPEN(svrCertFile, "rb")) != XBADFILE);
    ExpectNull(wolfSSL_PEM_X509_INFO_read(XBADFILE, NULL, NULL, NULL));
    ExpectNotNull(sk = wolfSSL_PEM_X509_INFO_read(fp, NULL, NULL, NULL));

    sk_X509_INFO_pop_free(sk, X509_INFO_free);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif
    return EXPECT_RESULT();
}
#endif /* !NO_BIO */

static int test_wolfSSL_X509_NAME_ENTRY_get_object(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509 *x509 = NULL;
    X509_NAME* name = NULL;
    int idx = 0;
    X509_NAME_ENTRY *ne = NULL;
    ASN1_OBJECT *object = NULL;

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(cliCertFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = X509_get_subject_name(x509));
    ExpectIntGE(X509_NAME_get_index_by_NID(NULL, NID_commonName, -1),
        BAD_FUNC_ARG);
    ExpectIntGE(idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1), 0);
    ExpectIntGE(idx = X509_NAME_get_index_by_NID(name, NID_commonName, -2), 0);

    ExpectNotNull(ne = X509_NAME_get_entry(name, idx));
    ExpectNull(X509_NAME_ENTRY_get_object(NULL));
    ExpectNotNull(object = X509_NAME_ENTRY_get_object(ne));

    X509_free(x509);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_get1_certs(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SIGNER_DER_CERT) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509_STORE_CTX *storeCtx = NULL;
    X509_STORE *store = NULL;
    X509 *caX509 = NULL;
    X509 *svrX509 = NULL;
    X509_NAME *subject = NULL;
    WOLF_STACK_OF(WOLFSSL_X509) *certs = NULL;

    ExpectNotNull(caX509 = X509_load_certificate_file(caCertFile,
        SSL_FILETYPE_PEM));
    ExpectNotNull((svrX509 = wolfSSL_X509_load_certificate_file(svrCertFile,
        SSL_FILETYPE_PEM)));
    ExpectNotNull(storeCtx = X509_STORE_CTX_new());
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(subject = X509_get_subject_name(caX509));

    /* Errors */
    ExpectNull(X509_STORE_get1_certs(storeCtx, subject));
    ExpectNull(X509_STORE_get1_certs(NULL, subject));
    ExpectNull(X509_STORE_get1_certs(storeCtx, NULL));

    ExpectIntEQ(X509_STORE_add_cert(store, caX509), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, caX509, NULL),
        SSL_SUCCESS);

    /* Should find the cert */
    ExpectNotNull(certs = X509_STORE_get1_certs(storeCtx, subject));
    ExpectIntEQ(1, wolfSSL_sk_X509_num(certs));

    sk_X509_pop_free(certs, NULL);
    certs = NULL;

    /* Should not find the cert */
    ExpectNotNull(subject = X509_get_subject_name(svrX509));
    ExpectNotNull(certs = X509_STORE_get1_certs(storeCtx, subject));
    ExpectIntEQ(0, wolfSSL_sk_X509_num(certs));

    sk_X509_pop_free(certs, NULL);
    certs = NULL;

    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);
    X509_free(svrX509);
    X509_free(caX509);
#endif /* OPENSSL_EXTRA && WOLFSSL_SIGNER_DER_CERT && !NO_FILESYSTEM */
    return EXPECT_RESULT();
}

#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_LOCAL_X509_STORE) && \
    (defined(OPENSSL_ALL) || defined(WOLFSSL_QT)) && defined(HAVE_CRL)
static int test_wolfSSL_X509_STORE_set_get_crl_provider(X509_STORE_CTX* ctx,
        X509_CRL** crl_out, X509* cert) {
    X509_CRL *crl = NULL;
    XFILE fp = XBADFILE;
    char* cert_issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    int ret = 0;

    (void)ctx;

    if (cert_issuer == NULL)
        return 0;

    if ((fp = XFOPEN("certs/crl/crl.pem", "rb")) != XBADFILE) {
        PEM_read_X509_CRL(fp, &crl, NULL, NULL);
        XFCLOSE(fp);
        if (crl != NULL) {
            char* crl_issuer = X509_NAME_oneline(
                    X509_CRL_get_issuer(crl), NULL, 0);
            if ((crl_issuer != NULL) &&
                   (XSTRCMP(cert_issuer, crl_issuer) == 0)) {
                *crl_out = X509_CRL_dup(crl);
                if (*crl_out != NULL)
                    ret = 1;
            }
            OPENSSL_free(crl_issuer);
        }
    }

    X509_CRL_free(crl);
    OPENSSL_free(cert_issuer);
    return ret;
}

static int test_wolfSSL_X509_STORE_set_get_crl_provider2(X509_STORE_CTX* ctx,
        X509_CRL** crl_out, X509* cert) {
    (void)ctx;
    (void)cert;
    *crl_out = NULL;
    return 1;
}

#ifndef NO_WOLFSSL_STUB
static int test_wolfSSL_X509_STORE_set_get_crl_check(X509_STORE_CTX* ctx,
        X509_CRL* crl) {
    (void)ctx;
    (void)crl;
    return 1;
}
#endif

static int test_wolfSSL_X509_STORE_set_get_crl_verify(int ok,
        X509_STORE_CTX* ctx) {
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);
    int flags = X509_VERIFY_PARAM_get_flags(param);
    if ((flags & (X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL)) !=
            (X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL)) {
        /* Make sure the flags are set */
        return 0;
    }
    /* Ignore CRL missing error */
#ifndef OPENSSL_COMPATIBLE_DEFAULTS
    if (cert_error == WC_NO_ERR_TRACE(CRL_MISSING))
#else
    if (cert_error == X509_V_ERR_UNABLE_TO_GET_CRL)
#endif
        return 1;
    return ok;
}

static int test_wolfSSL_X509_STORE_set_get_crl_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    X509_STORE* cert_store = NULL;

    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
            WOLFSSL_SUCCESS);
    ExpectNotNull(cert_store = SSL_CTX_get_cert_store(ctx));
    X509_STORE_set_get_crl(cert_store,
            test_wolfSSL_X509_STORE_set_get_crl_provider);
#ifndef NO_WOLFSSL_STUB
    X509_STORE_set_check_crl(cert_store,
            test_wolfSSL_X509_STORE_set_get_crl_check);
#endif

    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_set_get_crl_ctx_ready2(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    X509_STORE* cert_store = NULL;
    X509_VERIFY_PARAM* param = NULL;

    SSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
            WOLFSSL_SUCCESS);
    ExpectNotNull(cert_store = SSL_CTX_get_cert_store(ctx));
    X509_STORE_set_get_crl(cert_store,
            test_wolfSSL_X509_STORE_set_get_crl_provider2);
#ifndef NO_WOLFSSL_STUB
    X509_STORE_set_check_crl(cert_store,
            test_wolfSSL_X509_STORE_set_get_crl_check);
#endif
    X509_STORE_set_verify_cb(cert_store,
            test_wolfSSL_X509_STORE_set_get_crl_verify);
    ExpectNotNull(X509_STORE_get0_param(cert_store));
    ExpectNotNull(param = X509_VERIFY_PARAM_new());
    ExpectIntEQ(X509_VERIFY_PARAM_inherit(NULL, NULL) , WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_VERIFY_PARAM_inherit(param, NULL) , WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_VERIFY_PARAM_inherit(param,
            X509_STORE_get0_param(cert_store)), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_VERIFY_PARAM_inherit(param,
            X509_STORE_get0_param(cert_store)), 1);
    ExpectIntEQ(X509_VERIFY_PARAM_set_flags(
        param, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL), 1);
    ExpectIntEQ(X509_STORE_set1_param(cert_store, param), 1);
    ExpectIntEQ(X509_STORE_set_flags(cert_store,
            X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL), 1);


    X509_VERIFY_PARAM_free(param);
    return EXPECT_RESULT();
}
#endif

/* This test mimics the usage of the CRL provider in gRPC */
static int test_wolfSSL_X509_STORE_set_get_crl(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_LOCAL_X509_STORE) && \
    (defined(OPENSSL_ALL) || defined(WOLFSSL_QT)) && defined(HAVE_CRL)
    test_ssl_cbf func_cb_client;
    test_ssl_cbf func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(func_cb_client));
    XMEMSET(&func_cb_server, 0, sizeof(func_cb_server));

    func_cb_client.ctx_ready = test_wolfSSL_X509_STORE_set_get_crl_ctx_ready;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&func_cb_client,
        &func_cb_server, NULL), TEST_SUCCESS);

    XMEMSET(&func_cb_client, 0, sizeof(func_cb_client));
    XMEMSET(&func_cb_server, 0, sizeof(func_cb_server));

    func_cb_client.ctx_ready = test_wolfSSL_X509_STORE_set_get_crl_ctx_ready2;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&func_cb_client,
        &func_cb_server, NULL), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}


static int test_wolfSSL_dup_CA_list(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_ALL)
    EXPECT_DECLS;
    STACK_OF(X509_NAME) *originalStack = NULL;
    STACK_OF(X509_NAME) *copyStack = NULL;
    int originalCount = 0;
    int copyCount = 0;
    X509_NAME *name = NULL;
    int i;

    originalStack = sk_X509_NAME_new_null();
    ExpectNotNull(originalStack);

    for (i = 0; i < 3; i++) {
        name = X509_NAME_new();
        ExpectNotNull(name);
        ExpectIntEQ(sk_X509_NAME_push(originalStack, name), i+1);
        if (EXPECT_FAIL()) {
            X509_NAME_free(name);
        }
    }

    copyStack = SSL_dup_CA_list(originalStack);
    ExpectNotNull(copyStack);
    ExpectIntEQ(sk_X509_NAME_num(NULL), BAD_FUNC_ARG);
    originalCount = sk_X509_NAME_num(originalStack);
    copyCount = sk_X509_NAME_num(copyStack);

    ExpectIntEQ(originalCount, copyCount);
    sk_X509_NAME_pop_free(originalStack, X509_NAME_free);
    sk_X509_NAME_pop_free(copyStack, X509_NAME_free);

    originalStack = NULL;
    copyStack = NULL;

    originalStack = sk_X509_NAME_new_null();
    ExpectNull(sk_X509_NAME_pop(NULL));
    ExpectNull(sk_X509_NAME_pop(originalStack));
    for (i = 0; i < 3; i++) {
        name = X509_NAME_new();
        ExpectNotNull(name);
        ExpectIntEQ(sk_X509_NAME_push(originalStack, name), i+1);
        if (EXPECT_FAIL()) {
            X509_NAME_free(name);
        }
        name = NULL;
    }
    ExpectNotNull(name = sk_X509_NAME_pop(originalStack));
    X509_NAME_free(name);
    wolfSSL_sk_X509_NAME_set_cmp_func(NULL, NULL);
    wolfSSL_sk_X509_NAME_set_cmp_func(originalStack, NULL);
    wolfSSL_sk_X509_NAME_pop_free(originalStack, X509_NAME_free);

    res = EXPECT_RESULT();
#endif /* OPENSSL_ALL */
    return res;
}

static int test_ForceZero(void)
{
    EXPECT_DECLS;
    unsigned char data[32];
    unsigned int i, j, len;

    /* Test case with 0 length */
    ForceZero(data, 0);

    /* Test ForceZero */
    for (i = 0; i < sizeof(data); i++) {
        for (len = 1; len < sizeof(data) - i; len++) {
            for (j = 0; j < sizeof(data); j++)
                data[j] = ((unsigned char)j + 1);

            ForceZero(data + i, len);

            for (j = 0; j < sizeof(data); j++) {
                if (j < i || j >= i + len) {
                    ExpectIntNE(data[j], 0x00);
                }
                else {
                    ExpectIntEQ(data[j], 0x00);
                }
            }
        }
    }

    return EXPECT_RESULT();
}

#ifndef NO_BIO

static int test_wolfSSL_X509_print(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && \
   !defined(NO_RSA) && defined(XSNPRINTF)
    X509 *x509 = NULL;
    BIO *bio = NULL;
#if defined(OPENSSL_ALL) && !defined(NO_WOLFSSL_DIR)
    const X509_ALGOR *cert_sig_alg = NULL;
#endif

    ExpectNotNull(x509 = X509_load_certificate_file(svrCertFile,
        WOLFSSL_FILETYPE_PEM));

    /* print to memory */
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(X509_print(bio, x509), SSL_SUCCESS);

#if defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME)
  #if defined(WC_DISABLE_RADIX_ZERO_PAD)
     /* Will print IP address subject alt name. */
     ExpectIntEQ(BIO_get_mem_data(bio, NULL), 3349);
  #elif defined(NO_ASN_TIME)
      /* Will print IP address subject alt name but not Validity. */
     ExpectIntEQ(BIO_get_mem_data(bio, NULL), 3235);
  #else
      /* Will print IP address subject alt name. */
     ExpectIntEQ(BIO_get_mem_data(bio, NULL), 3350);
  #endif
#elif defined(NO_ASN_TIME)
    /* With NO_ASN_TIME defined, X509_print skips printing Validity. */
    ExpectIntEQ(BIO_get_mem_data(bio, NULL), 3213);
#else
    ExpectIntEQ(BIO_get_mem_data(bio, NULL), 3328);
#endif
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = BIO_new_fd(STDERR_FILENO, BIO_NOCLOSE));

#if defined(OPENSSL_ALL) && !defined(NO_WOLFSSL_DIR)
    /* Print signature */
    ExpectNotNull(cert_sig_alg = X509_get0_tbs_sigalg(x509));
    ExpectIntEQ(X509_signature_print(bio, cert_sig_alg, NULL), SSL_SUCCESS);
#endif

    /* print to stderr */
#if !defined(NO_WOLFSSL_DIR)
    ExpectIntEQ(X509_print(bio, x509), SSL_SUCCESS);
#endif
    /* print again */
    ExpectIntEQ(X509_print_fp(stderr, x509), SSL_SUCCESS);

    X509_free(x509);
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_CRL_print(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && defined(HAVE_CRL) && \
    !defined(NO_RSA) && !defined(NO_FILESYSTEM) && defined(XSNPRINTF)
    X509_CRL* crl = NULL;
    BIO *bio = NULL;
    XFILE fp = XBADFILE;

    ExpectTrue((fp = XFOPEN("./certs/crl/crl.pem", "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL*)PEM_read_X509_CRL(fp, (X509_CRL **)NULL,
        NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(X509_CRL_print(bio, crl), SSL_SUCCESS);

    X509_CRL_free(crl);
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_BIO_get_len(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    BIO *bio = NULL;
    const char txt[] = "Some example text to push to the BIO.";

    ExpectIntEQ(wolfSSL_BIO_get_len(bio), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));

    ExpectIntEQ(wolfSSL_BIO_write(bio, txt, sizeof(txt)), sizeof(txt));
    ExpectIntEQ(wolfSSL_BIO_get_len(bio), sizeof(txt));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = BIO_new_fd(STDERR_FILENO, BIO_NOCLOSE));
    ExpectIntEQ(wolfSSL_BIO_get_len(bio), WC_NO_ERR_TRACE(WOLFSSL_BAD_FILE));
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

#endif /* !NO_BIO */

static int test_wolfSSL_RSA(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    RSA* rsa = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *dmp1 = NULL;
    const BIGNUM *dmq1 = NULL;
    const BIGNUM *iqmp = NULL;

    ExpectNotNull(rsa = RSA_new());
    ExpectIntEQ(RSA_size(NULL), 0);
    ExpectIntEQ(RSA_size(rsa), 0);
    ExpectIntEQ(RSA_set0_key(rsa, NULL, NULL, NULL), 0);
    ExpectIntEQ(RSA_set0_crt_params(rsa, NULL, NULL, NULL), 0);
    ExpectIntEQ(RSA_set0_factors(rsa, NULL, NULL), 0);
#ifdef WOLFSSL_RSA_KEY_CHECK
    ExpectIntEQ(RSA_check_key(rsa), 0);
#endif

    RSA_free(rsa);
    rsa = NULL;
    ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
    ExpectIntEQ(RSA_size(rsa), 256);

#if (!defined(HAVE_FIPS) || FIPS_VERSION3_GT(6,0,0)) && !defined(HAVE_SELFTEST)
    {
        /* Test setting only subset of parameters */
        RSA *rsa2 = NULL;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        unsigned char signature[2048/8];
        unsigned int signatureLen = 0;
        BIGNUM* n2 = NULL;
        BIGNUM* e2 = NULL;
        BIGNUM* d2 = NULL;
        BIGNUM* p2 = NULL;
        BIGNUM* q2 = NULL;
        BIGNUM* dmp12 = NULL;
        BIGNUM* dmq12 = NULL;
        BIGNUM* iqmp2 = NULL;

        XMEMSET(hash, 0, sizeof(hash));
        RSA_get0_key(rsa, &n, &e, &d);
        RSA_get0_factors(rsa, &p, &q);
        RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa), 1);
        /* Quick sanity check */
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa), 1);

        /* Verifying */
        ExpectNotNull(n2 = BN_dup(n));
        ExpectNotNull(e2 = BN_dup(e));
        ExpectNotNull(p2 = BN_dup(p));
        ExpectNotNull(q2 = BN_dup(q));
        ExpectNotNull(dmp12 = BN_dup(dmp1));
        ExpectNotNull(dmq12 = BN_dup(dmq1));
        ExpectNotNull(iqmp2 = BN_dup(iqmp));

        ExpectNotNull(rsa2 = RSA_new());
        ExpectIntEQ(RSA_set0_key(rsa2, n2, e2, NULL), 1);
        if (EXPECT_SUCCESS()) {
            n2 = NULL;
            e2 = NULL;
        }
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa2), 1);
        ExpectIntEQ(RSA_set0_factors(rsa2, p2, q2), 1);
        if (EXPECT_SUCCESS()) {
            p2 = NULL;
            q2 = NULL;
        }
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa2), 1);
        ExpectIntEQ(RSA_set0_crt_params(rsa2, dmp12, dmq12, iqmp2), 1);
        if (EXPECT_SUCCESS()) {
            dmp12 = NULL;
            dmq12 = NULL;
            iqmp2 = NULL;
        }
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa2), 1);
        RSA_free(rsa2);
        rsa2 = NULL;

        BN_free(iqmp2);
        iqmp2 = NULL;
        BN_free(dmq12);
        dmq12 = NULL;
        BN_free(dmp12);
        dmp12 = NULL;
        BN_free(q2);
        q2 = NULL;
        BN_free(p2);
        p2 = NULL;
        BN_free(e2);
        e2 = NULL;
        BN_free(n2);
        n2 = NULL;

        ExpectNotNull(n2 = BN_dup(n));
        ExpectNotNull(e2 = BN_dup(e));
        ExpectNotNull(d2 = BN_dup(d));
        ExpectNotNull(p2 = BN_dup(p));
        ExpectNotNull(q2 = BN_dup(q));
        ExpectNotNull(dmp12 = BN_dup(dmp1));
        ExpectNotNull(dmq12 = BN_dup(dmq1));
        ExpectNotNull(iqmp2 = BN_dup(iqmp));

        /* Signing */
        XMEMSET(signature, 0, sizeof(signature));
        ExpectNotNull(rsa2 = RSA_new());
        ExpectIntEQ(RSA_set0_key(rsa2, n2, e2, d2), 1);
        if (EXPECT_SUCCESS()) {
            n2 = NULL;
            e2 = NULL;
            d2 = NULL;
        }
#if defined(WOLFSSL_SP_MATH) && !defined(RSA_LOW_MEM)
        /* SP is not support signing without CRT parameters. */
        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa2), 0);
        ExpectIntEQ(RSA_set0_factors(rsa2, p2, q2), 1);
        if (EXPECT_SUCCESS()) {
            p2 = NULL;
            q2 = NULL;
        }
        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa2), 0);
#else
        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa2), 1);
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa), 1);
        ExpectIntEQ(RSA_set0_factors(rsa2, p2, q2), 1);
        if (EXPECT_SUCCESS()) {
            p2 = NULL;
            q2 = NULL;
        }
        XMEMSET(signature, 0, sizeof(signature));
        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa2), 1);
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa), 1);
#endif
        ExpectIntEQ(RSA_set0_crt_params(rsa2, dmp12, dmq12, iqmp2), 1);
        if (EXPECT_SUCCESS()) {
            dmp12 = NULL;
            dmq12 = NULL;
            iqmp2 = NULL;
        }
        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa2), 1);
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa), 1);
        RSA_free(rsa2);
        rsa2 = NULL;

        BN_free(iqmp2);
        BN_free(dmq12);
        BN_free(dmp12);
        BN_free(q2);
        BN_free(p2);
        BN_free(d2);
        BN_free(e2);
        BN_free(n2);
    }
#endif

#ifdef WOLFSSL_RSA_KEY_CHECK
    ExpectIntEQ(RSA_check_key(NULL), 0);
    ExpectIntEQ(RSA_check_key(rsa), 1);
#endif

    /* sanity check */
    ExpectIntEQ(RSA_bits(NULL), 0);

    /* key */
    ExpectIntEQ(RSA_bits(rsa), 2048);
    RSA_get0_key(rsa, &n, &e, &d);
    ExpectPtrEq(rsa->n, n);
    ExpectPtrEq(rsa->e, e);
    ExpectPtrEq(rsa->d, d);
    n = NULL;
    e = NULL;
    d = NULL;
    ExpectNotNull(n = BN_new());
    ExpectNotNull(e = BN_new());
    ExpectNotNull(d = BN_new());
    ExpectIntEQ(RSA_set0_key(rsa, (BIGNUM*)n, (BIGNUM*)e, (BIGNUM*)d), 1);
    if (EXPECT_FAIL()) {
        BN_free((BIGNUM*)n);
        BN_free((BIGNUM*)e);
        BN_free((BIGNUM*)d);
    }
    ExpectPtrEq(rsa->n, n);
    ExpectPtrEq(rsa->e, e);
    ExpectPtrEq(rsa->d, d);
    ExpectIntEQ(RSA_set0_key(rsa, NULL, NULL, NULL), 1);
    ExpectIntEQ(RSA_set0_key(NULL, (BIGNUM*)n, (BIGNUM*)e, (BIGNUM*)d), 0);

    /* crt_params */
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    ExpectPtrEq(rsa->dmp1, dmp1);
    ExpectPtrEq(rsa->dmq1, dmq1);
    ExpectPtrEq(rsa->iqmp, iqmp);
    dmp1 = NULL;
    dmq1 = NULL;
    iqmp = NULL;
    ExpectNotNull(dmp1 = BN_new());
    ExpectNotNull(dmq1 = BN_new());
    ExpectNotNull(iqmp = BN_new());
    ExpectIntEQ(RSA_set0_crt_params(rsa, (BIGNUM*)dmp1, (BIGNUM*)dmq1,
        (BIGNUM*)iqmp), 1);
    if (EXPECT_FAIL()) {
        BN_free((BIGNUM*)dmp1);
        BN_free((BIGNUM*)dmq1);
        BN_free((BIGNUM*)iqmp);
    }
    ExpectPtrEq(rsa->dmp1, dmp1);
    ExpectPtrEq(rsa->dmq1, dmq1);
    ExpectPtrEq(rsa->iqmp, iqmp);
    ExpectIntEQ(RSA_set0_crt_params(rsa, NULL, NULL, NULL), 1);
    ExpectIntEQ(RSA_set0_crt_params(NULL, (BIGNUM*)dmp1, (BIGNUM*)dmq1,
        (BIGNUM*)iqmp), 0);
    RSA_get0_crt_params(NULL, NULL, NULL, NULL);
    RSA_get0_crt_params(rsa, NULL, NULL, NULL);
    RSA_get0_crt_params(NULL, &dmp1, &dmq1, &iqmp);
    ExpectNull(dmp1);
    ExpectNull(dmq1);
    ExpectNull(iqmp);

    /* factors */
    RSA_get0_factors(rsa, NULL, NULL);
    RSA_get0_factors(rsa, &p, &q);
    ExpectPtrEq(rsa->p, p);
    ExpectPtrEq(rsa->q, q);
    p = NULL;
    q = NULL;
    ExpectNotNull(p = BN_new());
    ExpectNotNull(q = BN_new());
    ExpectIntEQ(RSA_set0_factors(rsa, (BIGNUM*)p, (BIGNUM*)q), 1);
    if (EXPECT_FAIL()) {
        BN_free((BIGNUM*)p);
        BN_free((BIGNUM*)q);
    }
    ExpectPtrEq(rsa->p, p);
    ExpectPtrEq(rsa->q, q);
    ExpectIntEQ(RSA_set0_factors(rsa, NULL, NULL), 1);
    ExpectIntEQ(RSA_set0_factors(NULL, (BIGNUM*)p, (BIGNUM*)q), 0);
    RSA_get0_factors(NULL, NULL, NULL);
    RSA_get0_factors(NULL, &p, &q);
    ExpectNull(p);
    ExpectNull(q);

    ExpectIntEQ(BN_hex2bn(&rsa->n, "1FFFFF"), 1);
    ExpectIntEQ(RSA_bits(rsa), 21);
    RSA_free(rsa);
    rsa = NULL;

#if !defined(USE_FAST_MATH) || (FP_MAX_BITS >= (3072*2))
    ExpectNotNull(rsa = RSA_generate_key(3072, 17, NULL, NULL));
    ExpectIntEQ(RSA_size(rsa), 384);
    ExpectIntEQ(RSA_bits(rsa), 3072);
    RSA_free(rsa);
    rsa = NULL;
#endif

    /* remove for now with odd key size until adjusting rsa key size check with
       wc_MakeRsaKey()
    ExpectNotNull(rsa = RSA_generate_key(2999, 65537, NULL, NULL));
    RSA_free(rsa);
    rsa = NULL;
    */

    ExpectNull(RSA_generate_key(-1, 3, NULL, NULL));
    ExpectNull(RSA_generate_key(RSA_MIN_SIZE - 1, 3, NULL, NULL));
    ExpectNull(RSA_generate_key(RSA_MAX_SIZE + 1, 3, NULL, NULL));
    ExpectNull(RSA_generate_key(2048, 0, NULL, NULL));


#if !defined(NO_FILESYSTEM) && !defined(NO_ASN)
    {
        byte buff[FOURK_BUF];
        byte der[FOURK_BUF];
        const char PrivKeyPemFile[] = "certs/client-keyEnc.pem";

        XFILE f = XBADFILE;
        int bytes = 0;

        /* test loading encrypted RSA private pem w/o password */
        ExpectTrue((f = XFOPEN(PrivKeyPemFile, "rb")) != XBADFILE);
        ExpectIntGT(bytes = (int)XFREAD(buff, 1, sizeof(buff), f), 0);
        if (f != XBADFILE)
            XFCLOSE(f);
        XMEMSET(der, 0, sizeof(der));
        /* test that error value is returned with no password */
        ExpectIntLT(wc_KeyPemToDer(buff, bytes, der, (word32)sizeof(der), ""),
            0);
    }
#endif
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_DER(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA) && defined(OPENSSL_EXTRA)
    RSA *rsa = NULL;
    int i;
    const unsigned char *buff = NULL;
    unsigned char *newBuff = NULL;

    struct tbl_s
    {
        const unsigned char *der;
        int sz;
    } tbl[] = {

#ifdef USE_CERT_BUFFERS_1024
        {client_key_der_1024, sizeof_client_key_der_1024},
        {server_key_der_1024, sizeof_server_key_der_1024},
#endif
#ifdef USE_CERT_BUFFERS_2048
        {client_key_der_2048, sizeof_client_key_der_2048},
        {server_key_der_2048, sizeof_server_key_der_2048},
#endif
        {NULL, 0}
    };

    /* Public Key DER */
    struct tbl_s pub[] = {
#ifdef USE_CERT_BUFFERS_1024
        {client_keypub_der_1024, sizeof_client_keypub_der_1024},
#endif
#ifdef USE_CERT_BUFFERS_2048
        {client_keypub_der_2048, sizeof_client_keypub_der_2048},
#endif
        {NULL, 0}
    };

    ExpectNull(d2i_RSAPublicKey(&rsa, NULL, pub[0].sz));
    buff = pub[0].der;
    ExpectNull(d2i_RSAPublicKey(&rsa, &buff, 1));
    ExpectNull(d2i_RSAPrivateKey(&rsa, NULL, tbl[0].sz));
    buff = tbl[0].der;
    ExpectNull(d2i_RSAPrivateKey(&rsa, &buff, 1));

    ExpectIntEQ(i2d_RSAPublicKey(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    rsa = RSA_new();
    ExpectIntEQ(i2d_RSAPublicKey(rsa, NULL), 0);
    RSA_free(rsa);
    rsa = NULL;

    for (i = 0; tbl[i].der != NULL; i++)
    {
        /* Passing in pointer results in pointer moving. */
        buff = tbl[i].der;
        ExpectNotNull(d2i_RSAPublicKey(&rsa, &buff, tbl[i].sz));
        ExpectNotNull(rsa);
        RSA_free(rsa);
        rsa = NULL;
    }
    for (i = 0; tbl[i].der != NULL; i++)
    {
        /* Passing in pointer results in pointer moving. */
        buff = tbl[i].der;
        ExpectNotNull(d2i_RSAPrivateKey(&rsa, &buff, tbl[i].sz));
        ExpectNotNull(rsa);
        RSA_free(rsa);
        rsa = NULL;
    }

    for (i = 0; pub[i].der != NULL; i++)
    {
        buff = pub[i].der;
        ExpectNotNull(d2i_RSAPublicKey(&rsa, &buff, pub[i].sz));
        ExpectNotNull(rsa);
        ExpectIntEQ(i2d_RSAPublicKey(rsa, NULL), pub[i].sz);
        newBuff = NULL;
        ExpectIntEQ(i2d_RSAPublicKey(rsa, &newBuff), pub[i].sz);
        ExpectNotNull(newBuff);
        ExpectIntEQ(XMEMCMP((void *)newBuff, (void *)pub[i].der, pub[i].sz), 0);
        XFREE((void *)newBuff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        RSA_free(rsa);
        rsa = NULL;
    }
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_print(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && \
   !defined(NO_STDIO_FILESYSTEM) && \
   !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
   !defined(NO_BIO) && defined(XFPRINTF)
    BIO *bio = NULL;
    WOLFSSL_RSA* rsa = NULL;

    ExpectNotNull(bio = BIO_new_fd(STDERR_FILENO, BIO_NOCLOSE));
    ExpectNotNull(rsa = RSA_new());

    ExpectIntEQ(RSA_print(NULL, rsa, 0), -1);
    ExpectIntEQ(RSA_print_fp(XBADFILE, rsa, 0), 0);
    ExpectIntEQ(RSA_print(bio, NULL, 0), -1);
    ExpectIntEQ(RSA_print_fp(stderr, NULL, 0), 0);
    /* Some very large number of indent spaces. */
    ExpectIntEQ(RSA_print(bio, rsa, 128), -1);
    /* RSA is empty. */
    ExpectIntEQ(RSA_print(bio, rsa, 0), 0);
    ExpectIntEQ(RSA_print_fp(stderr, rsa, 0), 0);

    RSA_free(rsa);
    rsa = NULL;
    ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));

    ExpectIntEQ(RSA_print(bio, rsa, 0), 1);
    ExpectIntEQ(RSA_print(bio, rsa, 4), 1);
    ExpectIntEQ(RSA_print(bio, rsa, -1), 1);
    ExpectIntEQ(RSA_print_fp(stderr, rsa, 0), 1);
    ExpectIntEQ(RSA_print_fp(stderr, rsa, 4), 1);
    ExpectIntEQ(RSA_print_fp(stderr, rsa, -1), 1);

    BIO_free(bio);
    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_padding_add_PKCS1_PSS(void)
{
    EXPECT_DECLS;
#ifndef NO_RSA
#if defined(OPENSSL_ALL) && defined(WC_RSA_PSS) && !defined(WC_NO_RNG)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    RSA *rsa = NULL;
    const unsigned char *derBuf = client_key_der_2048;
    unsigned char em[256] = {0}; /* len = 2048/8 */
    /* Random data simulating a hash */
    const unsigned char mHash[WC_SHA256_DIGEST_SIZE] = {
        0x28, 0x6e, 0xfd, 0xf8, 0x76, 0xc7, 0x00, 0x3d, 0x91, 0x4e, 0x59, 0xe4,
        0x8e, 0xb7, 0x40, 0x7b, 0xd1, 0x0c, 0x98, 0x4b, 0xe3, 0x3d, 0xb3, 0xeb,
        0x6f, 0x8a, 0x3c, 0x42, 0xab, 0x21, 0xad, 0x28
    };

    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &derBuf, sizeof_client_key_der_2048));
    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(NULL, em, mHash, EVP_sha256(),
        RSA_PSS_SALTLEN_DIGEST), 0);
    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, NULL, mHash, EVP_sha256(),
        RSA_PSS_SALTLEN_DIGEST), 0);
    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, NULL, EVP_sha256(),
        RSA_PSS_SALTLEN_DIGEST), 0);
    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, NULL,
        RSA_PSS_SALTLEN_DIGEST), 0);
    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, EVP_sha256(), -5), 0);

    ExpectIntEQ(RSA_verify_PKCS1_PSS(NULL, mHash, EVP_sha256(), em,
        RSA_PSS_SALTLEN_MAX_SIGN), 0);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, NULL, EVP_sha256(), em,
        RSA_PSS_SALTLEN_MAX_SIGN), 0);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, NULL, em,
        RSA_PSS_SALTLEN_MAX_SIGN), 0);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), NULL,
        RSA_PSS_SALTLEN_MAX_SIGN), 0);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em,
        RSA_PSS_SALTLEN_MAX_SIGN), 0);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em, -5), 0);

    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, EVP_sha256(),
        RSA_PSS_SALTLEN_DIGEST), 1);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em,
        RSA_PSS_SALTLEN_DIGEST), 1);

    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, EVP_sha256(),
        RSA_PSS_SALTLEN_MAX_SIGN), 1);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em,
        RSA_PSS_SALTLEN_MAX_SIGN), 1);

    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, EVP_sha256(),
        RSA_PSS_SALTLEN_MAX), 1);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em,
        RSA_PSS_SALTLEN_MAX), 1);

    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, EVP_sha256(), 10), 1);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em, 10), 1);

    RSA_free(rsa);
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* OPENSSL_ALL && WC_RSA_PSS && !WC_NO_RNG*/
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_sign_sha3(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
#if defined(OPENSSL_ALL) && defined(WC_RSA_PSS) && !defined(WC_NO_RNG)
    RSA* rsa = NULL;
    const unsigned char *derBuf = client_key_der_2048;
    unsigned char sigRet[256] = {0};
    unsigned int sigLen = sizeof(sigRet);
    /* Random data simulating a hash */
    const unsigned char mHash[WC_SHA3_256_DIGEST_SIZE] = {
        0x28, 0x6e, 0xfd, 0xf8, 0x76, 0xc7, 0x00, 0x3d, 0x91, 0x4e, 0x59, 0xe4,
        0x8e, 0xb7, 0x40, 0x7b, 0xd1, 0x0c, 0x98, 0x4b, 0xe3, 0x3d, 0xb3, 0xeb,
        0x6f, 0x8a, 0x3c, 0x42, 0xab, 0x21, 0xad, 0x28
    };

    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &derBuf, sizeof_client_key_der_2048));
    ExpectIntEQ(RSA_sign(NID_sha3_256, mHash, sizeof(mHash), sigRet, &sigLen,
        rsa), 1);

    RSA_free(rsa);
#endif /* OPENSSL_ALL && WC_RSA_PSS && !WC_NO_RNG*/
#endif /* !NO_RSA && WOLFSSL_SHA3 && !WOLFSSL_NOSHA3_256*/
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_get0_key(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa = NULL;
    const BIGNUM* n = NULL;
    const BIGNUM* e = NULL;
    const BIGNUM* d = NULL;

    const unsigned char* der;
    int derSz;

#ifdef USE_CERT_BUFFERS_1024
    der = client_key_der_1024;
    derSz = sizeof_client_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    der = client_key_der_2048;
    derSz = sizeof_client_key_der_2048;
#else
    der = NULL;
    derSz = 0;
#endif

    if (der != NULL) {
        RSA_get0_key(NULL, NULL, NULL, NULL);
        RSA_get0_key(rsa, NULL, NULL, NULL);
        RSA_get0_key(NULL, &n, &e, &d);
        ExpectNull(n);
        ExpectNull(e);
        ExpectNull(d);

        ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, derSz));
        ExpectNotNull(rsa);

        RSA_get0_key(rsa, NULL, NULL, NULL);
        RSA_get0_key(rsa, &n, NULL, NULL);
        ExpectNotNull(n);
        RSA_get0_key(rsa, NULL, &e, NULL);
        ExpectNotNull(e);
        RSA_get0_key(rsa, NULL, NULL, &d);
        ExpectNotNull(d);
        RSA_get0_key(rsa, &n, &e, &d);
        ExpectNotNull(n);
        ExpectNotNull(e);
        ExpectNotNull(d);

        RSA_free(rsa);
    }
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_meth(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa = NULL;
    RSA_METHOD *rsa_meth = NULL;

#ifdef WOLFSSL_KEY_GEN
    ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
    RSA_free(rsa);
    rsa = NULL;
#else
    ExpectNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
#endif

    ExpectNotNull(RSA_get_default_method());

    wolfSSL_RSA_meth_free(NULL);

    ExpectNull(wolfSSL_RSA_meth_new(NULL, 0));

    ExpectNotNull(rsa_meth = RSA_meth_new("placeholder RSA method",
        RSA_METHOD_FLAG_NO_CHECK));

#ifndef NO_WOLFSSL_STUB
    ExpectIntEQ(RSA_meth_set_pub_enc(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set_pub_dec(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set_priv_enc(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set_priv_dec(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set_init(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set_finish(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set0_app_data(rsa_meth, NULL), 1);
#endif

    ExpectIntEQ(RSA_flags(NULL), 0);
    RSA_set_flags(NULL, RSA_FLAG_CACHE_PUBLIC);
    RSA_clear_flags(NULL, RSA_FLAG_CACHE_PUBLIC);
    ExpectIntEQ(RSA_test_flags(NULL, RSA_FLAG_CACHE_PUBLIC), 0);

    ExpectNotNull(rsa = RSA_new());
    /* No method set. */
    ExpectIntEQ(RSA_flags(rsa), 0);
    RSA_set_flags(rsa, RSA_FLAG_CACHE_PUBLIC);
    RSA_clear_flags(rsa, RSA_FLAG_CACHE_PUBLIC);
    ExpectIntEQ(RSA_test_flags(rsa, RSA_FLAG_CACHE_PUBLIC), 0);

    ExpectIntEQ(RSA_set_method(NULL, rsa_meth), 1);
    ExpectIntEQ(RSA_set_method(rsa, rsa_meth), 1);
    if (EXPECT_FAIL()) {
        wolfSSL_RSA_meth_free(rsa_meth);
    }
    ExpectNull(RSA_get_method(NULL));
    ExpectPtrEq(RSA_get_method(rsa), rsa_meth);
    ExpectIntEQ(RSA_flags(rsa), RSA_METHOD_FLAG_NO_CHECK);
    RSA_set_flags(rsa, RSA_FLAG_CACHE_PUBLIC);
    ExpectIntNE(RSA_test_flags(rsa, RSA_FLAG_CACHE_PUBLIC), 0);
    ExpectIntEQ(RSA_flags(rsa), RSA_FLAG_CACHE_PUBLIC |
                                RSA_METHOD_FLAG_NO_CHECK);
    RSA_clear_flags(rsa, RSA_FLAG_CACHE_PUBLIC);
    ExpectIntEQ(RSA_test_flags(rsa, RSA_FLAG_CACHE_PUBLIC), 0);
    ExpectIntNE(RSA_flags(rsa), RSA_FLAG_CACHE_PUBLIC);

    /* rsa_meth is freed here */
    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_verify(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)
#ifndef NO_BIO
    XFILE fp = XBADFILE;
    RSA *pKey = NULL;
    RSA *pubKey = NULL;
    X509 *cert = NULL;
    const char *text = "Hello wolfSSL !";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char signature[2048/8];
    unsigned int signatureLength;
    byte *buf = NULL;
    BIO *bio = NULL;
    SHA256_CTX c;
    EVP_PKEY *evpPkey = NULL;
    EVP_PKEY *evpPubkey = NULL;
    size_t sz;

    /* generate hash */
    SHA256_Init(&c);
    SHA256_Update(&c, text, strlen(text));
    SHA256_Final(hash, &c);
#ifdef WOLFSSL_SMALL_STACK_CACHE
    /* workaround for small stack cache case */
    wc_Sha256Free((wc_Sha256*)&c);
#endif

    /* read privete key file */
    ExpectTrue((fp = XFOPEN(svrKeyFile, "rb")) != XBADFILE);
    ExpectIntEQ(XFSEEK(fp, 0, XSEEK_END), 0);
    ExpectTrue((sz = XFTELL(fp)) > 0);
    ExpectIntEQ(XFSEEK(fp, 0, XSEEK_SET), 0);
    ExpectNotNull(buf = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE));
    ExpectIntEQ(XFREAD(buf, 1, sz, fp), sz);
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    /* read private key and sign hash data */
    ExpectNotNull(bio = BIO_new_mem_buf(buf, (int)sz));
    ExpectNotNull(evpPkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL));
    ExpectNotNull(pKey = EVP_PKEY_get1_RSA(evpPkey));
    ExpectIntEQ(RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH,
        signature, &signatureLength, pKey), SSL_SUCCESS);

    /* read public key and verify signed data */
    ExpectTrue((fp = XFOPEN(svrCertFile,"rb")) != XBADFILE);
    ExpectNotNull(cert = PEM_read_X509(fp, 0, 0, 0 ));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectNull(X509_get_pubkey(NULL));
    ExpectNotNull(evpPubkey = X509_get_pubkey(cert));
    ExpectNotNull(pubKey = EVP_PKEY_get1_RSA(evpPubkey));
    ExpectIntEQ(RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature,
        signatureLength, pubKey), SSL_SUCCESS);

    ExpectIntEQ(RSA_verify(NID_sha256, NULL, SHA256_DIGEST_LENGTH, NULL,
        signatureLength, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(RSA_verify(NID_sha256, NULL, SHA256_DIGEST_LENGTH, signature,
        signatureLength, pubKey), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, NULL,
        signatureLength, pubKey), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature,
        signatureLength, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));


    RSA_free(pKey);
    EVP_PKEY_free(evpPkey);
    RSA_free(pubKey);
    EVP_PKEY_free(evpPubkey);
    X509_free(cert);
    BIO_free(bio);
    XFREE(buf, NULL, DYNAMIC_TYPE_FILE);
#endif
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_sign(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa;
    unsigned char hash[SHA256_DIGEST_LENGTH];
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
    const unsigned char* pubDer = client_keypub_der_1024;
    size_t pubDerSz = sizeof_client_keypub_der_1024;
    unsigned char signature[1024/8];
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
    const unsigned char* pubDer = client_keypub_der_2048;
    size_t pubDerSz = sizeof_client_keypub_der_2048;
    unsigned char signature[2048/8];
#endif
    unsigned int signatureLen;
    const unsigned char* der;

    XMEMSET(hash, 0, sizeof(hash));

    der = privDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    /* Invalid parameters. */
    ExpectIntEQ(RSA_sign(NID_rsaEncryption, NULL, 0, NULL, NULL, NULL), 0);
    ExpectIntEQ(RSA_sign(NID_rsaEncryption, hash, sizeof(hash), signature,
        &signatureLen, rsa), 0);
    ExpectIntEQ(RSA_sign(NID_sha256, NULL, sizeof(hash), signature,
        &signatureLen, rsa), 0);
    ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), NULL,
        &signatureLen, rsa), 0);
    ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
        NULL, rsa), 0);
    ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, NULL), 0);

    ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, rsa), 1);

    RSA_free(rsa);
    der = pubDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPublicKey(&rsa, &der, pubDerSz));

    ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
        signatureLen, rsa), 1);

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_sign_ex(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
    const unsigned char* pubDer = client_keypub_der_1024;
    size_t pubDerSz = sizeof_client_keypub_der_1024;
    unsigned char signature[1024/8];
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
    const unsigned char* pubDer = client_keypub_der_2048;
    size_t pubDerSz = sizeof_client_keypub_der_2048;
    unsigned char signature[2048/8];
#endif
    unsigned int signatureLen;
    const unsigned char* der;
    unsigned char encodedHash[51];
    unsigned int encodedHashLen;
    const unsigned char expEncHash[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
        /* Hash data */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    XMEMSET(hash, 0, sizeof(hash));

    ExpectNotNull(rsa = wolfSSL_RSA_new());
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, rsa, 1), 0);
    wolfSSL_RSA_free(rsa);

    der = privDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_rsaEncryption,NULL, 0, NULL, NULL, NULL,
        -1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_rsaEncryption, hash, sizeof(hash),
        signature, &signatureLen, rsa, 1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, NULL, sizeof(hash), signature,
        &signatureLen, rsa, 1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), NULL,
        &signatureLen, rsa, 1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        NULL, rsa, 1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, NULL, 1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, rsa, -1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, NULL, sizeof(hash), signature,
        &signatureLen, rsa, 0), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), NULL,
        &signatureLen, rsa, 0), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        NULL, rsa, 0), 0);

    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, rsa, 1), 1);
    /* Test returning encoded hash. */
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), encodedHash,
        &encodedHashLen, rsa, 0), 1);
    ExpectIntEQ(encodedHashLen, sizeof(expEncHash));
    ExpectIntEQ(XMEMCMP(encodedHash, expEncHash, sizeof(expEncHash)), 0);

    RSA_free(rsa);
    der = pubDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPublicKey(&rsa, &der, pubDerSz));

    ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
        signatureLen, rsa), 1);

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}


static int test_wolfSSL_RSA_public_decrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa;
    unsigned char msg[SHA256_DIGEST_LENGTH];
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* pubDer = client_keypub_der_1024;
    size_t pubDerSz = sizeof_client_keypub_der_1024;
    unsigned char decMsg[1024/8];
    const unsigned char encMsg[] = {
        0x45, 0x8e, 0x6e, 0x7a, 0x9c, 0xe1, 0x67, 0x36,
        0x72, 0xfc, 0x9d, 0x05, 0xdf, 0xc2, 0xaf, 0x54,
        0xc5, 0x2f, 0x94, 0xb8, 0xc7, 0x82, 0x40, 0xfa,
        0xa7, 0x8c, 0xb1, 0x89, 0x40, 0xc3, 0x59, 0x5a,
        0x77, 0x08, 0x54, 0x93, 0x43, 0x7f, 0xc4, 0xb7,
        0xc4, 0x78, 0xf1, 0xf8, 0xab, 0xbf, 0xc2, 0x81,
        0x5d, 0x97, 0xea, 0x7a, 0x60, 0x90, 0x51, 0xb7,
        0x47, 0x78, 0x48, 0x1e, 0x88, 0x6b, 0x89, 0xde,
        0xce, 0x41, 0x41, 0xae, 0x49, 0xf6, 0xfd, 0x2d,
        0x2d, 0x9c, 0x70, 0x7d, 0xf9, 0xcf, 0x77, 0x5f,
        0x06, 0xc7, 0x20, 0xe3, 0x57, 0xd4, 0xd8, 0x1a,
        0x96, 0xa2, 0x39, 0xb0, 0x6e, 0x8e, 0x68, 0xf8,
        0x57, 0x7b, 0x26, 0x88, 0x17, 0xc4, 0xb7, 0xf1,
        0x59, 0xfa, 0xb6, 0x95, 0xdd, 0x1e, 0xe8, 0xd8,
        0x4e, 0xbd, 0xcd, 0x41, 0xad, 0xc7, 0xe2, 0x39,
        0xb8, 0x00, 0xca, 0xf5, 0x59, 0xdf, 0xf8, 0x43
    };
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2)) && \
    defined(WC_RSA_NO_PADDING)
    const unsigned char encMsgNoPad[] = {
        0x0d, 0x41, 0x5a, 0xc7, 0x60, 0xd7, 0xbe, 0xb6,
        0x42, 0xd1, 0x65, 0xb1, 0x7e, 0x59, 0x54, 0xcc,
        0x76, 0x62, 0xd0, 0x2f, 0x4d, 0xe3, 0x23, 0x62,
        0xc8, 0x14, 0xfe, 0x5e, 0xa1, 0xc7, 0x05, 0xee,
        0x9e, 0x28, 0x2e, 0xf5, 0xfd, 0xa4, 0xc0, 0x43,
        0x55, 0xa2, 0x6b, 0x6b, 0x16, 0xa7, 0x63, 0x06,
        0xa7, 0x78, 0x4f, 0xda, 0xae, 0x10, 0x6d, 0xd1,
        0x2e, 0x1d, 0xbb, 0xbc, 0xc4, 0x1d, 0x82, 0xe4,
        0xc6, 0x76, 0x77, 0xa6, 0x0a, 0xef, 0xd2, 0x89,
        0xff, 0x30, 0x85, 0x22, 0xa0, 0x68, 0x88, 0x54,
        0xa3, 0xd1, 0x92, 0xd1, 0x3f, 0x57, 0xe4, 0xc7,
        0x43, 0x5a, 0x8b, 0xb3, 0x86, 0xaf, 0xd5, 0x6d,
        0x07, 0xe1, 0xa0, 0x5f, 0xe1, 0x9a, 0x06, 0xba,
        0x56, 0xd2, 0xb0, 0x73, 0xf5, 0xb3, 0xd0, 0x5f,
        0xc0, 0xbf, 0x22, 0x4c, 0x54, 0x4e, 0x11, 0xe2,
        0xc5, 0xf8, 0x66, 0x39, 0x9d, 0x70, 0x90, 0x31
    };
#endif
#else
    const unsigned char* pubDer = client_keypub_der_2048;
    size_t pubDerSz = sizeof_client_keypub_der_2048;
    unsigned char decMsg[2048/8];
    const unsigned char encMsg[] = {
        0x16, 0x5d, 0xbb, 0x00, 0x38, 0x73, 0x01, 0x34,
        0xca, 0x59, 0xc6, 0x8b, 0x64, 0x70, 0x89, 0xf5,
        0x50, 0x2d, 0x1d, 0x69, 0x1f, 0x07, 0x1e, 0x31,
        0xae, 0x9b, 0xa6, 0x6e, 0xee, 0x80, 0xd9, 0x9e,
        0x59, 0x33, 0x70, 0x30, 0x28, 0x42, 0x7d, 0x24,
        0x36, 0x95, 0x6b, 0xf9, 0x0a, 0x23, 0xcb, 0xce,
        0x66, 0xa5, 0x07, 0x5e, 0x11, 0xa7, 0xdc, 0xfb,
        0xd9, 0xc2, 0x51, 0xf0, 0x05, 0xc9, 0x39, 0xb3,
        0xae, 0xff, 0xfb, 0xe9, 0xb1, 0x9a, 0x54, 0xac,
        0x1d, 0xca, 0x42, 0x1a, 0xfd, 0x7c, 0x97, 0xa0,
        0x60, 0x2b, 0xcd, 0xb6, 0x36, 0x33, 0xfc, 0x44,
        0x69, 0xf7, 0x2e, 0x8c, 0x3b, 0x5f, 0xb4, 0x9f,
        0xa7, 0x02, 0x8f, 0x6d, 0x6b, 0x79, 0x10, 0x32,
        0x7d, 0xf4, 0x5d, 0xa1, 0x63, 0x22, 0x59, 0xc4,
        0x44, 0x8e, 0x44, 0x24, 0x8b, 0x14, 0x9d, 0x2b,
        0xb5, 0xd3, 0xad, 0x9a, 0x87, 0x0d, 0xe7, 0x70,
        0x6d, 0xe9, 0xae, 0xaa, 0x52, 0xbf, 0x1a, 0x9b,
        0xc8, 0x3d, 0x45, 0x7c, 0xd1, 0x90, 0xe3, 0xd9,
        0x57, 0xcf, 0xc3, 0x29, 0x69, 0x05, 0x07, 0x96,
        0x2e, 0x46, 0x74, 0x0a, 0xa7, 0x76, 0x8b, 0xc0,
        0x1c, 0x04, 0x80, 0x08, 0xa0, 0x94, 0x7e, 0xbb,
        0x2d, 0x99, 0xe9, 0xab, 0x18, 0x4d, 0x48, 0x2d,
        0x94, 0x5e, 0x50, 0x21, 0x42, 0xdf, 0xf5, 0x61,
        0x42, 0x7d, 0x86, 0x5d, 0x9e, 0x89, 0xc9, 0x5b,
        0x24, 0xab, 0xa1, 0xd8, 0x20, 0x45, 0xcb, 0x81,
        0xcf, 0xc5, 0x25, 0x7d, 0x11, 0x6e, 0xbd, 0x80,
        0xac, 0xba, 0xdc, 0xef, 0xb9, 0x05, 0x9c, 0xd5,
        0xc2, 0x26, 0x57, 0x69, 0x8b, 0x08, 0x27, 0xc7,
        0xea, 0xbe, 0xaf, 0x52, 0x21, 0x95, 0x9f, 0xa0,
        0x2f, 0x2f, 0x53, 0x7c, 0x2f, 0xa3, 0x0b, 0x79,
        0x39, 0x01, 0xa3, 0x37, 0x46, 0xa8, 0xc4, 0x34,
        0x41, 0x20, 0x7c, 0x3f, 0x70, 0x9a, 0x47, 0xe8
    };
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2)) && \
    defined(WC_RSA_NO_PADDING)
    const unsigned char encMsgNoPad[] = {
        0x79, 0x69, 0xdc, 0x0d, 0xff, 0x09, 0xeb, 0x91,
        0xbc, 0xda, 0xe4, 0xd3, 0xcd, 0xd5, 0xd3, 0x1c,
        0xb9, 0x66, 0xa8, 0x02, 0xf3, 0x75, 0x40, 0xf1,
        0x38, 0x4a, 0x37, 0x7b, 0x19, 0xc8, 0xcd, 0xea,
        0x79, 0xa8, 0x51, 0x32, 0x00, 0x3f, 0x4c, 0xde,
        0xaa, 0xe5, 0xe2, 0x7c, 0x10, 0xcd, 0x6e, 0x00,
        0xc6, 0xc4, 0x63, 0x98, 0x58, 0x9b, 0x38, 0xca,
        0xf0, 0x5d, 0xc8, 0xf0, 0x57, 0xf6, 0x21, 0x50,
        0x3f, 0x63, 0x05, 0x9f, 0xbf, 0xb6, 0x3b, 0x50,
        0x85, 0x06, 0x34, 0x08, 0x57, 0xb9, 0x44, 0xce,
        0xe4, 0x66, 0xbf, 0x0c, 0xfe, 0x36, 0xa4, 0x5b,
        0xed, 0x2d, 0x7d, 0xed, 0xf1, 0xbd, 0xda, 0x3e,
        0x19, 0x1f, 0x99, 0xc8, 0xe4, 0xc2, 0xbb, 0xb5,
        0x6c, 0x83, 0x22, 0xd1, 0xe7, 0x57, 0xcf, 0x1b,
        0x91, 0x0c, 0xa5, 0x47, 0x06, 0x71, 0x8f, 0x93,
        0xf3, 0xad, 0xdb, 0xe3, 0xf8, 0xa0, 0x0b, 0xcd,
        0x89, 0x4e, 0xa5, 0xb5, 0x03, 0x68, 0x61, 0x89,
        0x0b, 0xe2, 0x03, 0x8b, 0x1f, 0x54, 0xae, 0x0f,
        0xfa, 0xf0, 0xb7, 0x0f, 0x8c, 0x84, 0x35, 0x13,
        0x8d, 0x65, 0x1f, 0x2c, 0xd5, 0xce, 0xc4, 0x6c,
        0x98, 0x67, 0xe4, 0x1a, 0x85, 0x67, 0x69, 0x17,
        0x17, 0x5a, 0x5d, 0xfd, 0x23, 0xdd, 0x03, 0x3f,
        0x6d, 0x7a, 0xb6, 0x8b, 0x99, 0xc0, 0xb6, 0x70,
        0x86, 0xac, 0xf6, 0x02, 0xc2, 0x28, 0x42, 0xed,
        0x06, 0xcf, 0xca, 0x3d, 0x07, 0x16, 0xf0, 0x0e,
        0x04, 0x55, 0x1e, 0x59, 0x3f, 0x32, 0xc7, 0x12,
        0xc5, 0x0d, 0x9d, 0x64, 0x7d, 0x2e, 0xd4, 0xbc,
        0x8c, 0x24, 0x42, 0x94, 0x2b, 0xf6, 0x11, 0x7f,
        0xb1, 0x1c, 0x09, 0x12, 0x6f, 0x5e, 0x2e, 0x7a,
        0xc6, 0x01, 0xe0, 0x98, 0x31, 0xb7, 0x13, 0x03,
        0xce, 0x29, 0xe1, 0xef, 0x9d, 0xdf, 0x9b, 0xa5,
        0xba, 0x0b, 0xad, 0xf2, 0xeb, 0x2f, 0xf9, 0xd1
    };
#endif
#endif
    const unsigned char* der;
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2)) && \
    defined(WC_RSA_NO_PADDING)
    int i;
#endif

    XMEMSET(msg, 0, sizeof(msg));

    der = pubDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPublicKey(&rsa, &der, pubDerSz));

    ExpectIntEQ(RSA_public_decrypt(0, NULL, NULL, NULL, 0), -1);
    ExpectIntEQ(RSA_public_decrypt(-1, encMsg, decMsg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsg), NULL, decMsg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsg), encMsg, NULL, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsg), encMsg, decMsg, NULL,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsg), encMsg, decMsg, rsa,
        RSA_PKCS1_PSS_PADDING), -1);

    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsg), encMsg, decMsg, rsa,
        RSA_PKCS1_PADDING), 32);
    ExpectIntEQ(XMEMCMP(decMsg, msg, sizeof(msg)), 0);

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2)) && \
    defined(WC_RSA_NO_PADDING)
    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsgNoPad), encMsgNoPad, decMsg,
        rsa, RSA_NO_PADDING), sizeof(decMsg));
    /* Zeros before actual data. */
    for (i = 0; i < (int)(sizeof(decMsg) - sizeof(msg)); i += sizeof(msg)) {
        ExpectIntEQ(XMEMCMP(decMsg + i, msg, sizeof(msg)), 0);
    }
    /* Check actual data. */
    XMEMSET(msg, 0x01, sizeof(msg));
    ExpectIntEQ(XMEMCMP(decMsg + i, msg, sizeof(msg)), 0);
#endif

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_private_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa;
    unsigned char msg[SHA256_DIGEST_LENGTH];
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
    unsigned char encMsg[1024/8];
    const unsigned char expEncMsg[] = {
        0x45, 0x8e, 0x6e, 0x7a, 0x9c, 0xe1, 0x67, 0x36,
        0x72, 0xfc, 0x9d, 0x05, 0xdf, 0xc2, 0xaf, 0x54,
        0xc5, 0x2f, 0x94, 0xb8, 0xc7, 0x82, 0x40, 0xfa,
        0xa7, 0x8c, 0xb1, 0x89, 0x40, 0xc3, 0x59, 0x5a,
        0x77, 0x08, 0x54, 0x93, 0x43, 0x7f, 0xc4, 0xb7,
        0xc4, 0x78, 0xf1, 0xf8, 0xab, 0xbf, 0xc2, 0x81,
        0x5d, 0x97, 0xea, 0x7a, 0x60, 0x90, 0x51, 0xb7,
        0x47, 0x78, 0x48, 0x1e, 0x88, 0x6b, 0x89, 0xde,
        0xce, 0x41, 0x41, 0xae, 0x49, 0xf6, 0xfd, 0x2d,
        0x2d, 0x9c, 0x70, 0x7d, 0xf9, 0xcf, 0x77, 0x5f,
        0x06, 0xc7, 0x20, 0xe3, 0x57, 0xd4, 0xd8, 0x1a,
        0x96, 0xa2, 0x39, 0xb0, 0x6e, 0x8e, 0x68, 0xf8,
        0x57, 0x7b, 0x26, 0x88, 0x17, 0xc4, 0xb7, 0xf1,
        0x59, 0xfa, 0xb6, 0x95, 0xdd, 0x1e, 0xe8, 0xd8,
        0x4e, 0xbd, 0xcd, 0x41, 0xad, 0xc7, 0xe2, 0x39,
        0xb8, 0x00, 0xca, 0xf5, 0x59, 0xdf, 0xf8, 0x43
    };
#ifdef WC_RSA_NO_PADDING
    const unsigned char expEncMsgNoPad[] = {
        0x0d, 0x41, 0x5a, 0xc7, 0x60, 0xd7, 0xbe, 0xb6,
        0x42, 0xd1, 0x65, 0xb1, 0x7e, 0x59, 0x54, 0xcc,
        0x76, 0x62, 0xd0, 0x2f, 0x4d, 0xe3, 0x23, 0x62,
        0xc8, 0x14, 0xfe, 0x5e, 0xa1, 0xc7, 0x05, 0xee,
        0x9e, 0x28, 0x2e, 0xf5, 0xfd, 0xa4, 0xc0, 0x43,
        0x55, 0xa2, 0x6b, 0x6b, 0x16, 0xa7, 0x63, 0x06,
        0xa7, 0x78, 0x4f, 0xda, 0xae, 0x10, 0x6d, 0xd1,
        0x2e, 0x1d, 0xbb, 0xbc, 0xc4, 0x1d, 0x82, 0xe4,
        0xc6, 0x76, 0x77, 0xa6, 0x0a, 0xef, 0xd2, 0x89,
        0xff, 0x30, 0x85, 0x22, 0xa0, 0x68, 0x88, 0x54,
        0xa3, 0xd1, 0x92, 0xd1, 0x3f, 0x57, 0xe4, 0xc7,
        0x43, 0x5a, 0x8b, 0xb3, 0x86, 0xaf, 0xd5, 0x6d,
        0x07, 0xe1, 0xa0, 0x5f, 0xe1, 0x9a, 0x06, 0xba,
        0x56, 0xd2, 0xb0, 0x73, 0xf5, 0xb3, 0xd0, 0x5f,
        0xc0, 0xbf, 0x22, 0x4c, 0x54, 0x4e, 0x11, 0xe2,
        0xc5, 0xf8, 0x66, 0x39, 0x9d, 0x70, 0x90, 0x31
    };
#endif
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
    unsigned char encMsg[2048/8];
    const unsigned char expEncMsg[] = {
        0x16, 0x5d, 0xbb, 0x00, 0x38, 0x73, 0x01, 0x34,
        0xca, 0x59, 0xc6, 0x8b, 0x64, 0x70, 0x89, 0xf5,
        0x50, 0x2d, 0x1d, 0x69, 0x1f, 0x07, 0x1e, 0x31,
        0xae, 0x9b, 0xa6, 0x6e, 0xee, 0x80, 0xd9, 0x9e,
        0x59, 0x33, 0x70, 0x30, 0x28, 0x42, 0x7d, 0x24,
        0x36, 0x95, 0x6b, 0xf9, 0x0a, 0x23, 0xcb, 0xce,
        0x66, 0xa5, 0x07, 0x5e, 0x11, 0xa7, 0xdc, 0xfb,
        0xd9, 0xc2, 0x51, 0xf0, 0x05, 0xc9, 0x39, 0xb3,
        0xae, 0xff, 0xfb, 0xe9, 0xb1, 0x9a, 0x54, 0xac,
        0x1d, 0xca, 0x42, 0x1a, 0xfd, 0x7c, 0x97, 0xa0,
        0x60, 0x2b, 0xcd, 0xb6, 0x36, 0x33, 0xfc, 0x44,
        0x69, 0xf7, 0x2e, 0x8c, 0x3b, 0x5f, 0xb4, 0x9f,
        0xa7, 0x02, 0x8f, 0x6d, 0x6b, 0x79, 0x10, 0x32,
        0x7d, 0xf4, 0x5d, 0xa1, 0x63, 0x22, 0x59, 0xc4,
        0x44, 0x8e, 0x44, 0x24, 0x8b, 0x14, 0x9d, 0x2b,
        0xb5, 0xd3, 0xad, 0x9a, 0x87, 0x0d, 0xe7, 0x70,
        0x6d, 0xe9, 0xae, 0xaa, 0x52, 0xbf, 0x1a, 0x9b,
        0xc8, 0x3d, 0x45, 0x7c, 0xd1, 0x90, 0xe3, 0xd9,
        0x57, 0xcf, 0xc3, 0x29, 0x69, 0x05, 0x07, 0x96,
        0x2e, 0x46, 0x74, 0x0a, 0xa7, 0x76, 0x8b, 0xc0,
        0x1c, 0x04, 0x80, 0x08, 0xa0, 0x94, 0x7e, 0xbb,
        0x2d, 0x99, 0xe9, 0xab, 0x18, 0x4d, 0x48, 0x2d,
        0x94, 0x5e, 0x50, 0x21, 0x42, 0xdf, 0xf5, 0x61,
        0x42, 0x7d, 0x86, 0x5d, 0x9e, 0x89, 0xc9, 0x5b,
        0x24, 0xab, 0xa1, 0xd8, 0x20, 0x45, 0xcb, 0x81,
        0xcf, 0xc5, 0x25, 0x7d, 0x11, 0x6e, 0xbd, 0x80,
        0xac, 0xba, 0xdc, 0xef, 0xb9, 0x05, 0x9c, 0xd5,
        0xc2, 0x26, 0x57, 0x69, 0x8b, 0x08, 0x27, 0xc7,
        0xea, 0xbe, 0xaf, 0x52, 0x21, 0x95, 0x9f, 0xa0,
        0x2f, 0x2f, 0x53, 0x7c, 0x2f, 0xa3, 0x0b, 0x79,
        0x39, 0x01, 0xa3, 0x37, 0x46, 0xa8, 0xc4, 0x34,
        0x41, 0x20, 0x7c, 0x3f, 0x70, 0x9a, 0x47, 0xe8
    };
#ifdef WC_RSA_NO_PADDING
    const unsigned char expEncMsgNoPad[] = {
        0x79, 0x69, 0xdc, 0x0d, 0xff, 0x09, 0xeb, 0x91,
        0xbc, 0xda, 0xe4, 0xd3, 0xcd, 0xd5, 0xd3, 0x1c,
        0xb9, 0x66, 0xa8, 0x02, 0xf3, 0x75, 0x40, 0xf1,
        0x38, 0x4a, 0x37, 0x7b, 0x19, 0xc8, 0xcd, 0xea,
        0x79, 0xa8, 0x51, 0x32, 0x00, 0x3f, 0x4c, 0xde,
        0xaa, 0xe5, 0xe2, 0x7c, 0x10, 0xcd, 0x6e, 0x00,
        0xc6, 0xc4, 0x63, 0x98, 0x58, 0x9b, 0x38, 0xca,
        0xf0, 0x5d, 0xc8, 0xf0, 0x57, 0xf6, 0x21, 0x50,
        0x3f, 0x63, 0x05, 0x9f, 0xbf, 0xb6, 0x3b, 0x50,
        0x85, 0x06, 0x34, 0x08, 0x57, 0xb9, 0x44, 0xce,
        0xe4, 0x66, 0xbf, 0x0c, 0xfe, 0x36, 0xa4, 0x5b,
        0xed, 0x2d, 0x7d, 0xed, 0xf1, 0xbd, 0xda, 0x3e,
        0x19, 0x1f, 0x99, 0xc8, 0xe4, 0xc2, 0xbb, 0xb5,
        0x6c, 0x83, 0x22, 0xd1, 0xe7, 0x57, 0xcf, 0x1b,
        0x91, 0x0c, 0xa5, 0x47, 0x06, 0x71, 0x8f, 0x93,
        0xf3, 0xad, 0xdb, 0xe3, 0xf8, 0xa0, 0x0b, 0xcd,
        0x89, 0x4e, 0xa5, 0xb5, 0x03, 0x68, 0x61, 0x89,
        0x0b, 0xe2, 0x03, 0x8b, 0x1f, 0x54, 0xae, 0x0f,
        0xfa, 0xf0, 0xb7, 0x0f, 0x8c, 0x84, 0x35, 0x13,
        0x8d, 0x65, 0x1f, 0x2c, 0xd5, 0xce, 0xc4, 0x6c,
        0x98, 0x67, 0xe4, 0x1a, 0x85, 0x67, 0x69, 0x17,
        0x17, 0x5a, 0x5d, 0xfd, 0x23, 0xdd, 0x03, 0x3f,
        0x6d, 0x7a, 0xb6, 0x8b, 0x99, 0xc0, 0xb6, 0x70,
        0x86, 0xac, 0xf6, 0x02, 0xc2, 0x28, 0x42, 0xed,
        0x06, 0xcf, 0xca, 0x3d, 0x07, 0x16, 0xf0, 0x0e,
        0x04, 0x55, 0x1e, 0x59, 0x3f, 0x32, 0xc7, 0x12,
        0xc5, 0x0d, 0x9d, 0x64, 0x7d, 0x2e, 0xd4, 0xbc,
        0x8c, 0x24, 0x42, 0x94, 0x2b, 0xf6, 0x11, 0x7f,
        0xb1, 0x1c, 0x09, 0x12, 0x6f, 0x5e, 0x2e, 0x7a,
        0xc6, 0x01, 0xe0, 0x98, 0x31, 0xb7, 0x13, 0x03,
        0xce, 0x29, 0xe1, 0xef, 0x9d, 0xdf, 0x9b, 0xa5,
        0xba, 0x0b, 0xad, 0xf2, 0xeb, 0x2f, 0xf9, 0xd1
    };
#endif
#endif
    const unsigned char* der;

    XMEMSET(msg, 0x00, sizeof(msg));

    der = privDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(RSA_private_encrypt(0, NULL, NULL, NULL, 0), -1);
    ExpectIntEQ(RSA_private_encrypt(0, msg, encMsg, rsa, RSA_PKCS1_PADDING),
        -1);
    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), NULL, encMsg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), msg, NULL, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), msg, encMsg, NULL,
         RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), msg, encMsg, rsa,
         RSA_PKCS1_PSS_PADDING), -1);

    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), msg, encMsg, rsa,
         RSA_PKCS1_PADDING), sizeof(encMsg));
    ExpectIntEQ(XMEMCMP(encMsg, expEncMsg, sizeof(expEncMsg)), 0);

#ifdef WC_RSA_NO_PADDING
    /* Non-zero message. */
    XMEMSET(msg, 0x01, sizeof(msg));
    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), msg, encMsg, rsa,
         RSA_NO_PADDING), sizeof(encMsg));
    ExpectIntEQ(XMEMCMP(encMsg, expEncMsgNoPad, sizeof(expEncMsgNoPad)), 0);
#endif

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_public_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA* rsa = NULL;
    const unsigned char msg[2048/8] = { 0 };
    unsigned char encMsg[2048/8];

    ExpectNotNull(rsa = RSA_new());

    ExpectIntEQ(RSA_public_encrypt(-1, msg, encMsg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_encrypt(sizeof(msg), NULL, encMsg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_encrypt(sizeof(msg), msg, NULL, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_encrypt(sizeof(msg), msg, encMsg, NULL,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_encrypt(sizeof(msg), msg, encMsg, rsa,
        RSA_PKCS1_PSS_PADDING), -1);
    /* Empty RSA key. */
    ExpectIntEQ(RSA_public_encrypt(sizeof(msg), msg, encMsg, rsa,
        RSA_PKCS1_PADDING), -1);

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_private_decrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA* rsa = NULL;
    unsigned char msg[2048/8];
    const unsigned char encMsg[2048/8] = { 0 };

    ExpectNotNull(rsa = RSA_new());

    ExpectIntEQ(RSA_private_decrypt(-1, encMsg, msg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_decrypt(sizeof(encMsg), NULL, msg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_decrypt(sizeof(encMsg), encMsg, NULL, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_decrypt(sizeof(encMsg), encMsg, msg, NULL,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_decrypt(sizeof(encMsg), encMsg, msg, rsa,
        RSA_PKCS1_PSS_PADDING), -1);
    /* Empty RSA key. */
    ExpectIntEQ(RSA_private_decrypt(sizeof(encMsg), encMsg, msg, rsa,
        RSA_PKCS1_PADDING), -1);

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_GenAdd(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
    const unsigned char* pubDer = client_keypub_der_1024;
    size_t pubDerSz = sizeof_client_keypub_der_1024;
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
    const unsigned char* pubDer = client_keypub_der_2048;
    size_t pubDerSz = sizeof_client_keypub_der_2048;
#endif
    const unsigned char* der;

    der = privDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(wolfSSL_RSA_GenAdd(NULL), -1);
#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
    !defined(RSA_LOW_MEM)
    ExpectIntEQ(wolfSSL_RSA_GenAdd(rsa), 1);
#else
    /* dmp1 and dmq1 are not set (allocated) in this config */
    ExpectIntEQ(wolfSSL_RSA_GenAdd(rsa), -1);
#endif

    RSA_free(rsa);
    der = pubDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPublicKey(&rsa, &der, pubDerSz));
    /* Need private values. */
    ExpectIntEQ(wolfSSL_RSA_GenAdd(rsa), -1);

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_blinding_on(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_WOLFSSL_STUB)
    RSA *rsa;
    WOLFSSL_BN_CTX *bnCtx = NULL;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
#endif
    const unsigned char* der;

    der = privDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, privDerSz));
    ExpectNotNull(bnCtx = wolfSSL_BN_CTX_new());

    /* Does nothing so all parameters are valid. */
    ExpectIntEQ(wolfSSL_RSA_blinding_on(NULL, NULL), 1);
    ExpectIntEQ(wolfSSL_RSA_blinding_on(rsa, NULL), 1);
    ExpectIntEQ(wolfSSL_RSA_blinding_on(NULL, bnCtx), 1);
    ExpectIntEQ(wolfSSL_RSA_blinding_on(rsa, bnCtx), 1);

    wolfSSL_BN_CTX_free(bnCtx);
    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_ex_data(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA)
    RSA* rsa = NULL;
    unsigned char data[1];

    ExpectNotNull(rsa = RSA_new());

    ExpectNull(wolfSSL_RSA_get_ex_data(NULL, 0));
    ExpectNull(wolfSSL_RSA_get_ex_data(rsa, 0));
#ifdef MAX_EX_DATA
    ExpectNull(wolfSSL_RSA_get_ex_data(rsa, MAX_EX_DATA));
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(rsa, MAX_EX_DATA, data), 0);
#endif
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(NULL, 0, NULL), 0);
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(NULL, 0, data), 0);

#ifdef HAVE_EX_DATA
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(rsa, 0, NULL), 1);
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(rsa, 0, data), 1);
    ExpectPtrEq(wolfSSL_RSA_get_ex_data(rsa, 0), data);
#else
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(rsa, 0, NULL), 0);
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(rsa, 0, data), 0);
    ExpectNull(wolfSSL_RSA_get_ex_data(rsa, 0));
#endif

    RSA_free(rsa);
#endif /* !NO_RSA && OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

static int test_wolfSSL_RSA_LoadDer(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL))
    RSA *rsa = NULL;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
#endif

    ExpectNotNull(rsa = RSA_new());

    ExpectIntEQ(wolfSSL_RSA_LoadDer(NULL, privDer, (int)privDerSz), -1);
    ExpectIntEQ(wolfSSL_RSA_LoadDer(rsa, NULL, (int)privDerSz), -1);
    ExpectIntEQ(wolfSSL_RSA_LoadDer(rsa, privDer, 0), -1);

    ExpectIntEQ(wolfSSL_RSA_LoadDer(rsa, privDer, (int)privDerSz), 1);

    RSA_free(rsa);
#endif /* !NO_RSA && OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

/* Local API. */
static int test_wolfSSL_RSA_To_Der(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_TEST_STATIC_BUILD
#if defined(WOLFSSL_KEY_GEN) && defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA* rsa;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
    const unsigned char* pubDer = client_keypub_der_1024;
    size_t pubDerSz = sizeof_client_keypub_der_1024;
    unsigned char out[sizeof(client_key_der_1024)];
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
    const unsigned char* pubDer = client_keypub_der_2048;
    size_t pubDerSz = sizeof_client_keypub_der_2048;
    unsigned char out[sizeof(client_key_der_2048)];
#endif
    const unsigned char* der;
    unsigned char* outDer = NULL;

    der = privDer;
    rsa = NULL;
    ExpectNotNull(wolfSSL_d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(wolfSSL_RSA_To_Der(NULL, &outDer, 0, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 2, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, NULL, 0, HEAP_HINT), privDerSz);
    outDer = out;
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 0, HEAP_HINT), privDerSz);
    ExpectIntEQ(XMEMCMP(out, privDer, privDerSz), 0);
    outDer = NULL;
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 0, HEAP_HINT), privDerSz);
    ExpectNotNull(outDer);
    ExpectIntEQ(XMEMCMP(outDer, privDer, privDerSz), 0);
    XFREE(outDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, NULL, 1, HEAP_HINT), pubDerSz);
    outDer = out;
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 1, HEAP_HINT), pubDerSz);
    ExpectIntEQ(XMEMCMP(out, pubDer, pubDerSz), 0);

    RSA_free(rsa);

    ExpectNotNull(rsa = RSA_new());
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 0, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 1, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    RSA_free(rsa);

    der = pubDer;
    rsa = NULL;
    ExpectNotNull(wolfSSL_d2i_RSAPublicKey(&rsa, &der, pubDerSz));
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 0, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    RSA_free(rsa);
#endif
#endif
    return EXPECT_RESULT();
}

/* wolfSSL_PEM_read_RSAPublicKey is a stub function. */
static int test_wolfSSL_PEM_read_RSAPublicKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
    XFILE file = XBADFILE;
    const char* fname = "./certs/server-keyPub.pem";
    RSA *rsa = NULL;

    ExpectNull(wolfSSL_PEM_read_RSAPublicKey(XBADFILE, NULL, NULL, NULL));

    ExpectTrue((file = XFOPEN(fname, "rb")) != XBADFILE);
    ExpectNotNull(rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL));
    ExpectIntEQ(RSA_size(rsa), 256);
    RSA_free(rsa);
    if (file != XBADFILE)
        XFCLOSE(file);
#endif
    return EXPECT_RESULT();
}

/* wolfSSL_PEM_read_RSAPublicKey is a stub function. */
static int test_wolfSSL_PEM_write_RSA_PUBKEY(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && \
    defined(WOLFSSL_KEY_GEN)
    RSA* rsa = NULL;

    ExpectIntEQ(wolfSSL_PEM_write_RSA_PUBKEY(XBADFILE, NULL), 0);
    ExpectIntEQ(wolfSSL_PEM_write_RSA_PUBKEY(stderr, NULL), 0);
    /* Valid but stub so returns 0. */
    ExpectIntEQ(wolfSSL_PEM_write_RSA_PUBKEY(stderr, rsa), 0);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_PEM_write_RSAPrivateKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_KEY_GEN) && \
    (defined(WOLFSSL_PEM_TO_DER) || \
    defined(WOLFSSL_DER_TO_PEM)) && !defined(NO_FILESYSTEM)
    RSA* rsa = NULL;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
#endif
    const unsigned char* der;
#ifndef NO_AES
    unsigned char passwd[] = "password";
#endif

    ExpectNotNull(rsa = RSA_new());
    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(stderr, rsa, NULL, NULL, 0,
        NULL, NULL), 0);
    RSA_free(rsa);

    der = privDer;
    rsa = NULL;
    ExpectNotNull(wolfSSL_d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(XBADFILE, rsa, NULL, NULL, 0,
        NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(stderr, NULL, NULL, NULL, 0,
        NULL, NULL), 0);

    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(stderr, rsa, NULL, NULL, 0,
        NULL, NULL), 1);
#ifndef NO_AES
    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(stderr, rsa, EVP_aes_128_cbc(),
        NULL, 0, NULL, NULL), 1);
    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(stderr, rsa, EVP_aes_128_cbc(),
        passwd, sizeof(passwd) - 1, NULL, NULL), 1);
#endif
    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_PEM_write_mem_RSAPrivateKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_KEY_GEN) && \
    (defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM))
    RSA* rsa = NULL;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
#endif
    const unsigned char* der;
#ifndef NO_AES
    unsigned char passwd[] = "password";
#endif
    unsigned char* pem = NULL;
    int plen;

    ExpectNotNull(rsa = RSA_new());
    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, NULL, NULL, 0, &pem,
        &plen), 0);
    RSA_free(rsa);

    der = privDer;
    rsa = NULL;
    ExpectNotNull(wolfSSL_d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(NULL, NULL, NULL, 0, &pem,
        &plen), 0);
    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, NULL, NULL, 0, NULL,
        &plen), 0);
    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, NULL, NULL, 0, &pem,
        NULL), 0);

    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, NULL, NULL, 0, &pem,
        &plen), 1);
    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    pem = NULL;
#ifndef NO_AES
    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, EVP_aes_128_cbc(),
        NULL, 0, &pem, &plen), 1);
    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    pem = NULL;
    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, EVP_aes_128_cbc(),
        passwd, sizeof(passwd) - 1, &pem, &plen), 1);
    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
#endif

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_DH(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DH)
    DH *dh = NULL;
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* g;
    BIGNUM* pub = NULL;
    BIGNUM* priv = NULL;
#if defined(OPENSSL_ALL)
#if !defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    FILE* f = NULL;
    unsigned char buf[268];
    const unsigned char* pt = buf;
    long len = 0;

    dh = NULL;
    XMEMSET(buf, 0, sizeof(buf));
    /* Test 2048 bit parameters */
    ExpectTrue((f = XFOPEN("./certs/dh2048.der", "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectNotNull(dh = d2i_DHparams(NULL, &pt, len));
    ExpectNotNull(dh->p);
    ExpectNotNull(dh->g);
    ExpectTrue(pt == buf);
    ExpectIntEQ(DH_generate_key(dh), 1);

    /* first, test for expected successful key agreement. */
    if (EXPECT_SUCCESS()) {
        DH *dh2 = NULL;
        unsigned char buf2[268];
        int sz1 = 0, sz2 = 0;

        ExpectNotNull(dh2 = d2i_DHparams(NULL, &pt, len));
        ExpectIntEQ(DH_generate_key(dh2), 1);

        ExpectIntGT(sz1=DH_compute_key(buf, dh2->pub_key, dh), 0);
        ExpectIntGT(sz2=DH_compute_key(buf2, dh->pub_key, dh2), 0);
        ExpectIntEQ(sz1, sz2);
        ExpectIntEQ(XMEMCMP(buf, buf2, (size_t)sz1), 0);

        ExpectIntNE(sz1 = DH_size(dh), 0);
        ExpectIntEQ(DH_compute_key_padded(buf, dh2->pub_key, dh), sz1);
        ExpectIntEQ(DH_compute_key_padded(buf2, dh->pub_key, dh2), sz1);
        ExpectIntEQ(XMEMCMP(buf, buf2, (size_t)sz1), 0);

        if (dh2 != NULL)
            DH_free(dh2);
    }

    ExpectIntEQ(DH_generate_key(dh), 1);
    ExpectIntEQ(DH_compute_key(NULL, NULL, NULL), -1);
    ExpectNotNull(pub = BN_new());
    ExpectIntEQ(BN_set_word(pub, 1), 1);
    ExpectIntEQ(DH_compute_key(buf, NULL, NULL), -1);
    ExpectIntEQ(DH_compute_key(NULL, pub, NULL), -1);
    ExpectIntEQ(DH_compute_key(NULL, NULL, dh), -1);
    ExpectIntEQ(DH_compute_key(buf, pub, NULL), -1);
    ExpectIntEQ(DH_compute_key(buf, NULL, dh), -1);
    ExpectIntEQ(DH_compute_key(NULL, pub, dh), -1);
    ExpectIntEQ(DH_compute_key(buf, pub, dh), -1);
    BN_free(pub);
    pub = NULL;

    DH_get0_pqg(dh, (const BIGNUM**)&p,
                    (const BIGNUM**)&q,
                    (const BIGNUM**)&g);
    ExpectPtrEq(p, dh->p);
    ExpectPtrEq(q, dh->q);
    ExpectPtrEq(g, dh->g);
    DH_get0_key(NULL, (const BIGNUM**)&pub, (const BIGNUM**)&priv);
    DH_get0_key(dh, (const BIGNUM**)&pub, (const BIGNUM**)&priv);
    ExpectPtrEq(pub, dh->pub_key);
    ExpectPtrEq(priv, dh->priv_key);
    DH_get0_key(dh, (const BIGNUM**)&pub, NULL);
    ExpectPtrEq(pub, dh->pub_key);
    DH_get0_key(dh, NULL, (const BIGNUM**)&priv);
    ExpectPtrEq(priv, dh->priv_key);
    pub = NULL;
    priv = NULL;
    ExpectNotNull(pub = BN_new());
    ExpectNotNull(priv = BN_new());
    ExpectIntEQ(DH_set0_key(NULL, pub, priv), 0);
    ExpectIntEQ(DH_set0_key(dh, pub, priv), 1);
    if (EXPECT_FAIL()) {
        BN_free(pub);
        BN_free(priv);
    }
    pub = NULL;
    priv = NULL;
    ExpectNotNull(pub = BN_new());
    ExpectIntEQ(DH_set0_key(dh, pub, NULL), 1);
    if (EXPECT_FAIL()) {
        BN_free(pub);
    }
    ExpectNotNull(priv = BN_new());
    ExpectIntEQ(DH_set0_key(dh, NULL, priv), 1);
    if (EXPECT_FAIL()) {
        BN_free(priv);
    }
    ExpectPtrEq(pub, dh->pub_key);
    ExpectPtrEq(priv, dh->priv_key);
    pub = NULL;
    priv = NULL;

    DH_free(dh);
    dh = NULL;

    ExpectNotNull(dh = DH_new());
    p = NULL;
    ExpectNotNull(p = BN_new());
    ExpectIntEQ(BN_set_word(p, 1), 1);
    ExpectIntEQ(DH_compute_key(buf, p, dh), -1);
    ExpectNotNull(pub = BN_new());
    ExpectNotNull(priv = BN_new());
    ExpectIntEQ(DH_set0_key(dh, pub, priv), 1);
    if (EXPECT_FAIL()) {
        BN_free(pub);
        BN_free(priv);
    }
    pub = NULL;
    priv = NULL;
    ExpectIntEQ(DH_compute_key(buf, p, dh), -1);
    BN_free(p);
    p = NULL;
    DH_free(dh);
    dh = NULL;

#ifdef WOLFSSL_KEY_GEN
    ExpectNotNull(dh = DH_generate_parameters(2048, 2, NULL, NULL));
    ExpectIntEQ(wolfSSL_DH_generate_parameters_ex(NULL, 2048, 2, NULL), 0);
    DH_free(dh);
    dh = NULL;
#endif
#endif /* !HAVE_FIPS || (HAVE_FIPS_VERSION && HAVE_FIPS_VERSION > 2) */
#endif /* OPENSSL_ALL */

    (void)dh;
    (void)p;
    (void)q;
    (void)g;
    (void)pub;
    (void)priv;

    ExpectNotNull(dh = wolfSSL_DH_new());

    /* invalid parameters test */
    DH_get0_pqg(NULL, (const BIGNUM**)&p,
                      (const BIGNUM**)&q,
                      (const BIGNUM**)&g);

    DH_get0_pqg(dh, NULL,
                    (const BIGNUM**)&q,
                    (const BIGNUM**)&g);

    DH_get0_pqg(dh, NULL, NULL, (const BIGNUM**)&g);

    DH_get0_pqg(dh, NULL, NULL, NULL);

    DH_get0_pqg(dh, (const BIGNUM**)&p,
                    (const BIGNUM**)&q,
                    (const BIGNUM**)&g);

    ExpectPtrEq(p, NULL);
    ExpectPtrEq(q, NULL);
    ExpectPtrEq(g, NULL);
    DH_free(dh);
    dh = NULL;

#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS) && !defined(WOLFSSL_DH_EXTRA)) \
 || (defined(HAVE_FIPS_VERSION) && FIPS_VERSION_GT(2,0))
#if defined(OPENSSL_ALL) || \
    defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    dh = wolfSSL_DH_new();
    ExpectNotNull(dh);
    p = wolfSSL_BN_new();
    ExpectNotNull(p);
    ExpectIntEQ(BN_set_word(p, 11), 1);
    g = wolfSSL_BN_new();
    ExpectNotNull(g);
    ExpectIntEQ(BN_set_word(g, 2), 1);
    q = wolfSSL_BN_new();
    ExpectNotNull(q);
    ExpectIntEQ(BN_set_word(q, 5), 1);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, NULL, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(NULL, p, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(NULL, NULL, q, NULL), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(NULL, NULL, NULL, g), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(NULL, p, q, g), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, NULL, q, g), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, q, NULL), 0);
    /* Don't need q. */
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, NULL, g), 1);
    if (EXPECT_FAIL()) {
        BN_free(p);
        BN_free(g);
    }
    p = NULL;
    g = NULL;
    /* Setting again will free the p and g. */
    wolfSSL_BN_free(q);
    q = NULL;
    DH_free(dh);
    dh = NULL;

    dh = wolfSSL_DH_new();
    ExpectNotNull(dh);

    p = wolfSSL_BN_new();
    ExpectNotNull(p);
    ExpectIntEQ(BN_set_word(p, 11), 1);
    g = wolfSSL_BN_new();
    ExpectNotNull(g);
    ExpectIntEQ(BN_set_word(g, 2), 1);
    q = wolfSSL_BN_new();
    ExpectNotNull(q);
    ExpectIntEQ(BN_set_word(q, 5), 1);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, q, g), 1);
    /* p, q and g are now owned by dh - don't free. */
    if (EXPECT_FAIL()) {
        BN_free(p);
        BN_free(q);
        BN_free(g);
    }
    p = NULL;
    q = NULL;
    g = NULL;

    p = wolfSSL_BN_new();
    ExpectNotNull(p);
    ExpectIntEQ(BN_set_word(p, 11), 1);
    g = wolfSSL_BN_new();
    ExpectNotNull(g);
    ExpectIntEQ(BN_set_word(g, 2), 1);
    q = wolfSSL_BN_new();
    ExpectNotNull(q);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, NULL, NULL), 1);
    if (EXPECT_FAIL()) {
        BN_free(p);
    }
    p = NULL;
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, NULL, q, NULL), 1);
    if (EXPECT_FAIL()) {
        BN_free(q);
    }
    q = NULL;
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, NULL, NULL, g), 1);
    if (EXPECT_FAIL()) {
        BN_free(g);
    }
    g = NULL;
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, NULL, NULL, NULL), 1);
    /* p, q and g are now owned by dh - don't free. */

    DH_free(dh);
    dh = NULL;

    ExpectIntEQ(DH_generate_key(NULL), 0);
    ExpectNotNull(dh = DH_new());
    ExpectIntEQ(DH_generate_key(dh), 0);
    p = wolfSSL_BN_new();
    ExpectNotNull(p);
    ExpectIntEQ(BN_set_word(p, 0), 1);
    g = wolfSSL_BN_new();
    ExpectNotNull(g);
    ExpectIntEQ(BN_set_word(g, 2), 1);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, NULL, g), 1);
    if (EXPECT_FAIL()) {
        BN_free(p);
        BN_free(g);
    }
    p = NULL;
    g = NULL;
    ExpectIntEQ(DH_generate_key(dh), 0);
    DH_free(dh);
    dh = NULL;
#endif
#endif

    /* Test DH_up_ref() */
    dh = wolfSSL_DH_new();
    ExpectNotNull(dh);
    ExpectIntEQ(wolfSSL_DH_up_ref(NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_DH_up_ref(dh), WOLFSSL_SUCCESS);
    DH_free(dh); /* decrease ref count */
    DH_free(dh); /* free WOLFSSL_DH */
    dh = NULL;
    q = NULL;

    ExpectNull((dh = DH_new_by_nid(NID_sha1)));
#if (defined(HAVE_PUBLIC_FFDHE) || (defined(HAVE_FIPS) && \
    FIPS_VERSION_EQ(2,0))) || (!defined(HAVE_PUBLIC_FFDHE) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)))
#ifdef HAVE_FFDHE_2048
    ExpectNotNull((dh = DH_new_by_nid(NID_ffdhe2048)));
    DH_free(dh);
    dh = NULL;
    q = NULL;
#endif
#ifdef HAVE_FFDHE_3072
    ExpectNotNull((dh = DH_new_by_nid(NID_ffdhe3072)));
    DH_free(dh);
    dh = NULL;
    q = NULL;
#endif
#ifdef HAVE_FFDHE_4096
    ExpectNotNull((dh = DH_new_by_nid(NID_ffdhe4096)));
    DH_free(dh);
    dh = NULL;
    q = NULL;
#endif
#else
    ExpectNull((dh = DH_new_by_nid(NID_ffdhe2048)));
#endif /* (HAVE_PUBLIC_FFDHE || (HAVE_FIPS && HAVE_FIPS_VERSION == 2)) ||
        * (!HAVE_PUBLIC_FFDHE && (!HAVE_FIPS || HAVE_FIPS_VERSION > 2))*/

    ExpectIntEQ(wolfSSL_DH_size(NULL), -1);
#endif /* OPENSSL_EXTRA && !NO_DH */
    return EXPECT_RESULT();
}

static int test_wolfSSL_DH_dup(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || defined(WOLFSSL_OPENSSH) || \
    defined(OPENSSL_EXTRA)
    DH *dh = NULL;
    DH *dhDup = NULL;

    ExpectNotNull(dh = wolfSSL_DH_new());

    ExpectNull(dhDup = wolfSSL_DH_dup(NULL));
    ExpectNull(dhDup = wolfSSL_DH_dup(dh));

#if defined(OPENSSL_ALL) || \
    defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    {
        WOLFSSL_BIGNUM* p = NULL;
        WOLFSSL_BIGNUM* g = NULL;

        ExpectNotNull(p = wolfSSL_BN_new());
        ExpectNotNull(g = wolfSSL_BN_new());
        ExpectIntEQ(wolfSSL_BN_set_word(p, 11), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_BN_set_word(g, 2), WOLFSSL_SUCCESS);

        ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, NULL, g), 1);
        if (EXPECT_FAIL()) {
            wolfSSL_BN_free(p);
            wolfSSL_BN_free(g);
        }

        ExpectNotNull(dhDup = wolfSSL_DH_dup(dh));
        wolfSSL_DH_free(dhDup);
    }
#endif

    wolfSSL_DH_free(dh);
#endif
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_DH_check(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
#ifndef NO_DH
#ifndef NO_BIO
#ifndef NO_DSA
    byte buf[6000];
    char file[] = "./certs/dsaparams.pem";
    XFILE f = XBADFILE;
    int  bytes = 0;
    BIO* bio = NULL;
    DSA* dsa = NULL;
#elif !defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)
    static const byte dh2048[] = {
        0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01,
        0x00, 0xb0, 0xa1, 0x08, 0x06, 0x9c, 0x08, 0x13,
        0xba, 0x59, 0x06, 0x3c, 0xbc, 0x30, 0xd5, 0xf5,
        0x00, 0xc1, 0x4f, 0x44, 0xa7, 0xd6, 0xef, 0x4a,
        0xc6, 0x25, 0x27, 0x1c, 0xe8, 0xd2, 0x96, 0x53,
        0x0a, 0x5c, 0x91, 0xdd, 0xa2, 0xc2, 0x94, 0x84,
        0xbf, 0x7d, 0xb2, 0x44, 0x9f, 0x9b, 0xd2, 0xc1,
        0x8a, 0xc5, 0xbe, 0x72, 0x5c, 0xa7, 0xe7, 0x91,
        0xe6, 0xd4, 0x9f, 0x73, 0x07, 0x85, 0x5b, 0x66,
        0x48, 0xc7, 0x70, 0xfa, 0xb4, 0xee, 0x02, 0xc9,
        0x3d, 0x9a, 0x4a, 0xda, 0x3d, 0xc1, 0x46, 0x3e,
        0x19, 0x69, 0xd1, 0x17, 0x46, 0x07, 0xa3, 0x4d,
        0x9f, 0x2b, 0x96, 0x17, 0x39, 0x6d, 0x30, 0x8d,
        0x2a, 0xf3, 0x94, 0xd3, 0x75, 0xcf, 0xa0, 0x75,
        0xe6, 0xf2, 0x92, 0x1f, 0x1a, 0x70, 0x05, 0xaa,
        0x04, 0x83, 0x57, 0x30, 0xfb, 0xda, 0x76, 0x93,
        0x38, 0x50, 0xe8, 0x27, 0xfd, 0x63, 0xee, 0x3c,
        0xe5, 0xb7, 0xc8, 0x09, 0xae, 0x6f, 0x50, 0x35,
        0x8e, 0x84, 0xce, 0x4a, 0x00, 0xe9, 0x12, 0x7e,
        0x5a, 0x31, 0xd7, 0x33, 0xfc, 0x21, 0x13, 0x76,
        0xcc, 0x16, 0x30, 0xdb, 0x0c, 0xfc, 0xc5, 0x62,
        0xa7, 0x35, 0xb8, 0xef, 0xb7, 0xb0, 0xac, 0xc0,
        0x36, 0xf6, 0xd9, 0xc9, 0x46, 0x48, 0xf9, 0x40,
        0x90, 0x00, 0x2b, 0x1b, 0xaa, 0x6c, 0xe3, 0x1a,
        0xc3, 0x0b, 0x03, 0x9e, 0x1b, 0xc2, 0x46, 0xe4,
        0x48, 0x4e, 0x22, 0x73, 0x6f, 0xc3, 0x5f, 0xd4,
        0x9a, 0xd6, 0x30, 0x07, 0x48, 0xd6, 0x8c, 0x90,
        0xab, 0xd4, 0xf6, 0xf1, 0xe3, 0x48, 0xd3, 0x58,
        0x4b, 0xa6, 0xb9, 0xcd, 0x29, 0xbf, 0x68, 0x1f,
        0x08, 0x4b, 0x63, 0x86, 0x2f, 0x5c, 0x6b, 0xd6,
        0xb6, 0x06, 0x65, 0xf7, 0xa6, 0xdc, 0x00, 0x67,
        0x6b, 0xbb, 0xc3, 0xa9, 0x41, 0x83, 0xfb, 0xc7,
        0xfa, 0xc8, 0xe2, 0x1e, 0x7e, 0xaf, 0x00, 0x3f,
        0x93, 0x02, 0x01, 0x02
    };
    const byte* params;
#endif
    DH*  dh = NULL;
    WOLFSSL_BIGNUM* p = NULL;
    WOLFSSL_BIGNUM* g = NULL;
    WOLFSSL_BIGNUM* pTmp = NULL;
    WOLFSSL_BIGNUM* gTmp = NULL;
    int codes = -1;

#ifndef NO_DSA
    /* Initialize DH */
    ExpectTrue((f = XFOPEN(file, "rb")) != XBADFILE);
    ExpectIntGT(bytes = (int)XFREAD(buf, 1, sizeof(buf), f), 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectNotNull(bio = BIO_new_mem_buf((void*)buf, bytes));

    ExpectNotNull(dsa = wolfSSL_PEM_read_bio_DSAparams(bio, NULL, NULL, NULL));

    ExpectNotNull(dh = wolfSSL_DSA_dup_DH(dsa));
    ExpectNotNull(dh);

    BIO_free(bio);
    DSA_free(dsa);
#elif !defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)
    params = dh2048;
    ExpectNotNull(dh = wolfSSL_d2i_DHparams(NULL, &params,
        (long)sizeof(dh2048)));
#else
    ExpectNotNull(dh = wolfSSL_DH_new_by_nid(NID_ffdhe2048));
#endif

    /* Test assumed to be valid dh.
     * Should return WOLFSSL_SUCCESS
     * codes should be 0
     * Invalid codes = {DH_NOT_SUITABLE_GENERATOR, DH_CHECK_P_NOT_PRIME}
     */
    ExpectIntEQ(wolfSSL_DH_check(dh, &codes), 1);
    ExpectIntEQ(codes, 0);

    /* Test NULL dh: expected BAD_FUNC_ARG */
    ExpectIntEQ(wolfSSL_DH_check(NULL, &codes), 0);

    /* Break dh prime to test if codes = DH_CHECK_P_NOT_PRIME */
    if (dh != NULL) {
        pTmp = dh->p;
        dh->p  = NULL;
    }
    ExpectIntEQ(wolfSSL_DH_check(dh, &codes), 1);
    ExpectIntEQ(wolfSSL_DH_check(dh, NULL), 0);
    ExpectIntEQ(codes, DH_CHECK_P_NOT_PRIME);
    /* set dh->p back to normal so it won't fail on next tests */
    if (dh != NULL) {
        dh->p = pTmp;
        pTmp = NULL;
    }

    /* Break dh generator to test if codes = DH_NOT_SUITABLE_GENERATOR */
    if (dh != NULL) {
        gTmp = dh->g;
        dh->g = NULL;
    }
    ExpectIntEQ(wolfSSL_DH_check(dh, &codes), 1);
    ExpectIntEQ(wolfSSL_DH_check(dh, NULL), 0);
    ExpectIntEQ(codes, DH_NOT_SUITABLE_GENERATOR);
    if (dh != NULL) {
        dh->g = gTmp;
        gTmp = NULL;
    }

    /* Cleanup */
    DH_free(dh);
    dh = NULL;

    dh = DH_new();
    ExpectNotNull(dh);
    /* Check empty DH. */
    ExpectIntEQ(wolfSSL_DH_check(dh, &codes), 1);
    ExpectIntEQ(wolfSSL_DH_check(dh, NULL), 0);
    ExpectIntEQ(codes, DH_NOT_SUITABLE_GENERATOR | DH_CHECK_P_NOT_PRIME);
    /* Check non-prime valued p. */
    ExpectNotNull(p = BN_new());
    ExpectIntEQ(BN_set_word(p, 4), 1);
    ExpectNotNull(g = BN_new());
    ExpectIntEQ(BN_set_word(g, 2), 1);
    ExpectIntEQ(DH_set0_pqg(dh, p, NULL, g), 1);
    if (EXPECT_FAIL()) {
        wolfSSL_BN_free(p);
        wolfSSL_BN_free(g);
    }
    ExpectIntEQ(wolfSSL_DH_check(dh, &codes), 1);
    ExpectIntEQ(wolfSSL_DH_check(dh, NULL), 0);
    ExpectIntEQ(codes, DH_CHECK_P_NOT_PRIME);
    DH_free(dh);
    dh = NULL;
#endif
#endif /* !NO_DH  && !NO_DSA */
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_DH_prime(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DH)
    WOLFSSL_BIGNUM* bn = NULL;
#if WOLFSSL_MAX_BN_BITS >= 768
    WOLFSSL_BIGNUM* bn2 = NULL;
#endif

    bn = wolfSSL_DH_768_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 768
    ExpectNotNull(bn);
    bn2 = wolfSSL_DH_768_prime(bn);
    ExpectNotNull(bn2);
    ExpectTrue(bn == bn2);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif

    bn = wolfSSL_DH_1024_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 1024
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
    bn = wolfSSL_DH_2048_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 2048
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
    bn = wolfSSL_DH_3072_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 3072
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
    bn = wolfSSL_DH_4096_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 4096
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
    bn = wolfSSL_DH_6144_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 6144
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
    bn = wolfSSL_DH_8192_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 8192
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_DH_1536_prime(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DH)
    BIGNUM* bn = NULL;
    unsigned char bits[200];
    int sz = 192; /* known binary size */
    const byte expected[] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
        0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
        0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
        0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,
        0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
        0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,
        0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
        0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
        0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
        0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,
        0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
        0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,
        0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
        0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
        0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
        0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A,
        0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
        0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,
        0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
        0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
        0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
        0xF1,0x74,0x6C,0x08,0xCA,0x23,0x73,0x27,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    };

    ExpectNotNull(bn = get_rfc3526_prime_1536(NULL));
    ExpectIntEQ(sz, BN_bn2bin((const BIGNUM*)bn, bits));
    ExpectIntEQ(0, XMEMCMP(expected, bits, sz));

    BN_free(bn);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_DH_get_2048_256(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DH)
    WOLFSSL_DH* dh = NULL;
    const WOLFSSL_BIGNUM* pBn;
    const WOLFSSL_BIGNUM* gBn;
    const WOLFSSL_BIGNUM* qBn;
    const byte pExpected[] = {
        0x87, 0xA8, 0xE6, 0x1D, 0xB4, 0xB6, 0x66, 0x3C, 0xFF, 0xBB, 0xD1, 0x9C,
        0x65, 0x19, 0x59, 0x99, 0x8C, 0xEE, 0xF6, 0x08, 0x66, 0x0D, 0xD0, 0xF2,
        0x5D, 0x2C, 0xEE, 0xD4, 0x43, 0x5E, 0x3B, 0x00, 0xE0, 0x0D, 0xF8, 0xF1,
        0xD6, 0x19, 0x57, 0xD4, 0xFA, 0xF7, 0xDF, 0x45, 0x61, 0xB2, 0xAA, 0x30,
        0x16, 0xC3, 0xD9, 0x11, 0x34, 0x09, 0x6F, 0xAA, 0x3B, 0xF4, 0x29, 0x6D,
        0x83, 0x0E, 0x9A, 0x7C, 0x20, 0x9E, 0x0C, 0x64, 0x97, 0x51, 0x7A, 0xBD,
        0x5A, 0x8A, 0x9D, 0x30, 0x6B, 0xCF, 0x67, 0xED, 0x91, 0xF9, 0xE6, 0x72,
        0x5B, 0x47, 0x58, 0xC0, 0x22, 0xE0, 0xB1, 0xEF, 0x42, 0x75, 0xBF, 0x7B,
        0x6C, 0x5B, 0xFC, 0x11, 0xD4, 0x5F, 0x90, 0x88, 0xB9, 0x41, 0xF5, 0x4E,
        0xB1, 0xE5, 0x9B, 0xB8, 0xBC, 0x39, 0xA0, 0xBF, 0x12, 0x30, 0x7F, 0x5C,
        0x4F, 0xDB, 0x70, 0xC5, 0x81, 0xB2, 0x3F, 0x76, 0xB6, 0x3A, 0xCA, 0xE1,
        0xCA, 0xA6, 0xB7, 0x90, 0x2D, 0x52, 0x52, 0x67, 0x35, 0x48, 0x8A, 0x0E,
        0xF1, 0x3C, 0x6D, 0x9A, 0x51, 0xBF, 0xA4, 0xAB, 0x3A, 0xD8, 0x34, 0x77,
        0x96, 0x52, 0x4D, 0x8E, 0xF6, 0xA1, 0x67, 0xB5, 0xA4, 0x18, 0x25, 0xD9,
        0x67, 0xE1, 0x44, 0xE5, 0x14, 0x05, 0x64, 0x25, 0x1C, 0xCA, 0xCB, 0x83,
        0xE6, 0xB4, 0x86, 0xF6, 0xB3, 0xCA, 0x3F, 0x79, 0x71, 0x50, 0x60, 0x26,
        0xC0, 0xB8, 0x57, 0xF6, 0x89, 0x96, 0x28, 0x56, 0xDE, 0xD4, 0x01, 0x0A,
        0xBD, 0x0B, 0xE6, 0x21, 0xC3, 0xA3, 0x96, 0x0A, 0x54, 0xE7, 0x10, 0xC3,
        0x75, 0xF2, 0x63, 0x75, 0xD7, 0x01, 0x41, 0x03, 0xA4, 0xB5, 0x43, 0x30,
        0xC1, 0x98, 0xAF, 0x12, 0x61, 0x16, 0xD2, 0x27, 0x6E, 0x11, 0x71, 0x5F,
        0x69, 0x38, 0x77, 0xFA, 0xD7, 0xEF, 0x09, 0xCA, 0xDB, 0x09, 0x4A, 0xE9,
        0x1E, 0x1A, 0x15, 0x97
    };
    const byte gExpected[] = {
        0x3F, 0xB3, 0x2C, 0x9B, 0x73, 0x13, 0x4D, 0x0B, 0x2E, 0x77, 0x50, 0x66,
        0x60, 0xED, 0xBD, 0x48, 0x4C, 0xA7, 0xB1, 0x8F, 0x21, 0xEF, 0x20, 0x54,
        0x07, 0xF4, 0x79, 0x3A, 0x1A, 0x0B, 0xA1, 0x25, 0x10, 0xDB, 0xC1, 0x50,
        0x77, 0xBE, 0x46, 0x3F, 0xFF, 0x4F, 0xED, 0x4A, 0xAC, 0x0B, 0xB5, 0x55,
        0xBE, 0x3A, 0x6C, 0x1B, 0x0C, 0x6B, 0x47, 0xB1, 0xBC, 0x37, 0x73, 0xBF,
        0x7E, 0x8C, 0x6F, 0x62, 0x90, 0x12, 0x28, 0xF8, 0xC2, 0x8C, 0xBB, 0x18,
        0xA5, 0x5A, 0xE3, 0x13, 0x41, 0x00, 0x0A, 0x65, 0x01, 0x96, 0xF9, 0x31,
        0xC7, 0x7A, 0x57, 0xF2, 0xDD, 0xF4, 0x63, 0xE5, 0xE9, 0xEC, 0x14, 0x4B,
        0x77, 0x7D, 0xE6, 0x2A, 0xAA, 0xB8, 0xA8, 0x62, 0x8A, 0xC3, 0x76, 0xD2,
        0x82, 0xD6, 0xED, 0x38, 0x64, 0xE6, 0x79, 0x82, 0x42, 0x8E, 0xBC, 0x83,
        0x1D, 0x14, 0x34, 0x8F, 0x6F, 0x2F, 0x91, 0x93, 0xB5, 0x04, 0x5A, 0xF2,
        0x76, 0x71, 0x64, 0xE1, 0xDF, 0xC9, 0x67, 0xC1, 0xFB, 0x3F, 0x2E, 0x55,
        0xA4, 0xBD, 0x1B, 0xFF, 0xE8, 0x3B, 0x9C, 0x80, 0xD0, 0x52, 0xB9, 0x85,
        0xD1, 0x82, 0xEA, 0x0A, 0xDB, 0x2A, 0x3B, 0x73, 0x13, 0xD3, 0xFE, 0x14,
        0xC8, 0x48, 0x4B, 0x1E, 0x05, 0x25, 0x88, 0xB9, 0xB7, 0xD2, 0xBB, 0xD2,
        0xDF, 0x01, 0x61, 0x99, 0xEC, 0xD0, 0x6E, 0x15, 0x57, 0xCD, 0x09, 0x15,
        0xB3, 0x35, 0x3B, 0xBB, 0x64, 0xE0, 0xEC, 0x37, 0x7F, 0xD0, 0x28, 0x37,
        0x0D, 0xF9, 0x2B, 0x52, 0xC7, 0x89, 0x14, 0x28, 0xCD, 0xC6, 0x7E, 0xB6,
        0x18, 0x4B, 0x52, 0x3D, 0x1D, 0xB2, 0x46, 0xC3, 0x2F, 0x63, 0x07, 0x84,
        0x90, 0xF0, 0x0E, 0xF8, 0xD6, 0x47, 0xD1, 0x48, 0xD4, 0x79, 0x54, 0x51,
        0x5E, 0x23, 0x27, 0xCF, 0xEF, 0x98, 0xC5, 0x82, 0x66, 0x4B, 0x4C, 0x0F,
        0x6C, 0xC4, 0x16, 0x59
    };
    const byte qExpected[] = {
        0x8C, 0xF8, 0x36, 0x42, 0xA7, 0x09, 0xA0, 0x97, 0xB4, 0x47, 0x99, 0x76,
        0x40, 0x12, 0x9D, 0xA2, 0x99, 0xB1, 0xA4, 0x7D, 0x1E, 0xB3, 0x75, 0x0B,
        0xA3, 0x08, 0xB0, 0xFE, 0x64, 0xF5, 0xFB, 0xD3
    };
    int pSz = 0;
    int qSz = 0;
    int gSz = 0;
    byte* pReturned = NULL;
    byte* qReturned = NULL;
    byte* gReturned = NULL;

    ExpectNotNull((dh = wolfSSL_DH_get_2048_256()));
    wolfSSL_DH_get0_pqg(dh, &pBn, &qBn, &gBn);

    ExpectIntGT((pSz = wolfSSL_BN_num_bytes(pBn)), 0);
    ExpectNotNull(pReturned = (byte*)XMALLOC(pSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntGT((pSz = wolfSSL_BN_bn2bin(pBn, pReturned)), 0);
    ExpectIntEQ(pSz, sizeof(pExpected));
    ExpectIntEQ(XMEMCMP(pExpected, pReturned, pSz), 0);

    ExpectIntGT((qSz = wolfSSL_BN_num_bytes(qBn)), 0);
    ExpectNotNull(qReturned = (byte*)XMALLOC(qSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntGT((qSz = wolfSSL_BN_bn2bin(qBn, qReturned)), 0);
    ExpectIntEQ(qSz, sizeof(qExpected));
    ExpectIntEQ(XMEMCMP(qExpected, qReturned, qSz), 0);

    ExpectIntGT((gSz = wolfSSL_BN_num_bytes(gBn)), 0);
    ExpectNotNull(gReturned = (byte*)XMALLOC(gSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntGT((gSz = wolfSSL_BN_bn2bin(gBn, gReturned)), 0);
    ExpectIntEQ(gSz, sizeof(gExpected));
    ExpectIntEQ(XMEMCMP(gExpected, gReturned, gSz), 0);

    wolfSSL_DH_free(dh);
    XFREE(pReturned, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(gReturned, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(qReturned, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_PEM_write_DHparams(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO) && \
    !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA) && !defined(NO_FILESYSTEM)
    DH* dh = NULL;
    BIO* bio = NULL;
    XFILE fp = XBADFILE;
    byte pem[2048];
    int  pemSz = 0;
    const char expected[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "MIIBCAKCAQEAsKEIBpwIE7pZBjy8MNX1AMFPRKfW70rGJScc6NKWUwpckd2iwpSE\n"
        "v32yRJ+b0sGKxb5yXKfnkebUn3MHhVtmSMdw+rTuAsk9mkraPcFGPhlp0RdGB6NN\n"
        "nyuWFzltMI0q85TTdc+gdebykh8acAWqBINXMPvadpM4UOgn/WPuPOW3yAmub1A1\n"
        "joTOSgDpEn5aMdcz/CETdswWMNsM/MVipzW477ewrMA29tnJRkj5QJAAKxuqbOMa\n"
        "wwsDnhvCRuRITiJzb8Nf1JrWMAdI1oyQq9T28eNI01hLprnNKb9oHwhLY4YvXGvW\n"
        "tgZl96bcAGdru8OpQYP7x/rI4h5+rwA/kwIBAg==\n"
        "-----END DH PARAMETERS-----\n";
    const char badPem[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "-----END DH PARAMETERS-----\n";
    const char emptySeqPem[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "MAA=\n"
        "-----END DH PARAMETERS-----\n";

    ExpectTrue((fp = XFOPEN(dhParamFile, "rb")) != XBADFILE);
    ExpectIntGT((pemSz = (int)XFREAD(pem, 1, sizeof(pem), fp)), 0);
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    ExpectNull(PEM_read_bio_DHparams(NULL, NULL, NULL, NULL));

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectNull(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL));
    ExpectIntEQ(BIO_write(bio, badPem, (int)sizeof(badPem)),
        (int)sizeof(badPem));
    ExpectNull(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectNull(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL));
    ExpectIntEQ(BIO_write(bio, emptySeqPem, (int)sizeof(emptySeqPem)),
        (int)sizeof(emptySeqPem));
    ExpectNull(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(BIO_write(bio, pem, pemSz), pemSz);
    ExpectNotNull(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(fp = XFOPEN("./test-write-dhparams.pem", "wb"));
    ExpectIntEQ(PEM_write_DHparams(fp, dh), WOLFSSL_SUCCESS);
    ExpectIntEQ(PEM_write_DHparams(fp, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    DH_free(dh);
    dh = NULL;

    dh = wolfSSL_DH_new();
    ExpectIntEQ(PEM_write_DHparams(fp, dh), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    wolfSSL_DH_free(dh);
    dh = NULL;

    /* check results */
    XMEMSET(pem, 0, sizeof(pem));
    ExpectTrue((fp = XFOPEN("./test-write-dhparams.pem", "rb")) != XBADFILE);
    ExpectIntGT((pemSz = (int)XFREAD(pem, 1, sizeof(pem), fp)), 0);
    ExpectIntEQ(XMEMCMP(pem, expected, pemSz), 0);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_d2i_DHparams(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
#if !defined(NO_DH) && (defined(HAVE_FFDHE_2048) || defined(HAVE_FFDHE_3072))
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    XFILE f = XBADFILE;
    unsigned char buf[4096];
    const unsigned char* pt = buf;
#ifdef HAVE_FFDHE_2048
    const char* params1 = "./certs/dh2048.der";
#endif
#ifdef HAVE_FFDHE_3072
    const char* params2 = "./certs/dh3072.der";
#endif
    long len = 0;
    WOLFSSL_DH* dh = NULL;
    XMEMSET(buf, 0, sizeof(buf));

    /* Test 2048 bit parameters */
#ifdef HAVE_FFDHE_2048
    ExpectTrue((f = XFOPEN(params1, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Valid case */
    ExpectNotNull(dh = wolfSSL_d2i_DHparams(NULL, &pt, len));
    ExpectNotNull(dh->p);
    ExpectNotNull(dh->g);
    ExpectTrue(pt == buf);
    ExpectIntEQ(DH_set_length(NULL, BN_num_bits(dh->p)), 0);
    ExpectIntEQ(DH_set_length(dh, BN_num_bits(dh->p)), 1);
    ExpectIntEQ(DH_generate_key(dh), WOLFSSL_SUCCESS);

    /* Invalid cases */
    ExpectNull(wolfSSL_d2i_DHparams(NULL, NULL, len));
    ExpectNull(wolfSSL_d2i_DHparams(NULL, &pt, -1));
    ExpectNull(wolfSSL_d2i_DHparams(NULL, &pt, 10));

    DH_free(dh);
    dh = NULL;

    *buf = 0;
    pt = buf;
#endif /* HAVE_FFDHE_2048 */

    /* Test 3072 bit parameters */
#ifdef HAVE_FFDHE_3072
    ExpectTrue((f = XFOPEN(params2, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Valid case */
    ExpectNotNull(dh = wolfSSL_d2i_DHparams(&dh, &pt, len));
    ExpectNotNull(dh->p);
    ExpectNotNull(dh->g);
    ExpectTrue(pt != buf);
    ExpectIntEQ(DH_generate_key(dh), 1);

    /* Invalid cases */
    ExpectNull(wolfSSL_d2i_DHparams(NULL, NULL, len));
    ExpectNull(wolfSSL_d2i_DHparams(NULL, &pt, -1));

    DH_free(dh);
    dh = NULL;
#endif /* HAVE_FFDHE_3072 */

#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH */
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_DH_LoadDer(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)) && \
    defined(OPENSSL_EXTRA)
    static const byte dh2048[] = {
        0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01,
        0x00, 0xb0, 0xa1, 0x08, 0x06, 0x9c, 0x08, 0x13,
        0xba, 0x59, 0x06, 0x3c, 0xbc, 0x30, 0xd5, 0xf5,
        0x00, 0xc1, 0x4f, 0x44, 0xa7, 0xd6, 0xef, 0x4a,
        0xc6, 0x25, 0x27, 0x1c, 0xe8, 0xd2, 0x96, 0x53,
        0x0a, 0x5c, 0x91, 0xdd, 0xa2, 0xc2, 0x94, 0x84,
        0xbf, 0x7d, 0xb2, 0x44, 0x9f, 0x9b, 0xd2, 0xc1,
        0x8a, 0xc5, 0xbe, 0x72, 0x5c, 0xa7, 0xe7, 0x91,
        0xe6, 0xd4, 0x9f, 0x73, 0x07, 0x85, 0x5b, 0x66,
        0x48, 0xc7, 0x70, 0xfa, 0xb4, 0xee, 0x02, 0xc9,
        0x3d, 0x9a, 0x4a, 0xda, 0x3d, 0xc1, 0x46, 0x3e,
        0x19, 0x69, 0xd1, 0x17, 0x46, 0x07, 0xa3, 0x4d,
        0x9f, 0x2b, 0x96, 0x17, 0x39, 0x6d, 0x30, 0x8d,
        0x2a, 0xf3, 0x94, 0xd3, 0x75, 0xcf, 0xa0, 0x75,
        0xe6, 0xf2, 0x92, 0x1f, 0x1a, 0x70, 0x05, 0xaa,
        0x04, 0x83, 0x57, 0x30, 0xfb, 0xda, 0x76, 0x93,
        0x38, 0x50, 0xe8, 0x27, 0xfd, 0x63, 0xee, 0x3c,
        0xe5, 0xb7, 0xc8, 0x09, 0xae, 0x6f, 0x50, 0x35,
        0x8e, 0x84, 0xce, 0x4a, 0x00, 0xe9, 0x12, 0x7e,
        0x5a, 0x31, 0xd7, 0x33, 0xfc, 0x21, 0x13, 0x76,
        0xcc, 0x16, 0x30, 0xdb, 0x0c, 0xfc, 0xc5, 0x62,
        0xa7, 0x35, 0xb8, 0xef, 0xb7, 0xb0, 0xac, 0xc0,
        0x36, 0xf6, 0xd9, 0xc9, 0x46, 0x48, 0xf9, 0x40,
        0x90, 0x00, 0x2b, 0x1b, 0xaa, 0x6c, 0xe3, 0x1a,
        0xc3, 0x0b, 0x03, 0x9e, 0x1b, 0xc2, 0x46, 0xe4,
        0x48, 0x4e, 0x22, 0x73, 0x6f, 0xc3, 0x5f, 0xd4,
        0x9a, 0xd6, 0x30, 0x07, 0x48, 0xd6, 0x8c, 0x90,
        0xab, 0xd4, 0xf6, 0xf1, 0xe3, 0x48, 0xd3, 0x58,
        0x4b, 0xa6, 0xb9, 0xcd, 0x29, 0xbf, 0x68, 0x1f,
        0x08, 0x4b, 0x63, 0x86, 0x2f, 0x5c, 0x6b, 0xd6,
        0xb6, 0x06, 0x65, 0xf7, 0xa6, 0xdc, 0x00, 0x67,
        0x6b, 0xbb, 0xc3, 0xa9, 0x41, 0x83, 0xfb, 0xc7,
        0xfa, 0xc8, 0xe2, 0x1e, 0x7e, 0xaf, 0x00, 0x3f,
        0x93, 0x02, 0x01, 0x02
    };
    WOLFSSL_DH* dh = NULL;

    ExpectNotNull(dh = wolfSSL_DH_new());

    ExpectIntEQ(wolfSSL_DH_LoadDer(NULL, NULL, 0), -1);
    ExpectIntEQ(wolfSSL_DH_LoadDer(dh, NULL, 0), -1);
    ExpectIntEQ(wolfSSL_DH_LoadDer(NULL, dh2048, sizeof(dh2048)), -1);

    ExpectIntEQ(wolfSSL_DH_LoadDer(dh, dh2048, sizeof(dh2048)), 1);

    wolfSSL_DH_free(dh);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_i2d_DHparams(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
#if !defined(NO_DH) && (defined(HAVE_FFDHE_2048) || defined(HAVE_FFDHE_3072))
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    XFILE f = XBADFILE;
    unsigned char buf[4096];
    const unsigned char* pt;
    unsigned char* pt2;
#ifdef HAVE_FFDHE_2048
    const char* params1 = "./certs/dh2048.der";
#endif
#ifdef HAVE_FFDHE_3072
    const char* params2 = "./certs/dh3072.der";
#endif
    long len = 0;
    WOLFSSL_DH* dh = NULL;

    /* Test 2048 bit parameters */
#ifdef HAVE_FFDHE_2048
    pt = buf;
    pt2 = buf;

    ExpectTrue((f = XFOPEN(params1, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Valid case */
    ExpectNotNull(dh = wolfSSL_d2i_DHparams(NULL, &pt, len));
    ExpectTrue(pt == buf);
    ExpectIntEQ(DH_generate_key(dh), 1);
    ExpectIntEQ(wolfSSL_i2d_DHparams(dh, &pt2), 268);

    /* Invalid case */
    ExpectIntEQ(wolfSSL_i2d_DHparams(NULL, &pt2), 0);

    /* Return length only */
    ExpectIntEQ(wolfSSL_i2d_DHparams(dh, NULL), 268);

    DH_free(dh);
    dh = NULL;

    *buf = 0;
#endif

    /* Test 3072 bit parameters */
#ifdef HAVE_FFDHE_3072
    pt = buf;
    pt2 = buf;

    ExpectTrue((f = XFOPEN(params2, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Valid case */
    ExpectNotNull(dh = wolfSSL_d2i_DHparams(NULL, &pt, len));
    ExpectTrue(pt == buf);
    ExpectIntEQ(DH_generate_key(dh), 1);
    ExpectIntEQ(wolfSSL_i2d_DHparams(dh, &pt2), 396);

    /* Invalid case */
    ExpectIntEQ(wolfSSL_i2d_DHparams(NULL, &pt2), 0);

    /* Return length only */
    ExpectIntEQ(wolfSSL_i2d_DHparams(dh, NULL), 396);

    DH_free(dh);
    dh = NULL;
#endif

    dh = DH_new();
    ExpectNotNull(dh);
    pt2 = buf;
    ExpectIntEQ(wolfSSL_i2d_DHparams(dh, &pt2), 0);
    DH_free(dh);
    dh = NULL;
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH && (HAVE_FFDHE_2048 || HAVE_FFDHE_3072) */
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_ECC) && !defined(OPENSSL_NO_PK)

/*----------------------------------------------------------------------------*
 | EC
 *----------------------------------------------------------------------------*/

static int test_wolfSSL_EC_GROUP(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    EC_GROUP *group = NULL;
    EC_GROUP *group2 = NULL;
    EC_GROUP *group3 = NULL;
#ifndef HAVE_ECC_BRAINPOOL
    EC_GROUP *group4 = NULL;
#endif
    WOLFSSL_BIGNUM* order = NULL;
    int group_bits;
    int i;
    static const int knownEccNids[] = {
        NID_X9_62_prime192v1,
        NID_X9_62_prime192v2,
        NID_X9_62_prime192v3,
        NID_X9_62_prime239v1,
        NID_X9_62_prime239v2,
        NID_X9_62_prime239v3,
        NID_X9_62_prime256v1,
        NID_secp112r1,
        NID_secp112r2,
        NID_secp128r1,
        NID_secp128r2,
        NID_secp160r1,
        NID_secp160r2,
        NID_secp224r1,
        NID_secp384r1,
        NID_secp521r1,
        NID_secp160k1,
        NID_secp192k1,
        NID_secp224k1,
        NID_secp256k1,
        NID_brainpoolP160r1,
        NID_brainpoolP192r1,
        NID_brainpoolP224r1,
        NID_brainpoolP256r1,
        NID_brainpoolP320r1,
        NID_brainpoolP384r1,
        NID_brainpoolP512r1,
    };
    int knowEccNidsLen = (int)(sizeof(knownEccNids) / sizeof(*knownEccNids));
    static const int knownEccEnums[] = {
        ECC_SECP192R1,
        ECC_PRIME192V2,
        ECC_PRIME192V3,
        ECC_PRIME239V1,
        ECC_PRIME239V2,
        ECC_PRIME239V3,
        ECC_SECP256R1,
        ECC_SECP112R1,
        ECC_SECP112R2,
        ECC_SECP128R1,
        ECC_SECP128R2,
        ECC_SECP160R1,
        ECC_SECP160R2,
        ECC_SECP224R1,
        ECC_SECP384R1,
        ECC_SECP521R1,
        ECC_SECP160K1,
        ECC_SECP192K1,
        ECC_SECP224K1,
        ECC_SECP256K1,
        ECC_BRAINPOOLP160R1,
        ECC_BRAINPOOLP192R1,
        ECC_BRAINPOOLP224R1,
        ECC_BRAINPOOLP256R1,
        ECC_BRAINPOOLP320R1,
        ECC_BRAINPOOLP384R1,
        ECC_BRAINPOOLP512R1,
    };
    int knowEccEnumsLen = (int)(sizeof(knownEccEnums) / sizeof(*knownEccEnums));

    ExpectNotNull(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectNotNull(group2 = EC_GROUP_dup(group));
    ExpectNotNull(group3 = wolfSSL_EC_GROUP_new_by_curve_name(NID_secp384r1));
#ifndef HAVE_ECC_BRAINPOOL
    ExpectNotNull(group4 = wolfSSL_EC_GROUP_new_by_curve_name(
        NID_brainpoolP256r1));
#endif

    ExpectNull(EC_GROUP_dup(NULL));

    ExpectIntEQ(wolfSSL_EC_GROUP_get_curve_name(NULL), 0);
    ExpectIntEQ(wolfSSL_EC_GROUP_get_curve_name(group), NID_X9_62_prime256v1);

    ExpectIntEQ((group_bits = EC_GROUP_order_bits(NULL)), 0);
    ExpectIntEQ((group_bits = EC_GROUP_order_bits(group)), 256);
#ifndef HAVE_ECC_BRAINPOOL
    ExpectIntEQ((group_bits = EC_GROUP_order_bits(group4)), 0);
#endif

    ExpectIntEQ(wolfSSL_EC_GROUP_get_degree(NULL), 0);
    ExpectIntEQ(wolfSSL_EC_GROUP_get_degree(group), 256);

    ExpectNotNull(order = BN_new());
    ExpectIntEQ(wolfSSL_EC_GROUP_get_order(NULL, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_GROUP_get_order(group, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_GROUP_get_order(NULL, order, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_GROUP_get_order(group, order, NULL), 1);
    wolfSSL_BN_free(order);

    ExpectNotNull(EC_GROUP_method_of(group));

    ExpectIntEQ(EC_METHOD_get_field_type(NULL), 0);
    ExpectIntEQ(EC_METHOD_get_field_type(EC_GROUP_method_of(group)),
        NID_X9_62_prime_field);

    ExpectIntEQ(wolfSSL_EC_GROUP_cmp(NULL, NULL, NULL), -1);
    ExpectIntEQ(wolfSSL_EC_GROUP_cmp(group, NULL, NULL), -1);
    ExpectIntEQ(wolfSSL_EC_GROUP_cmp(NULL, group, NULL), -1);
    ExpectIntEQ(wolfSSL_EC_GROUP_cmp(group, group3, NULL), 1);

#ifndef NO_WOLFSSL_STUB
    wolfSSL_EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
#endif

#ifndef HAVE_ECC_BRAINPOOL
    EC_GROUP_free(group4);
#endif
    EC_GROUP_free(group3);
    EC_GROUP_free(group2);
    EC_GROUP_free(group);

    for (i = 0; i < knowEccNidsLen; i++) {
        group = NULL;
        ExpectNotNull(group = EC_GROUP_new_by_curve_name(knownEccNids[i]));
        ExpectIntGT(wolfSSL_EC_GROUP_get_degree(group), 0);
        EC_GROUP_free(group);
    }
    for (i = 0; i < knowEccEnumsLen; i++) {
        group = NULL;
        ExpectNotNull(group = EC_GROUP_new_by_curve_name(knownEccEnums[i]));
        ExpectIntEQ(wolfSSL_EC_GROUP_get_curve_name(group), knownEccNids[i]);
        EC_GROUP_free(group);
    }
#endif
   return EXPECT_RESULT();
}

static int test_wolfSSL_PEM_read_bio_ECPKParameters(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    EC_GROUP *group = NULL;
    BIO* bio = NULL;
#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && \
    ECC_MIN_KEY_SZ <= 384 && !defined(NO_ECC_SECP)
    EC_GROUP *ret = NULL;
    static char ec_nc_p384[] = "-----BEGIN EC PARAMETERS-----\n"
                               "BgUrgQQAIg==\n"
                               "-----END EC PARAMETERS-----";
#endif
    static char ec_nc_bad_1[] = "-----BEGIN EC PARAMETERS-----\n"
                                "MAA=\n"
                                "-----END EC PARAMETERS-----";
    static char ec_nc_bad_2[] = "-----BEGIN EC PARAMETERS-----\n"
                                "BgA=\n"
                                "-----END EC PARAMETERS-----";
    static char ec_nc_bad_3[] = "-----BEGIN EC PARAMETERS-----\n"
                                "BgE=\n"
                                "-----END EC PARAMETERS-----";
    static char ec_nc_bad_4[] = "-----BEGIN EC PARAMETERS-----\n"
                                "BgE*\n"
                                "-----END EC PARAMETERS-----";

    /* Test that first parameter, bio, being NULL fails. */
    ExpectNull(PEM_read_bio_ECPKParameters(NULL, NULL, NULL, NULL));

    /* Test that reading named parameters works. */
    ExpectNotNull(bio = BIO_new(BIO_s_file()));
    ExpectIntEQ(BIO_read_filename(bio, eccKeyFile), WOLFSSL_SUCCESS);
    ExpectNotNull(group = PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL));
    ExpectIntEQ(EC_GROUP_get_curve_name(group), NID_X9_62_prime256v1);
    BIO_free(bio);
    bio = NULL;
    EC_GROUP_free(group);
    group = NULL;

#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && \
    ECC_MIN_KEY_SZ <= 384 && !defined(NO_ECC_SECP)
    /* Test that reusing group works. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_p384,
        sizeof(ec_nc_p384)));
    ExpectNotNull(group = PEM_read_bio_ECPKParameters(bio, &group, NULL, NULL));
    ExpectIntEQ(EC_GROUP_get_curve_name(group), NID_secp384r1);
    BIO_free(bio);
    bio = NULL;
    EC_GROUP_free(group);
    group = NULL;

    /* Test that returning through group works. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_p384,
        sizeof(ec_nc_p384)));
    ExpectNotNull(ret = PEM_read_bio_ECPKParameters(bio, &group, NULL, NULL));
    ExpectIntEQ(group == ret, 1);
    ExpectIntEQ(EC_GROUP_get_curve_name(group), NID_secp384r1);
    BIO_free(bio);
    bio = NULL;
    EC_GROUP_free(group);
    group = NULL;
#endif

    /* Test 0x30, 0x00 (not and object id) fails. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_bad_1,
        sizeof(ec_nc_bad_1)));
    ExpectNull(PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    /* Test 0x06, 0x00 (empty object id) fails. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_bad_2,
        sizeof(ec_nc_bad_2)));
    ExpectNull(PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    /* Test 0x06, 0x01 (badly formed object id) fails. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_bad_3,
        sizeof(ec_nc_bad_3)));
    ExpectNull(PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    /* Test invalid PEM encoding - invalid character. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_bad_4,
        sizeof(ec_nc_bad_4)));
    ExpectNull(PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL));
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_i2d_ECPKParameters(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    EC_GROUP* grp = NULL;
    unsigned char p256_oid[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    };
    unsigned char *der = p256_oid;
    unsigned char out_der[sizeof(p256_oid)];

    XMEMSET(out_der, 0, sizeof(out_der));
    ExpectNotNull(d2i_ECPKParameters(&grp, (const unsigned char **)&der,
            sizeof(p256_oid)));
    der = out_der;
    ExpectIntEQ(i2d_ECPKParameters(grp, &der), sizeof(p256_oid));
    ExpectBufEQ(p256_oid, out_der, sizeof(p256_oid));
    EC_GROUP_free(grp);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EC_POINT(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_SP_MATH) && \
  (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2)))

#ifdef OPENSSL_EXTRA
    BN_CTX* ctx = NULL;
    EC_GROUP* group = NULL;
#ifndef HAVE_ECC_BRAINPOOL
    EC_GROUP* group2 = NULL;
#endif
    EC_POINT* Gxy = NULL;
    EC_POINT* new_point = NULL;
    EC_POINT* set_point = NULL;
    EC_POINT* get_point = NULL;
    EC_POINT* infinity = NULL;
    BIGNUM* k = NULL;
    BIGNUM* Gx = NULL;
    BIGNUM* Gy = NULL;
    BIGNUM* Gz = NULL;
    BIGNUM* X = NULL;
    BIGNUM* Y = NULL;
    BIGNUM* set_point_bn = NULL;
    char* hexStr = NULL;

    const char* kTest = "F4F8338AFCC562C5C3F3E1E46A7EFECD"
                        "17AF381913FF7A96314EA47055EA0FD0";
    /* NISTP256R1 Gx/Gy */
    const char* kGx   = "6B17D1F2E12C4247F8BCE6E563A440F2"
                        "77037D812DEB33A0F4A13945D898C296";
    const char* kGy   = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E16"
                        "2BCE33576B315ECECBB6406837BF51F5";
    const char* uncompG
                      = "046B17D1F2E12C4247F8BCE6E563A440F2"
                        "77037D812DEB33A0F4A13945D898C296"
                        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E16"
                        "2BCE33576B315ECECBB6406837BF51F5";
    const char* compG
                      = "036B17D1F2E12C4247F8BCE6E563A440F2"
                        "77037D812DEB33A0F4A13945D898C296";

#ifndef HAVE_SELFTEST
    EC_POINT *tmp = NULL;
    size_t bin_len;
    unsigned int blen = 0;
    unsigned char* buf = NULL;
    unsigned char bufInf[1] = { 0x00 };

    const unsigned char binUncompG[] = {
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
        0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
        0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
        0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
    };
    const unsigned char binUncompGBad[] = {
        0x09, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
        0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
        0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
        0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
    };

#ifdef HAVE_COMP_KEY
    const unsigned char binCompG[] = {
        0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
        0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    };
#endif
#endif

    ExpectNotNull(ctx = BN_CTX_new());
    ExpectNotNull(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
#ifndef HAVE_ECC_BRAINPOOL
    /* Used to make groups curve_idx == -1. */
    ExpectNotNull(group2 = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1));
#endif

    ExpectNull(EC_POINT_new(NULL));
    ExpectNotNull(Gxy = EC_POINT_new(group));
    ExpectNotNull(new_point = EC_POINT_new(group));
    ExpectNotNull(set_point = EC_POINT_new(group));
    ExpectNotNull(X = BN_new());
    ExpectNotNull(Y = BN_new());
    ExpectNotNull(set_point_bn = BN_new());

    ExpectNotNull(infinity = EC_POINT_new(group));

    /* load test values */
    ExpectIntEQ(BN_hex2bn(&k,  kTest), WOLFSSL_SUCCESS);
    ExpectIntEQ(BN_hex2bn(&Gx, kGx),   WOLFSSL_SUCCESS);
    ExpectIntEQ(BN_hex2bn(&Gy, kGy),   WOLFSSL_SUCCESS);
    ExpectIntEQ(BN_hex2bn(&Gz, "1"),   WOLFSSL_SUCCESS);

    /* populate coordinates for input point */
    if (Gxy != NULL) {
        Gxy->X = Gx;
        Gxy->Y = Gy;
        Gxy->Z = Gz;
    }

    /* Test handling of NULL point. */
    EC_POINT_clear_free(NULL);

    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(NULL, NULL,
        NULL, NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, NULL,
        NULL, NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(NULL, Gxy,
        NULL, NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(NULL, NULL,
        X, NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(NULL, NULL,
        NULL, Y, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(NULL, Gxy,
        X, Y, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, NULL,
        X, Y, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, Gxy,
        NULL, Y, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, Gxy,
        X, NULL, ctx), 0);
    /* Getting point at infinity returns an error. */
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, infinity,
        X, Y, ctx), 0);

#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_SP_MATH) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    ExpectIntEQ(EC_POINT_add(NULL, NULL, NULL, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_add(group, NULL, NULL, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_add(NULL, new_point, NULL, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_add(NULL, NULL, new_point, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_add(NULL, NULL, NULL, Gxy, ctx), 0);
    ExpectIntEQ(EC_POINT_add(NULL, new_point, new_point, Gxy, ctx), 0);
    ExpectIntEQ(EC_POINT_add(group, NULL, new_point, Gxy, ctx), 0);
    ExpectIntEQ(EC_POINT_add(group, new_point, NULL, Gxy, ctx), 0);
    ExpectIntEQ(EC_POINT_add(group, new_point, new_point, NULL, ctx), 0);

    ExpectIntEQ(EC_POINT_mul(NULL, NULL, Gx, Gxy, k, ctx), 0);
    ExpectIntEQ(EC_POINT_mul(NULL, new_point, Gx, Gxy, k, ctx), 0);
    ExpectIntEQ(EC_POINT_mul(group, NULL, Gx, Gxy, k, ctx), 0);

    ExpectIntEQ(EC_POINT_add(group, new_point, new_point, Gxy, ctx), 1);
    /* perform point multiplication */
    ExpectIntEQ(EC_POINT_mul(group, new_point, Gx, Gxy, k, ctx), 1);
    ExpectIntEQ(BN_is_zero(new_point->X), 0);
    ExpectIntEQ(BN_is_zero(new_point->Y), 0);
    ExpectIntEQ(BN_is_zero(new_point->Z), 0);
    ExpectIntEQ(EC_POINT_mul(group, new_point, NULL, Gxy, k, ctx), 1);
    ExpectIntEQ(BN_is_zero(new_point->X), 0);
    ExpectIntEQ(BN_is_zero(new_point->Y), 0);
    ExpectIntEQ(BN_is_zero(new_point->Z), 0);
    ExpectIntEQ(EC_POINT_mul(group, new_point, Gx, NULL, NULL, ctx), 1);
    ExpectIntEQ(BN_is_zero(new_point->X), 0);
    ExpectIntEQ(BN_is_zero(new_point->Y), 0);
    ExpectIntEQ(BN_is_zero(new_point->Z), 0);
    ExpectIntEQ(EC_POINT_mul(group, new_point, NULL, NULL, NULL, ctx), 1);
    ExpectIntEQ(BN_is_zero(new_point->X), 1);
    ExpectIntEQ(BN_is_zero(new_point->Y), 1);
    ExpectIntEQ(BN_is_zero(new_point->Z), 1);
    /* Set point to something. */
    ExpectIntEQ(EC_POINT_add(group, new_point, Gxy, Gxy, ctx), 1);
#else
    ExpectIntEQ(EC_POINT_set_affine_coordinates_GFp(group, new_point, Gx, Gy,
        ctx), 1);
    ExpectIntEQ(BN_is_zero(new_point->X), 0);
    ExpectIntEQ(BN_is_zero(new_point->Y), 0);
    ExpectIntEQ(BN_is_zero(new_point->Z), 0);
#endif

    /* check if point X coordinate is zero */
    ExpectIntEQ(BN_is_zero(new_point->X), 0);

#if defined(USE_ECC_B_PARAM) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
    ExpectIntEQ(EC_POINT_is_on_curve(group, new_point, ctx), 1);
#endif

    /* extract the coordinates from point */
    ExpectIntEQ(EC_POINT_get_affine_coordinates_GFp(group, new_point, X, Y,
        ctx), WOLFSSL_SUCCESS);

    /* check if point X coordinate is zero */
    ExpectIntEQ(BN_is_zero(X), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* set the same X and Y points in another object */
    ExpectIntEQ(EC_POINT_set_affine_coordinates_GFp(group, set_point, X, Y,
        ctx), WOLFSSL_SUCCESS);

    /* compare points as they should be the same */
    ExpectIntEQ(EC_POINT_cmp(NULL, NULL, NULL, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(group, NULL, NULL, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(NULL, new_point, NULL, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(NULL, NULL, set_point, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(NULL, new_point, set_point, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(group, NULL, set_point, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(group, new_point, NULL, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(group, new_point, set_point, ctx), 0);

    /* Test copying */
    ExpectIntEQ(EC_POINT_copy(NULL, NULL), 0);
    ExpectIntEQ(EC_POINT_copy(NULL, set_point), 0);
    ExpectIntEQ(EC_POINT_copy(new_point, NULL), 0);
    ExpectIntEQ(EC_POINT_copy(new_point, set_point), 1);

    /* Test inverting */
    ExpectIntEQ(EC_POINT_invert(NULL, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_invert(NULL, new_point, ctx), 0);
    ExpectIntEQ(EC_POINT_invert(group, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_invert(group, new_point, ctx), 1);

#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_SP_MATH) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    {
        EC_POINT* orig_point = NULL;
        ExpectNotNull(orig_point = EC_POINT_new(group));
        ExpectIntEQ(EC_POINT_add(group, orig_point, set_point, set_point, NULL),
                    1);
        /* new_point should be set_point inverted so adding it will revert
         * the point back to set_point */
        ExpectIntEQ(EC_POINT_add(group, orig_point, orig_point, new_point,
                                 NULL), 1);
        ExpectIntEQ(EC_POINT_cmp(group, orig_point, set_point, NULL), 0);
        EC_POINT_free(orig_point);
    }
#endif

    /* Test getting affine converts from projective. */
    ExpectIntEQ(EC_POINT_copy(set_point, new_point), 1);
    /* Force non-affine coordinates */
    ExpectIntEQ(BN_add(new_point->Z, (WOLFSSL_BIGNUM*)BN_value_one(),
        (WOLFSSL_BIGNUM*)BN_value_one()), 1);
    if (new_point != NULL) {
        new_point->inSet = 0;
    }
    /* extract the coordinates from point */
    ExpectIntEQ(EC_POINT_get_affine_coordinates_GFp(group, new_point, X, Y,
        ctx), WOLFSSL_SUCCESS);
    /* check if point ordinates have changed. */
    ExpectIntNE(BN_cmp(X, set_point->X), 0);
    ExpectIntNE(BN_cmp(Y, set_point->Y), 0);

    /* Test check for infinity */
#ifndef WOLF_CRYPTO_CB_ONLY_ECC
    ExpectIntEQ(EC_POINT_is_at_infinity(NULL, NULL), 0);
    ExpectIntEQ(EC_POINT_is_at_infinity(NULL, infinity), 0);
    ExpectIntEQ(EC_POINT_is_at_infinity(group, NULL), 0);
    ExpectIntEQ(EC_POINT_is_at_infinity(group, infinity), 1);
    ExpectIntEQ(EC_POINT_is_at_infinity(group, Gxy), 0);
#else
    ExpectIntEQ(EC_POINT_is_at_infinity(group, infinity), 0);
#endif

    ExpectPtrEq(EC_POINT_point2bn(group, set_point,
        POINT_CONVERSION_UNCOMPRESSED, set_point_bn, ctx), set_point_bn);

    /* check bn2hex */
    hexStr = BN_bn2hex(k);
    ExpectStrEQ(hexStr, kTest);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) && \
     defined(XFPRINTF)
    BN_print_fp(stderr, k);
    fprintf(stderr, "\n");
#endif
    XFREE(hexStr, NULL, DYNAMIC_TYPE_ECC);

    hexStr = BN_bn2hex(Gx);
    ExpectStrEQ(hexStr, kGx);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) && \
     defined(XFPRINTF)
    BN_print_fp(stderr, Gx);
    fprintf(stderr, "\n");
#endif
    XFREE(hexStr, NULL, DYNAMIC_TYPE_ECC);

    hexStr = BN_bn2hex(Gy);
    ExpectStrEQ(hexStr, kGy);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) && \
     defined(XFPRINTF)
    BN_print_fp(stderr, Gy);
    fprintf(stderr, "\n");
#endif
    XFREE(hexStr, NULL, DYNAMIC_TYPE_ECC);

    /* Test point to hex */
    ExpectNull(EC_POINT_point2hex(NULL, NULL, POINT_CONVERSION_UNCOMPRESSED,
        ctx));
    ExpectNull(EC_POINT_point2hex(NULL, Gxy, POINT_CONVERSION_UNCOMPRESSED,
        ctx));
    ExpectNull(EC_POINT_point2hex(group, NULL, POINT_CONVERSION_UNCOMPRESSED,
        ctx));
#ifndef HAVE_ECC_BRAINPOOL
    /* Group not supported in wolfCrypt. */
    ExpectNull(EC_POINT_point2hex(group2, Gxy, POINT_CONVERSION_UNCOMPRESSED,
        ctx));
#endif

    hexStr = EC_POINT_point2hex(group, Gxy, POINT_CONVERSION_UNCOMPRESSED, ctx);
    ExpectNotNull(hexStr);
    ExpectStrEQ(hexStr, uncompG);
    ExpectNotNull(get_point = EC_POINT_hex2point(group, hexStr, NULL, ctx));
    ExpectIntEQ(EC_POINT_cmp(group, Gxy, get_point, ctx), 0);
    XFREE(hexStr, NULL, DYNAMIC_TYPE_ECC);

    hexStr = EC_POINT_point2hex(group, Gxy, POINT_CONVERSION_COMPRESSED, ctx);
    ExpectNotNull(hexStr);
    ExpectStrEQ(hexStr, compG);
    #ifdef HAVE_COMP_KEY
    ExpectNotNull(get_point = EC_POINT_hex2point
                                            (group, hexStr, get_point, ctx));
    ExpectIntEQ(EC_POINT_cmp(group, Gxy, get_point, ctx), 0);
    #endif
    XFREE(hexStr, NULL, DYNAMIC_TYPE_ECC);
    EC_POINT_free(get_point);

#ifndef HAVE_SELFTEST
    /* Test point to oct */
    ExpectIntEQ(EC_POINT_point2oct(NULL, NULL, POINT_CONVERSION_UNCOMPRESSED,
        NULL, 0, ctx), 0);
    ExpectIntEQ(EC_POINT_point2oct(NULL, Gxy, POINT_CONVERSION_UNCOMPRESSED,
        NULL, 0, ctx), 0);
    ExpectIntEQ(EC_POINT_point2oct(group, NULL, POINT_CONVERSION_UNCOMPRESSED,
        NULL, 0, ctx), 0);
    bin_len = EC_POINT_point2oct(group, Gxy, POINT_CONVERSION_UNCOMPRESSED,
        NULL, 0, ctx);
    ExpectIntEQ(bin_len, sizeof(binUncompG));
    ExpectNotNull(buf = (unsigned char*)XMALLOC(bin_len, NULL,
         DYNAMIC_TYPE_ECC));
    ExpectIntEQ(EC_POINT_point2oct(group, Gxy, POINT_CONVERSION_UNCOMPRESSED,
        buf, bin_len, ctx), bin_len);
    ExpectIntEQ(XMEMCMP(buf, binUncompG, sizeof(binUncompG)), 0);
    XFREE(buf, NULL, DYNAMIC_TYPE_ECC);

    /* Infinity (x=0, y=0) encodes as '0x00'. */
    ExpectIntEQ(EC_POINT_point2oct(group, infinity,
        POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx), 1);
    ExpectIntEQ(EC_POINT_point2oct(group, infinity,
        POINT_CONVERSION_UNCOMPRESSED, bufInf, 0, ctx), 0);
    ExpectIntEQ(EC_POINT_point2oct(group, infinity,
        POINT_CONVERSION_UNCOMPRESSED, bufInf, 1, ctx), 1);
    ExpectIntEQ(bufInf[0], 0);

    wolfSSL_EC_POINT_dump(NULL, NULL);
    /* Test point i2d */
    ExpectIntEQ(ECPoint_i2d(NULL, NULL, NULL, &blen), 0);
    ExpectIntEQ(ECPoint_i2d(NULL, Gxy, NULL, &blen), 0);
    ExpectIntEQ(ECPoint_i2d(group, NULL, NULL, &blen), 0);
    ExpectIntEQ(ECPoint_i2d(group, Gxy, NULL, NULL), 0);
    ExpectIntEQ(ECPoint_i2d(group, Gxy, NULL, &blen), 1);
    ExpectIntEQ(blen, sizeof(binUncompG));
    ExpectNotNull(buf = (unsigned char*)XMALLOC(blen, NULL, DYNAMIC_TYPE_ECC));
    blen--;
    ExpectIntEQ(ECPoint_i2d(group, Gxy, buf, &blen), 0);
    blen++;
    ExpectIntEQ(ECPoint_i2d(group, Gxy, buf, &blen), 1);
    ExpectIntEQ(XMEMCMP(buf, binUncompG, sizeof(binUncompG)), 0);
    XFREE(buf, NULL, DYNAMIC_TYPE_ECC);

#ifdef HAVE_COMP_KEY
    /* Test point to oct compressed */
    bin_len = EC_POINT_point2oct(group, Gxy, POINT_CONVERSION_COMPRESSED, NULL,
        0, ctx);
    ExpectIntEQ(bin_len, sizeof(binCompG));
    ExpectNotNull(buf = (unsigned char*)XMALLOC(bin_len, NULL,
        DYNAMIC_TYPE_ECC));
    ExpectIntEQ(EC_POINT_point2oct(group, Gxy, POINT_CONVERSION_COMPRESSED, buf,
        bin_len, ctx), bin_len);
    ExpectIntEQ(XMEMCMP(buf, binCompG, sizeof(binCompG)), 0);
    XFREE(buf, NULL, DYNAMIC_TYPE_ECC);
#endif

    /* Test point BN */
    ExpectNull(wolfSSL_EC_POINT_point2bn(NULL, NULL,
        POINT_CONVERSION_UNCOMPRESSED, NULL, ctx));
    ExpectNull(wolfSSL_EC_POINT_point2bn(NULL, Gxy,
        POINT_CONVERSION_UNCOMPRESSED, NULL, ctx));
    ExpectNull(wolfSSL_EC_POINT_point2bn(group, NULL,
        POINT_CONVERSION_UNCOMPRESSED, NULL, ctx));
    ExpectNull(wolfSSL_EC_POINT_point2bn(group, Gxy, 0, NULL, ctx));

    /* Test oct to point */
    ExpectNotNull(tmp = EC_POINT_new(group));
    ExpectIntEQ(EC_POINT_oct2point(NULL, NULL, binUncompG, sizeof(binUncompG),
        ctx), 0);
    ExpectIntEQ(EC_POINT_oct2point(NULL, tmp, binUncompG, sizeof(binUncompG),
        ctx), 0);
    ExpectIntEQ(EC_POINT_oct2point(group, NULL, binUncompG, sizeof(binUncompG),
        ctx), 0);
    ExpectIntEQ(EC_POINT_oct2point(group, tmp, binUncompGBad,
        sizeof(binUncompGBad), ctx), 0);
    ExpectIntEQ(EC_POINT_oct2point(group, tmp, binUncompG, sizeof(binUncompG),
        ctx), 1);
    ExpectIntEQ(EC_POINT_cmp(group, tmp, Gxy, ctx), 0);
    EC_POINT_free(tmp);
    tmp = NULL;

    /* Test setting BN ordinates. */
    ExpectNotNull(tmp = EC_POINT_new(group));
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(NULL, NULL, NULL,
        NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, NULL, NULL,
        NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(NULL, tmp, NULL,
        NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(NULL, NULL, Gx,
        NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(NULL, NULL, NULL,
        Gy, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(NULL, tmp, Gx, Gy,
        ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, NULL, Gx, Gy,
        ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, tmp, NULL,
        Gy, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, tmp, Gx,
        NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, tmp, Gx, Gy,
        ctx), 1);
    EC_POINT_free(tmp);
    tmp = NULL;

    /* Test point d2i */
    ExpectNotNull(tmp = EC_POINT_new(group));
    ExpectIntEQ(ECPoint_d2i(NULL, sizeof(binUncompG), NULL, NULL), 0);
    ExpectIntEQ(ECPoint_d2i(binUncompG, sizeof(binUncompG), NULL, NULL), 0);
    ExpectIntEQ(ECPoint_d2i(NULL, sizeof(binUncompG), group, NULL), 0);
    ExpectIntEQ(ECPoint_d2i(NULL, sizeof(binUncompG), NULL, tmp), 0);
    ExpectIntEQ(ECPoint_d2i(NULL, sizeof(binUncompG), group, tmp), 0);
    ExpectIntEQ(ECPoint_d2i(binUncompG, sizeof(binUncompG), NULL, tmp), 0);
    ExpectIntEQ(ECPoint_d2i(binUncompG, sizeof(binUncompG), group, NULL), 0);
    ExpectIntEQ(ECPoint_d2i(binUncompGBad, sizeof(binUncompG), group, tmp), 0);
    ExpectIntEQ(ECPoint_d2i(binUncompG, sizeof(binUncompG), group, tmp), 1);
    ExpectIntEQ(EC_POINT_cmp(group, tmp, Gxy, ctx), 0);
    EC_POINT_free(tmp);
    tmp = NULL;

#ifdef HAVE_COMP_KEY
    /* Test oct compressed to point */
    ExpectNotNull(tmp = EC_POINT_new(group));
    ExpectIntEQ(EC_POINT_oct2point(group, tmp, binCompG, sizeof(binCompG), ctx),
        1);
    ExpectIntEQ(EC_POINT_cmp(group, tmp, Gxy, ctx), 0);
    EC_POINT_free(tmp);
    tmp = NULL;

    /* Test point d2i - compressed */
    ExpectNotNull(tmp = EC_POINT_new(group));
    ExpectIntEQ(ECPoint_d2i(binCompG, sizeof(binCompG), group, tmp), 1);
    ExpectIntEQ(EC_POINT_cmp(group, tmp, Gxy, ctx), 0);
    EC_POINT_free(tmp);
    tmp = NULL;
#endif
#endif

    /* test BN_mod_add */
    ExpectIntEQ(BN_mod_add(new_point->Z, (WOLFSSL_BIGNUM*)BN_value_one(),
        (WOLFSSL_BIGNUM*)BN_value_one(), (WOLFSSL_BIGNUM*)BN_value_one(), NULL),
        1);
    ExpectIntEQ(BN_is_zero(new_point->Z), 1);

    /* cleanup */
    BN_free(X);
    BN_free(Y);
    BN_free(k);
    BN_free(set_point_bn);
    EC_POINT_free(infinity);
    EC_POINT_free(new_point);
    EC_POINT_free(set_point);
    EC_POINT_clear_free(Gxy);
#ifndef HAVE_ECC_BRAINPOOL
    EC_GROUP_free(group2);
#endif
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
#endif
#endif /* !WOLFSSL_SP_MATH && ( !HAVE_FIPS || HAVE_FIPS_VERSION > 2) */
    return EXPECT_RESULT();
}

static int test_wolfSSL_SPAKE(void)
{
    EXPECT_DECLS;

#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && !defined(WOLFSSL_ATECC508A) \
    && !defined(WOLFSSL_ATECC608A) && !defined(HAVE_SELFTEST) && \
       !defined(WOLFSSL_SP_MATH) && !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    BIGNUM* x = NULL; /* kdc priv */
    BIGNUM* y = NULL; /* client priv */
    BIGNUM* w = NULL; /* shared value */
    byte M_bytes[] = {
        /* uncompressed */
        0x04,
        /* x */
        0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24,
        0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95,
        0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f,
        /* y */
        0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65,
        0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0,
        0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20
    };
    EC_POINT* M = NULL; /* shared value */
    byte N_bytes[] = {
        /* uncompressed */
        0x04,
        /* x */
        0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f,
        0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2,
        0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49,
        /* y */
        0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33,
        0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5,
        0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7
    };
    EC_POINT* N = NULL; /* shared value */
    EC_POINT* T = NULL; /* kdc pub */
    EC_POINT* tmp1 = NULL; /* kdc pub */
    EC_POINT* tmp2 = NULL; /* kdc pub */
    EC_POINT* S = NULL; /* client pub */
    EC_POINT* client_secret = NULL;
    EC_POINT* kdc_secret = NULL;
    EC_GROUP* group = NULL;
    BN_CTX* bn_ctx = NULL;

    /* Values taken from a test run of Kerberos 5 */

    ExpectNotNull(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectNotNull(bn_ctx = BN_CTX_new());

    ExpectNotNull(M = EC_POINT_new(group));
    ExpectNotNull(N = EC_POINT_new(group));
    ExpectNotNull(T = EC_POINT_new(group));
    ExpectNotNull(tmp1 = EC_POINT_new(group));
    ExpectNotNull(tmp2 = EC_POINT_new(group));
    ExpectNotNull(S = EC_POINT_new(group));
    ExpectNotNull(client_secret = EC_POINT_new(group));
    ExpectNotNull(kdc_secret = EC_POINT_new(group));
    ExpectIntEQ(BN_hex2bn(&x, "DAC3027CD692B4BDF0EDFE9B7D0E4E7"
                              "E5D8768A725EAEEA6FC68EC239A17C0"), 1);
    ExpectIntEQ(BN_hex2bn(&y, "6F6A1D394E26B1655A54B26DCE30D49"
                              "90CC47EBE08F809EF3FF7F6AEAABBB5"), 1);
    ExpectIntEQ(BN_hex2bn(&w, "1D992AB8BA851B9BA05353453D81EE9"
                              "506AB395478F0AAB647752CF117B36250"), 1);
    ExpectIntEQ(EC_POINT_oct2point(group, M, M_bytes, sizeof(M_bytes), bn_ctx),
                1);
    ExpectIntEQ(EC_POINT_oct2point(group, N, N_bytes, sizeof(N_bytes), bn_ctx),
                1);

    /* Function pattern similar to ossl_keygen and ossl_result in krb5 */

    /* kdc */
    /* T=x*P+w*M */
    /* All in one function call */
    ExpectIntEQ(EC_POINT_mul(group, T, x, M, w, bn_ctx), 1);
    /* Spread into separate calls */
    ExpectIntEQ(EC_POINT_mul(group, tmp1, x, NULL, NULL, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_mul(group, tmp2, NULL, M, w, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_add(group, tmp1, tmp1, tmp2, bn_ctx),
                1);
    ExpectIntEQ(EC_POINT_cmp(group, T, tmp1, bn_ctx), 0);
    /* client */
    /* S=y*P+w*N */
    /* All in one function call */
    ExpectIntEQ(EC_POINT_mul(group, S, y, N, w, bn_ctx), 1);
    /* Spread into separate calls */
    ExpectIntEQ(EC_POINT_mul(group, tmp1, y, NULL, NULL, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_mul(group, tmp2, NULL, N, w, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_add(group, tmp1, tmp1, tmp2, bn_ctx),
                1);
    ExpectIntEQ(EC_POINT_cmp(group, S, tmp1, bn_ctx), 0);
    /* K=y*(T-w*M) */
    ExpectIntEQ(EC_POINT_mul(group, client_secret, NULL, M, w, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_invert(group, client_secret, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_add(group, client_secret, T, client_secret, bn_ctx),
                1);
    ExpectIntEQ(EC_POINT_mul(group, client_secret, NULL, client_secret, y,
                             bn_ctx), 1);
    /* kdc */
    /* K=x*(S-w*N) */
    ExpectIntEQ(EC_POINT_mul(group, kdc_secret, NULL, N, w, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_invert(group, kdc_secret, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_add(group, kdc_secret, S, kdc_secret, bn_ctx),
                1);
    ExpectIntEQ(EC_POINT_mul(group, kdc_secret, NULL, kdc_secret, x, bn_ctx),
                1);

    /* kdc_secret == client_secret */
    ExpectIntEQ(EC_POINT_cmp(group, client_secret, kdc_secret, bn_ctx), 0);

    BN_free(x);
    BN_free(y);
    BN_free(w);
    EC_POINT_free(M);
    EC_POINT_free(N);
    EC_POINT_free(T);
    EC_POINT_free(tmp1);
    EC_POINT_free(tmp2);
    EC_POINT_free(S);
    EC_POINT_free(client_secret);
    EC_POINT_free(kdc_secret);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EC_KEY_generate(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    WOLFSSL_EC_KEY* key = NULL;
#ifndef HAVE_ECC_BRAINPOOL
    WOLFSSL_EC_GROUP* group = NULL;
#endif

    ExpectNotNull(key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(NULL), 0);
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(key), 1);
    wolfSSL_EC_KEY_free(key);
    key = NULL;

#ifndef HAVE_ECC_BRAINPOOL
    ExpectNotNull(group = wolfSSL_EC_GROUP_new_by_curve_name(
        NID_brainpoolP256r1));
    ExpectNotNull(key = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_set_group(key, group), 1);
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(key), 0);
    wolfSSL_EC_KEY_free(key);
    wolfSSL_EC_GROUP_free(group);
#endif
#endif
    return EXPECT_RESULT();
}

static int test_EC_i2d(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(HAVE_FIPS)
    EC_KEY *key = NULL;
    EC_KEY *copy = NULL;
    int len = 0;
    unsigned char *buf = NULL;
    unsigned char *p = NULL;
    const unsigned char *tmp = NULL;
    const unsigned char octBad[] = {
        0x09, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
        0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
        0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
        0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
    };

    ExpectNotNull(key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectIntEQ(EC_KEY_generate_key(key), 1);
    ExpectIntGT((len = i2d_EC_PUBKEY(key, NULL)), 0);
    ExpectNotNull(buf = (unsigned char*)XMALLOC(len, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    p = buf;
    ExpectIntEQ(i2d_EC_PUBKEY(key, &p), len);

    ExpectNull(o2i_ECPublicKey(NULL, NULL, -1));
    ExpectNull(o2i_ECPublicKey(&copy, NULL, -1));
    ExpectNull(o2i_ECPublicKey(&key, NULL, -1));
    ExpectNull(o2i_ECPublicKey(NULL, &tmp, -1));
    ExpectNull(o2i_ECPublicKey(NULL, NULL, 0));
    ExpectNull(o2i_ECPublicKey(&key, NULL, 0));
    ExpectNull(o2i_ECPublicKey(&key, &tmp, 0));
    tmp = buf;
    ExpectNull(o2i_ECPublicKey(NULL, &tmp, 0));
    ExpectNull(o2i_ECPublicKey(&copy, &tmp, 0));
    ExpectNull(o2i_ECPublicKey(NULL, &tmp, -1));
    ExpectNull(o2i_ECPublicKey(&key, &tmp, -1));

    ExpectIntEQ(i2o_ECPublicKey(NULL, NULL), 0);
    ExpectIntEQ(i2o_ECPublicKey(NULL, &buf), 0);

    tmp = buf;
    ExpectNull(d2i_ECPrivateKey(NULL, &tmp, 0));
    ExpectNull(d2i_ECPrivateKey(NULL, &tmp, 1));
    ExpectNull(d2i_ECPrivateKey(&copy, &tmp, 0));
    ExpectNull(d2i_ECPrivateKey(&copy, &tmp, 1));
    ExpectNull(d2i_ECPrivateKey(&key, &tmp, 0));

    {
        EC_KEY *pubkey = NULL;
        BIO* bio = NULL;

        ExpectNotNull(bio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(bio, buf, len), 0);
        ExpectNotNull(d2i_EC_PUBKEY_bio(bio, &pubkey));

        BIO_free(bio);
        EC_KEY_free(pubkey);
    }

    ExpectIntEQ(i2d_ECPrivateKey(NULL, &p), 0);
    ExpectIntEQ(i2d_ECPrivateKey(NULL, NULL), 0);

    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer(NULL, NULL, -1), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(NULL, NULL, -1, 0), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, NULL, -1, 0), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(NULL, buf, -1, 0), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(NULL, NULL, 0, 0), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(NULL, NULL, -1,
        WOLFSSL_EC_KEY_LOAD_PUBLIC), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(NULL, buf, len,
        WOLFSSL_EC_KEY_LOAD_PUBLIC), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, NULL, len,
        WOLFSSL_EC_KEY_LOAD_PUBLIC), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, buf, -1,
        WOLFSSL_EC_KEY_LOAD_PUBLIC), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, buf, len, 0), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, buf, len,
        WOLFSSL_EC_KEY_LOAD_PRIVATE), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, octBad, sizeof(octBad),
        WOLFSSL_EC_KEY_LOAD_PRIVATE), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, octBad, sizeof(octBad),
        WOLFSSL_EC_KEY_LOAD_PUBLIC), -1);

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    buf = NULL;
    buf = NULL;

    ExpectIntGT((len = i2d_ECPrivateKey(key, NULL)), 0);
    ExpectNotNull(buf = (unsigned char*)XMALLOC(len, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    p = buf;
    ExpectIntEQ(i2d_ECPrivateKey(key, &p), len);

    p = NULL;
    ExpectIntEQ(i2d_ECPrivateKey(key, &p), len);
    XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    p = NULL;

    /* Bad point is also an invalid private key. */
    tmp = octBad;
    ExpectNull(d2i_ECPrivateKey(&copy, &tmp, sizeof(octBad)));
    tmp = buf;
    ExpectNotNull(d2i_ECPrivateKey(&copy, &tmp, len));
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    buf = NULL;
    buf = NULL;

    ExpectIntGT((len = i2o_ECPublicKey(key, NULL)), 0);
    ExpectNotNull(buf = (unsigned char*)XMALLOC(len, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    p = buf;
    ExpectIntGT((len = i2o_ECPublicKey(key, &p)), 0);
    p = NULL;
    ExpectIntGT((len = i2o_ECPublicKey(key, &p)), 0);
    tmp = buf;
    ExpectNotNull(o2i_ECPublicKey(&copy, &tmp, len));
    tmp = octBad;
    ExpectNull(o2i_ECPublicKey(&key, &tmp, sizeof(octBad)));

    ExpectIntEQ(EC_KEY_check_key(NULL), 0);
    ExpectIntEQ(EC_KEY_check_key(key), 1);

    XFREE(p, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(buf, NULL, DYNAMIC_TYPE_OPENSSL);

    EC_KEY_free(key);
    EC_KEY_free(copy);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EC_curve(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    int nid = NID_secp160k1;
    const char* nid_name = NULL;

    ExpectNull(EC_curve_nid2nist(NID_sha256));

    ExpectNotNull(nid_name = EC_curve_nid2nist(nid));
    ExpectIntEQ(XMEMCMP(nid_name, "K-160", XSTRLEN("K-160")), 0);

    ExpectIntEQ(EC_curve_nist2nid("INVALID"), 0);
    ExpectIntEQ(EC_curve_nist2nid(nid_name), nid);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EC_KEY_dup(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS)
    WOLFSSL_EC_KEY* ecKey = NULL;
    WOLFSSL_EC_KEY* dupKey = NULL;
    ecc_key* srcKey = NULL;
    ecc_key* destKey = NULL;

    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);

    /* Valid cases */
    ExpectNotNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    ExpectIntEQ(EC_KEY_check_key(dupKey), 1);

    /* Compare pubkey */
    if (ecKey != NULL) {
        srcKey = (ecc_key*)ecKey->internal;
    }
    if (dupKey != NULL) {
        destKey = (ecc_key*)dupKey->internal;
    }
    ExpectIntEQ(wc_ecc_cmp_point(&srcKey->pubkey, &destKey->pubkey), 0);

    /* compare EC_GROUP */
    ExpectIntEQ(wolfSSL_EC_GROUP_cmp(ecKey->group, dupKey->group, NULL), MP_EQ);

    /* compare EC_POINT */
    ExpectIntEQ(wolfSSL_EC_POINT_cmp(ecKey->group, ecKey->pub_key, \
                dupKey->pub_key, NULL), MP_EQ);

    /* compare BIGNUM */
    ExpectIntEQ(wolfSSL_BN_cmp(ecKey->priv_key, dupKey->priv_key), MP_EQ);
    wolfSSL_EC_KEY_free(dupKey);
    dupKey = NULL;

    /* Invalid cases */
    /* NULL key */
    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(NULL));
    /* NULL ecc_key */
    if (ecKey != NULL) {
        wc_ecc_free((ecc_key*)ecKey->internal);
        XFREE(ecKey->internal, NULL, DYNAMIC_TYPE_ECC);
        ecKey->internal = NULL; /* Set ecc_key to NULL */
    }
    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    wolfSSL_EC_KEY_free(ecKey);
    ecKey = NULL;
    wolfSSL_EC_KEY_free(dupKey);
    dupKey = NULL;

    /* NULL Group */
    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);
    if (ecKey != NULL) {
        wolfSSL_EC_GROUP_free(ecKey->group);
        ecKey->group = NULL; /* Set group to NULL */
    }
    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    wolfSSL_EC_KEY_free(ecKey);
    ecKey = NULL;
    wolfSSL_EC_KEY_free(dupKey);
    dupKey = NULL;

    /* NULL public key */
    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);
    if (ecKey != NULL) {
        wc_ecc_del_point((ecc_point*)ecKey->pub_key->internal);
        ecKey->pub_key->internal = NULL; /* Set ecc_point to NULL */
    }

    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    if (ecKey != NULL) {
        wolfSSL_EC_POINT_free(ecKey->pub_key);
        ecKey->pub_key = NULL; /* Set pub_key to NULL */
    }
    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    wolfSSL_EC_KEY_free(ecKey);
    ecKey = NULL;
    wolfSSL_EC_KEY_free(dupKey);
    dupKey = NULL;

    /* NULL private key */
    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);

    if (ecKey != NULL) {
        wolfSSL_BN_free(ecKey->priv_key);
        ecKey->priv_key = NULL; /* Set priv_key to NULL */
    }
    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));

    wolfSSL_EC_KEY_free(ecKey);
    ecKey = NULL;
    wolfSSL_EC_KEY_free(dupKey);
    dupKey = NULL;

    /* Test EC_KEY_up_ref */
    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EC_KEY_up_ref(NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EC_KEY_up_ref(ecKey), WOLFSSL_SUCCESS);
    /* reference count doesn't follow duplicate */
    ExpectNotNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    ExpectIntEQ(wolfSSL_EC_KEY_up_ref(dupKey), WOLFSSL_SUCCESS); /* +1 */
    ExpectIntEQ(wolfSSL_EC_KEY_up_ref(dupKey), WOLFSSL_SUCCESS); /* +2 */
    wolfSSL_EC_KEY_free(dupKey); /* 3 */
    wolfSSL_EC_KEY_free(dupKey); /* 2 */
    wolfSSL_EC_KEY_free(dupKey); /* 1, free */
    wolfSSL_EC_KEY_free(ecKey);  /* 2 */
    wolfSSL_EC_KEY_free(ecKey);  /* 1, free */
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EC_KEY_set_group(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(NO_ECC256) && !defined(NO_ECC_SECP) && \
    defined(OPENSSL_EXTRA)
    EC_KEY   *key    = NULL;
    EC_GROUP *group  = NULL;
    const EC_GROUP *group2 = NULL;

    ExpectNotNull(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectNotNull(key = EC_KEY_new());

    ExpectNull(EC_KEY_get0_group(NULL));
    ExpectIntEQ(EC_KEY_set_group(NULL, NULL), 0);
    ExpectIntEQ(EC_KEY_set_group(key, NULL), 0);
    ExpectIntEQ(EC_KEY_set_group(NULL, group), 0);

    ExpectIntEQ(EC_KEY_set_group(key, group), WOLFSSL_SUCCESS);
    ExpectNotNull(group2 = EC_KEY_get0_group(key));
    ExpectIntEQ(EC_GROUP_cmp(group2, group, NULL), 0);

    EC_GROUP_free(group);
    EC_KEY_free(key);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EC_KEY_set_conv_form(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    BIO* bio = NULL;
    EC_KEY* key = NULL;

    /* Error condition: NULL key. */
    ExpectIntLT(EC_KEY_get_conv_form(NULL), 0);

    ExpectNotNull(bio = BIO_new_file("./certs/ecc-keyPub.pem", "rb"));
    ExpectNotNull(key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL));
    /* Conversion form defaults to uncompressed. */
    ExpectIntEQ(EC_KEY_get_conv_form(key), POINT_CONVERSION_UNCOMPRESSED);
#ifdef HAVE_COMP_KEY
    /* Explicitly set to compressed. */
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    ExpectIntEQ(EC_KEY_get_conv_form(key), POINT_CONVERSION_COMPRESSED);
#else
    /* Will still work just won't change anything. */
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    ExpectIntEQ(EC_KEY_get_conv_form(key), POINT_CONVERSION_UNCOMPRESSED);
    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);
    ExpectIntEQ(EC_KEY_get_conv_form(key), POINT_CONVERSION_UNCOMPRESSED);
#endif
    EC_KEY_set_conv_form(NULL, POINT_CONVERSION_UNCOMPRESSED);

    BIO_free(bio);
    EC_KEY_free(key);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EC_KEY_private_key(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    WOLFSSL_EC_KEY* key = NULL;
    WOLFSSL_BIGNUM* priv = NULL;
    WOLFSSL_BIGNUM* priv2 = NULL;
    WOLFSSL_BIGNUM* bn;

    ExpectNotNull(key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectNotNull(priv = wolfSSL_BN_new());
    ExpectNotNull(priv2 = wolfSSL_BN_new());
    ExpectIntNE(BN_set_word(priv, 2), 0);
    ExpectIntNE(BN_set_word(priv2, 2), 0);

    ExpectNull(wolfSSL_EC_KEY_get0_private_key(NULL));
    /* No private key set. */
    ExpectNull(wolfSSL_EC_KEY_get0_private_key(key));

    ExpectIntEQ(wolfSSL_EC_KEY_set_private_key(NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_KEY_set_private_key(key, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_KEY_set_private_key(NULL, priv), 0);

    ExpectIntEQ(wolfSSL_EC_KEY_set_private_key(key, priv), 1);
    ExpectNotNull(bn = wolfSSL_EC_KEY_get0_private_key(key));
    ExpectPtrNE(bn, priv);
    ExpectIntEQ(wolfSSL_EC_KEY_set_private_key(key, priv2), 1);
    ExpectNotNull(bn = wolfSSL_EC_KEY_get0_private_key(key));
    ExpectPtrNE(bn, priv2);

    wolfSSL_BN_free(priv2);
    wolfSSL_BN_free(priv);
    wolfSSL_EC_KEY_free(key);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EC_KEY_public_key(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    WOLFSSL_EC_KEY* key = NULL;
    WOLFSSL_EC_POINT* pub = NULL;
    WOLFSSL_EC_POINT* point = NULL;

    ExpectNotNull(key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

    ExpectNull(wolfSSL_EC_KEY_get0_public_key(NULL));
    ExpectNotNull(wolfSSL_EC_KEY_get0_public_key(key));

    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(key), 1);

    ExpectNotNull(pub = wolfSSL_EC_KEY_get0_public_key(key));

    ExpectIntEQ(wolfSSL_EC_KEY_set_public_key(NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_KEY_set_public_key(key, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_KEY_set_public_key(NULL, pub), 0);

    ExpectIntEQ(wolfSSL_EC_KEY_set_public_key(key, pub), 1);
    ExpectNotNull(point = wolfSSL_EC_KEY_get0_public_key(key));
    ExpectPtrEq(point, pub);

    wolfSSL_EC_KEY_free(key);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EC_KEY_print_fp(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && ((defined(HAVE_ECC224) && defined(HAVE_ECC256)) || \
    defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 224 && \
    defined(OPENSSL_EXTRA) && defined(XFPRINTF) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM)
    EC_KEY* key = NULL;

    /* Bad file pointer. */
    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(NULL, key, 0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* NULL key. */
    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(stderr, NULL, 0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectNotNull((key = wolfSSL_EC_KEY_new_by_curve_name(NID_secp224r1)));
    /* Negative indent. */
    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(stderr, key, -1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(stderr, key, 4), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(key), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(stderr, key, 4), WOLFSSL_SUCCESS);
    wolfSSL_EC_KEY_free(key);

    ExpectNotNull((key = wolfSSL_EC_KEY_new_by_curve_name(
        NID_X9_62_prime256v1)));
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(key), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(stderr, key, 4), WOLFSSL_SUCCESS);
    wolfSSL_EC_KEY_free(key);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_EC_get_builtin_curves(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    EC_builtin_curve* curves = NULL;
    size_t crv_len = 0;
    size_t i = 0;

    ExpectIntGT((crv_len = EC_get_builtin_curves(NULL, 0)), 0);
    ExpectNotNull(curves = (EC_builtin_curve*)XMALLOC(
        sizeof(EC_builtin_curve) * crv_len, NULL, DYNAMIC_TYPE_TMP_BUFFER));

    ExpectIntEQ((EC_get_builtin_curves(curves, 0)), crv_len);
    ExpectIntEQ(EC_get_builtin_curves(curves, crv_len), crv_len);

    for (i = 0; EXPECT_SUCCESS() && (i < crv_len); i++) {
        if (curves[i].comment != NULL) {
            ExpectStrEQ(OBJ_nid2sn(curves[i].nid), curves[i].comment);
        }
    }

    if (crv_len > 1) {
        ExpectIntEQ(EC_get_builtin_curves(curves, crv_len - 1), crv_len - 1);
    }

    XFREE(curves, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* OPENSSL_EXTRA || OPENSSL_ALL */
    return EXPECT_RESULT();
}

static int test_wolfSSL_ECDSA_SIG(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    WOLFSSL_ECDSA_SIG* sig = NULL;
    WOLFSSL_ECDSA_SIG* sig2 = NULL;
    WOLFSSL_BIGNUM* r = NULL;
    WOLFSSL_BIGNUM* s = NULL;
    const WOLFSSL_BIGNUM* r2 = NULL;
    const WOLFSSL_BIGNUM* s2 = NULL;
    const unsigned char* cp = NULL;
    unsigned char* p = NULL;
    unsigned char outSig[8];
    unsigned char sigData[8] =
                             { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };
    unsigned char sigDataBad[8] =
                             { 0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };

    wolfSSL_ECDSA_SIG_free(NULL);

    ExpectNotNull(sig = wolfSSL_ECDSA_SIG_new());
    ExpectNotNull(r = wolfSSL_BN_new());
    ExpectNotNull(s = wolfSSL_BN_new());
    ExpectIntEQ(wolfSSL_BN_set_word(r, 1), 1);
    ExpectIntEQ(wolfSSL_BN_set_word(s, 1), 1);

    wolfSSL_ECDSA_SIG_get0(NULL, NULL, NULL);
    wolfSSL_ECDSA_SIG_get0(NULL, &r2, NULL);
    wolfSSL_ECDSA_SIG_get0(NULL, NULL, &s2);
    wolfSSL_ECDSA_SIG_get0(NULL, &r2, &s2);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(NULL, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(sig, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(NULL, r, NULL), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(NULL, NULL, s), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(NULL, r, s), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(sig, NULL, s), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(sig, r, NULL), 0);

    r2 = NULL;
    s2 = NULL;
    wolfSSL_ECDSA_SIG_get0(NULL, &r2, &s2);
    ExpectNull(r2);
    ExpectNull(s2);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(sig, r, s), 1);
    if (EXPECT_FAIL()) {
        wolfSSL_BN_free(r);
        wolfSSL_BN_free(s);
    }
    wolfSSL_ECDSA_SIG_get0(sig, &r2, &s2);
    ExpectPtrEq(r2, r);
    ExpectPtrEq(s2, s);
    r2 = NULL;
    wolfSSL_ECDSA_SIG_get0(sig, &r2, NULL);
    ExpectPtrEq(r2, r);
    s2 = NULL;
    wolfSSL_ECDSA_SIG_get0(sig, NULL, &s2);
    ExpectPtrEq(s2, s);

    /* r and s are freed when sig is freed. */
    wolfSSL_ECDSA_SIG_free(sig);
    sig = NULL;

    ExpectNull(wolfSSL_d2i_ECDSA_SIG(NULL, NULL, sizeof(sigData)));
    cp = sigDataBad;
    ExpectNull(wolfSSL_d2i_ECDSA_SIG(NULL, &cp, sizeof(sigDataBad)));
    cp = sigData;
    ExpectNotNull((sig = wolfSSL_d2i_ECDSA_SIG(NULL, &cp, sizeof(sigData))));
    ExpectIntEQ((cp == sigData + 8), 1);
    cp = sigData;
    ExpectNull(wolfSSL_d2i_ECDSA_SIG(&sig, NULL, sizeof(sigData)));
    ExpectNotNull((sig2 = wolfSSL_d2i_ECDSA_SIG(&sig, &cp, sizeof(sigData))));
    ExpectIntEQ((sig == sig2), 1);
    cp = outSig;

    p = outSig;
    ExpectIntEQ(wolfSSL_i2d_ECDSA_SIG(NULL, &p), 0);
    ExpectIntEQ(wolfSSL_i2d_ECDSA_SIG(NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_i2d_ECDSA_SIG(sig, NULL), 8);
    ExpectIntEQ(wolfSSL_i2d_ECDSA_SIG(sig, &p), sizeof(sigData));
    ExpectIntEQ((p == outSig + 8), 1);
    ExpectIntEQ(XMEMCMP(sigData, outSig, 8), 0);

    p = NULL;
    ExpectIntEQ(wolfSSL_i2d_ECDSA_SIG(sig, &p), 8);
#ifndef WOLFSSL_I2D_ECDSA_SIG_ALLOC
    ExpectNull(p);
#else
    ExpectNotNull(p);
    ExpectIntEQ(XMEMCMP(p, outSig, 8), 0);
    XFREE(p, NULL, DYNAMIC_TYPE_OPENSSL);
#endif

    wolfSSL_ECDSA_SIG_free(sig);
#endif
    return EXPECT_RESULT();
}

static int test_ECDSA_size_sign(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ECC256) && !defined(NO_ECC_SECP)
    EC_KEY* key = NULL;
    ECDSA_SIG* ecdsaSig = NULL;
    int id;
    byte hash[WC_MAX_DIGEST_SIZE];
    byte hash2[WC_MAX_DIGEST_SIZE];
    byte sig[ECC_MAX_SIG_SIZE];
    unsigned int sigSz = sizeof(sig);

    XMEMSET(hash, 123, sizeof(hash));
    XMEMSET(hash2, 234, sizeof(hash2));

    id = wc_ecc_get_curve_id_from_name("SECP256R1");
    ExpectIntEQ(id, ECC_SECP256R1);

    ExpectNotNull(key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectIntEQ(EC_KEY_generate_key(key), 1);

    ExpectIntGE(ECDSA_size(NULL), 0);

    ExpectIntEQ(ECDSA_sign(0, hash, sizeof(hash), sig, &sigSz, NULL), 0);
    ExpectIntEQ(ECDSA_sign(0, NULL, sizeof(hash), sig, &sigSz, key), 0);
    ExpectIntEQ(ECDSA_sign(0, hash, sizeof(hash), NULL, &sigSz, key), 0);
    ExpectIntEQ(ECDSA_verify(0, hash, sizeof(hash), sig, (int)sigSz, NULL), 0);
    ExpectIntEQ(ECDSA_verify(0, NULL, sizeof(hash), sig, (int)sigSz, key), 0);
    ExpectIntEQ(ECDSA_verify(0, hash, sizeof(hash), NULL, (int)sigSz, key), 0);

    ExpectIntEQ(ECDSA_sign(0, hash, sizeof(hash), sig, &sigSz, key), 1);
    ExpectIntGE(ECDSA_size(key), sigSz);
    ExpectIntEQ(ECDSA_verify(0, hash, sizeof(hash), sig, (int)sigSz, key), 1);
    ExpectIntEQ(ECDSA_verify(0, hash2, sizeof(hash2), sig, (int)sigSz, key), 0);

    ExpectNull(ECDSA_do_sign(NULL, sizeof(hash), NULL));
    ExpectNull(ECDSA_do_sign(NULL, sizeof(hash), key));
    ExpectNull(ECDSA_do_sign(hash, sizeof(hash), NULL));
    ExpectNotNull(ecdsaSig = ECDSA_do_sign(hash, sizeof(hash), key));
    ExpectIntEQ(ECDSA_do_verify(NULL, sizeof(hash), NULL, NULL), -1);
    ExpectIntEQ(ECDSA_do_verify(hash, sizeof(hash), NULL, NULL), -1);
    ExpectIntEQ(ECDSA_do_verify(NULL, sizeof(hash), ecdsaSig, NULL), -1);
    ExpectIntEQ(ECDSA_do_verify(NULL, sizeof(hash), NULL, key), -1);
    ExpectIntEQ(ECDSA_do_verify(NULL, sizeof(hash), ecdsaSig, key), -1);
    ExpectIntEQ(ECDSA_do_verify(hash, sizeof(hash), NULL, key), -1);
    ExpectIntEQ(ECDSA_do_verify(hash, sizeof(hash), ecdsaSig, NULL), -1);
    ExpectIntEQ(ECDSA_do_verify(hash, sizeof(hash), ecdsaSig, key), 1);
    ExpectIntEQ(ECDSA_do_verify(hash2, sizeof(hash2), ecdsaSig, key), 0);
    ECDSA_SIG_free(ecdsaSig);

    EC_KEY_free(key);
#endif /* OPENSSL_EXTRA && !NO_ECC256 && !NO_ECC_SECP */
    return EXPECT_RESULT();
}

static int test_ECDH_compute_key(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ECC256) && !defined(NO_ECC_SECP) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    EC_KEY* key1 = NULL;
    EC_KEY* key2 = NULL;
    EC_POINT* pub1 = NULL;
    EC_POINT* pub2 = NULL;
    byte secret1[32];
    byte secret2[32];
    int i;

    ExpectNotNull(key1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectIntEQ(EC_KEY_generate_key(key1), 1);
    ExpectNotNull(pub1 = wolfSSL_EC_KEY_get0_public_key(key1));
    ExpectNotNull(key2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectIntEQ(EC_KEY_generate_key(key2), 1);
    ExpectNotNull(pub2 = wolfSSL_EC_KEY_get0_public_key(key2));

    ExpectIntEQ(ECDH_compute_key(NULL, sizeof(secret1), NULL, NULL, NULL), 0);
    ExpectIntEQ(ECDH_compute_key(secret1, sizeof(secret1), NULL, NULL, NULL),
        0);
    ExpectIntEQ(ECDH_compute_key(NULL, sizeof(secret1), pub2, NULL, NULL), 0);
    ExpectIntEQ(ECDH_compute_key(NULL, sizeof(secret1), NULL, key1, NULL), 0);
    ExpectIntEQ(ECDH_compute_key(NULL, sizeof(secret1), pub2, key1, NULL), 0);
    ExpectIntEQ(ECDH_compute_key(secret1, sizeof(secret1), NULL, key1, NULL),
        0);
    ExpectIntEQ(ECDH_compute_key(secret1, sizeof(secret1), pub2, NULL, NULL),
        0);

    ExpectIntEQ(ECDH_compute_key(secret1, sizeof(secret1) - 16, pub2, key1,
        NULL), 0);

    ExpectIntEQ(ECDH_compute_key(secret1, sizeof(secret1), pub2, key1, NULL),
        sizeof(secret1));
    ExpectIntEQ(ECDH_compute_key(secret2, sizeof(secret2), pub1, key2, NULL),
        sizeof(secret2));

    for (i = 0; i < (int)sizeof(secret1); i++) {
        ExpectIntEQ(secret1[i], secret2[i]);
    }

    EC_KEY_free(key2);
    EC_KEY_free(key1);
#endif /* OPENSSL_EXTRA && !NO_ECC256 && !NO_ECC_SECP &&
        * !WOLF_CRYPTO_CB_ONLY_ECC */
    return EXPECT_RESULT();
}

#endif /* HAVE_ECC && !OPENSSL_NO_PK */

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ) && \
    !defined(NO_ASN_TIME)
static int test_openssl_make_self_signed_certificate(EVP_PKEY* pkey,
        int expectedDerSz)
{
    EXPECT_DECLS;
    X509* x509 = NULL;
    BIGNUM* serial_number = NULL;
    X509_NAME* name = NULL;
    time_t epoch_off = 0;
    ASN1_INTEGER* asn1_serial_number = NULL;
    long not_before, not_after;
    int derSz;

    ExpectNotNull(x509 = X509_new());

    ExpectIntNE(X509_set_pubkey(x509, pkey), 0);

    ExpectNotNull(serial_number = BN_new());
    ExpectIntNE(BN_pseudo_rand(serial_number, 64, 0, 0), 0);
    ExpectNotNull(asn1_serial_number = X509_get_serialNumber(x509));
    ExpectNotNull(BN_to_ASN1_INTEGER(serial_number, asn1_serial_number));

    /* version 3 */
    ExpectIntNE(X509_set_version(x509, 2L), 0);

    ExpectNotNull(name = X509_NAME_new());

    ExpectIntNE(X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8,
        (unsigned char*)"www.wolfssl.com", -1, -1, 0), 0);
    ExpectIntNE(X509_NAME_add_entry_by_NID(name, NID_pkcs9_contentType,
                MBSTRING_UTF8,(unsigned char*)"Server", -1, -1, 0), 0);

    ExpectIntNE(X509_set_subject_name(x509, name), 0);
    ExpectIntNE(X509_set_issuer_name(x509, name), 0);

    not_before = (long)wc_Time(NULL);
    not_after = not_before + (365 * 24 * 60 * 60);
    ExpectNotNull(X509_time_adj(X509_get_notBefore(x509), not_before,
        &epoch_off));
    ExpectNotNull(X509_time_adj(X509_get_notAfter(x509), not_after,
        &epoch_off));

    ExpectIntNE(X509_sign(x509, pkey, EVP_sha256()), 0);

    ExpectNotNull(wolfSSL_X509_get_der(x509, &derSz));
    ExpectIntGE(derSz, expectedDerSz);

    BN_free(serial_number);
    X509_NAME_free(name);
    X509_free(x509);

    return EXPECT_RESULT();
}
#endif

static int test_openssl_generate_key_and_cert(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    int expectedDerSz;
    EVP_PKEY* pkey = NULL;
#ifdef HAVE_ECC
    EC_KEY* ec_key = NULL;
#endif
#if !defined(NO_RSA)
    int key_length = 2048;
    BIGNUM* exponent = NULL;
    RSA* rsa = NULL;

    ExpectNotNull(pkey = EVP_PKEY_new());
    ExpectNotNull(exponent = BN_new());
    ExpectNotNull(rsa = RSA_new());

    ExpectIntNE(BN_set_word(exponent, WC_RSA_EXPONENT), 0);
#ifndef WOLFSSL_KEY_GEN
    ExpectIntEQ(RSA_generate_key_ex(rsa, key_length, exponent, NULL), 0);

    #if defined(USE_CERT_BUFFERS_1024)
    ExpectIntNE(wolfSSL_RSA_LoadDer_ex(rsa, server_key_der_1024,
        sizeof_server_key_der_1024, WOLFSSL_RSA_LOAD_PRIVATE), 0);
    key_length = 1024;
    #elif defined(USE_CERT_BUFFERS_2048)
    ExpectIntNE(wolfSSL_RSA_LoadDer_ex(rsa, server_key_der_2048,
        sizeof_server_key_der_2048, WOLFSSL_RSA_LOAD_PRIVATE), 0);
    #else
    RSA_free(rsa);
    rsa = NULL;
    #endif
#else
    ExpectIntEQ(RSA_generate_key_ex(NULL, key_length, exponent, NULL), 0);
    ExpectIntEQ(RSA_generate_key_ex(rsa, 0, exponent, NULL), 0);
    ExpectIntEQ(RSA_generate_key_ex(rsa, key_length, NULL, NULL), 0);
    ExpectIntNE(RSA_generate_key_ex(rsa, key_length, exponent, NULL), 0);
#endif

    if (rsa) {
        ExpectIntNE(EVP_PKEY_assign_RSA(pkey, rsa), 0);
        if (EXPECT_FAIL()) {
            RSA_free(rsa);
        }

    #if !defined(NO_CERTS) && defined(WOLFSSL_CERT_GEN) && \
            defined(WOLFSSL_CERT_REQ) && !defined(NO_ASN_TIME)
        expectedDerSz = 743;
        ExpectIntEQ(test_openssl_make_self_signed_certificate(pkey,
                    expectedDerSz), TEST_SUCCESS);
    #endif
    }

    EVP_PKEY_free(pkey);
    pkey = NULL;
    BN_free(exponent);
#endif /* !NO_RSA */

#ifdef HAVE_ECC
    ExpectNotNull(pkey = EVP_PKEY_new());
    ExpectNotNull(ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

#ifndef NO_WOLFSSL_STUB
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
#endif

    ExpectIntNE(EC_KEY_generate_key(ec_key), 0);
    ExpectIntNE(EVP_PKEY_assign_EC_KEY(pkey, ec_key), 0);
    if (EXPECT_FAIL()) {
        EC_KEY_free(ec_key);
    }

#if !defined(NO_CERTS) && defined(WOLFSSL_CERT_GEN) && \
        defined(WOLFSSL_CERT_REQ) && !defined(NO_ASN_TIME)
    expectedDerSz = 344;
    ExpectIntEQ(test_openssl_make_self_signed_certificate(pkey, expectedDerSz),
                TEST_SUCCESS);
#endif

    EVP_PKEY_free(pkey);
#endif /* HAVE_ECC */
    (void)pkey;
    (void)expectedDerSz;
#endif /* OPENSSL_EXTRA */

    return EXPECT_RESULT();
}

static int test_stubs_are_stubs(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_STUB) && \
    !defined(NO_TLS) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER))
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL_CTX* ctxN = NULL;
  #ifndef NO_WOLFSSL_CLIENT
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
  #elif !defined(NO_WOLFSSL_SERVER)
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
  #endif

    #define CHECKZERO_RET(x, y, z) ExpectIntEQ((int) x(y), 0); \
                     ExpectIntEQ((int) x(z), 0)
    /* test logic, all stubs return same result regardless of ctx being NULL
     * as there are no sanity checks, it's just a stub! If at some
     * point a stub is not a stub it should begin to return BAD_FUNC_ARG
     * if invalid inputs are supplied. Test calling both
     * with and without valid inputs, if a stub functionality remains unchanged.
     */
    CHECKZERO_RET(wolfSSL_CTX_sess_accept, ctx, ctxN);
    CHECKZERO_RET(wolfSSL_CTX_sess_connect, ctx, ctxN);
    CHECKZERO_RET(wolfSSL_CTX_sess_accept_good, ctx, ctxN);
    CHECKZERO_RET(wolfSSL_CTX_sess_connect_good, ctx, ctxN);
    CHECKZERO_RET(wolfSSL_CTX_sess_accept_renegotiate, ctx, ctxN);
    CHECKZERO_RET(wolfSSL_CTX_sess_connect_renegotiate, ctx, ctxN);
    CHECKZERO_RET(wolfSSL_CTX_sess_hits, ctx, ctxN);
    CHECKZERO_RET(wolfSSL_CTX_sess_cb_hits, ctx, ctxN);
    CHECKZERO_RET(wolfSSL_CTX_sess_cache_full, ctx, ctxN);
    CHECKZERO_RET(wolfSSL_CTX_sess_misses, ctx, ctxN);
    CHECKZERO_RET(wolfSSL_CTX_sess_timeouts, ctx, ctxN);

    /* when implemented this should take WOLFSSL object instead, right now
     * always returns 0 */
    ExpectPtrEq(SSL_get_current_expansion(NULL), NULL);

    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    ExpectStrEQ(SSL_COMP_get_name(NULL), "not supported");
    ExpectPtrEq(SSL_get_current_expansion(NULL), NULL);
#endif /* OPENSSL_EXTRA && !NO_WOLFSSL_STUB && (!NO_WOLFSSL_CLIENT ||
        * !NO_WOLFSSL_SERVER) */
    return EXPECT_RESULT();
}

static int test_CONF_modules_xxx(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA)
    CONF_modules_free();

    CONF_modules_unload(0);
    CONF_modules_unload(1);
    CONF_modules_unload(-1);

    res = TEST_SUCCESS;
#endif /* OPENSSL_EXTRA */
    return res;
}
static int test_CRYPTO_set_dynlock_xxx(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA)
    CRYPTO_set_dynlock_create_callback(
        (struct CRYPTO_dynlock_value *(*)(const char*, int))NULL);

    CRYPTO_set_dynlock_create_callback(
        (struct CRYPTO_dynlock_value *(*)(const char*, int))1);

    CRYPTO_set_dynlock_destroy_callback(
        (void (*)(struct CRYPTO_dynlock_value*, const char*, int))NULL);

    CRYPTO_set_dynlock_destroy_callback(
        (void (*)(struct CRYPTO_dynlock_value*, const char*, int))1);

    CRYPTO_set_dynlock_lock_callback(
        (void (*)(int, struct CRYPTO_dynlock_value *, const char*, int))NULL);

    CRYPTO_set_dynlock_lock_callback(
        (void (*)(int, struct CRYPTO_dynlock_value *, const char*, int))1);

    res = TEST_SUCCESS;
#endif /* OPENSSL_EXTRA */
    return res;
}
static int test_CRYPTO_THREADID_xxx(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    CRYPTO_THREADID_current((CRYPTO_THREADID*)NULL);
    CRYPTO_THREADID_current((CRYPTO_THREADID*)1);
    ExpectIntEQ(CRYPTO_THREADID_hash((const CRYPTO_THREADID*)NULL), 0);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}
static int test_ENGINE_cleanup(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA)
    ENGINE_cleanup();

    res = TEST_SUCCESS;
#endif /* OPENSSL_EXTRA */
    return res;
}

static int test_wolfSSL_CTX_LoadCRL(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CRL) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER))
    WOLFSSL_CERT_MANAGER* cm = NULL;
    const char* issuerCert = "./certs/client-cert.pem";
    const char* validFilePath = "./certs/crl/cliCrl.pem";
    int pemType = WOLFSSL_FILETYPE_PEM;
#ifndef NO_TLS
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    const char* badPath = "dummypath";
    const char* validPath = "./certs/crl";
    int derType = WOLFSSL_FILETYPE_ASN1;
#ifdef HAVE_CRL_MONITOR
    int monitor = WOLFSSL_CRL_MONITOR;
#else
    int monitor = 0;
#endif

    #define FAIL_T1(x, y, z, p, d) ExpectIntEQ((int) x(y, z, p, d), \
                                       WC_NO_ERR_TRACE(BAD_FUNC_ARG))
    #define FAIL_T2(x, y, z, p, d) ExpectIntEQ((int) x(y, z, p, d), \
                                    WC_NO_ERR_TRACE(NOT_COMPILED_IN))
    #define SUCC_T(x, y, z, p, d) ExpectIntEQ((int) x(y, z, p, d), \
                                                WOLFSSL_SUCCESS)
#ifndef NO_WOLFSSL_CLIENT
    #define NEW_CTX(ctx) ExpectNotNull( \
            (ctx) = wolfSSL_CTX_new(wolfSSLv23_client_method()))
#elif !defined(NO_WOLFSSL_SERVER)
    #define NEW_CTX(ctx) ExpectNotNull( \
            (ctx) = wolfSSL_CTX_new(wolfSSLv23_server_method()))
#else
    #define NEW_CTX(ctx) return
#endif

    FAIL_T1(wolfSSL_CTX_LoadCRL, ctx, validPath, pemType, monitor);

    NEW_CTX(ctx);

#ifndef HAVE_CRL_MONITOR
    FAIL_T2(wolfSSL_CTX_LoadCRL, ctx, validPath, pemType, WOLFSSL_CRL_MONITOR);
    wolfSSL_CTX_free(ctx);
    NEW_CTX(ctx);
#endif

    SUCC_T (wolfSSL_CTX_LoadCRL, ctx, validPath, pemType, monitor);
    SUCC_T (wolfSSL_CTX_LoadCRL, ctx, badPath, pemType, monitor);
    SUCC_T (wolfSSL_CTX_LoadCRL, ctx, badPath, derType, monitor);

    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    NEW_CTX(ctx);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx, issuerCert, NULL),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx, validFilePath, pemType), WOLFSSL_SUCCESS);
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    NEW_CTX(ctx);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx, issuerCert, NULL),
            WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_LoadCRLFile(ssl, validFilePath, pemType), WOLFSSL_SUCCESS);
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif /* !NO_TLS */

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, issuerCert, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLFile(cm, validFilePath, pemType),
        WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_CRL) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    defined(HAVE_CRL_UPDATE_CB)
int crlUpdateTestStatus = 0;
WOLFSSL_CERT_MANAGER* updateCrlTestCm = NULL;
static void updateCrlCb(CrlInfo* old, CrlInfo* cnew)
{
    const char* crl1 = "./certs/crl/crl.pem";
    const char* crlRevoked = "./certs/crl/crl.revoked";
    byte *crl1Buff = NULL;
    word32 crl1Sz;
    byte *crlRevBuff = NULL;
    word32  crlRevSz;
    WOLFSSL_CERT_MANAGER* cm = updateCrlTestCm;
    XFILE f;
    word32 sz;
    CrlInfo crl1Info;
    CrlInfo crlRevInfo;

    crlUpdateTestStatus = 0;
    if (old == NULL || cnew == NULL) {
        return;
    }

    AssertTrue((f = XFOPEN(crl1, "rb")) != XBADFILE);
    AssertTrue(XFSEEK(f, 0, XSEEK_END) == 0);
    AssertIntGE(sz = (size_t) XFTELL(f), 1);
    AssertTrue(XFSEEK(f, 0, XSEEK_SET) == 0);
    AssertTrue( \
        (crl1Buff = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE)) != NULL);
    AssertTrue(XFREAD(crl1Buff, 1, sz, f) == sz);
    XFCLOSE(f);
    crl1Sz = sz;

    AssertTrue((f = XFOPEN(crlRevoked, "rb")) != XBADFILE);
    AssertTrue(XFSEEK(f, 0, XSEEK_END) == 0);
    AssertIntGE(sz = (size_t) XFTELL(f), 1);
    AssertTrue(XFSEEK(f, 0, XSEEK_SET) == 0);
    AssertTrue( \
        (crlRevBuff = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE)) != NULL);
    AssertTrue(XFREAD(crlRevBuff, 1, sz, f) == sz);
    XFCLOSE(f);
    crlRevSz = sz;

    AssertIntEQ(wolfSSL_CertManagerGetCRLInfo(
        cm, &crl1Info, crl1Buff, crl1Sz, WOLFSSL_FILETYPE_PEM),
        WOLFSSL_SUCCESS);
    AssertIntEQ(wolfSSL_CertManagerGetCRLInfo(
        cm, &crlRevInfo, crlRevBuff, crlRevSz, WOLFSSL_FILETYPE_PEM),
        WOLFSSL_SUCCESS);

    /* Old entry being replaced should match crl1 */
    AssertIntEQ(crl1Info.issuerHashLen,  old->issuerHashLen);
    AssertIntEQ(crl1Info.lastDateMaxLen, old->lastDateMaxLen);
    AssertIntEQ(crl1Info.lastDateFormat, old->lastDateFormat);
    AssertIntEQ(crl1Info.nextDateMaxLen, old->nextDateMaxLen);
    AssertIntEQ(crl1Info.nextDateFormat, old->nextDateFormat);
    AssertIntEQ(crl1Info.crlNumber,      old->crlNumber);
    AssertIntEQ(XMEMCMP(
        crl1Info.issuerHash, old->issuerHash, old->issuerHashLen), 0);
    AssertIntEQ(XMEMCMP(
        crl1Info.lastDate, old->lastDate, old->lastDateMaxLen), 0);
    AssertIntEQ(XMEMCMP(
        crl1Info.nextDate, old->nextDate, old->nextDateMaxLen), 0);

    /* Newer entry should match crl revoked */
    AssertIntEQ(crlRevInfo.issuerHashLen,  cnew->issuerHashLen);
    AssertIntEQ(crlRevInfo.lastDateMaxLen, cnew->lastDateMaxLen);
    AssertIntEQ(crlRevInfo.lastDateFormat, cnew->lastDateFormat);
    AssertIntEQ(crlRevInfo.nextDateMaxLen, cnew->nextDateMaxLen);
    AssertIntEQ(crlRevInfo.nextDateFormat, cnew->nextDateFormat);
    AssertIntEQ(crlRevInfo.crlNumber,      cnew->crlNumber);
    AssertIntEQ(XMEMCMP(
        crlRevInfo.issuerHash, cnew->issuerHash, cnew->issuerHashLen), 0);
    AssertIntEQ(XMEMCMP(
        crlRevInfo.lastDate, cnew->lastDate, cnew->lastDateMaxLen), 0);
    AssertIntEQ(XMEMCMP(
        crlRevInfo.nextDate, cnew->nextDate, cnew->nextDateMaxLen), 0);

    XFREE(crl1Buff, NULL, DYNAMIC_TYPE_FILE);
    XFREE(crlRevBuff, NULL, DYNAMIC_TYPE_FILE);
    crlUpdateTestStatus = 1;
}
#endif

static int test_wolfSSL_crl_update_cb(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CRL) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    defined(HAVE_CRL_UPDATE_CB)
    const char* crl1 =        "./certs/crl/crl.pem";
    const char* crlRevoked =  "./certs/crl/crl.revoked";
    const char* issuerCert =  "./certs/client-cert.pem";
    const char* caCert     =  "./certs/ca-cert.pem";
    const char* goodCert =    "./certs/server-cert.pem";
    const char* revokedCert = "./certs/server-revoked-cert.pem";
    int pemType = WOLFSSL_FILETYPE_PEM;
    WOLFSSL_CERT_MANAGER* cm = NULL;

    updateCrlTestCm = wolfSSL_CertManagerNew();
    ExpectNotNull(updateCrlTestCm);
    cm = updateCrlTestCm;
    ExpectIntEQ(wolfSSL_CertManagerSetCRLUpdate_Cb(cm, updateCrlCb),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, caCert, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, issuerCert, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLFile(cm, crl1, pemType),
        WOLFSSL_SUCCESS);
    /* CRL1 does not have good cert revoked */
    ExpectIntEQ(wolfSSL_CertManagerVerify(cm, goodCert, pemType),
        WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CertManagerVerify(cm, revokedCert, pemType),
        WOLFSSL_SUCCESS);
    /* Load newer CRL from same issuer, callback verifies CRL entry details */
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLFile(cm, crlRevoked, pemType),
        WOLFSSL_SUCCESS);
    /* CRL callback verified entry info was as expected */
    ExpectIntEQ(crlUpdateTestStatus, 1);
    /* Ensure that both certs fail with newer CRL */
    ExpectIntNE(wolfSSL_CertManagerVerify(cm, goodCert, pemType),
        WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CertManagerVerify(cm, revokedCert, pemType),
        WOLFSSL_SUCCESS);
#endif
    return EXPECT_RESULT();
}

static int test_SetTmpEC_DHE_Sz(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_SetTmpEC_DHE_Sz(ctx, 32));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_SetTmpEC_DHE_Sz(ssl, 32));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif

    return EXPECT_RESULT();
}

static int test_wolfSSL_CTX_get0_privatekey(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;

    (void)ctx;

#ifndef NO_RSA
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_method()));
    ExpectNull(SSL_CTX_get0_privatekey(ctx));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
                                                WOLFSSL_FILETYPE_PEM));
    ExpectNull(SSL_CTX_get0_privatekey(ctx));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
                                               WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(SSL_CTX_get0_privatekey(ctx));
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif
#ifdef HAVE_ECC
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_method()));
    ExpectNull(SSL_CTX_get0_privatekey(ctx));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, eccCertFile,
                                                WOLFSSL_FILETYPE_PEM));
    ExpectNull(SSL_CTX_get0_privatekey(ctx));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, eccKeyFile,
                                               WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(SSL_CTX_get0_privatekey(ctx));
    wolfSSL_CTX_free(ctx);
#endif
#endif

    return EXPECT_RESULT();
}

static int test_wolfSSL_dtls_set_mtu(void)
{
    EXPECT_DECLS;
#if (defined(WOLFSSL_DTLS_MTU) || defined(WOLFSSL_SCTP)) && \
    !defined(NO_WOLFSSL_SERVER) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    const char* testCertFile;
    const char* testKeyFile;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method()));
#ifndef NO_RSA
        testCertFile = svrCertFile;
        testKeyFile = svrKeyFile;
#elif defined(HAVE_ECC)
        testCertFile = eccCertFile;
        testKeyFile = eccKeyFile;
#endif
    if  (testCertFile != NULL && testKeyFile != NULL) {
        ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, testCertFile,
                                                    WOLFSSL_FILETYPE_PEM));
        ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, testKeyFile,
                                                   WOLFSSL_FILETYPE_PEM));
    }
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_CTX_dtls_set_mtu(NULL, 1488), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_dtls_set_mtu(NULL, 1488), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_dtls_set_mtu(ctx, 20000), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl, 20000), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_get_error(ssl, WC_NO_ERR_TRACE(WOLFSSL_FAILURE)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_dtls_set_mtu(ctx, 1488), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl, 1488), WOLFSSL_SUCCESS);

#ifdef OPENSSL_EXTRA
    ExpectIntEQ(SSL_set_mtu(ssl, 1488), WOLFSSL_SUCCESS);
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif

    return EXPECT_RESULT();
}

#if defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(SINGLE_THREADED) && \
    defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)

static WC_INLINE void generateDTLSMsg(byte* out, int outSz, word32 seq,
        enum HandShakeType hsType, word16 length)
{
    size_t idx = 0;
    byte* l;

    /* record layer */
    /* handshake type */
    out[idx++] = handshake;
    /* protocol version */
    out[idx++] = 0xfe;
    out[idx++] = 0xfd; /* DTLS 1.2 */
    /* epoch 0 */
    XMEMSET(out + idx, 0, 2);
    idx += 2;
    /* sequence number */
    XMEMSET(out + idx, 0, 6);
    c32toa(seq, out + idx + 2);
    idx += 6;
    /* length in BE */
    if (length)
        c16toa(length, out + idx);
    else
        c16toa(outSz - idx - 2, out + idx);
    idx += 2;

    /* handshake layer */
    /* handshake type */
    out[idx++] = (byte)hsType;
    /* length */
    l = out + idx;
    idx += 3;
    /* message seq */
    c16toa(0, out + idx);
    idx += 2;
    /* frag offset */
    c32to24(0, out + idx);
    idx += 3;
    /* frag length */
    c32to24((word32)outSz - (word32)idx - 3, l);
    c32to24((word32)outSz - (word32)idx - 3, out + idx);
    idx += 3;
    XMEMSET(out + idx, 0, outSz - idx);
}

static void test_wolfSSL_dtls_plaintext_server(WOLFSSL* ssl)
{
    byte msg[] = "This is a msg for the client";
    byte reply[40];
    AssertIntGT(wolfSSL_read(ssl, reply, sizeof(reply)),0);
    reply[sizeof(reply) - 1] = '\0';
    fprintf(stderr, "Client message: %s\n", reply);
    AssertIntEQ(wolfSSL_write(ssl, msg, sizeof(msg)), sizeof(msg));
}

static void test_wolfSSL_dtls_plaintext_client(WOLFSSL* ssl)
{
    byte ch[50];
    int fd = wolfSSL_get_wfd(ssl);
    byte msg[] = "This is a msg for the server";
    byte reply[40];

    AssertIntGE(fd, 0);
    generateDTLSMsg(ch, sizeof(ch), 20, client_hello, 0);
    /* Server should ignore this datagram */
    AssertIntEQ(send(fd, ch, sizeof(ch), 0), sizeof(ch));
    generateDTLSMsg(ch, sizeof(ch), 20, client_hello, 10000);
    /* Server should ignore this datagram */
    AssertIntEQ(send(fd, ch, sizeof(ch), 0), sizeof(ch));

    AssertIntEQ(wolfSSL_write(ssl, msg, sizeof(msg)), sizeof(msg));
    AssertIntGT(wolfSSL_read(ssl, reply, sizeof(reply)),0);
    reply[sizeof(reply) - 1] = '\0';
    fprintf(stderr, "Server response: %s\n", reply);
}

static int test_wolfSSL_dtls_plaintext(void)
{
    callback_functions func_cb_client;
    callback_functions func_cb_server;
    size_t i;
    struct test_params {
        method_provider client_meth;
        method_provider server_meth;
        ssl_callback on_result_server;
        ssl_callback on_result_client;
    } params[] = {
        {wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
                test_wolfSSL_dtls_plaintext_server,
                test_wolfSSL_dtls_plaintext_client},
    };

    for (i = 0; i < sizeof(params)/sizeof(*params); i++) {
        XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
        XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

        func_cb_client.doUdp = func_cb_server.doUdp = 1;
        func_cb_server.method = params[i].server_meth;
        func_cb_client.method = params[i].client_meth;
        func_cb_client.on_result = params[i].on_result_client;
        func_cb_server.on_result = params[i].on_result_server;

        test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

        if (!func_cb_client.return_code)
            return TEST_FAIL;
        if (!func_cb_server.return_code)
            return TEST_FAIL;
    }

    return TEST_RES_CHECK(1);
}
#else
static int test_wolfSSL_dtls_plaintext(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(SINGLE_THREADED) && \
    defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)

static void test_wolfSSL_dtls12_fragments_spammer(WOLFSSL* ssl)
{
    byte b[1100]; /* buffer for the messages to send */
    size_t idx = 0;
    size_t seq_offset = 0;
    size_t msg_offset = 0;
    int i;
    int fd = wolfSSL_get_wfd(ssl);
    int ret = wolfSSL_connect_cert(ssl); /* This gets us past the cookie */
    word32 seq_number = 100; /* start high so server definitely reads this */
    word16 msg_number = 50; /* start high so server has to buffer this */
    AssertIntEQ(ret, 1);
    /* Now let's start spamming the peer with fragments it needs to store */
    XMEMSET(b, -1, sizeof(b));

    /* record layer */
    /* handshake type */
    b[idx++] = 22;
    /* protocol version */
    b[idx++] = 0xfe;
    b[idx++] = 0xfd; /* DTLS 1.2 */
    /* epoch 0 */
    XMEMSET(b + idx, 0, 2);
    idx += 2;
    /* sequence number */
    XMEMSET(b + idx, 0, 6);
    seq_offset = idx + 2; /* increment only the low 32 bits */
    idx += 6;
    /* static length in BE */
    c16toa(42, b + idx);
    idx += 2;

    /* handshake layer */
    /* cert type */
    b[idx++] = 11;
    /* length */
    c32to24(1000, b + idx);
    idx += 3;
    /* message seq */
    c16toa(0, b + idx);
    msg_offset = idx;
    idx += 2;
    /* frag offset */
    c32to24(500, b + idx);
    idx += 3;
    /* frag length */
    c32to24(30, b + idx);
    idx += 3;
    (void)idx; /* inhibit clang-analyzer-deadcode.DeadStores */

    for (i = 0; i < DTLS_POOL_SZ * 2 && ret > 0;
            seq_number++, msg_number++, i++) {
        struct timespec delay;
        XMEMSET(&delay, 0, sizeof(delay));
        delay.tv_nsec = 10000000; /* wait 0.01 seconds */
        c32toa(seq_number, b + seq_offset);
        c16toa(msg_number, b + msg_offset);
        ret = (int)send(fd, b, 55, 0);
        nanosleep(&delay, NULL);
    }
}

#ifdef WOLFSSL_DTLS13
static void test_wolfSSL_dtls13_fragments_spammer(WOLFSSL* ssl)
{
    const word16 sendCountMax = 100;
    byte b[150]; /* buffer for the messages to send */
    size_t idx = 0;
    size_t msg_offset = 0;
    int fd = wolfSSL_get_wfd(ssl);
    word16 msg_number = 10; /* start high so server has to buffer this */
    int ret = wolfSSL_connect_cert(ssl); /* This gets us past the cookie */
    AssertIntEQ(ret, 1);
    /* Now let's start spamming the peer with fragments it needs to store */
    XMEMSET(b, -1, sizeof(b));

    /* handshake type */
    b[idx++] = 11;
    /* length */
    c32to24(10000, b + idx);
    idx += 3;
    /* message_seq */
    msg_offset = idx;
    idx += 2;
    /* fragment_offset */
    c32to24(5000, b + idx);
    idx += 3;
    /* fragment_length */
    c32to24(100, b + idx);
    idx += 3;
    /* fragment contents */
    idx += 100;

    for (; ret > 0 && msg_number < sendCountMax; msg_number++) {
        byte sendBuf[150];
        int sendSz = sizeof(sendBuf);
        struct timespec delay;
        XMEMSET(&delay, 0, sizeof(delay));
        delay.tv_nsec = 10000000; /* wait 0.01 seconds */
        c16toa(msg_number, b + msg_offset);
        ret = sendSz = BuildTls13Message(ssl, sendBuf, sendSz, b,
            (int)idx, handshake, 0, 0, 0);
        if (sendSz > 0)
            ret = (int)send(fd, sendBuf, (size_t)sendSz, 0);
        nanosleep(&delay, NULL);
    }
}
#endif

static int test_wolfSSL_dtls_fragments(void)
{
    EXPECT_DECLS;
    callback_functions func_cb_client;
    callback_functions func_cb_server;
    size_t i;
    struct test_params {
        method_provider client_meth;
        method_provider server_meth;
        ssl_callback spammer;
    } params[] = {
#if !defined(WOLFSSL_NO_TLS12)
        {wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
                test_wolfSSL_dtls12_fragments_spammer},
#endif
#ifdef WOLFSSL_DTLS13
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                test_wolfSSL_dtls13_fragments_spammer},
#endif
    };

    for (i = 0; i < sizeof(params)/sizeof(*params); i++) {
        XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
        XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

        func_cb_client.doUdp = func_cb_server.doUdp = 1;
        func_cb_server.method = params[i].server_meth;
        func_cb_client.method = params[i].client_meth;
        func_cb_client.ssl_ready = params[i].spammer;

        test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

        ExpectFalse(func_cb_client.return_code);
        ExpectFalse(func_cb_server.return_code);

        /* The socket should be closed by the server resulting in a
         * socket error, fatal error or reading a close notify alert */
        if (func_cb_client.last_err != WC_NO_ERR_TRACE(SOCKET_ERROR_E) &&
                func_cb_client.last_err != WOLFSSL_ERROR_ZERO_RETURN &&
                func_cb_client.last_err != WC_NO_ERR_TRACE(FATAL_ERROR)) {
            ExpectIntEQ(func_cb_client.last_err, WC_NO_ERR_TRACE(SOCKET_ERROR_E));
        }
        /* Check the server returned an error indicating the msg buffer
         * was full */
        ExpectIntEQ(func_cb_server.last_err, WC_NO_ERR_TRACE(DTLS_TOO_MANY_FRAGMENTS_E));

        if (EXPECT_FAIL())
            break;
    }

    return EXPECT_RESULT();
}

static void test_wolfSSL_dtls_send_alert(WOLFSSL* ssl)
{
    int fd, ret;
    byte alert_msg[] = {
        0x15, /* alert type */
        0xfe, 0xfd, /* version */
        0x00, 0x00, /* epoch */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* seq number */
        0x00, 0x02, /* length */
        0x02, /* level: fatal */
        0x46 /* protocol version */
    };

    fd = wolfSSL_get_wfd(ssl);
    AssertIntGE(fd, 0);
    ret = (int)send(fd, alert_msg, sizeof(alert_msg), 0);
    AssertIntGT(ret, 0);
}

static int _test_wolfSSL_ignore_alert_before_cookie(byte version12)
{
    callback_functions client_cbs, server_cbs;

    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));
    client_cbs.doUdp = server_cbs.doUdp = 1;
    if (version12) {
#if !defined(WOLFSSL_NO_TLS12)
        client_cbs.method = wolfDTLSv1_2_client_method;
        server_cbs.method = wolfDTLSv1_2_server_method;
#else
        return TEST_SKIPPED;
#endif
    }
    else
    {
#ifdef WOLFSSL_DTLS13
        client_cbs.method = wolfDTLSv1_3_client_method;
        server_cbs.method = wolfDTLSv1_3_server_method;
#else
        return TEST_SKIPPED;
#endif /* WOLFSSL_DTLS13 */
    }

    client_cbs.ssl_ready = test_wolfSSL_dtls_send_alert;
    test_wolfSSL_client_server_nofail(&client_cbs, &server_cbs);

    if (!client_cbs.return_code)
        return TEST_FAIL;
    if (!server_cbs.return_code)
        return TEST_FAIL;

    return TEST_SUCCESS;
}

static int test_wolfSSL_ignore_alert_before_cookie(void)
{
    int ret;
    ret =_test_wolfSSL_ignore_alert_before_cookie(0);
    if (ret != 0)
        return ret;
    ret =_test_wolfSSL_ignore_alert_before_cookie(1);
    if (ret != 0)
        return ret;
    return 0;
}

static void test_wolfSSL_send_bad_record(WOLFSSL* ssl)
{
    int ret;
    int fd;

    byte bad_msg[] = {
        0x17, /* app data  */
        0xaa, 0xfd, /* bad version */
        0x00, 0x01, /* epoch 1 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x55, /* not seen seq number */
        0x00, 0x26, /* length: 38 bytes */
        0xae, 0x30, 0x31, 0xb1, 0xf1, 0xb9, 0x6f, 0xda, 0x17, 0x19, 0xd9, 0x57,
        0xa9, 0x9d, 0x5c, 0x51, 0x9b, 0x53, 0x63, 0xa5, 0x24, 0x70, 0xa1,
        0xae, 0xdf, 0x1c, 0xb9, 0xfc, 0xe3, 0xd7, 0x77, 0x6d, 0xb6, 0x89, 0x0f,
        0x03, 0x18, 0x72
    };

    fd = wolfSSL_get_wfd(ssl);
    AssertIntGE(fd, 0);
    ret = (int)send(fd, bad_msg, sizeof(bad_msg), 0);
    AssertIntEQ(ret, sizeof(bad_msg));
    ret = wolfSSL_write(ssl, "badrecordtest", sizeof("badrecordtest"));
    AssertIntEQ(ret, sizeof("badrecordtest"));
}

static void test_wolfSSL_read_string(WOLFSSL* ssl)
{
    byte buf[100];
    int ret;

    ret = wolfSSL_read(ssl, buf, sizeof(buf));
    AssertIntGT(ret, 0);
    AssertIntEQ(strcmp((char*)buf, "badrecordtest"), 0);
}

static int _test_wolfSSL_dtls_bad_record(
    method_provider client_method, method_provider server_method)
{
    callback_functions client_cbs, server_cbs;

    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));
    client_cbs.doUdp = server_cbs.doUdp = 1;
    client_cbs.method = client_method;
    server_cbs.method = server_method;

    client_cbs.on_result = test_wolfSSL_send_bad_record;
    server_cbs.on_result = test_wolfSSL_read_string;

    test_wolfSSL_client_server_nofail(&client_cbs, &server_cbs);

    if (!client_cbs.return_code)
        return TEST_FAIL;
    if (!server_cbs.return_code)
        return TEST_FAIL;

    return TEST_SUCCESS;
}

static int test_wolfSSL_dtls_bad_record(void)
{
    int ret = TEST_SUCCESS;
#if !defined(WOLFSSL_NO_TLS12)
    ret = _test_wolfSSL_dtls_bad_record(wolfDTLSv1_2_client_method,
        wolfDTLSv1_2_server_method);
#endif
#ifdef WOLFSSL_DTLS13
    if (ret == TEST_SUCCESS) {
        ret = _test_wolfSSL_dtls_bad_record(wolfDTLSv1_3_client_method,
        wolfDTLSv1_3_server_method);
    }
#endif /* WOLFSSL_DTLS13 */
    return ret;

}

#else
static int test_wolfSSL_dtls_fragments(void)
{
    return TEST_SKIPPED;
}
static int test_wolfSSL_ignore_alert_before_cookie(void)
{
    return TEST_SKIPPED;
}
static int test_wolfSSL_dtls_bad_record(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_DTLS13) && !defined(WOLFSSL_TLS13_IGNORE_AEAD_LIMITS) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES)
static volatile int test_AEAD_seq_num = 0;
#ifdef WOLFSSL_ATOMIC_INITIALIZER
wolfSSL_Atomic_Int test_AEAD_done = WOLFSSL_ATOMIC_INITIALIZER(0);
#else
static volatile int test_AEAD_done = 0;
#endif
#ifdef WOLFSSL_MUTEX_INITIALIZER
static wolfSSL_Mutex test_AEAD_mutex = WOLFSSL_MUTEX_INITIALIZER(test_AEAD_mutex);
#endif

static int test_AEAD_fail_decryption = 0;
static int test_AEAD_cbiorecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int fd = wolfSSL_get_fd(ssl);
    int ret = -1;
    if (fd >= 0 && (ret = (int)recv(fd, buf, sz, 0)) > 0) {
        if (test_AEAD_fail_decryption) {
            /* Modify the packet to trigger a decryption failure */
            buf[ret/2] ^= 0xFF;
            if (test_AEAD_fail_decryption == 1)
                test_AEAD_fail_decryption = 0;
        }
    }
    (void)ctx;
    return ret;
}

static void test_AEAD_get_limits(WOLFSSL* ssl, w64wrapper* hardLimit,
        w64wrapper* keyUpdateLimit, w64wrapper* sendLimit)
{
    if (sendLimit)
        w64Zero(sendLimit);
    switch (ssl->specs.bulk_cipher_algorithm) {
        case wolfssl_aes_gcm:
            if (sendLimit)
                *sendLimit = AEAD_AES_LIMIT;
            FALL_THROUGH;
        case wolfssl_chacha:
            if (hardLimit)
                *hardLimit = DTLS_AEAD_AES_GCM_CHACHA_FAIL_LIMIT;
            if (keyUpdateLimit)
                *keyUpdateLimit = DTLS_AEAD_AES_GCM_CHACHA_FAIL_KU_LIMIT;
            break;
        case wolfssl_aes_ccm:
            if (sendLimit)
                *sendLimit = DTLS_AEAD_AES_CCM_LIMIT;
            if (ssl->specs.aead_mac_size == AES_CCM_8_AUTH_SZ) {
                if (hardLimit)
                    *hardLimit = DTLS_AEAD_AES_CCM_8_FAIL_LIMIT;
                if (keyUpdateLimit)
                    *keyUpdateLimit = DTLS_AEAD_AES_CCM_8_FAIL_KU_LIMIT;
            }
            else {
                if (hardLimit)
                    *hardLimit = DTLS_AEAD_AES_CCM_FAIL_LIMIT;
                if (keyUpdateLimit)
                    *keyUpdateLimit = DTLS_AEAD_AES_CCM_FAIL_KU_LIMIT;
            }
            break;
        default:
            fprintf(stderr, "Unrecognized bulk cipher");
            AssertFalse(1);
            break;
    }
}

static void test_AEAD_limit_client(WOLFSSL* ssl)
{
    int ret;
    int i;
    int didReKey = 0;
    char msgBuf[20];
    w64wrapper hardLimit;
    w64wrapper keyUpdateLimit;
    w64wrapper counter;
    w64wrapper sendLimit;

    test_AEAD_get_limits(ssl, &hardLimit, &keyUpdateLimit, &sendLimit);

    w64Zero(&counter);
    AssertTrue(w64Equal(Dtls13GetEpoch(ssl, ssl->dtls13Epoch)->dropCount, counter));

    wolfSSL_SSLSetIORecv(ssl, test_AEAD_cbiorecv);

    for (i = 0; i < 10; i++) {
        /* Test some failed decryptions */
        test_AEAD_fail_decryption = 1;
        w64Increment(&counter);
        ret = wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
        /* Should succeed since decryption failures are dropped */
        AssertIntGT(ret, 0);
        AssertTrue(w64Equal(Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount, counter));
    }

    test_AEAD_fail_decryption = 1;
    Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount = keyUpdateLimit;
    w64Increment(&Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount);
    /* 100 read calls should be enough to complete the key update */
    w64Zero(&counter);
    for (i = 0; i < 100; i++) {
        /* Key update should be sent and negotiated */
        ret = wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
        AssertIntGT(ret, 0);
        /* Epoch after one key update is 4 */
        if (w64Equal(ssl->dtls13PeerEpoch, w64From32(0, 4)) &&
                w64Equal(Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount, counter)) {
            didReKey = 1;
            break;
        }
    }
    AssertTrue(didReKey);

    if (!w64IsZero(sendLimit)) {
        /* Test the sending limit for AEAD ciphers */
#ifdef WOLFSSL_MUTEX_INITIALIZER
        (void)wc_LockMutex(&test_AEAD_mutex);
#endif
        Dtls13GetEpoch(ssl, ssl->dtls13Epoch)->nextSeqNumber = sendLimit;
        test_AEAD_seq_num = 1;
        XMEMSET(msgBuf, 0, sizeof(msgBuf));
        ret = wolfSSL_write(ssl, msgBuf, sizeof(msgBuf));
        AssertIntGT(ret, 0);
        didReKey = 0;
        w64Zero(&counter);
#ifdef WOLFSSL_MUTEX_INITIALIZER
        wc_UnLockMutex(&test_AEAD_mutex);
#endif
        /* 100 read calls should be enough to complete the key update */
        for (i = 0; i < 100; i++) {
            /* Key update should be sent and negotiated */
            ret = wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
            AssertIntGT(ret, 0);
            /* Epoch after another key update is 5 */
            if (w64Equal(ssl->dtls13Epoch, w64From32(0, 5)) &&
                    w64Equal(Dtls13GetEpoch(ssl, ssl->dtls13Epoch)->dropCount, counter)) {
                didReKey = 1;
                break;
            }
        }
        AssertTrue(didReKey);
    }

    test_AEAD_fail_decryption = 2;
    Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount = hardLimit;
    w64Decrement(&Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount);
    /* Connection should fail with a DECRYPT_ERROR */
    ret = wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
    AssertIntEQ(ret, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    AssertIntEQ(wolfSSL_get_error(ssl, ret), WC_NO_ERR_TRACE(DECRYPT_ERROR));

#ifdef WOLFSSL_ATOMIC_INITIALIZER
    WOLFSSL_ATOMIC_STORE(test_AEAD_done, 1);
#else
    test_AEAD_done = 1;
#endif
}

int counter = 0;
static void test_AEAD_limit_server(WOLFSSL* ssl)
{
    char msgBuf[] = "Sending data";
    int ret = WOLFSSL_SUCCESS;
    w64wrapper sendLimit;
    SOCKET_T fd = wolfSSL_get_fd(ssl);
    struct timespec delay;
    XMEMSET(&delay, 0, sizeof(delay));
    delay.tv_nsec = 100000000; /* wait 0.1 seconds */
    tcp_set_nonblocking(&fd); /* So that read doesn't block */
    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    test_AEAD_get_limits(ssl, NULL, NULL, &sendLimit);
    while (!
    #ifdef WOLFSSL_ATOMIC_INITIALIZER
           WOLFSSL_ATOMIC_LOAD(test_AEAD_done)
    #else
           test_AEAD_done
    #endif
           && ret > 0)
    {
        counter++;
#ifdef WOLFSSL_MUTEX_INITIALIZER
        (void)wc_LockMutex(&test_AEAD_mutex);
#endif
        if (test_AEAD_seq_num) {
            /* We need to update the seq number so that we can understand the
             * peer. Otherwise we will incorrectly interpret the seq number. */
            Dtls13Epoch* e = Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch);
            AssertNotNull(e);
            e->nextPeerSeqNumber = sendLimit;
            test_AEAD_seq_num = 0;
        }
#ifdef WOLFSSL_MUTEX_INITIALIZER
        wc_UnLockMutex(&test_AEAD_mutex);
#endif
        (void)wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
        ret = wolfSSL_write(ssl, msgBuf, sizeof(msgBuf));
        nanosleep(&delay, NULL);
    }
}

static int test_wolfSSL_dtls_AEAD_limit(void)
{
    callback_functions func_cb_client;
    callback_functions func_cb_server;
    XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
    XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

    func_cb_client.doUdp = func_cb_server.doUdp = 1;
    func_cb_server.method = wolfDTLSv1_3_server_method;
    func_cb_client.method = wolfDTLSv1_3_client_method;
    func_cb_server.on_result = test_AEAD_limit_server;
    func_cb_client.on_result = test_AEAD_limit_client;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    if (!func_cb_client.return_code)
        return TEST_FAIL;
    if (!func_cb_server.return_code)
        return TEST_FAIL;

    return TEST_SUCCESS;
}
#else
static int test_wolfSSL_dtls_AEAD_limit(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_DTLS) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(SINGLE_THREADED) && \
    !defined(DEBUG_VECTOR_REGISTER_ACCESS_FUZZING)
static void test_wolfSSL_dtls_send_ch(WOLFSSL* ssl)
{
    int fd, ret;
    byte ch_msg[] = {
        0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xfa, 0x01, 0x00, 0x01, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xee, 0xfe, 0xfd, 0xc0, 0xca, 0xb5, 0x6f, 0x3d, 0x23, 0xcc, 0x53, 0x9a,
        0x67, 0x17, 0x70, 0xd3, 0xfb, 0x23, 0x16, 0x9e, 0x4e, 0xd6, 0x7e, 0x29,
        0xab, 0xfa, 0x4c, 0xa5, 0x84, 0x95, 0xc3, 0xdb, 0x21, 0x9a, 0x52, 0x00,
        0x00, 0x00, 0x36, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0,
        0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0x00, 0x9f, 0x00, 0x9e, 0xcc, 0xa9, 0xcc,
        0xa8, 0xcc, 0xaa, 0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x28, 0xc0, 0x24, 0xc0,
        0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x6b, 0x00, 0x67, 0x00,
        0x39, 0x00, 0x33, 0xcc, 0x14, 0xcc, 0x13, 0xcc, 0x15, 0x01, 0x00, 0x01,
        0x8e, 0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc, 0x00, 0x0d, 0x00, 0x20,
        0x00, 0x1e, 0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x02, 0x03, 0x08, 0x06,
        0x08, 0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08, 0x09, 0x06, 0x01,
        0x05, 0x01, 0x04, 0x01, 0x03, 0x01, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x0c,
        0x00, 0x0a, 0x00, 0x19, 0x00, 0x18, 0x00, 0x17, 0x00, 0x15, 0x01, 0x00,
        0x00, 0x16, 0x00, 0x00, 0x00, 0x33, 0x01, 0x4b, 0x01, 0x49, 0x00, 0x17,
        0x00, 0x41, 0x04, 0x96, 0xcb, 0x2e, 0x4e, 0xd9, 0x88, 0x71, 0xc7, 0xf3,
        0x1a, 0x16, 0xdd, 0x7a, 0x7c, 0xf7, 0x67, 0x8a, 0x5d, 0x9a, 0x55, 0xa6,
        0x4a, 0x90, 0xd9, 0xfb, 0xc7, 0xfb, 0xbe, 0x09, 0xa9, 0x8a, 0xb5, 0x7a,
        0xd1, 0xde, 0x83, 0x74, 0x27, 0x31, 0x1c, 0xaa, 0xae, 0xef, 0x58, 0x43,
        0x13, 0x7d, 0x15, 0x4d, 0x7f, 0x68, 0xf6, 0x8a, 0x38, 0xef, 0x0e, 0xb3,
        0xcf, 0xb8, 0x4a, 0xa9, 0xb4, 0xd7, 0xcb, 0x01, 0x00, 0x01, 0x00, 0x1d,
        0x0a, 0x22, 0x8a, 0xd1, 0x78, 0x85, 0x1e, 0x5a, 0xe1, 0x1d, 0x1e, 0xb7,
        0x2d, 0xbc, 0x5f, 0x52, 0xbc, 0x97, 0x5d, 0x8b, 0x6a, 0x8b, 0x9d, 0x1e,
        0xb1, 0xfc, 0x8a, 0xb2, 0x56, 0xcd, 0xed, 0x4b, 0xfb, 0x66, 0x3f, 0x59,
        0x3f, 0x15, 0x5d, 0x09, 0x9e, 0x2f, 0x60, 0x5b, 0x31, 0x81, 0x27, 0xf0,
        0x1c, 0xda, 0xcd, 0x48, 0x66, 0xc6, 0xbb, 0x25, 0xf0, 0x5f, 0xda, 0x4c,
        0xcf, 0x1d, 0x88, 0xc8, 0xda, 0x1b, 0x53, 0xea, 0xbd, 0xce, 0x6d, 0xf6,
        0x4a, 0x76, 0xdb, 0x75, 0x99, 0xaf, 0xcf, 0x76, 0x4a, 0xfb, 0xe3, 0xef,
        0xb2, 0xcb, 0xae, 0x4a, 0xc0, 0xe8, 0x63, 0x1f, 0xd6, 0xe8, 0xe6, 0x45,
        0xf9, 0xea, 0x0d, 0x06, 0x19, 0xfc, 0xb1, 0xfd, 0x5d, 0x92, 0x89, 0x7b,
        0xc7, 0x9f, 0x1a, 0xb3, 0x2b, 0xc7, 0xad, 0x0e, 0xfb, 0x13, 0x41, 0x83,
        0x84, 0x58, 0x3a, 0x25, 0xb9, 0x49, 0x35, 0x1c, 0x23, 0xcb, 0xd6, 0xe7,
        0xc2, 0x8c, 0x4b, 0x2a, 0x73, 0xa1, 0xdf, 0x4f, 0x73, 0x9b, 0xb3, 0xd2,
        0xb2, 0x95, 0x00, 0x3c, 0x26, 0x09, 0x89, 0x71, 0x05, 0x39, 0xc8, 0x98,
        0x8f, 0xed, 0x32, 0x15, 0x78, 0xcd, 0xd3, 0x7e, 0xfb, 0x5a, 0x78, 0x2a,
        0xdc, 0xca, 0x20, 0x09, 0xb5, 0x14, 0xf9, 0xd4, 0x58, 0xf6, 0x69, 0xf8,
        0x65, 0x9f, 0xb7, 0xe4, 0x93, 0xf1, 0xa3, 0x84, 0x7e, 0x1b, 0x23, 0x5d,
        0xea, 0x59, 0x3e, 0x4d, 0xca, 0xfd, 0xa5, 0x55, 0xdd, 0x99, 0xb5, 0x02,
        0xf8, 0x0d, 0xe5, 0xf4, 0x06, 0xb0, 0x43, 0x9e, 0x2e, 0xbf, 0x05, 0x33,
        0x65, 0x7b, 0x13, 0x8c, 0xf9, 0x16, 0x4d, 0xc5, 0x15, 0x0b, 0x40, 0x2f,
        0x66, 0x94, 0xf2, 0x43, 0x95, 0xe7, 0xa9, 0xb6, 0x39, 0x99, 0x73, 0xb3,
        0xb0, 0x06, 0xfe, 0x52, 0x9e, 0x57, 0xba, 0x75, 0xfd, 0x76, 0x7b, 0x20,
        0x31, 0x68, 0x4c
    };

    fd = wolfSSL_get_wfd(ssl);
    AssertIntGE(fd, 0);
    ret = (int)send(fd, ch_msg, sizeof(ch_msg), 0);
    AssertIntGT(ret, 0);
    /* consume the HRR otherwise handshake will fail */
    ret = (int)recv(fd, ch_msg, sizeof(ch_msg), 0);
    AssertIntGT(ret, 0);
}

#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SEND_HRR_COOKIE)
static void test_wolfSSL_dtls_send_ch_with_invalid_cookie(WOLFSSL* ssl)
{
    int fd, ret;
    byte ch_msh_invalid_cookie[] = {
      0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
      0x4e, 0x01, 0x00, 0x02, 0x42, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02,
      0x42, 0xfe, 0xfd, 0x69, 0xca, 0x77, 0x60, 0x6f, 0xfc, 0xd1, 0x5b, 0x60,
      0x5d, 0xf1, 0xa6, 0x5c, 0x44, 0x71, 0xae, 0xca, 0x62, 0x19, 0x0c, 0xb6,
      0xf7, 0x2c, 0xa6, 0xd5, 0xd2, 0x99, 0x9d, 0x18, 0xae, 0xac, 0x11, 0x00,
      0x00, 0x00, 0x36, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0,
      0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0x00, 0x9f, 0x00, 0x9e, 0xcc, 0xa9, 0xcc,
      0xa8, 0xcc, 0xaa, 0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x28, 0xc0, 0x24, 0xc0,
      0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x6b, 0x00, 0x67, 0x00,
      0x39, 0x00, 0x33, 0xcc, 0x14, 0xcc, 0x13, 0xcc, 0x15, 0x01, 0x00, 0x01,
      0xe2, 0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc, 0x00, 0x0d, 0x00, 0x20,
      0x00, 0x1e, 0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x02, 0x03, 0x08, 0x06,
      0x08, 0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08, 0x09, 0x06, 0x01,
      0x05, 0x01, 0x04, 0x01, 0x03, 0x01, 0x02, 0x01, 0x00, 0x2c, 0x00, 0x45,
      0x00, 0x43, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2d, 0x00,
      0x03, 0x02, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x19,
      0x00, 0x18, 0x00, 0x17, 0x00, 0x15, 0x01, 0x00, 0x00, 0x16, 0x00, 0x00,
      0x00, 0x33, 0x01, 0x4b, 0x01, 0x49, 0x00, 0x17, 0x00, 0x41, 0x04, 0x7c,
      0x5a, 0xc2, 0x5a, 0xfd, 0xcd, 0x2b, 0x08, 0xb2, 0xeb, 0x8e, 0xc0, 0x02,
      0x03, 0x9d, 0xb1, 0xc1, 0x0d, 0x7b, 0x7f, 0x46, 0x43, 0xdf, 0xf3, 0xee,
      0x2b, 0x78, 0x0e, 0x29, 0x8c, 0x42, 0x11, 0x2c, 0xde, 0xd7, 0x41, 0x0f,
      0x28, 0x94, 0x80, 0x41, 0x70, 0xc4, 0x17, 0xfd, 0x6d, 0xfa, 0xee, 0x9a,
      0xf2, 0xc4, 0x15, 0x4c, 0x5f, 0x54, 0xb6, 0x78, 0x6e, 0xf9, 0x63, 0x27,
      0x33, 0xb8, 0x7b, 0x01, 0x00, 0x01, 0x00, 0xd4, 0x46, 0x62, 0x9c, 0xbf,
      0x8f, 0x1b, 0x65, 0x9b, 0xf0, 0x29, 0x64, 0xd8, 0x50, 0x0e, 0x74, 0xf1,
      0x58, 0x10, 0xc9, 0xd9, 0x82, 0x5b, 0xd9, 0xbe, 0x14, 0xdf, 0xde, 0x86,
      0xb4, 0x2e, 0x15, 0xee, 0x4f, 0xf6, 0x74, 0x9e, 0x59, 0x11, 0x36, 0x2d,
      0xb9, 0x67, 0xaa, 0x5a, 0x09, 0x9b, 0x45, 0xf1, 0x01, 0x4c, 0x4e, 0xf6,
      0xda, 0x6a, 0xae, 0xa7, 0x73, 0x7b, 0x2e, 0xb6, 0x24, 0x89, 0x99, 0xb7,
      0x52, 0x16, 0x62, 0x0a, 0xab, 0x58, 0xf8, 0x3f, 0x10, 0x5b, 0x83, 0xfd,
      0x7b, 0x81, 0x77, 0x81, 0x8d, 0xef, 0x24, 0x56, 0x6d, 0xba, 0x49, 0xd4,
      0x8b, 0xb5, 0xa0, 0xb1, 0xc9, 0x8c, 0x32, 0x95, 0x1c, 0x5e, 0x0a, 0x4b,
      0xf6, 0x00, 0x50, 0x0a, 0x87, 0x99, 0x59, 0xcf, 0x6f, 0x9d, 0x02, 0xd0,
      0x1b, 0xa1, 0x96, 0x45, 0x28, 0x76, 0x40, 0x33, 0x28, 0xc9, 0xa1, 0xfd,
      0x46, 0xab, 0x2c, 0x9e, 0x5e, 0xc6, 0x74, 0x19, 0x9a, 0xf5, 0x9b, 0x51,
      0x11, 0x4f, 0xc8, 0xb9, 0x99, 0x6b, 0x4e, 0x3e, 0x31, 0x64, 0xb4, 0x92,
      0xf4, 0x0d, 0x41, 0x4b, 0x2c, 0x65, 0x23, 0xf7, 0x47, 0xe3, 0xa5, 0x2e,
      0xe4, 0x9c, 0x2b, 0xc9, 0x41, 0x22, 0x83, 0x8a, 0x23, 0xef, 0x29, 0x7e,
      0x4f, 0x3f, 0xa3, 0xbf, 0x73, 0x2b, 0xd7, 0xcc, 0xc8, 0xc6, 0xe9, 0xbc,
      0x01, 0xb7, 0x32, 0x63, 0xd4, 0x7e, 0x7f, 0x9a, 0xaf, 0x5f, 0x05, 0x31,
      0x53, 0xd6, 0x1f, 0xa2, 0xd0, 0xdf, 0x67, 0x56, 0xf1, 0x9c, 0x4a, 0x9d,
      0x83, 0xb4, 0xef, 0xb3, 0xf2, 0xcc, 0xf1, 0x91, 0x6c, 0x47, 0xc3, 0x8b,
      0xd0, 0x92, 0x79, 0x3d, 0xa0, 0xc0, 0x3a, 0x57, 0x26, 0x6d, 0x0a, 0xad,
      0x5f, 0xad, 0xb4, 0x74, 0x48, 0x4a, 0x51, 0xe1, 0xb5, 0x82, 0x0a, 0x4c,
      0x4f, 0x9d, 0xaf, 0xee, 0x5a, 0xa2, 0x4d, 0x4d, 0x5f, 0xe0, 0x17, 0x00,
      0x23, 0x00, 0x00
    };
    byte alert_reply[50];
    byte expected_alert_reply[] = {
        0x15, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x02, 0x02, 0x2f
    };

    fd = wolfSSL_get_wfd(ssl);
    if (fd >= 0) {
        ret = (int)send(fd, ch_msh_invalid_cookie,
                sizeof(ch_msh_invalid_cookie), 0);
        AssertIntGT(ret, 0);
        /* should reply with an illegal_parameter reply */
        ret = (int)recv(fd, alert_reply, sizeof(alert_reply), 0);
        AssertIntEQ(ret, sizeof(expected_alert_reply));
        AssertIntEQ(XMEMCMP(alert_reply, expected_alert_reply,
                sizeof(expected_alert_reply)), 0);
    }
}
#endif

static word32 test_wolfSSL_dtls_stateless_HashWOLFSSL(const WOLFSSL* ssl)
{
#ifndef NO_MD5
    enum wc_HashType hashType = WC_HASH_TYPE_MD5;
#elif !defined(NO_SHA)
    enum wc_HashType hashType = WC_HASH_TYPE_SHA;
#elif !defined(NO_SHA256)
    enum wc_HashType hashType = WC_HASH_TYPE_SHA256;
#else
    #error "We need a digest to hash the WOLFSSL object"
#endif
    byte hashBuf[WC_MAX_DIGEST_SIZE];
    wc_HashAlg hash;
    const TLSX* exts = ssl->extensions;
    WOLFSSL sslCopy; /* Use a copy to omit certain fields */
    HS_Hashes* hsHashes = ssl->hsHashes; /* Is re-allocated in
                                          * InitHandshakeHashes */

    XMEMCPY(&sslCopy, ssl, sizeof(*ssl));
    XMEMSET(hashBuf, 0, sizeof(hashBuf));

    /* Following fields are not important to compare */
    XMEMSET(sslCopy.buffers.inputBuffer.staticBuffer, 0, STATIC_BUFFER_LEN);
    sslCopy.buffers.inputBuffer.buffer = NULL;
    sslCopy.buffers.inputBuffer.bufferSize = 0;
    sslCopy.buffers.inputBuffer.dynamicFlag = 0;
    sslCopy.buffers.inputBuffer.offset = 0;
    XMEMSET(sslCopy.buffers.outputBuffer.staticBuffer, 0, STATIC_BUFFER_LEN);
    sslCopy.buffers.outputBuffer.buffer = NULL;
    sslCopy.buffers.outputBuffer.bufferSize = 0;
    sslCopy.buffers.outputBuffer.dynamicFlag = 0;
    sslCopy.buffers.outputBuffer.offset = 0;
    sslCopy.error = 0;
    sslCopy.curSize = 0;
    sslCopy.curStartIdx = 0;
    sslCopy.keys.curSeq_lo = 0;
    XMEMSET(&sslCopy.curRL, 0, sizeof(sslCopy.curRL));
#ifdef WOLFSSL_DTLS13
    XMEMSET(&sslCopy.keys.curSeq, 0, sizeof(sslCopy.keys.curSeq));
    sslCopy.dtls13FastTimeout = 0;
#endif
    sslCopy.keys.dtls_peer_handshake_number = 0;
    XMEMSET(&sslCopy.alert_history, 0, sizeof(sslCopy.alert_history));
    sslCopy.hsHashes = NULL;
#ifdef WOLFSSL_ASYNC_IO
#ifdef WOLFSSL_ASYNC_CRYPT
    sslCopy.asyncDev = NULL;
#endif
    sslCopy.async = NULL;
#endif

    AssertIntEQ(wc_HashInit(&hash, hashType), 0);
    AssertIntEQ(wc_HashUpdate(&hash, hashType, (byte*)&sslCopy, sizeof(sslCopy)), 0);
    /* hash extension list */
    while (exts != NULL) {
        AssertIntEQ(wc_HashUpdate(&hash, hashType, (byte*)exts, sizeof(*exts)), 0);
        exts = exts->next;
    }
    /* Hash suites */
    if (sslCopy.suites != NULL) {
        AssertIntEQ(wc_HashUpdate(&hash, hashType, (byte*)sslCopy.suites,
                sizeof(struct Suites)), 0);
    }
    /* Hash hsHashes */
    AssertIntEQ(wc_HashUpdate(&hash, hashType, (byte*)hsHashes,
            sizeof(*hsHashes)), 0);
    AssertIntEQ(wc_HashFinal(&hash, hashType, hashBuf), 0);
    AssertIntEQ(wc_HashFree(&hash, hashType), 0);

    return MakeWordFromHash(hashBuf);
}

static CallbackIORecv test_wolfSSL_dtls_compare_stateless_cb;
static int test_wolfSSL_dtls_compare_stateless_cb_call_once;
static int test_wolfSSL_dtls_compare_stateless_read_cb_once(WOLFSSL *ssl,
        char *buf, int sz, void *ctx)
{
    if (test_wolfSSL_dtls_compare_stateless_cb_call_once) {
        test_wolfSSL_dtls_compare_stateless_cb_call_once = 0;
        return test_wolfSSL_dtls_compare_stateless_cb(ssl, buf, sz, ctx);
    }
    else {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
}

static void test_wolfSSL_dtls_compare_stateless(WOLFSSL* ssl)
{
    /* Compare the ssl object before and after one ClientHello msg */
    SOCKET_T fd = wolfSSL_get_fd(ssl);
    int res;
    int err;
    word32 initHash;

    test_wolfSSL_dtls_compare_stateless_cb = ssl->CBIORecv;
    test_wolfSSL_dtls_compare_stateless_cb_call_once = 1;
    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    ssl->CBIORecv = test_wolfSSL_dtls_compare_stateless_read_cb_once;

    initHash = test_wolfSSL_dtls_stateless_HashWOLFSSL(ssl);
    (void)initHash;

    res = tcp_select(fd, 5);
    /* We are expecting a msg. A timeout indicates failure. */
    AssertIntEQ(res, TEST_RECV_READY);

    res = wolfSSL_accept(ssl);
    err = wolfSSL_get_error(ssl, res);
    AssertIntEQ(res, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    AssertIntEQ(err, WOLFSSL_ERROR_WANT_READ);

    AssertIntEQ(initHash, test_wolfSSL_dtls_stateless_HashWOLFSSL(ssl));

    wolfSSL_dtls_set_using_nonblock(ssl, 0);
    ssl->CBIORecv = test_wolfSSL_dtls_compare_stateless_cb;

}

#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SEND_HRR_COOKIE)
static void test_wolfSSL_dtls_enable_hrrcookie(WOLFSSL* ssl)
{
    int ret;
    ret = wolfSSL_send_hrr_cookie(ssl, NULL, 0);
    AssertIntEQ(ret, WOLFSSL_SUCCESS);
    test_wolfSSL_dtls_compare_stateless(ssl);
}
#endif

static int test_wolfSSL_dtls_stateless(void)
{
    callback_functions client_cbs, server_cbs;
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        ssl_callback client_ssl_ready;
        ssl_callback server_ssl_ready;
    } test_params[] = {
#if !defined(WOLFSSL_NO_TLS12)
        {wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
                test_wolfSSL_dtls_send_ch, test_wolfSSL_dtls_compare_stateless},
#endif
#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SEND_HRR_COOKIE)
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                test_wolfSSL_dtls_send_ch, test_wolfSSL_dtls_enable_hrrcookie},
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                test_wolfSSL_dtls_send_ch_with_invalid_cookie, test_wolfSSL_dtls_enable_hrrcookie},
#endif
    };

    if (0 == sizeof(test_params)){
        return TEST_SKIPPED;
    }

    for (i = 0; i < sizeof(test_params)/sizeof(*test_params); i++) {
        XMEMSET(&client_cbs, 0, sizeof(client_cbs));
        XMEMSET(&server_cbs, 0, sizeof(server_cbs));
        client_cbs.doUdp = server_cbs.doUdp = 1;
        client_cbs.method = test_params[i].client_meth;
        server_cbs.method = test_params[i].server_meth;

        client_cbs.ssl_ready = test_params[i].client_ssl_ready;
        server_cbs.ssl_ready = test_params[i].server_ssl_ready;
        test_wolfSSL_client_server_nofail(&client_cbs, &server_cbs);

        if (!client_cbs.return_code)
            return TEST_FAIL;
        if (!server_cbs.return_code)
            return TEST_FAIL;
    }

    return TEST_SUCCESS;
}
#else
static int test_wolfSSL_dtls_stateless(void)
{
    return TEST_SKIPPED;
}
#endif /* WOLFSSL_DTLS13 && WOLFSSL_SEND_HRR_COOKIE &&
        * HAVE_IO_TESTS_DEPENDENCIES && !SINGLE_THREADED */

#ifdef HAVE_CERT_CHAIN_VALIDATION
static int load_ca_into_cm(WOLFSSL_CERT_MANAGER* cm, char* certA)
{
    int ret;

    if ((ret = wolfSSL_CertManagerLoadCA(cm, certA, 0)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "loading cert %s failed\n", certA);
        fprintf(stderr, "Error: (%d): %s\n", ret,
            wolfSSL_ERR_reason_error_string((word32)ret));
        return -1;
    }

    return 0;
}

static int verify_cert_with_cm(WOLFSSL_CERT_MANAGER* cm, char* certA)
{
    int ret;
    if ((ret = wolfSSL_CertManagerVerify(cm, certA, WOLFSSL_FILETYPE_PEM))
                                                         != WOLFSSL_SUCCESS) {
        fprintf(stderr, "could not verify the cert: %s\n", certA);
        fprintf(stderr, "Error: (%d): %s\n", ret,
            wolfSSL_ERR_reason_error_string((word32)ret));
        return -1;
    }
    else {
        fprintf(stderr, "successfully verified: %s\n", certA);
    }

    return 0;
}
#define LOAD_ONE_CA(a, b, c, d)                         \
                    do {                                \
                        (a) = load_ca_into_cm(c, d);    \
                        if ((a) != 0)                   \
                            return (b);                 \
                        else                            \
                            (b)--;                      \
                    } while(0)

#define VERIFY_ONE_CERT(a, b, c, d)                     \
                    do {                                \
                        (a) = verify_cert_with_cm(c, d);\
                        if ((a) != 0)                   \
                            return (b);                 \
                        else                            \
                            (b)--;                      \
                    } while(0)

static int test_chainG(WOLFSSL_CERT_MANAGER* cm)
{
    int ret;
    int i = -1;
    /* Chain G is a valid chain per RFC 5280 section 4.2.1.9 */
    char chainGArr[9][50] = {"certs/ca-cert.pem",
                             "certs/test-pathlen/chainG-ICA7-pathlen100.pem",
                             "certs/test-pathlen/chainG-ICA6-pathlen10.pem",
                             "certs/test-pathlen/chainG-ICA5-pathlen20.pem",
                             "certs/test-pathlen/chainG-ICA4-pathlen5.pem",
                             "certs/test-pathlen/chainG-ICA3-pathlen99.pem",
                             "certs/test-pathlen/chainG-ICA2-pathlen1.pem",
                             "certs/test-pathlen/chainG-ICA1-pathlen0.pem",
                             "certs/test-pathlen/chainG-entity.pem"};

    LOAD_ONE_CA(ret, i, cm, chainGArr[0]); /* if failure, i = -1 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[1]); /* if failure, i = -2 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[2]); /* if failure, i = -3 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[3]); /* if failure, i = -4 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[4]); /* if failure, i = -5 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[5]); /* if failure, i = -6 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[6]); /* if failure, i = -7 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[7]); /* if failure, i = -8 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[1]); /* if failure, i = -9 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[2]); /* if failure, i = -10 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[3]); /* if failure, i = -11 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[4]); /* if failure, i = -12 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[5]); /* if failure, i = -13 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[6]); /* if failure, i = -14 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[7]); /* if failure, i = -15 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[8]); /* if failure, i = -16 here */

    /* test validating the entity twice, should have no effect on pathLen since
     * entity/leaf cert */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[8]); /* if failure, i = -17 here */

    return ret;
}

static int test_chainH(WOLFSSL_CERT_MANAGER* cm)
{
    int ret;
    int i = -1;
    /* Chain H is NOT a valid chain per RFC5280 section 4.2.1.9:
     * ICA4-pathlen of 2 signing ICA3-pathlen of 2 (reduce max path len to 2)
     * ICA3-pathlen of 2 signing ICA2-pathlen of 2 (reduce max path len to 1)
     * ICA2-pathlen of 2 signing ICA1-pathlen of 0 (reduce max path len to 0)
     * ICA1-pathlen of 0 signing entity (pathlen is already 0, ERROR)
     * Test should successfully verify ICA4, ICA3, ICA2 and then fail on ICA1
     */
    char chainHArr[6][50] = {"certs/ca-cert.pem",
                             "certs/test-pathlen/chainH-ICA4-pathlen2.pem",
                             "certs/test-pathlen/chainH-ICA3-pathlen2.pem",
                             "certs/test-pathlen/chainH-ICA2-pathlen2.pem",
                             "certs/test-pathlen/chainH-ICA1-pathlen0.pem",
                             "certs/test-pathlen/chainH-entity.pem"};

    LOAD_ONE_CA(ret, i, cm, chainHArr[0]); /* if failure, i = -1 here */
    LOAD_ONE_CA(ret, i, cm, chainHArr[1]); /* if failure, i = -2 here */
    LOAD_ONE_CA(ret, i, cm, chainHArr[2]); /* if failure, i = -3 here */
    LOAD_ONE_CA(ret, i, cm, chainHArr[3]); /* if failure, i = -4 here */
    LOAD_ONE_CA(ret, i, cm, chainHArr[4]); /* if failure, i = -5 here */
    VERIFY_ONE_CERT(ret, i, cm, chainHArr[1]); /* if failure, i = -6 here */
    VERIFY_ONE_CERT(ret, i, cm, chainHArr[2]); /* if failure, i = -7 here */
    VERIFY_ONE_CERT(ret, i, cm, chainHArr[3]); /* if failure, i = -8 here */
    VERIFY_ONE_CERT(ret, i, cm, chainHArr[4]); /* if failure, i = -9 here */
    VERIFY_ONE_CERT(ret, i, cm, chainHArr[5]); /* if failure, i = -10 here */

    return ret;
}

static int test_chainI(WOLFSSL_CERT_MANAGER* cm)
{
    int ret;
    int i = -1;
    /* Chain I is a valid chain per RFC5280 section 4.2.1.9:
     * ICA3-pathlen of 2 signing ICA2 without a pathlen (reduce maxPathLen to 2)
     * ICA2-no_pathlen signing ICA1-no_pathlen (reduce maxPathLen to 1)
     * ICA1-no_pathlen signing entity (reduce maxPathLen to 0)
     * Test should successfully verify ICA4, ICA3, ICA2 and then fail on ICA1
     */
    char chainIArr[5][50] = {"certs/ca-cert.pem",
                             "certs/test-pathlen/chainI-ICA3-pathlen2.pem",
                             "certs/test-pathlen/chainI-ICA2-no_pathlen.pem",
                             "certs/test-pathlen/chainI-ICA1-no_pathlen.pem",
                             "certs/test-pathlen/chainI-entity.pem"};

    LOAD_ONE_CA(ret, i, cm, chainIArr[0]); /* if failure, i = -1 here */
    LOAD_ONE_CA(ret, i, cm, chainIArr[1]); /* if failure, i = -2 here */
    LOAD_ONE_CA(ret, i, cm, chainIArr[2]); /* if failure, i = -3 here */
    LOAD_ONE_CA(ret, i, cm, chainIArr[3]); /* if failure, i = -4 here */
    VERIFY_ONE_CERT(ret, i, cm, chainIArr[1]); /* if failure, i = -5 here */
    VERIFY_ONE_CERT(ret, i, cm, chainIArr[2]); /* if failure, i = -6 here */
    VERIFY_ONE_CERT(ret, i, cm, chainIArr[3]); /* if failure, i = -7 here */
    VERIFY_ONE_CERT(ret, i, cm, chainIArr[4]); /* if failure, i = -8 here */

    return ret;
}

static int test_chainJ(WOLFSSL_CERT_MANAGER* cm)
{
    int ret;
    int i = -1;
    /* Chain J is NOT a valid chain per RFC5280 section 4.2.1.9:
     * ICA4-pathlen of 2 signing ICA3 without a pathlen (reduce maxPathLen to 2)
     * ICA3-pathlen of 2 signing ICA2 without a pathlen (reduce maxPathLen to 1)
     * ICA2-no_pathlen signing ICA1-no_pathlen (reduce maxPathLen to 0)
     * ICA1-no_pathlen signing entity (ERROR, pathlen zero and non-leaf cert)
     */
    char chainJArr[6][50] = {"certs/ca-cert.pem",
                             "certs/test-pathlen/chainJ-ICA4-pathlen2.pem",
                             "certs/test-pathlen/chainJ-ICA3-no_pathlen.pem",
                             "certs/test-pathlen/chainJ-ICA2-no_pathlen.pem",
                             "certs/test-pathlen/chainJ-ICA1-no_pathlen.pem",
                             "certs/test-pathlen/chainJ-entity.pem"};

    LOAD_ONE_CA(ret, i, cm, chainJArr[0]); /* if failure, i = -1 here */
    LOAD_ONE_CA(ret, i, cm, chainJArr[1]); /* if failure, i = -2 here */
    LOAD_ONE_CA(ret, i, cm, chainJArr[2]); /* if failure, i = -3 here */
    LOAD_ONE_CA(ret, i, cm, chainJArr[3]); /* if failure, i = -4 here */
    LOAD_ONE_CA(ret, i, cm, chainJArr[4]); /* if failure, i = -5 here */
    VERIFY_ONE_CERT(ret, i, cm, chainJArr[1]); /* if failure, i = -6 here */
    VERIFY_ONE_CERT(ret, i, cm, chainJArr[2]); /* if failure, i = -7 here */
    VERIFY_ONE_CERT(ret, i, cm, chainJArr[3]); /* if failure, i = -8 here */
    VERIFY_ONE_CERT(ret, i, cm, chainJArr[4]); /* if failure, i = -9 here */
    VERIFY_ONE_CERT(ret, i, cm, chainJArr[5]); /* if failure, i = -10 here */

    return ret;
}

static int test_various_pathlen_chains(void)
{
    EXPECT_DECLS;
    WOLFSSL_CERT_MANAGER* cm = NULL;

    /* Test chain G (large chain with varying pathLens) */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
    ExpectIntEQ(test_chainG(cm), -1);
#else
    ExpectIntEQ(test_chainG(cm), 0);
#endif /* NO_WOLFSSL_CLIENT && NO_WOLFSSL_SERVER */
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    /* end test chain G */

    /* Test chain H (5 chain with same pathLens) */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntLT(test_chainH(cm), 0);
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    /* end test chain H */

    /* Test chain I (only first ICA has pathLen set and it's set to 2,
     * followed by 2 ICA's, should pass) */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
    ExpectIntEQ(test_chainI(cm), -1);
#else
    ExpectIntEQ(test_chainI(cm), 0);
#endif /* NO_WOLFSSL_CLIENT && NO_WOLFSSL_SERVER */
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    cm = NULL;

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    cm = NULL;

    /* Test chain J (Again only first ICA has pathLen set and it's set to 2,
     * this time followed by 3 ICA's, should fail */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntLT(test_chainJ(cm), 0);
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    cm = NULL;

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);

    return EXPECT_RESULT();
}
#endif /* !NO_RSA && !NO_SHA && !NO_FILESYSTEM && !NO_CERTS */

#if defined(HAVE_KEYING_MATERIAL) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
static int test_export_keying_material_cb(WOLFSSL_CTX *ctx, WOLFSSL *ssl)
{
    EXPECT_DECLS;
    byte ekm[100] = {0};

    (void)ctx;

    /* Success Cases */
    ExpectIntEQ(wolfSSL_export_keying_material(ssl, ekm, sizeof(ekm),
            "Test label", XSTR_SIZEOF("Test label"), NULL, 0, 0), 1);
    ExpectIntEQ(wolfSSL_export_keying_material(ssl, ekm, sizeof(ekm),
            "Test label", XSTR_SIZEOF("Test label"), NULL, 0, 1), 1);
    /* Use some random context */
    ExpectIntEQ(wolfSSL_export_keying_material(ssl, ekm, sizeof(ekm),
            "Test label", XSTR_SIZEOF("Test label"), ekm, 10, 1), 1);
    /* Failure cases */
    ExpectIntEQ(wolfSSL_export_keying_material(ssl, ekm, sizeof(ekm),
            "client finished", XSTR_SIZEOF("client finished"), NULL, 0, 0), 0);
    ExpectIntEQ(wolfSSL_export_keying_material(ssl, ekm, sizeof(ekm),
            "server finished", XSTR_SIZEOF("server finished"), NULL, 0, 0), 0);
    ExpectIntEQ(wolfSSL_export_keying_material(ssl, ekm, sizeof(ekm),
            "master secret", XSTR_SIZEOF("master secret"), NULL, 0, 0), 0);
    ExpectIntEQ(wolfSSL_export_keying_material(ssl, ekm, sizeof(ekm),
            "extended master secret", XSTR_SIZEOF("extended master secret"),
            NULL, 0, 0), 0);
    ExpectIntEQ(wolfSSL_export_keying_material(ssl, ekm, sizeof(ekm),
            "key expansion", XSTR_SIZEOF("key expansion"), NULL, 0, 0), 0);

    return EXPECT_RESULT();
}

static int test_export_keying_material_ssl_cb(WOLFSSL* ssl)
{
    wolfSSL_KeepArrays(ssl);
    return TEST_SUCCESS;
}

static int test_export_keying_material(void)
{
    EXPECT_DECLS;
    test_ssl_cbf serverCb;
    test_ssl_cbf clientCb;

    XMEMSET(&serverCb, 0, sizeof(serverCb));
    XMEMSET(&clientCb, 0, sizeof(clientCb));
    clientCb.ssl_ready = test_export_keying_material_ssl_cb;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&clientCb,
        &serverCb, test_export_keying_material_cb), TEST_SUCCESS);

    return EXPECT_RESULT();
}
#endif /* HAVE_KEYING_MATERIAL */

static int test_wolfSSL_THREADID_hash(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    CRYPTO_THREADID id;

    CRYPTO_THREADID_current(NULL);
    /* Hash result is word32. */
    ExpectTrue(CRYPTO_THREADID_hash(NULL) == 0UL);
    XMEMSET(&id, 0, sizeof(id));
    ExpectTrue(CRYPTO_THREADID_hash(&id) == 0UL);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}
static int test_wolfSSL_set_ecdh_auto(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(SSL_set_ecdh_auto(NULL,0), 1);
    ExpectIntEQ(SSL_set_ecdh_auto(NULL,1), 1);
    ExpectIntEQ(SSL_set_ecdh_auto(ssl,0), 1);
    ExpectIntEQ(SSL_set_ecdh_auto(ssl,1), 1);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}
static int test_wolfSSL_CTX_set_ecdh_auto(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    WOLFSSL_CTX* ctx = NULL;

    ExpectIntEQ(SSL_CTX_set_ecdh_auto(NULL,0), 1);
    ExpectIntEQ(SSL_CTX_set_ecdh_auto(NULL,1), 1);
    ExpectIntEQ(SSL_CTX_set_ecdh_auto(ctx,0), 1);
    ExpectIntEQ(SSL_CTX_set_ecdh_auto(ctx,1), 1);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_ERROR_CODE_OPENSSL) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
static THREAD_RETURN WOLFSSL_THREAD SSL_read_test_server_thread(void* args)
{
    EXPECT_DECLS;
    callback_functions* callbacks = NULL;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    SOCKET_T     sfd = 0;
    SOCKET_T     cfd = 0;
    word16       port;
    char msg[] = "I hear you fa shizzle!";
    int  len   = (int) XSTRLEN(msg);
    char input[1024];
    int  ret = 0;
    int  err = 0;

    if (!args)
        WOLFSSL_RETURN_FROM_THREAD(0);

    ((func_args*)args)->return_code = TEST_FAIL;

    callbacks   = ((func_args*)args)->callbacks;
    ctx         = wolfSSL_CTX_new(callbacks->method());

#if defined(USE_WINDOWS_API)
    port = ((func_args*)args)->signal->port;
#else
    /* Let tcp_listen assign port */
    port = 0;
#endif

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_load_verify_locations(ctx,
        caCertFile, 0));

    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_use_certificate_file(ctx,
        svrCertFile, WOLFSSL_FILETYPE_PEM));

    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_use_PrivateKey_file(ctx,
        svrKeyFile, WOLFSSL_FILETYPE_PEM));

#if !defined(NO_FILESYSTEM) && !defined(NO_DH)
    ExpectIntEQ(wolfSSL_CTX_SetTmpDH_file(ctx, dhParamFile,
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
#elif !defined(NO_DH)
    SetDHCtx(ctx);  /* will repick suites with DHE, higher priority than PSK */
#endif

    if (callbacks->ctx_ready)
        callbacks->ctx_ready(ctx);

    ssl = wolfSSL_new(ctx);
    ExpectNotNull(ssl);

    /* listen and accept */
    tcp_accept(&sfd, &cfd, (func_args*)args, port, 0, 0, 0, 0, 1, 0, 0);
    CloseSocket(sfd);

    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_set_fd(ssl, cfd));

    if (callbacks->ssl_ready)
        callbacks->ssl_ready(ssl);

    if (EXPECT_SUCCESS()) {
        do {
            err = 0; /* Reset error */
            ret = wolfSSL_accept(ssl);
            if (ret != WOLFSSL_SUCCESS) {
                err = wolfSSL_get_error(ssl, 0);
            }
        } while (ret != WOLFSSL_SUCCESS && err == WC_NO_ERR_TRACE(WC_PENDING_E));
    }

    ExpectIntEQ(ret, WOLFSSL_SUCCESS);

    /* read and write data */
    XMEMSET(input, 0, sizeof(input));

    while (EXPECT_SUCCESS()) {
        ret = wolfSSL_read(ssl, input, sizeof(input));
        if (ret > 0) {
            break;
        }
        else {
            err = wolfSSL_get_error(ssl,ret);
            if (err == WOLFSSL_ERROR_WANT_READ) {
                continue;
            }
            break;
        }
    }

    if (EXPECT_SUCCESS() && (err == WOLFSSL_ERROR_ZERO_RETURN)) {
        do {
            ret = wolfSSL_write(ssl, msg, len);
            if (ret > 0) {
                break;
            }
        } while (ret < 0);
    }

    /* bidirectional shutdown */
    while (EXPECT_SUCCESS()) {
        ret = wolfSSL_shutdown(ssl);
        ExpectIntNE(ret, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        if (ret == WOLFSSL_SUCCESS) {
            break;
        }
    }

    if (EXPECT_SUCCESS()) {
        /* wait for the peer to disconnect the tcp connection */
        do {
            ret = wolfSSL_read(ssl, input, sizeof(input));
            err = wolfSSL_get_error(ssl, ret);
        } while (ret > 0 || err != WOLFSSL_ERROR_ZERO_RETURN);
    }

    /* detect TCP disconnect */
    ExpectIntLE(ret,WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_get_error(ssl, ret), WOLFSSL_ERROR_ZERO_RETURN);

    ((func_args*)args)->return_code = EXPECT_RESULT();

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    CloseSocket(cfd);
#if defined(HAVE_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif
    WOLFSSL_RETURN_FROM_THREAD(0);
}
static THREAD_RETURN WOLFSSL_THREAD SSL_read_test_client_thread(void* args)
{
    EXPECT_DECLS;
    callback_functions* callbacks = NULL;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    SOCKET_T     sfd = 0;
    char msg[] = "hello wolfssl server!";
    int  len   = (int) XSTRLEN(msg);
    char input[1024];
    int  idx;
    int  ret, err;

    if (!args)
        WOLFSSL_RETURN_FROM_THREAD(0);

    ((func_args*)args)->return_code = TEST_FAIL;
    callbacks   = ((func_args*)args)->callbacks;
    ctx         = wolfSSL_CTX_new(callbacks->method());

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_load_verify_locations(ctx,
        caCertFile, 0));

    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_use_certificate_file(ctx,
        cliCertFile, WOLFSSL_FILETYPE_PEM));

    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_use_PrivateKey_file(ctx,
        cliKeyFile, WOLFSSL_FILETYPE_PEM));

    ExpectNotNull((ssl = wolfSSL_new(ctx)));

    tcp_connect(&sfd, wolfSSLIP, ((func_args*)args)->signal->port, 0, 0, ssl);

    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_set_fd(ssl, sfd));

    if (EXPECT_SUCCESS()) {
        do {
            err = 0; /* Reset error */
            ret = wolfSSL_connect(ssl);
            if (ret != WOLFSSL_SUCCESS) {
                err = wolfSSL_get_error(ssl, 0);
            }
        } while (ret != WOLFSSL_SUCCESS && err == WC_NO_ERR_TRACE(WC_PENDING_E));
    }

    ExpectIntGE(wolfSSL_write(ssl, msg, len), 0);

    if (EXPECT_SUCCESS()) {
        if (0 < (idx = wolfSSL_read(ssl, input, sizeof(input)-1))) {
            input[idx] = 0;
        }
    }

    if (EXPECT_SUCCESS()) {
        ret = wolfSSL_shutdown(ssl);
        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE) {
            ret = wolfSSL_shutdown(ssl);
        }
    }
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);

    ((func_args*)args)->return_code = EXPECT_RESULT();

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    CloseSocket(sfd);
#if defined(HAVE_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif
    WOLFSSL_RETURN_FROM_THREAD(0);
}
#endif /* OPENSSL_EXTRA && WOLFSSL_ERROR_CODE_OPENSSL &&
          HAVE_IO_TESTS_DEPENDENCIES && !WOLFSSL_NO_TLS12 */

/* This test is to check wolfSSL_read behaves as same as
 * openSSL when it is called after SSL_shutdown completes.
 */
static int test_wolfSSL_read_detect_TCP_disconnect(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_ERROR_CODE_OPENSSL) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;
    THREAD_TYPE clientThread;
    callback_functions server_cbf;
    callback_functions client_cbf;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif
    StartTCP();
    InitTcpReady(&ready);

#if defined(USE_WINDOWS_API)
    /* use RNG to get random port if using windows */
    ready.port = GetRandomPort();
#endif

    XMEMSET(&client_args, 0, sizeof(func_args));
    XMEMSET(&server_args, 0, sizeof(func_args));

    XMEMSET(&server_cbf, 0, sizeof(callback_functions));
    XMEMSET(&client_cbf, 0, sizeof(callback_functions));

    server_cbf.method = wolfTLSv1_2_server_method;
    client_cbf.method = wolfTLSv1_2_client_method;

    server_args.callbacks = &server_cbf;
    client_args.callbacks = &client_cbf;

    server_args.signal = &ready;
    client_args.signal = &ready;

    start_thread(SSL_read_test_server_thread, &server_args, &serverThread);

    wait_tcp_ready(&server_args);

    start_thread(SSL_read_test_client_thread, &client_args, &clientThread);

    join_thread(clientThread);
    join_thread(serverThread);

    ExpectTrue(client_args.return_code);
    ExpectTrue(server_args.return_code);

    FreeTcpReady(&ready);
#endif
    return EXPECT_RESULT();
}
static int test_wolfSSL_CTX_get_min_proto_version(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_TLS)
    WOLFSSL_CTX *ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_method()));
    ExpectIntEQ(wolfSSL_CTX_set_min_proto_version(ctx, SSL3_VERSION),
        WOLFSSL_SUCCESS);
    #ifdef WOLFSSL_ALLOW_SSLV3
        ExpectIntEQ(wolfSSL_CTX_get_min_proto_version(ctx), SSL3_VERSION);
    #else
        ExpectIntGT(wolfSSL_CTX_get_min_proto_version(ctx), SSL3_VERSION);
    #endif
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    #ifndef NO_OLD_TLS
    #ifdef WOLFSSL_ALLOW_TLSV10
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_method()));
    #else
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_method()));
    #endif
    ExpectIntEQ(wolfSSL_CTX_set_min_proto_version(ctx, TLS1_VERSION),
        WOLFSSL_SUCCESS);
    #ifdef WOLFSSL_ALLOW_TLSV10
        ExpectIntEQ(wolfSSL_CTX_get_min_proto_version(ctx), TLS1_VERSION);
    #else
        ExpectIntGT(wolfSSL_CTX_get_min_proto_version(ctx), TLS1_VERSION);
    #endif
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
    #endif

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_method()));
    ExpectIntEQ(wolfSSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION),
        WOLFSSL_SUCCESS);
    #ifndef NO_OLD_TLS
        ExpectIntEQ(wolfSSL_CTX_get_min_proto_version(ctx), TLS1_1_VERSION);
    #else
        ExpectIntGT(wolfSSL_CTX_get_min_proto_version(ctx), TLS1_1_VERSION);
    #endif
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    #ifndef WOLFSSL_NO_TLS12
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_method()));
        ExpectIntEQ(wolfSSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_get_min_proto_version(ctx), TLS1_2_VERSION);
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
    #endif

    #ifdef WOLFSSL_TLS13
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_method()));
        ExpectIntEQ(wolfSSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_get_min_proto_version(ctx), TLS1_3_VERSION);
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
    #endif
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
    defined(WOLFSSL_OPENSSH) || defined(HAVE_SBLIM_SFCB)))
static int test_wolfSSL_set_SSL_CTX(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) \
    && !defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_TLS13) && \
    !defined(NO_RSA)
    WOLFSSL_CTX *ctx1 = NULL;
    WOLFSSL_CTX *ctx2 = NULL;
    WOLFSSL *ssl = NULL;
    const byte *session_id1 = (const byte *)"CTX1";
    const byte *session_id2 = (const byte *)"CTX2";

    ExpectNotNull(ctx1 = wolfSSL_CTX_new(wolfTLS_server_method()));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx1, svrCertFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx1, svrKeyFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectIntEQ(wolfSSL_CTX_set_min_proto_version(ctx1, TLS1_2_VERSION),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_get_min_proto_version(ctx1), TLS1_2_VERSION);
    ExpectIntEQ(wolfSSL_CTX_get_max_proto_version(ctx1), TLS1_3_VERSION);
    ExpectIntEQ(wolfSSL_CTX_set_session_id_context(ctx1, session_id1, 4),
        WOLFSSL_SUCCESS);

    ExpectNotNull(ctx2 = wolfSSL_CTX_new(wolfTLS_server_method()));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx2, svrCertFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx2, svrKeyFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectIntEQ(wolfSSL_CTX_set_min_proto_version(ctx2, TLS1_2_VERSION),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_max_proto_version(ctx2, TLS1_2_VERSION),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_get_min_proto_version(ctx2), TLS1_2_VERSION);
    ExpectIntEQ(wolfSSL_CTX_get_max_proto_version(ctx2), TLS1_2_VERSION);
    ExpectIntEQ(wolfSSL_CTX_set_session_id_context(ctx2, session_id2, 4),
        WOLFSSL_SUCCESS);

#ifdef HAVE_SESSION_TICKET
    ExpectIntEQ((wolfSSL_CTX_get_options(ctx1) & SSL_OP_NO_TICKET), 0);
    wolfSSL_CTX_set_options(ctx2, SSL_OP_NO_TICKET);
    ExpectIntNE((wolfSSL_CTX_get_options(ctx2) & SSL_OP_NO_TICKET), 0);
#endif

    ExpectNotNull(ssl = wolfSSL_new(ctx2));
    ExpectIntNE((wolfSSL_get_options(ssl) & WOLFSSL_OP_NO_TLSv1_3), 0);
#ifdef WOLFSSL_INT_H
#ifdef WOLFSSL_SESSION_ID_CTX
    ExpectIntEQ(XMEMCMP(ssl->sessionCtx, session_id2, 4), 0);
#endif
#ifdef WOLFSSL_COPY_CERT
    if (ctx2 != NULL && ctx2->certificate != NULL) {
        ExpectFalse(ssl->buffers.certificate == ctx2->certificate);
    }
    if (ctx2 != NULL && ctx2->certChain != NULL) {
        ExpectFalse(ssl->buffers.certChain == ctx2->certChain);
    }
#else
    ExpectTrue(ssl->buffers.certificate == ctx2->certificate);
    ExpectTrue(ssl->buffers.certChain == ctx2->certChain);
#endif
#endif

#ifdef HAVE_SESSION_TICKET
    ExpectIntNE((wolfSSL_get_options(ssl) & SSL_OP_NO_TICKET), 0);
#endif

    /* Set the ctx1 that has TLSv1.3 as max proto version */
    ExpectNotNull(wolfSSL_set_SSL_CTX(ssl, ctx1));

    /* MUST not change proto versions of ssl */
    ExpectIntNE((wolfSSL_get_options(ssl) & WOLFSSL_OP_NO_TLSv1_3), 0);
#ifdef HAVE_SESSION_TICKET
    /* MUST not change */
    ExpectIntNE((wolfSSL_get_options(ssl) & SSL_OP_NO_TICKET), 0);
#endif
    /* MUST change */
#ifdef WOLFSSL_INT_H
#ifdef WOLFSSL_COPY_CERT
    if (ctx1 != NULL && ctx1->certificate != NULL) {
        ExpectFalse(ssl->buffers.certificate == ctx1->certificate);
    }
    if (ctx1 != NULL && ctx1->certChain != NULL) {
        ExpectFalse(ssl->buffers.certChain == ctx1->certChain);
    }
#else
    ExpectTrue(ssl->buffers.certificate == ctx1->certificate);
    ExpectTrue(ssl->buffers.certChain == ctx1->certChain);
#endif
#ifdef WOLFSSL_SESSION_ID_CTX
    ExpectIntEQ(XMEMCMP(ssl->sessionCtx, session_id1, 4), 0);
#endif
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx1);
    wolfSSL_CTX_free(ctx2);
#endif /* defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL) */
    return EXPECT_RESULT();
}
#endif /* defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
    defined(WOLFSSL_OPENSSH) || defined(HAVE_SBLIM_SFCB))) */

static int test_wolfSSL_security_level(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    SSL_CTX *ctx = NULL;

    #ifdef WOLFSSL_TLS13
        #ifdef NO_WOLFSSL_SERVER
            ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
        #else
            ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
        #endif
        SSL_CTX_set_security_level(NULL, 1);
        SSL_CTX_set_security_level(ctx, 1);
        #if defined(WOLFSSL_SYS_CRYPTO_POLICY)
        ExpectIntEQ(SSL_CTX_get_security_level(NULL), BAD_FUNC_ARG);
        #else
        ExpectIntEQ(SSL_CTX_get_security_level(NULL), 0);
        #endif /* WOLFSSL_SYS_CRYPTO_POLICY */
        /* Stub so nothing happens. */
        ExpectIntEQ(SSL_CTX_get_security_level(ctx), 0);

        SSL_CTX_free(ctx);
    #else
        (void)ctx;
    #endif
#endif
    return EXPECT_RESULT();
}

/* System wide crypto-policy test.
 *
 * Loads three different policies (legacy, default, future),
 * then tests crypt_policy api.
 * */
static int test_wolfSSL_crypto_policy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SYS_CRYPTO_POLICY) && !defined(NO_TLS)
    int          rc = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    const char * policy_list[] = {
        "examples/crypto_policies/legacy/wolfssl.txt",
        "examples/crypto_policies/default/wolfssl.txt",
        "examples/crypto_policies/future/wolfssl.txt",
    };
    const char * ciphers_list[] = {
        "@SECLEVEL=1:EECDH:kRSA:EDH:PSK:DHEPSK:ECDHEPSK:RSAPSK"
        ":!eNULL:!aNULL",
        "@SECLEVEL=2:EECDH:kRSA:EDH:PSK:DHEPSK:ECDHEPSK:RSAPSK"
        ":!RC4:!eNULL:!aNULL",
        "@SECLEVEL=3:EECDH:EDH:PSK:DHEPSK:ECDHEPSK:!RSAPSK:!kRSA"
        ":!AES128:!RC4:!eNULL:!aNULL:!SHA1",
    };
    int          seclevel_list[] = { 1, 2, 3 };
    int          i = 0;

    for (i = 0; i < 3; ++i) {
        const char *  ciphers = NULL;
        int           n_diff = 0;
        WOLFSSL_CTX * ctx = NULL;
        WOLFSSL     * ssl = NULL;

        /* Enable crypto policy. */
        rc = wolfSSL_crypto_policy_enable(policy_list[i]);
        ExpectIntEQ(rc, WOLFSSL_SUCCESS);

        rc = wolfSSL_crypto_policy_is_enabled();
        ExpectIntEQ(rc, 1);

        /* Trying to enable while already enabled should return
         * forbidden. */
        rc = wolfSSL_crypto_policy_enable(policy_list[i]);
        ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);

        /* Security level and ciphers should match what is expected. */
        rc = wolfSSL_crypto_policy_get_level();
        ExpectIntEQ(rc, seclevel_list[i]);

        ciphers = wolfSSL_crypto_policy_get_ciphers();
        ExpectNotNull(ciphers);

        if (ciphers != NULL) {
            n_diff = XSTRNCMP(ciphers, ciphers_list[i], strlen(ciphers));
            #ifdef DEBUG_WOLFSSL
            if (n_diff) {
                printf("error: got \n%s, expected \n%s\n",
                       ciphers, ciphers_list[i]);
            }
            #endif /* DEBUG_WOLFSSL */
            ExpectIntEQ(n_diff, 0);
        }

        /* TLSv1_2_method should work for all policies. */
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_method());
        ExpectNotNull(ctx);

        if (ctx != NULL) {
            ssl = wolfSSL_new(ctx);
            ExpectNotNull(ssl);

            /* These API should be rejected while enabled. */
            rc = wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_3);
            ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);

            rc = wolfSSL_SetMinVersion(ssl, WOLFSSL_TLSV1_3);
            ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);
        }

        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        if (ssl != NULL) {
            wolfSSL_free(ssl);
            ssl = NULL;
        }

        wolfSSL_crypto_policy_disable();

        /* Do the same test by buffer. */
        rc = wolfSSL_crypto_policy_enable_buffer(ciphers_list[i]);
        ExpectIntEQ(rc, WOLFSSL_SUCCESS);

        rc = wolfSSL_crypto_policy_is_enabled();
        ExpectIntEQ(rc, 1);

        /* Security level and ciphers should match what is expected. */
        rc = wolfSSL_crypto_policy_get_level();
        ExpectIntEQ(rc, seclevel_list[i]);

        ciphers = wolfSSL_crypto_policy_get_ciphers();
        ExpectNotNull(ciphers);

        if (ciphers != NULL) {
            n_diff = XSTRNCMP(ciphers, ciphers_list[i], strlen(ciphers));
            #ifdef DEBUG_WOLFSSL
            if (n_diff) {
                printf("error: got \n%s, expected \n%s\n",
                       ciphers, ciphers_list[i]);
            }
            #endif /* DEBUG_WOLFSSL */
            ExpectIntEQ(n_diff, 0);
        }

        wolfSSL_crypto_policy_disable();
    }

    wolfSSL_crypto_policy_disable();

#endif /* WOLFSSL_SYS_CRYPTO_POLICY && !NO_TLS */
    return EXPECT_RESULT();
}

/* System wide crypto-policy test: certs and keys.
 *
 * Loads three different policies (legacy, default, future),
 * then tests loading different certificates and keys of
 * varying strength.
 * */
static int test_wolfSSL_crypto_policy_certs_and_keys(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SYS_CRYPTO_POLICY) && !defined(NO_TLS)
    int          rc = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    const char * policy_list[] = {
        "examples/crypto_policies/legacy/wolfssl.txt",
        "examples/crypto_policies/default/wolfssl.txt",
        "examples/crypto_policies/future/wolfssl.txt",
    };
    int          i = 0;

    for (i = 0; i < 3; ++i) {
        WOLFSSL_CTX * ctx = NULL;
        WOLFSSL     * ssl = NULL;
        int           is_legacy = 0;
        int           is_future = 0;
        /* certs */
        const char *  cert1024 = "certs/1024/client-cert.pem";
        const char *  cert2048 = "certs/client-cert.pem";
        const char *  cert3072 = "certs/3072/client-cert.pem";
        const char *  cert256 = "certs/client-ecc-cert.pem";
        const char *  cert384 = "certs/client-ecc384-cert.pem";
        /* keys */
        const char *  key1024 = "certs/1024/client-key.pem";
        const char *  key2048 = "certs/client-key.pem";
        const char *  key3072 = "certs/3072/client-key.pem";
        const char *  key256 = "certs/ecc-key.pem";
        const char *  key384 = "certs/client-ecc384-key.pem";

        is_legacy = (XSTRSTR(policy_list[i], "legacy") != NULL) ? 1 : 0;
        is_future = (XSTRSTR(policy_list[i], "future") != NULL) ? 1 : 0;

        /* Enable crypto policy. */
        rc = wolfSSL_crypto_policy_enable(policy_list[i]);
        ExpectIntEQ(rc, WOLFSSL_SUCCESS);

        rc = wolfSSL_crypto_policy_is_enabled();
        ExpectIntEQ(rc, 1);

        /* TLSv1_2_method should work for all policies. */
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_method());
        ExpectNotNull(ctx);

        /* Test certs of varying strength. */
        if (ctx != NULL) {
            /* VERIFY_PEER must be set for key/cert checks to be done. */
            wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

            /* Test loading a cert with 1024 RSA key size.
             * This should fail for all but legacy. */
            rc = wolfSSL_CTX_use_certificate_chain_file(ctx, cert1024);

            if (is_legacy) {
                ExpectIntEQ(rc, WOLFSSL_SUCCESS);
            }
            else {
                ExpectIntEQ(rc, WOLFSSL_FAILURE);
            }

            /* Test loading a cert with 2048 RSA key size.
             * Future crypto-policy is min 3072 RSA and DH key size,
             * and should fail. */
            rc = wolfSSL_CTX_use_certificate_chain_file(ctx, cert2048);

            if (is_future) {
                /* Future crypto-policy is min 3072 RSA and DH key size, this
                 * and should fail. */
                ExpectIntEQ(rc, WOLFSSL_FAILURE);

                /* Set to VERIFY_NONE. This will disable key size checks,
                 * it should now succeed. */
                wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
                rc = wolfSSL_CTX_use_certificate_chain_file(ctx, cert2048);

                ExpectIntEQ(rc, WOLFSSL_SUCCESS);

                /* Set back to verify peer. */
                wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

            }
            else {
                ExpectIntEQ(rc, WOLFSSL_SUCCESS);
            }

            /* Test loading a CA cert with 3072 RSA key size.
             * This should succeed for all policies. */
            rc = wolfSSL_CTX_use_certificate_chain_file(ctx, cert3072);
            ExpectIntEQ(rc, WOLFSSL_SUCCESS);

            /* Test loading an ecc cert with 256 key size.
             * This should succeed for all policies. */
            rc = wolfSSL_CTX_use_certificate_chain_file(ctx, cert256);
            ExpectIntEQ(rc, WOLFSSL_SUCCESS);

            /* Test loading an ecc cert with 384 key size.
             * This should succeed for all policies. */
            rc = wolfSSL_CTX_use_certificate_chain_file(ctx, cert384);
            ExpectIntEQ(rc, WOLFSSL_SUCCESS);

            /* cleanup */
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        /* TLSv1_2_method should work for all policies. */
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_method());
        ExpectNotNull(ctx);

        /* Repeat same tests for keys of varying strength. */
        if (ctx != NULL) {
            /* 1024 RSA */
            rc = SSL_CTX_use_PrivateKey_file(ctx, key1024,
                                             SSL_FILETYPE_PEM);

            if (is_legacy) {
                ExpectIntEQ(rc, WOLFSSL_SUCCESS);
            }
            else {
                ExpectIntEQ(rc, WOLFSSL_FAILURE);
            }

            /* 2048 RSA */
            rc = SSL_CTX_use_PrivateKey_file(ctx, key2048,
                                             SSL_FILETYPE_PEM);

            if (!is_future) {
                ExpectIntEQ(rc, WOLFSSL_SUCCESS);
            }
            else {
                ExpectIntEQ(rc, WOLFSSL_FAILURE);
            }

            /* 3072 RSA */
            rc = SSL_CTX_use_PrivateKey_file(ctx, key3072,
                                             SSL_FILETYPE_PEM);
            ExpectIntEQ(rc, WOLFSSL_SUCCESS);

            /* 256 ecc */
            rc = SSL_CTX_use_PrivateKey_file(ctx, key256,
                                             SSL_FILETYPE_PEM);
            ExpectIntEQ(rc, WOLFSSL_SUCCESS);

            /* 384 ecc */
            rc = SSL_CTX_use_PrivateKey_file(ctx, key384,
                                             SSL_FILETYPE_PEM);
            ExpectIntEQ(rc, WOLFSSL_SUCCESS);

            /* cleanup */
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        #ifdef HAVE_ECC
        /* Test set ecc min key size. */
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_method());
        ExpectNotNull(ctx);

        if (ctx != NULL) {
            ssl = SSL_new(ctx);
            ExpectNotNull(ssl);

            /* Test setting ctx. */
            rc = wolfSSL_CTX_SetMinEccKey_Sz(ctx, 160);
            if (is_legacy) {
                ExpectIntEQ(rc, WOLFSSL_SUCCESS);
            }
            else {
                ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);
            }

            rc = wolfSSL_CTX_SetMinEccKey_Sz(ctx, 224);
            if (!is_future) {
                ExpectIntEQ(rc, WOLFSSL_SUCCESS);
            }
            else {
                ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);
            }

            rc = wolfSSL_CTX_SetMinEccKey_Sz(ctx, 256);
            ExpectIntEQ(rc, WOLFSSL_SUCCESS);

            /* Test setting ssl. */
            if (ssl != NULL) {
                rc = wolfSSL_SetMinEccKey_Sz(ssl, 160);
                if (is_legacy) {
                    ExpectIntEQ(rc, WOLFSSL_SUCCESS);
                }
                else {
                    ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);
                }

                rc = wolfSSL_SetMinEccKey_Sz(ssl, 224);
                if (!is_future) {
                    ExpectIntEQ(rc, WOLFSSL_SUCCESS);
                }
                else {
                    ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);
                }

                rc = wolfSSL_SetMinEccKey_Sz(ssl, 256);
                ExpectIntEQ(rc, WOLFSSL_SUCCESS);

                wolfSSL_free(ssl);
                ssl = NULL;
            }

            /* cleanup */
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
        #endif /* HAVE_ECC */

        #if !defined(NO_RSA)
        /* Test set rsa min key size. */
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_method());
        ExpectNotNull(ctx);

        if (ctx != NULL) {
            ssl = SSL_new(ctx);
            ExpectNotNull(ssl);

            /* Test setting ctx. */
            rc = wolfSSL_CTX_SetMinRsaKey_Sz(ctx, 1024);
            if (is_legacy) {
                ExpectIntEQ(rc, WOLFSSL_SUCCESS);
            }
            else {
                ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);
            }

            rc = wolfSSL_CTX_SetMinRsaKey_Sz(ctx, 2048);
            if (!is_future) {
                ExpectIntEQ(rc, WOLFSSL_SUCCESS);
            }
            else {
                ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);
            }

            rc = wolfSSL_CTX_SetMinRsaKey_Sz(ctx, 3072);
            ExpectIntEQ(rc, WOLFSSL_SUCCESS);

            /* Test setting ssl. */
            if (ssl != NULL) {
                rc = wolfSSL_SetMinRsaKey_Sz(ssl, 1024);
                if (is_legacy) {
                    ExpectIntEQ(rc, WOLFSSL_SUCCESS);
                }
                else {
                    ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);
                }

                rc = wolfSSL_SetMinRsaKey_Sz(ssl, 2048);
                if (!is_future) {
                    ExpectIntEQ(rc, WOLFSSL_SUCCESS);
                }
                else {
                    ExpectIntEQ(rc, CRYPTO_POLICY_FORBIDDEN);
                }

                rc = wolfSSL_SetMinRsaKey_Sz(ssl, 3072);
                ExpectIntEQ(rc, WOLFSSL_SUCCESS);

                wolfSSL_free(ssl);
                ssl = NULL;
            }

            /* cleanup */
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
        #endif /* !NO_RSA */

        wolfSSL_crypto_policy_disable();
    }

    wolfSSL_crypto_policy_disable();
#endif /* WOLFSSL_SYS_CRYPTO_POLICY && !NO_TLS */
    return EXPECT_RESULT();
}

/* System wide crypto-policy test: tls and dtls methods.
 * */
static int test_wolfSSL_crypto_policy_tls_methods(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SYS_CRYPTO_POLICY) && !defined(NO_TLS)
    int          rc = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    const char * policy_list[] = {
        "examples/crypto_policies/legacy/wolfssl.txt",
        "examples/crypto_policies/default/wolfssl.txt",
        "examples/crypto_policies/future/wolfssl.txt",
    };
    int          i = 0;

    for (i = 0; i < 3; ++i) {
        WOLFSSL_CTX * ctx = NULL;
        int           is_legacy = 0;

        is_legacy = (XSTRSTR(policy_list[i], "legacy") != NULL) ? 1 : 0;

        /* Enable crypto policy. */
        rc = wolfSSL_crypto_policy_enable(policy_list[i]);
        ExpectIntEQ(rc, WOLFSSL_SUCCESS);

        rc = wolfSSL_crypto_policy_is_enabled();
        ExpectIntEQ(rc, 1);

        /* Try to use old TLS methods. Only allowed with legacy. */
        #if !defined(NO_OLD_TLS)
        ctx = wolfSSL_CTX_new(wolfTLSv1_1_method());

        if (is_legacy) {
            ExpectNotNull(ctx);
        }
        else {
            ExpectNull(ctx);
        }

        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        #if defined(WOLFSSL_ALLOW_TLSV10)
        ctx = wolfSSL_CTX_new(wolfTLSv1_method());

        if (is_legacy) {
            ExpectNotNull(ctx);
        }
        else {
            ExpectNull(ctx);
        }

        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
        #endif /* WOLFSSL_ALLOW_TLSV10 */
        #else
        (void) is_legacy;
        #endif /* !NO_OLD_TLS */

        /* TLSv1_2_method should work for all policies. */
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_method());
        ExpectNotNull(ctx);

        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        ctx = wolfSSL_CTX_new(wolfTLSv1_3_method());
        ExpectNotNull(ctx);

        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        ctx = wolfSSL_CTX_new(TLS_method());
        ExpectNotNull(ctx);

        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        #ifdef WOLFSSL_DTLS
        ctx = wolfSSL_CTX_new(DTLS_method());
        ExpectNotNull(ctx);

        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        ctx = wolfSSL_CTX_new(wolfDTLSv1_2_method());
        ExpectNotNull(ctx);

        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        #ifndef NO_OLD_TLS
        /* Only allowed with legacy. */
        ctx = wolfSSL_CTX_new(wolfDTLSv1_method());

        if (is_legacy) {
            ExpectNotNull(ctx);
        }
        else {
            ExpectNull(ctx);
        }

        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
        #endif /* !NO_OLD_TLS */
        #endif /* WOLFSSL_DTLS */

        wolfSSL_crypto_policy_disable();
    }

    wolfSSL_crypto_policy_disable();
#endif /* WOLFSSL_SYS_CRYPTO_POLICY && !NO_TLS */
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_SYS_CRYPTO_POLICY) && !defined(NO_TLS)
/*  Helper function for test_wolfSSL_crypto_policy_ciphers.
 *  Searches ssl suites for cipher string.
 *
 *  Returns   1 if found.
 *  Returns   0 if not found.
 *  Returns < 0 if error.
 * */
static int crypto_policy_cipher_found(const WOLFSSL * ssl,
                                      const char *    cipher,
                                      int             match)
{
    WOLF_STACK_OF(WOLFSSL_CIPHER) * sk = NULL;
    WOLFSSL_CIPHER *                current = NULL;
    const char *                    suite;
    int                             found = 0;
    int                             i = 0;

    if (ssl == NULL || cipher == NULL || *cipher == '\0') {
        return -1;
    }

    sk = wolfSSL_get_ciphers_compat(ssl);

    if (sk == NULL) {
        return -1;
    }

    do {
        current = wolfSSL_sk_SSL_CIPHER_value(sk, i++);
        if (current) {
            suite = wolfSSL_CIPHER_get_name(current);
            if (suite) {
                if (match == 1) {
                    /* prefix match */
                    if (XSTRNCMP(suite, cipher, XSTRLEN(cipher)) == 0) {
                        found = 1;
                        break;
                    }
                }
                else if (match == -1) {
                    /* postfix match */
                    if (XSTRLEN(suite) > XSTRLEN(cipher)) {
                        const char * postfix = suite + XSTRLEN(suite)
                                               - XSTRLEN(cipher);
                        if (XSTRNCMP(postfix, cipher, XSTRLEN(cipher)) == 0) {
                            found = 1;
                            break;
                        }
                    }
                }
                else {
                    /* needle in haystack match */
                    if (XSTRSTR(suite, cipher)) {
                        found = 1;
                        break;
                    }
                }
            }
        }
    } while (current);

    return found == 1;
}
#endif /* WOLFSSL_SYS_CRYPTO_POLICY && !NO_TLS */

/* System wide crypto-policy test: ciphers.
 * */
static int test_wolfSSL_crypto_policy_ciphers(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SYS_CRYPTO_POLICY) && !defined(NO_TLS)
    int          rc = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    const char * policy_list[] = {
        "examples/crypto_policies/legacy/wolfssl.txt",
        "examples/crypto_policies/default/wolfssl.txt",
        "examples/crypto_policies/future/wolfssl.txt",
    };
    int          seclevel_list[] = { 1, 2, 3 };
    int          i = 0;
    int          is_legacy = 0;
    int          is_future = 0;

    for (i = 0; i < 3; ++i) {
        WOLFSSL_CTX * ctx = NULL;
        WOLFSSL     * ssl = NULL;
        int           found = 0;

        is_legacy = (XSTRSTR(policy_list[i], "legacy") != NULL) ? 1 : 0;
        is_future = (XSTRSTR(policy_list[i], "future") != NULL) ? 1 : 0;

        (void) is_legacy;

        /* Enable crypto policy. */
        rc = wolfSSL_crypto_policy_enable(policy_list[i]);
        ExpectIntEQ(rc, WOLFSSL_SUCCESS);

        rc = wolfSSL_crypto_policy_is_enabled();
        ExpectIntEQ(rc, 1);

        ctx = wolfSSL_CTX_new(TLS_method());
        ExpectNotNull(ctx);

        ssl = SSL_new(ctx);
        ExpectNotNull(ssl);

        rc = wolfSSL_CTX_get_security_level(ctx);
        ExpectIntEQ(rc, seclevel_list[i]);

        rc = wolfSSL_get_security_level(ssl);
        ExpectIntEQ(rc, seclevel_list[i]);

        found = crypto_policy_cipher_found(ssl, "RC4", 0);
        ExpectIntEQ(found, is_legacy);

        /* We return a different cipher string depending on build settings. */
        #if !defined(WOLFSSL_CIPHER_INTERNALNAME) && \
        !defined(NO_ERROR_STRINGS) && !defined(WOLFSSL_QT)
        found = crypto_policy_cipher_found(ssl, "AES_128", 0);
        ExpectIntEQ(found, !is_future);

        found = crypto_policy_cipher_found(ssl, "TLS_DHE_RSA_WITH_AES", 1);
        ExpectIntEQ(found, !is_future);

        found = crypto_policy_cipher_found(ssl, "_SHA", -1);
        ExpectIntEQ(found, !is_future);
        #else
        found = crypto_policy_cipher_found(ssl, "AES128", 0);
        ExpectIntEQ(found, !is_future);

        found = crypto_policy_cipher_found(ssl, "DHE-RSA-AES", 1);
        ExpectIntEQ(found, !is_future);

        found = crypto_policy_cipher_found(ssl, "-SHA", -1);
        ExpectIntEQ(found, !is_future);
        #endif

        if (ssl != NULL) {
            SSL_free(ssl);
            ssl = NULL;
        }

        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        wolfSSL_crypto_policy_disable();
    }

    wolfSSL_crypto_policy_disable();

#endif /* WOLFSSL_SYS_CRYPTO_POLICY && !NO_TLS */
    return EXPECT_RESULT();
}

static int test_wolfSSL_SSL_in_init(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_BIO) && !defined(NO_TLS)
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;
    const char* testCertFile;
    const char* testKeyFile;

#ifdef WOLFSSL_TLS13
    #ifdef NO_WOLFSSL_SERVER
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    #else
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    #endif
#else
    #ifdef NO_WOLFSSL_SERVER
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    #else
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    #endif
#endif
#ifndef NO_RSA
    testCertFile = svrCertFile;
    testKeyFile = svrKeyFile;
#elif defined(HAVE_ECC)
    testCertFile = eccCertFile;
    testKeyFile = eccKeyFile;
#else
    testCertFile = NULL;
    testKeyFile = NULL;
#endif
    if ((testCertFile != NULL) && (testKeyFile != NULL)) {
        ExpectTrue(SSL_CTX_use_certificate_file(ctx, testCertFile,
            SSL_FILETYPE_PEM));
        ExpectTrue(SSL_CTX_use_PrivateKey_file(ctx, testKeyFile,
            SSL_FILETYPE_PEM));
    }

    ExpectNotNull(ssl = SSL_new(ctx));
    ExpectIntEQ(SSL_in_init(ssl), 1);

    SSL_CTX_free(ctx);
    SSL_free(ssl);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_CTX_set_timeout(void)
{
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS) && \
    !defined(NO_SESSION_CACHE)
    WOLFSSL_CTX* ctx = NULL;
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    int timeout;
#endif

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    /* in WOLFSSL_ERROR_CODE_OPENSSL macro guard,
     * wolfSSL_CTX_set_timeout returns previous timeout value on success.
     */
    ExpectIntEQ(wolfSSL_CTX_set_timeout(NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* giving 0 as timeout value sets default timeout */
    timeout = wolfSSL_CTX_set_timeout(ctx, 0);
    ExpectIntEQ(wolfSSL_CTX_set_timeout(ctx, 20), timeout);
    ExpectIntEQ(wolfSSL_CTX_set_timeout(ctx, 30), 20);

#else
    ExpectIntEQ(wolfSSL_CTX_set_timeout(NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_set_timeout(ctx, 100), 1);
    ExpectIntEQ(wolfSSL_CTX_set_timeout(ctx, 0), 1);
#endif

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_OpenSSL_version(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    const char* ver;

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    ExpectNotNull(ver = OpenSSL_version(0));
#else
    ExpectNotNull(ver = OpenSSL_version());
#endif
    ExpectIntEQ(XMEMCMP(ver, "wolfSSL " LIBWOLFSSL_VERSION_STRING,
        XSTRLEN("wolfSSL " LIBWOLFSSL_VERSION_STRING)), 0);
#endif
    return EXPECT_RESULT();
}

static int test_CONF_CTX_CMDLINE(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_TLS)
    SSL_CTX* ctx = NULL;
    SSL_CONF_CTX* cctx = NULL;

    ExpectNotNull(cctx = SSL_CONF_CTX_new());

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);

    /* set flags */
    ExpectIntEQ(SSL_CONF_CTX_set_flags(cctx, WOLFSSL_CONF_FLAG_CMDLINE),
        WOLFSSL_CONF_FLAG_CMDLINE);
    ExpectIntEQ(SSL_CONF_CTX_set_flags(cctx, WOLFSSL_CONF_FLAG_CERTIFICATE),
        WOLFSSL_CONF_FLAG_CMDLINE | WOLFSSL_CONF_FLAG_CERTIFICATE);
    /* cmd invalid command */
    ExpectIntEQ(SSL_CONF_cmd(cctx, "foo", "foobar"), -2);
    ExpectIntEQ(SSL_CONF_cmd(cctx, "foo", NULL), -2);
    ExpectIntEQ(SSL_CONF_cmd(cctx, NULL, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(SSL_CONF_cmd(cctx, NULL, "foobar"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(SSL_CONF_cmd(NULL, "-curves", "foobar"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* cmd Certificate and Private Key*/
    {
    #if !defined(NO_CERTS) && !defined(NO_RSA)
        const char*  ourCert = svrCertFile;
        const char*  ourKey  = svrKeyFile;

        ExpectIntEQ(SSL_CONF_cmd(cctx, "-cert", NULL), -3);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "-cert", ourCert), WOLFSSL_SUCCESS);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "-key", NULL), -3);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "-key", ourKey), WOLFSSL_SUCCESS);
        ExpectIntEQ(SSL_CONF_CTX_finish(cctx), WOLFSSL_SUCCESS);
    #endif
    }

    /* cmd curves */
    {
    #if defined(HAVE_ECC)
        const char* curve = "secp256r1";

        ExpectIntEQ(SSL_CONF_cmd(cctx, "-curves", NULL), -3);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "-curves", curve), WOLFSSL_SUCCESS);
        ExpectIntEQ(SSL_CONF_CTX_finish(cctx), WOLFSSL_SUCCESS);
    #endif
    }

    /* cmd CipherString */
    {
        char* cipher = wolfSSL_get_cipher_list(0/*top priority*/);

        ExpectIntEQ(SSL_CONF_cmd(cctx, "-cipher", NULL), -3);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "-cipher", cipher), WOLFSSL_SUCCESS);
        ExpectIntEQ(SSL_CONF_CTX_finish(cctx), WOLFSSL_SUCCESS);
    }

    /* cmd DH parameter */
    {
    #if !defined(NO_DH) && !defined(NO_BIO)
        const char* ourdhcert = "./certs/dh2048.pem";

        ExpectIntEQ(SSL_CONF_cmd(cctx, "-dhparam", NULL), -3);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "-dhparam", ourdhcert), WOLFSSL_SUCCESS);
        ExpectIntEQ(SSL_CONF_CTX_finish(cctx), WOLFSSL_SUCCESS);

    #endif
    }

    SSL_CTX_free(ctx);
    SSL_CONF_CTX_free(cctx);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

static int test_CONF_CTX_FILE(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_TLS)
    SSL_CTX* ctx = NULL;
    SSL_CONF_CTX* cctx = NULL;

    ExpectNotNull(cctx = SSL_CONF_CTX_new());
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);

    /* set flags */
    ExpectIntEQ(SSL_CONF_CTX_set_flags(cctx, WOLFSSL_CONF_FLAG_FILE),
        WOLFSSL_CONF_FLAG_FILE);
    ExpectIntEQ(SSL_CONF_CTX_set_flags(cctx, WOLFSSL_CONF_FLAG_CERTIFICATE),
        WOLFSSL_CONF_FLAG_FILE | WOLFSSL_CONF_FLAG_CERTIFICATE);
    /* sanity check */
    ExpectIntEQ(SSL_CONF_cmd(cctx, "foo", "foobar"), -2);
    ExpectIntEQ(SSL_CONF_cmd(cctx, "foo", NULL), -2);
    ExpectIntEQ(SSL_CONF_cmd(cctx, NULL, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(SSL_CONF_cmd(cctx, NULL, "foobar"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(SSL_CONF_cmd(NULL, "-curves", "foobar"), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* cmd Certificate and Private Key*/
    {
    #if !defined(NO_CERTS) && !defined(NO_RSA)
        const char*  ourCert = svrCertFile;
        const char*  ourKey  = svrKeyFile;

        ExpectIntEQ(SSL_CONF_cmd(cctx, "Certificate", NULL), -3);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "PrivateKey", NULL), -3);

        ExpectIntEQ(SSL_CONF_cmd(cctx, "Certificate", ourCert),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "PrivateKey", ourKey), WOLFSSL_SUCCESS);
        ExpectIntEQ(SSL_CONF_CTX_finish(cctx), WOLFSSL_SUCCESS);
    #endif
    }

    /* cmd curves */
    {
    #if defined(HAVE_ECC)
        const char* curve = "secp256r1";

        ExpectIntEQ(SSL_CONF_cmd(cctx, "Curves", NULL), -3);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "Curves", curve), WOLFSSL_SUCCESS);
        ExpectIntEQ(SSL_CONF_CTX_finish(cctx), WOLFSSL_SUCCESS);
    #endif
    }

    /* cmd CipherString */
    {
        char* cipher = wolfSSL_get_cipher_list(0/*top priority*/);

        ExpectIntEQ(SSL_CONF_cmd(cctx, "CipherString", NULL), -3);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "CipherString", cipher),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(SSL_CONF_CTX_finish(cctx), WOLFSSL_SUCCESS);
    }

    /* cmd DH parameter */
    {
    #if !defined(NO_DH) && !defined(NO_BIO) && defined(HAVE_FFDHE_3072)
        const char* ourdhcert = "./certs/dh3072.pem";

        ExpectIntEQ(SSL_CONF_cmd(cctx, "DHParameters", NULL), -3);
        ExpectIntEQ(SSL_CONF_cmd(cctx, "DHParameters", ourdhcert),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(SSL_CONF_CTX_finish(cctx), WOLFSSL_SUCCESS);

    #endif
    }

    SSL_CTX_free(ctx);
    SSL_CONF_CTX_free(cctx);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

static int test_wolfSSL_CRYPTO_get_ex_new_index(void)
{
    EXPECT_DECLS;
#ifdef HAVE_EX_DATA_CRYPTO
    int idx1, idx2;

    /* test for unsupported class index */
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_X509_STORE,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(
        WOLF_CRYPTO_EX_INDEX_X509_STORE_CTX,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_DH,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_DSA,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_EC_KEY,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_RSA,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_ENGINE,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_UI,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_BIO,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_APP,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_UI_METHOD,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_DRBG,
        0,NULL, NULL, NULL, NULL ), -1);
    ExpectIntEQ(wolfSSL_CRYPTO_get_ex_new_index(20,
        0,NULL, NULL, NULL, NULL ), -1);

    /* test for supported class index */
    idx1 = wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL,
        0,NULL, NULL, NULL, NULL );
    idx2 = wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL,
        0,NULL, NULL, NULL, NULL );
    ExpectIntNE(idx1, -1);
    ExpectIntNE(idx2, -1);
    ExpectIntNE(idx1, idx2);

    idx1 = wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL_CTX,
        0,NULL, NULL, NULL, NULL );
    idx2 = wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL_CTX,
        0,NULL, NULL, NULL, NULL );
    ExpectIntNE(idx1, -1);
    ExpectIntNE(idx2, -1);
    ExpectIntNE(idx1, idx2);

    idx1 = wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_X509,
        0,NULL, NULL, NULL, NULL );
    idx2 = wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_X509,
        0,NULL, NULL, NULL, NULL );
    ExpectIntNE(idx1, -1);
    ExpectIntNE(idx2, -1);
    ExpectIntNE(idx1, idx2);


    idx1 = wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL_SESSION,
        0,NULL, NULL, NULL, NULL );
    idx2 = wolfSSL_CRYPTO_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL_SESSION,
        0,NULL, NULL, NULL, NULL );
    ExpectIntNE(idx1, -1);
    ExpectIntNE(idx2, -1);
    ExpectIntNE(idx1, idx2);
#endif /* HAVE_EX_DATA_CRYPTO */
    return EXPECT_RESULT();
}

#if defined(HAVE_EX_DATA_CRYPTO) && defined(OPENSSL_EXTRA)

#define SESSION_NEW_IDX_LONG 0xDEADBEEF
#define SESSION_NEW_IDX_VAL  ((void*)0xAEADAEAD)
#define SESSION_DUP_IDX_VAL  ((void*)0xDEDEDEDE)
#define SESSION_NEW_IDX_PTR  "Testing"

static void test_wolfSSL_SESSION_get_ex_new_index_new_cb(void* p, void* ptr,
        CRYPTO_EX_DATA* a, int idx, long argValue, void* arg)
{
    AssertNotNull(p);
    AssertNull(ptr);
    AssertIntEQ(CRYPTO_set_ex_data(a, idx, SESSION_NEW_IDX_VAL), SSL_SUCCESS);
    AssertIntEQ(argValue, SESSION_NEW_IDX_LONG);
    AssertStrEQ(arg, SESSION_NEW_IDX_PTR);
}

static int test_wolfSSL_SESSION_get_ex_new_index_dup_cb(CRYPTO_EX_DATA* out,
        const CRYPTO_EX_DATA* in, void* inPtr, int idx, long argV,
        void* arg)
{
    EXPECT_DECLS;

    ExpectNotNull(out);
    ExpectNotNull(in);
    ExpectPtrEq(*(void**)inPtr, SESSION_NEW_IDX_VAL);
    ExpectPtrEq(CRYPTO_get_ex_data(in, idx), SESSION_NEW_IDX_VAL);
    ExpectPtrEq(CRYPTO_get_ex_data(out, idx), SESSION_NEW_IDX_VAL);
    ExpectIntEQ(argV, SESSION_NEW_IDX_LONG);
    ExpectStrEQ(arg, SESSION_NEW_IDX_PTR);
    *(void**)inPtr = SESSION_DUP_IDX_VAL;
    if (EXPECT_SUCCESS()) {
        return SSL_SUCCESS;
    }
    else {
        return SSL_FAILURE;
    }
}

static int test_wolfSSL_SESSION_get_ex_new_index_free_cb_called = 0;
static void test_wolfSSL_SESSION_get_ex_new_index_free_cb(void* p, void* ptr,
        CRYPTO_EX_DATA* a, int idx, long argValue, void* arg)
{
    EXPECT_DECLS;

    ExpectNotNull(p);
    ExpectNull(ptr);
    ExpectPtrNE(CRYPTO_get_ex_data(a, idx), 0);
    ExpectIntEQ(argValue, SESSION_NEW_IDX_LONG);
    ExpectStrEQ(arg, SESSION_NEW_IDX_PTR);
    if (EXPECT_SUCCESS()) {
        test_wolfSSL_SESSION_get_ex_new_index_free_cb_called++;
    }
}

static int test_wolfSSL_SESSION_get_ex_new_index(void)
{
    EXPECT_DECLS;
    int idx = SSL_SESSION_get_ex_new_index(SESSION_NEW_IDX_LONG,
                (void*)SESSION_NEW_IDX_PTR,
                test_wolfSSL_SESSION_get_ex_new_index_new_cb,
                test_wolfSSL_SESSION_get_ex_new_index_dup_cb,
                test_wolfSSL_SESSION_get_ex_new_index_free_cb);
    SSL_SESSION* s = SSL_SESSION_new();
    SSL_SESSION* d = NULL;

    ExpectNotNull(s);
    ExpectPtrEq(SSL_SESSION_get_ex_data(s, idx), SESSION_NEW_IDX_VAL);
    ExpectNotNull(d = SSL_SESSION_dup(s));
    ExpectPtrEq(SSL_SESSION_get_ex_data(d, idx), SESSION_DUP_IDX_VAL);
    SSL_SESSION_free(s);
    ExpectIntEQ(test_wolfSSL_SESSION_get_ex_new_index_free_cb_called, 1);
    SSL_SESSION_free(d);
    ExpectIntEQ(test_wolfSSL_SESSION_get_ex_new_index_free_cb_called, 2);

    crypto_ex_cb_free(crypto_ex_cb_ctx_session);
    crypto_ex_cb_ctx_session = NULL;
    return EXPECT_RESULT();
}
#else
static int test_wolfSSL_SESSION_get_ex_new_index(void)
{
    return TEST_SKIPPED;
}
#endif

static int test_wolfSSL_set_psk_use_session_callback(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_PSK) && !defined(NO_TLS)
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;
    const char* testCertFile;
    const char* testKeyFile;

#ifdef WOLFSSL_TLS13
    #ifdef NO_WOLFSSL_SERVER
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    #else
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    #endif
#else
    #ifdef NO_WOLFSSL_SERVER
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    #else
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    #endif
#endif
#ifndef NO_RSA
    testCertFile = svrCertFile;
    testKeyFile = svrKeyFile;
#elif defined(HAVE_ECC)
    testCertFile = eccCertFile;
    testKeyFile = eccKeyFile;
#else
    testCertFile = NULL;
    testKeyFile = NULL;
#endif
    if ((testCertFile != NULL) && (testKeyFile != NULL)) {
        ExpectTrue(SSL_CTX_use_certificate_file(ctx, testCertFile,
            SSL_FILETYPE_PEM));
        ExpectTrue(SSL_CTX_use_PrivateKey_file(ctx, testKeyFile,
            SSL_FILETYPE_PEM));
    }

    ExpectNotNull(ssl = SSL_new(ctx));

    SSL_set_psk_use_session_callback(ssl, my_psk_use_session_cb);

    SSL_CTX_free(ctx);
    SSL_free(ssl);
#endif
    return EXPECT_RESULT();
}

/* similar to error_test() in wolfcrypt/test/test.c, but adding error codes from
 * TLS layer.
 */
static int error_test(void)
{
    EXPECT_DECLS;
    const char* errStr;
    const char* unknownStr = wc_GetErrorString(0);

#ifdef NO_ERROR_STRINGS
    /* Ensure a valid error code's string matches an invalid code's.
     * The string is that error strings are not available.
     */
    errStr = wc_GetErrorString(OPEN_RAN_E);
    ExpectIntEQ(XSTRCMP(errStr, unknownStr), 0);
    if (EXPECT_FAIL())
        return OPEN_RAN_E;
#else
    int i;
    int j = 0;
    /* Values that are not or no longer error codes. */
    static const struct {
        int first;
        int last;
    } missing[] = {
#ifndef OPENSSL_EXTRA
        { 0, 0 },
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(HAVE_WEBSERVER) || defined(HAVE_MEMCACHED)
        { -11, -12 },
        { -15, -17 },
        { -19, -19 },
        { -26, -27 },
        { -30, WC_SPAN1_FIRST_E + 1 },
#else
        { -9, WC_SPAN1_FIRST_E + 1 },
#endif
        { -124, -124 },
        { -167, -169 },
        { -300, -300 },
        { -334, -336 },
        { -346, -349 },
        { -356, -356 },
        { -358, -358 },
        { -384, -384 },
        { -466, -499 },
        { WOLFSSL_LAST_E - 1, WC_SPAN2_FIRST_E + 1 },
        { WC_SPAN2_LAST_E - 1, MIN_CODE_E }
    };

    /* Check that all errors have a string and it's the same through the two
     * APIs. Check that the values that are not errors map to the unknown
     * string.
     */
    for (i = 0; i >= MIN_CODE_E; i--) {
        int this_missing = 0;
        for (j = 0; j < (int)XELEM_CNT(missing); ++j) {
            if ((i <= missing[j].first) && (i >= missing[j].last)) {
                this_missing = 1;
                break;
            }
        }
        errStr = wolfSSL_ERR_reason_error_string((word32)i);

        if (! this_missing) {
            ExpectIntNE(XSTRCMP(errStr, unknownStr), 0);
            if (EXPECT_FAIL()) {
                return i;
            }
            ExpectTrue(XSTRLEN(errStr) < WOLFSSL_MAX_ERROR_SZ);
            if (EXPECT_FAIL()) {
                return i;
            }
        }
        else {
            j++;
            ExpectIntEQ(XSTRCMP(errStr, unknownStr), 0);
            if (EXPECT_FAIL()) {
                return i;
            }
        }
    }
#endif

    return 1;
}

static int test_wolfSSL_ERR_strings(void)
{
    EXPECT_DECLS;

#if !defined(NO_ERROR_STRINGS)
    const char* err1 = "unsupported cipher suite";
    const char* err2 = "wolfSSL PEM routines";
    const char* err  = NULL;

    (void)err;
    (void)err1;
    (void)err2;

#if defined(OPENSSL_EXTRA)
    ExpectNotNull(err = ERR_reason_error_string(WC_NO_ERR_TRACE(UNSUPPORTED_SUITE)));
    ExpectIntEQ(XSTRNCMP(err, err1, XSTRLEN(err1)), 0);

    ExpectNotNull(err = ERR_func_error_string(WC_NO_ERR_TRACE(UNSUPPORTED_SUITE)));
    ExpectIntEQ((*err == '\0'), 1);

    ExpectNotNull(err = ERR_lib_error_string(PEM_R_PROBLEMS_GETTING_PASSWORD));
    ExpectIntEQ(XSTRNCMP(err, err2, XSTRLEN(err2)), 0);
#else
    ExpectNotNull(err = wolfSSL_ERR_reason_error_string(WC_NO_ERR_TRACE((word32)UNSUPPORTED_SUITE)));
    ExpectIntEQ(XSTRNCMP(err, err1, XSTRLEN(err1)), 0);

    ExpectNotNull(err = wolfSSL_ERR_func_error_string(WC_NO_ERR_TRACE((word32)UNSUPPORTED_SUITE)));
    ExpectIntEQ((*err == '\0'), 1);

    ExpectNotNull(err = wolfSSL_ERR_lib_error_string(-WOLFSSL_PEM_R_PROBLEMS_GETTING_PASSWORD_E));
    ExpectIntEQ((*err == '\0'), 1);
#endif
#endif

    ExpectIntEQ(error_test(), 1);

    return EXPECT_RESULT();
}
static int test_wolfSSL_EVP_shake128(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SHA3) && \
                                            defined(WOLFSSL_SHAKE128)
    const EVP_MD* md = NULL;

    ExpectNotNull(md = EVP_shake128());
    ExpectIntEQ(XSTRNCMP(md, "SHAKE128", XSTRLEN("SHAKE128")), 0);
#endif

    return EXPECT_RESULT();
}

static int test_wolfSSL_EVP_shake256(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SHA3) && \
                                            defined(WOLFSSL_SHAKE256)
    const EVP_MD* md = NULL;

    ExpectNotNull(md = EVP_shake256());
    ExpectIntEQ(XSTRNCMP(md, "SHAKE256", XSTRLEN("SHAKE256")), 0);
#endif

    return EXPECT_RESULT();
}

/*
 *  Testing EVP digest API with SM3
 */
static int test_wolfSSL_EVP_sm3(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM3)
    EXPECT_DECLS;
    const EVP_MD* md = NULL;
    EVP_MD_CTX* mdCtx = NULL;
    byte data[WC_SM3_BLOCK_SIZE * 4];
    byte hash[WC_SM3_DIGEST_SIZE];
    byte calcHash[WC_SM3_DIGEST_SIZE];
    byte expHash[WC_SM3_DIGEST_SIZE] = {
        0x38, 0x48, 0x15, 0xa7, 0x0e, 0xae, 0x0b, 0x27,
        0x5c, 0xde, 0x9d, 0xa5, 0xd1, 0xa4, 0x30, 0xa1,
        0xca, 0xd4, 0x54, 0x58, 0x44, 0xa2, 0x96, 0x1b,
        0xd7, 0x14, 0x80, 0x3f, 0x80, 0x1a, 0x07, 0xb6
    };
    word32 chunk;
    word32 i;
    unsigned int sz;
    int ret;

    XMEMSET(data, 0, sizeof(data));

    md = EVP_sm3();
    ExpectTrue(md != NULL);
    ExpectIntEQ(XSTRNCMP(md, "SM3", XSTRLEN("SM3")), 0);
    mdCtx = EVP_MD_CTX_new();
    ExpectTrue(mdCtx != NULL);

    /* Invalid Parameters */
    ExpectIntEQ(EVP_DigestInit(NULL, md), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Valid Parameters */
    ExpectIntEQ(EVP_DigestInit(mdCtx, md), WOLFSSL_SUCCESS);

    ExpectIntEQ(EVP_DigestUpdate(NULL, NULL, 1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, NULL, 1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestUpdate(NULL, data, 1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* Valid Parameters */
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, WC_SM3_BLOCK_SIZE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, WC_SM3_BLOCK_SIZE - 2),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, WC_SM3_BLOCK_SIZE * 2),
        WOLFSSL_SUCCESS);
    /* Ensure too many bytes for lengths. */
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, WC_SM3_PAD_SIZE),
        WOLFSSL_SUCCESS);

    /* Invalid Parameters */
    ExpectIntEQ(EVP_DigestFinal(NULL, NULL, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestFinal(mdCtx, NULL, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestFinal(NULL, hash, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestFinal(NULL, hash, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestFinal(mdCtx, NULL, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* Valid Parameters */
    ExpectIntEQ(EVP_DigestFinal(mdCtx, hash, NULL), WOLFSSL_SUCCESS);
    ExpectBufEQ(hash, expHash, WC_SM3_DIGEST_SIZE);

    /* Chunk tests. */
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, sizeof(data)), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestFinal(mdCtx, calcHash, &sz), WOLFSSL_SUCCESS);
    ExpectIntEQ(sz, WC_SM3_DIGEST_SIZE);
    for (chunk = 1; chunk <= WC_SM3_BLOCK_SIZE + 1; chunk++) {
        for (i = 0; i + chunk <= (word32)sizeof(data); i += chunk) {
            ExpectIntEQ(EVP_DigestUpdate(mdCtx, data + i, chunk),
                WOLFSSL_SUCCESS);
        }
        if (i < (word32)sizeof(data)) {
            ExpectIntEQ(EVP_DigestUpdate(mdCtx, data + i,
                (word32)sizeof(data) - i), WOLFSSL_SUCCESS);
        }
        ExpectIntEQ(EVP_DigestFinal(mdCtx, hash, NULL), WOLFSSL_SUCCESS);
        ExpectBufEQ(hash, calcHash, WC_SM3_DIGEST_SIZE);
    }

    /* Not testing when the low 32-bit length overflows. */

    ret = EVP_MD_CTX_cleanup(mdCtx);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    wolfSSL_EVP_MD_CTX_free(mdCtx);

    res = EXPECT_RESULT();
#endif
    return res;
}  /* END test_EVP_sm3 */

static int test_EVP_blake2(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && (defined(HAVE_BLAKE2) || defined(HAVE_BLAKE2S))
    const EVP_MD* md = NULL;
    (void)md;

#if defined(HAVE_BLAKE2)
    ExpectNotNull(md = EVP_blake2b512());
    ExpectIntEQ(XSTRNCMP(md, "BLAKE2b512", XSTRLEN("BLAKE2b512")), 0);
#endif

#if defined(HAVE_BLAKE2S)
    ExpectNotNull(md = EVP_blake2s256());
    ExpectIntEQ(XSTRNCMP(md, "BLAKE2s256", XSTRLEN("BLAKE2s256")), 0);
#endif
#endif

    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA)
static void list_md_fn(const EVP_MD* m, const char* from,
                       const char* to, void* arg)
{
    const char* mn;
    BIO *bio;

    (void) from;
    (void) to;
    (void) arg;
    (void) mn;
    (void) bio;

    if (!m) {
        /* alias */
        AssertNull(m);
        AssertNotNull(to);
    }
    else {
        AssertNotNull(m);
        AssertNull(to);
    }

    AssertNotNull(from);

#if !defined(NO_FILESYSTEM) && defined(DEBUG_WOLFSSL_VERBOSE)
    mn = EVP_get_digestbyname(from);
    /* print to stderr */
    AssertNotNull(arg);

    bio = BIO_new(BIO_s_file());
    BIO_set_fp(bio, arg, BIO_NOCLOSE);
    BIO_printf(bio, "Use %s message digest algorithm\n", mn);
    BIO_free(bio);
#endif
}
#endif

static int test_EVP_MD_do_all(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA)
    EVP_MD_do_all(NULL, stderr);

    EVP_MD_do_all(list_md_fn, stderr);

    res = TEST_SUCCESS;
#endif

    return res;
}

#if defined(OPENSSL_EXTRA)
static void obj_name_t(const OBJ_NAME* nm, void* arg)
{
    (void)arg;
    (void)nm;

    AssertIntGT(nm->type, OBJ_NAME_TYPE_UNDEF);

#if !defined(NO_FILESYSTEM) && defined(DEBUG_WOLFSSL_VERBOSE)
    /* print to stderr */
    AssertNotNull(arg);

    BIO *bio = BIO_new(BIO_s_file());
    BIO_set_fp(bio, arg, BIO_NOCLOSE);
    BIO_printf(bio, "%s\n", nm);
    BIO_free(bio);
#endif
}

#endif
static int test_OBJ_NAME_do_all(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA)

    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, NULL, NULL);

    OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, NULL, stderr);

    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, obj_name_t, stderr);
    OBJ_NAME_do_all(OBJ_NAME_TYPE_PKEY_METH, obj_name_t, stderr);
    OBJ_NAME_do_all(OBJ_NAME_TYPE_COMP_METH, obj_name_t, stderr);
    OBJ_NAME_do_all(OBJ_NAME_TYPE_NUM, obj_name_t, stderr);
    OBJ_NAME_do_all(OBJ_NAME_TYPE_UNDEF, obj_name_t, stderr);
    OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, obj_name_t, stderr);
    OBJ_NAME_do_all(-1, obj_name_t, stderr);

    res = TEST_SUCCESS;
#endif

    return res;
}

static int test_SSL_CIPHER_get_xxx(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_TLS)
    const SSL_CIPHER* cipher = NULL;
    STACK_OF(SSL_CIPHER) *supportedCiphers = NULL;
    int i, numCiphers = 0;
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;
    const char* testCertFile;
    const char* testKeyFile;
    char buf[256] = {0};

    const char* cipher_id = NULL;
    int   expect_nid1 = NID_undef;
    int   expect_nid2 = NID_undef;
    int   expect_nid3 = NID_undef;
    int   expect_nid4 = NID_undef;
    int   expect_nid5 = 0;

    const char* cipher_id2 = NULL;
    int   expect_nid21 = NID_undef;
    int   expect_nid22 = NID_undef;
    int   expect_nid23 = NID_undef;
    int   expect_nid24 = NID_undef;
    int   expect_nid25 = 0;

    (void)cipher;
    (void)supportedCiphers;
    (void)i;
    (void)numCiphers;
    (void)ctx;
    (void)ssl;
    (void)testCertFile;
    (void)testKeyFile;

#if defined(WOLFSSL_TLS13)
    cipher_id = "TLS13-AES128-GCM-SHA256";
    expect_nid1 = NID_auth_rsa;
    expect_nid2 = NID_aes_128_gcm;
    expect_nid3 = NID_sha256;
    expect_nid4 = NID_kx_any;
    expect_nid5 = 1;

    #if !defined(WOLFSSL_NO_TLS12)
    cipher_id2 = "ECDHE-RSA-AES256-GCM-SHA384";
    expect_nid21 = NID_auth_rsa;
    expect_nid22 = NID_aes_256_gcm;
    expect_nid23 = NID_sha384;
    expect_nid24 = NID_kx_ecdhe;
    expect_nid25 = 1;
    #endif
#endif

    #ifdef NO_WOLFSSL_SERVER
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    #else
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    #endif

    if (cipher_id) {
    #ifndef NO_RSA
        testCertFile = svrCertFile;
        testKeyFile = svrKeyFile;
    #elif defined(HAVE_ECC)
        testCertFile = eccCertFile;
        testKeyFile = eccKeyFile;
    #else
        testCertFile = NULL;
        testKeyFile = NULL;
    #endif
        if  (testCertFile != NULL && testKeyFile != NULL) {
            ExpectTrue(SSL_CTX_use_certificate_file(ctx, testCertFile,
                                                    SSL_FILETYPE_PEM));
            ExpectTrue(SSL_CTX_use_PrivateKey_file(ctx, testKeyFile,
                                                    SSL_FILETYPE_PEM));
        }

        ExpectNotNull(ssl = SSL_new(ctx));
        ExpectIntEQ(SSL_in_init(ssl), 1);

        supportedCiphers = SSL_get_ciphers(ssl);
        numCiphers = sk_num(supportedCiphers);

        for (i = 0; i < numCiphers; ++i) {

            if ((cipher = (const WOLFSSL_CIPHER*)sk_value(supportedCiphers, i))) {
                SSL_CIPHER_description(cipher, buf, sizeof(buf));
            }

            if (XMEMCMP(cipher_id, buf, XSTRLEN(cipher_id)) == 0) {
                break;
            }
        }
        /* test case for */
        if (i != numCiphers) {
            ExpectIntEQ(wolfSSL_CIPHER_get_auth_nid(cipher), expect_nid1);
            ExpectIntEQ(wolfSSL_CIPHER_get_cipher_nid(cipher), expect_nid2);
            ExpectIntEQ(wolfSSL_CIPHER_get_digest_nid(cipher), expect_nid3);
            ExpectIntEQ(wolfSSL_CIPHER_get_kx_nid(cipher), expect_nid4);
            ExpectIntEQ(wolfSSL_CIPHER_is_aead(cipher), expect_nid5);
        }

        if (cipher_id2) {

            for (i = 0; i < numCiphers; ++i) {

                if ((cipher = (const WOLFSSL_CIPHER*)sk_value(supportedCiphers, i))) {
                    SSL_CIPHER_description(cipher, buf, sizeof(buf));
                }

                if (XMEMCMP(cipher_id2, buf, XSTRLEN(cipher_id2)) == 0) {
                    break;
                }
            }
            /* test case for */
            if (i != numCiphers) {
                ExpectIntEQ(wolfSSL_CIPHER_get_auth_nid(cipher), expect_nid21);
                ExpectIntEQ(wolfSSL_CIPHER_get_cipher_nid(cipher), expect_nid22);
                ExpectIntEQ(wolfSSL_CIPHER_get_digest_nid(cipher), expect_nid23);
                ExpectIntEQ(wolfSSL_CIPHER_get_kx_nid(cipher), expect_nid24);
                ExpectIntEQ(wolfSSL_CIPHER_is_aead(cipher), expect_nid25);
            }
        }
    }

    SSL_CTX_free(ctx);
    SSL_free(ssl);
#endif

    return EXPECT_RESULT();
}

#if defined(WOLF_CRYPTO_CB) && defined(HAVE_IO_TESTS_DEPENDENCIES)

static int load_pem_key_file_as_der(const char* privKeyFile, DerBuffer** pDer,
    int* keyFormat)
{
    int ret;
    byte* key_buf = NULL;
    size_t key_sz = 0;
    EncryptedInfo encInfo;

    XMEMSET(&encInfo, 0, sizeof(encInfo));

    ret = load_file(privKeyFile, &key_buf, &key_sz);
    if (ret == 0) {
        ret = wc_PemToDer(key_buf, key_sz, PRIVATEKEY_TYPE, pDer,
            NULL, &encInfo, keyFormat);
    }

    if (key_buf != NULL) {
        free(key_buf); key_buf = NULL;
    }
    (void)encInfo; /* not used in this test */

#ifdef DEBUG_WOLFSSL
    fprintf(stderr, "%s (%d): Loading PEM %s (len %d) to DER (len %d)\n",
        (ret == 0) ? "Success" : "Failure", ret, privKeyFile, (int)key_sz,
        (*pDer)->length);
#endif

    return ret;
}
static int test_CryptoCb_Func(int thisDevId, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    const char* privKeyFile = (const char*)ctx;
    DerBuffer* pDer = NULL;
    int keyFormat = 0;

    if (info->algo_type == WC_ALGO_TYPE_PK) {
    #ifdef DEBUG_WOLFSSL
        fprintf(stderr, "test_CryptoCb_Func: Pk Type %d\n", info->pk.type);
    #endif

    #ifndef NO_RSA
        if (info->pk.type == WC_PK_TYPE_RSA) {
            switch (info->pk.rsa.type) {
                case RSA_PUBLIC_ENCRYPT:
                case RSA_PUBLIC_DECRYPT:
                    /* perform software based RSA public op */
                    ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE); /* fallback to software */
                    break;
                case RSA_PRIVATE_ENCRYPT:
                case RSA_PRIVATE_DECRYPT:
                {
                    RsaKey key;

                    /* perform software based RSA private op */
                #ifdef DEBUG_WOLFSSL
                    fprintf(stderr, "test_CryptoCb_Func: RSA Priv\n");
                #endif

                    ret = load_pem_key_file_as_der(privKeyFile, &pDer,
                        &keyFormat);
                    if (ret != 0) {
                        return ret;
                    }
                    ret = wc_InitRsaKey(&key, HEAP_HINT);
                    if (ret == 0) {
                        word32 keyIdx = 0;
                        /* load RSA private key and perform private transform */
                        ret = wc_RsaPrivateKeyDecode(pDer->buffer, &keyIdx,
                            &key, pDer->length);
                        if (ret == 0) {
                            ret = wc_RsaFunction(
                                info->pk.rsa.in, info->pk.rsa.inLen,
                                info->pk.rsa.out, info->pk.rsa.outLen,
                                info->pk.rsa.type, &key, info->pk.rsa.rng);
                        }
                        else {
                            /* if decode fails, then fall-back to software based crypto */
                            fprintf(stderr, "test_CryptoCb_Func: RSA private "
                                "key decode failed %d, falling back to "
                                "software\n", ret);
                            ret = CRYPTOCB_UNAVAILABLE;
                        }
                        wc_FreeRsaKey(&key);
                    }
                    wc_FreeDer(&pDer); pDer = NULL;
                    break;
                }
            }
        #ifdef DEBUG_WOLFSSL
            fprintf(stderr, "test_CryptoCb_Func: RSA Type %d, Ret %d, Out %d\n",
                info->pk.rsa.type, ret, *info->pk.rsa.outLen);
        #endif
        }
        #ifdef WOLF_CRYPTO_CB_RSA_PAD
        else if (info->pk.type == WC_PK_TYPE_RSA_PKCS ||
                 info->pk.type == WC_PK_TYPE_RSA_PSS  ||
                 info->pk.type == WC_PK_TYPE_RSA_OAEP) {
            RsaKey key;

            if (info->pk.rsa.type == RSA_PUBLIC_ENCRYPT ||
                info->pk.rsa.type == RSA_PUBLIC_DECRYPT) {
                /* Have all public key ops fall back to SW */
                return CRYPTOCB_UNAVAILABLE;
            }

            if (info->pk.rsa.padding == NULL) {
                return BAD_FUNC_ARG;
            }

            /* Initialize key */
            ret = load_pem_key_file_as_der(privKeyFile, &pDer,
                &keyFormat);
            if (ret != 0) {
                return ret;
            }

            ret = wc_InitRsaKey(&key, HEAP_HINT);
            if (ret == 0) {
                word32 keyIdx = 0;
                /* load RSA private key and perform private transform */
                ret = wc_RsaPrivateKeyDecode(pDer->buffer, &keyIdx,
                    &key, pDer->length);
            }
            /* Perform RSA operation */
            if ((ret == 0) && (info->pk.type == WC_PK_TYPE_RSA_PKCS)) {
            #if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
                ret = wc_RsaSSL_Sign(info->pk.rsa.in, info->pk.rsa.inLen,
                    info->pk.rsa.out, *info->pk.rsa.outLen, &key,
                    info->pk.rsa.rng);
            #else
                ret = CRYPTOCB_UNAVAILABLE;
            #endif
            }
            if ((ret == 0) && (info->pk.type == WC_PK_TYPE_RSA_PSS)) {
            #ifdef WC_RSA_PSS
                ret = wc_RsaPSS_Sign_ex(info->pk.rsa.in, info->pk.rsa.inLen,
                    info->pk.rsa.out, *info->pk.rsa.outLen,
                    info->pk.rsa.padding->hash, info->pk.rsa.padding->mgf,
                    info->pk.rsa.padding->saltLen, &key, info->pk.rsa.rng);
            #else
                ret = CRYPTOCB_UNAVAILABLE;
            #endif
            }
            if ((ret == 0) && (info->pk.type == WC_PK_TYPE_RSA_OAEP)) {
            #if !defined(WC_NO_RSA_OAEP) || defined(WC_RSA_NO_PADDING)
                ret = wc_RsaPrivateDecrypt_ex(
                    info->pk.rsa.in, info->pk.rsa.inLen,
                    info->pk.rsa.out, *info->pk.rsa.outLen,
                    &key, WC_RSA_OAEP_PAD, info->pk.rsa.padding->hash,
                    info->pk.rsa.padding->mgf, info->pk.rsa.padding->label,
                    info->pk.rsa.padding->labelSz);
            #else
                ret = CRYPTOCB_UNAVAILABLE;
            #endif
            }

            if (ret > 0) {
                *info->pk.rsa.outLen = ret;
            }

            wc_FreeRsaKey(&key);
            wc_FreeDer(&pDer); pDer = NULL;
        }
        #endif /* ifdef WOLF_CRYPTO_CB_RSA_PAD */
    #endif /* !NO_RSA */
    #ifdef HAVE_ECC
        if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
            /* mark this key as ephemeral */
            if (info->pk.eckg.key != NULL) {
                XSTRNCPY(info->pk.eckg.key->label, "ephemeral",
                    sizeof(info->pk.eckg.key->label));
                info->pk.eckg.key->labelLen = (int)XSTRLEN(info->pk.eckg.key->label);
            }
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
            ecc_key key;

            /* perform software based ECC sign */
        #ifdef DEBUG_WOLFSSL
            fprintf(stderr, "test_CryptoCb_Func: ECC Sign\n");
        #endif

            if (info->pk.eccsign.key != NULL &&
                XSTRCMP(info->pk.eccsign.key->label, "ephemeral") == 0) {
                /* this is an empheral key */
            #ifdef DEBUG_WOLFSSL
                fprintf(stderr, "test_CryptoCb_Func: skipping signing op on "
                    "ephemeral key\n");
            #endif
                return CRYPTOCB_UNAVAILABLE;
            }

            ret = load_pem_key_file_as_der(privKeyFile, &pDer, &keyFormat);
            if (ret != 0) {
                return ret;
            }

            ret = wc_ecc_init(&key);
            if (ret == 0) {
                word32 keyIdx = 0;
                /* load ECC private key and perform private transform */
                ret = wc_EccPrivateKeyDecode(pDer->buffer, &keyIdx,
                    &key, pDer->length);
                if (ret == 0) {
                    ret = wc_ecc_sign_hash(
                        info->pk.eccsign.in, info->pk.eccsign.inlen,
                        info->pk.eccsign.out, info->pk.eccsign.outlen,
                        info->pk.eccsign.rng, &key);
                }
                else {
                    /* if decode fails, then fall-back to software based crypto */
                    fprintf(stderr, "test_CryptoCb_Func: ECC private key "
                        "decode failed %d, falling back to software\n", ret);
                    ret = CRYPTOCB_UNAVAILABLE;
                }
                wc_ecc_free(&key);
            }
            wc_FreeDer(&pDer); pDer = NULL;

        #ifdef DEBUG_WOLFSSL
            fprintf(stderr, "test_CryptoCb_Func: ECC Ret %d, Out %d\n",
                ret, *info->pk.eccsign.outlen);
        #endif
        }
    #endif /* HAVE_ECC */
    #ifdef HAVE_ED25519
        if (info->pk.type == WC_PK_TYPE_ED25519_SIGN) {
            ed25519_key key;

            /* perform software based ED25519 sign */
        #ifdef DEBUG_WOLFSSL
            fprintf(stderr, "test_CryptoCb_Func: ED25519 Sign\n");
        #endif

            ret = load_pem_key_file_as_der(privKeyFile, &pDer, &keyFormat);
            if (ret != 0) {
                return ret;
            }
            ret = wc_ed25519_init(&key);
            if (ret == 0) {
                word32 keyIdx = 0;
                /* load ED25519 private key and perform private transform */
                ret = wc_Ed25519PrivateKeyDecode(pDer->buffer, &keyIdx,
                    &key, pDer->length);
                if (ret == 0) {
                    /* calculate public key */
                    ret = wc_ed25519_make_public(&key, key.p, ED25519_PUB_KEY_SIZE);
                    if (ret == 0) {
                        key.pubKeySet = 1;
                        ret = wc_ed25519_sign_msg_ex(
                            info->pk.ed25519sign.in, info->pk.ed25519sign.inLen,
                            info->pk.ed25519sign.out, info->pk.ed25519sign.outLen,
                            &key, info->pk.ed25519sign.type,
                            info->pk.ed25519sign.context,
                            info->pk.ed25519sign.contextLen);
                    }
                }
                else {
                    /* if decode fails, then fall-back to software based crypto */
                    fprintf(stderr, "test_CryptoCb_Func: ED25519 private key "
                        "decode failed %d, falling back to software\n", ret);
                    ret = CRYPTOCB_UNAVAILABLE;
                }
                wc_ed25519_free(&key);
            }
            wc_FreeDer(&pDer); pDer = NULL;

        #ifdef DEBUG_WOLFSSL
            fprintf(stderr, "test_CryptoCb_Func: ED25519 Ret %d, Out %d\n",
                ret, *info->pk.ed25519sign.outLen);
        #endif
        }
    #endif /* HAVE_ED25519 */
    }
    (void)thisDevId;
    (void)keyFormat;

    return ret;
}

/* tlsVer: WOLFSSL_TLSV1_2 or WOLFSSL_TLSV1_3 */
static int test_wc_CryptoCb_TLS(int tlsVer,
    const char* cliCaPemFile, const char* cliCertPemFile,
    const char* cliPrivKeyPemFile, const char* cliPubKeyPemFile,
    const char* svrCaPemFile, const char* svrCertPemFile,
    const char* svrPrivKeyPemFile, const char* svrPubKeyPemFile)
{
    EXPECT_DECLS;
    callback_functions client_cbf;
    callback_functions server_cbf;

    XMEMSET(&client_cbf, 0, sizeof(client_cbf));
    XMEMSET(&server_cbf, 0, sizeof(server_cbf));

    if (tlsVer == WOLFSSL_TLSV1_3) {
    #ifdef WOLFSSL_TLS13
        server_cbf.method = wolfTLSv1_3_server_method;
        client_cbf.method = wolfTLSv1_3_client_method;
    #endif
    }
    else if (tlsVer == WOLFSSL_TLSV1_2) {
    #ifndef WOLFSSL_NO_TLS12
        server_cbf.method = wolfTLSv1_2_server_method;
        client_cbf.method = wolfTLSv1_2_client_method;
    #endif
    }
    else if (tlsVer == WOLFSSL_TLSV1_1) {
    #ifndef NO_OLD_TLS
        server_cbf.method = wolfTLSv1_1_server_method;
        client_cbf.method = wolfTLSv1_1_client_method;
    #endif
    }
    else if (tlsVer == WOLFSSL_TLSV1) {
    #if !defined(NO_OLD_TLS) && defined(WOLFSSL_ALLOW_TLSV10)
        server_cbf.method = wolfTLSv1_server_method;
        client_cbf.method = wolfTLSv1_client_method;
    #endif
    }
    else if (tlsVer == WOLFSSL_SSLV3) {
    #if !defined(NO_OLD_TLS) && defined(WOLFSSL_ALLOW_SSLV3) && \
         defined(WOLFSSL_STATIC_RSA)
        server_cbf.method = wolfSSLv3_server_method;
        client_cbf.method = wolfSSLv3_client_method;
    #endif
    }
    else if (tlsVer == WOLFSSL_DTLSV1_2) {
    #if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)
        server_cbf.method = wolfDTLSv1_2_server_method;
        client_cbf.method = wolfDTLSv1_2_client_method;
    #endif
    }
    else if (tlsVer == WOLFSSL_DTLSV1) {
    #if defined(WOLFSSL_DTLS) && !defined(NO_OLD_TLS)
        server_cbf.method = wolfDTLSv1_server_method;
        client_cbf.method = wolfDTLSv1_client_method;
    #endif
    }

    if (server_cbf.method == NULL) {
        /* not enabled */
        return TEST_SUCCESS;
    }

    /* Setup the keys for the TLS test */
    client_cbf.certPemFile = cliCertPemFile;
    client_cbf.keyPemFile = cliPubKeyPemFile;
    client_cbf.caPemFile = cliCaPemFile;

    server_cbf.certPemFile = svrCertPemFile;
    server_cbf.keyPemFile = svrPubKeyPemFile;
    server_cbf.caPemFile = svrCaPemFile;

    /* Setup a crypto callback with pointer to private key file for testing */
    client_cbf.devId = 1;
    wc_CryptoCb_RegisterDevice(client_cbf.devId, test_CryptoCb_Func,
        (void*)cliPrivKeyPemFile);
    server_cbf.devId = 2;
    wc_CryptoCb_RegisterDevice(server_cbf.devId, test_CryptoCb_Func,
        (void*)svrPrivKeyPemFile);

    /* Perform TLS server and client test */
    /* First test is at WOLFSSL_CTX level */
    test_wolfSSL_client_server(&client_cbf, &server_cbf);
    /* Check for success */
    ExpectIntEQ(server_cbf.return_code, TEST_SUCCESS);
    ExpectIntEQ(client_cbf.return_code, TEST_SUCCESS);

    if (EXPECT_SUCCESS()) {
        /* Second test is a WOLFSSL object level */
        client_cbf.loadToSSL = 1; server_cbf.loadToSSL = 1;
        test_wolfSSL_client_server(&client_cbf, &server_cbf);
    }

    /* Check for success */
    ExpectIntEQ(server_cbf.return_code, TEST_SUCCESS);
    ExpectIntEQ(client_cbf.return_code, TEST_SUCCESS);

    /* Un register the devId's */
    wc_CryptoCb_UnRegisterDevice(client_cbf.devId);
    client_cbf.devId = INVALID_DEVID;
    wc_CryptoCb_UnRegisterDevice(server_cbf.devId);
    server_cbf.devId = INVALID_DEVID;

    return EXPECT_RESULT();
}
#endif /* WOLF_CRYPTO_CB && HAVE_IO_TESTS_DEPENDENCIES */

static int test_wc_CryptoCb(void)
{
    EXPECT_DECLS;
#ifdef WOLF_CRYPTO_CB
    /* TODO: Add crypto callback API tests */

#ifdef HAVE_IO_TESTS_DEPENDENCIES
    #if !defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519)
    int tlsVer;
    #endif

    #ifndef NO_RSA
    for (tlsVer = WOLFSSL_SSLV3; tlsVer <= WOLFSSL_DTLSV1; tlsVer++) {
        ExpectIntEQ(test_wc_CryptoCb_TLS(tlsVer,
            svrCertFile, cliCertFile, cliKeyFile, cliKeyPubFile,
            cliCertFile, svrCertFile, svrKeyFile, svrKeyPubFile),
            TEST_SUCCESS);
    }
    #endif
    #ifdef HAVE_ECC
    for (tlsVer = WOLFSSL_TLSV1; tlsVer <= WOLFSSL_DTLSV1; tlsVer++) {
        ExpectIntEQ(test_wc_CryptoCb_TLS(tlsVer,
            caEccCertFile,  cliEccCertFile, cliEccKeyFile, cliEccKeyPubFile,
            cliEccCertFile, eccCertFile,    eccKeyFile,    eccKeyPubFile),
            TEST_SUCCESS);
    }
    #endif
    #ifdef HAVE_ED25519
    for (tlsVer = WOLFSSL_TLSV1_2; tlsVer <= WOLFSSL_DTLSV1_2; tlsVer++) {
        if (tlsVer == WOLFSSL_DTLSV1) continue;
        ExpectIntEQ(test_wc_CryptoCb_TLS(tlsVer,
            caEdCertFile,  cliEdCertFile, cliEdKeyFile, cliEdKeyPubFile,
            cliEdCertFile, edCertFile,    edKeyFile,    edKeyPubFile),
            TEST_SUCCESS);
    }
    #endif
#endif /* HAVE_IO_TESTS_DEPENDENCIES */
#endif /* WOLF_CRYPTO_CB */
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_STATIC_MEMORY) && defined(HAVE_IO_TESTS_DEPENDENCIES)

/* tlsVer: Example: WOLFSSL_TLSV1_2 or WOLFSSL_TLSV1_3 */
static int test_wolfSSL_CTX_StaticMemory_TLS(int tlsVer,
    const char* cliCaPemFile, const char* cliCertPemFile,
    const char* cliPrivKeyPemFile,
    const char* svrCaPemFile, const char* svrCertPemFile,
    const char* svrPrivKeyPemFile,
    byte* cliMem, word32 cliMemSz, byte* svrMem, word32 svrMemSz)
{
    EXPECT_DECLS;
    callback_functions client_cbf;
    callback_functions server_cbf;

    XMEMSET(&client_cbf, 0, sizeof(client_cbf));
    XMEMSET(&server_cbf, 0, sizeof(server_cbf));

    if (tlsVer == WOLFSSL_TLSV1_3) {
    #ifdef WOLFSSL_TLS13
        server_cbf.method_ex = wolfTLSv1_3_server_method_ex;
        client_cbf.method_ex = wolfTLSv1_3_client_method_ex;
    #endif
    }
    else if (tlsVer == WOLFSSL_TLSV1_2) {
    #ifndef WOLFSSL_NO_TLS12
        server_cbf.method_ex = wolfTLSv1_2_server_method_ex;
        client_cbf.method_ex = wolfTLSv1_2_client_method_ex;
    #endif
    }
    else if (tlsVer == WOLFSSL_TLSV1_1) {
    #ifndef NO_OLD_TLS
        server_cbf.method_ex = wolfTLSv1_1_server_method_ex;
        client_cbf.method_ex = wolfTLSv1_1_client_method_ex;
    #endif
    }
    else if (tlsVer == WOLFSSL_TLSV1) {
    #if !defined(NO_OLD_TLS) && defined(WOLFSSL_ALLOW_TLSV10)
        server_cbf.method_ex = wolfTLSv1_server_method_ex;
        client_cbf.method_ex = wolfTLSv1_client_method_ex;
    #endif
    }
    else if (tlsVer == WOLFSSL_SSLV3) {
    #if !defined(NO_OLD_TLS) && defined(WOLFSSL_ALLOW_SSLV3) && \
         defined(WOLFSSL_STATIC_RSA)
        server_cbf.method_ex = wolfSSLv3_server_method_ex;
        client_cbf.method_ex = wolfSSLv3_client_method_ex;
    #endif
    }
    else if (tlsVer == WOLFSSL_DTLSV1_2) {
    #if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)
        server_cbf.method_ex = wolfDTLSv1_2_server_method_ex;
        client_cbf.method_ex = wolfDTLSv1_2_client_method_ex;
    #endif
    }
    else if (tlsVer == WOLFSSL_DTLSV1) {
    #if defined(WOLFSSL_DTLS) && !defined(NO_OLD_TLS)
        server_cbf.method_ex = wolfDTLSv1_server_method_ex;
        client_cbf.method_ex = wolfDTLSv1_client_method_ex;
    #endif
    }

    if (server_cbf.method_ex == NULL) {
        /* not enabled */
        return TEST_SUCCESS;
    }

    /* Setup the keys for the TLS test */
    client_cbf.certPemFile = cliCertPemFile;
    client_cbf.keyPemFile = cliPrivKeyPemFile;
    client_cbf.caPemFile = cliCaPemFile;

    server_cbf.certPemFile = svrCertPemFile;
    server_cbf.keyPemFile = svrPrivKeyPemFile;
    server_cbf.caPemFile = svrCaPemFile;

    client_cbf.mem = cliMem;
    client_cbf.memSz = cliMemSz;
    server_cbf.mem = svrMem;
    server_cbf.memSz = svrMemSz;

    client_cbf.devId = INVALID_DEVID;
    server_cbf.devId = INVALID_DEVID;

    /* Perform TLS server and client test */
    /* First test is at WOLFSSL_CTX level */
    test_wolfSSL_client_server(&client_cbf, &server_cbf);
    /* Check for success */
    ExpectIntEQ(server_cbf.return_code, TEST_SUCCESS);
    ExpectIntEQ(client_cbf.return_code, TEST_SUCCESS);

    if (EXPECT_SUCCESS()) {
       /* Second test is a WOLFSSL object level */
       client_cbf.loadToSSL = 1; server_cbf.loadToSSL = 1;
       test_wolfSSL_client_server(&client_cbf, &server_cbf);
    }

    /* Check for success */
    ExpectIntEQ(server_cbf.return_code, TEST_SUCCESS);
    ExpectIntEQ(client_cbf.return_code, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#endif /* WOLFSSL_STATIC_MEMORY && HAVE_IO_TESTS_DEPENDENCIES */

#if defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFCRYPT_ONLY)
static int test_wolfSSL_CTX_StaticMemory_SSL(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    WOLFSSL *ssl1 = NULL, *ssl2 = NULL, *ssl3 = NULL;
    WOLFSSL_MEM_STATS mem_stats;
    WOLFSSL_MEM_CONN_STATS ssl_stats;

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_RSA)
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
#endif

    ExpectNotNull((ssl1 = wolfSSL_new(ctx)));
    ExpectNotNull((ssl2 = wolfSSL_new(ctx)));

#ifndef WOLFSSL_STATIC_MEMORY_LEAN
    /* this should fail because kMaxCtxClients == 2 */
    ExpectNull((ssl3 = wolfSSL_new(ctx)));
#else
    (void)ssl3;
#endif

    if (wolfSSL_is_static_memory(ssl1, &ssl_stats) == 1) {
    #if defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_STATIC_MEMORY_LEAN)
        wolfSSL_PrintStatsConn(&ssl_stats);
    #endif
        (void)ssl_stats;
    }

    /* display collected statistics */
    if (wolfSSL_CTX_is_static_memory(ctx, &mem_stats) == 1) {
    #if defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_STATIC_MEMORY_LEAN)
        wolfSSL_PrintStats(&mem_stats);
    #endif
        (void)mem_stats;
    }

    wolfSSL_free(ssl1);
    wolfSSL_free(ssl2);

    return EXPECT_RESULT();
}
#endif /* WOLFSSL_STATIC_MEMORY && !WOLFCRYPT_ONLY */

static int test_wolfSSL_CTX_StaticMemory(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFCRYPT_ONLY)
    wolfSSL_method_func method_func;
    WOLFSSL_CTX* ctx;
    const int kMaxCtxClients = 2;
    #ifdef HAVE_IO_TESTS_DEPENDENCIES
    #if !defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519)
    int tlsVer;
    byte cliMem[TEST_TLS_STATIC_MEMSZ];
    #endif
    #endif
    byte svrMem[TEST_TLS_STATIC_MEMSZ];

#ifndef NO_WOLFSSL_SERVER
    #ifndef WOLFSSL_NO_TLS12
        method_func = wolfTLSv1_2_server_method_ex;
    #else
        method_func = wolfTLSv1_3_server_method_ex;
    #endif
#else
    #ifndef WOLFSSL_NO_TLS12
        method_func = wolfTLSv1_2_client_method_ex;
    #else
        method_func = wolfTLSv1_3_client_method_ex;
    #endif
#endif

    /* Test creating CTX directly from static memory pool */
    ctx = NULL;
    ExpectIntEQ(wolfSSL_CTX_load_static_memory(&ctx, method_func, svrMem,
        sizeof(svrMem), 0, kMaxCtxClients), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_wolfSSL_CTX_StaticMemory_SSL(ctx), TEST_SUCCESS);
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* Test for heap allocated CTX, then assigning static pool to it */
    ExpectNotNull(ctx = wolfSSL_CTX_new(method_func(NULL)));
    ExpectIntEQ(wolfSSL_CTX_load_static_memory(&ctx, NULL, svrMem,
        sizeof(svrMem), 0, kMaxCtxClients), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_wolfSSL_CTX_StaticMemory_SSL(ctx), TEST_SUCCESS);
    wolfSSL_CTX_free(ctx);

    /* TLS Level Tests using static memory */
#ifdef HAVE_IO_TESTS_DEPENDENCIES
    #ifndef NO_RSA
    for (tlsVer = WOLFSSL_SSLV3; tlsVer <= WOLFSSL_DTLSV1; tlsVer++) {
        ExpectIntEQ(test_wolfSSL_CTX_StaticMemory_TLS(tlsVer,
            svrCertFile, cliCertFile, cliKeyFile,
            cliCertFile, svrCertFile, svrKeyFile,
            cliMem, (word32)sizeof(cliMem), svrMem, (word32)sizeof(svrMem)),
            TEST_SUCCESS);
    }
    #endif
    #ifdef HAVE_ECC
    for (tlsVer = WOLFSSL_TLSV1; tlsVer <= WOLFSSL_DTLSV1; tlsVer++) {
        ExpectIntEQ(test_wolfSSL_CTX_StaticMemory_TLS(tlsVer,
            caEccCertFile,  cliEccCertFile, cliEccKeyFile,
            cliEccCertFile, eccCertFile,    eccKeyFile,
            cliMem, (word32)sizeof(cliMem), svrMem, (word32)sizeof(svrMem)),
            TEST_SUCCESS);
    }
    #endif
    #ifdef HAVE_ED25519
    for (tlsVer = WOLFSSL_TLSV1_2; tlsVer <= WOLFSSL_DTLSV1_2; tlsVer++) {
        if (tlsVer == WOLFSSL_DTLSV1) continue;
        ExpectIntEQ(test_wolfSSL_CTX_StaticMemory_TLS(tlsVer,
            caEdCertFile,  cliEdCertFile, cliEdKeyFile,
            cliEdCertFile, edCertFile,    edKeyFile,
            cliMem, (word32)sizeof(cliMem), svrMem, (word32)sizeof(svrMem)),
            TEST_SUCCESS);
    }
    #endif
#endif /* HAVE_IO_TESTS_DEPENDENCIES */
#endif /* WOLFSSL_STATIC_MEMORY && !WOLFCRYPT_ONLY */
    return EXPECT_RESULT();
}

static int test_openssl_FIPS_drbg(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(WC_NO_RNG) && defined(HAVE_HASHDRBG)
    DRBG_CTX* dctx = NULL;
    byte data1[32], data2[32], zeroData[32];
    byte testSeed[16];
    size_t dlen = sizeof(data1);
    int i;

    XMEMSET(data1, 0, dlen);
    XMEMSET(data2, 0, dlen);
    XMEMSET(zeroData, 0, sizeof(zeroData));
    for (i = 0; i < (int)sizeof(testSeed); i++) {
        testSeed[i] = (byte)i;
    }

    ExpectNotNull(dctx = FIPS_get_default_drbg());
    ExpectIntEQ(FIPS_drbg_init(dctx, 0, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(FIPS_drbg_set_callbacks(dctx, NULL, NULL, 20, NULL, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(FIPS_drbg_instantiate(dctx, NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(FIPS_drbg_generate(dctx, data1, dlen, 0, NULL, 0),
        WOLFSSL_SUCCESS);
    ExpectIntNE(XMEMCMP(data1, zeroData, dlen), 0);
    ExpectIntEQ(FIPS_drbg_reseed(dctx, testSeed, sizeof(testSeed)),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(FIPS_drbg_generate(dctx, data2, dlen, 0, NULL, 0),
        WOLFSSL_SUCCESS);
    ExpectIntNE(XMEMCMP(data1, zeroData, dlen), 0);
    ExpectIntNE(XMEMCMP(data1, data2, dlen), 0);
    ExpectIntEQ(FIPS_drbg_uninstantiate(dctx), WOLFSSL_SUCCESS);
#ifndef HAVE_GLOBAL_RNG
    /* gets freed by wolfSSL_Cleanup() when HAVE_GLOBAL_RNG defined */
    wolfSSL_FIPS_drbg_free(dctx);
#endif
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_FIPS_mode(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL)
#ifdef HAVE_FIPS
    ExpectIntEQ(wolfSSL_FIPS_mode(), 1);
    ExpectIntEQ(wolfSSL_FIPS_mode_set(0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_FIPS_mode_set(1), WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(wolfSSL_FIPS_mode(), 0);
    ExpectIntEQ(wolfSSL_FIPS_mode_set(0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_FIPS_mode_set(1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif
#endif
    return EXPECT_RESULT();
}

#ifdef WOLFSSL_DTLS

/* Prints out the current window */
static void DUW_TEST_print_window_binary(word32 h, word32 l, word32* w) {
#ifdef WOLFSSL_DEBUG_DTLS_WINDOW
    int i;
    for (i = WOLFSSL_DTLS_WINDOW_WORDS - 1; i >= 0; i--) {
        word32 b = w[i];
        int j;
        /* Prints out a 32 bit binary number in big endian order */
        for (j = 0; j < 32; j++, b <<= 1) {
            if (b & (((word32)1) << 31))
                fprintf(stderr, "1");
            else
                fprintf(stderr, "0");
        }
        fprintf(stderr, " ");
    }
    fprintf(stderr, "cur_hi %u cur_lo %u\n", h, l);
#else
    (void)h;
    (void)l;
    (void)w;
#endif
}

/* a - cur_hi
 * b - cur_lo
 * c - next_hi
 * d - next_lo
 * e - window
 * f - expected next_hi
 * g - expected next_lo
 * h - expected window[1]
 * i - expected window[0]
 */
#define DUW_TEST(a,b,c,d,e,f,g,h,i) do { \
    ExpectIntEQ(wolfSSL_DtlsUpdateWindow((a), (b), &(c), &(d), (e)), 1); \
    DUW_TEST_print_window_binary((a), (b), (e)); \
    ExpectIntEQ((c), (f)); \
    ExpectIntEQ((d), (g)); \
    ExpectIntEQ((e)[1], (h)); \
    ExpectIntEQ((e)[0], (i)); \
} while (0)

static int test_wolfSSL_DtlsUpdateWindow(void)
{
    EXPECT_DECLS;
    word32 window[WOLFSSL_DTLS_WINDOW_WORDS];
    word32 next_lo = 0;
    word16 next_hi = 0;

#ifdef WOLFSSL_DEBUG_DTLS_WINDOW
    fprintf(stderr, "\n");
#endif

    XMEMSET(window, 0, sizeof window);
    DUW_TEST(0, 0, next_hi, next_lo, window, 0, 1, 0, 0x01);
    DUW_TEST(0, 1, next_hi, next_lo, window, 0, 2, 0, 0x03);
    DUW_TEST(0, 5, next_hi, next_lo, window, 0, 6, 0, 0x31);
    DUW_TEST(0, 4, next_hi, next_lo, window, 0, 6, 0, 0x33);
    DUW_TEST(0, 100, next_hi, next_lo, window, 0, 101, 0, 0x01);
    DUW_TEST(0, 101, next_hi, next_lo, window, 0, 102, 0, 0x03);
    DUW_TEST(0, 133, next_hi, next_lo, window, 0, 134, 0x03, 0x01);
    DUW_TEST(0, 200, next_hi, next_lo, window, 0, 201, 0, 0x01);
    DUW_TEST(0, 264, next_hi, next_lo, window, 0, 265, 0, 0x01);
    DUW_TEST(0, 0xFFFFFFFF, next_hi, next_lo, window, 1, 0, 0, 0x01);
    DUW_TEST(0, 0xFFFFFFFD, next_hi, next_lo, window, 1, 0, 0, 0x05);
    DUW_TEST(0, 0xFFFFFFFE, next_hi, next_lo, window, 1, 0, 0, 0x07);
    DUW_TEST(1, 3, next_hi, next_lo, window, 1, 4, 0, 0x71);
    DUW_TEST(1, 0, next_hi, next_lo, window, 1, 4, 0, 0x79);
    DUW_TEST(1, 0xFFFFFFFF, next_hi, next_lo, window, 2, 0, 0, 0x01);
    DUW_TEST(2, 3, next_hi, next_lo, window, 2, 4, 0, 0x11);
    DUW_TEST(2, 0, next_hi, next_lo, window, 2, 4, 0, 0x19);
    DUW_TEST(2, 25, next_hi, next_lo, window, 2, 26, 0, 0x6400001);
    DUW_TEST(2, 27, next_hi, next_lo, window, 2, 28, 0, 0x19000005);
    DUW_TEST(2, 29, next_hi, next_lo, window, 2, 30, 0, 0x64000015);
    DUW_TEST(2, 33, next_hi, next_lo, window, 2, 34, 6, 0x40000151);
    DUW_TEST(2, 60, next_hi, next_lo, window, 2, 61, 0x3200000A, 0x88000001);
    DUW_TEST(1, 0xFFFFFFF0, next_hi, next_lo, window, 2, 61, 0x3200000A, 0x88000001);
    DUW_TEST(2, 0xFFFFFFFD, next_hi, next_lo, window, 2, 0xFFFFFFFE, 0, 0x01);
    DUW_TEST(3, 1, next_hi, next_lo, window, 3, 2, 0, 0x11);
    DUW_TEST(99, 66, next_hi, next_lo, window, 99, 67, 0, 0x01);
    DUW_TEST(50, 66, next_hi, next_lo, window, 99, 67, 0, 0x01);
    DUW_TEST(100, 68, next_hi, next_lo, window, 100, 69, 0, 0x01);
    DUW_TEST(99, 50, next_hi, next_lo, window, 100, 69, 0, 0x01);
    DUW_TEST(99, 0xFFFFFFFF, next_hi, next_lo, window, 100, 69, 0, 0x01);
    DUW_TEST(150, 0xFFFFFFFF, next_hi, next_lo, window, 151, 0, 0, 0x01);
    DUW_TEST(152, 0xFFFFFFFF, next_hi, next_lo, window, 153, 0, 0, 0x01);

    return EXPECT_RESULT();
}
#endif /* WOLFSSL_DTLS */

#ifdef WOLFSSL_DTLS
static int DFB_TEST(WOLFSSL* ssl, word32 seq, word32 len, word32 f_offset,
        word32 f_len, word32 f_count, byte ready, word32 bytesReceived)
{
    DtlsMsg* cur;
    static byte msg[100];
    static byte msgInit = 0;

    if (!msgInit) {
        int i;
        for (i = 0; i < 100; i++)
            msg[i] = i + 1;
        msgInit = 1;
    }

    /* Sanitize test parameters */
    if (len > sizeof(msg))
        return -1;
    if (f_offset + f_len > sizeof(msg))
        return -1;

    DtlsMsgStore(ssl, 0, seq, msg + f_offset, len, certificate, f_offset, f_len, NULL);

    if (ssl->dtls_rx_msg_list == NULL)
        return -100;

    if ((cur = DtlsMsgFind(ssl->dtls_rx_msg_list, 0, seq)) == NULL)
        return -200;
    if (cur->fragBucketListCount != f_count)
        return -300;
    if (cur->ready != ready)
        return -400;
    if (cur->bytesReceived != bytesReceived)
        return -500;
    if (ready) {
        if (cur->fragBucketList != NULL)
            return -600;
        if (XMEMCMP(cur->fullMsg, msg, cur->sz) != 0)
            return -700;
    }
    else {
        DtlsFragBucket* fb;
        if (cur->fragBucketList == NULL)
            return -800;
        for (fb = cur->fragBucketList; fb != NULL; fb = fb->m.m.next) {
            if (XMEMCMP(fb->buf, msg + fb->m.m.offset, fb->m.m.sz) != 0)
                return -900;
        }
    }
    return 0;
}

static int test_wolfSSL_DTLS_fragment_buckets(void)
{
    EXPECT_DECLS;
    WOLFSSL ssl[1];

    XMEMSET(ssl, 0, sizeof(*ssl));

    ExpectIntEQ(DFB_TEST(ssl, 0, 100, 0, 100, 0, 1, 100), 0); /*  0-100 */

    ExpectIntEQ(DFB_TEST(ssl, 1, 100,  0, 20, 1, 0,  20), 0); /*  0-20  */
    ExpectIntEQ(DFB_TEST(ssl, 1, 100, 20, 20, 1, 0,  40), 0); /* 20-40  */
    ExpectIntEQ(DFB_TEST(ssl, 1, 100, 40, 20, 1, 0,  60), 0); /* 40-60  */
    ExpectIntEQ(DFB_TEST(ssl, 1, 100, 60, 20, 1, 0,  80), 0); /* 60-80  */
    ExpectIntEQ(DFB_TEST(ssl, 1, 100, 80, 20, 0, 1, 100), 0); /* 80-100 */

    /* Test all permutations of 3 regions */
    /* 1 2 3 */
    ExpectIntEQ(DFB_TEST(ssl, 2, 100,  0, 30, 1, 0,  30), 0); /*  0-30  */
    ExpectIntEQ(DFB_TEST(ssl, 2, 100, 30, 30, 1, 0,  60), 0); /* 30-60  */
    ExpectIntEQ(DFB_TEST(ssl, 2, 100, 60, 40, 0, 1, 100), 0); /* 60-100 */
    /* 1 3 2 */
    ExpectIntEQ(DFB_TEST(ssl, 3, 100,  0, 30, 1, 0,  30), 0); /*  0-30  */
    ExpectIntEQ(DFB_TEST(ssl, 3, 100, 60, 40, 2, 0,  70), 0); /* 60-100 */
    ExpectIntEQ(DFB_TEST(ssl, 3, 100, 30, 30, 0, 1, 100), 0); /* 30-60  */
    /* 2 1 3 */
    ExpectIntEQ(DFB_TEST(ssl, 4, 100, 30, 30, 1, 0,  30), 0); /* 30-60  */
    ExpectIntEQ(DFB_TEST(ssl, 4, 100,  0, 30, 1, 0,  60), 0); /*  0-30  */
    ExpectIntEQ(DFB_TEST(ssl, 4, 100, 60, 40, 0, 1, 100), 0); /* 60-100 */
    /* 2 3 1 */
    ExpectIntEQ(DFB_TEST(ssl, 5, 100, 30, 30, 1, 0,  30), 0); /* 30-60  */
    ExpectIntEQ(DFB_TEST(ssl, 5, 100, 60, 40, 1, 0,  70), 0); /* 60-100 */
    ExpectIntEQ(DFB_TEST(ssl, 5, 100,  0, 30, 0, 1, 100), 0); /*  0-30  */
    /* 3 1 2 */
    ExpectIntEQ(DFB_TEST(ssl, 6, 100, 60, 40, 1, 0,  40), 0); /* 60-100 */
    ExpectIntEQ(DFB_TEST(ssl, 6, 100,  0, 30, 2, 0,  70), 0); /*  0-30  */
    ExpectIntEQ(DFB_TEST(ssl, 6, 100, 30, 30, 0, 1, 100), 0); /* 30-60  */
    /* 3 2 1 */
    ExpectIntEQ(DFB_TEST(ssl, 7, 100, 60, 40, 1, 0,  40), 0); /* 60-100 */
    ExpectIntEQ(DFB_TEST(ssl, 7, 100, 30, 30, 1, 0,  70), 0); /* 30-60  */
    ExpectIntEQ(DFB_TEST(ssl, 7, 100,  0, 30, 0, 1, 100), 0); /*  0-30  */

    /* Test overlapping regions */
    ExpectIntEQ(DFB_TEST(ssl, 8, 100,  0, 30, 1, 0,  30), 0); /*  0-30  */
    ExpectIntEQ(DFB_TEST(ssl, 8, 100, 20, 10, 1, 0,  30), 0); /* 20-30  */
    ExpectIntEQ(DFB_TEST(ssl, 8, 100, 70, 10, 2, 0,  40), 0); /* 70-80  */
    ExpectIntEQ(DFB_TEST(ssl, 8, 100, 20, 30, 2, 0,  60), 0); /* 20-50  */
    ExpectIntEQ(DFB_TEST(ssl, 8, 100, 40, 60, 0, 1, 100), 0); /* 40-100 */

    /* Test overlapping multiple regions */
    ExpectIntEQ(DFB_TEST(ssl, 9, 100,  0, 20, 1, 0,  20), 0); /*  0-20  */
    ExpectIntEQ(DFB_TEST(ssl, 9, 100, 30,  5, 2, 0,  25), 0); /* 30-35  */
    ExpectIntEQ(DFB_TEST(ssl, 9, 100, 40,  5, 3, 0,  30), 0); /* 40-45  */
    ExpectIntEQ(DFB_TEST(ssl, 9, 100, 50,  5, 4, 0,  35), 0); /* 50-55  */
    ExpectIntEQ(DFB_TEST(ssl, 9, 100, 60,  5, 5, 0,  40), 0); /* 60-65  */
    ExpectIntEQ(DFB_TEST(ssl, 9, 100, 70,  5, 6, 0,  45), 0); /* 70-75  */
    ExpectIntEQ(DFB_TEST(ssl, 9, 100, 30, 25, 4, 0,  55), 0); /* 30-55  */
    ExpectIntEQ(DFB_TEST(ssl, 9, 100, 55, 15, 2, 0,  65), 0); /* 55-70  */
    ExpectIntEQ(DFB_TEST(ssl, 9, 100, 75, 25, 2, 0,  90), 0); /* 75-100 */
    ExpectIntEQ(DFB_TEST(ssl, 9, 100, 10, 25, 0, 1, 100), 0); /* 10-35 */

    ExpectIntEQ(DFB_TEST(ssl, 10, 100,  0, 20, 1, 0,  20), 0); /*  0-20  */
    ExpectIntEQ(DFB_TEST(ssl, 10, 100, 30, 20, 2, 0,  40), 0); /* 30-50  */
    ExpectIntEQ(DFB_TEST(ssl, 10, 100,  0, 40, 1, 0,  50), 0); /*  0-40  */
    ExpectIntEQ(DFB_TEST(ssl, 10, 100, 50, 50, 0, 1, 100), 0); /* 10-35 */

    DtlsMsgListDelete(ssl->dtls_rx_msg_list, ssl->heap);
    ssl->dtls_rx_msg_list = NULL;
    ssl->dtls_rx_msg_list_sz = 0;

    return EXPECT_RESULT();
}

#endif


#if !defined(NO_FILESYSTEM) && \
     defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
     defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)

static int test_wolfSSL_dtls_stateless2(void)
{
    EXPECT_DECLS;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_c2 = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c2, NULL,
        wolfDTLSv1_2_client_method, NULL), 0);
    ExpectFalse(wolfSSL_is_stateful(ssl_s));
    /* send CH */
    ExpectTrue((wolfSSL_connect(ssl_c2) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c2->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), WOLFSSL_FAILURE);
    ExpectFalse(wolfSSL_is_stateful(ssl_s));
    ExpectIntNE(test_ctx.c_len, 0);
    /* consume HRR */
    test_ctx.c_len = 0;
    /* send CH1 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
    /* send HRR */
    ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), WOLFSSL_FAILURE);
    /* send CH2 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
    /* send HRR */
    ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectTrue(wolfSSL_is_stateful(ssl_s));

    wolfSSL_free(ssl_c2);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}

#ifdef HAVE_MAX_FRAGMENT
static int test_wolfSSL_dtls_stateless_maxfrag(void)
{
    EXPECT_DECLS;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_c2 = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    word16 max_fragment = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);
    ExpectNotNull(ssl_s);
    ExpectNotNull(ssl_c2 = wolfSSL_new(ctx_c));
    ExpectIntEQ(wolfSSL_UseMaxFragment(ssl_c2, WOLFSSL_MFL_2_8),
        WOLFSSL_SUCCESS);
    wolfSSL_SetIOWriteCtx(ssl_c2, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_c2, &test_ctx);
    if (EXPECT_SUCCESS()) {
        max_fragment = ssl_s->max_fragment;
    }
    /* send CH */
    ExpectTrue((wolfSSL_connect(ssl_c2) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c2->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    /* CH without cookie shouldn't change state */
    ExpectIntEQ(ssl_s->max_fragment, max_fragment);
    ExpectIntNE(test_ctx.c_len, 0);

    /* consume HRR from buffer */
    test_ctx.c_len = 0;
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c2);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif /* HAVE_MAX_FRAGMENT */

#if defined(WOLFSSL_DTLS_NO_HVR_ON_RESUME)
#define ROUNDS_WITH_HVR 4
#define ROUNDS_WITHOUT_HVR 2
#define HANDSHAKE_TYPE_OFFSET DTLS_RECORD_HEADER_SZ
static int buf_is_hvr(const byte *data, int len)
{
    if (len < DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ)
        return 0;
    return data[HANDSHAKE_TYPE_OFFSET] == hello_verify_request;
}

static int _test_wolfSSL_dtls_stateless_resume(byte useticket, byte bad)
{
    EXPECT_DECLS;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    int round_trips;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
        &ssl_s, wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);
#ifdef HAVE_SESSION_TICKET
    if (useticket) {
        ExpectIntEQ(wolfSSL_UseSessionTicket(ssl_c), WOLFSSL_SUCCESS);
    }
#endif
    round_trips = ROUNDS_WITH_HVR;
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, round_trips,
        &round_trips), 0);
    ExpectIntEQ(round_trips, ROUNDS_WITH_HVR);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));
    wolfSSL_shutdown(ssl_c);
    wolfSSL_shutdown(ssl_s);
    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;

    test_ctx.c_len = test_ctx.s_len = 0;
    /* make resumption invalid */
    if (bad && (sess != NULL)) {
        if (useticket) {
#ifdef HAVE_SESSION_TICKET
            if (sess->ticket != NULL) {
                sess->ticket[0] = !sess->ticket[0];
            }
#endif /* HAVE_SESSION_TICKET */
        }
        else {
            sess->sessionID[0] = !sess->sessionID[0];
        }
    }
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectTrue((wolfSSL_connect(ssl_c) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectFalse(bad && !buf_is_hvr(test_ctx.c_buff, test_ctx.c_len));
    ExpectFalse(!bad && buf_is_hvr(test_ctx.c_buff, test_ctx.c_len));
    if (!useticket) {
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, &round_trips), 0);
        ExpectFalse(bad && round_trips != ROUNDS_WITH_HVR - 1);
        ExpectFalse(!bad && round_trips != ROUNDS_WITHOUT_HVR - 1);
    }
    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}

static int test_wolfSSL_dtls_stateless_resume(void)
{
    EXPECT_DECLS;
#ifdef HAVE_SESSION_TICKET
    ExpectIntEQ(_test_wolfSSL_dtls_stateless_resume(1, 0), TEST_SUCCESS);
    ExpectIntEQ(_test_wolfSSL_dtls_stateless_resume(1, 1), TEST_SUCCESS);
#endif /* HAVE_SESION_TICKET */
    ExpectIntEQ(_test_wolfSSL_dtls_stateless_resume(0, 0), TEST_SUCCESS);
    ExpectIntEQ(_test_wolfSSL_dtls_stateless_resume(0, 1), TEST_SUCCESS);
    return EXPECT_RESULT();
}
#endif /* WOLFSSL_DTLS_NO_HVR_ON_RESUME */

#if !defined(NO_OLD_TLS)
static int test_wolfSSL_dtls_stateless_downgrade(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_c2 = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_c2 = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_CTX_SetMinVersion(ctx_s, WOLFSSL_DTLSV1),
        WOLFSSL_SUCCESS);
    ExpectNotNull(ctx_c2 = wolfSSL_CTX_new(wolfDTLSv1_client_method()));
    wolfSSL_SetIORecv(ctx_c2, test_memio_read_cb);
    wolfSSL_SetIOSend(ctx_c2, test_memio_write_cb);
    ExpectNotNull(ssl_c2 = wolfSSL_new(ctx_c2));
    wolfSSL_SetIOWriteCtx(ssl_c2, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_c2, &test_ctx);
    /* send CH */
    ExpectTrue((wolfSSL_connect(ssl_c2) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c2->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectIntNE(test_ctx.c_len, 0);
    /* consume HRR */
    test_ctx.c_len = 0;
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c2);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_c2);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}
#endif /* !defined(NO_OLD_TLS) */

#endif /* defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)*/

#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_OLD_TLS) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
static int test_WOLFSSL_dtls_version_alert(void)
{
    EXPECT_DECLS;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_server_method), 0);

    /* client hello */
    ExpectTrue((wolfSSL_connect(ssl_c) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c->error == WC_NO_ERR_TRACE(WANT_READ)));
    /* hrr */
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    /* client hello 1 */
    ExpectTrue((wolfSSL_connect(ssl_c) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c->error == WC_NO_ERR_TRACE(WANT_READ)));
    /* server hello */
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    /* should fail */
    ExpectTrue((wolfSSL_connect(ssl_c) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c->error == WC_NO_ERR_TRACE(VERSION_ERROR)));
    /* shuould fail */
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(VERSION_ERROR) || ssl_s->error == WC_NO_ERR_TRACE(FATAL_ERROR)));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}
#else
static int test_WOLFSSL_dtls_version_alert(void)
{
    return TEST_SKIPPED;
}
#endif /* defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) &&
        * !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&
        * !defined(NO_OLD_TLS) && !defined(NO_RSA)
        */


#if defined(WOLFSSL_TICKET_NONCE_MALLOC) && defined(HAVE_SESSION_TICKET)       \
    && defined(WOLFSSL_TLS13) &&                                               \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))\
    && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
static int send_new_session_ticket(WOLFSSL *ssl, byte nonceLength, byte filler)
{
    struct test_memio_ctx *test_ctx;
    byte buf[2048];
    int idx, sz;
    word32 tmp;
    int ret;

    idx = 5; /* space for record header */

    buf[idx] = session_ticket; /* type */
    idx++;

    tmp = OPAQUE32_LEN +
        OPAQUE32_LEN +
        OPAQUE8_LEN + nonceLength +
        OPAQUE16_LEN + OPAQUE8_LEN + OPAQUE16_LEN;
    c32to24(tmp, buf + idx);
    idx += OPAQUE24_LEN;

    c32toa((word32)12345, buf+idx); /* lifetime */
    idx += OPAQUE32_LEN;
    c32toa((word32)12345, buf+idx); /* add */
    idx += OPAQUE32_LEN;
    buf[idx] = nonceLength; /* nonce length */
    idx++;
    XMEMSET(&buf[idx], filler, nonceLength); /* nonce */
    idx += nonceLength;
    tmp = 1; /* ticket len */
    c16toa((word16)tmp, buf+idx);
    idx += 2;
    buf[idx] = 0xFF; /* ticket */
    idx++;
    tmp = 0; /* ext len */
    c16toa((word16)tmp, buf+idx);
    idx += 2;

    sz = BuildTls13Message(ssl, buf, 2048, buf+5, idx - 5,
        handshake, 0, 0, 0);
    AssertIntGT(sz, 0);
    test_ctx = (struct test_memio_ctx*)wolfSSL_GetIOWriteCtx(ssl);
    AssertNotNull(test_ctx);
    ret = test_memio_write_cb(ssl, (char*)buf, sz, test_ctx);
    return !(ret == sz);
}

static int test_ticket_nonce_check(WOLFSSL_SESSION *sess, byte len)
{
    int ret = 0;

    if ((sess == NULL) || (sess->ticketNonce.len != len)) {
        ret = -1;
    }
    else {
        int i;
        for (i = 0; i < len; i++) {
            if (sess->ticketNonce.data[i] != len) {
                ret = -1;
                break;
            }
        }
    }

    return ret;
}

static int test_ticket_nonce_malloc_do(WOLFSSL *ssl_s, WOLFSSL *ssl_c, byte len)
{
    EXPECT_DECLS;
    char *buf[1024];

    ExpectIntEQ(send_new_session_ticket(ssl_s, len, len), 0);
    ExpectTrue((wolfSSL_recv(ssl_c, buf, 1024, 0) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c->error == WC_NO_ERR_TRACE(WANT_READ)));

    ExpectIntEQ(test_ticket_nonce_check(ssl_c->session, len), 0);

    return EXPECT_RESULT();
}

static int test_ticket_nonce_cache(WOLFSSL *ssl_s, WOLFSSL *ssl_c, byte len)
{
    EXPECT_DECLS;
    WOLFSSL_SESSION *sess = NULL;
    WOLFSSL_SESSION *cached = NULL;
    WOLFSSL_CTX *ctx = ssl_c->ctx;

    ExpectIntEQ(test_ticket_nonce_malloc_do(ssl_s, ssl_c, len), TEST_SUCCESS);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    ExpectIntEQ(AddSessionToCache(ctx, sess, sess->sessionID, sess->sessionIDSz,
        NULL, ssl_c->options.side, 1,NULL), 0);

    ExpectNotNull(cached = wolfSSL_SESSION_new());

    ExpectIntEQ(wolfSSL_GetSessionFromCache(ssl_c, cached), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_ticket_nonce_check(cached, len), 0);

    wolfSSL_SESSION_free(cached);
    wolfSSL_SESSION_free(sess);

    return EXPECT_RESULT();
}

static int test_ticket_nonce_malloc(void)
{
    EXPECT_DECLS;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    byte small;
    byte medium;
    byte big;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* will send ticket manually */
    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(ssl_s), 0);

    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, 0);

    while (EXPECT_SUCCESS() && (ssl_c->options.handShakeDone == 0) &&
            (ssl_s->options.handShakeDone == 0)) {
        ExpectTrue((wolfSSL_connect(ssl_c) == WOLFSSL_SUCCESS) ||
            (ssl_c->error == WC_NO_ERR_TRACE(WANT_READ)));

        ExpectTrue((wolfSSL_accept(ssl_s) == WOLFSSL_SUCCESS) ||
            (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    }

    small = TLS13_TICKET_NONCE_STATIC_SZ;
#if TLS13_TICKET_NONCE_STATIC_SZ + 20 <= 255
    medium = small + 20;
#else
    medium = 255;
#endif
#if TLS13_TICKET_NONCE_STATIC_SZ + 20 + 20 <= 255
    big = small + 20;
#else
    big = 255;
#endif

    ExpectIntEQ(test_ticket_nonce_malloc_do(ssl_s, ssl_c, small), TEST_SUCCESS);
    ExpectPtrEq(ssl_c->session->ticketNonce.data,
         ssl_c->session->ticketNonce.dataStatic);
    ExpectIntEQ(test_ticket_nonce_malloc_do(ssl_s, ssl_c, medium),
        TEST_SUCCESS);
    ExpectIntEQ(test_ticket_nonce_malloc_do(ssl_s, ssl_c, big), TEST_SUCCESS);
    ExpectIntEQ(test_ticket_nonce_malloc_do(ssl_s, ssl_c, medium),
        TEST_SUCCESS);
    ExpectIntEQ(test_ticket_nonce_malloc_do(ssl_s, ssl_c, small), TEST_SUCCESS);
    ExpectIntEQ(test_ticket_nonce_cache(ssl_s, ssl_c, small), TEST_SUCCESS);
    ExpectIntEQ(test_ticket_nonce_cache(ssl_s, ssl_c, medium), TEST_SUCCESS);
    ExpectIntEQ(test_ticket_nonce_cache(ssl_s, ssl_c, big), TEST_SUCCESS);
    ExpectIntEQ(test_ticket_nonce_cache(ssl_s, ssl_c, medium), TEST_SUCCESS);
    ExpectIntEQ(test_ticket_nonce_cache(ssl_s, ssl_c, small), TEST_SUCCESS);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}

#endif /* WOLFSSL_TICKET_NONCE_MALLOC */

#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(WOLFSSL_TICKET_DECRYPT_NO_CREATE) &&                 \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && !defined(NO_RSA) && \
    defined(HAVE_ECC) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)

static int test_ticket_ret_create(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    byte ticket[SESSION_TICKET_LEN];
    struct test_memio_ctx test_ctx;
    WOLFSSL_SESSION *sess = NULL;
    word16 ticketLen = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, 0);
    ExpectIntEQ(wolfSSL_CTX_UseSessionTicket(ctx_c), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));
    ExpectIntLE(sess->ticketLen, SESSION_TICKET_LEN);
    if (sess != NULL) {
        ticketLen = sess->ticketLen;
        XMEMCPY(ticket, sess->ticket, sess->ticketLen);
    }
    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;

    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);

    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntLE(ssl_c->session->ticketLen, SESSION_TICKET_LEN);
    ExpectIntEQ(ssl_c->session->ticketLen, ticketLen);
    ExpectTrue(XMEMCMP(ssl_c->session->ticket, ticket, ticketLen) != 0);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}
#else
static int test_ticket_ret_create(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_TLS13) && !defined(NO_PSK) && \
    defined(HAVE_SESSION_TICKET) && defined(OPENSSL_EXTRA) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_AESGCM) && \
    !defined(NO_SHA256) && defined(WOLFSSL_AES_128) && \
    defined(WOLFSSL_SHA384) && defined(WOLFSSL_AES_256)
static void test_ticket_and_psk_mixing_on_result(WOLFSSL* ssl)
{
    int ret;
    WOLFSSL_SESSION* session = NULL;

    AssertIntEQ(wolfSSL_get_current_cipher_suite(ssl), 0x1301);
    if (!wolfSSL_is_server(ssl)) {
        session = wolfSSL_SESSION_dup(wolfSSL_get_session(ssl));
        AssertNotNull(session);
    }
    do {
        ret = wolfSSL_shutdown(ssl);
    } while (ret == WOLFSSL_SHUTDOWN_NOT_DONE);
    AssertIntEQ(wolfSSL_clear(ssl), WOLFSSL_SUCCESS);
    wolfSSL_set_psk_callback_ctx(ssl, (void*)"TLS13-AES256-GCM-SHA384");
#ifndef OPENSSL_COMPATIBLE_DEFAULTS
    /* OpenSSL considers PSK to be verified. We error out with NO_PEER_CERT. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);
#endif

    if (!wolfSSL_is_server(ssl)) {
        /* client */
        AssertIntEQ(wolfSSL_set_cipher_list(ssl, "TLS13-AES256-GCM-SHA384:"
                "TLS13-AES128-GCM-SHA256"), WOLFSSL_SUCCESS);
        wolfSSL_set_session(ssl, session);
        wolfSSL_SESSION_free(session);
        wolfSSL_set_psk_client_tls13_callback(ssl, my_psk_client_tls13_cb);
        AssertIntEQ(wolfSSL_connect(ssl), WOLFSSL_SUCCESS);
    }
    else {
        /* server */
        /* Different ciphersuite so that the ticket will be invalidated based on
         * the ciphersuite */
        AssertIntEQ(wolfSSL_set_cipher_list(ssl, "TLS13-AES256-GCM-SHA384"),
            WOLFSSL_SUCCESS);
        wolfSSL_set_psk_server_tls13_callback(ssl, my_psk_server_tls13_cb);
        AssertIntEQ(wolfSSL_accept(ssl), WOLFSSL_SUCCESS);
    }
}

static void test_ticket_and_psk_mixing_ssl_ready(WOLFSSL* ssl)
{
    AssertIntEQ(wolfSSL_UseSessionTicket(ssl), WOLFSSL_SUCCESS);
    AssertIntEQ(wolfSSL_set_cipher_list(ssl, "TLS13-AES128-GCM-SHA256"),
        WOLFSSL_SUCCESS);
}

static int test_ticket_and_psk_mixing(void)
{
    EXPECT_DECLS;
    /* Test mixing tickets and regular PSK */
    callback_functions client_cbs, server_cbs;

    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));

    client_cbs.method = wolfTLSv1_3_client_method;
    server_cbs.method = wolfTLSv1_3_server_method;

    client_cbs.ssl_ready = test_ticket_and_psk_mixing_ssl_ready;

    client_cbs.on_result = test_ticket_and_psk_mixing_on_result;
    server_cbs.on_result = test_ticket_and_psk_mixing_on_result;

    test_wolfSSL_client_server_nofail(&client_cbs, &server_cbs);

    ExpectIntEQ(client_cbs.return_code, TEST_SUCCESS);
    ExpectIntEQ(server_cbs.return_code, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
static int test_ticket_and_psk_mixing(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_TLS13) && !defined(NO_PSK) && defined(HAVE_SESSION_TICKET) \
    && defined(OPENSSL_EXTRA) && defined(HAVE_IO_TESTS_DEPENDENCIES) && \
    defined(HAVE_AESGCM) && !defined(NO_SHA256) && defined(WOLFSSL_AES_128) && \
    defined(WOLFSSL_SHA384) && defined(WOLFSSL_AES_256)
static int test_prioritize_psk_cb_called = FALSE;

static unsigned int test_prioritize_psk_cb(WOLFSSL* ssl,
        const char* identity, unsigned char* key, unsigned int key_max_len,
        const char** ciphersuite)
{
    test_prioritize_psk_cb_called = TRUE;
    return my_psk_server_tls13_cb(ssl, identity, key, key_max_len, ciphersuite);
}

static void test_prioritize_psk_on_result(WOLFSSL* ssl)
{
    int ret;
    WOLFSSL_SESSION* session = NULL;
    AssertIntEQ(wolfSSL_get_current_cipher_suite(ssl), 0x1301);
    if (!wolfSSL_is_server(ssl)) {
        session = wolfSSL_SESSION_dup(wolfSSL_get_session(ssl));
        AssertNotNull(session);
    }
    do {
        ret = wolfSSL_shutdown(ssl);
    } while (ret == WOLFSSL_SHUTDOWN_NOT_DONE);
    AssertIntEQ(wolfSSL_clear(ssl), WOLFSSL_SUCCESS);
    wolfSSL_set_psk_callback_ctx(ssl, (void*)"TLS13-AES256-GCM-SHA384");
    /* Previous connection was made with TLS13-AES128-GCM-SHA256. Order is
     * important. */
    AssertIntEQ(wolfSSL_set_cipher_list(ssl, "TLS13-AES256-GCM-SHA384:"
            "TLS13-AES128-GCM-SHA256"), WOLFSSL_SUCCESS);
#ifndef OPENSSL_COMPATIBLE_DEFAULTS
    /* OpenSSL considers PSK to be verified. We error out with NO_PEER_CERT. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);
#endif

    if (!wolfSSL_is_server(ssl)) {
        /* client */
        wolfSSL_set_psk_client_tls13_callback(ssl, my_psk_client_tls13_cb);
        wolfSSL_set_session(ssl, session);
        wolfSSL_SESSION_free(session);
        AssertIntEQ(wolfSSL_connect(ssl), WOLFSSL_SUCCESS);
    }
    else {
        /* server */
        wolfSSL_set_psk_server_tls13_callback(ssl, test_prioritize_psk_cb);
        AssertIntEQ(wolfSSL_accept(ssl), WOLFSSL_SUCCESS);
#ifdef WOLFSSL_PRIORITIZE_PSK
        /* The ticket should be first tried with all ciphersuites and chosen */
        AssertFalse(test_prioritize_psk_cb_called);
#else
        /* Ciphersuites should be tried with each PSK. This triggers the PSK
         * callback that sets this var. */
        AssertTrue(test_prioritize_psk_cb_called);
#endif
    }
}

static void test_prioritize_psk_ssl_ready(WOLFSSL* ssl)
{
    if (!wolfSSL_is_server(ssl))
        AssertIntEQ(wolfSSL_set_cipher_list(ssl, "TLS13-AES128-GCM-SHA256"),
                WOLFSSL_SUCCESS);
    else
        AssertIntEQ(wolfSSL_set_cipher_list(ssl, "TLS13-AES256-GCM-SHA384:"
                "TLS13-AES128-GCM-SHA256"), WOLFSSL_SUCCESS);
}

static int test_prioritize_psk(void)
{
    EXPECT_DECLS;
    /* We always send the ticket first. With WOLFSSL_PRIORITIZE_PSK the order
     * of the PSK's will be followed instead of the ciphersuite. */
    callback_functions client_cbs, server_cbs;

    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));

    client_cbs.method = wolfTLSv1_3_client_method;
    server_cbs.method = wolfTLSv1_3_server_method;

    client_cbs.ssl_ready = test_prioritize_psk_ssl_ready;
    server_cbs.ssl_ready = test_prioritize_psk_ssl_ready;

    client_cbs.on_result = test_prioritize_psk_on_result;
    server_cbs.on_result = test_prioritize_psk_on_result;

    test_wolfSSL_client_server_nofail(&client_cbs, &server_cbs);

    ExpectIntEQ(client_cbs.return_code, TEST_SUCCESS);
    ExpectIntEQ(server_cbs.return_code, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
static int test_prioritize_psk(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_TLS13) && defined(OPENSSL_EXTRA) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && defined(HAVE_AESGCM) && \
    !defined(NO_SHA256) && defined(WOLFSSL_AES_128) && \
    !defined(WOLFSSL_NO_TLS12)
static int test_wolfSSL_CTX_set_ciphersuites_ctx_ready_server(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectTrue(SSL_CTX_set_cipher_list(ctx, "DEFAULT"));
    /* Set TLS 1.3 specific suite */
    ExpectTrue(SSL_CTX_set_ciphersuites(ctx, "TLS13-AES128-GCM-SHA256"));
    return EXPECT_RESULT();
}

static int test_wolfSSL_CTX_set_ciphersuites(void)
{
    EXPECT_DECLS;
    /* Test using SSL_CTX_set_cipher_list and SSL_CTX_set_ciphersuites and then
     * do a 1.2 connection. */
    test_ssl_cbf client_cbs, server_cbs;

    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));

    client_cbs.method = wolfTLSv1_2_client_method;
    server_cbs.method = wolfTLS_server_method; /* Allow downgrade */

    server_cbs.ctx_ready = test_wolfSSL_CTX_set_ciphersuites_ctx_ready_server;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbs,
        &server_cbs, NULL), TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
static int test_wolfSSL_CTX_set_ciphersuites(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_CRL) && defined(WOLFSSL_CHECK_ALERT_ON_ERR) && \
        defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
static int test_wolfSSL_CRL_CERT_REVOKED_alert_ctx_ready(WOLFSSL_CTX* ctx)
{
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    return TEST_SUCCESS;
}

static int test_wolfSSL_CRL_CERT_REVOKED_alert_on_cleanup(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    WOLFSSL_ALERT_HISTORY h;
    ExpectIntEQ(wolfSSL_get_alert_history(ssl, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_rx.level, alert_fatal);
    ExpectIntEQ(h.last_rx.code, certificate_revoked);
    return EXPECT_RESULT();
}

static int test_wolfSSL_CRL_CERT_REVOKED_alert(void)
{
    EXPECT_DECLS;
    test_ssl_cbf client_cbs, server_cbs;

    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));

    server_cbs.certPemFile = "./certs/server-revoked-cert.pem";
    server_cbs.keyPemFile = "./certs/server-revoked-key.pem";
    client_cbs.crlPemFile = "./certs/crl/crl.revoked";

    client_cbs.ctx_ready = test_wolfSSL_CRL_CERT_REVOKED_alert_ctx_ready;
    server_cbs.on_cleanup = test_wolfSSL_CRL_CERT_REVOKED_alert_on_cleanup;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbs,
        &server_cbs, NULL), -1001);

    return EXPECT_RESULT();
}
#else
static int test_wolfSSL_CRL_CERT_REVOKED_alert(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET) \
    && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && defined(HAVE_AESGCM) && \
    !defined(NO_SHA256) && defined(WOLFSSL_AES_128) && \
    defined(WOLFSSL_SHA384) && defined(WOLFSSL_AES_256) && \
    !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB)

static WOLFSSL_CTX* test_TLS_13_ticket_different_ciphers_ctx = NULL;
static WOLFSSL_SESSION* test_TLS_13_ticket_different_ciphers_session = NULL;
static int test_TLS_13_ticket_different_ciphers_run = 0;

static int test_TLS_13_ticket_different_ciphers_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    switch (test_TLS_13_ticket_different_ciphers_run) {
        case 0:
            /* First run */
            ExpectIntEQ(wolfSSL_set_cipher_list(ssl, "TLS13-AES128-GCM-SHA256"),
                WOLFSSL_SUCCESS);
            if (wolfSSL_is_server(ssl)) {
                ExpectNotNull(test_TLS_13_ticket_different_ciphers_ctx =
                    wolfSSL_get_SSL_CTX(ssl));
                ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_up_ref(
                    test_TLS_13_ticket_different_ciphers_ctx));
            }
            break;
        case 1:
            /* Second run */
            ExpectIntEQ(wolfSSL_set_cipher_list(ssl, "TLS13-AES256-GCM-SHA384:"
                                                     "TLS13-AES128-GCM-SHA256"),
                            WOLFSSL_SUCCESS);
            if (!wolfSSL_is_server(ssl)) {
                ExpectIntEQ(wolfSSL_set_session(ssl,
                    test_TLS_13_ticket_different_ciphers_session),
                    WOLFSSL_SUCCESS);
            }
            break;
        default:
            /* Bad state? */
            Fail(("Should not enter here"), ("Should not enter here"));
    }

    return EXPECT_RESULT();
}

static int test_TLS_13_ticket_different_ciphers_on_result(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    switch (test_TLS_13_ticket_different_ciphers_run) {
        case 0:
            /* First run */
            ExpectNotNull(test_TLS_13_ticket_different_ciphers_session =
                    wolfSSL_get1_session(ssl));
            break;
        case 1:
            /* Second run */
            ExpectTrue(wolfSSL_session_reused(ssl));
            break;
        default:
            /* Bad state? */
            Fail(("Should not enter here"), ("Should not enter here"));
    }
    return EXPECT_RESULT();
}

static int test_TLS_13_ticket_different_ciphers(void)
{
    EXPECT_DECLS;
    /* Check that we handle the connection when the ticket doesn't match
     * the first ciphersuite. */
    test_ssl_cbf client_cbs, server_cbs;
    struct test_params {
        method_provider client_meth;
        method_provider server_meth;
        int doUdp;
    } params[] = {
#ifdef WOLFSSL_DTLS13
        /* Test that the stateless code handles sessions correctly */
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, 1},
#endif
        {wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, 0},
    };
    size_t i;

    for (i = 0; i < sizeof(params)/sizeof(*params); i++) {
        XMEMSET(&client_cbs, 0, sizeof(client_cbs));
        XMEMSET(&server_cbs, 0, sizeof(server_cbs));

        test_TLS_13_ticket_different_ciphers_run = 0;

        client_cbs.doUdp = server_cbs.doUdp = params[i].doUdp;

        client_cbs.method = params[i].client_meth;
        server_cbs.method = params[i].server_meth;

        client_cbs.ssl_ready = test_TLS_13_ticket_different_ciphers_ssl_ready;
        server_cbs.ssl_ready = test_TLS_13_ticket_different_ciphers_ssl_ready;

        client_cbs.on_result = test_TLS_13_ticket_different_ciphers_on_result;

        server_cbs.ticNoInit = 1;

        ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbs,
            &server_cbs, NULL), TEST_SUCCESS);

        test_TLS_13_ticket_different_ciphers_run++;

        server_cbs.ctx = test_TLS_13_ticket_different_ciphers_ctx;

        ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbs,
            &server_cbs, NULL), TEST_SUCCESS);

        wolfSSL_SESSION_free(test_TLS_13_ticket_different_ciphers_session);
        test_TLS_13_ticket_different_ciphers_session = NULL;
        wolfSSL_CTX_free(test_TLS_13_ticket_different_ciphers_ctx);
        test_TLS_13_ticket_different_ciphers_ctx = NULL;
    }

    return EXPECT_RESULT();
}
#else
static int test_TLS_13_ticket_different_ciphers(void)
{
    return TEST_SKIPPED;
}
#endif
#if defined(WOLFSSL_EXTRA_ALERTS) && !defined(WOLFSSL_NO_TLS12) &&             \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)

#define TEST_WRONG_CS_CLIENT "DHE-RSA-AES128-SHA"
/* AKA TLS_DHE_RSA_WITH_AES_128_CBC_SHA */

byte test_extra_alerts_wrong_cs_sh[] = {
  0x16, 0x03, 0x03, 0x00, 0x56, 0x02, 0x00, 0x00, 0x52, 0x03, 0x03, 0xef,
  0x0c, 0x30, 0x98, 0xa2, 0xac, 0xfa, 0x68, 0xe9, 0x3e, 0xaa, 0x5c, 0xcf,
  0xa7, 0x42, 0x72, 0xaf, 0xa0, 0xe8, 0x39, 0x2b, 0x3e, 0x81, 0xa7, 0x7a,
  0xa5, 0x62, 0x8a, 0x0e, 0x41, 0xba, 0xda, 0x20, 0x18, 0x9f, 0xe1, 0x8c,
  0x1d, 0xc0, 0x37, 0x9c, 0xf4, 0x90, 0x5d, 0x8d, 0xa0, 0x79, 0xa7, 0x4b,
  0xa8, 0x79, 0xdf, 0xcd, 0x8d, 0xf5, 0xb5, 0x50, 0x5f, 0xf1, 0xdb, 0x4d,
  0xbb, 0x07, 0x54, 0x1c,
  0x00, 0x02, /* TLS_RSA_WITH_NULL_SHA */
  0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00,
  0x02, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00
};

static int test_extra_alerts_wrong_cs(void)
{
    EXPECT_DECLS;
#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_ALERT_HISTORY h;
    WOLFSSL *ssl_c = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
        wolfTLSv1_2_client_method, NULL), 0);

    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, TEST_WRONG_CS_CLIENT),
        WOLFSSL_SUCCESS);

    /* CH */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* consume CH */
    test_ctx.s_len = 0;
    /* inject SH */
    XMEMCPY(test_ctx.c_buff, test_extra_alerts_wrong_cs_sh,
        sizeof(test_extra_alerts_wrong_cs_sh));
    test_ctx.c_len = sizeof(test_extra_alerts_wrong_cs_sh);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_tx.code, handshake_failure);
    ExpectIntEQ(h.last_tx.level, alert_fatal);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}
#else
static int test_extra_alerts_wrong_cs(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_TLS12) &&   \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)

#define TEST_CS_DOWNGRADE_CLIENT "ECDHE-RSA-AES256-GCM-SHA384"

byte test_wrong_cs_downgrade_sh[] = {
  0x16, 0x03, 0x03, 0x00, 0x56, 0x02, 0x00, 0x00, 0x52, 0x03, 0x03, 0x10,
  0x2c, 0x88, 0xd9, 0x7a, 0x23, 0xc9, 0xbd, 0x11, 0x3b, 0x64, 0x24, 0xab,
  0x5b, 0x45, 0x33, 0xf6, 0x2c, 0x34, 0xe4, 0xcf, 0xf4, 0x78, 0xc8, 0x62,
  0x06, 0xc7, 0xe5, 0x30, 0x39, 0xbf, 0xa1, 0x20, 0xa3, 0x06, 0x74, 0xc3,
  0xa9, 0x74, 0x52, 0x8a, 0xfb, 0xae, 0xf0, 0xd8, 0x6f, 0xb2, 0x9d, 0xfe,
  0x78, 0xf0, 0x3f, 0x51, 0x8f, 0x9c, 0xcf, 0xbe, 0x61, 0x43, 0x9d, 0xf8,
  0x85, 0xe5, 0x2f, 0x54,
  0xc0, 0x2f, /* ECDHE-RSA-AES128-GCM-SHA256 */
  0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00,
  0x02, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00
};

static int test_wrong_cs_downgrade(void)
{
    EXPECT_DECLS;
#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL *ssl_c = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
        wolfSSLv23_client_method, NULL), 0);

    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, TEST_CS_DOWNGRADE_CLIENT),
        WOLFSSL_SUCCESS);

    /* CH */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* consume CH */
    test_ctx.s_len = 0;
    /* inject SH */
    XMEMCPY(test_ctx.c_buff, test_wrong_cs_downgrade_sh,
        sizeof(test_wrong_cs_downgrade_sh));
    test_ctx.c_len = sizeof(test_wrong_cs_downgrade_sh);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
#ifdef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(WOLFSSL_ERROR_SYSCALL));
#else
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(MATCH_SUITE_ERROR));
#endif /* OPENSSL_EXTRA */


    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}
#else
static int test_wrong_cs_downgrade(void)
{
    return TEST_SKIPPED;
}
#endif

#if !defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_EXTRA_ALERTS) &&             \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_SP_MATH)

static void test_remove_msg(byte *msg, int tail_len, int *len, int msg_length)
{
    tail_len -= msg_length;
    XMEMMOVE(msg, msg + msg_length, tail_len);
    *len = *len - msg_length;
}

static int test_remove_hs_msg_from_buffer(byte *buf, int *len, byte type,
    byte *found)
{
    const unsigned int  _HANDSHAKE_HEADER_SZ = 4;
    const unsigned int _RECORD_HEADER_SZ = 5;
    const int _change_cipher_hs = 55;
    const int _change_cipher = 20;
    const int _handshake = 22;
    unsigned int tail_len;
    byte *idx, *curr;
    word8 currType;
    word16 rLength;
    word32 hLength;

    idx = buf;
    tail_len = (unsigned int)*len;
    *found = 0;
    while (tail_len > _RECORD_HEADER_SZ) {
        curr = idx;
        currType = *idx;
        ato16(idx + 3, &rLength);
        idx += _RECORD_HEADER_SZ;
        tail_len -= _RECORD_HEADER_SZ;

        if (tail_len < rLength)
            return -1;

        if (type == _change_cipher_hs && currType == _change_cipher) {
            if (rLength != 1)
                return -1;
            /* match */
            test_remove_msg(curr, *len - (int)(curr - buf),
                len, _RECORD_HEADER_SZ + 1);
            *found = 1;
            return 0;
        }

        if (currType != _handshake) {
            idx += rLength;
            tail_len -= rLength;
            continue;
        }

        if (rLength < _HANDSHAKE_HEADER_SZ)
            return -1;
        currType = *idx;
        ato24(idx+1, &hLength);
        hLength += _HANDSHAKE_HEADER_SZ;
        if (tail_len < hLength)
            return -1;
        if (currType != type) {
            idx += hLength;
            tail_len -= hLength;
            continue;
        }

        /* match */
        test_remove_msg(curr, *len - (int)(curr - buf), len,
            hLength + _RECORD_HEADER_SZ);
        *found = 1;
        return 0;
    }

    /* not found */
    return 0;
}

static int test_remove_hs_message(byte hs_message_type,
    int extra_round, byte alert_type)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_ALERT_HISTORY h;
    byte found = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    if (extra_round) {
        ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
            WOLFSSL_ERROR_WANT_READ);

        /* this will complete handshake from server side */
        ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    }

    ExpectIntEQ(test_remove_hs_msg_from_buffer(test_ctx.c_buff,
         &test_ctx.c_len, hs_message_type, &found), 0);

    if (!found) {
        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_s);
        return TEST_SKIPPED;
    }

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &h), WOLFSSL_SUCCESS);
    ExpectTrue(alert_type == 0xff || h.last_tx.code == alert_type);
    ExpectIntEQ(h.last_tx.level, alert_fatal);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}

static int test_extra_alerts_skip_hs(void)
{
    EXPECT_DECLS;
    const byte _server_key_exchange = 12;
    const byte _server_hello = 2;
    const byte _certificate = 11;

    /* server_hello */
    ExpectIntNE(test_remove_hs_message(_server_hello, 0,
        unexpected_message), TEST_FAIL);
    ExpectIntNE(test_remove_hs_message(_certificate, 0,
        0xff), TEST_FAIL);
    ExpectIntNE(test_remove_hs_message(_server_key_exchange, 0,
        unexpected_message), TEST_FAIL);

    return EXPECT_RESULT();
}
#else
static int test_extra_alerts_skip_hs(void)
{
    return TEST_SKIPPED;
}
#endif

#if !defined(WOLFSSL_NO_TLS12) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)\
    && defined(WOLFSSL_EXTRA_ALERTS) && !defined(NO_PSK) && !defined(NO_DH)

static unsigned int test_server_psk_cb(WOLFSSL* ssl, const char* id,
    unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)id;
    (void)key_max_len;
    /* zero means error */
    key[0] = 0x10;
    return 1;
}

static int test_extra_alerts_bad_psk(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_ALERT_HISTORY h;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, "DHE-PSK-AES128-GCM-SHA256"),
        WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, "DHE-PSK-AES128-GCM-SHA256"),
        WOLFSSL_SUCCESS);

    wolfSSL_set_psk_server_callback(ssl_s, test_server_psk_cb);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_tx.code, handshake_failure);
    ExpectIntEQ(h.last_tx.level, alert_fatal);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}
#else
static int test_extra_alerts_bad_psk(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
/*
 * Emulates wolfSSL_shutdown that goes on EAGAIN,
 * by returning on output WOLFSSL_ERROR_WANT_WRITE.*/
static int custom_wolfSSL_shutdown(WOLFSSL *ssl, char *buf,
        int sz, void *ctx)
{
    (void)ssl;
    (void)buf;
    (void)ctx;
    (void)sz;

    return WOLFSSL_CBIO_ERR_WANT_WRITE;
}

static int test_multiple_alerts_EAGAIN(void)
{
    EXPECT_DECLS;
    size_t size_of_last_packet = 0;

    /* declare wolfSSL objects */
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Create and initialize WOLFSSL_CTX and WOLFSSL objects */
#ifdef USE_TLSV13
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
          wolfTLSv1_3_client_method,  wolfTLSv1_3_server_method), 0);
#else
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
         wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
#endif
    ExpectNotNull(ctx_c);
    ExpectNotNull(ssl_c);
    ExpectNotNull(ctx_s);
    ExpectNotNull(ssl_s);

    /* Load client certificates into WOLFSSL_CTX */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_c, "./certs/ca-cert.pem", NULL), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /*
     * We set the custom callback for the IO to emulate multiple EAGAINs
     * on shutdown, so we can check that we don't send multiple packets.
     * */
    wolfSSL_SSLSetIOSend(ssl_c, custom_wolfSSL_shutdown);

    /*
     * We call wolfSSL_shutdown multiple times to reproduce the behaviour,
     * to check that it doesn't add the CLOSE_NOTIFY packet multiple times
     * on the output buffer.
     * */
    wolfSSL_shutdown(ssl_c);
    wolfSSL_shutdown(ssl_c);

    if (ssl_c != NULL) {
        size_of_last_packet = ssl_c->buffers.outputBuffer.length;
    }
    wolfSSL_shutdown(ssl_c);

    /*
     * Finally we check the length of the output buffer.
     * */
    ExpectIntEQ((ssl_c->buffers.outputBuffer.length - size_of_last_packet), 0);

    /* Cleanup and return */
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_free(ssl_s);

    return EXPECT_RESULT();
}
#else
static int test_multiple_alerts_EAGAIN(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)\
    && !defined(NO_PSK)
static unsigned int test_tls13_bad_psk_binder_client_cb(WOLFSSL* ssl,
        const char* hint, char* identity, unsigned int id_max_len,
        unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;
    (void)key_max_len;

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    XSTRNCPY(identity, "Client_identity", id_max_len);

    key[0] = 0x20;
    return 1;
}

static unsigned int test_tls13_bad_psk_binder_server_cb(WOLFSSL* ssl,
        const char* id, unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)id;
    (void)key_max_len;
    /* zero means error */
    key[0] = 0x10;
    return 1;
}
#endif

static int test_tls13_bad_psk_binder(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)\
    && !defined(NO_PSK)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_ALERT_HISTORY h;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_bad_psk_binder_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_bad_psk_binder_server_cb);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ( wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(BAD_BINDER));

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_rx.code, illegal_parameter);
    ExpectIntEQ(h.last_rx.level, alert_fatal);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_HARDEN_TLS) && !defined(WOLFSSL_NO_TLS12) && \
        defined(HAVE_IO_TESTS_DEPENDENCIES)
static int test_harden_no_secure_renegotiation_io_cb(WOLFSSL *ssl, char *buf,
        int sz, void *ctx)
{
    static int sentServerHello = FALSE;

    if (!sentServerHello) {
        byte renegExt[] = { 0xFF, 0x01, 0x00, 0x01, 0x00 };
        size_t i;

        if (sz < (int)sizeof(renegExt))
            return WOLFSSL_CBIO_ERR_GENERAL;

        /* Remove SCR from ServerHello */
        for (i = 0; i < sz - sizeof(renegExt); i++) {
            if (XMEMCMP(buf + i, renegExt, sizeof(renegExt)) == 0) {
                /* Found the extension. Change it to something unrecognized. */
                buf[i+1] = 0x11;
                break;
            }
        }
        sentServerHello = TRUE;
    }

    return EmbedSend(ssl, buf, sz, ctx);
}

static void test_harden_no_secure_renegotiation_ssl_ready(WOLFSSL* ssl)
{
    wolfSSL_SSLSetIOSend(ssl, test_harden_no_secure_renegotiation_io_cb);
}

static void test_harden_no_secure_renegotiation_on_cleanup(WOLFSSL* ssl)
{
    WOLFSSL_ALERT_HISTORY h;
    AssertIntEQ(wolfSSL_get_alert_history(ssl, &h), WOLFSSL_SUCCESS);
    AssertIntEQ(h.last_rx.code, handshake_failure);
    AssertIntEQ(h.last_rx.level, alert_fatal);
}

static int test_harden_no_secure_renegotiation(void)
{
    EXPECT_DECLS;
    callback_functions client_cbs, server_cbs;

    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));

    client_cbs.method = wolfTLSv1_2_client_method;
    server_cbs.method = wolfTLSv1_2_server_method;

    server_cbs.ssl_ready = test_harden_no_secure_renegotiation_ssl_ready;
    server_cbs.on_cleanup = test_harden_no_secure_renegotiation_on_cleanup;
    test_wolfSSL_client_server_nofail(&client_cbs, &server_cbs);

    ExpectIntEQ(client_cbs.return_code, TEST_FAIL);
    ExpectIntEQ(client_cbs.last_err, WC_NO_ERR_TRACE(SECURE_RENEGOTIATION_E));
    ExpectIntEQ(server_cbs.return_code, TEST_FAIL);
    ExpectTrue(server_cbs.last_err == WC_NO_ERR_TRACE(SOCKET_ERROR_E) ||
               server_cbs.last_err == WC_NO_ERR_TRACE(FATAL_ERROR));

    return EXPECT_RESULT();
}
#else
static int test_harden_no_secure_renegotiation(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_OCSP) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
static int test_override_alt_cert_chain_cert_cb(int preverify,
        WOLFSSL_X509_STORE_CTX* store)
{
    fprintf(stderr, "preverify: %d\n", preverify);
    fprintf(stderr, "store->error: %d\n", store->error);
    fprintf(stderr, "error reason: %s\n", wolfSSL_ERR_reason_error_string(store->error));
    if (store->error == WC_NO_ERR_TRACE(OCSP_INVALID_STATUS)) {
        fprintf(stderr, "Overriding OCSP error\n");
        return 1;
    }
#ifndef WOLFSSL_ALT_CERT_CHAINS
    else if ((store->error == WC_NO_ERR_TRACE(ASN_NO_SIGNER_E) ||
              store->error == WC_NO_ERR_TRACE(ASN_SELF_SIGNED_E)
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(HAVE_WEBSERVER)
            || store->error == WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
#endif
            ) && store->error_depth == store->totalCerts - 1) {
        fprintf(stderr, "Overriding no signer error only for root cert\n");
        return 1;
    }
#endif
    else
        return preverify;
}

static int test_override_alt_cert_chain_ocsp_cb(void* ioCtx, const char* url,
        int urlSz, unsigned char* request, int requestSz,
        unsigned char** response)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)request;
    (void)requestSz;
    (void)response;
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static int test_override_alt_cert_chain_client_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER,
            test_override_alt_cert_chain_cert_cb);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL |
            WOLFSSL_OCSP_URL_OVERRIDE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
            test_override_alt_cert_chain_ocsp_cb, NULL, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "not a url"),
            WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

static int test_override_alt_cert_chain_client_ctx_ready2(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL |
            WOLFSSL_OCSP_URL_OVERRIDE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
            test_override_alt_cert_chain_ocsp_cb, NULL, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "not a url"),
            WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

static int test_override_alt_cert_chain_server_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_CTX_use_certificate_chain_file(ctx,
            "./certs/intermediate/server-chain-alt.pem"), WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

static int test_override_alt_cert_chain(void)
{
    EXPECT_DECLS;
    size_t i;
    struct test_params {
        ctx_cb client_ctx_cb;
        ctx_cb server_ctx_cb;
        int result;
    } params[] = {
        {test_override_alt_cert_chain_client_ctx_ready,
                test_override_alt_cert_chain_server_ctx_ready, TEST_SUCCESS},
        {test_override_alt_cert_chain_client_ctx_ready2,
                test_override_alt_cert_chain_server_ctx_ready, -1001},
    };

    for (i = 0; i < sizeof(params)/sizeof(*params); i++) {
        test_ssl_cbf client_cbs, server_cbs;
        XMEMSET(&client_cbs, 0, sizeof(client_cbs));
        XMEMSET(&server_cbs, 0, sizeof(server_cbs));

        fprintf(stderr, "test config: %d\n", (int)i);

        client_cbs.ctx_ready = params[i].client_ctx_cb;
        server_cbs.ctx_ready = params[i].server_ctx_cb;

        ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbs,
            &server_cbs, NULL), params[i].result);

        ExpectIntEQ(client_cbs.return_code,
                    params[i].result <= 0 ? -1000 : TEST_SUCCESS);
        ExpectIntEQ(server_cbs.return_code,
                    params[i].result <= 0 ? -1000 : TEST_SUCCESS);
    }

    return EXPECT_RESULT();
}
#else
static int test_override_alt_cert_chain(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_RPK) && !defined(NO_TLS)

#define svrRpkCertFile     "./certs/rpk/server-cert-rpk.der"
#define clntRpkCertFile    "./certs/rpk/client-cert-rpk.der"

#if defined(WOLFSSL_ALWAYS_VERIFY_CB) && defined(WOLFSSL_TLS13)
static int MyRpkVerifyCb(int mode, WOLFSSL_X509_STORE_CTX* strctx)
{
    int ret = WOLFSSL_SUCCESS;
    (void)mode;
    (void)strctx;
    WOLFSSL_ENTER("MyRpkVerifyCb");
    return ret;
}
#endif /* WOLFSSL_ALWAYS_VERIFY_CB && WOLFSSL_TLS13 */

static WC_INLINE int test_rpk_memio_setup(
    struct test_memio_ctx *ctx,
    WOLFSSL_CTX **ctx_c,
    WOLFSSL_CTX **ctx_s,
    WOLFSSL **ssl_c,
    WOLFSSL **ssl_s,
    method_provider method_c,
    method_provider method_s,
    const char* certfile_c, int fmt_cc, /* client cert file path and format */
    const char* certfile_s, int fmt_cs, /* server cert file path and format */
    const char* pkey_c,     int fmt_kc, /* client private key and format */
    const char* pkey_s,     int fmt_ks  /* server private key and format */
    )
{
    int ret;
    if (ctx_c != NULL && *ctx_c == NULL) {
        *ctx_c = wolfSSL_CTX_new(method_c());
        if (*ctx_c == NULL) {
            return -1;
        }
        wolfSSL_CTX_set_verify(*ctx_c, WOLFSSL_VERIFY_PEER, NULL);

        ret = wolfSSL_CTX_load_verify_locations(*ctx_c, caCertFile, 0);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }
        wolfSSL_SetIORecv(*ctx_c, test_memio_read_cb);
        wolfSSL_SetIOSend(*ctx_c, test_memio_write_cb);

        ret = wolfSSL_CTX_use_certificate_file(*ctx_c, certfile_c, fmt_cc);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }
        ret = wolfSSL_CTX_use_PrivateKey_file(*ctx_c, pkey_c, fmt_kc);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }
    }

    if (ctx_s != NULL && *ctx_s == NULL) {
        *ctx_s = wolfSSL_CTX_new(method_s());
        if (*ctx_s == NULL) {
            return -1;
        }
        wolfSSL_CTX_set_verify(*ctx_s, WOLFSSL_VERIFY_PEER, NULL);

        ret = wolfSSL_CTX_load_verify_locations(*ctx_s, cliCertFile, 0);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }

        ret = wolfSSL_CTX_use_PrivateKey_file(*ctx_s, pkey_s, fmt_ks);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }
        ret = wolfSSL_CTX_use_certificate_file(*ctx_s, certfile_s, fmt_cs);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }
        wolfSSL_SetIORecv(*ctx_s, test_memio_read_cb);
        wolfSSL_SetIOSend(*ctx_s, test_memio_write_cb);
        if (ctx->s_ciphers != NULL) {
            ret = wolfSSL_CTX_set_cipher_list(*ctx_s, ctx->s_ciphers);
            if (ret != WOLFSSL_SUCCESS) {
                return -1;
            }
        }
    }

    if (ctx_c != NULL && ssl_c != NULL) {
        *ssl_c = wolfSSL_new(*ctx_c);
        if (*ssl_c == NULL) {
            return -1;
        }
        wolfSSL_SetIOWriteCtx(*ssl_c, ctx);
        wolfSSL_SetIOReadCtx(*ssl_c, ctx);
    }
    if (ctx_s != NULL && ssl_s != NULL) {
        *ssl_s = wolfSSL_new(*ctx_s);
        if (*ssl_s == NULL) {
            return -1;
        }
        wolfSSL_SetIOWriteCtx(*ssl_s, ctx);
        wolfSSL_SetIOReadCtx(*ssl_s, ctx);
#if !defined(NO_DH)
        SetDH(*ssl_s);
#endif
    }

    return 0;
}
#endif /* HAVE_RPK && !NO_TLS */

static int test_rpk_set_xxx_cert_type(void)
{
    EXPECT_DECLS;
#if defined(HAVE_RPK) && !defined(NO_TLS)

    char ctype[MAX_CLIENT_CERT_TYPE_CNT + 1];   /* prepare bigger buffer */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int tp;

    ctx = wolfSSL_CTX_new(wolfTLS_client_method());
    ExpectNotNull(ctx);

    ssl = wolfSSL_new(ctx);
    ExpectNotNull(ssl);

    /*--------------------------------------------*/
    /* tests for wolfSSL_CTX_set_client_cert_type */
    /*--------------------------------------------*/

    /* illegal parameter test caces */
    ExpectIntEQ(wolfSSL_CTX_set_client_cert_type(NULL, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_CTX_set_client_cert_type(ctx, ctype,
                                                sizeof(ctype)),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ctype[0] = WOLFSSL_CERT_TYPE_RPK;  /* set an identical cert type */
    ctype[1] = WOLFSSL_CERT_TYPE_RPK;

    ExpectIntEQ(wolfSSL_CTX_set_client_cert_type(ctx, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ctype[0] = WOLFSSL_CERT_TYPE_X509;
    ctype[1] = 10;                      /* set unknown cert type */

    ExpectIntEQ(wolfSSL_CTX_set_client_cert_type(ctx, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* pass larger type count */
    ctype[0] = WOLFSSL_CERT_TYPE_RPK;
    ctype[1] = WOLFSSL_CERT_TYPE_X509;
    ctype[2] = 1;                       /* pass unacceptable type count */

    ExpectIntEQ(wolfSSL_CTX_set_client_cert_type(ctx, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT + 1),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* should accept NULL for type buffer */
    ExpectIntEQ(wolfSSL_CTX_set_client_cert_type(ctx, NULL,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WOLFSSL_SUCCESS);

    /* should accept zero for type count */
    ExpectIntEQ(wolfSSL_CTX_set_client_cert_type(ctx, ctype,
                                                0),
                                                WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_CTX_set_client_cert_type(ctx, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WOLFSSL_SUCCESS);

    /*--------------------------------------------*/
    /* tests for wolfSSL_CTX_set_server_cert_type */
    /*--------------------------------------------*/

    ExpectIntEQ(wolfSSL_CTX_set_server_cert_type(NULL, ctype,
                                                MAX_SERVER_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_CTX_set_server_cert_type(ctx, ctype,
                                                sizeof(ctype)),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ctype[0] = WOLFSSL_CERT_TYPE_RPK;  /* set an identical cert type */
    ctype[1] = WOLFSSL_CERT_TYPE_RPK;

    ExpectIntEQ(wolfSSL_CTX_set_server_cert_type(ctx, ctype,
                                                MAX_SERVER_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ctype[0] = WOLFSSL_CERT_TYPE_X509;
    ctype[1] = 10;                      /* set unknown cert type */

    ExpectIntEQ(wolfSSL_CTX_set_server_cert_type(ctx, ctype,
                                                MAX_SERVER_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* pass larger type count */
    ctype[0] = WOLFSSL_CERT_TYPE_RPK;
    ctype[1] = WOLFSSL_CERT_TYPE_X509;
    ctype[2] = 1;                       /* pass unacceptable type count */

    ExpectIntEQ(wolfSSL_CTX_set_server_cert_type(ctx, ctype,
                                                MAX_SERVER_CERT_TYPE_CNT + 1),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* should accept NULL for type buffer */
    ExpectIntEQ(wolfSSL_CTX_set_server_cert_type(ctx, NULL,
                                                MAX_SERVER_CERT_TYPE_CNT),
                                                WOLFSSL_SUCCESS);

    /* should accept zero for type count */
    ExpectIntEQ(wolfSSL_CTX_set_server_cert_type(ctx, ctype,
                                                0),
                                                WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_CTX_set_server_cert_type(ctx, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WOLFSSL_SUCCESS);

    /*--------------------------------------------*/
    /* tests for wolfSSL_set_client_cert_type */
    /*--------------------------------------------*/

    ExpectIntEQ(wolfSSL_set_client_cert_type(NULL, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl, ctype,
                                                sizeof(ctype)),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ctype[0] = WOLFSSL_CERT_TYPE_RPK;  /* set an identical cert type */
    ctype[1] = WOLFSSL_CERT_TYPE_RPK;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ctype[0] = WOLFSSL_CERT_TYPE_X509;
    ctype[1] = 10;                      /* set unknown cert type */

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* pass larger type count */
    ctype[0] = WOLFSSL_CERT_TYPE_RPK;
    ctype[1] = WOLFSSL_CERT_TYPE_X509;
    ctype[2] = 1;                       /* pass unacceptable type count */

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT + 1),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* should accept NULL for type buffer */
    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl, NULL,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WOLFSSL_SUCCESS);

    /* should accept zero for type count */
    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl, ctype,
                                                0),
                                                WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl, ctype,
                                                MAX_CLIENT_CERT_TYPE_CNT),
                                                WOLFSSL_SUCCESS);

    /*--------------------------------------------*/
    /* tests for wolfSSL_CTX_set_server_cert_type */
    /*--------------------------------------------*/

    ExpectIntEQ(wolfSSL_set_server_cert_type(NULL, ctype,
                                                MAX_SERVER_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl, ctype,
                                                sizeof(ctype)),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ctype[0] = WOLFSSL_CERT_TYPE_RPK;  /* set an identical cert type */
    ctype[1] = WOLFSSL_CERT_TYPE_RPK;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl, ctype,
                                                MAX_SERVER_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ctype[0] = WOLFSSL_CERT_TYPE_X509;
    ctype[1] = 10;                      /* set unknown cert type */

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl, ctype,
                                                MAX_SERVER_CERT_TYPE_CNT),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* pass larger type count */
    ctype[0] = WOLFSSL_CERT_TYPE_RPK;
    ctype[1] = WOLFSSL_CERT_TYPE_X509;
    ctype[2] = 1;                       /* pass unacceptable type count */

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl, ctype,
                                                MAX_SERVER_CERT_TYPE_CNT + 1),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* should accept NULL for type buffer */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl, NULL,
                                                MAX_SERVER_CERT_TYPE_CNT),
                                                WOLFSSL_SUCCESS);

    /* should accept zero for type count */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl, ctype,
                                                0),
                                                WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl, ctype,
                                                MAX_SERVER_CERT_TYPE_CNT),
                                                WOLFSSL_SUCCESS);

    /*------------------------------------------------*/
    /* tests for wolfSSL_get_negotiated_xxx_cert_type */
    /*------------------------------------------------*/

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(NULL, &tp),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl, NULL),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(NULL, &tp),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl, NULL),
                                                WC_NO_ERR_TRACE(BAD_FUNC_ARG));


    /* clean up */
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

#endif
    return EXPECT_RESULT();
}

static int test_tls13_rpk_handshake(void)
{
    EXPECT_DECLS;
#if defined(HAVE_RPK) && (!defined(WOLFSSL_NO_TLS12) || defined(WOLFSSL_TLS13))
#ifdef WOLFSSL_TLS13
    int ret = 0;
#endif
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int err;
    char certType_c[MAX_CLIENT_CERT_TYPE_CNT];
    char certType_s[MAX_CLIENT_CERT_TYPE_CNT];
    int typeCnt_c;
    int typeCnt_s;
    int tp = 0;
#if defined(WOLFSSL_ALWAYS_VERIFY_CB) && defined(WOLFSSL_TLS13)
    int isServer;
#endif

    (void)err;
    (void)typeCnt_c;
    (void)typeCnt_s;
    (void)certType_c;
    (void)certType_s;

#ifndef WOLFSSL_NO_TLS12
    /*  TLS1.2
     *  Both client and server load x509 cert and start handshaking.
     *  Check no negotiation occurred.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
            cliCertFile,     WOLFSSL_FILETYPE_PEM,
            svrCertFile,     WOLFSSL_FILETYPE_PEM,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM)
        , 0);


    /* set client certificate type in client end */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    /*  both client and server do not call client/server_cert_type APIs,
     *  expecting default settings works and no negotiation performed.
     */

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* confirm no negotiation occurred */
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                            WOLFSSL_SUCCESS);
    ExpectIntEQ((int)tp, WOLFSSL_CERT_TYPE_UNKNOWN);
    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                            WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                            WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                            WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    (void)typeCnt_c;
    (void)typeCnt_s;

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;
#endif

#ifdef WOLFSSL_TLS13
    /*  Both client and server load x509 cert and start handshaking.
     *  Check no negotiation occurred.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            cliCertFile,     WOLFSSL_FILETYPE_PEM,
            svrCertFile,     WOLFSSL_FILETYPE_PEM,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
        , 0);

    /* set client certificate type in client end */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    /*  both client and server do not call client/server_cert_type APIs,
     *  expecting default settings works and no negotiation performed.
     */

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* confirm no negotiation occurred */
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ((int)tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    (void)typeCnt_c;
    (void)typeCnt_s;

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;


    /*  Both client and server load RPK cert and start handshaking.
     *  Confirm negotiated cert types match as expected.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            clntRpkCertFile, WOLFSSL_FILETYPE_ASN1,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
        , 0);

    /* set client certificate type in client end */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in client end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* set client certificate type in server end */
    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in server end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;
#endif


#ifndef WOLFSSL_NO_TLS12
    /*  TLS1.2
     *  Both client and server load RPK cert and start handshaking.
     *  Confirm negotiated cert types match as expected.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
            clntRpkCertFile, WOLFSSL_FILETYPE_ASN1,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
        , 0);

    /* set client certificate type in client end */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in client end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* set client certificate type in server end */
    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in server end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    if (test_memio_do_handshake(ssl_c, ssl_s, 10, NULL) != 0)
        return TEST_FAIL;

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;
#endif


#ifdef WOLFSSL_TLS13
    /*  Both client and server load x509 cert.
     *  Have client call set_client_cert_type with both RPK and x509.
     *  This doesn't makes client add client cert type extension to ClientHello,
     *  since it does not load RPK cert actually.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            cliCertFile,     WOLFSSL_FILETYPE_PEM,
            svrCertFile,     WOLFSSL_FILETYPE_PEM,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
        , 0);

    /* set client certificate type in client end
     *
     * client indicates both RPK and x509 certs are available but loaded RPK
     * cert only. It does not have client add client-cert-type extension in CH.
     */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* client indicates both RPK and x509 certs are acceptable */
    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* server indicates both RPK and x509 certs are acceptable */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* server should indicate only RPK cert is available */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = -1;
    typeCnt_s = 1;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    if (test_memio_do_handshake(ssl_c, ssl_s, 10, NULL) != 0)
        return TEST_FAIL;

    /* Negotiation for client-cert-type should NOT happen. Therefore -1 should
     * be returned as cert type.
     */
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;


    /*  Have client load RPK cert and have server load x509 cert.
     *  Check the negotiation result from both ends.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            clntRpkCertFile, WOLFSSL_FILETYPE_ASN1,
            svrCertFile,     WOLFSSL_FILETYPE_PEM,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
        , 0);

    /* have client tell to use RPK cert */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = -1;
    typeCnt_c = 1;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* have client tell to accept both RPK and x509 cert */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* have server accept to both RPK and x509 cert */
    certType_c[0] = WOLFSSL_CERT_TYPE_X509;
    certType_c[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_c = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* does not call wolfSSL_set_server_cert_type intentionally in sesrver
     * end, expecting the default setting works.
     */


    if (test_memio_do_handshake(ssl_c, ssl_s, 10, NULL) != 0)
        return TEST_FAIL;

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;


    /*  Have both client and server load RPK cert, however, have server
     *  indicate its cert type x509.
     *  Client is expected to detect the cert type mismatch then to send alert
     *  with "unsupported_certificate".
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            clntRpkCertFile, WOLFSSL_FILETYPE_ASN1,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1, /* server sends RPK cert */
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
        , 0);

    /* have client tell to use RPK cert */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = -1;
    typeCnt_c = 1;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* have client tell to accept both RPK and x509 cert */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* have server accept to both RPK and x509 cert */
    certType_c[0] = WOLFSSL_CERT_TYPE_X509;
    certType_c[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_c = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* have server tell to use x509 cert intentionally. This will bring
     * certificate type mismatch in client side.
     */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = -1;
    typeCnt_s = 1;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* expect client detect cert type mismatch then send Alert */
    ret = test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);
    if (ret != -1)
        return TEST_FAIL;

    ExpectIntEQ(wolfSSL_get_error(ssl_c, ret), WC_NO_ERR_TRACE(UNSUPPORTED_CERTIFICATE));

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;


    /*  Have client load x509 cert and server load RPK cert,
     *  however, have client indicate its cert type RPK.
     *  Server is expected to detect the cert type mismatch then to send alert
     *  with "unsupported_certificate".
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            cliCertFile,     WOLFSSL_FILETYPE_PEM,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
        , 0);

    /* have client tell to use RPK cert intentionally */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = -1;
    typeCnt_c = 1;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* have client tell to accept both RPK and x509 cert */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* have server accept to both RPK and x509 cert */
    certType_c[0] = WOLFSSL_CERT_TYPE_X509;
    certType_c[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_c = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* have server tell to use x509 cert intentionally. This will bring
     * certificate type mismatch in client side.
     */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = -1;
    typeCnt_s = 1;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    ret = test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);

    /* expect server detect cert type mismatch then send Alert */
    ExpectIntNE(ret, 0);
    err = wolfSSL_get_error(ssl_c, ret);
    ExpectIntEQ(err, WC_NO_ERR_TRACE(UNSUPPORTED_CERTIFICATE));

    /* client did not load RPK cert actually, so negotiation did not happen */
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    /* client did not load RPK cert actually, so negotiation did not happen */
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;


#if defined(WOLFSSL_ALWAYS_VERIFY_CB)
    /*  Both client and server load RPK cert and set certificate verify
     *  callbacks then start handshaking.
     *  Confirm both side can refer the peer's cert.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            clntRpkCertFile, WOLFSSL_FILETYPE_ASN1,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
        , 0);

    /* set client certificate type in client end */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in client end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* set client certificate type in server end */
    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in server end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* set certificate verify callback to both client and server */
    isServer = 0;
    wolfSSL_SetCertCbCtx(ssl_c, &isServer);
    wolfSSL_set_verify(ssl_c, SSL_VERIFY_PEER, MyRpkVerifyCb);

    isServer = 1;
    wolfSSL_SetCertCbCtx(ssl_c, &isServer);
    wolfSSL_set_verify(ssl_s, SSL_VERIFY_PEER, MyRpkVerifyCb);

    ret = test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);
    if (ret != 0)
        return TEST_FAIL;

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;
#endif /* WOLFSSL_ALWAYS_VERIFY_CB */
#endif /* WOLFSSL_TLS13 */

#endif /* HAVE_RPK && (!WOLFSSL_NO_TLS12 || WOLFSSL_TLS13) */
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)


static int test_dtls13_bad_epoch_ch(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const int EPOCH_OFF = 3;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* disable hrr cookie so we can later check msgsReceived.got_client_hello
     *  with just one message */
    ExpectIntEQ(wolfSSL_disable_hrr_cookie(ssl_s), WOLFSSL_SUCCESS);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntGE(test_ctx.s_len, EPOCH_OFF + 2);

    /* first CH should use epoch 0x0 */
    ExpectTrue((test_ctx.s_buff[EPOCH_OFF] == 0x0) &&
        (test_ctx.s_buff[EPOCH_OFF + 1] == 0x0));

    /* change epoch to 2 */
    test_ctx.s_buff[EPOCH_OFF + 1] = 0x2;

    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntNE(ssl_s->msgsReceived.got_client_hello, 1);

    /* resend the CH */
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}
#else
static int test_dtls13_bad_epoch_ch(void)
{
    return TEST_SKIPPED;
}
#endif

#if ((defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
      defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TICKET_HAVE_ID) && \
      !defined(WOLFSSL_TLS13_MIDDLEBOX_COMPAT)) || \
     (!defined(NO_OLD_TLS) && ((!defined(NO_AES) && !defined(NO_AES_CBC)) || \
      !defined(NO_DES3))) || !defined(WOLFSSL_NO_TLS12)) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_SESSION_CACHE)
static int test_short_session_id_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    WOLFSSL_SESSION *sess = NULL;
    /* Setup the session to avoid errors */
    ssl->session->timeout = (word32)-1;
    ssl->session->side = WOLFSSL_CLIENT_END;
#if defined(SESSION_CERTS) || (defined(WOLFSSL_TLS13) && \
                               defined(HAVE_SESSION_TICKET))
    ssl->session->version = ssl->version;
#endif
    /* Force a short session ID to be sent */
    ssl->session->sessionIDSz = 4;
#ifndef NO_SESSION_CACHE_REF
    /* Allow the client cache to be used */
    ssl->session->idLen = 4;
#endif
    ssl->session->isSetup = 1;
    ExpectNotNull(sess = wolfSSL_get_session(ssl));
    ExpectIntEQ(wolfSSL_set_session(ssl, sess), WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

static int test_short_session_id(void)
{
    EXPECT_DECLS;
    test_ssl_cbf client_cbf;
    test_ssl_cbf server_cbf;
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* tls_version;
    } params[] = {
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TICKET_HAVE_ID) && \
    !defined(WOLFSSL_TLS13_MIDDLEBOX_COMPAT)
/* With WOLFSSL_TLS13_MIDDLEBOX_COMPAT a short ID will result in an error */
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, "TLSv1_3" },
#ifdef WOLFSSL_DTLS13
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, "DTLSv1_3" },
#endif
#endif
#ifndef WOLFSSL_NO_TLS12
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2" },
#ifdef WOLFSSL_DTLS
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2" },
#endif
#endif
#if !defined(NO_OLD_TLS) && ((!defined(NO_AES) && !defined(NO_AES_CBC)) || \
        !defined(NO_DES3))
        { wolfTLSv1_1_client_method, wolfTLSv1_1_server_method, "TLSv1_1" },
#ifdef WOLFSSL_DTLS
        { wolfDTLSv1_client_method, wolfDTLSv1_server_method, "DTLSv1_0" },
#endif
#endif
    };

    fprintf(stderr, "\n");

    for (i = 0; i < sizeof(params)/sizeof(*params) && !EXPECT_FAIL(); i++) {
        XMEMSET(&client_cbf, 0, sizeof(client_cbf));
        XMEMSET(&server_cbf, 0, sizeof(server_cbf));

        fprintf(stderr, "\tTesting short ID with %s\n", params[i].tls_version);

        client_cbf.ssl_ready = test_short_session_id_ssl_ready;
        client_cbf.method = params[i].client_meth;
        server_cbf.method = params[i].server_meth;

        ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbf,
            &server_cbf, NULL), TEST_SUCCESS);
    }
    return EXPECT_RESULT();
}
#else
static int test_short_session_id(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_NULL_CIPHER) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) \
    && defined(WOLFSSL_DTLS13)
static byte* test_find_string(const char *string,
    byte *buf, int buf_size)
{
    int string_size, i;

    string_size = (int)XSTRLEN(string);
    for (i = 0; i < buf_size - string_size - 1; i++) {
        if (XSTRCMP((char*)&buf[i], string) == 0)
            return &buf[i];
    }
    return NULL;
}

static int test_wolfSSL_dtls13_null_cipher(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char *test_str = "test";
    int test_str_size;
    byte buf[255], *ptr = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_ciphers = test_ctx.s_ciphers = "TLS13-SHA256-SHA256";
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    test_str_size = XSTRLEN("test") + 1;
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, test_str_size), test_str_size);
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), test_str_size);
    ExpectIntEQ(XSTRCMP((char*)buf, test_str), 0);

    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, test_str_size), test_str_size);

    /* check that the packet was sent cleartext */
    ExpectNotNull(ptr = test_find_string(test_str, test_ctx.s_buff,
        test_ctx.s_len));
    if (ptr != NULL) {
        /* modify the message */
        *ptr = 'H';
        /* bad messages should be ignored in DTLS */
        ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), -1);
        ExpectIntEQ(ssl_s->error, WC_NO_ERR_TRACE(WANT_READ));
    }

    ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SHUTDOWN_NOT_DONE);
    ExpectIntEQ(wolfSSL_shutdown(ssl_s), WOLFSSL_SHUTDOWN_NOT_DONE);
    ExpectIntEQ(wolfSSL_shutdown(ssl_c), 1);
    ExpectIntEQ(wolfSSL_shutdown(ssl_s), 1);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return TEST_SUCCESS;
}
#else
static int test_wolfSSL_dtls13_null_cipher(void)
{
    return TEST_SKIPPED;
}
#endif
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) &&          \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&   \
    !defined(SINGLE_THREADED) && !defined(NO_RSA)

static int test_dtls_msg_get_connected_port(int fd, word16 *port)
{
    SOCKADDR_S peer;
    XSOCKLENT len;
    int ret;

    XMEMSET((byte*)&peer, 0, sizeof(peer));
    len = sizeof(peer);
    ret = getpeername(fd,  (SOCKADDR*)&peer, &len);
    if (ret != 0 || len > (XSOCKLENT)sizeof(peer))
        return -1;
    switch (peer.ss_family) {
#ifdef WOLFSSL_IPV6
    case WOLFSSL_IP6: {
        *port = ntohs(((SOCKADDR_IN6*)&peer)->sin6_port);
        break;
    }
#endif /* WOLFSSL_IPV6 */
    case WOLFSSL_IP4:
        *port = ntohs(((SOCKADDR_IN*)&peer)->sin_port);
        break;
    default:
        return -1;
    }
    return 0;
}

static int test_dtls_msg_from_other_peer_cb(WOLFSSL_CTX *ctx, WOLFSSL *ssl)
{
    char buf[1] = {'t'};
    SOCKADDR_IN_T addr;
    int sock_fd;
    word16 port;
    int err;

    (void)ssl;
    (void)ctx;

    if (ssl == NULL)
        return -1;

    err = test_dtls_msg_get_connected_port(wolfSSL_get_fd(ssl), &port);
    if (err != 0)
        return -1;

    sock_fd = socket(AF_INET_V, SOCK_DGRAM, 0);
    if (sock_fd == -1)
        return -1;
    build_addr(&addr, wolfSSLIP, port, 1, 0);

    /* send a packet to the server. Being another socket, the kernel will ensure
     * the source port will be different. */
    err = (int)sendto(sock_fd, buf, sizeof(buf), 0, (SOCKADDR*)&addr,
        sizeof(addr));

    close(sock_fd);
    if (err == -1)
        return -1;

    return 0;
}

/* setup a SSL session but just after the handshake send a packet to the server
 * with a source address different than the one of the connected client. The I/O
 * callback EmbedRecvFrom should just ignore the packet. Sending of the packet
 * is done in test_dtls_msg_from_other_peer_cb */
static int test_dtls_msg_from_other_peer(void)
{
    EXPECT_DECLS;
    callback_functions client_cbs;
    callback_functions server_cbs;

    XMEMSET((byte*)&client_cbs, 0, sizeof(client_cbs));
    XMEMSET((byte*)&server_cbs, 0, sizeof(server_cbs));

    client_cbs.method = wolfDTLSv1_2_client_method;
    server_cbs.method = wolfDTLSv1_2_server_method;
    client_cbs.doUdp = 1;
    server_cbs.doUdp = 1;

    test_wolfSSL_client_server_nofail_ex(&client_cbs, &server_cbs,
        test_dtls_msg_from_other_peer_cb);

    ExpectIntEQ(client_cbs.return_code, WOLFSSL_SUCCESS);
    ExpectIntEQ(server_cbs.return_code, WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}
#else
static int test_dtls_msg_from_other_peer(void)
{
    return TEST_SKIPPED;
}
#endif /* defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) &&          \
        *  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&  \
        *  !defined(SINGLE_THREADED) && !defined(NO_RSA) */
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_IPV6) &&               \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&   \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
static int test_dtls_ipv6_check(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    SOCKADDR_IN fake_addr6;
    int sockfd = -1;

    ExpectNotNull(ctx_c = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl_c  = wolfSSL_new(ctx_c));
    ExpectNotNull(ctx_s = wolfSSL_CTX_new(wolfDTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx_s, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx_s, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl_s  = wolfSSL_new(ctx_s));
    XMEMSET((byte*)&fake_addr6, 0, sizeof(fake_addr6));
    /* mimic a sockaddr_in6 struct, this way we can't test without
     *  WOLFSSL_IPV6 */
    fake_addr6.sin_family = WOLFSSL_IP6;
    ExpectIntNE(sockfd = socket(AF_INET, SOCK_DGRAM, 0), -1);
    ExpectIntEQ(wolfSSL_set_fd(ssl_c, sockfd), WOLFSSL_SUCCESS);
    /* can't return error here, as the peer is opaque for wolfssl library at
     * this point */
    ExpectIntEQ(wolfSSL_dtls_set_peer(ssl_c, &fake_addr6, sizeof(fake_addr6)),
        WOLFSSL_SUCCESS);
    ExpectIntNE(fcntl(sockfd, F_SETFL, O_NONBLOCK), -1);
    wolfSSL_dtls_set_using_nonblock(ssl_c, 1);
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(ssl_c->error, WC_NO_ERR_TRACE(SOCKET_ERROR_E));

    ExpectIntEQ(wolfSSL_dtls_set_peer(ssl_s, &fake_addr6, sizeof(fake_addr6)),
        WOLFSSL_SUCCESS);
    /* reuse the socket */
    ExpectIntEQ(wolfSSL_set_fd(ssl_c, sockfd), WOLFSSL_SUCCESS);
    wolfSSL_dtls_set_using_nonblock(ssl_s, 1);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(ssl_s->error, WC_NO_ERR_TRACE(SOCKET_ERROR_E));
    if (sockfd != -1)
        close(sockfd);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#else
static int test_dtls_ipv6_check(void)
{
    return TEST_SKIPPED;
}
#endif

#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&   \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_SECURE_RENEGOTIATION)

static WOLFSSL_SESSION* test_wolfSSL_SCR_after_resumption_session = NULL;

static void test_wolfSSL_SCR_after_resumption_ctx_ready(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx), WOLFSSL_SUCCESS);
}

static void test_wolfSSL_SCR_after_resumption_on_result(WOLFSSL* ssl)
{
    if (test_wolfSSL_SCR_after_resumption_session == NULL) {
        test_wolfSSL_SCR_after_resumption_session = wolfSSL_get1_session(ssl);
        AssertNotNull(test_wolfSSL_SCR_after_resumption_session);
    }
    else {
        char testMsg[] = "Message after SCR";
        char msgBuf[sizeof(testMsg)];
        int ret;
        if (!wolfSSL_is_server(ssl)) {
            AssertIntEQ(WOLFSSL_SUCCESS,
                    wolfSSL_set_session(ssl,
                       test_wolfSSL_SCR_after_resumption_session));
        }
        AssertIntEQ(wolfSSL_Rehandshake(ssl), WOLFSSL_SUCCESS);
        AssertIntEQ(wolfSSL_write(ssl, testMsg, sizeof(testMsg)),
                    sizeof(testMsg));
        ret = wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
        if (ret != sizeof(msgBuf)) /* Possibly APP_DATA_READY error. Retry. */
            ret = wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
        AssertIntEQ(ret, sizeof(msgBuf));
    }
}

static void test_wolfSSL_SCR_after_resumption_ssl_ready(WOLFSSL* ssl)
{
    AssertIntEQ(WOLFSSL_SUCCESS,
           wolfSSL_set_session(ssl, test_wolfSSL_SCR_after_resumption_session));
}

static int test_wolfSSL_SCR_after_resumption(void)
{
    EXPECT_DECLS;
    callback_functions func_cb_client;
    callback_functions func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(func_cb_client));
    XMEMSET(&func_cb_server, 0, sizeof(func_cb_server));

    func_cb_client.method = wolfTLSv1_2_client_method;
    func_cb_client.ctx_ready = test_wolfSSL_SCR_after_resumption_ctx_ready;
    func_cb_client.on_result = test_wolfSSL_SCR_after_resumption_on_result;
    func_cb_server.method = wolfTLSv1_2_server_method;
    func_cb_server.ctx_ready = test_wolfSSL_SCR_after_resumption_ctx_ready;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);

    func_cb_client.ssl_ready = test_wolfSSL_SCR_after_resumption_ssl_ready;
    func_cb_server.on_result = test_wolfSSL_SCR_after_resumption_on_result;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);

    wolfSSL_SESSION_free(test_wolfSSL_SCR_after_resumption_session);

    return EXPECT_RESULT();
}

#else
static int test_wolfSSL_SCR_after_resumption(void)
{
    return TEST_SKIPPED;
}
#endif

static int test_wolfSSL_configure_args(void)
{
    EXPECT_DECLS;
#if defined(LIBWOLFSSL_CONFIGURE_ARGS) && defined(HAVE_WC_INTROSPECTION)
    ExpectNotNull(wolfSSL_configure_args());
#endif
    return EXPECT_RESULT();
}

static int test_dtls_no_extensions(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    struct test_memio_ctx test_ctx;
    const byte chNoExtensions[] = {
        /* Handshake type */
        0x16,
        /* Version */
        0xfe, 0xff,
        /* Epoch */
        0x00, 0x00,
        /* Seq number */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Length */
        0x00, 0x40,
        /* CH type */
        0x01,
        /* Length */
        0x00, 0x00, 0x34,
        /* Msg Seq */
        0x00, 0x00,
        /* Frag offset */
        0x00, 0x00, 0x00,
        /* Frag length */
        0x00, 0x00, 0x34,
        /* Version */
        0xfe, 0xff,
        /* Random */
        0x62, 0xfe, 0xbc, 0xfe, 0x2b, 0xfe, 0x3f, 0xeb, 0x03, 0xc4, 0xea, 0x37,
        0xe7, 0x47, 0x7e, 0x8a, 0xd9, 0xbf, 0x77, 0x0f, 0x6c, 0xb6, 0x77, 0x0b,
        0x03, 0x3f, 0x82, 0x2b, 0x21, 0x64, 0x57, 0x1d,
        /* Session Length */
        0x00,
        /* Cookie Length */
        0x00,
        /* CS Length */
        0x00, 0x0c,
        /* CS */
        0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x39, 0x00, 0x33,
        /* Comp Meths Length */
        0x01,
        /* Comp Meths */
        0x00
        /* And finally... no extensions */
    };
    int i;
#ifdef OPENSSL_EXTRA
    int repeats = 2;
#else
    int repeats = 1;
#endif

    for (i = 0; i < repeats; i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ssl_s = NULL;
        ctx_s = NULL;

        ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
            NULL, wolfDTLS_server_method), 0);

        XMEMCPY(test_ctx.s_buff, chNoExtensions, sizeof(chNoExtensions));
        test_ctx.s_len = sizeof(chNoExtensions);

#ifdef OPENSSL_EXTRA
        if (i > 0) {
            ExpectIntEQ(wolfSSL_set_max_proto_version(ssl_s, DTLS1_2_VERSION),
                        WOLFSSL_SUCCESS);
        }
#endif

        ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

        /* Expecting a handshake msg. Either HVR or SH. */
        ExpectIntGT(test_ctx.c_len, 0);
        ExpectIntEQ(test_ctx.c_buff[0], 0x16);

        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}

static int test_tls_alert_no_server_hello(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL *ssl_c = NULL;
    WOLFSSL_CTX *ctx_c = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char alert_msg[] = { 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28 };

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ssl_c = NULL;
    ctx_c = NULL;

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
        wolfTLSv1_2_client_method, NULL), 0);

    XMEMCPY(test_ctx.c_buff, alert_msg, sizeof(alert_msg));
    test_ctx.c_len = sizeof(alert_msg);

    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WC_NO_ERR_TRACE(FATAL_ERROR));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

static int test_TLSX_CA_NAMES_bad_extension(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    !defined(NO_CERTS) && !defined(WOLFSSL_NO_CA_NAMES) && \
    defined(OPENSSL_EXTRA) && defined(WOLFSSL_SHA384) && \
    defined(HAVE_NULL_CIPHER)
    /* This test should only fail (with BUFFER_ERROR) when we actually try to
     * parse the CA Names extension. Otherwise it will return other non-related
     * errors. If CA Names will be parsed in more configurations, that should
     * be reflected in the macro guard above. */
    WOLFSSL *ssl_c = NULL;
    WOLFSSL_CTX *ctx_c = NULL;
    struct test_memio_ctx test_ctx;
    /* HRR + SH using TLS_DHE_PSK_WITH_NULL_SHA384 */
    const byte shBadCaNamesExt[] = {
        0x16, 0x03, 0x04, 0x00, 0x3f, 0x02, 0x00, 0x00, 0x3b, 0x03, 0x03, 0xcf,
        0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e,
        0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07,
        0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c, 0x00, 0x13, 0x03, 0x00, 0x00,
        0x13, 0x94, 0x7e, 0x00, 0x03, 0x0b, 0xf7, 0x03, 0x00, 0x2b, 0x00, 0x02,
        0x03, 0x04, 0x00, 0x33, 0x00, 0x02, 0x00, 0x19, 0x16, 0x03, 0x03, 0x00,
        0x5c, 0x02, 0x00, 0x00, 0x3b, 0x03, 0x03, 0x03, 0xcf, 0x21, 0xad, 0x74,
        0x00, 0x00, 0x83, 0x3f, 0x3b, 0x80, 0x01, 0xac, 0x65, 0x8c, 0x19, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x02, 0x00, 0x9e, 0x09, 0x1c, 0xe8,
        0xa8, 0x09, 0x9c, 0x00, 0xc0, 0xb5, 0x00, 0x00, 0x11, 0x8f, 0x00, 0x00,
        0x03, 0x3f, 0x00, 0x0c, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x13, 0x05,
        0x00, 0x00, 0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x09, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x11, 0x00, 0x00, 0x0d, 0x00, 0x2f, 0x00, 0x01, 0xff,
        0xff, 0xff, 0xff, 0xfa, 0x0d, 0x00, 0x00, 0x00, 0xad, 0x02
    };
    const byte shBadCaNamesExt2[] = {
        0x16, 0x03, 0x04, 0x00, 0x3f, 0x02, 0x00, 0x00, 0x3b, 0x03, 0x03, 0xcf,
        0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e,
        0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07,
        0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c, 0x00, 0x13, 0x03, 0x00, 0x00,
        0x13, 0x94, 0x7e, 0x00, 0x03, 0x0b, 0xf7, 0x03, 0x00, 0x2b, 0x00, 0x02,
        0x03, 0x04, 0x00, 0x33, 0x00, 0x02, 0x00, 0x19, 0x16, 0x03, 0x03, 0x00,
        0x5e, 0x02, 0x00, 0x00, 0x3b, 0x03, 0x03, 0x7f, 0xd0, 0x2d, 0xea, 0x6e,
        0x53, 0xa1, 0x6a, 0xc9, 0xc8, 0x54, 0xef, 0x75, 0xe4, 0xd9, 0xc6, 0x3e,
        0x74, 0xcb, 0x30, 0x80, 0xcc, 0x83, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0x5a, 0x00, 0xc0, 0xb5, 0x00, 0x00, 0x11, 0x8f, 0x00, 0x00,
        0x03, 0x03, 0x00, 0x0c, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x53, 0x25,
        0x00, 0x00, 0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x02, 0x05, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x11, 0x00, 0x00, 0x0d, 0x00, 0x2f, 0x00, 0x06, 0x00,
        0x04, 0x00, 0x03, 0x30, 0x00, 0x13, 0x94, 0x00, 0x06, 0x00, 0x04, 0x02
    };
    int i = 0;

    for (i = 0; i < 2; i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
            wolfTLSv1_3_client_method, NULL), 0);

        switch (i) {
            case 0:
                XMEMCPY(test_ctx.c_buff, shBadCaNamesExt,
                        sizeof(shBadCaNamesExt));
                test_ctx.c_len = sizeof(shBadCaNamesExt);
                break;
            case 1:
                XMEMCPY(test_ctx.c_buff, shBadCaNamesExt2,
                        sizeof(shBadCaNamesExt2));
                test_ctx.c_len = sizeof(shBadCaNamesExt2);
                break;
        }

        ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
#ifndef WOLFSSL_DISABLE_EARLY_SANITY_CHECKS
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WC_NO_ERR_TRACE(OUT_OF_ORDER_E));
#else
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WC_NO_ERR_TRACE(BUFFER_ERROR));
#endif

        wolfSSL_free(ssl_c);
        ssl_c = NULL;
        wolfSSL_CTX_free(ctx_c);
        ctx_c = NULL;
    }

#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES)
static void test_dtls_1_0_hvr_downgrade_ctx_ready(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_DTLSV1_2),
                WOLFSSL_SUCCESS);
}

static int test_dtls_1_0_hvr_downgrade(void)
{
    EXPECT_DECLS;
    callback_functions func_cb_client;
    callback_functions func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
    XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

    func_cb_client.doUdp = func_cb_server.doUdp = 1;
    func_cb_client.method = wolfDTLS_client_method;
    func_cb_server.method = wolfDTLSv1_2_server_method;
    func_cb_client.ctx_ready = test_dtls_1_0_hvr_downgrade_ctx_ready;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
static int test_dtls_1_0_hvr_downgrade(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif

#if defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12) && \
        defined(HAVE_SESSION_TICKET)

static WOLFSSL_SESSION* test_session_ticket_no_id_session = NULL;

static void test_session_ticket_no_id_on_result(WOLFSSL* ssl)
{
    test_session_ticket_no_id_session = wolfSSL_get1_session(ssl);
    AssertNotNull(test_session_ticket_no_id_session);
}

static void test_session_ticket_no_id_ctx_ready(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(wolfSSL_CTX_UseSessionTicket(ctx), WOLFSSL_SUCCESS);
}

static void test_session_ticket_no_id_ssl_ready(WOLFSSL* ssl)
{
    test_session_ticket_no_id_session->sessionIDSz = 0;
    AssertIntEQ(WOLFSSL_SUCCESS,
           wolfSSL_set_session(ssl, test_session_ticket_no_id_session));
}

static int test_session_ticket_no_id(void)
{
    /* We are testing an expired (invalid crypto context in out case since the
     * ctx changes) session ticket being sent with the session ID being 0
     * length. */
    EXPECT_DECLS;
    callback_functions func_cb_client;
    callback_functions func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(func_cb_client));
    XMEMSET(&func_cb_server, 0, sizeof(func_cb_server));
    func_cb_client.method = wolfTLSv1_2_client_method;
    func_cb_client.ctx_ready = test_session_ticket_no_id_ctx_ready;
    func_cb_client.on_result = test_session_ticket_no_id_on_result;
    func_cb_server.method = wolfTLSv1_2_server_method;
    func_cb_server.ctx_ready = test_session_ticket_no_id_ctx_ready;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);

    XMEMSET(&func_cb_client, 0, sizeof(func_cb_client));
    XMEMSET(&func_cb_server, 0, sizeof(func_cb_server));
    func_cb_client.method = wolfTLSv1_2_client_method;
    func_cb_client.ctx_ready = test_session_ticket_no_id_ctx_ready;
    func_cb_client.ssl_ready = test_session_ticket_no_id_ssl_ready;
    func_cb_server.method = wolfTLSv1_2_server_method;
    func_cb_server.ctx_ready = test_session_ticket_no_id_ctx_ready;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);

    wolfSSL_SESSION_free(test_session_ticket_no_id_session);

    return EXPECT_RESULT();
}
#else
static int test_session_ticket_no_id(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif

static int test_session_ticket_hs_update(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB)
    struct test_memio_ctx test_ctx;
    struct test_memio_ctx test_ctx2;
    struct test_memio_ctx test_ctx3;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_c2 = NULL;
    WOLFSSL *ssl_c3 = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL *ssl_s2 = NULL;
    WOLFSSL *ssl_s3 = NULL;
    WOLFSSL_SESSION *sess = NULL;
    byte read_data[1];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&test_ctx2, 0, sizeof(test_ctx2));
    XMEMSET(&test_ctx3, 0, sizeof(test_ctx3));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Generate tickets */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    wolfSSL_SetLoggingPrefix("client");
    /* Read the ticket msg */
    ExpectIntEQ(wolfSSL_read(ssl_c, read_data, sizeof(read_data)),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    wolfSSL_SetLoggingPrefix(NULL);

    ExpectIntEQ(test_memio_setup(&test_ctx2, &ctx_c, &ctx_s, &ssl_c2, &ssl_s2,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx3, &ctx_c, &ctx_s, &ssl_c3, &ssl_s3,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));
    ExpectIntEQ(wolfSSL_set_session(ssl_c2, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c3, sess), WOLFSSL_SUCCESS);

    wolfSSL_SetLoggingPrefix("client");
    /* Exchange initial flights for the second connection */
    ExpectIntEQ(wolfSSL_connect(ssl_c2), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c2, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    wolfSSL_SetLoggingPrefix(NULL);
    wolfSSL_SetLoggingPrefix("server");
    ExpectIntEQ(wolfSSL_accept(ssl_s2), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_s2, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    wolfSSL_SetLoggingPrefix(NULL);

    /* Complete third connection so that new tickets are exchanged */
    ExpectIntEQ(test_memio_do_handshake(ssl_c3, ssl_s3, 10, NULL), 0);
    /* Read the ticket msg */
    wolfSSL_SetLoggingPrefix("client");
    ExpectIntEQ(wolfSSL_read(ssl_c3, read_data, sizeof(read_data)),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c3, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    wolfSSL_SetLoggingPrefix(NULL);

    /* Complete second connection */
    ExpectIntEQ(test_memio_do_handshake(ssl_c2, ssl_s2, 10, NULL), 0);

    ExpectIntEQ(wolfSSL_session_reused(ssl_c2), 1);
    ExpectIntEQ(wolfSSL_session_reused(ssl_c3), 1);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_c2);
    wolfSSL_free(ssl_c3);
    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_s2);
    wolfSSL_free(ssl_s3);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_SESSION_free(sess);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_SECURE_RENEGOTIATION)
static void test_dtls_downgrade_scr_server_ctx_ready_server(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_DTLSV1_2),
                WOLFSSL_SUCCESS);
    AssertIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx), WOLFSSL_SUCCESS);
}

static void test_dtls_downgrade_scr_server_ctx_ready(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx), WOLFSSL_SUCCESS);
}

static void test_dtls_downgrade_scr_server_on_result(WOLFSSL* ssl)
{
    char testMsg[] = "Message after SCR";
    char msgBuf[sizeof(testMsg)];
    if (wolfSSL_is_server(ssl)) {
        AssertIntEQ(wolfSSL_Rehandshake(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        AssertIntEQ(wolfSSL_get_error(ssl, -1), WC_NO_ERR_TRACE(APP_DATA_READY));
        AssertIntEQ(wolfSSL_read(ssl, msgBuf, sizeof(msgBuf)), sizeof(msgBuf));
        AssertIntEQ(wolfSSL_Rehandshake(ssl), WOLFSSL_SUCCESS);
        AssertIntEQ(wolfSSL_write(ssl, testMsg, sizeof(testMsg)),
                    sizeof(testMsg));
    }
    else {
        AssertIntEQ(wolfSSL_write(ssl, testMsg, sizeof(testMsg)),
                    sizeof(testMsg));
        AssertIntEQ(wolfSSL_read(ssl, msgBuf, sizeof(msgBuf)), sizeof(msgBuf));
    }
}

static int test_dtls_downgrade_scr_server(void)
{
    EXPECT_DECLS;
    callback_functions func_cb_client;
    callback_functions func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
    XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

    func_cb_client.doUdp = func_cb_server.doUdp = 1;
    func_cb_client.method = wolfDTLSv1_2_client_method;
    func_cb_server.method = wolfDTLS_server_method;
    func_cb_client.ctx_ready = test_dtls_downgrade_scr_server_ctx_ready;
    func_cb_server.ctx_ready = test_dtls_downgrade_scr_server_ctx_ready_server;
    func_cb_client.on_result = test_dtls_downgrade_scr_server_on_result;
    func_cb_server.on_result = test_dtls_downgrade_scr_server_on_result;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
static int test_dtls_downgrade_scr_server(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif

#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_SECURE_RENEGOTIATION)
static void test_dtls_downgrade_scr_ctx_ready(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_DTLSV1_2),
                WOLFSSL_SUCCESS);
    AssertIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx), WOLFSSL_SUCCESS);
}

static void test_dtls_downgrade_scr_on_result(WOLFSSL* ssl)
{
    char testMsg[] = "Message after SCR";
    char msgBuf[sizeof(testMsg)];
    if (wolfSSL_is_server(ssl)) {
        AssertIntEQ(wolfSSL_Rehandshake(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        AssertIntEQ(wolfSSL_get_error(ssl, -1), WC_NO_ERR_TRACE(APP_DATA_READY));
        AssertIntEQ(wolfSSL_read(ssl, msgBuf, sizeof(msgBuf)), sizeof(msgBuf));
        AssertIntEQ(wolfSSL_Rehandshake(ssl), WOLFSSL_SUCCESS);
        AssertIntEQ(wolfSSL_write(ssl, testMsg, sizeof(testMsg)),
                    sizeof(testMsg));
    }
    else {
        AssertIntEQ(wolfSSL_write(ssl, testMsg, sizeof(testMsg)),
                    sizeof(testMsg));
        AssertIntEQ(wolfSSL_read(ssl, msgBuf, sizeof(msgBuf)), sizeof(msgBuf));
    }
}

static int test_dtls_downgrade_scr(void)
{
    EXPECT_DECLS;
    callback_functions func_cb_client;
    callback_functions func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
    XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

    func_cb_client.doUdp = func_cb_server.doUdp = 1;
    func_cb_client.method = wolfDTLS_client_method;
    func_cb_server.method = wolfDTLSv1_2_server_method;
    func_cb_client.ctx_ready = test_dtls_downgrade_scr_ctx_ready;
    func_cb_client.on_result = test_dtls_downgrade_scr_on_result;
    func_cb_server.on_result = test_dtls_downgrade_scr_on_result;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
static int test_dtls_downgrade_scr(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && !defined(WOLFSSL_NO_TLS12)

static int test_dtls_client_hello_timeout_downgrade_read_cb(WOLFSSL *ssl,
        char *data, int sz, void *ctx)
{
    static int call_counter = 0;
    call_counter++;
    (void)ssl;
    (void)data;
    (void)sz;
    (void)ctx;
    switch (call_counter) {
        case 1:
        case 2:
            return WOLFSSL_CBIO_ERR_TIMEOUT;
        case 3:
            return WOLFSSL_CBIO_ERR_WANT_READ;
        default:
            AssertIntLE(call_counter, 3);
            return -1;
    }
}
#endif

/* Make sure we don't send acks before getting a server hello */
static int test_dtls_client_hello_timeout_downgrade(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && !defined(WOLFSSL_NO_TLS12)

    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    DtlsRecordLayerHeader* dtlsRH;
    size_t len;
    byte sequence_number[8];
    int i;

    for (i = 0; i < 2; i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLS_client_method, wolfDTLSv1_2_server_method), 0);

        if (i == 0) {
            /* First time simulate timeout in IO layer */
            /* CH1 */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            /* HVR */
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            /* CH2 */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            /* SH flight */
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            /* Drop the SH */
            dtlsRH = (DtlsRecordLayerHeader*)(test_ctx.c_buff);
            len = (size_t)((dtlsRH->length[0] << 8) | dtlsRH->length[1]);
            if (EXPECT_SUCCESS()) {
                XMEMMOVE(test_ctx.c_buff, test_ctx.c_buff +
                    sizeof(DtlsRecordLayerHeader) + len, test_ctx.c_len -
                   (sizeof(DtlsRecordLayerHeader) + len));
            }
            test_ctx.c_len -= sizeof(DtlsRecordLayerHeader) + len;
            /* Read the remainder of the flight */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            wolfSSL_SSLSetIORecv(ssl_c,
                    test_dtls_client_hello_timeout_downgrade_read_cb);
            /* CH3 */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            wolfSSL_SSLSetIORecv(ssl_c, test_memio_read_cb);
        }
        else {
            /* Second time call wolfSSL_dtls_got_timeout */
            /* CH1 */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            /* HVR */
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            /* CH2 */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            /* SH flight */
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            /* Drop the SH */
            dtlsRH = (DtlsRecordLayerHeader*)(test_ctx.c_buff);
            len = (size_t)((dtlsRH->length[0] << 8) | dtlsRH->length[1]);
            if (EXPECT_SUCCESS()) {
                XMEMMOVE(test_ctx.c_buff, test_ctx.c_buff +
                    sizeof(DtlsRecordLayerHeader) + len, test_ctx.c_len -
                   (sizeof(DtlsRecordLayerHeader) + len));
            }
            test_ctx.c_len -= sizeof(DtlsRecordLayerHeader) + len;
            /* Read the remainder of the flight */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            /* Quick timeout should be set as we received at least one msg */
            ExpectIntEQ(wolfSSL_dtls13_use_quick_timeout(ssl_c), 1);
            ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
            /* Quick timeout should be cleared after a quick timeout */
            /* CH3 */
            ExpectIntEQ(wolfSSL_dtls13_use_quick_timeout(ssl_c), 0);
            ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
        }

        /* Parse out to make sure we got exactly one ClientHello message */
        XMEMSET(&sequence_number, 0, sizeof(sequence_number));
        /* Second ClientHello after HVR */
        sequence_number[7] = 2;
        dtlsRH = (DtlsRecordLayerHeader*)test_ctx.s_buff;
        ExpectIntEQ(dtlsRH->type, handshake);
        ExpectIntEQ(dtlsRH->pvMajor, DTLS_MAJOR);
        ExpectIntEQ(dtlsRH->pvMinor, DTLSv1_2_MINOR);
        ExpectIntEQ(XMEMCMP(sequence_number, dtlsRH->sequence_number,
                sizeof(sequence_number)), 0);
        len = (size_t)((dtlsRH->length[0] << 8) | dtlsRH->length[1]);
        ExpectIntEQ(sizeof(DtlsRecordLayerHeader) + len, test_ctx.s_len);

        /* Connection should be able to continue */
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
        ssl_c = NULL;
        ssl_s = NULL;
        ctx_c = NULL;
        ctx_s = NULL;
        if (!EXPECT_SUCCESS())
            break;
    }

#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
static int test_dtls_client_hello_timeout_read_cb(WOLFSSL *ssl, char *data,
        int sz, void *ctx)
{
    static int call_counter = 0;
    call_counter++;
    (void)ssl;
    (void)data;
    (void)sz;
    (void)ctx;
    switch (call_counter) {
        case 1:
            return WOLFSSL_CBIO_ERR_TIMEOUT;
        case 2:
            return WOLFSSL_CBIO_ERR_WANT_READ;
        default:
            AssertIntLE(call_counter, 2);
            return -1;
    }
}
#endif

/* Make sure we don't send acks before getting a server hello */
static int test_dtls_client_hello_timeout(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL *ssl_c = NULL;
    WOLFSSL_CTX *ctx_c = NULL;
    struct test_memio_ctx test_ctx;
    DtlsRecordLayerHeader* dtlsRH;
    size_t idx;
    size_t len;
    byte sequence_number[8];
    int i;

    for (i = 0; i < 2; i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
            wolfDTLSv1_3_client_method, NULL), 0);

        if (i == 0) {
            /* First time simulate timeout in IO layer */
            wolfSSL_SSLSetIORecv(ssl_c, test_dtls_client_hello_timeout_read_cb);
            ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        }
        else {
            /* Second time call wolfSSL_dtls_got_timeout */
            ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
        }

        /* Parse out to make sure we got exactly two ClientHello messages */
        idx = 0;
        XMEMSET(&sequence_number, 0, sizeof(sequence_number));
        /* First ClientHello */
        dtlsRH = (DtlsRecordLayerHeader*)(test_ctx.s_buff + idx);
        ExpectIntEQ(dtlsRH->type, handshake);
        ExpectIntEQ(dtlsRH->pvMajor, DTLS_MAJOR);
        ExpectIntEQ(dtlsRH->pvMinor, DTLSv1_2_MINOR);
        ExpectIntEQ(XMEMCMP(sequence_number, dtlsRH->sequence_number,
                sizeof(sequence_number)), 0);
        len = (size_t)((dtlsRH->length[0] << 8) | dtlsRH->length[1]);
        ExpectIntLT(idx + sizeof(DtlsRecordLayerHeader) + len, test_ctx.s_len);
        idx += sizeof(DtlsRecordLayerHeader) + len;
        /* Second ClientHello */
        sequence_number[7] = 1;
        dtlsRH = (DtlsRecordLayerHeader*)(test_ctx.s_buff + idx);
        ExpectIntEQ(dtlsRH->type, handshake);
        ExpectIntEQ(dtlsRH->pvMajor, DTLS_MAJOR);
        ExpectIntEQ(dtlsRH->pvMinor, DTLSv1_2_MINOR);
        ExpectIntEQ(XMEMCMP(sequence_number, dtlsRH->sequence_number,
                sizeof(sequence_number)), 0);
        len = (size_t)((dtlsRH->length[0] << 8) | dtlsRH->length[1]);
        ExpectIntEQ(idx + sizeof(DtlsRecordLayerHeader) + len, test_ctx.s_len);

        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_c);
        ssl_c = NULL;
        ctx_c = NULL;
        if (!EXPECT_SUCCESS())
            break;
    }

#endif
    return EXPECT_RESULT();
}

/* DTLS test when dropping the changed cipher spec message */
static int test_dtls_dropped_ccs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) \
    && !defined(WOLFSSL_NO_TLS12)

    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    DtlsRecordLayerHeader* dtlsRH;
    size_t len;
    byte data[1];


    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HVR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server ccs + finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);

    /* Drop the ccs */
    dtlsRH = (DtlsRecordLayerHeader*)test_ctx.c_buff;
    len = (size_t)((dtlsRH->length[0] << 8) | dtlsRH->length[1]);
    ExpectIntEQ(len, 1);
    ExpectIntEQ(dtlsRH->type, change_cipher_spec);
    if (EXPECT_SUCCESS()) {
        XMEMMOVE(test_ctx.c_buff, test_ctx.c_buff +
                sizeof(DtlsRecordLayerHeader) + len, test_ctx.c_len -
               (sizeof(DtlsRecordLayerHeader) + len));
    }
    test_ctx.c_len -= sizeof(DtlsRecordLayerHeader) + len;

    /* Client rtx flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
    /* Server ccs + finished rtx */
    ExpectIntEQ(wolfSSL_read(ssl_s, data, sizeof(data)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client processes finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) \
    && !defined(WOLFSSL_NO_TLS12)
static int test_dtls_seq_num_downgrade_check_num(byte* ioBuf, int ioBufLen,
        byte seq_num)
{
    EXPECT_DECLS;
    DtlsRecordLayerHeader* dtlsRH;
    byte sequence_number[8];

    XMEMSET(&sequence_number, 0, sizeof(sequence_number));

    ExpectIntGE(ioBufLen, sizeof(*dtlsRH));
    dtlsRH = (DtlsRecordLayerHeader*)ioBuf;
    ExpectIntEQ(dtlsRH->type, handshake);
    ExpectIntEQ(dtlsRH->pvMajor, DTLS_MAJOR);
    ExpectIntEQ(dtlsRH->pvMinor, DTLSv1_2_MINOR);
    sequence_number[7] = seq_num;
    ExpectIntEQ(XMEMCMP(sequence_number, dtlsRH->sequence_number,
            sizeof(sequence_number)), 0);

    return EXPECT_RESULT();
}
#endif

/*
 * Make sure that we send the correct sequence number after a HelloVerifyRequest
 * and after a HelloRetryRequest. This is testing the server side as it is
 * operating statelessly and should copy the sequence number of the ClientHello.
 */
static int test_dtls_seq_num_downgrade(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLS_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls_seq_num_downgrade_check_num(test_ctx.s_buff,
            test_ctx.s_len, 0), TEST_SUCCESS);
    /* HVR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls_seq_num_downgrade_check_num(test_ctx.c_buff,
            test_ctx.c_len, 0), TEST_SUCCESS);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls_seq_num_downgrade_check_num(test_ctx.s_buff,
            test_ctx.s_len, 1), TEST_SUCCESS);
    /* Server first flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls_seq_num_downgrade_check_num(test_ctx.c_buff,
            test_ctx.c_len, 1), TEST_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/**
 * Make sure we don't send RSA Signature Hash Algorithms in the
 * CertificateRequest when we don't have any such ciphers set.
 * @return EXPECT_RESULT()
 */
static int test_certreq_sighash_algos(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_MAX_STRENGTH) && defined(HAVE_ECC) && \
    defined(WOLFSSL_SHA384) && defined(WOLFSSL_AES_256) && \
    defined(HAVE_AES_CBC) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int idx = 0;
    int maxIdx = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_ciphers = test_ctx.s_ciphers =
            "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA384";
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_c,
            "./certs/ca-ecc-cert.pem", NULL), WOLFSSL_SUCCESS);

    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_s, "./certs/ecc-key.pem",
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_s, "./certs/server-ecc.pem",
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_connect(ssl_c), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntEQ(wolfSSL_accept(ssl_s), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* Find the CertificateRequest message */
    for (idx = 0; idx < test_ctx.c_len && EXPECT_SUCCESS();) {
        word16 len;
        ExpectIntEQ(test_ctx.c_buff[idx++], handshake);
        ExpectIntEQ(test_ctx.c_buff[idx++], SSLv3_MAJOR);
        ExpectIntEQ(test_ctx.c_buff[idx++], TLSv1_2_MINOR);
        ato16(test_ctx.c_buff + idx, &len);
        idx += OPAQUE16_LEN;
        if (test_ctx.c_buff[idx] == certificate_request) {
            idx++;
            /* length */
            idx += OPAQUE24_LEN;
            /* cert types */
            idx += 1 + test_ctx.c_buff[idx];
            /* Sig algos */
            ato16(test_ctx.c_buff + idx, &len);
            idx += OPAQUE16_LEN;
            maxIdx = idx + (int)len;
            for (; idx < maxIdx && EXPECT_SUCCESS(); idx += OPAQUE16_LEN) {
                if (test_ctx.c_buff[idx+1] == ED25519_SA_MINOR ||
                        test_ctx.c_buff[idx+1] == ED448_SA_MINOR)
                    ExpectIntEQ(test_ctx.c_buff[idx], NEW_SA_MAJOR);
                else
                    ExpectIntEQ(test_ctx.c_buff[idx+1], ecc_dsa_sa_algo);
            }
            break;
        }
        else {
            idx += (int)len;
        }
    }
    ExpectIntLT(idx, test_ctx.c_len);


    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_CRL) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
static int test_revoked_loaded_int_cert_ctx_ready1(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, myVerify);
    myVerifyAction = VERIFY_USE_PREVERIFY;
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations_ex(ctx,
            "./certs/ca-cert.pem", NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations_ex(ctx,
            "./certs/intermediate/ca-int-cert.pem", NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
            "./certs/crl/extra-crls/ca-int-cert-revoked.pem",
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
            "./certs/crl/ca-int.pem",
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

static int test_revoked_loaded_int_cert_ctx_ready2(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, myVerify);
    myVerifyAction = VERIFY_USE_PREVERIFY;
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations_ex(ctx,
            "./certs/ca-cert.pem", NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations_ex(ctx,
            "./certs/intermediate/ca-int-cert.pem", NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations_ex(ctx,
            "./certs/intermediate/ca-int2-cert.pem", NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
            "./certs/crl/ca-int2.pem",
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
            "./certs/crl/extra-crls/ca-int-cert-revoked.pem",
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
            "./certs/crl/ca-int.pem",
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

static int test_revoked_loaded_int_cert_ctx_ready3_crl_missing_cb(int ret,
        WOLFSSL_CRL* crl, WOLFSSL_CERT_MANAGER* cm, void* ctx)
{
    (void)crl;
    (void)cm;
    (void)ctx;
    if (ret == WC_NO_ERR_TRACE(CRL_MISSING))
        return 1;
    return 0;
}

/* Here we are allowing missing CRL's but want to error out when its revoked */
static int test_revoked_loaded_int_cert_ctx_ready3(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, myVerify);
    myVerifyAction = VERIFY_USE_PREVERIFY;
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations_ex(ctx,
            "./certs/ca-cert.pem", NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations_ex(ctx,
            "./certs/intermediate/ca-int-cert.pem", NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations_ex(ctx,
            "./certs/intermediate/ca-int2-cert.pem", NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
            "./certs/crl/extra-crls/ca-int-cert-revoked.pem",
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetCRL_ErrorCb(ctx,
            test_revoked_loaded_int_cert_ctx_ready3_crl_missing_cb, NULL),
            WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}
#endif

static int test_revoked_loaded_int_cert(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CRL) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
    test_ssl_cbf client_cbf;
    test_ssl_cbf server_cbf;
    struct {
        const char* certPemFile;
        const char* keyPemFile;
        ctx_cb      client_ctx_ready;
    } test_params[] = {
        {"./certs/intermediate/ca-int2-cert.pem",
            "./certs/intermediate/ca-int2-key.pem",
            test_revoked_loaded_int_cert_ctx_ready1},
        {"./certs/intermediate/server-chain.pem",
            "./certs/server-key.pem", test_revoked_loaded_int_cert_ctx_ready2},
        {"./certs/intermediate/server-chain-short.pem",
            "./certs/server-key.pem", test_revoked_loaded_int_cert_ctx_ready2},
        {"./certs/intermediate/server-chain-short.pem",
            "./certs/server-key.pem", test_revoked_loaded_int_cert_ctx_ready3},
    };
    size_t i;

    printf("\n");

    for (i = 0; i < XELEM_CNT(test_params); i++) {
        XMEMSET(&client_cbf, 0, sizeof(client_cbf));
        XMEMSET(&server_cbf, 0, sizeof(server_cbf));

        printf("\tTesting with %s...\n", test_params[i].certPemFile);

        server_cbf.certPemFile = test_params[i].certPemFile;
        server_cbf.keyPemFile  = test_params[i].keyPemFile;

        client_cbf.ctx_ready = test_params[i].client_ctx_ready;

        ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbf,
            &server_cbf, NULL), -1001);
        ExpectIntEQ(client_cbf.last_err, WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
        ExpectIntEQ(server_cbf.last_err, WC_NO_ERR_TRACE(FATAL_ERROR));

        if (!EXPECT_SUCCESS())
            break;
        printf("\t%s passed\n", test_params[i].certPemFile);
    }
#endif
    return EXPECT_RESULT();
}

static int test_dtls13_frag_ch_pq(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(HAVE_LIBOQS)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char *test_str = "test";
    int test_str_size;
    byte buf[255];
#ifdef WOLFSSL_KYBER_ORIGINAL
    int group = WOLFSSL_KYBER_LEVEL5;
#else
    int group = WOLFSSL_ML_KEM_1024;
#endif

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    /* Add in a large post-quantum key share to make the CH long. */
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, group), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
#ifdef WOLFSSL_KYBER_ORIGINAL
    ExpectStrEQ(wolfSSL_get_curve_name(ssl_c), "KYBER_LEVEL5");
    ExpectStrEQ(wolfSSL_get_curve_name(ssl_s), "KYBER_LEVEL5");
#else
    ExpectStrEQ(wolfSSL_get_curve_name(ssl_c), "ML_KEM_1024");
    ExpectStrEQ(wolfSSL_get_curve_name(ssl_s), "ML_KEM_1024");
#endif
    test_str_size = XSTRLEN("test") + 1;
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, test_str_size), test_str_size);
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), test_str_size);
    ExpectIntEQ(XSTRCMP((char*)buf, test_str), 0);
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, test_str_size), test_str_size);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) \
    && defined(WOLFSSL_DTLS_MTU) && defined(WOLFSSL_DTLS_CH_FRAG)
static int test_dtls_frag_ch_count_records(byte* b, int len)
{
    DtlsRecordLayerHeader* dtlsRH;
    int records = 0;
    size_t recordLen;
    while (len > 0) {
        records++;
        dtlsRH = (DtlsRecordLayerHeader*)b;
        recordLen = (dtlsRH->length[0] << 8) | dtlsRH->length[1];
        if (recordLen > (size_t)len)
            break;
        b += sizeof(DtlsRecordLayerHeader) + recordLen;
        len -= sizeof(DtlsRecordLayerHeader) + recordLen;
    }
    return records;
}
#endif

static int test_dtls_frag_ch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_MTU) && defined(WOLFSSL_DTLS_CH_FRAG)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    static unsigned int DUMMY_MTU = 256;
    unsigned char four_frag_CH[] = {
      0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xda, 0x01, 0x00, 0x02, 0xdc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xce, 0xfe, 0xfd, 0xf3, 0x94, 0x01, 0x33, 0x2c, 0xcf, 0x2c, 0x47, 0xb1,
      0xe5, 0xa1, 0x7b, 0x19, 0x3e, 0xac, 0x68, 0xdd, 0xe6, 0x17, 0x6b, 0x85,
      0xad, 0x5f, 0xfc, 0x7f, 0x6e, 0xf0, 0xb9, 0xe0, 0x2e, 0xca, 0x47, 0x00,
      0x00, 0x00, 0x36, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0,
      0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0x00, 0x9f, 0x00, 0x9e, 0xcc, 0xa9, 0xcc,
      0xa8, 0xcc, 0xaa, 0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x28, 0xc0, 0x24, 0xc0,
      0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x6b, 0x00, 0x67, 0x00,
      0x39, 0x00, 0x33, 0xcc, 0x14, 0xcc, 0x13, 0xcc, 0x15, 0x01, 0x00, 0x02,
      0x7c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc, 0x00, 0x0d, 0x00, 0x20,
      0x00, 0x1e, 0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x02, 0x03, 0x08, 0x06,
      0x08, 0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08, 0x09, 0x06, 0x01,
      0x05, 0x01, 0x04, 0x01, 0x03, 0x01, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x0c,
      0x00, 0x0a, 0x00, 0x19, 0x00, 0x18, 0x00, 0x17, 0x00, 0x15, 0x01, 0x00,
      0x00, 0x16, 0x00, 0x00, 0x00, 0x33, 0x02, 0x39, 0x02, 0x37, 0x00, 0x17,
      0x00, 0x41, 0x04, 0x94, 0xdf, 0x36, 0xd7, 0xb3, 0x90, 0x6d, 0x01, 0xa1,
      0xe6, 0xed, 0x67, 0xf4, 0xd9, 0x9d, 0x2c, 0xac, 0x57, 0x74, 0xff, 0x19,
      0xbe, 0x5a, 0xc9, 0x30, 0x11, 0xb7, 0x2b, 0x59, 0x47, 0x80, 0x7c, 0xa9,
      0xb7, 0x31, 0x8c, 0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x00, 0xda, 0x01, 0x00, 0x02, 0xdc, 0x00, 0x00, 0x00, 0x00,
      0xce, 0x00, 0x00, 0xce, 0x9e, 0x13, 0x74, 0x3b, 0x86, 0xba, 0x69, 0x1f,
      0x12, 0xf7, 0xcd, 0x78, 0x53, 0xe8, 0x50, 0x4d, 0x71, 0x3f, 0x4b, 0x4e,
      0xeb, 0x3e, 0xe5, 0x43, 0x54, 0x78, 0x17, 0x6d, 0x00, 0x18, 0x00, 0x61,
      0x04, 0xd1, 0x99, 0x66, 0x4f, 0xda, 0xc7, 0x12, 0x3b, 0xff, 0xb2, 0xd6,
      0x2f, 0x35, 0xb6, 0x17, 0x1f, 0xb3, 0xd0, 0xb6, 0x52, 0xff, 0x97, 0x8b,
      0x01, 0xe8, 0xd9, 0x68, 0x71, 0x40, 0x02, 0xd5, 0x68, 0x3a, 0x58, 0xb2,
      0x5d, 0xee, 0xa4, 0xe9, 0x5f, 0xf4, 0xaf, 0x3e, 0x30, 0x9c, 0x3e, 0x2b,
      0xda, 0x61, 0x43, 0x99, 0x02, 0x35, 0x33, 0x9f, 0xcf, 0xb5, 0xd3, 0x28,
      0x19, 0x9d, 0x1c, 0xbe, 0x69, 0x07, 0x9e, 0xfc, 0xe4, 0x8e, 0xcd, 0x86,
      0x4a, 0x1b, 0xf0, 0xfc, 0x17, 0x94, 0x66, 0x53, 0xda, 0x24, 0x5e, 0xaf,
      0xce, 0xec, 0x62, 0x4c, 0x06, 0xb4, 0x52, 0x94, 0xb1, 0x4a, 0x7a, 0x8c,
      0x4f, 0x00, 0x19, 0x00, 0x85, 0x04, 0x00, 0x27, 0xeb, 0x99, 0x49, 0x7f,
      0xcb, 0x2c, 0x46, 0x54, 0x2d, 0x93, 0x5d, 0x25, 0x92, 0x58, 0x5e, 0x06,
      0xc3, 0x7c, 0xfb, 0x9a, 0xa7, 0xec, 0xcd, 0x9f, 0xe1, 0x6b, 0x2d, 0x78,
      0xf5, 0x16, 0xa9, 0x20, 0x52, 0x48, 0x19, 0x0f, 0x1a, 0xd0, 0xce, 0xd8,
      0x68, 0xb1, 0x4e, 0x7f, 0x33, 0x03, 0x7d, 0x0c, 0x39, 0xdb, 0x9c, 0x4b,
      0xf4, 0xe7, 0xc2, 0xf5, 0xdd, 0x51, 0x9b, 0x03, 0xa8, 0x53, 0x2b, 0xe6,
      0x00, 0x15, 0x4b, 0xff, 0xd2, 0xa0, 0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xda, 0x01, 0x00, 0x02, 0xdc, 0x00,
      0x00, 0x00, 0x01, 0x9c, 0x00, 0x00, 0xce, 0x58, 0x30, 0x10, 0x3d, 0x46,
      0xcc, 0xca, 0x1a, 0x44, 0xc8, 0x58, 0x9b, 0x27, 0x17, 0x67, 0x31, 0x96,
      0x8a, 0x66, 0x39, 0xf4, 0xcc, 0xc1, 0x9f, 0x12, 0x1f, 0x01, 0x30, 0x50,
      0x16, 0xd6, 0x89, 0x97, 0xa3, 0x66, 0xd7, 0x99, 0x50, 0x09, 0x6e, 0x80,
      0x87, 0xe4, 0xa2, 0x88, 0xae, 0xb4, 0x23, 0x57, 0x2f, 0x12, 0x60, 0xe7,
      0x7d, 0x44, 0x2d, 0xad, 0xbe, 0xe9, 0x0d, 0x01, 0x00, 0x01, 0x00, 0xd5,
      0xdd, 0x62, 0xee, 0xf3, 0x0e, 0xd9, 0x30, 0x0e, 0x38, 0xf3, 0x48, 0xf4,
      0xc9, 0x8f, 0x8c, 0x20, 0xf7, 0xd3, 0xa8, 0xb3, 0x87, 0x3c, 0x98, 0x5d,
      0x70, 0xc5, 0x03, 0x76, 0xb7, 0xd5, 0x0b, 0x7b, 0x23, 0x97, 0x6b, 0xe3,
      0xb5, 0x18, 0xeb, 0x64, 0x55, 0x18, 0xb2, 0x8a, 0x90, 0x1a, 0x8f, 0x0e,
      0x15, 0xda, 0xb1, 0x8e, 0x7f, 0xee, 0x1f, 0xe0, 0x3b, 0xb9, 0xed, 0xfc,
      0x4e, 0x3f, 0x78, 0x16, 0x39, 0x95, 0x5f, 0xb7, 0xcb, 0x65, 0x55, 0x72,
      0x7b, 0x7d, 0x86, 0x2f, 0x8a, 0xe5, 0xee, 0xf7, 0x57, 0x40, 0xf3, 0xc4,
      0x96, 0x4f, 0x11, 0x4d, 0x85, 0xf9, 0x56, 0xfa, 0x3d, 0xf0, 0xc9, 0xa4,
      0xec, 0x1e, 0xaa, 0x47, 0x90, 0x53, 0xdf, 0xe1, 0xb7, 0x78, 0x18, 0xeb,
      0xdd, 0x0d, 0x89, 0xb7, 0xf6, 0x15, 0x0e, 0x55, 0x12, 0xb3, 0x23, 0x17,
      0x0b, 0x59, 0x6f, 0x83, 0x05, 0x6b, 0xa6, 0xf8, 0x6c, 0x3a, 0x9b, 0x1b,
      0x50, 0x93, 0x51, 0xea, 0x95, 0x2d, 0x99, 0x96, 0x38, 0x16, 0xfe, 0xfd,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x7e, 0x01, 0x00,
      0x02, 0xdc, 0x00, 0x00, 0x00, 0x02, 0x6a, 0x00, 0x00, 0x72, 0x2d, 0x66,
      0x3e, 0xf2, 0x36, 0x5a, 0xf2, 0x23, 0x8f, 0x28, 0x09, 0xa9, 0x55, 0x8c,
      0x8f, 0xc0, 0x0d, 0x61, 0x98, 0x33, 0x56, 0x87, 0x7a, 0xfd, 0xa7, 0x50,
      0x71, 0x84, 0x2e, 0x41, 0x58, 0x00, 0x87, 0xd9, 0x27, 0xe5, 0x7b, 0xf4,
      0x6d, 0x84, 0x4e, 0x2e, 0x0c, 0x80, 0x0c, 0xf3, 0x8a, 0x02, 0x4b, 0x99,
      0x3a, 0x1f, 0x9f, 0x18, 0x7d, 0x1c, 0xec, 0xad, 0x60, 0x54, 0xa6, 0xa3,
      0x2c, 0x82, 0x5e, 0xf8, 0x8f, 0xae, 0xe1, 0xc4, 0x82, 0x7e, 0x43, 0x43,
      0xc5, 0x99, 0x49, 0x05, 0xd3, 0xf6, 0xdf, 0xa1, 0xb5, 0x2d, 0x0c, 0x13,
      0x2f, 0x1e, 0xb6, 0x28, 0x7c, 0x5c, 0xa1, 0x02, 0x6b, 0x8d, 0xa3, 0xeb,
      0xd4, 0x58, 0xe6, 0xa0, 0x7e, 0x6b, 0xaa, 0x09, 0x43, 0x67, 0x71, 0x87,
      0xa5, 0xcb, 0x68, 0xf3
    };

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* Fragment msgs */
    ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_c, DUMMY_MTU), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_s, DUMMY_MTU), WOLFSSL_SUCCESS);

    /* Add in some key shares to make the CH long */
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_ECC_SECP256R1),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_ECC_SECP384R1),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_ECC_SECP521R1),
            WOLFSSL_SUCCESS);
#ifdef HAVE_FFDHE_2048
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_FFDHE_2048),
            WOLFSSL_SUCCESS);
#endif
#ifdef HAVE_FFDHE_3072
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_FFDHE_3072),
            WOLFSSL_SUCCESS);
#endif
#ifdef HAVE_FFDHE_4096
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_FFDHE_4096),
            WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1), WOLFSSL_SUCCESS);

    /* Reject fragmented first CH */
    ExpectIntEQ(test_dtls_frag_ch_count_records(four_frag_CH,
            sizeof(four_frag_CH)), 4);
    XMEMCPY(test_ctx.s_buff, four_frag_CH, sizeof(four_frag_CH));
    test_ctx.s_len = sizeof(four_frag_CH);
    while (test_ctx.s_len > 0 && EXPECT_SUCCESS()) {
        int s_len = test_ctx.s_len;
        ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
        /* Fail if we didn't advance the buffer to avoid infinite loops */
        ExpectIntLT(test_ctx.s_len, s_len);
    }
    /* Expect all fragments read */
    ExpectIntEQ(test_ctx.s_len, 0);
    /* Expect quietly dropping fragmented first CH */
    ExpectIntEQ(test_ctx.c_len, 0);

#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH)
    /* Disable ECH as it pushes it over our MTU */
    wolfSSL_SetEchEnable(ssl_c, 0);
#endif

    /* Limit options to make the CH a fixed length */
    /* See wolfSSL_parse_cipher_list for reason why we provide 1.3 AND 1.2
     * ciphersuite. This is only necessary when building with OPENSSL_EXTRA. */
#ifdef OPENSSL_EXTRA
    ExpectTrue(wolfSSL_set_cipher_list(ssl_c, "TLS13-AES256-GCM-SHA384"
                                       ":DHE-RSA-AES256-GCM-SHA384"));
#else
    ExpectTrue(wolfSSL_set_cipher_list(ssl_c, "TLS13-AES256-GCM-SHA384"));
#endif

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Count records. Expect 1 unfragmented CH */
    ExpectIntEQ(test_dtls_frag_ch_count_records(test_ctx.s_buff,
            test_ctx.s_len), 1);
    /* HRR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Count records. Expect fragmented CH */
    ExpectIntGT(test_dtls_frag_ch_count_records(test_ctx.s_buff,
            test_ctx.s_len), 1);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;
#endif
    return EXPECT_RESULT();
}

static int test_dtls_empty_keyshare_with_cookie(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char ch_empty_keyshare_with_cookie[] = {
        0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
        0x12, 0x01, 0x00, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0xfe, 0xfd, 0xfb, 0x8c, 0x9b, 0x28, 0xae, 0x50, 0x1c, 0x4d, 0xf3,
        0xb8, 0xcf, 0x4d, 0xd8, 0x7e, 0x93, 0x13, 0x7b, 0x9e, 0xd9, 0xeb, 0xe9,
        0x13, 0x4b, 0x0d, 0x7f, 0x2e, 0x43, 0x62, 0x8c, 0xe4, 0x57, 0x79, 0x00,
        0x00, 0x00, 0x36, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0,
        0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0x00, 0x9f, 0x00, 0x9e, 0xcc, 0xa9, 0xcc,
        0xa8, 0xcc, 0xaa, 0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x28, 0xc0, 0x24, 0xc0,
        0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x6b, 0x00, 0x67, 0x00,
        0x39, 0x00, 0x33, 0xcc, 0x14, 0xcc, 0x13, 0xcc, 0x15, 0x01, 0x00, 0x00,
        0xa6, 0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc, 0x00, 0x2c, 0x00, 0x47,
        0x00, 0x45, 0x20, 0xee, 0x4b, 0x17, 0x70, 0x63, 0xa0, 0x4c, 0x82, 0xbf,
        0x43, 0x01, 0x7d, 0x8d, 0xc1, 0x1b, 0x4e, 0x9b, 0xa0, 0x3c, 0x53, 0x1f,
        0xb7, 0xd1, 0x10, 0x81, 0xa8, 0xdf, 0xdf, 0x8c, 0x7f, 0xf3, 0x11, 0x13,
        0x01, 0x02, 0x3d, 0x3b, 0x7d, 0x14, 0x2c, 0x31, 0xb3, 0x60, 0x72, 0x4d,
        0xe5, 0x1a, 0xb2, 0xa3, 0x61, 0x77, 0x73, 0x03, 0x40, 0x0e, 0x5f, 0xc5,
        0x61, 0x38, 0x43, 0x56, 0x21, 0x4a, 0x95, 0xd5, 0x35, 0xa8, 0x0d, 0x00,
        0x0d, 0x00, 0x2a, 0x00, 0x28, 0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x02,
        0x03, 0xfe, 0x0b, 0xfe, 0x0e, 0xfe, 0xa0, 0xfe, 0xa3, 0xfe, 0xa5, 0x08,
        0x06, 0x08, 0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08, 0x09, 0x06,
        0x01, 0x05, 0x01, 0x04, 0x01, 0x03, 0x01, 0x02, 0x01, 0x00, 0x0a, 0x00,
        0x18, 0x00, 0x16, 0x00, 0x19, 0x00, 0x18, 0x00, 0x17, 0x00, 0x15, 0x01,
        0x00, 0x02, 0x3a, 0x02, 0x3c, 0x02, 0x3d, 0x2f, 0x3a, 0x2f, 0x3c, 0x2f,
        0x3d, 0x00, 0x16, 0x00, 0x00, 0x00, 0x33, 0x00, 0x02, 0x00, 0x00
    };
    DtlsRecordLayerHeader* dtlsRH;
    byte sequence_number[8];

    XMEMSET(&sequence_number, 0, sizeof(sequence_number));
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMCPY(test_ctx.s_buff, ch_empty_keyshare_with_cookie,
            sizeof(ch_empty_keyshare_with_cookie));
    test_ctx.s_len = sizeof(ch_empty_keyshare_with_cookie);
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
        NULL, wolfDTLSv1_3_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Expect an alert. A plaintext alert should be exactly 15 bytes. */
    ExpectIntEQ(test_ctx.c_len, 15);
    dtlsRH = (DtlsRecordLayerHeader*)test_ctx.c_buff;
    ExpectIntEQ(dtlsRH->type, alert);
    ExpectIntEQ(dtlsRH->pvMajor, DTLS_MAJOR);
    ExpectIntEQ(dtlsRH->pvMinor, DTLSv1_2_MINOR);
    sequence_number[7] = 1;
    ExpectIntEQ(XMEMCMP(sequence_number, dtlsRH->sequence_number,
            sizeof(sequence_number)), 0);
    ExpectIntEQ(dtlsRH->length[0], 0);
    ExpectIntEQ(dtlsRH->length[1], 2);
    ExpectIntEQ(test_ctx.c_buff[13], alert_fatal);
    ExpectIntEQ(test_ctx.c_buff[14], illegal_parameter);

    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

static int test_dtls_old_seq_number(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HVR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client second flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Modify the sequence number */
    {
        DtlsRecordLayerHeader* dtlsRH = (DtlsRecordLayerHeader*)test_ctx.s_buff;
        XMEMSET(dtlsRH->sequence_number, 0, sizeof(dtlsRH->sequence_number));
    }
    /* Server second flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server should not do anything as a pkt was dropped */
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_ctx.s_len, 0);
    /* Trigger rtx */
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);

    /* Complete connection */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

static int test_dtls12_missing_finished(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char test_str[] = "test string";
    char test_buf[sizeof(test_str)];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HVR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
    /* Let's clear the output */
    test_ctx.c_len = 0;
    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_s, test_str, sizeof(test_str)),
                sizeof(test_str));
    /* Client should not error out on a missing finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server rtx second flight with finished */
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), 1);
    /* Client process rest of handshake */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);

    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_s, test_str, sizeof(test_str)),
                sizeof(test_str));
    ExpectIntEQ(wolfSSL_read(ssl_c, test_buf, sizeof(test_buf)),
                sizeof(test_str));
    ExpectBufEQ(test_buf, test_str, sizeof(test_str));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

static int test_dtls13_missing_finished_client(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char test_str[] = "test string";
    char test_buf[sizeof(test_str)];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HRR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Let's clear the output */
    test_ctx.c_len = 0;
    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_s, test_str, sizeof(test_str)),
                sizeof(test_str));
    /* Client second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server should not error out on a missing finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client rtx second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
    /* Client */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);
    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_s, test_str, sizeof(test_str)),
                sizeof(test_str));
    ExpectIntEQ(wolfSSL_read(ssl_c, test_buf, sizeof(test_buf)),
                sizeof(test_str));
    ExpectBufEQ(test_buf, test_str, sizeof(test_str));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

static int test_dtls13_missing_finished_server(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char test_str[] = "test string";
    char test_buf[sizeof(test_str)];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HRR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Let's clear the output */
    test_ctx.s_len = 0;
    /* We should signal that the handshake is done */
    ExpectTrue(wolfSSL_is_init_finished(ssl_c));
    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, sizeof(test_str)),
                sizeof(test_str));
    /* Server should not error out on a missing finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client rtx second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, sizeof(test_str)),
                sizeof(test_str));
    ExpectIntEQ(wolfSSL_read(ssl_s, test_buf, sizeof(test_buf)),
                sizeof(test_str));
    ExpectBufEQ(test_buf, test_str, sizeof(test_str));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_LIBOQS)
static void test_tls13_pq_groups_ctx_ready(WOLFSSL_CTX* ctx)
{
#ifdef WOLFSSL_KYBER_ORIGINAL
    int group = WOLFSSL_KYBER_LEVEL5;
#else
    int group = WOLFSSL_ML_KEM_1024;
#endif
    AssertIntEQ(wolfSSL_CTX_set_groups(ctx, &group, 1), WOLFSSL_SUCCESS);
}

static void test_tls13_pq_groups_on_result(WOLFSSL* ssl)
{
#ifdef WOLFSSL_KYBER_ORIGINAL
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "KYBER_LEVEL5");
#else
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "ML_KEM_1024");
#endif
}
#endif

static int test_tls13_pq_groups(void)
{
    EXPECT_DECLS;
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_LIBOQS)
    callback_functions func_cb_client;
    callback_functions func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
    XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

    func_cb_client.method = wolfTLSv1_3_client_method;
    func_cb_server.method = wolfTLSv1_3_server_method;
    func_cb_client.ctx_ready = test_tls13_pq_groups_ctx_ready;
    func_cb_client.on_result = test_tls13_pq_groups_on_result;
    func_cb_server.on_result = test_tls13_pq_groups_on_result;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

static int test_tls13_early_data(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_EARLY_DATA) && defined(HAVE_SESSION_TICKET)
    int written = 0;
    int read = 0;
    size_t i;
    int splitEarlyData;
    char msg[] = "This is early data";
    char msg2[] = "This is client data";
    char msg3[] = "This is server data";
    char msg4[] = "This is server immediate data";
    char msgBuf[50];
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* tls_version;
        int isUdp;
    } params[] = {
#ifdef WOLFSSL_TLS13
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
                "TLS 1.3", 0 },
#endif
#ifdef WOLFSSL_DTLS13
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                "DTLS 1.3", 1 },
#endif
    };

    for (i = 0; i < sizeof(params)/sizeof(*params) && !EXPECT_FAIL(); i++) {
        for (splitEarlyData = 0; splitEarlyData < 2; splitEarlyData++) {
            struct test_memio_ctx test_ctx;
            WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
            WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
            WOLFSSL_SESSION *sess = NULL;

            XMEMSET(&test_ctx, 0, sizeof(test_ctx));

            fprintf(stderr, "\tEarly data with %s\n", params[i].tls_version);

            ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
                    &ssl_s, params[i].client_meth, params[i].server_meth), 0);

            /* Get a ticket so that we can do 0-RTT on the next connection */
            ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
            /* Make sure we read the ticket */
            ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

            wolfSSL_free(ssl_c);
            ssl_c = NULL;
            wolfSSL_free(ssl_s);
            ssl_s = NULL;
            XMEMSET(&test_ctx, 0, sizeof(test_ctx));
            ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    params[i].client_meth, params[i].server_meth), 0);
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
#ifdef WOLFSSL_DTLS13
            if (params[i].isUdp) {
                wolfSSL_SetLoggingPrefix("server");
#ifdef WOLFSSL_DTLS13_NO_HRR_ON_RESUME
                ExpectIntEQ(wolfSSL_dtls13_no_hrr_on_resume(ssl_s, 1), WOLFSSL_SUCCESS);
#else
                /* Let's test this but we generally don't recommend turning off the
                 * cookie exchange */
                ExpectIntEQ(wolfSSL_disable_hrr_cookie(ssl_s), WOLFSSL_SUCCESS);
#endif
            }
#endif

            /* Test 0-RTT data */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_write_early_data(ssl_c, msg, sizeof(msg),
                    &written), sizeof(msg));
            ExpectIntEQ(written, sizeof(msg));

            if (splitEarlyData) {
                ExpectIntEQ(wolfSSL_write_early_data(ssl_c, msg, sizeof(msg),
                        &written), sizeof(msg));
                ExpectIntEQ(written, sizeof(msg));
            }

            /* Read first 0-RTT data (if split otherwise entire data) */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_read_early_data(ssl_s, msgBuf, sizeof(msgBuf),
                    &read), sizeof(msg));
            ExpectIntEQ(read, sizeof(msg));
            ExpectStrEQ(msg, msgBuf);

            /* Test 0.5-RTT data */
            ExpectIntEQ(wolfSSL_write(ssl_s, msg4, sizeof(msg4)), sizeof(msg4));

            if (splitEarlyData) {
                /* Read second 0-RTT data */
                ExpectIntEQ(wolfSSL_read_early_data(ssl_s, msgBuf, sizeof(msgBuf),
                        &read), sizeof(msg));
                ExpectIntEQ(read, sizeof(msg));
                ExpectStrEQ(msg, msgBuf);
            }

            if (params[i].isUdp) {
                wolfSSL_SetLoggingPrefix("client");
                ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
                ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WC_NO_ERR_TRACE(APP_DATA_READY));

                /* Read server 0.5-RTT data */
                ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)), sizeof(msg4));
                ExpectStrEQ(msg4, msgBuf);

                /* Complete handshake */
                ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
                ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
                /* Use wolfSSL_is_init_finished to check if handshake is complete. Normally
                 * a user would loop until it is true but here we control both sides so we
                 * just assert the expected value. wolfSSL_read_early_data does not provide
                 * handshake status to us with non-blocking IO and we can't use
                 * wolfSSL_accept as TLS layer may return ZERO_RETURN due to early data
                 * parsing logic. */
                wolfSSL_SetLoggingPrefix("server");
                ExpectFalse(wolfSSL_is_init_finished(ssl_s));
                ExpectIntEQ(wolfSSL_read_early_data(ssl_s, msgBuf, sizeof(msgBuf),
                        &read), 0);
                ExpectIntEQ(read, 0);
                ExpectTrue(wolfSSL_is_init_finished(ssl_s));

                wolfSSL_SetLoggingPrefix("client");
                ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
            }
            else {
                wolfSSL_SetLoggingPrefix("client");
                ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);

                wolfSSL_SetLoggingPrefix("server");
                ExpectFalse(wolfSSL_is_init_finished(ssl_s));
                ExpectIntEQ(wolfSSL_read_early_data(ssl_s, msgBuf, sizeof(msgBuf),
                        &read), 0);
                ExpectIntEQ(read, 0);
                ExpectTrue(wolfSSL_is_init_finished(ssl_s));

                /* Read server 0.5-RTT data */
                wolfSSL_SetLoggingPrefix("client");
                ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)), sizeof(msg4));
                ExpectStrEQ(msg4, msgBuf);
            }

            /* Test bi-directional write */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_write(ssl_c, msg2, sizeof(msg2)), sizeof(msg2));
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_read(ssl_s, msgBuf, sizeof(msgBuf)), sizeof(msg2));
            ExpectStrEQ(msg2, msgBuf);
            ExpectIntEQ(wolfSSL_write(ssl_s, msg3, sizeof(msg3)), sizeof(msg3));
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)), sizeof(msg3));
            ExpectStrEQ(msg3, msgBuf);

            wolfSSL_SetLoggingPrefix(NULL);
            ExpectTrue(wolfSSL_session_reused(ssl_c));
            ExpectTrue(wolfSSL_session_reused(ssl_s));

            wolfSSL_SESSION_free(sess);
            wolfSSL_free(ssl_c);
            wolfSSL_free(ssl_s);
            wolfSSL_CTX_free(ctx_c);
            wolfSSL_CTX_free(ctx_s);
        }
    }
#endif
    return EXPECT_RESULT();
}

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
static int test_self_signed_stapling_client_v1_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), 1);
    ExpectIntEQ(wolfSSL_CTX_UseOCSPStapling(ctx, WOLFSSL_CSR_OCSP,
            WOLFSSL_CSR_OCSP_USE_NONCE), 1);
    return EXPECT_RESULT();
}
#endif

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
static int test_self_signed_stapling_client_v2_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), 1);
    ExpectIntEQ(wolfSSL_CTX_UseOCSPStaplingV2(ctx, WOLFSSL_CSR2_OCSP,
            WOLFSSL_CSR2_OCSP_USE_NONCE), 1);
    return EXPECT_RESULT();
}

static int test_self_signed_stapling_client_v2_multi_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), 1);
    ExpectIntEQ(wolfSSL_CTX_UseOCSPStaplingV2(ctx, WOLFSSL_CSR2_OCSP_MULTI,
            0), 1);
    return EXPECT_RESULT();
}
#endif

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
static int test_self_signed_stapling_server_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), 1);
    return EXPECT_RESULT();
}
#endif

static int test_self_signed_stapling(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
    test_ssl_cbf client_cbf;
    test_ssl_cbf server_cbf;
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        ctx_cb client_ctx;
        const char* tls_version;
    } params[] = {
#if defined(WOLFSSL_TLS13) && defined(HAVE_CERTIFICATE_STATUS_REQUEST)
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            test_self_signed_stapling_client_v1_ctx_ready, "TLSv1_3 v1" },
#endif
#ifndef WOLFSSL_NO_TLS12
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
            test_self_signed_stapling_client_v1_ctx_ready, "TLSv1_2 v1" },
#endif
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
            test_self_signed_stapling_client_v2_ctx_ready, "TLSv1_2 v2" },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
            test_self_signed_stapling_client_v2_multi_ctx_ready,
            "TLSv1_2 v2 multi" },
#endif
#endif
    };

    for (i = 0; i < sizeof(params)/sizeof(*params) && !EXPECT_FAIL(); i++) {
        XMEMSET(&client_cbf, 0, sizeof(client_cbf));
        XMEMSET(&server_cbf, 0, sizeof(server_cbf));

        printf("\nTesting self-signed cert with status request: %s\n",
                params[i].tls_version);

        client_cbf.method = params[i].client_meth;
        client_cbf.ctx_ready = params[i].client_ctx;

        server_cbf.method = params[i].server_meth;
        server_cbf.certPemFile = "certs/ca-cert.pem";
        server_cbf.keyPemFile  = "certs/ca-key.pem";
        server_cbf.ctx_ready = test_self_signed_stapling_server_ctx_ready;

        ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbf,
            &server_cbf, NULL), TEST_SUCCESS);
    }
#endif
    return EXPECT_RESULT();
}

static int test_tls_multi_handshakes_one_record(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    RecordLayerHeader* rh = NULL;
    byte   *len ;
    int newRecIdx = RECORD_HEADER_SZ;
    int idx = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLS_client_method, wolfTLSv1_2_server_method), 0);

    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Combine server handshake msgs into one record */
    while (idx < test_ctx.c_len) {
        word16 recLen;

        rh = (RecordLayerHeader*)(test_ctx.c_buff + idx);
        len = &rh->length[0];

        ato16((const byte*)len, &recLen);
        idx += RECORD_HEADER_SZ;

        XMEMMOVE(test_ctx.c_buff + newRecIdx, test_ctx.c_buff + idx,
                (size_t)recLen);

        newRecIdx += recLen;
        idx += recLen;
    }
    rh = (RecordLayerHeader*)(test_ctx.c_buff);
    len = &rh->length[0];
    c16toa((word16)newRecIdx - RECORD_HEADER_SZ, len);
    test_ctx.c_len = newRecIdx;

    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


static int test_write_dup(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(HAVE_WRITE_DUP)
    size_t i, j;
    char hiWorld[] = "dup message";
    char readData[sizeof(hiWorld) + 5];
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* version_name;
        int version;
    } methods[] = {
#ifndef WOLFSSL_NO_TLS12
        {wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLS 1.2", WOLFSSL_TLSV1_2},
#endif
#ifdef WOLFSSL_TLS13
        {wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, "TLS 1.3", WOLFSSL_TLSV1_3},
#endif
    };
    struct {
        const char* cipher;
        int version;
    } ciphers[] = {
/* For simplicity the macros are copied from internal.h */
/* TLS 1.2 */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && !defined(NO_SHA256)
    #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
        #ifndef NO_RSA
            {"ECDHE-RSA-CHACHA20-POLY1305", WOLFSSL_TLSV1_2},
        #endif
    #endif
    #if !defined(NO_DH) && !defined(NO_RSA) && !defined(NO_TLS_DH)
        {"DHE-RSA-CHACHA20-POLY1305", WOLFSSL_TLSV1_2},
    #endif
#endif
#if !defined(NO_DH) && !defined(NO_AES) && !defined(NO_TLS) && \
    !defined(NO_RSA) && defined(HAVE_AESGCM) && !defined(NO_TLS_DH)
    #if !defined(NO_SHA256) && defined(WOLFSSL_AES_128)
        {"DHE-RSA-AES128-GCM-SHA256", WOLFSSL_TLSV1_2},
    #endif
    #if defined(WOLFSSL_SHA384) && defined(WOLFSSL_AES_256)
        {"DHE-RSA-AES256-GCM-SHA384", WOLFSSL_TLSV1_2},
    #endif
#endif
#if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)) \
                                         && !defined(NO_TLS) && !defined(NO_AES)
    #ifdef HAVE_AESGCM
        #if !defined(NO_SHA256) && defined(WOLFSSL_AES_128)
            #ifndef NO_RSA
                {"ECDHE-RSA-AES128-GCM-SHA256", WOLFSSL_TLSV1_2},
            #endif
        #endif
        #if defined(WOLFSSL_SHA384) && defined(WOLFSSL_AES_256)
            #ifndef NO_RSA
                {"ECDHE-RSA-AES256-GCM-SHA384", WOLFSSL_TLSV1_2},
            #endif
        #endif
    #endif
#endif
/* TLS 1.3 */
#ifdef WOLFSSL_TLS13
    #ifdef HAVE_AESGCM
        #if !defined(NO_SHA256) && defined(WOLFSSL_AES_128)
            {"TLS13-AES128-GCM-SHA256", WOLFSSL_TLSV1_3},
        #endif
        #if defined(WOLFSSL_SHA384) && defined(WOLFSSL_AES_256)
            {"TLS13-AES256-GCM-SHA384", WOLFSSL_TLSV1_3},
        #endif
    #endif
    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        #ifndef NO_SHA256
            {"TLS13-CHACHA20-POLY1305-SHA256", WOLFSSL_TLSV1_3},
        #endif
    #endif
    #ifdef HAVE_AESCCM
        #if !defined(NO_SHA256) && defined(WOLFSSL_AES_128)
            {"TLS13-AES128-CCM-SHA256", WOLFSSL_TLSV1_3},
        #endif
    #endif
#endif
    };

    for (i = 0; i < XELEM_CNT(methods); i++) {
        for (j = 0; j < XELEM_CNT(ciphers) && !EXPECT_FAIL(); j++) {
            struct test_memio_ctx test_ctx;
            WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
            WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
            WOLFSSL *ssl_c2 = NULL;

            if (methods[i].version != ciphers[j].version)
                continue;

            if (i == 0 && j == 0)
                printf("\n");

            printf("Testing %s with %s... ", methods[i].version_name,
                    ciphers[j].cipher);

            XMEMSET(&test_ctx, 0, sizeof(test_ctx));

            test_ctx.c_ciphers = test_ctx.s_ciphers = ciphers[j].cipher;

            ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    methods[i].client_meth, methods[i].server_meth), 0);
            ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

            ExpectNotNull(ssl_c2 = wolfSSL_write_dup(ssl_c));
            ExpectIntEQ(wolfSSL_write(ssl_c, hiWorld, sizeof(hiWorld)),
                    WC_NO_ERR_TRACE(WRITE_DUP_WRITE_E));
            ExpectIntEQ(wolfSSL_write(ssl_c2, hiWorld, sizeof(hiWorld)),
                    sizeof(hiWorld));

            ExpectIntEQ(wolfSSL_read(ssl_s, readData, sizeof(readData)),
                    sizeof(hiWorld));
            ExpectIntEQ(wolfSSL_write(ssl_s, hiWorld, sizeof(hiWorld)),
                    sizeof(hiWorld));

            ExpectIntEQ(wolfSSL_read(ssl_c2, readData, sizeof(readData)),
                    WC_NO_ERR_TRACE(WRITE_DUP_READ_E));
            ExpectIntEQ(wolfSSL_read(ssl_c, readData, sizeof(readData)),
                    sizeof(hiWorld));

            if (EXPECT_SUCCESS())
                printf("ok\n");
            else
                printf("failed\n");

            wolfSSL_free(ssl_c);
            wolfSSL_free(ssl_c2);
            wolfSSL_free(ssl_s);
            wolfSSL_CTX_free(ctx_c);
            wolfSSL_CTX_free(ctx_s);
        }
    }
#endif
    return EXPECT_RESULT();
}

static int test_read_write_hs(void)
{

    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_s = NULL, *ctx_c = NULL;
    WOLFSSL *ssl_s = NULL, *ssl_c = NULL;
    struct test_memio_ctx test_ctx;
    byte test_buffer[16];
    unsigned int test;

    /* test == 0 : client writes, server reads */
    /* test == 1 : server writes, client reads */
    for (test = 0; test < 2; test++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s,  &ssl_c, &ssl_s,
                                     wolfTLSv1_2_client_method,
                                     wolfTLSv1_2_server_method), 0);
        ExpectIntEQ(wolfSSL_set_group_messages(ssl_s), WOLFSSL_SUCCESS);
        /* CH -> */
        if (test == 0) {
            ExpectIntEQ(wolfSSL_write(ssl_c, "hello", 5), -1);
        } else {
            ExpectIntEQ(wolfSSL_read(ssl_c, test_buffer,
                                     sizeof(test_buffer)),  -1);
        }
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

        /* <- SH + SKE + SHD */
        if (test == 0) {
            ExpectIntEQ(wolfSSL_read(ssl_s, test_buffer,
                                     sizeof(test_buffer)), -1);
        } else {
            ExpectIntEQ(wolfSSL_write(ssl_s, "hello", 5), -1);
        }
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

        /* -> CKE + CLIENT FINISHED */
        if (test == 0) {
            ExpectIntEQ(wolfSSL_write(ssl_c, "hello", 5), -1);
        } else {
            ExpectIntEQ(wolfSSL_read(ssl_c, test_buffer,
                                     sizeof(test_buffer)), -1);
        }
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

        /* abide clang static analyzer */
        if (ssl_s != NULL) {
            /* disable group message to separate sending of ChangeCipherspec
             * from Finished */
            ssl_s->options.groupMessages = 0;
        }
        /* allow writing of CS, but not FINISHED */
        test_ctx.c_len = TEST_MEMIO_BUF_SZ - 6;

        /* <- CS */
        if (test == 0) {
            ExpectIntEQ(wolfSSL_read(ssl_s, test_buffer,
                                     sizeof(test_buffer)), -1);
        } else {
            ExpectIntEQ(wolfSSL_write(ssl_s, "hello", 5), -1);
        }
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_WRITE);

        /* move CS message where the client can read it */
        memmove(test_ctx.c_buff,
                (test_ctx.c_buff + TEST_MEMIO_BUF_SZ - 6), 6);
        test_ctx.c_len = 6;
        /* read CS */
        if (test == 0) {
            ExpectIntEQ(wolfSSL_write(ssl_c, "hello", 5), -1);
        } else {
            ExpectIntEQ(wolfSSL_read(ssl_c, test_buffer,
                                     sizeof(test_buffer)), -1);
        }
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(test_ctx.c_len, 0);

        if (test == 0) {
            /* send SERVER FINISHED */
            ExpectIntEQ(wolfSSL_read(ssl_s, test_buffer,
                                     sizeof(test_buffer)), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1),
                        WOLFSSL_ERROR_WANT_READ);
        } else {
            /* send SERVER FINISHED + App Data */
            ExpectIntEQ(wolfSSL_write(ssl_s, "hello", 5), 5);
        }

        ExpectIntGT(test_ctx.c_len, 0);

        /* Send and receive the data */
        if (test == 0) {
            ExpectIntEQ(wolfSSL_write(ssl_c, "hello", 5), 5);
            ExpectIntEQ(wolfSSL_read(ssl_s, test_buffer,
                                     sizeof(test_buffer)), 5);
        } else {
            ExpectIntEQ(wolfSSL_read(ssl_c, test_buffer,
                                     sizeof(test_buffer)), 5);
        }

        ExpectBufEQ(test_buffer, "hello", 5);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
        ssl_c = ssl_s = NULL;
        ctx_c = ctx_s = NULL;
    }

#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && defined(OPENSSL_EXTRA)
static const char* test_get_signature_nid_siglag;
static int test_get_signature_nid_sig;
static int test_get_signature_nid_hash;

static int test_get_signature_nid_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl, "ALL"), WOLFSSL_SUCCESS);
    if (!wolfSSL_is_server(ssl)) {
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl,
            test_get_signature_nid_siglag), WOLFSSL_SUCCESS);
    }
    return EXPECT_RESULT();
}

static int test_get_signature_nid_on_hs_client(WOLFSSL_CTX **ctx, WOLFSSL **ssl)
{
    EXPECT_DECLS;
    int nid = 0;
    (void)ctx;
    if (XSTRSTR(wolfSSL_get_cipher(*ssl), "TLS_RSA_") == NULL) {
        ExpectIntEQ(SSL_get_peer_signature_type_nid(*ssl, &nid), WOLFSSL_SUCCESS);
        ExpectIntEQ(nid, test_get_signature_nid_sig);
        ExpectIntEQ(SSL_get_peer_signature_nid(*ssl, &nid), WOLFSSL_SUCCESS);
        ExpectIntEQ(nid, test_get_signature_nid_hash);
    }
    else /* No sigalg info on static ciphersuite */
        return TEST_SUCCESS;
    return EXPECT_RESULT();
}

static int test_get_signature_nid_on_hs_server(WOLFSSL_CTX **ctx, WOLFSSL **ssl)
{
    EXPECT_DECLS;
    int nid = 0;
    (void)ctx;
    ExpectIntEQ(SSL_get_signature_type_nid(*ssl, &nid), WOLFSSL_SUCCESS);
    ExpectIntEQ(nid, test_get_signature_nid_sig);
    ExpectIntEQ(SSL_get_signature_nid(*ssl, &nid), WOLFSSL_SUCCESS);
    ExpectIntEQ(nid, test_get_signature_nid_hash);
    return EXPECT_RESULT();
}
#endif

static int test_get_signature_nid(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && defined(OPENSSL_EXTRA)
    test_ssl_cbf client_cbf;
    test_ssl_cbf server_cbf;
    size_t i;
#define TGSN_TLS12_RSA(sigalg, sig_nid, hash_nid) \
        { sigalg, sig_nid, hash_nid, WOLFSSL_TLSV1_2, svrCertFile, svrKeyFile, \
          caCertFile }
#define TGSN_TLS12_ECDSA(sigalg, sig_nid, hash_nid) \
        { sigalg, sig_nid, hash_nid, WOLFSSL_TLSV1_2, eccCertFile, eccKeyFile, \
          caEccCertFile }
#define TGSN_TLS13_RSA(sigalg, sig_nid, hash_nid) \
        { sigalg, sig_nid, hash_nid, WOLFSSL_TLSV1_3, svrCertFile, svrKeyFile, \
          caCertFile }
#define TGSN_TLS13_ECDSA(sigalg, sig_nid, hash_nid) \
        { sigalg, sig_nid, hash_nid, WOLFSSL_TLSV1_3, eccCertFile, eccKeyFile, \
          caEccCertFile }
#define TGSN_TLS13_ED25519(sigalg, sig_nid, hash_nid) \
        { sigalg, sig_nid, hash_nid, WOLFSSL_TLSV1_3, edCertFile, edKeyFile, \
            caEdCertFile }
#define TGSN_TLS13_ED448(sigalg, sig_nid, hash_nid) \
        { sigalg, sig_nid, hash_nid, WOLFSSL_TLSV1_3, ed448CertFile, ed448KeyFile, \
            caEd448CertFile }
    struct {
        const char* siglag;
        int sig_nid;
        int hash_nid;
        int tls_ver;
        const char* server_cert;
        const char* server_key;
        const char* client_ca;
    } params[] = {
#ifndef NO_RSA
    #ifndef NO_SHA256
        TGSN_TLS12_RSA("RSA+SHA256", NID_rsaEncryption, NID_sha256),
        #ifdef WC_RSA_PSS
        TGSN_TLS12_RSA("RSA-PSS+SHA256", NID_rsassaPss, NID_sha256),
        TGSN_TLS13_RSA("RSA-PSS+SHA256", NID_rsassaPss, NID_sha256),
        #endif
    #endif
    #ifdef WOLFSSL_SHA512
        TGSN_TLS12_RSA("RSA+SHA512", NID_rsaEncryption, NID_sha512),
        #ifdef WC_RSA_PSS
        TGSN_TLS12_RSA("RSA-PSS+SHA512", NID_rsassaPss, NID_sha512),
        TGSN_TLS13_RSA("RSA-PSS+SHA512", NID_rsassaPss, NID_sha512),
        #endif
    #endif
#endif
#ifdef HAVE_ECC
    #ifndef NO_SHA256
        TGSN_TLS12_ECDSA("ECDSA+SHA256", NID_X9_62_id_ecPublicKey, NID_sha256),
        TGSN_TLS13_ECDSA("ECDSA+SHA256", NID_X9_62_id_ecPublicKey, NID_sha256),
    #endif
#endif
#ifdef HAVE_ED25519
        TGSN_TLS13_ED25519("ED25519", NID_ED25519, NID_sha512),
#endif
#ifdef HAVE_ED448
        TGSN_TLS13_ED448("ED448", NID_ED448, NID_sha512),
#endif
    };
    /* These correspond to WOLFSSL_SSLV3...WOLFSSL_DTLSV1_3 */
    const char* tls_desc[] = {
        "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3",
        "DTLSv1.0", "DTLSv1.2", "DTLSv1.3"
    };

    printf("\n");

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {

        XMEMSET(&client_cbf, 0, sizeof(client_cbf));
        XMEMSET(&server_cbf, 0, sizeof(server_cbf));

        printf("Testing %s with %s...", tls_desc[params[i].tls_ver],
                params[i].siglag);

        switch (params[i].tls_ver) {
#ifndef WOLFSSL_NO_TLS12
            case WOLFSSL_TLSV1_2:
                client_cbf.method = wolfTLSv1_2_client_method;
                server_cbf.method = wolfTLSv1_2_server_method;
                break;
#endif
#ifdef WOLFSSL_TLS13
            case WOLFSSL_TLSV1_3:
                client_cbf.method = wolfTLSv1_3_client_method;
                server_cbf.method = wolfTLSv1_3_server_method;
                break;
#endif
            default:
                printf("skipping\n");
                continue;
        }

        test_get_signature_nid_siglag = params[i].siglag;
        test_get_signature_nid_sig = params[i].sig_nid;
        test_get_signature_nid_hash = params[i].hash_nid;

        client_cbf.ssl_ready = test_get_signature_nid_ssl_ready;
        server_cbf.ssl_ready = test_get_signature_nid_ssl_ready;

        client_cbf.on_handshake = test_get_signature_nid_on_hs_client;
        server_cbf.on_handshake = test_get_signature_nid_on_hs_server;

        server_cbf.certPemFile = params[i].server_cert;
        server_cbf.keyPemFile = params[i].server_key;

        client_cbf.caPemFile = params[i].client_ca;

        ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbf,
            &server_cbf, NULL), TEST_SUCCESS);
        if (EXPECT_SUCCESS())
            printf("passed\n");
    }

#endif
    return EXPECT_RESULT();
}

#if !defined(NO_CERTS) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
static word32 test_tls_cert_store_unchanged_HashCaTable(Signer** caTable)
{
#ifndef NO_MD5
    enum wc_HashType hashType = WC_HASH_TYPE_MD5;
#elif !defined(NO_SHA)
    enum wc_HashType hashType = WC_HASH_TYPE_SHA;
#elif !defined(NO_SHA256)
    enum wc_HashType hashType = WC_HASH_TYPE_SHA256;
#else
    #error "We need a digest to hash the Signer object"
#endif
    byte hashBuf[WC_MAX_DIGEST_SIZE];
    wc_HashAlg hash;
    size_t i;

    AssertIntEQ(wc_HashInit(&hash, hashType), 0);
    for (i = 0; i < CA_TABLE_SIZE; i++) {
        Signer* cur;
        for (cur = caTable[i]; cur != NULL; cur = cur->next)
            AssertIntEQ(wc_HashUpdate(&hash, hashType, (byte*)cur,
                    sizeof(*cur)), 0);
    }
    AssertIntEQ(wc_HashFinal(&hash, hashType, hashBuf), 0);
    AssertIntEQ(wc_HashFree(&hash, hashType), 0);

    return MakeWordFromHash(hashBuf);
}

static word32 test_tls_cert_store_unchanged_before_hashes[2];
static size_t test_tls_cert_store_unchanged_before_hashes_idx;
static word32 test_tls_cert_store_unchanged_after_hashes[2];
static size_t test_tls_cert_store_unchanged_after_hashes_idx;

static int test_tls_cert_store_unchanged_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectIntNE(test_tls_cert_store_unchanged_before_hashes
        [test_tls_cert_store_unchanged_before_hashes_idx++] =
            test_tls_cert_store_unchanged_HashCaTable(ctx->cm->caTable), 0);

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
            WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

    return EXPECT_RESULT();
}

static int test_tls_cert_store_unchanged_ctx_cleanup(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_CTX_UnloadIntermediateCerts(ctx), WOLFSSL_SUCCESS);
    ExpectIntNE(test_tls_cert_store_unchanged_after_hashes
        [test_tls_cert_store_unchanged_after_hashes_idx++] =
            test_tls_cert_store_unchanged_HashCaTable(ctx->cm->caTable), 0);

    return EXPECT_RESULT();
}

static int test_tls_cert_store_unchanged_on_hs(WOLFSSL_CTX **ctx, WOLFSSL **ssl)
{
    EXPECT_DECLS;
    WOLFSSL_CERT_MANAGER* cm;

    (void)ssl;
    /* WARNING: this approach bypasses the reference counter check in
     * wolfSSL_CTX_UnloadIntermediateCerts. It is not recommended as it may
     * cause unexpected behaviour when other active connections try accessing
     * the caTable. */
    ExpectNotNull(cm = wolfSSL_CTX_GetCertManager(*ctx));
    ExpectIntEQ(wolfSSL_CertManagerUnloadIntermediateCerts(cm),
            WOLFSSL_SUCCESS);
    ExpectIntNE(test_tls_cert_store_unchanged_after_hashes
        [test_tls_cert_store_unchanged_after_hashes_idx++] =
            test_tls_cert_store_unchanged_HashCaTable((*ctx)->cm->caTable), 0);

    return EXPECT_RESULT();
}

static int test_tls_cert_store_unchanged_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx;

    ExpectNotNull(ctx = wolfSSL_get_SSL_CTX(ssl));

    return EXPECT_RESULT();
}
#endif

static int test_tls_cert_store_unchanged(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
    test_ssl_cbf client_cbf;
    test_ssl_cbf server_cbf;
    int i;

    for (i = 0; i < 2; i++) {
        XMEMSET(&client_cbf, 0, sizeof(client_cbf));
        XMEMSET(&server_cbf, 0, sizeof(server_cbf));

        test_tls_cert_store_unchanged_before_hashes_idx = 0;
        XMEMSET(test_tls_cert_store_unchanged_before_hashes, 0,
                sizeof(test_tls_cert_store_unchanged_before_hashes));
        test_tls_cert_store_unchanged_after_hashes_idx = 0;
        XMEMSET(test_tls_cert_store_unchanged_after_hashes, 0,
                sizeof(test_tls_cert_store_unchanged_after_hashes));

        client_cbf.ctx_ready = test_tls_cert_store_unchanged_ctx_ready;
        server_cbf.ctx_ready = test_tls_cert_store_unchanged_ctx_ready;

        client_cbf.ssl_ready = test_tls_cert_store_unchanged_ssl_ready;
        server_cbf.ssl_ready = test_tls_cert_store_unchanged_ssl_ready;

        switch (i) {
            case 0:
                client_cbf.on_ctx_cleanup =
                        test_tls_cert_store_unchanged_ctx_cleanup;
                server_cbf.on_ctx_cleanup =
                        test_tls_cert_store_unchanged_ctx_cleanup;
                break;
            case 1:
                client_cbf.on_handshake = test_tls_cert_store_unchanged_on_hs;
                server_cbf.on_handshake = test_tls_cert_store_unchanged_on_hs;
                break;
            default:
                Fail(("Should not enter here"), ("Entered here"));
        }


        client_cbf.certPemFile = "certs/intermediate/client-chain.pem";
        server_cbf.certPemFile = "certs/intermediate/server-chain.pem";

        server_cbf.caPemFile = caCertFile;

        ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbf,
            &server_cbf, NULL), TEST_SUCCESS);

        ExpectBufEQ(test_tls_cert_store_unchanged_before_hashes,
                test_tls_cert_store_unchanged_after_hashes,
                sizeof(test_tls_cert_store_unchanged_after_hashes));
    }
#endif
    return EXPECT_RESULT();
}

static int test_wolfSSL_SendUserCanceled(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* tls_version;
    } params[] = {
#if defined(WOLFSSL_TLS13)
/* With WOLFSSL_TLS13_MIDDLEBOX_COMPAT a short ID will result in an error */
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, "TLSv1_3" },
#ifdef WOLFSSL_DTLS13
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, "DTLSv1_3" },
#endif
#endif
#ifndef WOLFSSL_NO_TLS12
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2" },
#ifdef WOLFSSL_DTLS
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2" },
#endif
#endif
#if !defined(NO_OLD_TLS)
        { wolfTLSv1_1_client_method, wolfTLSv1_1_server_method, "TLSv1_1" },
#ifdef WOLFSSL_DTLS
        { wolfDTLSv1_client_method, wolfDTLSv1_server_method, "DTLSv1_0" },
#endif
#endif
    };

    for (i = 0; i < sizeof(params)/sizeof(*params) && !EXPECT_FAIL(); i++) {
        WOLFSSL_CTX *ctx_c = NULL;
        WOLFSSL_CTX *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL;
        WOLFSSL *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        WOLFSSL_ALERT_HISTORY h;

        printf("Testing %s\n", params[i].tls_version);

        XMEMSET(&h, 0, sizeof(h));
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                params[i].client_meth, params[i].server_meth), 0);

        /* CH1 */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

        ExpectIntEQ(wolfSSL_SendUserCanceled(ssl_s), WOLFSSL_SHUTDOWN_NOT_DONE);

        /* Alert closed connection */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_ZERO_RETURN);

        /* Last alert will be close notify because user_canceled should be
         * followed by a close_notify */
        ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &h), WOLFSSL_SUCCESS);
        ExpectIntEQ(h.last_rx.code, close_notify);
        ExpectIntEQ(h.last_rx.level, alert_warning);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_OCSP) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    !defined(WOLFSSL_NO_TLS12)
static int test_ocsp_callback_fails_cb(void* ctx, const char* url, int urlSz,
                        byte* ocspReqBuf, int ocspReqSz, byte** ocspRespBuf)
{
    (void)ctx;
    (void)url;
    (void)urlSz;
    (void)ocspReqBuf;
    (void)ocspReqSz;
    (void)ocspRespBuf;
    return WOLFSSL_CBIO_ERR_GENERAL;
}
static int test_ocsp_callback_fails(void)
{
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    EXPECT_DECLS;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl_c, WOLFSSL_CSR_OCSP,0), WOLFSSL_SUCCESS);
    /* override URL to avoid exing from SendCertificateStatus because of no AuthInfo on the certificate */
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx_s, "http://dummy.test"), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx_s, WOLFSSL_OCSP_NO_NONCE    | WOLFSSL_OCSP_URL_OVERRIDE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, caCertFile, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_SetOCSP_Cb(ssl_s, test_ocsp_callback_fails_cb, NULL, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WC_NO_ERR_TRACE(OCSP_INVALID_STATUS));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}
#else
static int test_ocsp_callback_fails(void)
{
    return TEST_SKIPPED;
}
#endif /* defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_OCSP) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) */

#ifdef HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES
static int test_wolfSSL_SSLDisableRead_recv(WOLFSSL *ssl, char *buf, int sz,
                                             void *ctx)
{
    (void)ssl;
    (void)buf;
    (void)sz;
    (void)ctx;
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static int test_wolfSSL_SSLDisableRead(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL *ssl_c = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
            wolfTLS_client_method, NULL), 0);
    wolfSSL_SSLSetIORecv(ssl_c, test_wolfSSL_SSLDisableRead_recv);
    wolfSSL_SSLDisableRead(ssl_c);

    /* Disabling reading should not even go into the IO layer */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    wolfSSL_SSLEnableRead(ssl_c);
    /* By enabling reading we should reach the IO that will return an error */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), SOCKET_ERROR_E);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    return EXPECT_RESULT();
}
#else
static int test_wolfSSL_SSLDisableRead(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif

static int test_wolfSSL_inject(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* tls_version;
    } params[] = {
#if defined(WOLFSSL_TLS13)
/* With WOLFSSL_TLS13_MIDDLEBOX_COMPAT a short ID will result in an error */
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, "TLSv1_3" },
#ifdef WOLFSSL_DTLS13
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, "DTLSv1_3" },
#endif
#endif
#ifndef WOLFSSL_NO_TLS12
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2" },
#ifdef WOLFSSL_DTLS
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2" },
#endif
#endif
#if !defined(NO_OLD_TLS)
        { wolfTLSv1_1_client_method, wolfTLSv1_1_server_method, "TLSv1_1" },
#ifdef WOLFSSL_DTLS
        { wolfDTLSv1_client_method, wolfDTLSv1_server_method, "DTLSv1_0" },
#endif
#endif
    };

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        WOLFSSL_CTX *ctx_c = NULL;
        WOLFSSL_CTX *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL;
        WOLFSSL *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        WOLFSSL_ALERT_HISTORY h;
        int rounds;

        printf("Testing %s\n", params[i].tls_version);

        XMEMSET(&h, 0, sizeof(h));
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                params[i].client_meth, params[i].server_meth), 0);

        for (rounds = 0; rounds < 10 && EXPECT_SUCCESS(); rounds++) {
            wolfSSL_SetLoggingPrefix("client");
            if (wolfSSL_negotiate(ssl_c) != 1) {
                ExpectIntEQ(wolfSSL_get_error(ssl_c, -1),
                        WOLFSSL_ERROR_WANT_READ);
            }
            wolfSSL_SetLoggingPrefix("server");
            if (test_ctx.s_len > 0) {
                ExpectIntEQ(wolfSSL_inject(ssl_s, test_ctx.s_buff,
                                           test_ctx.s_len), 1);
                test_ctx.s_len = 0;
            }
            if (wolfSSL_negotiate(ssl_s) != 1) {
                ExpectIntEQ(wolfSSL_get_error(ssl_s, -1),
                        WOLFSSL_ERROR_WANT_READ);
            }
            wolfSSL_SetLoggingPrefix("client");
            if (test_ctx.c_len > 0) {
                ExpectIntEQ(wolfSSL_inject(ssl_c, test_ctx.c_buff,
                                           test_ctx.c_len), 1);
                test_ctx.c_len = 0;
            }
            wolfSSL_SetLoggingPrefix(NULL);
        }
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);
        ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}

/*----------------------------------------------------------------------------*
 | Main
 *----------------------------------------------------------------------------*/

typedef int (*TEST_FUNC)(void);
typedef struct {
    const char *name;
    TEST_FUNC func;
    byte run:1;
    byte fail:1;
} TEST_CASE;

#define TEST_DECL(func) { #func, func, 0, 0 }

int testAll = 1;

TEST_CASE testCases[] = {
    TEST_DECL(test_fileAccess),

    /*********************************
     * wolfcrypt
     *********************************/

    TEST_DECL(test_ForceZero),

    TEST_DECL(test_wolfCrypt_Init),

    TEST_DECL(test_wc_LoadStaticMemory_ex),
    TEST_DECL(test_wc_LoadStaticMemory_CTX),

    /* Locking with Compat Mutex */
    TEST_DECL(test_wc_SetMutexCb),
    TEST_DECL(test_wc_LockMutex_ex),

    /* Digests */
    /* test_md5.c */
    TEST_DECL(test_wc_InitMd5),
    TEST_DECL(test_wc_Md5Update),
    TEST_DECL(test_wc_Md5Final),
    TEST_DECL(test_wc_Md5_KATs),
    TEST_DECL(test_wc_Md5_other),
    TEST_DECL(test_wc_Md5Copy),
    TEST_DECL(test_wc_Md5GetHash),
    TEST_DECL(test_wc_Md5Transform),
    TEST_DECL(test_wc_Md5_Flags),

    /* test_sha.c */
    TEST_DECL(test_wc_InitSha),
    TEST_DECL(test_wc_ShaUpdate),
    TEST_DECL(test_wc_ShaFinal),
    TEST_DECL(test_wc_ShaFinalRaw),
    TEST_DECL(test_wc_Sha_KATs),
    TEST_DECL(test_wc_Sha_other),
    TEST_DECL(test_wc_ShaCopy),
    TEST_DECL(test_wc_ShaGetHash),
    TEST_DECL(test_wc_ShaTransform),
    TEST_DECL(test_wc_Sha_Flags),

    /* test_sha256.c */
    TEST_DECL(test_wc_InitSha256),
    TEST_DECL(test_wc_Sha256Update),
    TEST_DECL(test_wc_Sha256Final),
    TEST_DECL(test_wc_Sha256FinalRaw),
    TEST_DECL(test_wc_Sha256_KATs),
    TEST_DECL(test_wc_Sha256_other),
    TEST_DECL(test_wc_Sha256Copy),
    TEST_DECL(test_wc_Sha256GetHash),
    TEST_DECL(test_wc_Sha256Transform),
    TEST_DECL(test_wc_Sha256_Flags),

    TEST_DECL(test_wc_InitSha224),
    TEST_DECL(test_wc_Sha224Update),
    TEST_DECL(test_wc_Sha224Final),
    TEST_DECL(test_wc_Sha224_KATs),
    TEST_DECL(test_wc_Sha224_other),
    TEST_DECL(test_wc_Sha224Copy),
    TEST_DECL(test_wc_Sha224GetHash),
    TEST_DECL(test_wc_Sha224_Flags),

    /* test_sha512.c */
    TEST_DECL(test_wc_InitSha512),
    TEST_DECL(test_wc_Sha512Update),
    TEST_DECL(test_wc_Sha512Final),
    TEST_DECL(test_wc_Sha512FinalRaw),
    TEST_DECL(test_wc_Sha512_KATs),
    TEST_DECL(test_wc_Sha512_other),
    TEST_DECL(test_wc_Sha512Copy),
    TEST_DECL(test_wc_Sha512GetHash),
    TEST_DECL(test_wc_Sha512Transform),
    TEST_DECL(test_wc_Sha512_Flags),

    TEST_DECL(test_wc_InitSha512_224),
    TEST_DECL(test_wc_Sha512_224Update),
    TEST_DECL(test_wc_Sha512_224Final),
    TEST_DECL(test_wc_Sha512_224FinalRaw),
    TEST_DECL(test_wc_Sha512_224_KATs),
    TEST_DECL(test_wc_Sha512_224_other),
    TEST_DECL(test_wc_Sha512_224Copy),
    TEST_DECL(test_wc_Sha512_224GetHash),
    TEST_DECL(test_wc_Sha512_224Transform),
    TEST_DECL(test_wc_Sha512_224_Flags),

    TEST_DECL(test_wc_InitSha512_256),
    TEST_DECL(test_wc_Sha512_256Update),
    TEST_DECL(test_wc_Sha512_256Final),
    TEST_DECL(test_wc_Sha512_256FinalRaw),
    TEST_DECL(test_wc_Sha512_256_KATs),
    TEST_DECL(test_wc_Sha512_256_other),
    TEST_DECL(test_wc_Sha512_256Copy),
    TEST_DECL(test_wc_Sha512_256GetHash),
    TEST_DECL(test_wc_Sha512_256Transform),
    TEST_DECL(test_wc_Sha512_256_Flags),

    TEST_DECL(test_wc_InitSha384),
    TEST_DECL(test_wc_Sha384Update),
    TEST_DECL(test_wc_Sha384Final),
    TEST_DECL(test_wc_Sha384FinalRaw),
    TEST_DECL(test_wc_Sha384_KATs),
    TEST_DECL(test_wc_Sha384_other),
    TEST_DECL(test_wc_Sha384Copy),
    TEST_DECL(test_wc_Sha384GetHash),
    TEST_DECL(test_wc_Sha384_Flags),

    /* test_sha3.c */
    TEST_DECL(test_wc_InitSha3),
    TEST_DECL(test_wc_Sha3_Update),
    TEST_DECL(test_wc_Sha3_Final),
    TEST_DECL(test_wc_Sha3_224_KATs),
    TEST_DECL(test_wc_Sha3_256_KATs),
    TEST_DECL(test_wc_Sha3_384_KATs),
    TEST_DECL(test_wc_Sha3_512_KATs),
    TEST_DECL(test_wc_Sha3_other),
    TEST_DECL(test_wc_Sha3_Copy),
    TEST_DECL(test_wc_Sha3_GetHash),
    TEST_DECL(test_wc_Sha3_Flags),

    TEST_DECL(test_wc_InitShake128),
    TEST_DECL(test_wc_Shake128_Update),
    TEST_DECL(test_wc_Shake128_Final),
    TEST_DECL(test_wc_Shake128_KATs),
    TEST_DECL(test_wc_Shake128_other),
    TEST_DECL(test_wc_Shake128_Copy),
    TEST_DECL(test_wc_Shake128Hash),
    TEST_DECL(test_wc_Shake128_Absorb),
    TEST_DECL(test_wc_Shake128_SqueezeBlocks),
    TEST_DECL(test_wc_Shake128_XOF),

    TEST_DECL(test_wc_InitShake256),
    TEST_DECL(test_wc_Shake256_Update),
    TEST_DECL(test_wc_Shake256_Final),
    TEST_DECL(test_wc_Shake256_KATs),
    TEST_DECL(test_wc_Shake256_other),
    TEST_DECL(test_wc_Shake256_Copy),
    TEST_DECL(test_wc_Shake256Hash),
    TEST_DECL(test_wc_Shake256_Absorb),
    TEST_DECL(test_wc_Shake256_SqueezeBlocks),
    TEST_DECL(test_wc_Shake256_XOF),

    /* test_blake.c */
    TEST_DECL(test_wc_InitBlake2b),
    TEST_DECL(test_wc_InitBlake2b_WithKey),
    TEST_DECL(test_wc_Blake2bUpdate),
    TEST_DECL(test_wc_Blake2bFinal),
    TEST_DECL(test_wc_Blake2b_KATs),
    TEST_DECL(test_wc_Blake2b_other),

    TEST_DECL(test_wc_InitBlake2s),
    TEST_DECL(test_wc_InitBlake2s_WithKey),
    TEST_DECL(test_wc_Blake2sUpdate),
    TEST_DECL(test_wc_Blake2sFinal),
    TEST_DECL(test_wc_Blake2s_KATs),
    TEST_DECL(test_wc_Blake2s_other),

    /* test_sm3.c: SM3 Digest */
    TEST_DECL(test_wc_InitSm3),
    TEST_DECL(test_wc_Sm3Update),
    TEST_DECL(test_wc_Sm3Final),
    TEST_DECL(test_wc_Sm3FinalRaw),
    TEST_DECL(test_wc_Sm3_KATs),
    TEST_DECL(test_wc_Sm3_other),
    TEST_DECL(test_wc_Sm3Copy),
    TEST_DECL(test_wc_Sm3GetHash),
    TEST_DECL(test_wc_Sm3_Flags),
    TEST_DECL(test_wc_Sm3Hash),

    /* test_ripemd.c */
    TEST_DECL(test_wc_InitRipeMd),
    TEST_DECL(test_wc_RipeMdUpdate),
    TEST_DECL(test_wc_RipeMdFinal),
    TEST_DECL(test_wc_RipeMd_KATs),
    TEST_DECL(test_wc_RipeMd_other),

    /* test_hash.c */
    TEST_DECL(test_wc_HashInit),
    TEST_DECL(test_wc_HashSetFlags),
    TEST_DECL(test_wc_HashGetFlags),

    /* HMAC */
    TEST_DECL(test_wc_Md5HmacSetKey),
    TEST_DECL(test_wc_Md5HmacUpdate),
    TEST_DECL(test_wc_Md5HmacFinal),
    TEST_DECL(test_wc_ShaHmacSetKey),
    TEST_DECL(test_wc_ShaHmacUpdate),
    TEST_DECL(test_wc_ShaHmacFinal),
    TEST_DECL(test_wc_Sha224HmacSetKey),
    TEST_DECL(test_wc_Sha224HmacUpdate),
    TEST_DECL(test_wc_Sha224HmacFinal),
    TEST_DECL(test_wc_Sha256HmacSetKey),
    TEST_DECL(test_wc_Sha256HmacUpdate),
    TEST_DECL(test_wc_Sha256HmacFinal),
    TEST_DECL(test_wc_Sha384HmacSetKey),
    TEST_DECL(test_wc_Sha384HmacUpdate),
    TEST_DECL(test_wc_Sha384HmacFinal),

    /* CMAC */
    TEST_DECL(test_wc_InitCmac),
    TEST_DECL(test_wc_CmacUpdate),
    TEST_DECL(test_wc_CmacFinal),
    TEST_DECL(test_wc_AesCmacGenerate),

    /* Cipher */
    TEST_DECL(test_wc_Des3_SetIV),
    TEST_DECL(test_wc_Des3_SetKey),
    TEST_DECL(test_wc_Des3_CbcEncryptDecrypt),
    TEST_DECL(test_wc_Des3_EcbEncrypt),
    /* wc_encrypt API */
    TEST_DECL(test_wc_Des3_CbcEncryptDecryptWithKey),

    TEST_DECL(test_wc_Chacha_SetKey),
    TEST_DECL(test_wc_Chacha_Process),
    TEST_DECL(test_wc_Poly1305SetKey),
    TEST_DECL(test_wc_ChaCha20Poly1305_aead),

    TEST_DECL(test_wc_CamelliaSetKey),
    TEST_DECL(test_wc_CamelliaSetIV),
    TEST_DECL(test_wc_CamelliaEncryptDecryptDirect),
    TEST_DECL(test_wc_CamelliaCbcEncryptDecrypt),

    TEST_DECL(test_wc_Arc4SetKey),
    TEST_DECL(test_wc_Arc4Process),

    TEST_DECL(test_wc_Rc2SetKey),
    TEST_DECL(test_wc_Rc2SetIV),
    TEST_DECL(test_wc_Rc2EcbEncryptDecrypt),
    TEST_DECL(test_wc_Rc2CbcEncryptDecrypt),

    /* AES cipher and GMAC. */
    TEST_DECL(test_wc_AesSetKey),
    TEST_DECL(test_wc_AesSetIV),
    TEST_DECL(test_wc_AesCbcEncryptDecrypt),
    TEST_DECL(test_wc_AesCtrEncryptDecrypt),
    TEST_DECL(test_wc_AesGcmSetKey),
    TEST_DECL(test_wc_AesGcmEncryptDecrypt),
    TEST_DECL(test_wc_AesGcmMixedEncDecLongIV),
    TEST_DECL(test_wc_AesGcmStream),
    TEST_DECL(test_wc_GmacSetKey),
    TEST_DECL(test_wc_GmacUpdate),
    TEST_DECL(test_wc_AesCcmSetKey),
    TEST_DECL(test_wc_AesCcmEncryptDecrypt),
#if defined(WOLFSSL_AES_EAX) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
    TEST_DECL(test_wc_AesEaxVectors),
    TEST_DECL(test_wc_AesEaxEncryptAuth),
    TEST_DECL(test_wc_AesEaxDecryptAuth),
#endif /* WOLFSSL_AES_EAX */

    /* Ascon */
    TEST_DECL(test_ascon_hash256),
    TEST_DECL(test_ascon_aead128),

    /* SM4 cipher */
    TEST_DECL(test_wc_Sm4),
    TEST_DECL(test_wc_Sm4Ecb),
    TEST_DECL(test_wc_Sm4Cbc),
    TEST_DECL(test_wc_Sm4Ctr),
    TEST_DECL(test_wc_Sm4Gcm),
    TEST_DECL(test_wc_Sm4Ccm),

    /* RNG tests */
#ifdef HAVE_HASHDRBG
#ifdef TEST_RESEED_INTERVAL
    TEST_DECL(test_wc_RNG_GenerateBlock_Reseed),
#endif
    TEST_DECL(test_wc_RNG_GenerateBlock),
#endif
    TEST_DECL(test_get_rand_digit),
    TEST_DECL(test_wc_InitRngNonce),
    TEST_DECL(test_wc_InitRngNonce_ex),

    /* MP API tests */
    TEST_DECL(test_get_digit_count),
    TEST_DECL(test_mp_cond_copy),
    TEST_DECL(test_mp_rand),
    TEST_DECL(test_get_digit),
    TEST_DECL(test_wc_export_int),

    /* RSA */
    TEST_DECL(test_wc_InitRsaKey),
    TEST_DECL(test_wc_RsaPrivateKeyDecode),
    TEST_DECL(test_wc_RsaPublicKeyDecode),
    TEST_DECL(test_wc_RsaPublicKeyDecodeRaw),
    TEST_DECL(test_wc_RsaPrivateKeyDecodeRaw),
    TEST_DECL(test_wc_MakeRsaKey),
    TEST_DECL(test_wc_CheckProbablePrime),
    TEST_DECL(test_wc_RsaPSS_Verify),
    TEST_DECL(test_wc_RsaPSS_VerifyCheck),
    TEST_DECL(test_wc_RsaPSS_VerifyCheckInline),
    TEST_DECL(test_wc_RsaKeyToDer),
    TEST_DECL(test_wc_RsaKeyToPublicDer),
    TEST_DECL(test_wc_RsaPublicEncryptDecrypt),
    TEST_DECL(test_wc_RsaPublicEncryptDecrypt_ex),
    TEST_DECL(test_wc_RsaEncryptSize),
    TEST_DECL(test_wc_RsaSSL_SignVerify),
    TEST_DECL(test_wc_RsaFlattenPublicKey),
    TEST_DECL(test_RsaDecryptBoundsCheck),

    /* DSA */
    TEST_DECL(test_wc_InitDsaKey),
    TEST_DECL(test_wc_DsaSignVerify),
    TEST_DECL(test_wc_DsaPublicPrivateKeyDecode),
    TEST_DECL(test_wc_MakeDsaKey),
    TEST_DECL(test_wc_DsaKeyToDer),
    TEST_DECL(test_wc_DsaKeyToPublicDer),
    TEST_DECL(test_wc_DsaImportParamsRaw),
    TEST_DECL(test_wc_DsaImportParamsRawCheck),
    TEST_DECL(test_wc_DsaExportParamsRaw),
    TEST_DECL(test_wc_DsaExportKeyRaw),

    /* DH */
    TEST_DECL(test_wc_DhPublicKeyDecode),

    /* wolfCrypt ECC tests */
    TEST_DECL(test_wc_ecc_get_curve_size_from_name),
    TEST_DECL(test_wc_ecc_get_curve_id_from_name),
    TEST_DECL(test_wc_ecc_get_curve_id_from_params),
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && \
    !defined(HAVE_SELFTEST) && \
    !(defined(HAVE_FIPS) || defined(HAVE_FIPS_VERSION))
    TEST_DECL(test_wc_ecc_get_curve_id_from_dp_params),
#endif
    TEST_DECL(test_wc_ecc_make_key),
    TEST_DECL(test_wc_ecc_init),
    TEST_DECL(test_wc_ecc_check_key),
    TEST_DECL(test_wc_ecc_get_generator),
    TEST_DECL(test_wc_ecc_size),
    TEST_DECL(test_wc_ecc_params),
    TEST_DECL(test_wc_ecc_signVerify_hash),
    TEST_DECL(test_wc_ecc_shared_secret),
    TEST_DECL(test_wc_ecc_export_x963),
    TEST_DECL(test_wc_ecc_export_x963_ex),
    TEST_DECL(test_wc_ecc_import_x963),
    TEST_DECL(test_wc_ecc_import_private_key),
    TEST_DECL(test_wc_ecc_export_private_only),
    TEST_DECL(test_wc_ecc_rs_to_sig),
    TEST_DECL(test_wc_ecc_import_raw),
    TEST_DECL(test_wc_ecc_import_unsigned),
    TEST_DECL(test_wc_ecc_sig_size),
    TEST_DECL(test_wc_ecc_ctx_new),
    TEST_DECL(test_wc_ecc_ctx_reset),
    TEST_DECL(test_wc_ecc_ctx_set_peer_salt),
    TEST_DECL(test_wc_ecc_ctx_set_info),
    TEST_DECL(test_wc_ecc_encryptDecrypt),
    TEST_DECL(test_wc_ecc_del_point),
    TEST_DECL(test_wc_ecc_pointFns),
    TEST_DECL(test_wc_ecc_shared_secret_ssh),
    TEST_DECL(test_wc_ecc_verify_hash_ex),
    TEST_DECL(test_wc_ecc_mulmod),
    TEST_DECL(test_wc_ecc_is_valid_idx),
    TEST_DECL(test_wc_ecc_get_curve_id_from_oid),
    TEST_DECL(test_wc_ecc_sig_size_calc),
    TEST_DECL(test_wc_EccPrivateKeyToDer),

    /* SM2 elliptic curve */
    TEST_DECL(test_wc_ecc_sm2_make_key),
    TEST_DECL(test_wc_ecc_sm2_shared_secret),
    TEST_DECL(test_wc_ecc_sm2_create_digest),
    TEST_DECL(test_wc_ecc_sm2_verify_hash_ex),
    TEST_DECL(test_wc_ecc_sm2_verify_hash),
    TEST_DECL(test_wc_ecc_sm2_sign_hash_ex),
    TEST_DECL(test_wc_ecc_sm2_sign_hash),

    /* Curve25519 */
    TEST_DECL(test_wc_curve25519_init),
    TEST_DECL(test_wc_curve25519_size),
    TEST_DECL(test_wc_curve25519_export_key_raw),
    TEST_DECL(test_wc_curve25519_export_key_raw_ex),
    TEST_DECL(test_wc_curve25519_make_key),
    TEST_DECL(test_wc_curve25519_shared_secret_ex),
    TEST_DECL(test_wc_curve25519_make_pub),
    TEST_DECL(test_wc_curve25519_export_public_ex),
    TEST_DECL(test_wc_curve25519_export_private_raw_ex),
    TEST_DECL(test_wc_curve25519_import_private_raw_ex),
    TEST_DECL(test_wc_curve25519_import_private),

    /* ED25519 */
    TEST_DECL(test_wc_ed25519_make_key),
    TEST_DECL(test_wc_ed25519_init),
    TEST_DECL(test_wc_ed25519_sign_msg),
    TEST_DECL(test_wc_ed25519_import_public),
    TEST_DECL(test_wc_ed25519_import_private_key),
    TEST_DECL(test_wc_ed25519_export),
    TEST_DECL(test_wc_ed25519_size),
    TEST_DECL(test_wc_ed25519_exportKey),
    TEST_DECL(test_wc_Ed25519PublicKeyToDer),
    TEST_DECL(test_wc_Ed25519KeyToDer),
    TEST_DECL(test_wc_Ed25519PrivateKeyToDer),

    /* Curve448 */
    TEST_DECL(test_wc_curve448_make_key),
    TEST_DECL(test_wc_curve448_shared_secret_ex),
    TEST_DECL(test_wc_curve448_export_public_ex),
    TEST_DECL(test_wc_curve448_export_private_raw_ex),
    TEST_DECL(test_wc_curve448_export_key_raw),
    TEST_DECL(test_wc_curve448_import_private_raw_ex),
    TEST_DECL(test_wc_curve448_import_private),
    TEST_DECL(test_wc_curve448_init),
    TEST_DECL(test_wc_curve448_size),

    /* Ed448 */
    TEST_DECL(test_wc_ed448_make_key),
    TEST_DECL(test_wc_ed448_init),
    TEST_DECL(test_wc_ed448_sign_msg),
    TEST_DECL(test_wc_ed448_import_public),
    TEST_DECL(test_wc_ed448_import_private_key),
    TEST_DECL(test_wc_ed448_export),
    TEST_DECL(test_wc_ed448_size),
    TEST_DECL(test_wc_ed448_exportKey),
    TEST_DECL(test_wc_Ed448PublicKeyToDer),
    TEST_DECL(test_wc_Ed448KeyToDer),
    TEST_DECL(test_wc_Ed448PrivateKeyToDer),
    TEST_DECL(test_wc_Curve448PrivateKeyToDer),

    /* Kyber */
    TEST_DECL(test_wc_mlkem_make_key_kats),
    TEST_DECL(test_wc_mlkem_encapsulate_kats),
    TEST_DECL(test_wc_mlkem_decapsulate_kats),

    /* Dilithium */
    TEST_DECL(test_wc_dilithium),
    TEST_DECL(test_wc_dilithium_make_key),
    TEST_DECL(test_wc_dilithium_sign),
    TEST_DECL(test_wc_dilithium_verify),
    TEST_DECL(test_wc_dilithium_sign_vfy),
    TEST_DECL(test_wc_dilithium_check_key),
    TEST_DECL(test_wc_dilithium_public_der_decode),
    TEST_DECL(test_wc_dilithium_der),
    TEST_DECL(test_wc_dilithium_make_key_from_seed),
    TEST_DECL(test_wc_dilithium_sig_kats),
    TEST_DECL(test_wc_dilithium_verify_kats),

    /* Signature API */
    TEST_DECL(test_wc_SignatureGetSize_ecc),
    TEST_DECL(test_wc_SignatureGetSize_rsa),

    /* PEM and DER APIs. */
    TEST_DECL(test_wc_PemToDer),
    TEST_DECL(test_wc_AllocDer),
    TEST_DECL(test_wc_CertPemToDer),
    TEST_DECL(test_wc_KeyPemToDer),
    TEST_DECL(test_wc_PubKeyPemToDer),
    TEST_DECL(test_wc_PemPubKeyToDer),
    TEST_DECL(test_wc_GetPubKeyDerFromCert),
    TEST_DECL(test_wc_CheckCertSigPubKey),

    /* wolfCrypt ASN tests */
    TEST_DECL(test_ToTraditional),
    TEST_DECL(test_wc_CreateEncryptedPKCS8Key),
    TEST_DECL(test_wc_GetPkcs8TraditionalOffset),

    /* Certificate */
    TEST_DECL(test_wc_SetSubjectRaw),
    TEST_DECL(test_wc_GetSubjectRaw),
    TEST_DECL(test_wc_SetIssuerRaw),
    TEST_DECL(test_wc_SetIssueBuffer),
    TEST_DECL(test_wc_SetSubjectKeyId),
    TEST_DECL(test_wc_SetSubject),
    TEST_DECL(test_CheckCertSignature),
    TEST_DECL(test_wc_ParseCert),
    TEST_DECL(test_wc_ParseCert_Error),
    TEST_DECL(test_MakeCertWithPathLen),
    TEST_DECL(test_MakeCertWith0Ser),
    TEST_DECL(test_MakeCertWithCaFalse),
    TEST_DECL(test_wc_SetKeyUsage),
    TEST_DECL(test_wc_SetAuthKeyIdFromPublicKey_ex),
    TEST_DECL(test_wc_SetSubjectBuffer),
    TEST_DECL(test_wc_SetSubjectKeyIdFromPublicKey_ex),

    /* wolfcrypt PKCS#7 */
    TEST_DECL(test_wc_PKCS7_New),
    TEST_DECL(test_wc_PKCS7_Init),
    TEST_DECL(test_wc_PKCS7_InitWithCert),
    TEST_DECL(test_wc_PKCS7_EncodeData),
    TEST_DECL(test_wc_PKCS7_EncodeSignedData),
    TEST_DECL(test_wc_PKCS7_EncodeSignedData_ex),
    TEST_DECL(test_wc_PKCS7_VerifySignedData_RSA),
    TEST_DECL(test_wc_PKCS7_VerifySignedData_ECC),
    TEST_DECL(test_wc_PKCS7_EncodeDecodeEnvelopedData),
    TEST_DECL(test_wc_PKCS7_EncodeEncryptedData),
    TEST_DECL(test_wc_PKCS7_Degenerate),
    TEST_DECL(test_wc_PKCS7_BER),
    TEST_DECL(test_wc_PKCS7_signed_enveloped),
    TEST_DECL(test_wc_PKCS7_NoDefaultSignedAttribs),
    TEST_DECL(test_wc_PKCS7_SetOriEncryptCtx),
    TEST_DECL(test_wc_PKCS7_SetOriDecryptCtx),
    TEST_DECL(test_wc_PKCS7_DecodeCompressedData),

    /* wolfCrypt PKCS#12 */
    TEST_DECL(test_wc_i2d_PKCS12),

    /*
     * test_wolfCrypt_Cleanup needs to come after the above wolfCrypt tests to
     * avoid memory leaks.
     */
    TEST_DECL(test_wolfCrypt_Cleanup),

    TEST_DECL(test_wolfSSL_Init),

    TEST_DECL(test_dual_alg_support),

    TEST_DECL(test_dual_alg_ecdsa_mldsa),

    /*********************************
     * OpenSSL compatibility API tests
     *********************************/

    /* If at some point a stub get implemented this test should fail indicating
     * a need to implement a new test case
     */
    TEST_DECL(test_stubs_are_stubs),

    /* ASN.1 compatibility API tests */
    TEST_DECL(test_wolfSSL_ASN1_BIT_STRING),
    TEST_DECL(test_wolfSSL_ASN1_INTEGER),
    TEST_DECL(test_wolfSSL_ASN1_INTEGER_cmp),
    TEST_DECL(test_wolfSSL_ASN1_INTEGER_BN),
    TEST_DECL(test_wolfSSL_ASN1_INTEGER_get_set),
    TEST_DECL(test_wolfSSL_d2i_ASN1_INTEGER),
    TEST_DECL(test_wolfSSL_a2i_ASN1_INTEGER),
    TEST_DECL(test_wolfSSL_i2c_ASN1_INTEGER),
    TEST_DECL(test_wolfSSL_ASN1_OBJECT),
    TEST_DECL(test_wolfSSL_ASN1_get_object),
    TEST_DECL(test_wolfSSL_i2a_ASN1_OBJECT),
    TEST_DECL(test_wolfSSL_i2t_ASN1_OBJECT),
    TEST_DECL(test_wolfSSL_sk_ASN1_OBJECT),
    TEST_DECL(test_wolfSSL_ASN1_STRING),
    TEST_DECL(test_wolfSSL_ASN1_STRING_to_UTF8),
    TEST_DECL(test_wolfSSL_i2s_ASN1_STRING),
    TEST_DECL(test_wolfSSL_ASN1_STRING_canon),
    TEST_DECL(test_wolfSSL_ASN1_STRING_print),
    TEST_DECL(test_wolfSSL_ASN1_STRING_print_ex),
    TEST_DECL(test_wolfSSL_ASN1_UNIVERSALSTRING_to_string),
    TEST_DECL(test_wolfSSL_ASN1_GENERALIZEDTIME_free),
    TEST_DECL(test_wolfSSL_ASN1_GENERALIZEDTIME_print),
    TEST_DECL(test_wolfSSL_ASN1_TIME),
    TEST_DECL(test_wolfSSL_ASN1_TIME_to_string),
    TEST_DECL(test_wolfSSL_ASN1_TIME_diff_compare),
    TEST_DECL(test_wolfSSL_ASN1_TIME_adj),
    TEST_DECL(test_wolfSSL_ASN1_TIME_to_tm),
    TEST_DECL(test_wolfSSL_ASN1_TIME_to_generalizedtime),
    TEST_DECL(test_wolfSSL_ASN1_TIME_print),
    TEST_DECL(test_wolfSSL_ASN1_UTCTIME_print),
    TEST_DECL(test_wolfSSL_ASN1_TYPE),
    TEST_DECL(test_wolfSSL_IMPLEMENT_ASN1_FUNCTIONS),
    TEST_DECL(test_wolfSSL_i2d_ASN1_TYPE),
    TEST_DECL(test_wolfSSL_i2d_ASN1_SEQUENCE),
    TEST_DECL(test_ASN1_strings),

    TEST_DECL(test_wolfSSL_lhash),

    TEST_DECL(test_wolfSSL_certs),
    TEST_DECL(test_wolfSSL_X509_ext_d2i),

    TEST_DECL(test_wolfSSL_private_keys),
    TEST_DECL(test_wolfSSL_PEM_def_callback),
    TEST_DECL(test_wolfSSL_PEM_read_PrivateKey),
    TEST_DECL(test_wolfSSL_PEM_read_RSA_PUBKEY),
    TEST_DECL(test_wolfSSL_PEM_read_PUBKEY),
    TEST_DECL(test_wolfSSL_PEM_PrivateKey_rsa),
    TEST_DECL(test_wolfSSL_PEM_PrivateKey_ecc),
    TEST_DECL(test_wolfSSL_PEM_PrivateKey_dsa),
    TEST_DECL(test_wolfSSL_PEM_PrivateKey_dh),
    TEST_DECL(test_wolfSSL_PEM_PrivateKey),
    TEST_DECL(test_wolfSSL_PEM_file_RSAKey),
    TEST_DECL(test_wolfSSL_PEM_file_RSAPrivateKey),
#ifndef NO_BIO
    TEST_DECL(test_wolfSSL_BIO),
    TEST_DECL(test_wolfSSL_BIO_BIO_ring_read),
    TEST_DECL(test_wolfSSL_PEM_read_bio),
    TEST_DECL(test_wolfSSL_PEM_bio_RSAKey),
    TEST_DECL(test_wolfSSL_PEM_bio_DSAKey),
    TEST_DECL(test_wolfSSL_PEM_bio_ECKey),
    TEST_DECL(test_wolfSSL_PEM_bio_RSAPrivateKey),
    TEST_DECL(test_wolfSSL_PEM_PUBKEY),
#endif

    /* EVP API testing */
    TEST_DECL(test_wolfSSL_EVP_ENCODE_CTX_new),
    TEST_DECL(test_wolfSSL_EVP_ENCODE_CTX_free),
    TEST_DECL(test_wolfSSL_EVP_EncodeInit),
    TEST_DECL(test_wolfSSL_EVP_EncodeUpdate),
    TEST_DECL(test_wolfSSL_EVP_EncodeFinal),
    TEST_DECL(test_wolfSSL_EVP_DecodeInit),
    TEST_DECL(test_wolfSSL_EVP_DecodeUpdate),
    TEST_DECL(test_wolfSSL_EVP_DecodeFinal),

    TEST_DECL(test_wolfSSL_EVP_shake128),
    TEST_DECL(test_wolfSSL_EVP_shake256),
    TEST_DECL(test_wolfSSL_EVP_sm3),
    TEST_DECL(test_EVP_blake2),
#ifdef OPENSSL_ALL
    TEST_DECL(test_wolfSSL_EVP_md4),
    TEST_DECL(test_wolfSSL_EVP_ripemd160),
    TEST_DECL(test_wolfSSL_EVP_get_digestbynid),
    TEST_DECL(test_wolfSSL_EVP_MD_nid),

    TEST_DECL(test_wolfSSL_EVP_DigestFinal_ex),
    TEST_DECL(test_wolfSSL_EVP_DigestFinalXOF),
#endif

    TEST_DECL(test_EVP_MD_do_all),
    TEST_DECL(test_wolfSSL_EVP_MD_size),
    TEST_DECL(test_wolfSSL_EVP_MD_pkey_type),
    TEST_DECL(test_wolfSSL_EVP_Digest),
    TEST_DECL(test_wolfSSL_EVP_Digest_all),
    TEST_DECL(test_wolfSSL_EVP_MD_hmac_signing),
    TEST_DECL(test_wolfSSL_EVP_MD_rsa_signing),
    TEST_DECL(test_wolfSSL_EVP_MD_ecc_signing),

    TEST_DECL(test_wolfssl_EVP_aes_gcm),
    TEST_DECL(test_wolfssl_EVP_aes_gcm_AAD_2_parts),
    TEST_DECL(test_wolfssl_EVP_aes_gcm_zeroLen),
    TEST_DECL(test_wolfssl_EVP_aes_ccm),
    TEST_DECL(test_wolfssl_EVP_aes_ccm_zeroLen),
    TEST_DECL(test_wolfssl_EVP_chacha20),
    TEST_DECL(test_wolfssl_EVP_chacha20_poly1305),
    TEST_DECL(test_wolfssl_EVP_sm4_ecb),
    TEST_DECL(test_wolfssl_EVP_sm4_cbc),
    TEST_DECL(test_wolfssl_EVP_sm4_ctr),
    TEST_DECL(test_wolfssl_EVP_sm4_gcm_zeroLen),
    TEST_DECL(test_wolfssl_EVP_sm4_gcm),
    TEST_DECL(test_wolfssl_EVP_sm4_ccm_zeroLen),
    TEST_DECL(test_wolfssl_EVP_sm4_ccm),
#ifdef OPENSSL_ALL
    TEST_DECL(test_wolfSSL_EVP_aes_256_gcm),
    TEST_DECL(test_wolfSSL_EVP_aes_192_gcm),
    TEST_DECL(test_wolfSSL_EVP_aes_256_ccm),
    TEST_DECL(test_wolfSSL_EVP_aes_192_ccm),
    TEST_DECL(test_wolfSSL_EVP_aes_128_ccm),
    TEST_DECL(test_wolfSSL_EVP_rc4),
    TEST_DECL(test_wolfSSL_EVP_enc_null),
    TEST_DECL(test_wolfSSL_EVP_rc2_cbc),
    TEST_DECL(test_wolfSSL_EVP_mdc2),


#ifdef OPENSSL_EXTRA
    TEST_DECL(TestNullCipherUpdate),
    TEST_DECL(TestNullCipherUpdateEmptyData),
    TEST_DECL(TestNullCipherUpdateLargeData),
    TEST_DECL(TestNullCipherUpdateMultiple),
#endif
    TEST_DECL(test_evp_cipher_aes_gcm),
#endif
    TEST_DECL(test_wolfssl_EVP_aria_gcm),
    TEST_DECL(test_wolfSSL_EVP_Cipher_extra),
#ifdef OPENSSL_EXTRA
    TEST_DECL(test_wolfSSL_EVP_get_cipherbynid),
    TEST_DECL(test_wolfSSL_EVP_CIPHER_CTX),
#endif
#ifdef OPENSSL_ALL
    TEST_DECL(test_wolfSSL_EVP_CIPHER_CTX_iv_length),
    TEST_DECL(test_wolfSSL_EVP_CIPHER_CTX_key_length),
    TEST_DECL(test_wolfSSL_EVP_CIPHER_CTX_set_iv),
    TEST_DECL(test_wolfSSL_EVP_CIPHER_block_size),
    TEST_DECL(test_wolfSSL_EVP_CIPHER_iv_length),
    TEST_DECL(test_wolfSSL_EVP_X_STATE),
    TEST_DECL(test_wolfSSL_EVP_X_STATE_LEN),
    TEST_DECL(test_wolfSSL_EVP_BytesToKey),
#endif

    TEST_DECL(test_wolfSSL_EVP_PKEY_print_public),
    TEST_DECL(test_wolfSSL_EVP_PKEY_new_mac_key),
    TEST_DECL(test_wolfSSL_EVP_PKEY_new_CMAC_key),
    TEST_DECL(test_wolfSSL_EVP_PKEY_up_ref),
    TEST_DECL(test_wolfSSL_EVP_PKEY_hkdf),
    TEST_DECL(test_wolfSSL_EVP_PKEY_derive),
    TEST_DECL(test_wolfSSL_d2i_and_i2d_PublicKey),
    TEST_DECL(test_wolfSSL_d2i_and_i2d_PublicKey_ecc),
#ifndef NO_BIO
    TEST_DECL(test_wolfSSL_d2i_PUBKEY),
#endif
    TEST_DECL(test_wolfSSL_d2i_and_i2d_DSAparams),
    TEST_DECL(test_wolfSSL_i2d_PrivateKey),
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO)) && !defined(NO_RSA) && \
    !defined(NO_TLS)
#ifndef NO_BIO
    TEST_DECL(test_wolfSSL_d2i_PrivateKeys_bio),
#endif /* !NO_BIO */
#endif
#ifdef OPENSSL_ALL
    TEST_DECL(test_wolfSSL_EVP_PKEY_set1_get1_DSA),
    TEST_DECL(test_wolfSSL_EVP_PKEY_set1_get1_EC_KEY),
    TEST_DECL(test_wolfSSL_EVP_PKEY_set1_get1_DH),
    TEST_DECL(test_wolfSSL_EVP_PKEY_assign),
    TEST_DECL(test_wolfSSL_EVP_PKEY_assign_DH),
    TEST_DECL(test_wolfSSL_EVP_PKEY_base_id),
    TEST_DECL(test_wolfSSL_EVP_PKEY_id),
    TEST_DECL(test_wolfSSL_EVP_PKEY_paramgen),
    TEST_DECL(test_wolfSSL_EVP_PKEY_keygen),
    TEST_DECL(test_wolfSSL_EVP_PKEY_keygen_init),
    TEST_DECL(test_wolfSSL_EVP_PKEY_missing_parameters),
    TEST_DECL(test_wolfSSL_EVP_PKEY_copy_parameters),
    TEST_DECL(test_wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits),
    TEST_DECL(test_wolfSSL_EVP_PKEY_CTX_new_id),
    TEST_DECL(test_wolfSSL_EVP_PKEY_get0_EC_KEY),
#endif

    TEST_DECL(test_EVP_PKEY_rsa),
    TEST_DECL(test_EVP_PKEY_ec),
    TEST_DECL(test_wolfSSL_EVP_PKEY_encrypt),
    TEST_DECL(test_wolfSSL_EVP_PKEY_sign_verify_rsa),
    TEST_DECL(test_wolfSSL_EVP_PKEY_sign_verify_dsa),
    TEST_DECL(test_wolfSSL_EVP_PKEY_sign_verify_ec),
    TEST_DECL(test_EVP_PKEY_cmp),

#ifdef OPENSSL_ALL
    TEST_DECL(test_wolfSSL_EVP_SignInit_ex),
    TEST_DECL(test_wolfSSL_EVP_PKEY_param_check),
    TEST_DECL(test_wolfSSL_QT_EVP_PKEY_CTX_free),
#endif

    TEST_DECL(test_wolfSSL_EVP_PBE_scrypt),

    TEST_DECL(test_wolfSSL_CTX_add_extra_chain_cert),
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    TEST_DECL(test_wolfSSL_ERR_peek_last_error_line),
#endif
#ifndef NO_BIO
    TEST_DECL(test_wolfSSL_ERR_print_errors_cb),
    TEST_DECL(test_wolfSSL_GetLoggingCb),
    TEST_DECL(test_WOLFSSL_ERROR_MSG),
    TEST_DECL(test_wc_ERR_remove_state),
    TEST_DECL(test_wc_ERR_print_errors_fp),
#endif
    TEST_DECL(test_wolfSSL_configure_args),
    TEST_DECL(test_wolfSSL_sk_SSL_CIPHER),
    TEST_DECL(test_wolfSSL_set1_curves_list),
    TEST_DECL(test_wolfSSL_curves_mismatch),
    TEST_DECL(test_wolfSSL_set1_sigalgs_list),

    TEST_DECL(test_wolfSSL_OtherName),
    TEST_DECL(test_wolfSSL_FPKI),
    TEST_DECL(test_wolfSSL_URI),
    TEST_DECL(test_wolfSSL_TBS),

    TEST_DECL(test_wolfSSL_X509_STORE_CTX),
    TEST_DECL(test_wolfSSL_X509_STORE_CTX_ex),
    TEST_DECL(test_X509_STORE_untrusted),
#if defined(OPENSSL_ALL) && !defined(NO_RSA)
    TEST_DECL(test_X509_STORE_InvalidCa),
#endif
    TEST_DECL(test_wolfSSL_X509_STORE_CTX_trusted_stack_cleanup),
    TEST_DECL(test_wolfSSL_X509_STORE_CTX_get_issuer),
    TEST_DECL(test_wolfSSL_X509_STORE_set_flags),
    TEST_DECL(test_wolfSSL_X509_LOOKUP_load_file),
    TEST_DECL(test_wolfSSL_X509_Name_canon),
    TEST_DECL(test_wolfSSL_X509_LOOKUP_ctrl_file),
    TEST_DECL(test_wolfSSL_X509_LOOKUP_ctrl_hash_dir),
    TEST_DECL(test_wolfSSL_X509_NID),
    TEST_DECL(test_wolfSSL_X509_STORE_CTX_set_time),
    TEST_DECL(test_wolfSSL_get0_param),
    TEST_DECL(test_wolfSSL_X509_VERIFY_PARAM_set1_host),
    TEST_DECL(test_wolfSSL_set1_host),
    TEST_DECL(test_wolfSSL_X509_VERIFY_PARAM_set1_ip),
    TEST_DECL(test_wolfSSL_X509_STORE_CTX_get0_store),
    TEST_DECL(test_wolfSSL_X509_STORE),
    TEST_DECL(test_wolfSSL_X509_STORE_load_locations),
    TEST_DECL(test_X509_STORE_get0_objects),
    TEST_DECL(test_wolfSSL_X509_load_crl_file),
    TEST_DECL(test_wolfSSL_X509_STORE_get1_certs),
    TEST_DECL(test_wolfSSL_X509_STORE_set_get_crl),
    TEST_DECL(test_wolfSSL_X509_NAME_ENTRY_get_object),
    TEST_DECL(test_wolfSSL_X509_cmp_time),
    TEST_DECL(test_wolfSSL_X509_time_adj),

    /* X509 tests */
    TEST_DECL(test_wolfSSL_X509_subject_name_hash),
    TEST_DECL(test_wolfSSL_X509_issuer_name_hash),
    TEST_DECL(test_wolfSSL_X509_check_host),
    TEST_DECL(test_wolfSSL_X509_check_email),
    TEST_DECL(test_wolfSSL_X509_check_private_key),
    TEST_DECL(test_wolfSSL_X509),
    TEST_DECL(test_wolfSSL_X509_VERIFY_PARAM),
    TEST_DECL(test_wolfSSL_X509_sign),
    TEST_DECL(test_wolfSSL_X509_sign2),
    TEST_DECL(test_wolfSSL_X509_verify),
    TEST_DECL(test_wolfSSL_X509_get0_tbs_sigalg),
    TEST_DECL(test_wolfSSL_X509_ALGOR_get0),
    TEST_DECL(test_wolfSSL_X509_get_X509_PUBKEY),
    TEST_DECL(test_wolfSSL_X509_PUBKEY_RSA),
    TEST_DECL(test_wolfSSL_X509_PUBKEY_EC),
    TEST_DECL(test_wolfSSL_X509_PUBKEY_DSA),
    TEST_DECL(test_wolfSSL_PEM_write_bio_X509),
    TEST_DECL(test_wolfSSL_X509_NAME_get_entry),
    TEST_DECL(test_wolfSSL_X509_NAME),
    TEST_DECL(test_wolfSSL_X509_NAME_hash),
    TEST_DECL(test_wolfSSL_X509_NAME_print_ex),
    TEST_DECL(test_wolfSSL_X509_NAME_ENTRY),
    TEST_DECL(test_wolfSSL_X509_set_name),
    TEST_DECL(test_wolfSSL_X509_set_notAfter),
    TEST_DECL(test_wolfSSL_X509_set_notBefore),
    TEST_DECL(test_wolfSSL_X509_set_version),
    TEST_DECL(test_wolfSSL_X509_get_serialNumber),
    TEST_DECL(test_wolfSSL_X509_ext_get_critical_by_NID),
    TEST_DECL(test_wolfSSL_X509_CRL_distribution_points),
    TEST_DECL(test_wolfSSL_X509_SEP),
    TEST_DECL(test_wolfSSL_X509_CRL),
    TEST_DECL(test_wolfSSL_i2d_X509),
    TEST_DECL(test_wolfSSL_PEM_read_X509),
    TEST_DECL(test_wolfSSL_X509_check_ca),
    TEST_DECL(test_wolfSSL_X509_check_ip_asc),
    TEST_DECL(test_wolfSSL_X509_bad_altname),
    TEST_DECL(test_wolfSSL_X509_name_match),
    TEST_DECL(test_wolfSSL_X509_name_match2),
    TEST_DECL(test_wolfSSL_X509_name_match3),
    TEST_DECL(test_wolfSSL_X509_max_altnames),
    TEST_DECL(test_wolfSSL_X509_max_name_constraints),
    TEST_DECL(test_wolfSSL_make_cert),

    /* X509 ACERT tests */
    TEST_DECL(test_wolfSSL_X509_ACERT_verify),
    TEST_DECL(test_wolfSSL_X509_ACERT_misc_api),
    TEST_DECL(test_wolfSSL_X509_ACERT_buffer),
    TEST_DECL(test_wolfSSL_X509_ACERT_new_and_sign),
    TEST_DECL(test_wolfSSL_X509_ACERT_asn),

#ifndef NO_BIO
    TEST_DECL(test_wolfSSL_X509_INFO_multiple_info),
    TEST_DECL(test_wolfSSL_X509_INFO),
    TEST_DECL(test_wolfSSL_PEM_X509_INFO_read_bio),
    TEST_DECL(test_wolfSSL_PEM_X509_INFO_read),
#endif

#ifdef OPENSSL_ALL
    TEST_DECL(test_wolfSSL_X509_PUBKEY_get),
    TEST_DECL(test_wolfSSL_X509_set_pubkey),
#endif

    TEST_DECL(test_wolfSSL_X509_CA_num),
    TEST_DECL(test_x509_get_key_id),
    TEST_DECL(test_wolfSSL_X509_get_version),
#ifndef NO_BIO
    TEST_DECL(test_wolfSSL_X509_print),
    TEST_DECL(test_wolfSSL_X509_CRL_print),
#endif
    TEST_DECL(test_X509_get_signature_nid),
    /* X509 extension testing. */
    TEST_DECL(test_wolfSSL_X509_get_extension_flags),
    TEST_DECL(test_wolfSSL_X509_get_ext),
    TEST_DECL(test_wolfSSL_X509_get_ext_by_NID),
    TEST_DECL(test_wolfSSL_X509_get_ext_subj_alt_name),
    TEST_DECL(test_wolfSSL_X509_get_ext_count),
    TEST_DECL(test_wolfSSL_X509_set_ext),
    TEST_DECL(test_wolfSSL_X509_add_ext),
    TEST_DECL(test_wolfSSL_X509_EXTENSION_new),
    TEST_DECL(test_wolfSSL_X509_EXTENSION_dup),
    TEST_DECL(test_wolfSSL_X509_EXTENSION_get_object),
    TEST_DECL(test_wolfSSL_X509_EXTENSION_get_data),
    TEST_DECL(test_wolfSSL_X509_EXTENSION_get_critical),
    TEST_DECL(test_wolfSSL_X509_EXTENSION_create_by_OBJ),
    TEST_DECL(test_wolfSSL_X509V3_set_ctx),
    TEST_DECL(test_wolfSSL_X509V3_EXT_get),
    TEST_DECL(test_wolfSSL_X509V3_EXT_nconf),
    TEST_DECL(test_wolfSSL_X509V3_EXT),
    TEST_DECL(test_wolfSSL_X509V3_EXT_bc),
    TEST_DECL(test_wolfSSL_X509V3_EXT_san),
    TEST_DECL(test_wolfSSL_X509V3_EXT_aia),
    TEST_DECL(test_wolfSSL_X509V3_EXT_print),
    TEST_DECL(test_wolfSSL_X509_cmp),

    TEST_DECL(test_GENERAL_NAME_set0_othername),
    TEST_DECL(test_othername_and_SID_ext),
    TEST_DECL(test_wolfSSL_dup_CA_list),
    /* OpenSSL sk_X509 API test */
    TEST_DECL(test_sk_X509),
    /* OpenSSL sk_X509_CRL API test */
    TEST_DECL(test_sk_X509_CRL),

    /* OpenSSL X509 REQ API test */
    TEST_DECL(test_wolfSSL_d2i_X509_REQ),
    TEST_DECL(test_X509_REQ),
    TEST_DECL(test_wolfSSL_X509_REQ_print),

    /* OpenSSL compatibility outside SSL context w/ CRL lookup directory */
    TEST_DECL(test_X509_STORE_No_SSL_CTX),
    TEST_DECL(test_X509_LOOKUP_add_dir),

    /* RAND compatibility API */
    TEST_DECL(test_wolfSSL_RAND_set_rand_method),
    TEST_DECL(test_wolfSSL_RAND_bytes),
    TEST_DECL(test_wolfSSL_RAND),

    /* BN compatibility API */
    TEST_DECL(test_wolfSSL_BN_CTX),
    TEST_DECL(test_wolfSSL_BN),
    TEST_DECL(test_wolfSSL_BN_init),
    TEST_DECL(test_wolfSSL_BN_enc_dec),
    TEST_DECL(test_wolfSSL_BN_word),
    TEST_DECL(test_wolfSSL_BN_bits),
    TEST_DECL(test_wolfSSL_BN_shift),
    TEST_DECL(test_wolfSSL_BN_math),
    TEST_DECL(test_wolfSSL_BN_math_mod),
    TEST_DECL(test_wolfSSL_BN_math_other),
    TEST_DECL(test_wolfSSL_BN_rand),
    TEST_DECL(test_wolfSSL_BN_prime),

    /* OpenSSL PKCS5 API test */
    TEST_DECL(test_wolfSSL_PKCS5),

    /* OpenSSL PKCS8 API test */
    TEST_DECL(test_wolfSSL_PKCS8_Compat),
    TEST_DECL(test_wolfSSL_PKCS8_d2i),

    /* OpenSSL PKCS7 API test */
    TEST_DECL(test_wolfssl_PKCS7),
    TEST_DECL(test_wolfSSL_PKCS7_certs),
    TEST_DECL(test_wolfSSL_PKCS7_sign),
    TEST_DECL(test_wolfSSL_PKCS7_SIGNED_new),
#ifndef NO_BIO
    TEST_DECL(test_wolfSSL_PEM_write_bio_PKCS7),
#ifdef HAVE_SMIME
    TEST_DECL(test_wolfSSL_SMIME_read_PKCS7),
    TEST_DECL(test_wolfSSL_SMIME_write_PKCS7),
#endif /* HAVE_SMIME */
#endif /* !NO_BIO */

    /* OpenSSL PKCS12 API test */
    TEST_DECL(test_wolfSSL_PKCS12),

    /* Can't memory test as callbacks use Assert. */
    TEST_DECL(test_error_queue_per_thread),
    TEST_DECL(test_wolfSSL_ERR_put_error),
    TEST_DECL(test_wolfSSL_ERR_get_error_order),
#ifndef NO_BIO
    TEST_DECL(test_wolfSSL_ERR_print_errors),
#endif

    TEST_DECL(test_OBJ_NAME_do_all),
    TEST_DECL(test_wolfSSL_OBJ),
    TEST_DECL(test_wolfSSL_OBJ_cmp),
    TEST_DECL(test_wolfSSL_OBJ_txt2nid),
    TEST_DECL(test_wolfSSL_OBJ_txt2obj),
#ifdef OPENSSL_ALL
    TEST_DECL(test_wolfSSL_OBJ_ln),
    TEST_DECL(test_wolfSSL_OBJ_sn),
#endif

#ifndef NO_BIO
    TEST_DECL(test_wolfSSL_BIO_gets),
    TEST_DECL(test_wolfSSL_BIO_puts),
    TEST_DECL(test_wolfSSL_BIO_dump),
    /* Can't memory test as server hangs. */
    TEST_DECL(test_wolfSSL_BIO_should_retry),
    TEST_DECL(test_wolfSSL_BIO_write),
    TEST_DECL(test_wolfSSL_BIO_printf),
    TEST_DECL(test_wolfSSL_BIO_f_md),
    TEST_DECL(test_wolfSSL_BIO_up_ref),
    TEST_DECL(test_wolfSSL_BIO_reset),
    TEST_DECL(test_wolfSSL_BIO_get_len),
#endif

    TEST_DECL(test_wolfSSL_check_domain),
    TEST_DECL(test_wolfSSL_cert_cb),
    TEST_DECL(test_wolfSSL_cert_cb_dyn_ciphers),
    TEST_DECL(test_wolfSSL_ciphersuite_auth),
    TEST_DECL(test_wolfSSL_sigalg_info),
    /* Can't memory test as tcp_connect aborts. */
    TEST_DECL(test_wolfSSL_SESSION),
    TEST_DECL(test_wolfSSL_SESSION_expire_downgrade),
    TEST_DECL(test_wolfSSL_CTX_sess_set_remove_cb),
    TEST_DECL(test_wolfSSL_ticket_keys),
    TEST_DECL(test_wolfSSL_sk_GENERAL_NAME),
    TEST_DECL(test_wolfSSL_GENERAL_NAME_print),
    TEST_DECL(test_wolfSSL_sk_DIST_POINT),
    TEST_DECL(test_wolfSSL_verify_mode),
    TEST_DECL(test_wolfSSL_verify_depth),
    TEST_DECL(test_wolfSSL_verify_result),
    TEST_DECL(test_wolfSSL_msg_callback),

    TEST_DECL(test_wolfSSL_OCSP_id_get0_info),
    TEST_DECL(test_wolfSSL_i2d_OCSP_CERTID),
    TEST_DECL(test_wolfSSL_d2i_OCSP_CERTID),
    TEST_DECL(test_wolfSSL_OCSP_id_cmp),
    TEST_DECL(test_wolfSSL_OCSP_SINGLERESP_get0_id),
    TEST_DECL(test_wolfSSL_OCSP_single_get0_status),
    TEST_DECL(test_wolfSSL_OCSP_resp_count),
    TEST_DECL(test_wolfSSL_OCSP_resp_get0),
    TEST_DECL(test_wolfSSL_OCSP_parse_url),
    TEST_DECL(test_wolfSSL_OCSP_REQ_CTX),

    TEST_DECL(test_wolfSSL_PEM_read),

    TEST_DECL(test_wolfSSL_OpenSSL_version),
    TEST_DECL(test_wolfSSL_OpenSSL_add_all_algorithms),
    TEST_DECL(test_wolfSSL_OPENSSL_hexstr2buf),

    TEST_DECL(test_CONF_modules_xxx),
#ifdef OPENSSL_ALL
    TEST_DECL(test_wolfSSL_TXT_DB),
    TEST_DECL(test_wolfSSL_NCONF),
#endif

    TEST_DECL(test_wolfSSL_CRYPTO_memcmp),
    TEST_DECL(test_wolfSSL_CRYPTO_get_ex_new_index),
    TEST_DECL(test_wolfSSL_SESSION_get_ex_new_index),
    TEST_DECL(test_CRYPTO_set_dynlock_xxx),
    TEST_DECL(test_CRYPTO_THREADID_xxx),
    TEST_DECL(test_ENGINE_cleanup),
    /* test the no op functions for compatibility */
    TEST_DECL(test_no_op_functions),
    /* OpenSSL error API tests */
    TEST_DECL(test_ERR_load_crypto_strings),

#ifdef OPENSSL_ALL
    TEST_DECL(test_wolfSSL_sk_CIPHER_description),
    TEST_DECL(test_wolfSSL_get_ciphers_compat),

    TEST_DECL(test_wolfSSL_CTX_ctrl),
#endif /* OPENSSL_ALL */
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO)) && !defined(NO_RSA)
    TEST_DECL(test_wolfSSL_CTX_use_certificate_ASN1),
#endif /* (OPENSSL_ALL || WOLFSSL_ASIO) && !NO_RSA */

    /*********************************
     * Crypto API tests
     *********************************/

    TEST_DECL(test_wolfSSL_MD4),
    TEST_DECL(test_wolfSSL_MD5),
    TEST_DECL(test_wolfSSL_MD5_Transform),
    TEST_DECL(test_wolfSSL_SHA),
    TEST_DECL(test_wolfSSL_SHA_Transform),
    TEST_DECL(test_wolfSSL_SHA224),
    TEST_DECL(test_wolfSSL_SHA256),
    TEST_DECL(test_wolfSSL_SHA256_Transform),
    TEST_DECL(test_wolfSSL_SHA512_Transform),
    TEST_DECL(test_wolfSSL_SHA512_224_Transform),
    TEST_DECL(test_wolfSSL_SHA512_256_Transform),
    TEST_DECL(test_wolfSSL_HMAC_CTX),
    TEST_DECL(test_wolfSSL_HMAC),
    TEST_DECL(test_wolfSSL_CMAC),

    TEST_DECL(test_wolfSSL_DES),
    TEST_DECL(test_wolfSSL_DES_ncbc),
    TEST_DECL(test_wolfSSL_DES_ecb_encrypt),
    TEST_DECL(test_wolfSSL_DES_ede3_cbc_encrypt),
    TEST_DECL(test_wolfSSL_AES_encrypt),
    TEST_DECL(test_wolfSSL_AES_ecb_encrypt),
    TEST_DECL(test_wolfSSL_AES_cbc_encrypt),
    TEST_DECL(test_wolfSSL_AES_cfb128_encrypt),
    TEST_DECL(test_wolfSSL_CRYPTO_cts128),
    TEST_DECL(test_wolfSSL_RC4),

    TEST_DECL(test_wolfSSL_RSA),
    TEST_DECL(test_wolfSSL_RSA_DER),
    TEST_DECL(test_wolfSSL_RSA_print),
    TEST_DECL(test_wolfSSL_RSA_padding_add_PKCS1_PSS),
    TEST_DECL(test_wolfSSL_RSA_sign_sha3),
    TEST_DECL(test_wolfSSL_RSA_get0_key),
    TEST_DECL(test_wolfSSL_RSA_meth),
    TEST_DECL(test_wolfSSL_RSA_verify),
    TEST_DECL(test_wolfSSL_RSA_sign),
    TEST_DECL(test_wolfSSL_RSA_sign_ex),
    TEST_DECL(test_wolfSSL_RSA_public_decrypt),
    TEST_DECL(test_wolfSSL_RSA_private_encrypt),
    TEST_DECL(test_wolfSSL_RSA_public_encrypt),
    TEST_DECL(test_wolfSSL_RSA_private_decrypt),
    TEST_DECL(test_wolfSSL_RSA_GenAdd),
    TEST_DECL(test_wolfSSL_RSA_blinding_on),
    TEST_DECL(test_wolfSSL_RSA_ex_data),
    TEST_DECL(test_wolfSSL_RSA_LoadDer),
    TEST_DECL(test_wolfSSL_RSA_To_Der),
    TEST_DECL(test_wolfSSL_PEM_read_RSAPublicKey),
    TEST_DECL(test_wolfSSL_PEM_write_RSA_PUBKEY),
    TEST_DECL(test_wolfSSL_PEM_write_RSAPrivateKey),
    TEST_DECL(test_wolfSSL_PEM_write_mem_RSAPrivateKey),

    TEST_DECL(test_wolfSSL_DH),
    TEST_DECL(test_wolfSSL_DH_dup),
    TEST_DECL(test_wolfSSL_DH_check),
    TEST_DECL(test_wolfSSL_DH_prime),
    TEST_DECL(test_wolfSSL_DH_1536_prime),
    TEST_DECL(test_wolfSSL_DH_get_2048_256),
    TEST_DECL(test_wolfSSL_PEM_write_DHparams),
    TEST_DECL(test_wolfSSL_PEM_read_DHparams),
    TEST_DECL(test_wolfSSL_d2i_DHparams),
    TEST_DECL(test_wolfSSL_DH_LoadDer),
    TEST_DECL(test_wolfSSL_i2d_DHparams),

#if defined(HAVE_ECC) && !defined(OPENSSL_NO_PK)
    TEST_DECL(test_wolfSSL_EC_GROUP),
    TEST_DECL(test_wolfSSL_i2d_ECPKParameters),
    TEST_DECL(test_wolfSSL_PEM_read_bio_ECPKParameters),
    TEST_DECL(test_wolfSSL_EC_POINT),
    TEST_DECL(test_wolfSSL_SPAKE),
    TEST_DECL(test_wolfSSL_EC_KEY_generate),
    TEST_DECL(test_EC_i2d),
    TEST_DECL(test_wolfSSL_EC_curve),
    TEST_DECL(test_wolfSSL_EC_KEY_dup),
    TEST_DECL(test_wolfSSL_EC_KEY_set_group),
    TEST_DECL(test_wolfSSL_EC_KEY_set_conv_form),
    TEST_DECL(test_wolfSSL_EC_KEY_private_key),
    TEST_DECL(test_wolfSSL_EC_KEY_public_key),
    TEST_DECL(test_wolfSSL_EC_KEY_print_fp),
    TEST_DECL(test_wolfSSL_EC_get_builtin_curves),
    TEST_DECL(test_wolfSSL_ECDSA_SIG),
    TEST_DECL(test_ECDSA_size_sign),
    TEST_DECL(test_ECDH_compute_key),
#endif

#ifdef OPENSSL_EXTRA
    TEST_DECL(test_EC25519),
    TEST_DECL(test_ED25519),
    TEST_DECL(test_EC448),
    TEST_DECL(test_ED448),
#endif

    TEST_DECL(test_DSA_do_sign_verify),
#ifdef OPENSSL_ALL
    TEST_DECL(test_wolfSSL_DSA_generate_parameters),
    TEST_DECL(test_wolfSSL_DSA_SIG),
#endif

    TEST_DECL(test_openssl_generate_key_and_cert),

    TEST_DECL(test_wolfSSL_FIPS_mode),
    TEST_DECL(test_openssl_FIPS_drbg),

    /*********************************
     * CertManager API tests
     *********************************/

    TEST_DECL(test_wolfSSL_CertManagerAPI),
    TEST_DECL(test_wolfSSL_CertManagerLoadCABuffer),
    TEST_DECL(test_wolfSSL_CertManagerLoadCABuffer_ex),
    TEST_DECL(test_wolfSSL_CertManagerGetCerts),
    TEST_DECL(test_wolfSSL_CertManagerSetVerify),
    TEST_DECL(test_wolfSSL_CertManagerNameConstraint),
    TEST_DECL(test_wolfSSL_CertManagerNameConstraint2),
    TEST_DECL(test_wolfSSL_CertManagerNameConstraint3),
    TEST_DECL(test_wolfSSL_CertManagerNameConstraint4),
    TEST_DECL(test_wolfSSL_CertManagerNameConstraint5),
    TEST_DECL(test_wolfSSL_CertManagerCRL),
    TEST_DECL(test_wolfSSL_CertManagerCheckOCSPResponse),
    TEST_DECL(test_wolfSSL_CheckOCSPResponse),
#ifdef HAVE_CERT_CHAIN_VALIDATION
    TEST_DECL(test_various_pathlen_chains),
#endif

    /*********************************
     * SSL/TLS API tests
     *********************************/

    TEST_DECL(test_wolfSSL_Method_Allocators),
#if !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)
    TEST_DECL(test_wolfSSL_CTX_new),
#endif
    TEST_DECL(test_server_wolfSSL_new),
    TEST_DECL(test_client_wolfSSL_new),
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER)) && \
    !defined(NO_TLS) && \
    (!defined(NO_RSA) || defined(HAVE_ECC)) && !defined(NO_FILESYSTEM)
    TEST_DECL(test_for_double_Free),
#endif
    TEST_DECL(test_wolfSSL_set_options),

#ifdef WOLFSSL_TLS13
    /* TLS v1.3 API tests */
    TEST_DECL(test_tls13_apis),
    TEST_DECL(test_tls13_cipher_suites),
#endif

    TEST_DECL(test_wolfSSL_tmp_dh),
    TEST_DECL(test_wolfSSL_ctrl),

#if defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
    defined(WOLFSSL_OPENSSH) || defined(HAVE_SBLIM_SFCB)))
    TEST_DECL(test_wolfSSL_set_SSL_CTX),
#endif
    TEST_DECL(test_wolfSSL_CTX_get_min_proto_version),
    TEST_DECL(test_wolfSSL_security_level),
    TEST_DECL(test_wolfSSL_crypto_policy),
    TEST_DECL(test_wolfSSL_crypto_policy_certs_and_keys),
    TEST_DECL(test_wolfSSL_crypto_policy_tls_methods),
    TEST_DECL(test_wolfSSL_crypto_policy_ciphers),
    TEST_DECL(test_wolfSSL_SSL_in_init),
    TEST_DECL(test_wolfSSL_CTX_set_timeout),
    TEST_DECL(test_wolfSSL_set_psk_use_session_callback),

    TEST_DECL(test_CONF_CTX_FILE),
    TEST_DECL(test_CONF_CTX_CMDLINE),

#if !defined(NO_CERTS) && (!defined(NO_WOLFSSL_CLIENT) || \
    !defined(WOLFSSL_NO_CLIENT_AUTH)) && !defined(NO_FILESYSTEM)
    /* Use the Cert Manager(CM) API to generate the error ASN_SIG_CONFIRM_E */
    /* Bad certificate signature tests */
    TEST_DECL(test_EccSigFailure_cm),
    TEST_DECL(test_RsaSigFailure_cm),
#endif /* NO_CERTS */

    /* PKCS8 testing */
    TEST_DECL(test_wolfSSL_no_password_cb),
    TEST_DECL(test_wolfSSL_PKCS8),
    TEST_DECL(test_wolfSSL_PKCS8_ED25519),
    TEST_DECL(test_wolfSSL_PKCS8_ED448),

#ifdef HAVE_IO_TESTS_DEPENDENCIES
    TEST_DECL(test_wolfSSL_get_finished),
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_CTX_add_session),
    /* Large number of memory allocations. */
    TEST_DECL(test_wolfSSL_CTX_add_session_ext_tls13),
    /* Large number of memory allocations. */
    TEST_DECL(test_wolfSSL_CTX_add_session_ext_dtls13),
    /* Large number of memory allocations. */
    TEST_DECL(test_wolfSSL_CTX_add_session_ext_tls12),
    /* Large number of memory allocations. */
    TEST_DECL(test_wolfSSL_CTX_add_session_ext_dtls12),
    /* Large number of memory allocations. */
    TEST_DECL(test_wolfSSL_CTX_add_session_ext_tls11),
    /* Large number of memory allocations. */
    TEST_DECL(test_wolfSSL_CTX_add_session_ext_dtls1),
#endif
    TEST_DECL(test_SSL_CIPHER_get_xxx),
    TEST_DECL(test_wolfSSL_ERR_strings),
    TEST_DECL(test_wolfSSL_CTX_set_cipher_list_bytes),
    TEST_DECL(test_wolfSSL_CTX_use_certificate),
    TEST_DECL(test_wolfSSL_CTX_use_certificate_file),
    TEST_DECL(test_wolfSSL_CTX_use_certificate_buffer),
    TEST_DECL(test_wolfSSL_use_certificate_buffer),
    TEST_DECL(test_wolfSSL_CTX_use_PrivateKey_file),
    TEST_DECL(test_wolfSSL_CTX_use_RSAPrivateKey_file),
    TEST_DECL(test_wolfSSL_use_RSAPrivateKey_file),
    TEST_DECL(test_wolfSSL_CTX_use_PrivateKey),
    TEST_DECL(test_wolfSSL_CTX_load_verify_locations),
    /* Large number of memory allocations. */
    TEST_DECL(test_wolfSSL_CTX_load_system_CA_certs),

#ifdef HAVE_CERT_CHAIN_VALIDATION
    TEST_DECL(test_wolfSSL_CertRsaPss),
#endif
    TEST_DECL(test_wolfSSL_CTX_load_verify_locations_ex),
    TEST_DECL(test_wolfSSL_CTX_load_verify_buffer_ex),
    TEST_DECL(test_wolfSSL_CTX_load_verify_chain_buffer_format),
    TEST_DECL(test_wolfSSL_CTX_add1_chain_cert),
    TEST_DECL(test_wolfSSL_CTX_use_certificate_chain_buffer_format),
    TEST_DECL(test_wolfSSL_CTX_use_certificate_chain_file_format),
    TEST_DECL(test_wolfSSL_use_certificate_chain_file),
    TEST_DECL(test_wolfSSL_CTX_trust_peer_cert),
    TEST_DECL(test_wolfSSL_CTX_LoadCRL),
    TEST_DECL(test_wolfSSL_crl_update_cb),
    TEST_DECL(test_wolfSSL_CTX_SetTmpDH_file),
    TEST_DECL(test_wolfSSL_CTX_SetTmpDH_buffer),
    TEST_DECL(test_wolfSSL_CTX_SetMinMaxDhKey_Sz),
    TEST_DECL(test_wolfSSL_CTX_der_load_verify_locations),
    TEST_DECL(test_wolfSSL_CTX_enable_disable),
    TEST_DECL(test_wolfSSL_CTX_ticket_API),
    TEST_DECL(test_wolfSSL_SetTmpDH_file),
    TEST_DECL(test_wolfSSL_SetTmpDH_buffer),
    TEST_DECL(test_wolfSSL_SetMinMaxDhKey_Sz),
    TEST_DECL(test_SetTmpEC_DHE_Sz),
    TEST_DECL(test_wolfSSL_CTX_get0_privatekey),
#ifdef WOLFSSL_DTLS
    TEST_DECL(test_wolfSSL_DtlsUpdateWindow),
    TEST_DECL(test_wolfSSL_DTLS_fragment_buckets),
#endif
    TEST_DECL(test_wolfSSL_dtls_set_mtu),
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_dtls_plaintext),
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES)
    TEST_DECL(test_wolfSSL_read_write),
    TEST_DECL(test_wolfSSL_read_write_ex),
    /* Can't memory test as server hangs if client fails before second connect.
     */
    TEST_DECL(test_wolfSSL_reuse_WOLFSSLobj),
    TEST_DECL(test_wolfSSL_CTX_verifyDepth_ServerClient_1),
    TEST_DECL(test_wolfSSL_CTX_verifyDepth_ServerClient_2),
    TEST_DECL(test_wolfSSL_CTX_verifyDepth_ServerClient_3),
    TEST_DECL(test_wolfSSL_CTX_set_cipher_list),
    /* Can't memory test as server hangs. */
    TEST_DECL(test_wolfSSL_dtls_export),
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_tls_export),
#endif
    TEST_DECL(test_wolfSSL_dtls_export_peers),
    TEST_DECL(test_wolfSSL_SetMinVersion),
    TEST_DECL(test_wolfSSL_CTX_SetMinVersion),

    /* wolfSSL handshake APIs. */
    TEST_DECL(test_wolfSSL_CTX_get0_set1_param),
    TEST_DECL(test_wolfSSL_a2i_IPADDRESS),
    TEST_DECL(test_wolfSSL_BUF),
    TEST_DECL(test_wolfSSL_set_tlsext_status_type),
    TEST_DECL(test_wolfSSL_get_client_ciphers),
    /* Can't memory test as server hangs. */
    TEST_DECL(test_wolfSSL_CTX_set_client_CA_list),
    TEST_DECL(test_wolfSSL_CTX_add_client_CA),
    TEST_DECL(test_wolfSSL_CTX_set_srp_username),
    TEST_DECL(test_wolfSSL_CTX_set_srp_password),
    TEST_DECL(test_wolfSSL_CTX_set_keylog_callback),
    TEST_DECL(test_wolfSSL_CTX_get_keylog_callback),
    TEST_DECL(test_wolfSSL_Tls12_Key_Logging_test),
    /* Can't memory test as server hangs. */
    TEST_DECL(test_wolfSSL_Tls13_Key_Logging_test),
    TEST_DECL(test_wolfSSL_Tls13_postauth),
    TEST_DECL(test_wolfSSL_set_ecdh_auto),
    TEST_DECL(test_wolfSSL_CTX_set_ecdh_auto),
    TEST_DECL(test_wolfSSL_set_minmax_proto_version),
    TEST_DECL(test_wolfSSL_CTX_set_max_proto_version),
    TEST_DECL(test_wolfSSL_THREADID_hash),

    /* TLS extensions tests */
#ifdef HAVE_IO_TESTS_DEPENDENCIES
#ifdef HAVE_SNI
    TEST_DECL(test_wolfSSL_UseSNI_params),
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_UseSNI_connection),
    TEST_DECL(test_wolfSSL_SNI_GetFromBuffer),
#endif /* HAVE_SNI */
#endif
    TEST_DECL(test_wolfSSL_UseTrustedCA),
    TEST_DECL(test_wolfSSL_UseMaxFragment),
    TEST_DECL(test_wolfSSL_UseTruncatedHMAC),
    TEST_DECL(test_wolfSSL_UseSupportedCurve),
#if defined(HAVE_ALPN) && defined(HAVE_IO_TESTS_DEPENDENCIES)
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_UseALPN_connection),
    TEST_DECL(test_wolfSSL_UseALPN_params),
#endif
#ifdef HAVE_ALPN_PROTOS_SUPPORT
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_set_alpn_protos),
#endif
    TEST_DECL(test_wolfSSL_DisableExtendedMasterSecret),
    TEST_DECL(test_wolfSSL_wolfSSL_UseSecureRenegotiation),
    TEST_DECL(test_wolfSSL_SCR_Reconnect),
    TEST_DECL(test_tls_ext_duplicate),
#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES)
    TEST_DECL(test_wolfSSL_Tls13_ECH_params),
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_Tls13_ECH),
#endif

    TEST_DECL(test_wolfSSL_X509_TLS_version_test_1),
    TEST_DECL(test_wolfSSL_X509_TLS_version_test_2),

    /* OCSP Stapling */
    TEST_DECL(test_wolfSSL_UseOCSPStapling),
    TEST_DECL(test_wolfSSL_UseOCSPStaplingV2),
    TEST_DECL(test_self_signed_stapling),
    TEST_DECL(test_ocsp_callback_fails),

    /* Multicast */
    TEST_DECL(test_wolfSSL_mcast),

    TEST_DECL(test_wolfSSL_read_detect_TCP_disconnect),

    TEST_DECL(test_wolfSSL_msgCb),
    TEST_DECL(test_wolfSSL_either_side),
    TEST_DECL(test_wolfSSL_DTLS_either_side),
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_dtls_fragments),
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_dtls_AEAD_limit),
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_ignore_alert_before_cookie),
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_dtls_bad_record),
    /* Uses Assert in handshake callback. */
    TEST_DECL(test_wolfSSL_dtls_stateless),
    TEST_DECL(test_generate_cookie),

#ifndef NO_BIO
    /* Can't memory test as server hangs. */
    TEST_DECL(test_wolfSSL_BIO_connect),
    /* Can't memory test as server Asserts in thread. */
    TEST_DECL(test_wolfSSL_BIO_accept),
    TEST_DECL(test_wolfSSL_BIO_tls),
    TEST_DECL(test_wolfSSL_BIO_s_null),
    TEST_DECL(test_wolfSSL_BIO_datagram),
#endif

#if defined(HAVE_PK_CALLBACKS) && !defined(WOLFSSL_NO_TLS12)
    TEST_DECL(test_DhCallbacks),
#endif

#if defined(HAVE_KEYING_MATERIAL) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
    TEST_DECL(test_export_keying_material),
#endif

    /* Can't memory test as client/server Asserts in thread. */
    TEST_DECL(test_ticket_and_psk_mixing),
    /* Can't memory test as client/server Asserts in thread. */
    TEST_DECL(test_prioritize_psk),

    /* Can't memory test as client/server hangs. */
    TEST_DECL(test_wc_CryptoCb),
    /* Can't memory test as client/server hangs. */
    TEST_DECL(test_wolfSSL_CTX_StaticMemory),
#if !defined(NO_FILESYSTEM) &&                                                 \
     defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) &&                    \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
#ifdef WOLFSSL_DTLS_NO_HVR_ON_RESUME
    TEST_DECL(test_wolfSSL_dtls_stateless_resume),
#endif /* WOLFSSL_DTLS_NO_HVR_ON_RESUME */
#ifdef HAVE_MAX_FRAGMENT
    TEST_DECL(test_wolfSSL_dtls_stateless_maxfrag),
#endif /* HAVE_MAX_FRAGMENT */
#ifndef NO_RSA
    TEST_DECL(test_wolfSSL_dtls_stateless2),
#if !defined(NO_OLD_TLS)
    TEST_DECL(test_wolfSSL_dtls_stateless_downgrade),
#endif /* !defined(NO_OLD_TLS) */
#endif /* ! NO_RSA */
#endif /* defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) &&     \
        *  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) */
    TEST_DECL(test_wolfSSL_CTX_set_ciphersuites),
    TEST_DECL(test_wolfSSL_CRL_CERT_REVOKED_alert),
    TEST_DECL(test_TLS_13_ticket_different_ciphers),
    TEST_DECL(test_WOLFSSL_dtls_version_alert),

#if defined(WOLFSSL_TICKET_NONCE_MALLOC) && defined(HAVE_SESSION_TICKET)       \
    && defined(WOLFSSL_TLS13) &&                                               \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    TEST_DECL(test_ticket_nonce_malloc),
#endif
    TEST_DECL(test_ticket_ret_create),
    TEST_DECL(test_wrong_cs_downgrade),
    TEST_DECL(test_extra_alerts_wrong_cs),
    TEST_DECL(test_extra_alerts_skip_hs),
    TEST_DECL(test_extra_alerts_bad_psk),
    TEST_DECL(test_multiple_alerts_EAGAIN),
    TEST_DECL(test_tls13_bad_psk_binder),
    /* Can't memory test as client/server Asserts. */
    TEST_DECL(test_harden_no_secure_renegotiation),
    TEST_DECL(test_override_alt_cert_chain),
    TEST_DECL(test_rpk_set_xxx_cert_type),
    TEST_DECL(test_tls13_rpk_handshake),
    TEST_DECL(test_dtls13_bad_epoch_ch),
    TEST_DECL(test_short_session_id),
    TEST_DECL(test_wolfSSL_dtls13_null_cipher),
    /* Can't memory test as client/server hangs. */
    TEST_DECL(test_dtls_msg_from_other_peer),
    TEST_DECL(test_dtls_ipv6_check),
    TEST_DECL(test_wolfSSL_SCR_after_resumption),
    TEST_DECL(test_dtls_no_extensions),
    TEST_DECL(test_tls_alert_no_server_hello),
    TEST_DECL(test_TLSX_CA_NAMES_bad_extension),
    TEST_DECL(test_dtls_1_0_hvr_downgrade),
    TEST_DECL(test_session_ticket_no_id),
    TEST_DECL(test_session_ticket_hs_update),
    TEST_DECL(test_dtls_downgrade_scr_server),
    TEST_DECL(test_dtls_downgrade_scr),
    TEST_DECL(test_dtls_client_hello_timeout_downgrade),
    TEST_DECL(test_dtls_client_hello_timeout),
    TEST_DECL(test_dtls_dropped_ccs),
    TEST_DECL(test_dtls_seq_num_downgrade),
    TEST_DECL(test_certreq_sighash_algos),
    TEST_DECL(test_revoked_loaded_int_cert),
    TEST_DECL(test_dtls_frag_ch),
    TEST_DECL(test_dtls13_frag_ch_pq),
    TEST_DECL(test_dtls_empty_keyshare_with_cookie),
    TEST_DECL(test_dtls_old_seq_number),
    TEST_DECL(test_dtls12_basic_connection_id),
    TEST_DECL(test_dtls13_basic_connection_id),
    TEST_DECL(test_dtls12_missing_finished),
    TEST_DECL(test_dtls13_missing_finished_client),
    TEST_DECL(test_dtls13_missing_finished_server),
    TEST_DECL(test_tls13_pq_groups),
    TEST_DECL(test_tls13_early_data),
    TEST_DECL(test_tls_multi_handshakes_one_record),
    TEST_DECL(test_write_dup),
    TEST_DECL(test_read_write_hs),
    TEST_DECL(test_get_signature_nid),
    TEST_DECL(test_tls_cert_store_unchanged),
    TEST_DECL(test_wolfSSL_SendUserCanceled),
    TEST_DECL(test_wolfSSL_SSLDisableRead),
    TEST_DECL(test_wolfSSL_inject),
    TEST_DECL(test_wolfSSL_dtls_cid_parse),
    TEST_DECL(test_ocsp_status_callback),
    TEST_DECL(test_ocsp_basic_verify),
    TEST_DECL(test_ocsp_response_parsing),
    TEST_DECL(test_ocsp_certid_enc_dec),
    /* This test needs to stay at the end to clean up any caches allocated. */
    TEST_DECL(test_wolfSSL_Cleanup)
};

#define TEST_CASE_CNT (int)(sizeof(testCases) / sizeof(*testCases))

static void TestSetup(void)
{
/* Stub, for now. Add common test setup code here. */
}

static void TestCleanup(void)
{
#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
    /* Clear any errors added to the error queue during the test run. */
    wolfSSL_ERR_clear_error();
#endif /* OPENSSL_EXTRA || DEBUG_WOLFSSL_VERBOSE */
}

/* Print out all API test cases with numeric identifier.
 */
void ApiTest_PrintTestCases(void)
{
    int i;

    printf("All Test Cases:\n");
    for (i = 0; i < TEST_CASE_CNT; i++) {
        printf("%3d: %s\n", i + 1, testCases[i].name);
    }
}

/* Add test case with index to the list to run.
 *
 * @param [in]  idx  Index of test case to run starting at 1.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when index is out of range of test case identifiers.
 */
int ApiTest_RunIdx(int idx)
{
    if (idx < 1 || idx > TEST_CASE_CNT) {
        printf("Index out of range (1 - %d): %d\n", TEST_CASE_CNT, idx);
        return BAD_FUNC_ARG;
    }

    testAll = 0;
    testCases[idx-1].run = 1;

    return 0;
}

/* Add test cases with part of the name to the list to run.
 *
 * @param [in]  name  Part of the name of test cases to run.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when name is not a known test case name.
 */
int ApiTest_RunPartName(char* name)
{
    int i;
    int cnt = 0;

    for (i = 0; i < TEST_CASE_CNT; i++) {
        if (XSTRSTR(testCases[i].name, name) != NULL) {
            cnt++;
            testAll = 0;
            testCases[i].run = 1;
        }
    }
    if (cnt > 0)
        return 0;

    printf("Not found a test case with: %s\n", name);
    printf("Use --list to see all test case names.\n");
    return BAD_FUNC_ARG;
}

/* Add test case with name to the list to run.
 *
 * @param [in]  name  Name of test case to run.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when name is not a known test case name.
 */
int ApiTest_RunName(char* name)
{
    int i;

    for (i = 0; i < TEST_CASE_CNT; i++) {
        if (XSTRCMP(testCases[i].name, name) == 0) {
            testAll = 0;
            testCases[i].run = 1;
            return 0;
        }
    }

    printf("Test case name not found: %s\n", name);
    printf("Use --list to see all test case names.\n");
    return BAD_FUNC_ARG;
}

/* Converts the result code to a string.
 *
 * @param [in]  res  Test result code.
 * @return  String describing test result.
 */
static const char* apitest_res_string(int res)
{
    const char* str = "invalid result";

    switch (res) {
    case TEST_SUCCESS:
        str = "passed";
        break;
    case TEST_FAIL:
        str = "failed";
        break;
    case TEST_SKIPPED:
        str = "skipped";
        break;
    }

    return str;
}

#ifndef WOLFSSL_UNIT_TEST_NO_TIMING
static double gettime_secs(void)
    #if defined(_WIN32) && (defined(_MSC_VER) || defined(__WATCOMC__))
    {
        /* there's no gettimeofday for Windows, so we'll use system time */
        #define EPOCH_DIFF 11644473600LL
        FILETIME currentFileTime;
        ULARGE_INTEGER uli = { 0, 0 };

    #if defined(__WATCOMC__)
        GetSystemTimeAsFileTime(&currentFileTime);
    #else
        GetSystemTimePreciseAsFileTime(&currentFileTime);
    #endif

        uli.LowPart = currentFileTime.dwLowDateTime;
        uli.HighPart = currentFileTime.dwHighDateTime;

        /* Convert to seconds since Unix epoch */
        return (double)((uli.QuadPart - (EPOCH_DIFF * 10000000)) / 10000000.0);
    }
    #else
    {
        struct timeval tv;
        LIBCALL_CHECK_RET(gettimeofday(&tv, 0));

        return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
    }
    #endif
#endif

int ApiTest(void)
{
    int i;
    int ret;
    int res = 0;
#ifndef WOLFSSL_UNIT_TEST_NO_TIMING
    double timeDiff;
#endif

    printf(" Begin API Tests\n");
    fflush(stdout);

    /* we must perform init and cleanup if not all tests are running */
    if (!testAll) {
    #ifdef WOLFCRYPT_ONLY
        if (wolfCrypt_Init() != 0) {
            printf("wolfCrypt Initialization failed\n");
            res = 1;
        }
    #else
        if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
            printf("wolfSSL Initialization failed\n");
            res = 1;
        }
    #endif
    }

    #ifdef WOLFSSL_DUMP_MEMIO_STREAM
    if (res == 0) {
        if (create_tmp_dir(tmpDirName, sizeof(tmpDirName) - 1) == NULL) {
            printf("failed to create tmp dir\n");
            res = 1;
        }
        else {
            tmpDirNameSet = 1;
        }
    }
    #endif

    if (res == 0) {
        for (i = 0; i < TEST_CASE_CNT; ++i) {
            EXPECT_DECLS;

        #ifdef WOLFSSL_DUMP_MEMIO_STREAM
            currentTestName = testCases[i].name;
        #endif

            /* When not testing all cases then skip if not marked for running.
             */
            if (!testAll && !testCases[i].run) {
                continue;
            }

            TestSetup();

            printf("   %3d: %-52s:", i + 1, testCases[i].name);
            fflush(stdout);
        #ifndef WOLFSSL_UNIT_TEST_NO_TIMING
            timeDiff = gettime_secs();
        #endif
            ret = testCases[i].func();
        #ifndef WOLFSSL_UNIT_TEST_NO_TIMING
            timeDiff = gettime_secs() - timeDiff;
        #endif
        #ifndef WOLFSSL_UNIT_TEST_NO_TIMING
            if (ret != TEST_SKIPPED) {
                printf(" %s (%9.5lf)\n", apitest_res_string(ret), timeDiff);
            }
            else
        #endif
            {
                printf(" %s\n", apitest_res_string(ret));
            }
            fflush(stdout);
            /* if return code is < 0 and not skipped then assert error */
            Expect((ret > 0 || ret == TEST_SKIPPED),
                ("Test failed\n"),
                ("ret %d", ret));
            testCases[i].fail = ((ret <= 0) && (ret != TEST_SKIPPED));
            res |= ((ret <= 0) && (ret != TEST_SKIPPED));

            TestCleanup();
        }
    }

#if defined(HAVE_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS) \
                      && (defined(NO_MAIN_DRIVER) || defined(HAVE_STACK_SIZE))
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    if (!testAll) {
    #ifdef WOLFCRYPT_ONLY
        wolfCrypt_Cleanup();
    #else
        wolfSSL_Cleanup();
    #endif
    }

    (void)testDevId;

    if (res != 0) {
        printf("\nFAILURES:\n");
        for (i = 0; i < TEST_CASE_CNT; ++i) {
            if (testCases[i].fail) {
                printf("   %3d: %s\n", i + 1, testCases[i].name);
            }
        }
        printf("\n");
        fflush(stdout);
    }

#ifdef WOLFSSL_DUMP_MEMIO_STREAM
    if (tmpDirNameSet) {
        printf("\nBinary dumps of the memio streams can be found in the\n"
                "%s directory. This can be imported into\n"
                "Wireshark by transforming the file with\n"
                "\tod -Ax -tx1 -v stream.dump > stream.dump.hex\n"
                "And then loading test_output.dump.hex into Wireshark using\n"
                "the \"Import from Hex Dump...\" option and selecting the\n"
                "TCP encapsulation option.\n", tmpDirName);
    }
#endif

    printf(" End API Tests\n");
    fflush(stdout);
    return res;
}
#ifdef OPENSSL_EXTRA
/* Function removed as individual test functions are now called directly */
#endif
