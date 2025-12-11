/* wolfcrypt/test/test.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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


#ifndef WOLFCRYPT_TEST_H
#define WOLFCRYPT_TEST_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WC_TEST_RET_CUSTOM_TYPE
    typedef WC_TEST_RET_CUSTOM_TYPE wc_test_ret_t;
#else
    typedef sword32 wc_test_ret_t;
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef HAVE_STACK_SIZE
THREAD_RETURN WOLFSSL_THREAD wolfcrypt_test(void* args);
#else
wc_test_ret_t wolfcrypt_test(void* args);
#endif

void wc_test_render_error_message(const char* msg, wc_test_ret_t es);

#ifndef NO_MAIN_DRIVER
wc_test_ret_t wolfcrypt_test_main(int argc, char** argv);
#endif

#if defined(WOLFSSL_ESPIDF) || defined(_WIN32_WCE)
int wolf_test_task(void);
#endif

#ifndef WC_TEST_RET_HAVE_CUSTOM_MACROS

#define WC_TEST_RET_TAG_NC     0L
#define WC_TEST_RET_TAG_EC     1L
#define WC_TEST_RET_TAG_ERRNO  2L
#define WC_TEST_RET_TAG_I      3L

wc_static_assert(-(long)MIN_CODE_E < 0x7ffL);

#define WC_TEST_RET_ENC(line, i, tag)                           \
        ((wc_test_ret_t)(-((wc_test_ret_t)(line) + ((wc_test_ret_t)((word32)(i) & 0x7ffL) * 100000L) + ((wc_test_ret_t)(tag) << 29L))))

#ifndef WC_TEST_RET_LN
#define WC_TEST_RET_LN __LINE__
#endif

/* encode no code */
#define WC_TEST_RET_ENC_NC WC_TEST_RET_ENC(WC_TEST_RET_LN, 0, WC_TEST_RET_TAG_NC)

/* encode positive integer */
#define WC_TEST_RET_ENC_I(i) WC_TEST_RET_ENC(WC_TEST_RET_LN, i, WC_TEST_RET_TAG_I)

/* encode error code (negative integer) */
#define WC_TEST_RET_ENC_EC(ec) WC_TEST_RET_ENC(WC_TEST_RET_LN, -(ec), WC_TEST_RET_TAG_EC)

/* encode system/libc error code */
#if defined(HAVE_ERRNO_H) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM) && !defined(WOLFSSL_USER_IO)
#include <errno.h>
#define WC_TEST_RET_ENC_ERRNO WC_TEST_RET_ENC(WC_TEST_RET_LN, errno, WC_TEST_RET_TAG_ERRNO)
#else
#define WC_TEST_RET_ENC_ERRNO WC_TEST_RET_ENC_NC
#endif

#define WC_TEST_RET_DEC_TAG(x) ((-(x)) >> 29L)

/* decode line number */
#define WC_TEST_RET_DEC_LN(x) ((int)(((-(x)) & ~(3L << 29L)) % 100000L))

/* decode integer or errno */
#define WC_TEST_RET_DEC_I(x) ((int)((((-(x)) & ~(3L << 29L)) / 100000L)))

/* decode error code */
#define WC_TEST_RET_DEC_EC(x) ((int)(-WC_TEST_RET_DEC_I(x)))

#endif /* !WC_TEST_RET_HAVE_CUSTOM_MACROS */

#ifdef WC_TEST_EXPORT_SUBTESTS

extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  error_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  base64_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  base16_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  asn_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  md2_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  md5_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  md4_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sha_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sha224_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sha256_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sha512_test(void);
#if !defined(WOLFSSL_NOSHA512_224) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sha512_224_test(void);
#endif
#if !defined(WOLFSSL_NOSHA512_256) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sha512_256_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sha384_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sha3_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  shake128_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  shake256_test(void);
#ifdef WOLFSSL_SM3
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sm3_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  hash_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  hmac_md5_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  hmac_sha_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  hmac_sha224_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  hmac_sha256_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  hmac_sha384_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  hmac_sha512_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  hmac_sha3_test(void);
#if defined(HAVE_HKDF) && !defined(NO_HMAC)
#if defined(WOLFSSL_AFALG_XILINX) || defined(WOLFSSL_AFALG_XILINX_AES) ||     \
    defined(WOLFSSL_AFALG_XILINX_SHA3) || defined(WOLFSSL_AFALG_HASH_KEEP) || \
    defined(WOLFSSL_AFALG_XILINX_RSA)
/* hkdf_test has issue with extern WOLFSSL_TEST_SUBROUTINE set on Xilinx with afalg */
static                  wc_test_ret_t  hkdf_test(void);
#else
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  hkdf_test(void);
#endif
#endif /* HAVE_HKDF && ! NO_HMAC */
#ifdef WOLFSSL_HAVE_PRF
#if defined(HAVE_HKDF) && !defined(NO_HMAC)
#ifdef WOLFSSL_BASE16
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  tls12_kdf_test(void);
#endif /* WOLFSSL_BASE16 */
#endif /* WOLFSSL_HAVE_HKDF && !NO_HMAC */
#endif /* WOLFSSL_HAVE_PRF */
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_HMAC) && defined(WOLFSSL_SHA384)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  prf_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sshkdf_test(void);
#ifdef WOLFSSL_TLS13
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  tls13_kdf_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  x963kdf_test(void);
#if defined(HAVE_HPKE) && defined(HAVE_ECC) && defined(HAVE_AESGCM)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  hpke_test(void);
#endif
#ifdef WC_SRTP_KDF
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  srtpkdf_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  arc4_test(void);
#ifdef WC_RC2
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  rc2_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  chacha_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  XChaCha_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  chacha20_poly1305_aead_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  XChaCha20Poly1305_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  des_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  des3_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aes_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aes_cbc_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aes_ctr_test(void);
#if defined(WOLFSSL_AES_CFB)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aes_cfb_test(void);
#endif
#ifdef WOLFSSL_AES_XTS
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aes_xts_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aes192_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aes256_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aesofb_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  cmac_test(void);
#ifdef HAVE_ASCON
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  ascon_hash256_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  ascon_aead128_test(void);
#endif
#if defined(WOLFSSL_SIPHASH)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  siphash_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  poly1305_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aesgcm_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aesgcm_default_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  gmac_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aesccm_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  aeskeywrap_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  camellia_test(void);
#ifdef WOLFSSL_SM4
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sm4_test(void);
#endif
#ifdef WC_RSA_NO_PADDING
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  rsa_no_pad_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  rsa_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  dh_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  dsa_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  srp_test(void);
#ifndef WC_NO_RNG
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  random_test(void);
#endif /* WC_NO_RNG */
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  pwdbased_test(void);
#if defined(USE_CERT_BUFFERS_2048) && \
        defined(HAVE_PKCS12) && \
            !defined(NO_ASN) && !defined(NO_PWDBASED) && !defined(NO_HMAC) && \
            !defined(NO_CERTS) && !defined(NO_DES3)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  pkcs12_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  ripemd_test(void);
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  openssl_test(void);   /* test mini api */

extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  openssl_pkey0_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  openssl_pkey1_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  openSSL_evpMD_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  openssl_evpSig_test(void);
#endif

extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t pbkdf1_test(void);
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t pkcs12_pbkdf_test(void);
#if defined(HAVE_PBKDF2) && !defined(NO_SHA256) && !defined(NO_HMAC)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t pbkdf2_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t scrypt_test(void);
#ifdef HAVE_ECC
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  ecc_test(void);
    #if defined(HAVE_ECC_ENCRYPT) && defined(HAVE_AES_CBC) && \
        (defined(WOLFSSL_AES_128) || defined(WOLFSSL_AES_256))
        extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  ecc_encrypt_test(void);
    #endif
    #if defined(USE_CERT_BUFFERS_256) && !defined(WOLFSSL_ATECC508A) && \
        !defined(WOLFSSL_ATECC608A) && !defined(NO_ECC256) && \
        defined(HAVE_ECC_VERIFY) && defined(HAVE_ECC_SIGN) && \
        !defined(WOLF_CRYPTO_CB_ONLY_ECC) && !defined(NO_ECC_SECP)
        /* skip for ATECC508/608A, cannot import private key buffers */
        extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t ecc_test_buffers(void);
    #endif
#endif
#ifdef HAVE_CURVE25519
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  curve25519_test(void);
#endif
#ifdef HAVE_ED25519
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  ed25519_test(void);
#endif
#ifdef HAVE_CURVE448
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  curve448_test(void);
#endif
#ifdef HAVE_ED448
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  ed448_test(void);
#endif
#ifdef WOLFSSL_HAVE_MLKEM
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  mlkem_test(void);
#endif
#ifdef HAVE_DILITHIUM
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  dilithium_test(void);
#endif
#if defined(WOLFSSL_HAVE_XMSS)
    #if !defined(WOLFSSL_SMALL_STACK) && WOLFSSL_XMSS_MIN_HEIGHT <= 10
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  xmss_test_verify_only(void);
    #endif
    #if !defined(WOLFSSL_XMSS_VERIFY_ONLY)
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  xmss_test(void);
    #endif
#endif
#if defined(WOLFSSL_HAVE_LMS)
    #if !defined(WOLFSSL_SMALL_STACK)
        #if (defined(WOLFSSL_WC_LMS) && (LMS_MAX_HEIGHT >= 10) && \
             !defined(WOLFSSL_NO_LMS_SHA256_256)) || defined(HAVE_LIBLMS)
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  lms_test_verify_only(void);
        #endif
    #endif
    #if !defined(WOLFSSL_LMS_VERIFY_ONLY)
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  lms_test(void);
    #endif
#endif
#ifdef WOLFCRYPT_HAVE_ECCSI
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  eccsi_test(void);
#endif
#ifdef WOLFCRYPT_HAVE_SAKKE
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  sakke_test(void);
#endif
#ifdef HAVE_BLAKE2
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  blake2b_test(void);
#endif
#ifdef HAVE_BLAKE2S
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  blake2s_test(void);
#endif
#ifdef HAVE_LIBZ
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t compress_test(void);
#endif
#ifdef HAVE_PKCS7
    #ifndef NO_PKCS7_ENCRYPTED_DATA
        extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t pkcs7encrypted_test(void);
    #endif
    #if defined(HAVE_LIBZ) && !defined(NO_PKCS7_COMPRESSED_DATA)
        extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t pkcs7compressed_test(void);
    #endif
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t pkcs7signed_test(void);
    extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t pkcs7enveloped_test(void);
    #if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
        extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t pkcs7authenveloped_test(void);
    #endif
    #if !defined(NO_AES) && defined(HAVE_AES_CBC)
        extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t pkcs7callback_test(byte* cert, word32 certSz, byte* key,
                word32 keySz);
    #endif
#endif
#if !defined(NO_ASN_TIME) && !defined(NO_RSA) && defined(WOLFSSL_TEST_CERT) && \
    !defined(NO_FILESYSTEM)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t cert_test(void);
#endif
#if defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_TEST_CERT) && \
   !defined(NO_FILESYSTEM) && !defined(NO_RSA) && defined(WOLFSSL_GEN_CERT)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t  certext_test(void);
#endif
#if defined(WOLFSSL_CERT_GEN_CACHE) && defined(WOLFSSL_TEST_CERT) && \
    defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_CERT_GEN)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t decodedCertCache_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t memory_test(void);
#if defined(WOLFSSL_PUBLIC_MP) && \
    ((defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
     defined(USE_FAST_MATH))
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t mp_test(void);
#endif
#if defined(WOLFSSL_PUBLIC_MP) && defined(WOLFSSL_KEY_GEN)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t prime_test(void);
#endif
#if defined(ASN_BER_TO_DER) && \
    (defined(WOLFSSL_TEST_CERT) || defined(OPENSSL_EXTRA) || \
     defined(OPENSSL_EXTRA_X509_SMALL))
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t berder_test(void);
#endif
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t logging_test(void);
#if !defined(NO_ASN) && !defined(NO_ASN_TIME)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t time_test(void);
#endif
#if defined(__INCLUDE_NUTTX_CONFIG_H)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t wolfcrypt_mutex_test(void);
#else
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t mutex_test(void);
#endif
#if defined(USE_WOLFSSL_MEMORY) && !defined(FREERTOS)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t memcb_test(void);
#endif
#ifdef WOLFSSL_CAAM_BLOB
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t blob_test(void);
#endif
#ifdef HAVE_ARIA
#include "wolfssl/wolfcrypt/port/aria/aria-crypt.h"
void printOutput(const char *strName, unsigned char *data, unsigned int dataSz);
extern WOLFSSL_TEST_SUBROUTINE int ariagcm_test(MC_ALGID);
#endif

#if defined(WOLF_CRYPTO_CB) && !defined(WC_TEST_NO_CRYPTOCB_SW_TEST)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t cryptocb_test(void);
#endif
#ifdef WOLFSSL_CERT_PIV
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t certpiv_test(void);
#endif
#ifdef WOLFSSL_AES_SIV
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t aes_siv_test(void);
#endif

#if defined(WOLFSSL_AES_EAX) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
extern WOLFSSL_TEST_SUBROUTINE wc_test_ret_t aes_eax_test(void);
#endif /* WOLFSSL_AES_EAX */

#endif /* WC_TEST_EXPORT_SUBTESTS */

#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFCRYPT_TEST_H */
