/* test_aes.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifndef WOLFCRYPT_TEST_AES_H
#define WOLFCRYPT_TEST_AES_H

#include <tests/api/api_decl.h>

int test_wc_AesSetKey(void);
int test_wc_AesSetIV(void);
int test_wc_AesEncryptDecryptDirect(void);
int test_wc_AesEcbEncryptDecrypt(void);
int test_wc_AesCbcEncryptDecrypt(void);
int test_wc_AesCbcEncryptDecrypt_UnalignedBuffers(void);
int test_wc_AesCbc_CrossCipher(void);
int test_wc_AesCfbEncryptDecrypt(void);
int test_wc_AesCfb_CrossCipher(void);
int test_wc_AesOfbEncryptDecrypt(void);
int test_wc_AesOfb_CrossCipher(void);
int test_wc_AesCtsEncryptDecrypt(void);
int test_wc_AesCtsEncryptDecrypt_InPlace(void);
int test_wc_AesCtsEncryptDecrypt_UnalignedBuffers(void);
int test_wc_AesCtrSetKey(void);
int test_wc_AesCtrEncryptDecrypt(void);
int test_wc_AesCtrEncryptDecrypt_UnalignedBuffers(void);
int test_wc_AesCtr_CrossCipher(void);
int test_wc_AesCtrCounterOverflow(void);
int test_wc_AesGcmSetKey(void);
int test_wc_AesGcmEncryptDecrypt_Sizes(void);
int test_wc_AesGcmEncryptDecrypt(void);
int test_wc_AesGcmEncryptDecrypt_InPlace(void);
int test_wc_AesGcmEncryptDecrypt_UnalignedBuffers(void);
int test_wc_AesGcm_CrossCipher(void);
int test_wc_AesGcmMixedEncDecLongIV(void);
int test_wc_AesGcmNonStdNonce(void);
int test_wc_AesGcmStream(void);
int test_wc_AesGcmStream_MidStreamState(void);
int test_wc_AesGcmStream_ReinitAfterFinal(void);
int test_wc_AesCcmSetKey(void);
int test_wc_AesCcmEncryptDecrypt(void);
int test_wc_AesCcmEncryptDecrypt_InPlace(void);
int test_wc_AesCcmEncryptDecrypt_UnalignedBuffers(void);
int test_wc_AesCcmAeadEdgeCases(void);
int test_wc_AesXtsSetKey(void);
int test_wc_AesXtsEncryptDecrypt_Sizes(void);
int test_wc_AesXtsEncryptDecrypt(void);
int test_wc_AesXtsEncryptDecrypt_InPlace(void);
int test_wc_AesXtsEncryptDecrypt_UnalignedBuffers(void);
int test_wc_AesXtsEncryptDecryptSector(void);
int test_wc_AesXtsStream(void);
int test_wc_AesXtsStream_MidStreamState(void);
int test_wc_AesXtsStream_ReinitAfterFinal(void);
#if defined(WOLFSSL_AES_EAX) && defined(WOLFSSL_AES_256) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
int test_wc_AesEaxVectors(void);
int test_wc_AesEaxEncryptAuth(void);
int test_wc_AesEaxDecryptAuth(void);
int test_wc_AesEaxStream(void);
#endif /* WOLFSSL_AES_EAX && WOLFSSL_AES_256*/
#if defined(WOLFSSL_AES_SIV) && defined(WOLFSSL_AES_128)
int test_wc_AesSivEncryptDecrypt(void);
#endif

int test_wc_AesCbc_MonteCarlo(void);
int test_wc_AesCtr_MonteCarlo(void);
int test_wc_AesGcm_MonteCarlo(void);
int test_wc_AesCcm_MonteCarlo(void);
int test_wc_AesCfb_MonteCarlo(void);
int test_wc_AesOfb_MonteCarlo(void);

int test_wc_GmacSetKey(void);
int test_wc_GmacUpdate(void);
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_AES_SETKEY) && \
    !defined(NO_AES) && defined(HAVE_AESGCM)
int test_wc_CryptoCb_AesSetKey(void);
int test_wc_CryptoCb_AesGcm_EncryptDecrypt(void);
#endif

/* These test functions always have a (possibly empty) definition in
 * test_aes.c so that callers can reference them unconditionally.  Declare
 * the prototypes unconditionally to satisfy -Wmissing-prototypes.  The
 * TEST_CRYPTOCB_TLS13_KEY_ZERO_DECL macro below, however, only registers
 * them with the test harness when the real bodies are compiled in. */
int test_wc_CryptoCb_Tls13_Key_Zero_After_Offload(void);
int test_wc_CryptoCb_Tls13_Key_No_Zero_Without_Offload(void);
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_AES_SETKEY) && \
    !defined(NO_AES) && defined(HAVE_AESGCM) && \
    defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
#define TEST_CRYPTOCB_TLS13_KEY_ZERO_DECL \
    , TEST_DECL_GROUP("aes", test_wc_CryptoCb_Tls13_Key_Zero_After_Offload) \
    , TEST_DECL_GROUP("aes", test_wc_CryptoCb_Tls13_Key_No_Zero_Without_Offload)
#else
#define TEST_CRYPTOCB_TLS13_KEY_ZERO_DECL
#endif

#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_AES_SETKEY) && \
    !defined(NO_AES) && defined(HAVE_AESGCM)
#define TEST_CRYPTOCB_AES_SETKEY_DECL , TEST_DECL_GROUP("aes", test_wc_CryptoCb_AesSetKey), \
                                        TEST_DECL_GROUP("aes", test_wc_CryptoCb_AesGcm_EncryptDecrypt)
#else
#define TEST_CRYPTOCB_AES_SETKEY_DECL
#endif

#define TEST_AES_DECLS                                          \
    TEST_DECL_GROUP("aes", test_wc_AesSetKey),                  \
    TEST_DECL_GROUP("aes", test_wc_AesSetIV),                   \
    TEST_DECL_GROUP("aes", test_wc_AesEncryptDecryptDirect),    \
    TEST_DECL_GROUP("aes", test_wc_AesEcbEncryptDecrypt),       \
    TEST_DECL_GROUP("aes", test_wc_AesCbcEncryptDecrypt),                  \
    TEST_DECL_GROUP("aes", test_wc_AesCbcEncryptDecrypt_UnalignedBuffers), \
    TEST_DECL_GROUP("aes", test_wc_AesCbc_CrossCipher),                   \
    TEST_DECL_GROUP("aes", test_wc_AesCfbEncryptDecrypt),                  \
    TEST_DECL_GROUP("aes", test_wc_AesCfb_CrossCipher),                   \
    TEST_DECL_GROUP("aes", test_wc_AesOfbEncryptDecrypt),       \
    TEST_DECL_GROUP("aes", test_wc_AesOfb_CrossCipher),                    \
    TEST_DECL_GROUP("aes", test_wc_AesCtsEncryptDecrypt),        \
    TEST_DECL_GROUP("aes", test_wc_AesCtsEncryptDecrypt_InPlace),            \
    TEST_DECL_GROUP("aes", test_wc_AesCtsEncryptDecrypt_UnalignedBuffers),  \
    TEST_DECL_GROUP("aes", test_wc_AesCtrSetKey),                           \
    TEST_DECL_GROUP("aes", test_wc_AesCtrEncryptDecrypt),                   \
    TEST_DECL_GROUP("aes", test_wc_AesCtrEncryptDecrypt_UnalignedBuffers),  \
    TEST_DECL_GROUP("aes", test_wc_AesCtr_CrossCipher),                    \
    TEST_DECL_GROUP("aes", test_wc_AesCtrCounterOverflow),                  \
    TEST_DECL_GROUP("aes", test_wc_AesGcmSetKey),               \
    TEST_DECL_GROUP("aes", test_wc_AesGcmEncryptDecrypt_Sizes), \
    TEST_DECL_GROUP("aes", test_wc_AesGcmEncryptDecrypt),        \
    TEST_DECL_GROUP("aes", test_wc_AesGcmEncryptDecrypt_InPlace),            \
    TEST_DECL_GROUP("aes", test_wc_AesGcmEncryptDecrypt_UnalignedBuffers),  \
    TEST_DECL_GROUP("aes", test_wc_AesGcm_CrossCipher),                    \
    TEST_DECL_GROUP("aes", test_wc_AesGcmMixedEncDecLongIV),                \
    TEST_DECL_GROUP("aes", test_wc_AesGcmNonStdNonce),          \
    TEST_DECL_GROUP("aes", test_wc_AesGcmStream),               \
    TEST_DECL_GROUP("aes", test_wc_AesGcmStream_MidStreamState),  \
    TEST_DECL_GROUP("aes", test_wc_AesGcmStream_ReinitAfterFinal), \
    TEST_DECL_GROUP("aes", test_wc_AesCcmSetKey),               \
    TEST_DECL_GROUP("aes", test_wc_AesCcmEncryptDecrypt),        \
    TEST_DECL_GROUP("aes", test_wc_AesCcmEncryptDecrypt_InPlace),            \
    TEST_DECL_GROUP("aes", test_wc_AesCcmEncryptDecrypt_UnalignedBuffers),  \
    TEST_DECL_GROUP("aes", test_wc_AesCcmAeadEdgeCases),                   \
    TEST_DECL_GROUP("aes", test_wc_AesXtsSetKey),                    \
    TEST_DECL_GROUP("aes", test_wc_AesXtsEncryptDecrypt_Sizes),     \
    TEST_DECL_GROUP("aes", test_wc_AesXtsEncryptDecrypt),            \
    TEST_DECL_GROUP("aes", test_wc_AesXtsEncryptDecrypt_InPlace),            \
    TEST_DECL_GROUP("aes", test_wc_AesXtsEncryptDecrypt_UnalignedBuffers),  \
    TEST_DECL_GROUP("aes", test_wc_AesXtsEncryptDecryptSector),             \
    TEST_DECL_GROUP("aes", test_wc_AesXtsStream),                   \
    TEST_DECL_GROUP("aes", test_wc_AesXtsStream_MidStreamState),     \
    TEST_DECL_GROUP("aes", test_wc_AesXtsStream_ReinitAfterFinal),  \
    TEST_DECL_GROUP("aes", test_wc_AesCbc_MonteCarlo),    \
    TEST_DECL_GROUP("aes", test_wc_AesCtr_MonteCarlo),    \
    TEST_DECL_GROUP("aes", test_wc_AesGcm_MonteCarlo),    \
    TEST_DECL_GROUP("aes", test_wc_AesCcm_MonteCarlo),    \
    TEST_DECL_GROUP("aes", test_wc_AesCfb_MonteCarlo),    \
    TEST_DECL_GROUP("aes", test_wc_AesOfb_MonteCarlo)     \
    TEST_CRYPTOCB_AES_SETKEY_DECL                         \
    TEST_CRYPTOCB_TLS13_KEY_ZERO_DECL

#if defined(WOLFSSL_AES_EAX) && defined(WOLFSSL_AES_256) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
#define TEST_AES_EAX_DECLS                                  \
    TEST_DECL_GROUP("aes-eax", test_wc_AesEaxVectors),      \
    TEST_DECL_GROUP("aes-eax", test_wc_AesEaxEncryptAuth),  \
    TEST_DECL_GROUP("aes-eax", test_wc_AesEaxDecryptAuth),  \
    TEST_DECL_GROUP("aes-eax", test_wc_AesEaxStream)
#endif /* WOLFSSL_AES_EAX */

#if defined(WOLFSSL_AES_SIV) && defined(WOLFSSL_AES_128)
#define TEST_AES_SIV_DECLS \
    TEST_DECL_GROUP("aes-siv", test_wc_AesSivEncryptDecrypt)
#endif /* WOLFSSL_AES_SIV && WOLFSSL_AES_128 */

#define TEST_GMAC_DECLS                             \
    TEST_DECL_GROUP("gmac", test_wc_GmacSetKey),    \
    TEST_DECL_GROUP("gmac", test_wc_GmacUpdate)

#endif /* WOLFCRYPT_TEST_AES_H */
