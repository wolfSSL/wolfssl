/* test_pkcs12.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/pkcs12.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_pkcs12.h>

/*******************************************************************************
 * PKCS#12
 ******************************************************************************/

int test_wc_i2d_PKCS12(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_PWDBASED) && defined(HAVE_PKCS12) \
    && !defined(NO_FILESYSTEM) && !defined(NO_RSA) \
    && !defined(NO_AES) && !defined(NO_SHA)
    WC_PKCS12* pkcs12 = NULL;
    unsigned char der[FOURK_BUF * 2];
    unsigned char* pt;
    int derSz = 0;
    unsigned char out[FOURK_BUF * 2];
    int outSz = FOURK_BUF * 2;
    const char p12_f[] = "./certs/test-servercert.p12";
    XFILE f = XBADFILE;

    ExpectTrue((f =  XFOPEN(p12_f, "rb")) != XBADFILE);
    ExpectIntGT(derSz = (int)XFREAD(der, 1, sizeof(der), f), 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectNotNull(pkcs12 = wc_PKCS12_new());
    ExpectIntEQ(wc_d2i_PKCS12(der, (word32)derSz, pkcs12), 0);
    ExpectIntEQ(wc_i2d_PKCS12(pkcs12, NULL, &outSz), WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(outSz, derSz);

    outSz = derSz - 1;
    pt = out;
    ExpectIntLE(wc_i2d_PKCS12(pkcs12, &pt, &outSz), 0);

    outSz = derSz;
    ExpectIntEQ(wc_i2d_PKCS12(pkcs12, &pt, &outSz), derSz);
    ExpectIntEQ((pt == out), 0);

    pt = NULL;
    ExpectIntEQ(wc_i2d_PKCS12(pkcs12, &pt, NULL), derSz);
    XFREE(pt, NULL, DYNAMIC_TYPE_PKCS);
    wc_PKCS12_free(pkcs12);
    pkcs12 = NULL;

    /* Run the same test but use wc_d2i_PKCS12_fp. */
    ExpectNotNull(pkcs12 = wc_PKCS12_new());
    ExpectIntEQ(wc_d2i_PKCS12_fp("./certs/test-servercert.p12", &pkcs12), 0);
    ExpectIntEQ(wc_i2d_PKCS12(pkcs12, NULL, &outSz), WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(outSz, derSz);
    wc_PKCS12_free(pkcs12);
    pkcs12 = NULL;

    /* wc_d2i_PKCS12_fp can also allocate the PKCS12 object for the caller. */
    ExpectIntEQ(wc_d2i_PKCS12_fp("./certs/test-servercert.p12", &pkcs12), 0);
    ExpectIntEQ(wc_i2d_PKCS12(pkcs12, NULL, &outSz), WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(outSz, derSz);
    wc_PKCS12_free(pkcs12);
    pkcs12 = NULL;
#endif
    return EXPECT_RESULT();
}

static int test_wc_PKCS12_create_once(int keyEncType, int certEncType)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && defined(HAVE_PKCS12) && !defined(NO_PWDBASED) && \
    !defined(NO_RSA) && !defined(NO_ASN_CRYPT) && \
    !defined(NO_HMAC) && !defined(NO_CERTS) && defined(USE_CERT_BUFFERS_2048)

    byte* inKey = (byte*) server_key_der_2048;
    const word32 inKeySz= sizeof_server_key_der_2048;
    byte* inCert = (byte*) server_cert_der_2048;
    const word32 inCertSz = sizeof_server_cert_der_2048;
    WC_DerCertList inCa = {
        (byte*)ca_cert_der_2048, sizeof_ca_cert_der_2048, NULL
    };
    char pkcs12Passwd[] = "test_wc_PKCS12_create";

    WC_PKCS12* pkcs12Export = NULL;
    WC_PKCS12* pkcs12Import = NULL;
    byte* pkcs12Der = NULL;
    byte* outKey = NULL;
    byte* outCert = NULL;
    WC_DerCertList* outCaList = NULL;
    word32 pkcs12DerSz = 0;
    word32 outKeySz = 0;
    word32 outCertSz = 0;

    ExpectNotNull(pkcs12Export = wc_PKCS12_create(pkcs12Passwd,
        sizeof(pkcs12Passwd) - 1,
        (char*) "friendlyName" /* not used currently */,
        inKey, inKeySz, inCert, inCertSz, &inCa, keyEncType, certEncType,
        2048, 2048, 0 /* not used currently */, NULL));
    pkcs12Der = NULL;
    ExpectIntGE((pkcs12DerSz = wc_i2d_PKCS12(pkcs12Export, &pkcs12Der, NULL)),
        0);

    ExpectNotNull(pkcs12Import = wc_PKCS12_new_ex(NULL));
    ExpectIntGE(wc_d2i_PKCS12(pkcs12Der, pkcs12DerSz, pkcs12Import), 0);
    ExpectIntEQ(wc_PKCS12_parse(pkcs12Import, pkcs12Passwd, &outKey, &outKeySz,
        &outCert, &outCertSz, &outCaList), 0);

    ExpectIntEQ(outKeySz, inKeySz);
    ExpectIntEQ(outCertSz, inCertSz);
    ExpectNotNull(outCaList);
    ExpectNotNull(outCaList->buffer);
    ExpectIntEQ(outCaList->bufferSz, inCa.bufferSz);
    ExpectNull(outCaList->next);

    ExpectIntEQ(XMEMCMP(inKey, outKey, outKeySz), 0);
    ExpectIntEQ(XMEMCMP(inCert, outCert, outCertSz), 0);
    ExpectIntEQ(XMEMCMP(inCa.buffer, outCaList->buffer, outCaList->bufferSz),
        0);

    XFREE(outKey, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(outCert, NULL, DYNAMIC_TYPE_PKCS);
    wc_FreeCertList(outCaList, NULL);
    wc_PKCS12_free(pkcs12Import);
    XFREE(pkcs12Der, NULL, DYNAMIC_TYPE_PKCS);
    wc_PKCS12_free(pkcs12Export);
#endif
    (void) keyEncType;
    (void) certEncType;

    return EXPECT_RESULT();
}

int test_wc_PKCS12_create(void)
{
    EXPECT_DECLS;

    EXPECT_TEST(test_wc_PKCS12_create_once(-1, -1));
#if !defined(NO_RC4) && !defined(NO_SHA)
    EXPECT_TEST(test_wc_PKCS12_create_once(PBE_SHA1_RC4_128, PBE_SHA1_RC4_128));
#endif
#if !defined(NO_DES3) && !defined(NO_SHA)
    EXPECT_TEST(test_wc_PKCS12_create_once(PBE_SHA1_DES, PBE_SHA1_DES));
#endif
#if !defined(NO_DES3) && !defined(NO_SHA)
    EXPECT_TEST(test_wc_PKCS12_create_once(PBE_SHA1_DES3, PBE_SHA1_DES3));
#endif
#if defined(HAVE_AES_CBC) && !defined(NO_AES) && !defined(NO_AES_256) && \
    !defined(NO_SHA) && defined(WOLFSSL_ASN_TEMPLATE)
    /* Encoding certificate with PBE_AES256_CBC needs WOLFSSL_ASN_TEMPLATE */
    EXPECT_TEST(test_wc_PKCS12_create_once(PBE_AES256_CBC, PBE_AES256_CBC));
#endif
#if defined(HAVE_AES_CBC) && !defined(NO_AES) && !defined(NO_AES_128) && \
    !defined(NO_SHA) && defined(WOLFSSL_ASN_TEMPLATE)
    /* Encoding certificate with PBE_AES128_CBC needs WOLFSSL_ASN_TEMPLATE */
    EXPECT_TEST(test_wc_PKCS12_create_once(PBE_AES128_CBC, PBE_AES128_CBC));
#endif
/* Testing a mixture of 2 algorithms */
#if defined(HAVE_AES_CBC) && !defined(NO_AES) && !defined(NO_AES_256) && \
    !defined(NO_SHA) && defined(WOLFSSL_ASN_TEMPLATE) && !defined(NO_DES3)
    EXPECT_TEST(test_wc_PKCS12_create_once(PBE_AES256_CBC, PBE_SHA1_DES3));
#endif

    (void) test_wc_PKCS12_create_once;

    return EXPECT_RESULT();
}

