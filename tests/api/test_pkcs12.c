/* test_pkcs12.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/pkcs12.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/aes.h>
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
    && !defined(NO_AES) && !defined(NO_SHA) && !defined(NO_SHA256)
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

#ifndef NO_SHA256
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
#endif

    (void) test_wc_PKCS12_create_once;

    return EXPECT_RESULT();
}

int test_wc_d2i_PKCS12_bad_mac_salt(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_PWDBASED) && defined(HAVE_PKCS12) \
    && !defined(NO_FILESYSTEM) && !defined(NO_RSA) \
    && !defined(NO_AES) && !defined(NO_SHA) && !defined(NO_SHA256)
    WC_PKCS12* pkcs12 = NULL;
    unsigned char der[FOURK_BUF * 2];
    int derSz = 0;
    const char p12_f[] = "./certs/test-servercert.p12";
    XFILE f = XBADFILE;
    int i;
    int found = 0;

    ExpectTrue((f = XFOPEN(p12_f, "rb")) != XBADFILE);
    ExpectIntGT(derSz = (int)XFREAD(der, 1, sizeof(der), f), 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    /* Scan backward within the last 100 bytes to find the MAC salt
     * OCTET STRING (tag 0x04, length 0x08 for a typical 8-byte salt).
     * Corrupt its length so that saltSz + curIdx > totalSz, triggering
     * the error path in GetSignData() after salt allocation. */
    for (i = derSz - 2; i >= 0 && i >= derSz - 100; i--) {
        if (der[i] == 0x04 && der[i + 1] == 0x08) {
            der[i + 1] = 0xFF;
            found = 1;
            break;
        }
    }
    ExpectIntEQ(found, 1);

    ExpectNotNull(pkcs12 = wc_PKCS12_new());
    ExpectIntNE(wc_d2i_PKCS12(der, (word32)derSz, pkcs12), 0);
    wc_PKCS12_free(pkcs12);
#endif
    return EXPECT_RESULT();
}

/* Test that a crafted PKCS12 with a ContentInfo SEQUENCE length smaller than
 * the contained OID is rejected, rather than causing an integer underflow
 * in ci->dataSz calculation. */
int test_wc_d2i_PKCS12_oid_underflow(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_PWDBASED) && defined(HAVE_PKCS12)
    WC_PKCS12* pkcs12 = NULL;

    /* Crafted PKCS12 DER: the inner ContentInfo SEQUENCE declares length 5,
     * but contains a valid OID (1.2.840.113549.1.7.1) that is 11 bytes
     * on the wire (tag 06 + length 09 + 9 value bytes). Without the bounds
     * check, (word32)curSz - (localIdx - curIdx) = 5 - 11 underflows
     * to ~4GB. */
    static const byte crafted[] = {
        0x30, 0x23,                                           /* outer SEQ */
        0x02, 0x01, 0x03,                                     /* version 3 */
        0x30, 0x1E,                                  /* AuthSafe wrapper SEQ */
          0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
          0x01, 0x07, 0x01,                             /* OID pkcs7-data */
          0xA0, 0x11,                              /* [0] CONSTRUCTED ctx */
            0x04, 0x0F,                                   /* OCTET STRING */
              0x30, 0x0D,                       /* SEQ of ContentInfo arr */
                0x30, 0x05,              /* ContentInfo SEQ, length=5 LIE */
                  0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                  0x01, 0x07, 0x01              /* OID: 11 bytes actual */
    };

    ExpectNotNull(pkcs12 = wc_PKCS12_new());
    ExpectIntEQ(wc_d2i_PKCS12(crafted, (word32)sizeof(crafted), pkcs12),
                ASN_PARSE_E);
    wc_PKCS12_free(pkcs12);
#endif
    return EXPECT_RESULT();
}

/* Test that validates the fix for heap OOB read vulnerability where
 * ASN.1 parsing after DecryptContent() would use stale ContentInfo bounds.
 * This is a basic test that verifies the fix compiles and basic PKCS#12
 * functionality still works after adding contentSz bounds checking. */
int test_wc_PKCS12_encrypted_content_bounds(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_PWDBASED) && defined(HAVE_PKCS12) && \
    !defined(NO_RSA) && !defined(NO_AES) && !defined(NO_SHA) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048)

    /* This test validates that the fix for heap OOB read is in place.
     * The fix ensures ASN.1 parsing uses contentSz (actual decrypted size)
     * instead of ci->dataSz (original ContentInfo size) as bounds.
     *
     * We test this by exercising the PKCS#12 parsing path with encrypted
     * content to ensure the fix doesn't break normal operation. */

    byte* inKey = (byte*) server_key_der_2048;
    const word32 inKeySz = sizeof_server_key_der_2048;
    byte* inCert = (byte*) server_cert_der_2048;
    const word32 inCertSz = sizeof_server_cert_der_2048;
    WC_DerCertList inCa = {
        (byte*)ca_cert_der_2048, sizeof_ca_cert_der_2048, NULL
    };
    char pkcs12Passwd[] = "test_bounds_fix";

    WC_PKCS12* pkcs12Export = NULL;
    WC_PKCS12* pkcs12Import = NULL;
    byte* pkcs12Der = NULL;
    byte* outKey = NULL;
    byte* outCert = NULL;
    WC_DerCertList* outCaList = NULL;
    int exportRet = 0;
    word32 pkcs12DerSz = 0;
    word32 outKeySz = 0;
    word32 outCertSz = 0;

    /* Create a PKCS#12 with encrypted content */
    ExpectNotNull(pkcs12Export = wc_PKCS12_create(pkcs12Passwd,
        sizeof(pkcs12Passwd) - 1, NULL, inKey, inKeySz, inCert, inCertSz,
        &inCa, -1, -1, 2048, 2048, 0, NULL));

    /* Serialize to DER - use int intermediate to avoid word32 truncation
     * of negative error codes from wc_i2d_PKCS12(). */
    ExpectIntGE((exportRet = wc_i2d_PKCS12(pkcs12Export, &pkcs12Der, NULL)), 0);
    pkcs12DerSz = (word32)exportRet;

    /* Parse it back - this exercises the fixed bounds checking code path */
    ExpectNotNull(pkcs12Import = wc_PKCS12_new_ex(NULL));
    ExpectIntGE(wc_d2i_PKCS12(pkcs12Der, pkcs12DerSz, pkcs12Import), 0);

    /* This parse operation now uses contentSz instead of ci->dataSz for bounds,
     * preventing the heap OOB read that existed before the fix */
    ExpectIntEQ(wc_PKCS12_parse(pkcs12Import, pkcs12Passwd, &outKey, &outKeySz,
        &outCert, &outCertSz, &outCaList), 0);

    /* Verify the parsing worked correctly */
    ExpectIntEQ(outKeySz, inKeySz);
    ExpectIntEQ(outCertSz, inCertSz);
    ExpectNotNull(outCaList);
    ExpectIntEQ(outCaList->bufferSz, inCa.bufferSz);
    ExpectIntEQ(XMEMCMP(outKey, inKey, inKeySz), 0);
    ExpectIntEQ(XMEMCMP(outCert, inCert, inCertSz), 0);
    ExpectIntEQ(XMEMCMP(outCaList->buffer, inCa.buffer, inCa.bufferSz), 0);

    /* Clean up */
    XFREE(outKey, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(outCert, NULL, DYNAMIC_TYPE_PKCS);
    wc_FreeCertList(outCaList, NULL);
    wc_PKCS12_free(pkcs12Import);
    XFREE(pkcs12Der, NULL, DYNAMIC_TYPE_PKCS);
    wc_PKCS12_free(pkcs12Export);

#endif

    /* Part 2: True regression test - craft a malformed PKCS#12 whose decrypted
     * SafeBags SEQUENCE claims a length that exceeds the decrypted content
     * bounds (contentSz) but fits within the stale ContentInfo bounds
     * (ci->dataSz). Before the fix, the parser used ci->dataSz, allowing a
     * heap OOB read; with the fix it uses contentSz and rejects the blob. */
#if !defined(NO_ASN) && !defined(NO_PWDBASED) && defined(HAVE_PKCS12) && \
    defined(WOLFSSL_AES_256) && defined(HAVE_AES_CBC) && \
    defined(HAVE_AES_DECRYPT) && !defined(NO_SHA256) && !defined(NO_HMAC) && \
    defined(WOLFSSL_ASN_TEMPLATE) && !defined(HAVE_FIPS)
    {
        static const char regPassword[] = "test";
        static const byte regSalt[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        static const byte regIv[16]  = {0};

        /* Malformed SafeBags plaintext (one AES block = 16 bytes).
         * The outer SEQUENCE claims length 100 - this exceeds the decrypted
         * content size (16) but fits inside the stale ci->dataSz (127) that
         * the unfixed code used as the parsing bound. */
        static const byte regPlaintext[16] = {
            0x30, 0x64, /* SEQUENCE, length 100 */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        /* Complete PKCS#12 DER (170 bytes).
         * Structure: PFX { version 3, authSafe { DATA { AuthenticatedSafe {
         *   EncryptedData { PBES2(AES-256-CBC, HMAC-SHA256, PBKDF2)
         *     <ciphertext placeholder at offset 154> } } } } }
         * No MacData - macIter=0 skips MAC verification. */
        byte regDer[170] = {
            0x30, 0x81, 0xA7,                               /* PFX SEQ (167) */
            0x02, 0x01, 0x03,                               /* version 3 */
            0x30, 0x81, 0xA1,                   /* authSafe ContentInfo (161) */
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                0xF7, 0x0D, 0x01, 0x07, 0x01,                /* OID data */
            0xA0, 0x81, 0x93,                            /* [0] CONS. (147) */
            0x04, 0x81, 0x90,                        /* OCTET STRING (144) */
            0x30, 0x81, 0x8D,              /* AuthenticatedSafe SEQ (141) */
            0x30, 0x81, 0x8A,                    /* ContentInfo SEQ (138) */
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                0xF7, 0x0D, 0x01, 0x07, 0x06,       /* OID encryptedData */
            0xA0, 0x7D,                              /* [0] CONS. (125) */
            0x30, 0x7B,                        /* EncryptedData SEQ (123) */
            0x02, 0x01, 0x00,                            /* version 0 */
            0x30, 0x76,                  /* EncryptedContentInfo SEQ (118) */
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                0xF7, 0x0D, 0x01, 0x07, 0x01,                /* OID data */
            /* --- EncryptContent payload (107 bytes) --- */
            0x30, 0x57,                  /* AlgorithmIdentifier SEQ (87) */
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                0xF7, 0x0D, 0x01, 0x05, 0x0D,                /* OID pbes2 */
            0x30, 0x4A,                         /* PBES2-params SEQ (74) */
            0x30, 0x29,                       /* keyDerivFunc SEQ (41) */
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                0xF7, 0x0D, 0x01, 0x05, 0x0C,               /* OID pbkdf2 */
            0x30, 0x1C,                      /* PBKDF2-params SEQ (28) */
            0x04, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  /* salt */
            0x02, 0x02, 0x08, 0x00,                  /* iterations 2048 */
            0x30, 0x0C,                                /* PRF SEQ (12) */
            0x06, 0x08, 0x2A, 0x86, 0x48, 0x86,
                0xF7, 0x0D, 0x02, 0x09,            /* OID hmac-sha256 */
            0x05, 0x00,                                        /* NULL */
            0x30, 0x1D,                    /* encryptionScheme SEQ (29) */
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x01, 0x2A,        /* OID aes256-cbc */
            0x04, 0x10,                                  /* IV OCT (16) */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x80, 0x10,                       /* [0] IMPLICIT CT (16) */
            /* 16 bytes ciphertext - filled at runtime */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        byte regKey[32];
        byte regCiphertext[16];
        Aes regAes;
        WC_PKCS12* regP12 = NULL;
        byte* regPkey = NULL;
        byte* regCert = NULL;
        word32 regPkeySz = 0;
        word32 regCertSz = 0;

        /* Derive AES-256 key with the same PBKDF2 that DecryptContent uses */
        ExpectIntEQ(wc_PBKDF2(regKey, (const byte*)regPassword,
            (int)XSTRLEN(regPassword), regSalt, (int)sizeof(regSalt),
            2048, 32, WC_SHA256), 0);

        /* Encrypt the malformed plaintext */
        ExpectIntEQ(wc_AesInit(&regAes, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_AesSetKey(&regAes, regKey, 32, regIv,
            AES_ENCRYPTION), 0);
        ExpectIntEQ(wc_AesCbcEncrypt(&regAes, regCiphertext, regPlaintext,
            sizeof(regPlaintext)), 0);
        wc_AesFree(&regAes);

        /* Patch ciphertext into the DER template at offset 154 */
        XMEMCPY(regDer + 154, regCiphertext, sizeof(regCiphertext));

        /* Parse the crafted PKCS#12 - d2i should succeed (outer structure
         * is valid), but wc_PKCS12_parse must fail because GetSequence
         * rejects SEQUENCE length 100 against contentSz 16. */
        ExpectNotNull(regP12 = wc_PKCS12_new_ex(NULL));
        ExpectIntGE(wc_d2i_PKCS12(regDer, (word32)sizeof(regDer), regP12), 0);
        ExpectIntLT(wc_PKCS12_parse(regP12, regPassword, &regPkey, &regPkeySz,
            &regCert, &regCertSz, NULL), 0);

        XFREE(regPkey, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(regCert, NULL, DYNAMIC_TYPE_PKCS);
        wc_PKCS12_free(regP12);
    }
#endif
    return EXPECT_RESULT();
}

/* Test that a crafted PKCS12 with a MAC OCTET STRING shorter than the
 * algorithm's native digest size is rejected, rather than allowing the
 * integrity check to be truncated to a brute-forceable length. */
int test_wc_PKCS12_truncated_mac_bypass(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_PWDBASED) && defined(HAVE_PKCS12) \
    && !defined(NO_HMAC) && !defined(NO_SHA256)
    static const byte authSafe[] = { 0x30, 0x00 }; /* empty SEQUENCE OF CI */
    static const char password[] = "wolfSSL test";
    static const byte salt[8] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    const int iter = 1;
    const word32 pwLen = (word32)(sizeof(password) - 1);

    byte unicodePw[2 * sizeof(password) + 2];
    int  unicodePwLen = 0;
    byte macKey[WC_SHA256_DIGEST_SIZE];
    byte fullMac[WC_SHA256_DIGEST_SIZE] = {0};
    Hmac hmac;
    int  hmacInited = 0;
    word32 i;

    WC_PKCS12* pkcs12 = NULL;
    byte pfx[64];
    word32 pfxLen = 0;

    /* BMPString-style password (UTF-16BE) with trailing 0x00 0x00, matching
     * the unicode conversion done internally by wc_PKCS12_create_mac. */
    for (i = 0; i < pwLen; i++) {
        unicodePw[unicodePwLen++] = 0x00;
        unicodePw[unicodePwLen++] = (byte)password[i];
    }
    unicodePw[unicodePwLen++] = 0x00;
    unicodePw[unicodePwLen++] = 0x00;

    /* Derive the MAC key the same way wc_PKCS12_create_mac does:
     * PKCS12-PBKDF SHA-256, id=3 (MAC key), kLen=32. */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(macKey, unicodePw, unicodePwLen,
                                   salt, (int)sizeof(salt),
                                   iter, WC_SHA256_DIGEST_SIZE,
                                   WC_SHA256, 3 /* id = MAC */, NULL),
                                   0);

    /* Compute the genuine HMAC-SHA256 over the authSafe content. */
    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    if (EXPECT_SUCCESS())
        hmacInited = 1;
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA256, macKey, sizeof(macKey)), 0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, authSafe, (word32)sizeof(authSafe)), 0);
    ExpectIntEQ(wc_HmacFinal(&hmac, fullMac), 0);
    if (hmacInited)
        wc_HmacFree(&hmac);

    /*
     * Build a 59-byte PFX with a 1-byte truncated digest equal to fullMac[0]:
     *
     *   30 39                                  PFX SEQUENCE (57)
     *      02 01 03                            version = 3
     *      30 11                               AuthSafe ContentInfo (17)
     *         06 09 2A 86 48 86 F7 0D 01 07 01 OID 1.2.840.113549.1.7.1 (data)
     *         A0 04                            [0] EXPLICIT (4)
     *            04 02                            OCTET STRING (2)
     *               30 00                           authSafe = empty SEQUENCE
     *      30 21                               MacData (33)
     *         30 12                               DigestInfo (18)
     *            30 0d                               AlgorithmIdentifier (13)
     *               06 09 60 86 48 01 65 03 04 02 01 OID SHA-256
     *               05 00                            NULL
     *            04 01 XX                            OCTET STRING (1)
     *         04 08 01 02 03 04 05 06 07 08      salt
     *         02 01 01                           iterations = 1
     */
    pfx[pfxLen++] = 0x30; pfx[pfxLen++] = 0x39;
    pfx[pfxLen++] = 0x02; pfx[pfxLen++] = 0x01; pfx[pfxLen++] = 0x03;
    pfx[pfxLen++] = 0x30; pfx[pfxLen++] = 0x11;
    pfx[pfxLen++] = 0x06; pfx[pfxLen++] = 0x09;
    pfx[pfxLen++] = 0x2A; pfx[pfxLen++] = 0x86; pfx[pfxLen++] = 0x48;
    pfx[pfxLen++] = 0x86; pfx[pfxLen++] = 0xF7; pfx[pfxLen++] = 0x0D;
    pfx[pfxLen++] = 0x01; pfx[pfxLen++] = 0x07; pfx[pfxLen++] = 0x01;
    pfx[pfxLen++] = 0xA0; pfx[pfxLen++] = 0x04;
    pfx[pfxLen++] = 0x04; pfx[pfxLen++] = 0x02;
    pfx[pfxLen++] = 0x30; pfx[pfxLen++] = 0x00;
    pfx[pfxLen++] = 0x30; pfx[pfxLen++] = 0x21;
    pfx[pfxLen++] = 0x30; pfx[pfxLen++] = 0x12;
    pfx[pfxLen++] = 0x30; pfx[pfxLen++] = 0x0D;
    pfx[pfxLen++] = 0x06; pfx[pfxLen++] = 0x09;
    pfx[pfxLen++] = 0x60; pfx[pfxLen++] = 0x86; pfx[pfxLen++] = 0x48;
    pfx[pfxLen++] = 0x01; pfx[pfxLen++] = 0x65; pfx[pfxLen++] = 0x03;
    pfx[pfxLen++] = 0x04; pfx[pfxLen++] = 0x02; pfx[pfxLen++] = 0x01;
    pfx[pfxLen++] = 0x05; pfx[pfxLen++] = 0x00;
    pfx[pfxLen++] = 0x04; pfx[pfxLen++] = 0x01;
    pfx[pfxLen++] = fullMac[0];
    pfx[pfxLen++] = 0x04; pfx[pfxLen++] = 0x08;
    pfx[pfxLen++] = 0x01; pfx[pfxLen++] = 0x02; pfx[pfxLen++] = 0x03;
    pfx[pfxLen++] = 0x04; pfx[pfxLen++] = 0x05; pfx[pfxLen++] = 0x06;
    pfx[pfxLen++] = 0x07; pfx[pfxLen++] = 0x08;
    pfx[pfxLen++] = 0x02; pfx[pfxLen++] = 0x01; pfx[pfxLen++] = 0x01;

    {
        byte* parsedPkey = NULL;
        word32 parsedPkeySz = 0;
        byte* parsedCert = NULL;
        word32 parsedCertSz = 0;
        int d2iRet;

        ExpectNotNull(pkcs12 = wc_PKCS12_new());

        /* Accept rejection at either parse time (wc_d2i_PKCS12) or
         * verify time (wc_PKCS12_parse); the test fails only if both
         * succeed. */
        d2iRet = wc_d2i_PKCS12(pfx, pfxLen, pkcs12);
        if (d2iRet == 0) {
            ExpectIntNE(wc_PKCS12_parse(pkcs12, password,
                            &parsedPkey, &parsedPkeySz,
                            &parsedCert, &parsedCertSz, NULL),
                        0);
        }
        else {
            ExpectIntNE(d2iRet, 0);
        }

        XFREE(parsedPkey, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(parsedCert, NULL, DYNAMIC_TYPE_PKCS);
        wc_PKCS12_free(pkcs12);
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS12_PBKDF(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS12) && !defined(NO_PWDBASED) && !defined(NO_SHA256)
    /* Test vectors from RFC 7292 Appendix B (SHA-256 based) */
    static const byte passwd[] = {
        0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67,
        0x00, 0x00
    };
    static const byte salt[] = {
        0x0a, 0x58, 0xCF, 0x64, 0x53, 0x0d, 0x82, 0x3f
    };
    static const byte passwd2[] = {
        0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x65,
        0x00, 0x67, 0x00, 0x00
    };
    static const byte salt2[] = {
        0x16, 0x82, 0xC0, 0xfC, 0x5b, 0x3f, 0x7e, 0xc5
    };
    static const byte verify[] = {
        0x27, 0xE9, 0x0D, 0x7E, 0xD5, 0xA1, 0xC4, 0x11,
        0xBA, 0x87, 0x8B, 0xC0, 0x90, 0xF5, 0xCE, 0xBE,
        0x5E, 0x9D, 0x5F, 0xE3, 0xD6, 0x2B, 0x73, 0xAA
    };
    static const byte verify2[] = {
        0x90, 0x1B, 0x49, 0x70, 0xF0, 0x94, 0xF0, 0xF8,
        0x45, 0xC0, 0xF3, 0xF3, 0x13, 0x59, 0x18, 0x6A,
        0x35, 0xE3, 0x67, 0xFE, 0xD3, 0x21, 0xFD, 0x7C
    };
    byte derived[24];

    /* bad args */
    ExpectIntNE(wc_PKCS12_PBKDF(NULL, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 24, WC_SHA256, 1), 0);
    ExpectIntNE(wc_PKCS12_PBKDF(derived, passwd, 0,
                    salt, (int)sizeof(salt), 1, 24, WC_SHA256, 1), 0);
    ExpectIntNE(wc_PKCS12_PBKDF(derived, passwd, (int)sizeof(passwd),
                    salt, 0, 1, 24, WC_SHA256, 1), 0);

    /* 1 iteration */
    ExpectIntEQ(wc_PKCS12_PBKDF(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 24, WC_SHA256, 1), 0);
    ExpectIntEQ(XMEMCMP(derived, verify, 24), 0);

    /* 1000 iterations */
    ExpectIntEQ(wc_PKCS12_PBKDF(derived, passwd2, (int)sizeof(passwd2),
                    salt2, (int)sizeof(salt2), 1000, 24, WC_SHA256, 1), 0);
    ExpectIntEQ(XMEMCMP(derived, verify2, 24), 0);

    /* iterations <= 0 treated as 1 */
    ExpectIntEQ(wc_PKCS12_PBKDF(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 0, 24, WC_SHA256, 1), 0);
    ExpectIntEQ(XMEMCMP(derived, verify, 24), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS12_PBKDF_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS12) && !defined(NO_PWDBASED) && !defined(NO_SHA256)
    static const byte passwd[] = {
        0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67,
        0x00, 0x00
    };
    static const byte salt[] = {
        0x0a, 0x58, 0xCF, 0x64, 0x53, 0x0d, 0x82, 0x3f
    };
    static const byte passwd2[] = {
        0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x65,
        0x00, 0x67, 0x00, 0x00
    };
    static const byte salt2[] = {
        0x16, 0x82, 0xC0, 0xfC, 0x5b, 0x3f, 0x7e, 0xc5
    };
    static const byte verify[] = {
        0x27, 0xE9, 0x0D, 0x7E, 0xD5, 0xA1, 0xC4, 0x11,
        0xBA, 0x87, 0x8B, 0xC0, 0x90, 0xF5, 0xCE, 0xBE,
        0x5E, 0x9D, 0x5F, 0xE3, 0xD6, 0x2B, 0x73, 0xAA
    };
    static const byte verify2[] = {
        0x90, 0x1B, 0x49, 0x70, 0xF0, 0x94, 0xF0, 0xF8,
        0x45, 0xC0, 0xF3, 0xF3, 0x13, 0x59, 0x18, 0x6A,
        0x35, 0xE3, 0x67, 0xFE, 0xD3, 0x21, 0xFD, 0x7C
    };
    byte derived[24];
    byte derived2[24];

    /* bad args */
    ExpectIntNE(wc_PKCS12_PBKDF_ex(NULL, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 24, WC_SHA256, 1, NULL), 0);
    ExpectIntNE(wc_PKCS12_PBKDF_ex(derived, passwd, 0,
                    salt, (int)sizeof(salt), 1, 24, WC_SHA256, 1, NULL), 0);
    ExpectIntNE(wc_PKCS12_PBKDF_ex(derived, passwd, (int)sizeof(passwd),
                    salt, 0, 1, 24, WC_SHA256, 1, NULL), 0);

    /* 1 iteration, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 24, WC_SHA256, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify, 24), 0);

    /* 1000 iterations, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd2, (int)sizeof(passwd2),
                   salt2, (int)sizeof(salt2), 1000, 24, WC_SHA256, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify2, 24), 0);

    /* _ex and non-_ex produce identical output */
    ExpectIntEQ(wc_PKCS12_PBKDF(derived2, passwd2, (int)sizeof(passwd2),
                    salt2, (int)sizeof(salt2), 1000, 24, WC_SHA256, 1), 0);
    ExpectIntEQ(XMEMCMP(derived, derived2, 24), 0);

    /* id 2 (IV) and id 3 (MAC) also accepted */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 24, WC_SHA256, 2, NULL), 0);
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 24, WC_SHA256, 3, NULL), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS12_PBKDF_ex_sha1(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS12) && !defined(NO_PWDBASED) && !defined(NO_SHA)
    /* Test vectors generated with OpenSSL PKCS12_key_gen_uni / SHA-1 */
    static const byte passwd[] = {
        0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67,
        0x00, 0x00
    };
    static const byte salt[] = {
        0x0a, 0x58, 0xCF, 0x64, 0x53, 0x0d, 0x82, 0x3f
    };
    static const byte passwd2[] = {
        0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x65,
        0x00, 0x67, 0x00, 0x00
    };
    static const byte salt2[] = {
        0x16, 0x82, 0xC0, 0xfC, 0x5b, 0x3f, 0x7e, 0xc5
    };
    static const byte verify[] = {
        0x8A, 0xAA, 0xE6, 0x29, 0x7B, 0x6C, 0xB0, 0x46,
        0x42, 0xAB, 0x5B, 0x07, 0x78, 0x51, 0x28, 0x4E,
        0xB7, 0x12, 0x8F, 0x1A, 0x2A, 0x7F, 0xBC, 0xA3
    };
    static const byte verify2[] = {
        0x48, 0x3D, 0xD6, 0xE9, 0x19, 0xD7, 0xDE, 0x2E,
        0x8E, 0x64, 0x8B, 0xA8, 0xF8, 0x62, 0xF3, 0xFB,
        0xFB, 0xDC, 0x2B, 0xCB, 0x2C, 0x02, 0x95, 0x7F
    };
    byte derived[24];

    /* 1 iteration, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 24, WC_SHA, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify, 24), 0);

    /* 1000 iterations, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd2, (int)sizeof(passwd2),
                    salt2, (int)sizeof(salt2), 1000, 24, WC_SHA, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify2, 24), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS12_PBKDF_ex_sha512(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS12) && !defined(NO_PWDBASED) && defined(WOLFSSL_SHA512)
    /* Test vectors generated with OpenSSL PKCS12_key_gen_uni / SHA-512 */
    static const byte passwd[] = {
        0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67,
        0x00, 0x00
    };
    static const byte salt[] = {
        0x0a, 0x58, 0xCF, 0x64, 0x53, 0x0d, 0x82, 0x3f
    };
    static const byte passwd2[] = {
        0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x65,
        0x00, 0x67, 0x00, 0x00
    };
    static const byte salt2[] = {
        0x16, 0x82, 0xC0, 0xfC, 0x5b, 0x3f, 0x7e, 0xc5
    };
    static const byte verify[] = {
        0x13, 0x04, 0xA9, 0xF0, 0x01, 0x53, 0x74, 0x25,
        0x24, 0x12, 0x7D, 0x51, 0xD5, 0x98, 0xBC, 0x04,
        0x7E, 0x64, 0x09, 0x03, 0x09, 0xCA, 0x84, 0xEB,
        0x31, 0x2E, 0xB3, 0xBA, 0xD5, 0x60, 0xDD, 0x8D,
        0x2C, 0x71, 0xAB, 0xA4, 0xF2, 0x15, 0xAB, 0x31,
        0xF3, 0xBC, 0x42, 0xB6, 0xE8, 0x5D, 0xBF, 0x89
    };
    static const byte verify2[] = {
        0xBC, 0xD9, 0x78, 0x3D, 0x77, 0x8D, 0xA0, 0xE4,
        0x69, 0x00, 0x0B, 0x28, 0xE0, 0xD5, 0xDF, 0xDA,
        0xF3, 0xC9, 0x8D, 0x77, 0x39, 0xF9, 0x76, 0x84,
        0x1D, 0xE9, 0x61, 0x79, 0x50, 0x16, 0x6B, 0xA5,
        0x1B, 0x1D, 0x07, 0x65, 0x1B, 0x4B, 0x98, 0x91,
        0xAF, 0xE1, 0x80, 0x15, 0x39, 0xA3, 0x42, 0xDD
    };
    byte derived[48];

    /* 1 iteration, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 48, WC_SHA512, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify, 48), 0);

    /* 1000 iterations, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd2, (int)sizeof(passwd2),
                    salt2, (int)sizeof(salt2), 1000, 48, WC_SHA512, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify2, 48), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS12_PBKDF_ex_sha224(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS12) && !defined(NO_PWDBASED) && defined(WOLFSSL_SHA224)
    /* Test vectors generated with OpenSSL PKCS12_key_gen_uni / SHA-224 */
    static const byte passwd[] = {
        0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67,
        0x00, 0x00
    };
    static const byte salt[] = {
        0x0a, 0x58, 0xCF, 0x64, 0x53, 0x0d, 0x82, 0x3f
    };
    static const byte passwd2[] = {
        0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x65,
        0x00, 0x67, 0x00, 0x00
    };
    static const byte salt2[] = {
        0x16, 0x82, 0xC0, 0xfC, 0x5b, 0x3f, 0x7e, 0xc5
    };
    static const byte verify[] = {
        0x96, 0x22, 0xB0, 0x87, 0xFF, 0xE5, 0xDC, 0xB2,
        0xA6, 0xE1, 0x67, 0x3A, 0x44, 0x11, 0x50, 0x00,
        0x67, 0xE7, 0x10, 0xB4, 0xE6, 0x63, 0x4D, 0xCF,
        0x37, 0x0C, 0x25, 0x3C
    };
    static const byte verify2[] = {
        0x9A, 0x30, 0xD2, 0xD2, 0x14, 0x47, 0x64, 0x3D,
        0x9B, 0xFA, 0x43, 0x49, 0x0F, 0x81, 0x3D, 0x9D,
        0x5E, 0x0E, 0xB9, 0x0D, 0xAF, 0xA6, 0x80, 0x2C,
        0xF9, 0x33, 0x3B, 0x9D
    };
    byte derived[28];

    /* 1 iteration, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 28, WC_SHA224, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify, 28), 0);

    /* 1000 iterations, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd2, (int)sizeof(passwd2),
                    salt2, (int)sizeof(salt2), 1000, 28, WC_SHA224, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify2, 28), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS12_PBKDF_ex_sha384(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS12) && !defined(NO_PWDBASED) && defined(WOLFSSL_SHA384)
    /* Test vectors generated with OpenSSL PKCS12_key_gen_uni / SHA-384 */
    static const byte passwd[] = {
        0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67,
        0x00, 0x00
    };
    static const byte salt[] = {
        0x0a, 0x58, 0xCF, 0x64, 0x53, 0x0d, 0x82, 0x3f
    };
    static const byte passwd2[] = {
        0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x65,
        0x00, 0x67, 0x00, 0x00
    };
    static const byte salt2[] = {
        0x16, 0x82, 0xC0, 0xfC, 0x5b, 0x3f, 0x7e, 0xc5
    };
    static const byte verify[] = {
        0x17, 0xD5, 0x0F, 0x1F, 0x21, 0x8A, 0x3B, 0xC9,
        0x6E, 0x10, 0x41, 0xBA, 0xEC, 0xF0, 0xA1, 0xF2,
        0x11, 0x99, 0x56, 0x55, 0x2B, 0xD0, 0x38, 0x80,
        0x9A, 0x40, 0x2F, 0x13, 0x0A, 0x24, 0x67, 0xFA,
        0x49, 0xED, 0xFA, 0x6A, 0x83, 0xB5, 0x40, 0x69,
        0xFB, 0x73, 0xB7, 0x48, 0x44, 0x33, 0x1A, 0xC3
    };
    static const byte verify2[] = {
        0x7F, 0x50, 0xFB, 0x97, 0xF1, 0x7C, 0x01, 0x15,
        0xA2, 0x0A, 0xCB, 0x88, 0x68, 0xFC, 0x37, 0xA7,
        0x88, 0x8C, 0xD7, 0x1A, 0xF3, 0x1D, 0xB2, 0xDD,
        0x93, 0xCF, 0x44, 0xED, 0xC9, 0xA4, 0x61, 0x04,
        0xBE, 0x4E, 0x16, 0x86, 0x36, 0xF1, 0x6E, 0x65,
        0x41, 0xE0, 0xD7, 0xC3, 0xE2, 0x4D, 0x95, 0x99
    };
    byte derived[48];

    /* 1 iteration, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 48, WC_SHA384, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify, 48), 0);

    /* 1000 iterations, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd2, (int)sizeof(passwd2),
                    salt2, (int)sizeof(salt2), 1000, 48, WC_SHA384, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify2, 48), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS12_PBKDF_ex_sha512_224(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS12) && !defined(NO_PWDBASED) && \
    defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    /* Test vectors generated with OpenSSL PKCS12_key_gen_uni / SHA-512/224 */
    static const byte passwd[] = {
        0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67,
        0x00, 0x00
    };
    static const byte salt[] = {
        0x0a, 0x58, 0xCF, 0x64, 0x53, 0x0d, 0x82, 0x3f
    };
    static const byte passwd2[] = {
        0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x65,
        0x00, 0x67, 0x00, 0x00
    };
    static const byte salt2[] = {
        0x16, 0x82, 0xC0, 0xfC, 0x5b, 0x3f, 0x7e, 0xc5
    };
    static const byte verify[] = {
        0xE1, 0xAD, 0xB3, 0x9E, 0x3E, 0x72, 0x85, 0x11,
        0x28, 0xFC, 0xF8, 0x5F, 0x4A, 0xBE, 0x74, 0x99,
        0x7B, 0x02, 0xF0, 0x8B, 0x47, 0x1B, 0x71, 0x40,
        0xB9, 0x7C, 0x03, 0x83
    };
    static const byte verify2[] = {
        0xF0, 0x3F, 0x58, 0x16, 0x8B, 0x0C, 0xF5, 0x09,
        0xC5, 0x7F, 0x20, 0xD2, 0x24, 0xEC, 0x27, 0xAE,
        0xC2, 0xA6, 0xBB, 0x21, 0xE5, 0x76, 0x5A, 0xF8,
        0x3C, 0xA6, 0x2A, 0xA6
    };
    byte derived[28];

    /* 1 iteration, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 28, WC_SHA512_224, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify, 28), 0);

    /* 1000 iterations, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd2, (int)sizeof(passwd2),
                    salt2, (int)sizeof(salt2), 1000, 28, WC_SHA512_224, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify2, 28), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS12_PBKDF_ex_sha512_256(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS12) && !defined(NO_PWDBASED) && \
    defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    /* Test vectors generated with OpenSSL PKCS12_key_gen_uni / SHA-512/256 */
    static const byte passwd[] = {
        0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67,
        0x00, 0x00
    };
    static const byte salt[] = {
        0x0a, 0x58, 0xCF, 0x64, 0x53, 0x0d, 0x82, 0x3f
    };
    static const byte passwd2[] = {
        0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x65,
        0x00, 0x67, 0x00, 0x00
    };
    static const byte salt2[] = {
        0x16, 0x82, 0xC0, 0xfC, 0x5b, 0x3f, 0x7e, 0xc5
    };
    static const byte verify[] = {
        0x08, 0x41, 0xAA, 0x5C, 0xBC, 0xEE, 0xA4, 0x3F,
        0x34, 0xA4, 0xDA, 0xB1, 0xEB, 0x83, 0x7E, 0xF1,
        0x84, 0xBC, 0x30, 0x75, 0x40, 0x94, 0x95, 0x1F,
        0xAE, 0x25, 0xAA, 0xD1, 0xFD, 0x80, 0x2B, 0x5B
    };
    static const byte verify2[] = {
        0xC9, 0x44, 0xE9, 0x01, 0x53, 0x03, 0x64, 0xB9,
        0x61, 0x6E, 0x7F, 0xAE, 0xAA, 0x8E, 0x2D, 0xBB,
        0xE1, 0xAC, 0x45, 0x34, 0x58, 0x08, 0xB9, 0xE6,
        0xFA, 0x61, 0xF6, 0x1D, 0x15, 0x84, 0x15, 0x75
    };
    byte derived[32];

    /* 1 iteration, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd, (int)sizeof(passwd),
                    salt, (int)sizeof(salt), 1, 32, WC_SHA512_256, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify, 32), 0);

    /* 1000 iterations, NULL heap */
    ExpectIntEQ(wc_PKCS12_PBKDF_ex(derived, passwd2, (int)sizeof(passwd2),
                    salt2, (int)sizeof(salt2), 1000, 32, WC_SHA512_256, 1, NULL), 0);
    ExpectIntEQ(XMEMCMP(derived, verify2, 32), 0);
#endif
    return EXPECT_RESULT();
}
