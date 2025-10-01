/* test_pkcs7.c
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

#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/asn.h>
#ifdef HAVE_LIBZ
    #include <wolfssl/wolfcrypt/compress.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_pkcs7.h>

/*******************************************************************************
 * PKCS#7
 ******************************************************************************/

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

/*
 * Testing wc_PKCS7_New()
 */
int test_wc_PKCS7_New(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7)
    PKCS7* pkcs7 = NULL;

    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, testDevId));
    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
} /* END test-wc_PKCS7_New */

/*
 * Testing wc_PKCS7_Init()
 */
int test_wc_PKCS7_Init(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7)
    PKCS7* pkcs7 = NULL;
    void*  heap = NULL;

    ExpectNotNull(pkcs7 = wc_PKCS7_New(heap, testDevId));

    ExpectIntEQ(wc_PKCS7_Init(pkcs7, heap, testDevId), 0);
    /* Pass in bad args. */
    ExpectIntEQ(wc_PKCS7_Init(NULL, heap, testDevId), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
} /* END test-wc_PKCS7_Init */


/*
 * Testing wc_PKCS7_InitWithCert()
 */
int test_wc_PKCS7_InitWithCert(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7)
    PKCS7* pkcs7 = NULL;

#ifndef NO_RSA
    #if defined(USE_CERT_BUFFERS_2048)
        unsigned char    cert[sizeof(client_cert_der_2048)];
        int              certSz = (int)sizeof(cert);

        XMEMSET(cert, 0, certSz);
        XMEMCPY(cert, client_cert_der_2048, sizeof(client_cert_der_2048));
    #elif defined(USE_CERT_BUFFERS_1024)
        unsigned char    cert[sizeof(client_cert_der_1024)];
        int              certSz = (int)sizeof(cert);

        XMEMSET(cert, 0, certSz);
        XMEMCPY(cert, client_cert_der_1024, sizeof_client_cert_der_1024);
    #else
        unsigned char   cert[ONEK_BUF];
        XFILE           fp = XBADFILE;
        int             certSz;

        ExpectTrue((fp = XFOPEN("./certs/1024/client-cert.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(certSz = (int)XFREAD(cert, 1, sizeof_client_cert_der_1024,
            fp), 0);
        if (fp != XBADFILE)
            XFCLOSE(fp);
    #endif
#elif defined(HAVE_ECC)
    #if defined(USE_CERT_BUFFERS_256)
        unsigned char    cert[sizeof(cliecc_cert_der_256)];
        int              certSz = (int)sizeof(cert);

        XMEMSET(cert, 0, certSz);
        XMEMCPY(cert, cliecc_cert_der_256, sizeof(cliecc_cert_der_256));
    #else
        unsigned char   cert[ONEK_BUF];
        XFILE           fp = XBADFILE;
        int             certSz;

        ExpectTrue((fp = XFOPEN("./certs/client-ecc-cert.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(certSz = (int)XFREAD(cert, 1, sizeof(cliecc_cert_der_256),
            fp), 0);
        if (fp != XBADFILE)
            XFCLOSE(fp);
    #endif
#else
        #error PKCS7 requires ECC or RSA
#endif

#ifdef HAVE_ECC
    {
    /* bad test case from ZD 11011, malformed cert gives bad ECC key */
        static unsigned char certWithInvalidEccKey[] = {
        0x30, 0x82, 0x03, 0x5F, 0x30, 0x82, 0x03, 0x04, 0xA0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x61, 0xB3, 0x1E, 0x59, 0xF3, 0x68, 0x6C, 0xA4, 0x79,
        0x42, 0x83, 0x2F, 0x1A, 0x50, 0x71, 0x03, 0xBE, 0x31, 0xAA, 0x2C, 0x30,
        0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30,
        0x81, 0x8D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x55, 0x53, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0C, 0x06, 0x4F, 0x72, 0x65, 0x67, 0x6F, 0x6E, 0x31, 0x0E, 0x30, 0x0C,
        0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x05, 0x53, 0x61, 0x6C, 0x65, 0x6D,
        0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x43,
        0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x45, 0x43, 0x43, 0x31, 0x0D, 0x30,
        0x0B, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x04, 0x46, 0x61, 0x73, 0x74,
        0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x77,
        0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63,
        0x6F, 0x6D, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
        0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40,
        0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x30,
        0x1E, 0x17, 0x0D, 0x32, 0x30, 0x30, 0x36, 0x31, 0x39, 0x31, 0x33, 0x32,
        0x33, 0x34, 0x31, 0x5A, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x33, 0x31, 0x36,
        0x31, 0x33, 0x32, 0x33, 0x34, 0x31, 0x5A, 0x30, 0x81, 0x8D, 0x31, 0x0B,
        0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
        0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x06, 0x4F, 0x72,
        0x65, 0x67, 0x6F, 0x6E, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04,
        0x07, 0x0C, 0x05, 0x53, 0x61, 0x6C, 0x65, 0x6D, 0x31, 0x13, 0x30, 0x11,
        0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x43, 0x6C, 0x69, 0x65, 0x6E,
        0x74, 0x20, 0x45, 0x43, 0x43, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55,
        0x04, 0x0B, 0x0C, 0x04, 0x46, 0x61, 0x73, 0x74, 0x31, 0x18, 0x30, 0x26,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77,
        0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1F,
        0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
        0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40, 0x77, 0x6F, 0x6C, 0x66,
        0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x59, 0x30, 0x13, 0x06,
        0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x02, 0x00, 0x04, 0x55, 0xBF,
        0xF4, 0x0F, 0x44, 0x50, 0x9A, 0x3D, 0xCE, 0x9B, 0xB7, 0xF0, 0xC5, 0x4D,
        0xF5, 0x70, 0x7B, 0xD4, 0xEC, 0x24, 0x8E, 0x19, 0x80, 0xEC, 0x5A, 0x4C,
        0xA2, 0x24, 0x03, 0x62, 0x2C, 0x9B, 0xDA, 0xEF, 0xA2, 0x35, 0x12, 0x43,
        0x84, 0x76, 0x16, 0xC6, 0x56, 0x95, 0x06, 0xCC, 0x01, 0xA9, 0xBD, 0xF6,
        0x75, 0x1A, 0x42, 0xF7, 0xBD, 0xA9, 0xB2, 0x36, 0x22, 0x5F, 0xC7, 0x5D,
        0x7F, 0xB4, 0xA3, 0x82, 0x01, 0x3E, 0x30, 0x82, 0x01, 0x3A, 0x30, 0x1D,
        0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xEB, 0xD4, 0x4B,
        0x59, 0x6B, 0x95, 0x61, 0x3F, 0x51, 0x57, 0xB6, 0x04, 0x4D, 0x89, 0x41,
        0x88, 0x44, 0x5C, 0xAB, 0xF2, 0x30, 0x81, 0xCD, 0x06, 0x03, 0x55, 0x1D,
        0x23, 0x04, 0x81, 0xC5, 0x30, 0x81, 0xC2, 0x80, 0x14, 0xEB, 0xD4, 0x4B,
        0x59, 0x72, 0x95, 0x61, 0x3F, 0x51, 0x57, 0xB6, 0x04, 0x4D, 0x89, 0x41,
        0x88, 0x44, 0x5C, 0xAB, 0xF2, 0xA1, 0x81, 0x93, 0xA4, 0x81, 0x90, 0x30,
        0x81, 0x8D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x55, 0x53, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x08, 0x08,
        0x0C, 0x06, 0x4F, 0x72, 0x65, 0x67, 0x6F, 0x6E, 0x31, 0x0E, 0x30, 0x0C,
        0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x05, 0x53, 0x61, 0x6C, 0x65, 0x6D,
        0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x43,
        0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x45, 0x43, 0x43, 0x31, 0x0D, 0x30,
        0x0B, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x04, 0x46, 0x61, 0x73, 0x74,
        0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x77,
        0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63,
        0x6F, 0x6D, 0x30, 0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
        0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40,
        0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x82,
        0x14, 0x61, 0xB3, 0x1E, 0x59, 0xF3, 0x68, 0x6C, 0xA4, 0x79, 0x42, 0x83,
        0x2F, 0x1A, 0x50, 0x71, 0x03, 0xBE, 0x32, 0xAA, 0x2C, 0x30, 0x0C, 0x06,
        0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30,
        0x1C, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x15, 0x30, 0x13, 0x82, 0x0B,
        0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x87,
        0x04, 0x23, 0x00, 0x00, 0x01, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x25,
        0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07,
        0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
        0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xE4, 0xA0, 0x23, 0x26,
        0x2B, 0x0B, 0x42, 0x0F, 0x97, 0x37, 0x6D, 0xCB, 0x14, 0x23, 0xC3, 0xC3,
        0xE6, 0x44, 0xCF, 0x5F, 0x4C, 0x26, 0xA3, 0x72, 0x64, 0x7A, 0x9C, 0xCB,
        0x64, 0xAB, 0xA6, 0xBE, 0x02, 0x21, 0x00, 0xAA, 0xC5, 0xA3, 0x50, 0xF6,
        0xF1, 0xA5, 0xDB, 0x05, 0xE0, 0x75, 0xD2, 0xF7, 0xBA, 0x49, 0x5F, 0x8F,
        0x7D, 0x1C, 0x44, 0xB1, 0x6E, 0xDF, 0xC8, 0xDA, 0x10, 0x48, 0x2D, 0x53,
        0x08, 0xA8, 0xB4
        };
#endif
        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        /* If initialization is not successful, it's free'd in init func. */
        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte*)cert, (word32)certSz),
            0);
        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;

        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        /* Valid initialization usage. */
        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

        /* Pass in bad args. No need free for null checks, free at end.*/
        ExpectIntEQ(wc_PKCS7_InitWithCert(NULL, (byte*)cert, (word32)certSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, (word32)certSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef HAVE_ECC
        ExpectIntLT(wc_PKCS7_InitWithCert(pkcs7, certWithInvalidEccKey,
            sizeof(certWithInvalidEccKey)), 0);
    }
#endif

    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_InitWithCert */


/*
 * Testing wc_PKCS7_EncodeData()
 */
int test_wc_PKCS7_EncodeData(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7)
    PKCS7* pkcs7 = NULL;
    byte   output[FOURK_BUF];
    byte   data[] = "My encoded DER cert.";

#ifndef NO_RSA
    #if defined(USE_CERT_BUFFERS_2048)
        unsigned char cert[sizeof(client_cert_der_2048)];
        unsigned char key[sizeof(client_key_der_2048)];
        int certSz = (int)sizeof(cert);
        int keySz = (int)sizeof(key);

        XMEMSET(cert, 0, certSz);
        XMEMSET(key, 0, keySz);
        XMEMCPY(cert, client_cert_der_2048, certSz);
        XMEMCPY(key, client_key_der_2048, keySz);
    #elif defined(USE_CERT_BUFFERS_1024)
        unsigned char cert[sizeof(sizeof_client_cert_der_1024)];
        unsigned char key[sizeof_client_key_der_1024];
        int certSz = (int)sizeof(cert);
        int keySz = (int)sizeof(key);

        XMEMSET(cert, 0, certSz);
        XMEMSET(key, 0, keySz);
        XMEMCPY(cert, client_cert_der_1024, certSz);
        XMEMCPY(key, client_key_der_1024, keySz);
    #else
        unsigned char cert[ONEK_BUF];
        unsigned char key[ONEK_BUF];
        XFILE         fp = XBADFILE;
        int           certSz;
        int           keySz;

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
        if (fp != XBADFILE)
            XFCLOSE(fp);
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
        if (fp != XBADFILE)
            XFCLOSE(fp);
    #endif
#endif

    XMEMSET(output, 0, sizeof(output));

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);

    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte*)cert, (word32)certSz), 0);

    if (pkcs7 != NULL) {
        pkcs7->content = data;
        pkcs7->contentSz = sizeof(data);
        pkcs7->privateKey = key;
        pkcs7->privateKeySz = (word32)keySz;
    }
    ExpectIntGT(wc_PKCS7_EncodeData(pkcs7, output, (word32)sizeof(output)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_PKCS7_EncodeData(NULL, output, (word32)sizeof(output)),
                                                            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeData(pkcs7, NULL, (word32)sizeof(output)),
                                                            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeData(pkcs7, output, 5), WC_NO_ERR_TRACE(BUFFER_E));

    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_PKCS7_EncodeData */


#if defined(HAVE_PKCS7) && defined(HAVE_PKCS7_RSA_RAW_SIGN_CALLBACK) && \
    !defined(NO_RSA) && !defined(NO_SHA256)
/* RSA sign raw digest callback */
static int rsaSignRawDigestCb(PKCS7* pkcs7, byte* digest, word32 digestSz,
                              byte* out, word32 outSz, byte* privateKey,
                              word32 privateKeySz, int devid, int hashOID)
{
    /* specific DigestInfo ASN.1 encoding prefix for a SHA2565 digest */
    byte digInfoEncoding[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    };

    int ret;
    byte digestInfo[ONEK_BUF];
    byte sig[FOURK_BUF];
    word32 digestInfoSz = 0;
    word32 idx = 0;
    RsaKey rsa;

    /* SHA-256 required only for this example callback due to above
     * digInfoEncoding[] */
    if (pkcs7 == NULL || digest == NULL || out == NULL ||
        (sizeof(digestInfo) < sizeof(digInfoEncoding) + digestSz) ||
        (hashOID != SHA256h)) {
        return -1;
    }

    /* build DigestInfo */
    XMEMCPY(digestInfo, digInfoEncoding, sizeof(digInfoEncoding));
    digestInfoSz += sizeof(digInfoEncoding);
    XMEMCPY(digestInfo + digestInfoSz, digest, digestSz);
    digestInfoSz += digestSz;

    /* set up RSA key */
    ret = wc_InitRsaKey_ex(&rsa, pkcs7->heap, devid);
    if (ret != 0) {
        return ret;
    }

    ret = wc_RsaPrivateKeyDecode(privateKey, &idx, &rsa, privateKeySz);

    /* sign DigestInfo */
    if (ret == 0) {
        ret = wc_RsaSSL_Sign(digestInfo, digestInfoSz, sig, sizeof(sig),
                             &rsa, pkcs7->rng);
        if (ret > 0) {
            if (ret > (int)outSz) {
                /* output buffer too small */
                ret = -1;
            }
            else {
                /* success, ret holds sig size */
                XMEMCPY(out, sig, ret);
            }
        }
    }

    wc_FreeRsaKey(&rsa);

    return ret;
}
#endif

#if defined(HAVE_PKCS7) && defined(ASN_BER_TO_DER)
typedef struct encodeSignedDataStream {
    byte out[FOURK_BUF*3];
    int  idx;
    word32 outIdx;
    word32 chunkSz; /* max amount of data to be returned */
} encodeSignedDataStream;


/* content is 8k of partially created bundle */
static int GetContentCB(PKCS7* pkcs7, byte** content, void* ctx)
{
    int ret = 0;
    encodeSignedDataStream* strm = (encodeSignedDataStream*)ctx;

    if (strm->outIdx  < pkcs7->contentSz) {
        ret = (pkcs7->contentSz > strm->outIdx + strm->chunkSz)?
                strm->chunkSz : pkcs7->contentSz - strm->outIdx;
        *content = strm->out + strm->outIdx;
        strm->outIdx += ret;
    }

    (void)pkcs7;
    return ret;
}

static int StreamOutputCB(PKCS7* pkcs7, const byte* output, word32 outputSz,
    void* ctx)
{
    encodeSignedDataStream* strm = (encodeSignedDataStream*)ctx;

    XMEMCPY(strm->out + strm->idx, output, outputSz);
    strm->idx += outputSz;
    (void)pkcs7;
    return 0;
}
#endif


/*
 * Testing wc_PKCS7_EncodeSignedData()
 */
int test_wc_PKCS7_EncodeSignedData(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7)
    PKCS7* pkcs7 = NULL;
    WC_RNG rng;
    byte   output[FOURK_BUF];
    byte   badOut[1];
    word32 outputSz = (word32)sizeof(output);
    word32 badOutSz = 0;
    byte   data[] = "Test data to encode.";
#ifndef NO_RSA
    int    encryptOid = RSAk;
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
        if (fp != XBADFILE)
            XFCLOSE(fp);
    #endif
#elif defined(HAVE_ECC)
    int    encryptOid = ECDSAk;
    #if defined(USE_CERT_BUFFERS_256)
        unsigned char    cert[sizeof(cliecc_cert_der_256)];
        unsigned char    key[sizeof(ecc_clikey_der_256)];
        int              certSz = (int)sizeof(cert);
        int              keySz = (int)sizeof(key);
        XMEMSET(cert, 0, certSz);
        XMEMSET(key, 0, keySz);
        XMEMCPY(cert, cliecc_cert_der_256, certSz);
        XMEMCPY(key, ecc_clikey_der_256, keySz);
    #else
        unsigned char   cert[ONEK_BUF];
        unsigned char   key[ONEK_BUF];
        XFILE           fp = XBADFILE;
        int             certSz;
        int             keySz;

        ExpectTrue((fp = XFOPEN("./certs/client-ecc-cert.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(certSz = (int)XFREAD(cert, 1, ONEK_BUF, fp), 0);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }

        ExpectTrue((fp = XFOPEN("./certs/client-ecc-key.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(keySz = (int)XFREAD(key, 1, ONEK_BUF, fp), 0);
        if (fp != XBADFILE)
            XFCLOSE(fp);
    #endif
#endif

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    XMEMSET(output, 0, outputSz);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);

    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, certSz), 0);

    if (pkcs7 != NULL) {
        pkcs7->content = data;
        pkcs7->contentSz = (word32)sizeof(data);
        pkcs7->privateKey = key;
        pkcs7->privateKeySz = (word32)sizeof(key);
        pkcs7->encryptOID = encryptOid;
    #ifdef NO_SHA
        pkcs7->hashOID = SHA256h;
    #else
        pkcs7->hashOID = SHAh;
    #endif
        pkcs7->rng = &rng;
    }

    ExpectIntGT(wc_PKCS7_EncodeSignedData(pkcs7, output, outputSz), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, outputSz), 0);

#if defined(ASN_BER_TO_DER) && !defined(NO_RSA)
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    /* reinitialize and test setting stream mode */
    {
        int signedSz = 0, i;
        encodeSignedDataStream strm;
        static const int numberOfChunkSizes = 4;
        static const word32 chunkSizes[] = { 4080, 4096, 5000, 9999 };
        /* chunkSizes were chosen to test around the default 4096 octet string
         * size used in pkcs7.c */

        XMEMSET(&strm, 0, sizeof(strm));

        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);

        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, certSz), 0);

        if (pkcs7 != NULL) {
            pkcs7->content = data;
            pkcs7->contentSz = (word32)sizeof(data);
            pkcs7->privateKey = key;
            pkcs7->privateKeySz = (word32)sizeof(key);
            pkcs7->encryptOID = encryptOid;
        #ifdef NO_SHA
            pkcs7->hashOID = SHA256h;
        #else
            pkcs7->hashOID = SHAh;
        #endif
            pkcs7->rng = &rng;
        }
        ExpectIntEQ(wc_PKCS7_GetStreamMode(pkcs7), 0);
        ExpectIntEQ(wc_PKCS7_SetStreamMode(pkcs7, 1, NULL, NULL, NULL), 0);
        ExpectIntEQ(wc_PKCS7_SetStreamMode(NULL, 1, NULL, NULL, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_PKCS7_GetStreamMode(pkcs7), 1);

        ExpectIntGT(signedSz = wc_PKCS7_EncodeSignedData(pkcs7, output,
            outputSz), 0);
        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;

        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

        /* use exact signed buffer size since BER encoded */
        ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output,
            (word32)signedSz), 0);
        wc_PKCS7_Free(pkcs7);

        /* now try with using callbacks for IO */
        for (i = 0; i < numberOfChunkSizes; i++) {
            strm.idx    = 0;
            strm.outIdx = 0;
            strm.chunkSz = chunkSizes[i];

            ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
            ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);

            ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, certSz), 0);

            if (pkcs7 != NULL) {
                pkcs7->contentSz  = 10000;
                pkcs7->privateKey = key;
                pkcs7->privateKeySz = (word32)sizeof(key);
                pkcs7->encryptOID = encryptOid;
            #ifdef NO_SHA
                pkcs7->hashOID = SHA256h;
            #else
                pkcs7->hashOID = SHAh;
            #endif
                pkcs7->rng = &rng;
            }
            ExpectIntEQ(wc_PKCS7_SetStreamMode(pkcs7, 1, GetContentCB,
                StreamOutputCB, (void*)&strm), 0);

            ExpectIntGT(signedSz = wc_PKCS7_EncodeSignedData(pkcs7, NULL, 0),
                0);
            wc_PKCS7_Free(pkcs7);
            pkcs7 = NULL;

            ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
            ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

            /* use exact signed buffer size since BER encoded */
            ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, strm.out,
                (word32)signedSz), 0);
            wc_PKCS7_Free(pkcs7);
            pkcs7 = NULL;
        }
    }
#endif
#ifndef NO_PKCS7_STREAM
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    {
        word32 z;
        int ret;

        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

        /* test for streaming mode */
        ret = -1;
        for (z = 0; z < outputSz && ret != 0; z++) {
            ret = wc_PKCS7_VerifySignedData(pkcs7, output + z, 1);
            if (ret < 0){
                ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
            }
        }
        ExpectIntEQ(ret, 0);
        ExpectIntNE(pkcs7->contentSz, 0);
        ExpectNotNull(pkcs7->contentDynamic);
    }
#endif /* !NO_PKCS7_STREAM */


    /* Pass in bad args. */
    ExpectIntEQ(wc_PKCS7_EncodeSignedData(NULL, output, outputSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeSignedData(pkcs7, NULL, outputSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeSignedData(pkcs7, badOut,
                                badOutSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    if (pkcs7 != NULL) {
        pkcs7->hashOID = 0; /* bad hashOID */
    }
    ExpectIntEQ(wc_PKCS7_EncodeSignedData(pkcs7, output, outputSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#if defined(HAVE_PKCS7) && defined(HAVE_PKCS7_RSA_RAW_SIGN_CALLBACK) && \
    !defined(NO_RSA) && !defined(NO_SHA256)
    /* test RSA sign raw digest callback, if using RSA and compiled in.
     * Example callback assumes SHA-256, so only run test if compiled in. */
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, certSz), 0);

    if (pkcs7 != NULL) {
        pkcs7->content = data;
        pkcs7->contentSz = (word32)sizeof(data);
        pkcs7->privateKey = key;
        pkcs7->privateKeySz = (word32)sizeof(key);
        pkcs7->encryptOID = RSAk;
        pkcs7->hashOID = SHA256h;
        pkcs7->rng = &rng;
    }

    ExpectIntEQ(wc_PKCS7_SetRsaSignRawDigestCb(pkcs7, rsaSignRawDigestCb), 0);

    ExpectIntGT(wc_PKCS7_EncodeSignedData(pkcs7, output, outputSz), 0);
#endif

    wc_PKCS7_Free(pkcs7);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);

#endif
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_EncodeSignedData */


/*
 * Testing wc_PKCS7_EncodeSignedData_ex() and wc_PKCS7_VerifySignedData_ex()
 */
int test_wc_PKCS7_EncodeSignedData_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7)
    int        i;
    PKCS7*     pkcs7 = NULL;
    WC_RNG     rng;
    byte       outputHead[FOURK_BUF/2];
    byte       outputFoot[FOURK_BUF/2];
    word32     outputHeadSz = (word32)sizeof(outputHead);
    word32     outputFootSz = (word32)sizeof(outputFoot);
    byte       data[FOURK_BUF];
    wc_HashAlg hash;
#ifdef NO_SHA
    enum wc_HashType hashType = WC_HASH_TYPE_SHA256;
#else
    enum wc_HashType hashType = WC_HASH_TYPE_SHA;
#endif
    byte        hashBuf[WC_MAX_DIGEST_SIZE];
    word32      hashSz = (word32)wc_HashGetDigestSize(hashType);

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
        unsigned char  cert[ONEK_BUF];
        unsigned char  key[ONEK_BUF];
        XFILE          fp = XBADFILE;
        int            certSz;
        int            keySz;

        ExpectTure((fp = XFOPEN("./certs/1024/client-cert.der", "rb")) !=
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
        if (fp != XBADFILE)
            XFCLOSE(fp);
    #endif
#elif defined(HAVE_ECC)
    #if defined(USE_CERT_BUFFERS_256)
        unsigned char   cert[sizeof(cliecc_cert_der_256)];
        unsigned char   key[sizeof(ecc_clikey_der_256)];
        int             certSz = (int)sizeof(cert);
        int             keySz = (int)sizeof(key);

        XMEMSET(cert, 0, certSz);
        XMEMSET(key, 0, keySz);
        XMEMCPY(cert, cliecc_cert_der_256, sizeof_cliecc_cert_der_256);
        XMEMCPY(key, ecc_clikey_der_256, sizeof_ecc_clikey_der_256);
    #else
        unsigned char cert[ONEK_BUF];
        unsigned char key[ONEK_BUF];
        XFILE         fp = XBADFILE;
        int           certSz;
        int           keySz;

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
        if (fp != XBADFILE)
            XFCLOSE(fp);
    #endif
#endif

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    /* initialize large data with sequence */
    for (i=0; i<(int)sizeof(data); i++)
        data[i] = i & 0xff;

    XMEMSET(outputHead, 0, outputHeadSz);
    XMEMSET(outputFoot, 0, outputFootSz);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);

    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, certSz), 0);

    if (pkcs7 != NULL) {
        pkcs7->content = NULL; /* not used for ex */
        pkcs7->contentSz = (word32)sizeof(data);
        pkcs7->privateKey = key;
        pkcs7->privateKeySz = (word32)sizeof(key);
        pkcs7->encryptOID = RSAk;
    #ifdef NO_SHA
        pkcs7->hashOID = SHA256h;
    #else
        pkcs7->hashOID = SHAh;
    #endif
        pkcs7->rng = &rng;
    }

    /* calculate hash for content */
    XMEMSET(&hash, 0, sizeof(wc_HashAlg));
    ExpectIntEQ(wc_HashInit(&hash, hashType), 0);
    ExpectIntEQ(wc_HashUpdate(&hash, hashType, data, sizeof(data)), 0);
    ExpectIntEQ(wc_HashFinal(&hash, hashType, hashBuf), 0);
    DoExpectIntEQ(wc_HashFree(&hash, hashType), 0);

    /* Perform PKCS7 sign using hash directly */
    ExpectIntEQ(wc_PKCS7_EncodeSignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, &outputHeadSz, outputFoot, &outputFootSz), 0);
    ExpectIntGT(outputHeadSz, 0);
    ExpectIntGT(outputFootSz, 0);

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

    /* required parameter even on verify when using _ex, if using outputHead
     * and outputFoot */
    if (pkcs7 != NULL) {
        pkcs7->contentSz = (word32)sizeof(data);
    }
    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, outputHeadSz, outputFoot, outputFootSz), 0);

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    /* assembly complete PKCS7 sign and use normal verify */
    {
        byte* output = NULL;
        word32 outputSz = 0;
    #ifndef NO_PKCS7_STREAM
        word32 z;
        int ret;
    #endif /* !NO_PKCS7_STREAM */

        ExpectNotNull(output = (byte*)XMALLOC(
            outputHeadSz + sizeof(data) + outputFootSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        if (output != NULL) {
            XMEMCPY(&output[outputSz], outputHead, outputHeadSz);
            outputSz += outputHeadSz;
            XMEMCPY(&output[outputSz], data, sizeof(data));
            outputSz += sizeof(data);
            XMEMCPY(&output[outputSz], outputFoot, outputFootSz);
            outputSz += outputFootSz;
        }

        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
        ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, outputSz), 0);

    #ifndef NO_PKCS7_STREAM
        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;

        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

        /* test for streaming mode */
        ret = -1;
        for (z = 0; z < outputSz && ret != 0; z++) {
            ret = wc_PKCS7_VerifySignedData(pkcs7, output + z, 1);
            if (ret < 0){
                ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
            }
        }
        ExpectIntEQ(ret, 0);
        ExpectIntNE(pkcs7->contentSz, 0);
        ExpectNotNull(pkcs7->contentDynamic);

        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;
        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    #endif /* !NO_PKCS7_STREAM */

        XFREE(output, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* Pass in bad args. */
    ExpectIntEQ(wc_PKCS7_EncodeSignedData_ex(NULL, hashBuf, hashSz, outputHead,
        &outputHeadSz, outputFoot, &outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeSignedData_ex(pkcs7, NULL, hashSz, outputHead,
        &outputHeadSz, outputFoot, &outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeSignedData_ex(pkcs7, hashBuf, 0, outputHead,
        &outputHeadSz, outputFoot, &outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeSignedData_ex(pkcs7, hashBuf, hashSz, NULL,
        &outputHeadSz, outputFoot, &outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeSignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, NULL, outputFoot, &outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeSignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, &outputHeadSz, NULL, &outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeSignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, &outputHeadSz, outputFoot, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    if (pkcs7 != NULL) {
        pkcs7->hashOID = 0; /* bad hashOID */
    }
    ExpectIntEQ(wc_PKCS7_EncodeSignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, &outputHeadSz, outputFoot, &outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(NULL, hashBuf, hashSz, outputHead,
        outputHeadSz, outputFoot, outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, NULL, hashSz, outputHead,
        outputHeadSz, outputFoot, outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_PKCS7_STREAM
    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, 0, outputHead,
        outputHeadSz, outputFoot, outputFootSz), WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
#else
    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, 0, outputHead,
        outputHeadSz, outputFoot, outputFootSz), WC_NO_ERR_TRACE(BUFFER_E));
#endif
    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, hashSz, NULL,
        outputHeadSz, outputFoot, outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_PKCS7_STREAM
    /* can pass in 0 buffer length with streaming API */
    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, 0, outputFoot, outputFootSz), WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
#else
    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, 0, outputFoot, outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, outputHeadSz, NULL, outputFootSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_PKCS7_STREAM
    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, outputHeadSz, outputFoot, 0), WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
#else
    ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, hashSz,
        outputHead, outputHeadSz, outputFoot, 0), WC_NO_ERR_TRACE(BUFFER_E));
#endif

    wc_PKCS7_Free(pkcs7);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_EncodeSignedData_ex */


#if defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM)

/**
 * Loads certs/keys from files or buffers into the argument buffers,
 * helper function called by CreatePKCS7SignedData().
 *
 * Returns 0 on success, negative on error.
 */
static int LoadPKCS7SignedDataCerts(
        int useIntermediateCertChain, int pkAlgoType,
        byte* intCARoot, word32* intCARootSz,
        byte* intCA1, word32* intCA1Sz,
        byte* intCA2, word32* intCA2Sz,
        byte* cert, word32* certSz,
        byte* key, word32* keySz)
{
    EXPECT_DECLS;
    int ret = 0;
    XFILE fp = XBADFILE;

#ifndef NO_RSA
    const char* intCARootRSA   = "./certs/ca-cert.der";
    const char* intCA1RSA      = "./certs/intermediate/ca-int-cert.der";
    const char* intCA2RSA      = "./certs/intermediate/ca-int2-cert.der";
    const char* intServCertRSA = "./certs/intermediate/server-int-cert.der";
    const char* intServKeyRSA  = "./certs/server-key.der";

    #if !defined(USE_CERT_BUFFERS_2048) && !defined(USE_CERT_BUFFERS_1024)
        const char* cli1024Cert    = "./certs/1024/client-cert.der";
        const char* cli1024Key     = "./certs/1024/client-key.der";
    #endif
#endif
#ifdef HAVE_ECC
    const char* intCARootECC   = "./certs/ca-ecc-cert.der";
    const char* intCA1ECC      = "./certs/intermediate/ca-int-ecc-cert.der";
    const char* intCA2ECC      = "./certs/intermediate/ca-int2-ecc-cert.der";
    const char* intServCertECC = "./certs/intermediate/server-int-ecc-cert.der";
    const char* intServKeyECC  = "./certs/ecc-key.der";

    #ifndef USE_CERT_BUFFERS_256
        const char* cliEccCert     = "./certs/client-ecc-cert.der";
        const char* cliEccKey      = "./certs/client-ecc-key.der";
    #endif
#endif

    if (cert == NULL || certSz == NULL || key == NULL || keySz == NULL ||
        ((useIntermediateCertChain == 1) &&
        (intCARoot == NULL || intCARootSz == NULL || intCA1 == NULL ||
         intCA1Sz == NULL || intCA2 == NULL || intCA2Sz == NULL))) {
        return BAD_FUNC_ARG;
    }

    /* Read/load certs and keys to use for signing based on PK type and chain */
    switch (pkAlgoType) {
#ifndef NO_RSA
        case RSA_TYPE:
            if (useIntermediateCertChain == 1) {
                ExpectTrue((fp = XFOPEN(intCARootRSA, "rb")) != XBADFILE);
                *intCARootSz = (word32)XFREAD(intCARoot, 1, *intCARootSz, fp);
                if (fp != XBADFILE) {
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*intCARootSz, 0);

                ExpectTrue((fp = XFOPEN(intCA1RSA, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *intCA1Sz = (word32)XFREAD(intCA1, 1, *intCA1Sz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*intCA1Sz, 0);

                ExpectTrue((fp = XFOPEN(intCA2RSA, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *intCA2Sz = (word32)XFREAD(intCA2, 1, *intCA2Sz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*intCA2Sz, 0);

                ExpectTrue((fp = XFOPEN(intServCertRSA, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *certSz = (word32)XFREAD(cert, 1, *certSz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*certSz, 0);

                ExpectTrue((fp = XFOPEN(intServKeyRSA, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *keySz = (word32)XFREAD(key, 1, *keySz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*keySz, 0);
            }
            else {
            #if defined(USE_CERT_BUFFERS_2048)
                *keySz  = sizeof_client_key_der_2048;
                *certSz = sizeof_client_cert_der_2048;
                XMEMCPY(key, client_key_der_2048, *keySz);
                XMEMCPY(cert, client_cert_der_2048, *certSz);
            #elif defined(USE_CERT_BUFFERS_1024)
                *keySz  = sizeof_client_key_der_1024;
                *certSz = sizeof_client_cert_der_1024;
                XMEMCPY(key, client_key_der_1024, *keySz);
                XMEMCPY(cert, client_cert_der_1024, *certSz);
            #else
                ExpectTrue((fp = XFOPEN(cli1024Key, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *keySz = (word32)XFREAD(key, 1, *keySz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*keySz, 0);

                ExpectTrue((fp = XFOPEN(cli1024Cert, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *certSz = (word32)XFREAD(cert, 1, *certSz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*certSz, 0);
            #endif /* USE_CERT_BUFFERS_2048 */
            }
            break;
#endif /* !NO_RSA */
#ifdef HAVE_ECC
        case ECC_TYPE:
            if (useIntermediateCertChain == 1) {
                ExpectTrue((fp = XFOPEN(intCARootECC, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *intCARootSz = (word32)XFREAD(intCARoot, 1, *intCARootSz,
                                                  fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*intCARootSz, 0);

                ExpectTrue((fp = XFOPEN(intCA1ECC, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *intCA1Sz = (word32)XFREAD(intCA1, 1, *intCA1Sz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*intCA1Sz, 0);

                ExpectTrue((fp = XFOPEN(intCA2ECC, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *intCA2Sz = (word32)XFREAD(intCA2, 1, *intCA2Sz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*intCA2Sz, 0);

                ExpectTrue((fp = XFOPEN(intServCertECC, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *certSz = (word32)XFREAD(cert, 1, *certSz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*certSz, 0);

                ExpectTrue((fp = XFOPEN(intServKeyECC, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *keySz = (word32)XFREAD(key, 1, *keySz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*keySz, 0);
            }
            else {
            #if defined(USE_CERT_BUFFERS_256)
                *keySz  = sizeof_ecc_clikey_der_256;
                *certSz = sizeof_cliecc_cert_der_256;
                XMEMCPY(key, ecc_clikey_der_256, *keySz);
                XMEMCPY(cert, cliecc_cert_der_256, *certSz);
            #else
                ExpectTrue((fp = XFOPEN(cliEccKey, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *keySz = (word32)XFREAD(key, 1, *keySz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*keySz, 0);

                ExpectTrue((fp = XFOPEN(cliEccCert, "rb")) != XBADFILE);
                if (fp != XBADFILE) {
                    *certSz = (word32)XFREAD(cert, 1, *certSz, fp);
                    XFCLOSE(fp);
                    fp = XBADFILE;
                }
                ExpectIntGT(*certSz, 0);
            #endif /* USE_CERT_BUFFERS_256 */
            }
            break;
#endif /* HAVE_ECC */
        default:
            WOLFSSL_MSG("Unsupported SignedData PK type");
            ret = BAD_FUNC_ARG;
            break;
    }

    if (EXPECT_FAIL() && (ret == 0)) {
        ret = BAD_FUNC_ARG;
    }
    return ret;
}

/**
 * Creates a PKCS7/CMS SignedData bundle to use for testing.
 *
 * output          output buffer to place SignedData
 * outputSz        size of output buffer
 * data            data buffer to be signed
 * dataSz          size of data buffer
 * withAttribs     [1/0] include attributes in SignedData message
 * detachedSig     [1/0] create detached signature, no content
 * useIntCertChain [1/0] use certificate chain and include intermediate and
 *                 root CAs in bundle
 * pkAlgoType      RSA_TYPE or ECC_TYPE, choose what key/cert type to use
 *
 * Return size of bundle created on success, negative on error */
int CreatePKCS7SignedData(unsigned char* output, int outputSz,
                          byte* data, word32 dataSz,
                          int withAttribs, int detachedSig,
                          int useIntermediateCertChain,
                          int pkAlgoType)
{
    EXPECT_DECLS;
    int ret = 0;
    WC_RNG rng;
    PKCS7* pkcs7 = NULL;

    static byte messageTypeOid[] =
               { 0x06, 0x0a, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01,
                 0x09, 0x02 };
    static byte messageType[] = { 0x13, 2, '1', '9' };

    PKCS7Attrib attribs[] =
    {
        { messageTypeOid, sizeof(messageTypeOid), messageType,
                                       sizeof(messageType) }
    };

    byte intCARoot[TWOK_BUF];
    byte intCA1[TWOK_BUF];
    byte intCA2[TWOK_BUF];
    byte cert[TWOK_BUF];
    byte key[TWOK_BUF];

    word32 intCARootSz = sizeof(intCARoot);
    word32 intCA1Sz    = sizeof(intCA1);
    word32 intCA2Sz    = sizeof(intCA2);
    word32 certSz      = sizeof(cert);
    word32 keySz       = sizeof(key);

    XMEMSET(intCARoot, 0, intCARootSz);
    XMEMSET(intCA1, 0, intCA1Sz);
    XMEMSET(intCA2, 0, intCA2Sz);
    XMEMSET(cert, 0, certSz);
    XMEMSET(key, 0, keySz);

    ret = LoadPKCS7SignedDataCerts(useIntermediateCertChain, pkAlgoType,
                intCARoot, &intCARootSz, intCA1, &intCA1Sz, intCA2, &intCA2Sz,
                cert, &certSz, key, &keySz);
    ExpectIntEQ(ret, 0);

    XMEMSET(output, 0, outputSz);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, certSz), 0);

    if (useIntermediateCertChain == 1) {
        /* Add intermediate and root CA certs into SignedData Certs SET */
        ExpectIntEQ(wc_PKCS7_AddCertificate(pkcs7, intCA2, intCA2Sz), 0);
        ExpectIntEQ(wc_PKCS7_AddCertificate(pkcs7, intCA1, intCA1Sz), 0);
        ExpectIntEQ(wc_PKCS7_AddCertificate(pkcs7, intCARoot, intCARootSz), 0);
    }

    if (pkcs7 != NULL) {
        pkcs7->content = data;
        pkcs7->contentSz = dataSz;
        pkcs7->privateKey = key;
        pkcs7->privateKeySz = (word32)sizeof(key);
        if (pkAlgoType == RSA_TYPE) {
            pkcs7->encryptOID = RSAk;
        }
        else {
            pkcs7->encryptOID = ECDSAk;
        }
    #ifdef NO_SHA
        pkcs7->hashOID = SHA256h;
    #else
        pkcs7->hashOID = SHAh;
    #endif
        pkcs7->rng = &rng;
        if (withAttribs) {
            /* include a signed attribute */
            pkcs7->signedAttribs   = attribs;
            pkcs7->signedAttribsSz = (sizeof(attribs)/sizeof(PKCS7Attrib));
        }
    }

    if (detachedSig) {
        ExpectIntEQ(wc_PKCS7_SetDetached(pkcs7, 1), 0);
    }

    outputSz = wc_PKCS7_EncodeSignedData(pkcs7, output, (word32)outputSz);
    ExpectIntGT(outputSz, 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    if (detachedSig && (pkcs7 != NULL)) {
        pkcs7->content = data;
        pkcs7->contentSz = dataSz;
    }
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, (word32)outputSz), 0);

    wc_PKCS7_Free(pkcs7);
    wc_FreeRng(&rng);

    if (EXPECT_FAIL()) {
        outputSz = 0;
    }
    return outputSz;
}
#endif

/*
 * Testing wc_PKCS_VerifySignedData()
 */
int test_wc_PKCS7_VerifySignedData_RSA(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    PKCS7* pkcs7 = NULL;
    byte   output[6000]; /* Large size needed for bundles with int CA certs */
    word32 outputSz = sizeof(output);
    byte   data[] = "Test data to encode.";
    byte   badOut[1];
    word32 badOutSz = 0;
    byte   badContent[] = "This is different content than was signed";
    wc_HashAlg hash;
#ifdef NO_SHA
    enum wc_HashType hashType = WC_HASH_TYPE_SHA256;
#else
    enum wc_HashType hashType = WC_HASH_TYPE_SHA;
#endif
    byte        hashBuf[WC_MAX_DIGEST_SIZE];
    word32      hashSz = (word32)wc_HashGetDigestSize(hashType);
#ifndef NO_RSA
    PKCS7DecodedAttrib* decodedAttrib = NULL;
    /* contentType OID (1.2.840.113549.1.9.3) */
    static const byte contentTypeOid[] =
        { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0d, 0x01, 0x09, 0x03 };

    /* PKCS#7 DATA content type (contentType defaults to DATA) */
    static const byte dataType[] =
        { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };

    /* messageDigest OID (1.2.840.113549.1.9.4) */
    static const byte messageDigestOid[] =
        { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04 };
#ifndef NO_ASN_TIME
    /* signingTime OID () */
    static const byte signingTimeOid[] =
        { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05};
#endif
#if !defined(NO_ASN) && !defined(NO_ASN_TIME)
    int dateLength = 0;
    byte dateFormat;
    const byte* datePart = NULL;
    struct tm timearg;
    time_t now;
    struct tm* nowTm = NULL;
#ifdef NEED_TMP_TIME
    struct tm tmpTimeStorage;
    struct tm* tmpTime = &tmpTimeStorage;
#endif
#endif /* !NO_ASN && !NO_ASN_TIME */
#ifndef NO_PKCS7_STREAM
    word32 z;
    int ret;
#endif /* !NO_PKCS7_STREAM */

    XMEMSET(&hash, 0, sizeof(wc_HashAlg));

    /* Success test with RSA certs/key */
    ExpectIntGT((outputSz = (word32)CreatePKCS7SignedData(output, (int)outputSz, data,
        (word32)sizeof(data), 0, 0, 0, RSA_TYPE)), 0);

    /* calculate hash for content, used later */
    ExpectIntEQ(wc_HashInit(&hash, hashType), 0);
    ExpectIntEQ(wc_HashUpdate(&hash, hashType, data, sizeof(data)), 0);
    ExpectIntEQ(wc_HashFinal(&hash, hashType, hashBuf), 0);
    DoExpectIntEQ(wc_HashFree(&hash, hashType), 0);

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, outputSz), 0);

#ifndef NO_PKCS7_STREAM
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

    /* test for streaming */
    ret = -1;
    for (z = 0; z < outputSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, output + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
    ExpectIntNE(pkcs7->contentSz, 0);
    ExpectNotNull(pkcs7->contentDynamic);
#endif /* !NO_PKCS7_STREAM */

    /* Check that decoded signed attributes are correct */

    /* messageDigest should be first */
    if (pkcs7 != NULL) {
        decodedAttrib = pkcs7->decodedAttrib;
    }
    ExpectNotNull(decodedAttrib);
    ExpectIntEQ(decodedAttrib->oidSz, (word32)sizeof(messageDigestOid));
    ExpectIntEQ(XMEMCMP(decodedAttrib->oid, messageDigestOid,
        decodedAttrib->oidSz), 0);
    /* + 2 for OCTET STRING and length bytes */
    ExpectIntEQ(decodedAttrib->valueSz, hashSz + 2);
    ExpectNotNull(decodedAttrib->value);
    ExpectIntEQ(XMEMCMP(decodedAttrib->value + 2, hashBuf, hashSz), 0);

#ifndef NO_ASN_TIME
    /* signingTime should be second */
    if (decodedAttrib != NULL) {
        decodedAttrib = decodedAttrib->next;
    }
    ExpectNotNull(decodedAttrib);
    ExpectIntEQ(decodedAttrib->oidSz, (word32)sizeof(signingTimeOid));
    ExpectIntEQ(XMEMCMP(decodedAttrib->oid, signingTimeOid,
        decodedAttrib->oidSz), 0);

    ExpectIntGT(decodedAttrib->valueSz, 0);
    ExpectNotNull(decodedAttrib->value);
#endif

    /* Verify signingTime if ASN and time are available */
#if !defined(NO_ASN) && !defined(NO_ASN_TIME)
    ExpectIntEQ(wc_GetDateInfo(decodedAttrib->value, decodedAttrib->valueSz,
        &datePart, &dateFormat, &dateLength), 0);
    ExpectNotNull(datePart);
    ExpectIntGT(dateLength, 0);
    XMEMSET(&timearg, 0, sizeof(timearg));
    ExpectIntEQ(wc_GetDateAsCalendarTime(datePart, dateLength, dateFormat,
         &timearg), 0);

    /* Get current time and compare year/month/day against attribute value */
    ExpectIntEQ(wc_GetTime(&now, sizeof(now)), 0);
    nowTm = (struct tm*)XGMTIME((time_t*)&now, tmpTime);
    ExpectNotNull(nowTm);

    ExpectIntEQ(timearg.tm_year, nowTm->tm_year);
    ExpectIntEQ(timearg.tm_mon, nowTm->tm_mon);
    ExpectIntEQ(timearg.tm_mday, nowTm->tm_mday);
#endif /* !NO_ASN && !NO_ASN_TIME */

    /* contentType should be third */
    if (decodedAttrib != NULL) {
        decodedAttrib = decodedAttrib->next;
    }
    ExpectNotNull(decodedAttrib);
    ExpectIntEQ(decodedAttrib->oidSz, (word32)sizeof(contentTypeOid));
    ExpectIntEQ(XMEMCMP(decodedAttrib->oid, contentTypeOid,
        decodedAttrib->oidSz), 0);
    ExpectIntEQ(decodedAttrib->valueSz, (int)sizeof(dataType) + 2);
    ExpectNotNull(decodedAttrib->value);
    ExpectIntEQ(XMEMCMP(decodedAttrib->value + 2, dataType, sizeof(dataType)),
        0);
#endif /* !NO_RSA */

    /* Test bad args. */
    ExpectIntEQ(wc_PKCS7_VerifySignedData(NULL, output, outputSz),
                                          WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, NULL, outputSz),
                                          WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #ifndef NO_PKCS7_STREAM
        /* can pass in 0 buffer length with streaming API */
        ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, badOut,
                                    badOutSz), WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
    #else
        ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, badOut,
                                    badOutSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #endif
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifndef NO_RSA
    /* Try RSA certs/key/sig first */
    outputSz = sizeof(output);
    XMEMSET(output, 0, outputSz);
    ExpectIntGT((outputSz = (word32)CreatePKCS7SignedData(output, (int)outputSz, data,
                                                  (word32)sizeof(data),
                                                  1, 1, 0, RSA_TYPE)), 0);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    if (pkcs7 != NULL) {
        pkcs7->content = badContent;
        pkcs7->contentSz = sizeof(badContent);
    }
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, outputSz),
                WC_NO_ERR_TRACE(SIG_VERIFY_E));

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifndef NO_PKCS7_STREAM
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    if (pkcs7 != NULL) {
        pkcs7->content = badContent;
        pkcs7->contentSz = sizeof(badContent);
    }
    /* test for streaming */
    ret = -1;
    for (z = 0; z < outputSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, output + z, 1);
        if (ret == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)){
            continue;
        }
        else if (ret < 0) {
            break;
        }
    }
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(SIG_VERIFY_E));
    ExpectIntNE(pkcs7->contentSz, 0);
    ExpectNotNull(pkcs7->contentDynamic);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
#endif /* !NO_PKCS7_STREAM */


    /* Test success case with detached signature and valid content */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    if (pkcs7 != NULL) {
        pkcs7->content = data;
        pkcs7->contentSz = sizeof(data);
    }
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, outputSz), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifndef NO_PKCS7_STREAM
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    if (pkcs7 != NULL) {
        pkcs7->content = data;
        pkcs7->contentSz = sizeof(data);
    }

    /* test for streaming */
    ret = -1;
    for (z = 0; z < outputSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, output + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
    ExpectIntNE(pkcs7->contentSz, 0);
    ExpectNotNull(pkcs7->contentDynamic);

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
#endif /* !NO_PKCS7_STREAM */

    /* verify using pre-computed content digest only (no content) */
    {
        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_Init(pkcs7, NULL, 0), 0);
        ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, hashSz,
            output, outputSz, NULL, 0), 0);
        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;
    }
#endif /* !NO_RSA */

    /* Test verify on signedData containing intermediate/root CA certs */
#ifndef NO_RSA
    outputSz = sizeof(output);
    XMEMSET(output, 0, outputSz);
    ExpectIntGT((outputSz = (word32)CreatePKCS7SignedData(output, (int)outputSz, data,
                                                  (word32)sizeof(data),
                                                  0, 0, 1, RSA_TYPE)), 0);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, outputSz), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifndef NO_PKCS7_STREAM
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

    /* test for streaming */
    ret = -1;
    for (z = 0; z < outputSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, output + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
    ExpectIntNE(pkcs7->contentSz, 0);
    ExpectNotNull(pkcs7->contentDynamic);

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
#endif /* !NO_PKCS7_STREAM */

#endif /* !NO_RSA */
#if defined(ASN_BER_TO_DER) && !defined(NO_PKCS7_STREAM) && \
        !defined(NO_FILESYSTEM)
    {
        XFILE signedBundle = XBADFILE;
        int   signedBundleSz = 0;
        int   chunkSz = 1;
        int   i, rc = 0;
        byte* buf = NULL;

        ExpectTrue((signedBundle = XFOPEN("./certs/test-stream-sign.p7b",
            "rb")) != XBADFILE);
        ExpectTrue(XFSEEK(signedBundle, 0, XSEEK_END) == 0);
        ExpectIntGT(signedBundleSz = (int)XFTELL(signedBundle), 0);
        ExpectTrue(XFSEEK(signedBundle, 0, XSEEK_SET) == 0);
        ExpectNotNull(buf = (byte*)XMALLOC(signedBundleSz, HEAP_HINT,
            DYNAMIC_TYPE_FILE));
        if (buf != NULL) {
            ExpectIntEQ(XFREAD(buf, 1, (size_t)signedBundleSz, signedBundle),
                signedBundleSz);
        }
        if (signedBundle != XBADFILE) {
            XFCLOSE(signedBundle);
            signedBundle = XBADFILE;
        }

        if (buf != NULL) {
            ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
            ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
            for (i = 0; i < signedBundleSz;) {
                int sz = (i + chunkSz > signedBundleSz)? signedBundleSz - i :
                    chunkSz;
                rc = wc_PKCS7_VerifySignedData(pkcs7, buf + i, (word32)sz);
                if (rc < 0 ) {
                    if (rc == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
                        i += sz;
                        continue;
                    }
                    break;
                }
                else {
                    break;
                }
            }
            ExpectIntEQ(rc, WC_NO_ERR_TRACE(PKCS7_SIGNEEDS_CHECK));
            wc_PKCS7_Free(pkcs7);
            pkcs7 = NULL;
        }

        /* now try with malformed bundle */
        if (buf != NULL) {
            ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
            ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
            buf[signedBundleSz - 2] = buf[signedBundleSz - 2] + 1;
            for (i = 0; i < signedBundleSz;) {
                int sz = (i + chunkSz > signedBundleSz)? signedBundleSz - i :
                    chunkSz;
                rc = wc_PKCS7_VerifySignedData(pkcs7, buf + i, (word32)sz);
                if (rc < 0 ) {
                    if (rc == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
                        i += sz;
                        continue;
                    }
                    break;
                }
                else {
                    break;
                }
            }
            ExpectIntEQ(rc, WC_NO_ERR_TRACE(ASN_PARSE_E));
            wc_PKCS7_Free(pkcs7);
            pkcs7 = NULL;
        }

        if (buf != NULL)
            XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_FILE);
    }
#endif /* BER and stream */
#endif
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_VerifySignedData()_RSA */

/*
 * Testing wc_PKCS_VerifySignedData()
 */
int test_wc_PKCS7_VerifySignedData_ECC(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && defined(HAVE_ECC)
    PKCS7* pkcs7 = NULL;
    byte   output[6000]; /* Large size needed for bundles with int CA certs */
    word32 outputSz = sizeof(output);
    byte   data[] = "Test data to encode.";
    byte   badContent[] = "This is different content than was signed";
    wc_HashAlg hash;
#ifndef NO_PKCS7_STREAM
    word32 z;
    int ret;
#endif /* !NO_PKCS7_STREAM */
#ifdef NO_SHA
    enum wc_HashType hashType = WC_HASH_TYPE_SHA256;
#else
    enum wc_HashType hashType = WC_HASH_TYPE_SHA;
#endif
    byte        hashBuf[WC_MAX_DIGEST_SIZE];
    word32      hashSz = (word32)wc_HashGetDigestSize(hashType);

    XMEMSET(&hash, 0, sizeof(wc_HashAlg));

    /* Success test with ECC certs/key */
    outputSz = sizeof(output);
    XMEMSET(output, 0, outputSz);
    ExpectIntGT((outputSz = (word32)CreatePKCS7SignedData(output, (int)outputSz, data,
        (word32)sizeof(data), 0, 0, 0, ECC_TYPE)), 0);

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, outputSz), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifndef NO_PKCS7_STREAM
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

    /* test for streaming */
    ret = -1;
    for (z = 0; z < outputSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, output + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
    ExpectIntNE(pkcs7->contentSz, 0);
    ExpectNotNull(pkcs7->contentDynamic);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
#endif /* !NO_PKCS7_STREAM */

    /* Invalid content should error, use detached signature so we can
     * easily change content */
    outputSz = sizeof(output);
    XMEMSET(output, 0, outputSz);
    ExpectIntGT((outputSz = (word32)CreatePKCS7SignedData(output, (int)outputSz, data,
        (word32)sizeof(data), 1, 1, 0, ECC_TYPE)), 0);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    if (pkcs7 != NULL) {
        pkcs7->content = badContent;
        pkcs7->contentSz = sizeof(badContent);
    }
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, outputSz),
        WC_NO_ERR_TRACE(SIG_VERIFY_E));
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifndef NO_PKCS7_STREAM
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    if (pkcs7 != NULL) {
        pkcs7->content = badContent;
        pkcs7->contentSz = sizeof(badContent);
    }

    /* test for streaming */
    ret = -1;
    for (z = 0; z < outputSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, output + z, 1);
        if (ret == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)){
            continue;
        }
        else if (ret < 0) {
            break;
        }
    }
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(SIG_VERIFY_E));
    ExpectIntNE(pkcs7->contentSz, 0);
    ExpectNotNull(pkcs7->contentDynamic);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
#endif /* !NO_PKCS7_STREAM */


    /* Test success case with detached signature and valid content */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    if (pkcs7 != NULL) {
        pkcs7->content = data;
        pkcs7->contentSz = sizeof(data);
    }
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, outputSz), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifndef NO_PKCS7_STREAM
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    if (pkcs7 != NULL) {
        pkcs7->content = data;
        pkcs7->contentSz = sizeof(data);
    }

    /* test for streaming */
    ret = -1;
    for (z = 0; z < outputSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, output + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
    ExpectIntNE(pkcs7->contentSz, 0);
    ExpectNotNull(pkcs7->contentDynamic);

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
#endif /* !NO_PKCS7_STREAM */

    /* verify using pre-computed content digest only (no content) */
    {
        /* calculate hash for content */
        ExpectIntEQ(wc_HashInit(&hash, hashType), 0);
        ExpectIntEQ(wc_HashUpdate(&hash, hashType, data, sizeof(data)), 0);
        ExpectIntEQ(wc_HashFinal(&hash, hashType, hashBuf), 0);
        ExpectIntEQ(wc_HashFree(&hash, hashType), 0);

        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_Init(pkcs7, NULL, 0), 0);
        ExpectIntEQ(wc_PKCS7_VerifySignedData_ex(pkcs7, hashBuf, hashSz,
            output, outputSz, NULL, 0), 0);
        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;
    }

    /* Test verify on signedData containing intermediate/root CA certs */
    outputSz = sizeof(output);
    XMEMSET(output, 0, outputSz);
    ExpectIntGT((outputSz = (word32)CreatePKCS7SignedData(output, (int)outputSz, data,
        (word32)sizeof(data), 0, 0, 1, ECC_TYPE)), 0);
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, output, outputSz), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifndef NO_PKCS7_STREAM
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

    /* test for streaming */
    ret = -1;
    for (z = 0; z < outputSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, output + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
    ExpectIntNE(pkcs7->contentSz, 0);
    ExpectNotNull(pkcs7->contentDynamic);

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
#endif /* !NO_PKCS7_STREAM */

#endif
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_VerifySignedData_ECC() */


#if defined(HAVE_PKCS7) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_256) && defined(HAVE_AES_KEYWRAP)
static const byte defKey[] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
};
static byte aesHandle[32]; /* simulated hardware key handle */


/* return 0 on success */
static int myDecryptionFunc(PKCS7* pkcs7, int encryptOID, byte* iv, int ivSz,
        byte* aad, word32 aadSz, byte* authTag, word32 authTagSz,
        byte* in, int inSz, byte* out, void* usrCtx)
{
    int ret;
    Aes aes;

    if (usrCtx == NULL) {
        /* no simulated handle passed in */
        return -1;
    }

    switch (encryptOID) {
        case AES256CBCb:
            if (ivSz  != AES_BLOCK_SIZE)
                return BAD_FUNC_ARG;
            break;

        default:
            WOLFSSL_MSG("Unsupported content cipher type for test");
            return ALGO_ID_E;
    };

    /* simulate using handle to get key */
    ret = wc_AesInit(&aes, HEAP_HINT, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, (byte*)usrCtx, 32, iv, AES_DECRYPTION);
        if (ret == 0)
            ret = wc_AesCbcDecrypt(&aes, out, in, (word32)inSz);
        wc_AesFree(&aes);
    }

    (void)aad;
    (void)aadSz;
    (void)authTag;
    (void)authTagSz;
    (void)pkcs7;
    return ret;
}


/* returns key size on success */
static int myCEKwrapFunc(PKCS7* pkcs7, byte* cek, word32 cekSz, byte* keyId,
        word32 keyIdSz, byte* orginKey, word32 orginKeySz,
        byte* out, word32 outSz, int keyWrapAlgo, int type, int direction)
{
    int ret = -1;

    (void)cekSz;
    (void)cek;
    (void)outSz;
    (void)keyIdSz;
    (void)direction;
    (void)orginKey; /* used with KAKRI */
    (void)orginKeySz;

    if (out == NULL)
        return BAD_FUNC_ARG;

    if (keyId[0] != 0x00) {
        return -1;
    }

    if (type != (int)PKCS7_KEKRI) {
        return -1;
    }

    switch (keyWrapAlgo) {
        case AES256_WRAP:
            /* simulate setting a handle for later decryption but use key
             * as handle in the test case here */
            ret = wc_AesKeyUnWrap(defKey, sizeof(defKey), cek, cekSz,
                                      aesHandle, sizeof(aesHandle), NULL);
            if (ret < 0)
                return ret;

            ret = wc_PKCS7_SetDecodeEncryptedCtx(pkcs7, (void*)aesHandle);
            if (ret < 0)
                return ret;

            /* return key size on success */
            return sizeof(defKey);

        default:
            WOLFSSL_MSG("Unsupported key wrap algorithm in example");
            return BAD_KEYWRAP_ALG_E;
    };
}
#endif /* HAVE_PKCS7 && !NO_AES && HAVE_AES_CBC && WOLFSSL_AES_256 &&
          HAVE_AES_KEYWRAP */


#if defined(HAVE_PKCS7) && defined(ASN_BER_TO_DER)
#define MAX_TEST_DECODE_SIZE 6000
static int test_wc_PKCS7_DecodeEnvelopedData_stream_decrypt_cb(wc_PKCS7* pkcs7,
    const byte* output, word32 outputSz, void* ctx) {
     WOLFSSL_BUFFER_INFO* out = (WOLFSSL_BUFFER_INFO*)ctx;

    if (out == NULL) {
        return -1;
    }

    if (outputSz + out->length > MAX_TEST_DECODE_SIZE) {
        printf("Example buffer size needs increased");
    }

    /* printf("Decoded in %d bytes\n", outputSz);
     * for (word32 z = 0; z < outputSz; z++) printf("%02X", output[z]);
     * printf("\n");
    */

    XMEMCPY(out->buffer + out->length, output, outputSz);
    out->length += outputSz;

    (void)pkcs7;
    return 0;
}
#endif /* HAVE_PKCS7 && ASN_BER_TO_DER */

/*
 * Testing wc_PKCS7_DecodeEnvelopedData with streaming
 */
int test_wc_PKCS7_DecodeEnvelopedData_stream(void)
{
#if defined(HAVE_PKCS7) && defined(ASN_BER_TO_DER)
    EXPECT_DECLS;
    PKCS7*      pkcs7 = NULL;
    int ret = 0;
    XFILE f = XBADFILE;
    const char* testStream = "./certs/test-stream-dec.p7b";
    byte testStreamBuffer[100];
    size_t testStreamBufferSz = 0;
    byte decodedData[MAX_TEST_DECODE_SIZE]; /* large enough to hold result of decode, which is ca-cert.pem */
    WOLFSSL_BUFFER_INFO out;

    out.length = 0;
    out.buffer = decodedData;

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte*)client_cert_der_2048,
        sizeof_client_cert_der_2048), 0);

    ExpectIntEQ(wc_PKCS7_SetKey(pkcs7, (byte*)client_key_der_2048,
        sizeof_client_key_der_2048), 0);
    ExpectIntEQ(wc_PKCS7_SetStreamMode(pkcs7, 1, NULL,
        test_wc_PKCS7_DecodeEnvelopedData_stream_decrypt_cb, (void*)&out), 0);

    ExpectTrue((f = XFOPEN(testStream, "rb")) != XBADFILE);
    if (EXPECT_SUCCESS()) {
        do {
            testStreamBufferSz = XFREAD(testStreamBuffer, 1,
                sizeof(testStreamBuffer), f);
            if (testStreamBufferSz == 0) {
                break;
            }

            ret = wc_PKCS7_DecodeEnvelopedData(pkcs7, testStreamBuffer,
                (word32)testStreamBufferSz, NULL, 0);
            if (testStreamBufferSz < sizeof(testStreamBuffer)) {
                break;
            }
        } while (ret == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
    #ifdef NO_DES3
        ExpectIntEQ(ret, ALGO_ID_E);
    #else
        ExpectIntGT(ret, 0);
    #endif
    }

    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    wc_PKCS7_Free(pkcs7);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
} /* END test_wc_PKCS7_DecodeEnvelopedData_stream() */

/*
 * Testing wc_PKCS7_EncodeEnvelopedData(), wc_PKCS7_DecodeEnvelopedData()
 */
int test_wc_PKCS7_EncodeDecodeEnvelopedData(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7)
    PKCS7*      pkcs7 = NULL;
#ifdef ASN_BER_TO_DER
    int encodedSz = 0;
#endif
#ifdef ECC_TIMING_RESISTANT
    WC_RNG      rng;
#endif
#ifdef HAVE_AES_KEYWRAP
    word32      tempWrd32   = 0;
    byte*       tmpBytePtr = NULL;
#endif
    const char  input[] = "Test data to encode.";
    int         i;
    int         testSz = 0;
    #if !defined(NO_RSA) && (!defined(NO_AES) || (!defined(NO_SHA) || \
        !defined(NO_SHA256) || defined(WOLFSSL_SHA512)))
        byte*   rsaCert     = NULL;
        byte*   rsaPrivKey  = NULL;
        word32  rsaCertSz;
        word32  rsaPrivKeySz;
        #if !defined(NO_FILESYSTEM) && (!defined(USE_CERT_BUFFERS_1024) && \
                                           !defined(USE_CERT_BUFFERS_2048) )
            static const char* rsaClientCert = "./certs/client-cert.der";
            static const char* rsaClientKey = "./certs/client-key.der";
            rsaCertSz = (word32)sizeof(rsaClientCert);
            rsaPrivKeySz = (word32)sizeof(rsaClientKey);
        #endif
    #endif
    #if defined(HAVE_ECC) && defined(HAVE_X963_KDF) && (!defined(NO_AES) || \
            !defined(NO_SHA) || !defined(NO_SHA256) || defined(WOLFSSL_SHA512))
        byte*   eccCert     = NULL;
        byte*   eccPrivKey  = NULL;
        word32  eccCertSz;
        word32  eccPrivKeySz;
        #if !defined(NO_FILESYSTEM) && !defined(USE_CERT_BUFFERS_256)
            static const char* eccClientCert = "./certs/client-ecc-cert.der";
            static const char* eccClientKey = "./certs/ecc-client-key.der";
        #endif
    #endif
    /* Generic buffer size. */
    byte    output[ONEK_BUF];
    byte    decoded[sizeof(input)/sizeof(char)];
    int     decodedSz = 0;
#ifndef NO_FILESYSTEM
    XFILE certFile = XBADFILE;
    XFILE keyFile = XBADFILE;
#endif

#ifdef ECC_TIMING_RESISTANT
    XMEMSET(&rng, 0, sizeof(WC_RNG));
#endif

#if !defined(NO_RSA) && (!defined(NO_AES) || (!defined(NO_SHA) ||\
    !defined(NO_SHA256) || defined(WOLFSSL_SHA512)))
    /* RSA certs and keys. */
    #if defined(USE_CERT_BUFFERS_1024)
        rsaCertSz = (word32)sizeof_client_cert_der_1024;
        /* Allocate buffer space. */
        ExpectNotNull(rsaCert = (byte*)XMALLOC(rsaCertSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        /* Init buffer. */
        if (rsaCert != NULL) {
            XMEMCPY(rsaCert, client_cert_der_1024, rsaCertSz);
        }
        rsaPrivKeySz = (word32)sizeof_client_key_der_1024;
        ExpectNotNull(rsaPrivKey = (byte*)XMALLOC(rsaPrivKeySz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        if (rsaPrivKey != NULL) {
            XMEMCPY(rsaPrivKey, client_key_der_1024, rsaPrivKeySz);
        }
    #elif defined(USE_CERT_BUFFERS_2048)
        rsaCertSz = (word32)sizeof_client_cert_der_2048;
        /* Allocate buffer */
        ExpectNotNull(rsaCert = (byte*)XMALLOC(rsaCertSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        /* Init buffer. */
        if (rsaCert != NULL) {
            XMEMCPY(rsaCert, client_cert_der_2048, rsaCertSz);
        }
        rsaPrivKeySz = (word32)sizeof_client_key_der_2048;
        ExpectNotNull(rsaPrivKey = (byte*)XMALLOC(rsaPrivKeySz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        if (rsaPrivKey != NULL) {
            XMEMCPY(rsaPrivKey, client_key_der_2048, rsaPrivKeySz);
        }
    #else
        /* File system. */
        ExpectTrue((certFile = XFOPEN(rsaClientCert, "rb")) != XBADFILE);
        rsaCertSz = (word32)FOURK_BUF;
        ExpectNotNull(rsaCert = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        ExpectTrue((rsaCertSz = (word32)XFREAD(rsaCert, 1, rsaCertSz,
            certFile)) > 0);
        if (certFile != XBADFILE)
            XFCLOSE(certFile);
        ExpectTrue((keyFile = XFOPEN(rsaClientKey, "rb")) != XBADFILE);
        ExpectNotNull(rsaPrivKey = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        rsaPrivKeySz = (word32)FOURK_BUF;
        ExpectTrue((rsaPrivKeySz = (word32)XFREAD(rsaPrivKey, 1, rsaPrivKeySz,
            keyFile)) > 0);
        if (keyFile != XBADFILE)
            XFCLOSE(keyFile);
    #endif /* USE_CERT_BUFFERS */
#endif /* NO_RSA */

/* ECC */
#if defined(HAVE_ECC) && defined(HAVE_X963_KDF) && (!defined(NO_AES) || \
        !defined(NO_SHA) || !defined(NO_SHA256) || defined(WOLFSSL_SHA512))

    #ifdef USE_CERT_BUFFERS_256
        ExpectNotNull(eccCert = (byte*)XMALLOC(TWOK_BUF, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        /* Init buffer. */
        eccCertSz = (word32)sizeof_cliecc_cert_der_256;
        if (eccCert != NULL) {
            XMEMCPY(eccCert, cliecc_cert_der_256, eccCertSz);
        }
        ExpectNotNull(eccPrivKey = (byte*)XMALLOC(TWOK_BUF, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        eccPrivKeySz = (word32)sizeof_ecc_clikey_der_256;
        if (eccPrivKey != NULL) {
            XMEMCPY(eccPrivKey, ecc_clikey_der_256, eccPrivKeySz);
        }
    #else /* File system. */
        ExpectTrue((certFile = XFOPEN(eccClientCert, "rb")) != XBADFILE);
        eccCertSz = (word32)FOURK_BUF;
        ExpectNotNull(eccCert = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        ExpectTrue((eccCertSz = (word32)XFREAD(eccCert, 1, eccCertSz,
            certFile)) > 0);
        if (certFile != XBADFILE) {
            XFCLOSE(certFile);
        }
        ExpectTrue((keyFile = XFOPEN(eccClientKey, "rb")) != XBADFILE);
        eccPrivKeySz = (word32)FOURK_BUF;
        ExpectNotNull(eccPrivKey = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        ExpectTrue((eccPrivKeySz = (word32)XFREAD(eccPrivKey, 1, eccPrivKeySz,
            keyFile)) > 0);
        if (keyFile != XBADFILE) {
            XFCLOSE(keyFile);
        }
    #endif /* USE_CERT_BUFFERS_256 */
#endif /* END HAVE_ECC */

#ifndef NO_FILESYSTEM
    /* Silence. */
    (void)keyFile;
    (void)certFile;
#endif

    {
    const pkcs7EnvelopedVector testVectors[] = {
    /* DATA is a global variable defined in the makefile. */
#if !defined(NO_RSA)
    #ifndef NO_DES3
        {(byte*)input, (word32)(sizeof(input)/sizeof(char)), DATA, DES3b, 0, 0,
            rsaCert, rsaCertSz, rsaPrivKey, rsaPrivKeySz},
    #endif /* NO_DES3 */
    #if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(HAVE_AES_KEYWRAP)
        #ifdef WOLFSSL_AES_128
        {(byte*)input, (word32)(sizeof(input)/sizeof(char)), DATA, AES128CBCb,
            0, 0, rsaCert, rsaCertSz, rsaPrivKey, rsaPrivKeySz},
        #endif
        #ifdef WOLFSSL_AES_192
        {(byte*)input, (word32)(sizeof(input)/sizeof(char)), DATA, AES192CBCb,
            0, 0, rsaCert, rsaCertSz, rsaPrivKey, rsaPrivKeySz},
        #endif
        #ifdef WOLFSSL_AES_256
        {(byte*)input, (word32)(sizeof(input)/sizeof(char)), DATA, AES256CBCb,
            0, 0, rsaCert, rsaCertSz, rsaPrivKey, rsaPrivKeySz},
        #endif
    #endif /* NO_AES && HAVE_AES_CBC */

#endif /* NO_RSA */
#if defined(HAVE_ECC) && defined(HAVE_X963_KDF)
    #if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(HAVE_AES_KEYWRAP)
        #if !defined(NO_SHA) && defined(WOLFSSL_AES_128)
            {(byte*)input, (word32)(sizeof(input)/sizeof(char)), DATA,
                AES128CBCb, AES128_WRAP, dhSinglePass_stdDH_sha1kdf_scheme,
                eccCert, eccCertSz, eccPrivKey, eccPrivKeySz},
        #endif
        #if !defined(NO_SHA256) && defined(WOLFSSL_AES_256)
            {(byte*)input, (word32)(sizeof(input)/sizeof(char)), DATA,
                AES256CBCb, AES256_WRAP, dhSinglePass_stdDH_sha256kdf_scheme,
                eccCert, eccCertSz, eccPrivKey, eccPrivKeySz},
        #endif
        #if defined(WOLFSSL_SHA512) && defined(WOLFSSL_AES_256)
            {(byte*)input, (word32)(sizeof(input)/sizeof(char)), DATA,
                AES256CBCb, AES256_WRAP, dhSinglePass_stdDH_sha512kdf_scheme,
                eccCert, eccCertSz, eccPrivKey, eccPrivKeySz},
        #endif
    #endif /* NO_AES && HAVE_AES_CBC && HAVE_AES_KEYWRAP */
#endif /* END HAVE_ECC */
    }; /* END pkcs7EnvelopedVector */

#ifdef ECC_TIMING_RESISTANT
    ExpectIntEQ(wc_InitRng(&rng), 0);
#endif

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, testDevId), 0);

    testSz = (int)sizeof(testVectors)/(int)sizeof(pkcs7EnvelopedVector);
    for (i = 0; i < testSz; i++) {
    #ifdef ASN_BER_TO_DER
        encodeSignedDataStream strm;

        /* test setting stream mode, the first one using IO callbacks */
        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (testVectors + i)->cert,
                                    (word32)(testVectors + i)->certSz), 0);
        if (pkcs7 != NULL) {
        #ifdef ECC_TIMING_RESISTANT
            pkcs7->rng = &rng;
        #endif

            if (i != 0)
                pkcs7->content       = (byte*)(testVectors + i)->content;
            pkcs7->contentSz     = (testVectors + i)->contentSz;
            pkcs7->contentOID    = (testVectors + i)->contentOID;
            pkcs7->encryptOID    = (testVectors + i)->encryptOID;
            pkcs7->keyWrapOID    = (testVectors + i)->keyWrapOID;
            pkcs7->keyAgreeOID   = (testVectors + i)->keyAgreeOID;
            pkcs7->privateKey    = (testVectors + i)->privateKey;
            pkcs7->privateKeySz  = (testVectors + i)->privateKeySz;
        }

        if (i == 0) {
            XMEMSET(&strm, 0, sizeof(strm));
            strm.chunkSz = FOURK_BUF;
            ExpectIntEQ(wc_PKCS7_SetStreamMode(pkcs7, 1, GetContentCB,
                StreamOutputCB, (void*)&strm), 0);
            encodedSz = wc_PKCS7_EncodeEnvelopedData(pkcs7, NULL, 0);
        }
        else {
            ExpectIntEQ(wc_PKCS7_SetStreamMode(pkcs7, 1, NULL, NULL, NULL), 0);
            encodedSz = wc_PKCS7_EncodeEnvelopedData(pkcs7, output,
                (word32)sizeof(output));
        }

        switch ((testVectors + i)->encryptOID) {
        #ifndef NO_DES3
            case DES3b:
            case DESb:
                ExpectIntEQ(encodedSz, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
                break;
        #endif
        #ifdef HAVE_AESCCM
        #ifdef WOLFSSL_AES_128
            case AES128CCMb:
                ExpectIntEQ(encodedSz, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
                break;
        #endif
        #ifdef WOLFSSL_AES_192
            case AES192CCMb:
                ExpectIntEQ(encodedSz, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
                break;
        #endif
        #ifdef WOLFSSL_AES_256
            case AES256CCMb:
                ExpectIntEQ(encodedSz, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
                break;
        #endif
        #endif
            default:
                ExpectIntGE(encodedSz, 0);
        }

        if (encodedSz > 0) {
            if (i == 0) {
                decodedSz = wc_PKCS7_DecodeEnvelopedData(pkcs7,
                    strm.out, (word32)encodedSz, decoded,
                    (word32)sizeof(decoded));
            }
            else {
                decodedSz = wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
                    (word32)encodedSz, decoded, (word32)sizeof(decoded));
            }
            ExpectIntGE(decodedSz, 0);
            /* Verify the size of each buffer. */
            ExpectIntEQ((word32)sizeof(input)/sizeof(char), decodedSz);
        }
        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;
        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    #endif

        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (testVectors + i)->cert,
                                    (word32)(testVectors + i)->certSz), 0);
        if (pkcs7 != NULL) {
#ifdef ECC_TIMING_RESISTANT
            pkcs7->rng = &rng;
#endif

            pkcs7->content       = (byte*)(testVectors + i)->content;
            pkcs7->contentSz     = (testVectors + i)->contentSz;
            pkcs7->contentOID    = (testVectors + i)->contentOID;
            pkcs7->encryptOID    = (testVectors + i)->encryptOID;
            pkcs7->keyWrapOID    = (testVectors + i)->keyWrapOID;
            pkcs7->keyAgreeOID   = (testVectors + i)->keyAgreeOID;
            pkcs7->privateKey    = (testVectors + i)->privateKey;
            pkcs7->privateKeySz  = (testVectors + i)->privateKeySz;
        }

    #ifdef ASN_BER_TO_DER
        /* test without setting stream mode */
        ExpectIntEQ(wc_PKCS7_GetStreamMode(pkcs7), 0);
    #endif

        ExpectIntGE(wc_PKCS7_EncodeEnvelopedData(pkcs7, output,
            (word32)sizeof(output)), 0);

        decodedSz = wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
            (word32)sizeof(output), decoded, (word32)sizeof(decoded));
        ExpectIntGE(decodedSz, 0);
        /* Verify the size of each buffer. */
        ExpectIntEQ((word32)sizeof(input)/sizeof(char), decodedSz);

        /* Don't free the last time through the loop. */
        if (i < testSz - 1) {
            wc_PKCS7_Free(pkcs7);
            pkcs7 = NULL;
            ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        }
    }  /* END test loop. */
    }

    /* Test bad args. */
    ExpectIntEQ(wc_PKCS7_EncodeEnvelopedData(NULL, output,
                    (word32)sizeof(output)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeEnvelopedData(pkcs7, NULL,
                    (word32)sizeof(output)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeEnvelopedData(pkcs7, output, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Decode.  */
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(NULL, output,
        (word32)sizeof(output), decoded, (word32)sizeof(decoded)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
        (word32)sizeof(output), NULL, (word32)sizeof(decoded)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
        (word32)sizeof(output), decoded, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, NULL,
        (word32)sizeof(output), decoded, (word32)sizeof(decoded)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, output, 0, decoded,
        (word32)sizeof(decoded)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Should get a return of BAD_FUNC_ARG with structure data. Order matters.*/
#if defined(HAVE_ECC) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(HAVE_AES_KEYWRAP) && defined(HAVE_X963_KDF)
    /* only a failure for KARI test cases */
    if (pkcs7 != NULL) {
        tempWrd32 = pkcs7->singleCertSz;
        pkcs7->singleCertSz = 0;
    }
    #if defined(WOLFSSL_ASN_TEMPLATE)
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
        (word32)sizeof(output), decoded, (word32)sizeof(decoded)),
        WC_NO_ERR_TRACE(BUFFER_E));
    #else
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
        (word32)sizeof(output), decoded, (word32)sizeof(decoded)),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    #endif
    if (pkcs7 != NULL) {
        pkcs7->singleCertSz = tempWrd32;

        tmpBytePtr = pkcs7->singleCert;
        pkcs7->singleCert = NULL;
    }
  #ifndef NO_RSA
    #if defined(NO_PKCS7_STREAM)
    /* when none streaming mode is used and PKCS7 is in bad state buffer error
     * is returned from kari parse which gets set to bad func arg */
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
        (word32)sizeof(output), decoded, (word32)sizeof(decoded)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #else
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
        (word32)sizeof(output), decoded, (word32)sizeof(decoded)),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    #endif
  #endif /* !NO_RSA */
    if (pkcs7 != NULL) {
        pkcs7->singleCert = tmpBytePtr;
    }
#endif
#ifdef HAVE_AES_KEYWRAP
    if (pkcs7 != NULL) {
        tempWrd32 = pkcs7->privateKeySz;
        pkcs7->privateKeySz = 0;
    }
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
        (word32)sizeof(output), decoded, (word32)sizeof(decoded)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    if (pkcs7 != NULL) {
        pkcs7->privateKeySz = tempWrd32;

        tmpBytePtr = pkcs7->privateKey;
        pkcs7->privateKey = NULL;
    }
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
        (word32)sizeof(output), decoded, (word32)sizeof(decoded)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    if (pkcs7 != NULL) {
        pkcs7->privateKey = tmpBytePtr;
    }
#endif

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256) && \
    defined(HAVE_AES_KEYWRAP)
    /* test of decrypt callback with KEKRI enveloped data */
    {
        int envelopedSz = 0;
        const byte keyId[] = { 0x00 };

        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        if (pkcs7 != NULL) {
            pkcs7->content      = (byte*)input;
            pkcs7->contentSz    = (word32)(sizeof(input)/sizeof(char));
            pkcs7->contentOID   = DATA;
            pkcs7->encryptOID   = AES256CBCb;
        }
        ExpectIntGT(wc_PKCS7_AddRecipient_KEKRI(pkcs7, AES256_WRAP,
                    (byte*)defKey, sizeof(defKey), (byte*)keyId,
                    sizeof(keyId), NULL, NULL, 0, NULL, 0, 0), 0);
        ExpectIntEQ(wc_PKCS7_SetSignerIdentifierType(pkcs7, CMS_SKID), 0);
        ExpectIntGT((envelopedSz = wc_PKCS7_EncodeEnvelopedData(pkcs7, output,
                        (word32)sizeof(output))), 0);
        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;

        /* decode envelopedData */
        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_SetWrapCEKCb(pkcs7, myCEKwrapFunc), 0);
        ExpectIntEQ(wc_PKCS7_SetDecodeEncryptedCb(pkcs7, myDecryptionFunc), 0);
        ExpectIntGT((decodedSz = wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
                        (word32)envelopedSz, decoded, sizeof(decoded))), 0);
        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;
    }
#endif /* !NO_AES && HAVE_AES_CBC && WOLFSSL_AES_256 && HAVE_AES_KEYWRAP */

#ifndef NO_RSA
    XFREE(rsaCert, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(rsaPrivKey, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* NO_RSA */
#if defined(HAVE_ECC) && defined(HAVE_X963_KDF)
    XFREE(eccCert, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(eccPrivKey, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* HAVE_ECC */

#ifdef ECC_TIMING_RESISTANT
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif

#if defined(USE_CERT_BUFFERS_2048) && !defined(NO_DES3) && \
    !defined(NO_RSA) && !defined(NO_SHA)
    {
        byte   out[7];
        byte   *cms = NULL;
        word32 cmsSz;
        XFILE  cmsFile = XBADFILE;

        XMEMSET(out, 0, sizeof(out));
        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectTrue((cmsFile = XFOPEN("./certs/test/ktri-keyid-cms.msg", "rb"))
            != XBADFILE);
        cmsSz = (word32)FOURK_BUF;
        ExpectNotNull(cms = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        ExpectTrue((cmsSz = (word32)XFREAD(cms, 1, cmsSz, cmsFile)) > 0);
        if (cmsFile != XBADFILE)
            XFCLOSE(cmsFile);

        ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte*)client_cert_der_2048,
            sizeof_client_cert_der_2048), 0);
        if (pkcs7 != NULL) {
            pkcs7->privateKey   = (byte*)client_key_der_2048;
            pkcs7->privateKeySz = sizeof_client_key_der_2048;
        }
        ExpectIntLT(wc_PKCS7_DecodeEnvelopedData(pkcs7, cms, cmsSz, out,
            2), 0);
        ExpectIntGT(wc_PKCS7_DecodeEnvelopedData(pkcs7, cms, cmsSz, out,
            sizeof(out)), 0);
        XFREE(cms, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        ExpectIntEQ(XMEMCMP(out, "test", 4), 0);
        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;
    }
#endif /* USE_CERT_BUFFERS_2048 && !NO_DES3 && !NO_RSA && !NO_SHA */
#endif /* HAVE_PKCS7 */
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_EncodeDecodeEnvelopedData() */


#if defined(HAVE_PKCS7) && defined(HAVE_ECC) && defined(HAVE_X963_KDF) && \
    !defined(NO_SHA256) && defined(WOLFSSL_AES_256)
static int wasAESKeyWrapCbCalled = 0;
static int wasAESKeyUnwrapCbCalled = 0;

static int testAESKeyWrapUnwrapCb(const byte* key, word32 keySz,
        const byte* in, word32 inSz, int wrap, byte* out, word32 outSz)
{
    (void)key;
    (void)keySz;
    (void)wrap;
    if (wrap)
        wasAESKeyWrapCbCalled = 1;
    else
        wasAESKeyUnwrapCbCalled = 1;
    XMEMSET(out, 0xEE, outSz);
    if (inSz <= outSz) {
        XMEMCPY(out, in, inSz);
    }
    return inSz;
}
#endif


/*
 * Test custom AES key wrap/unwrap callback
 */
int test_wc_PKCS7_SetAESKeyWrapUnwrapCb(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && defined(HAVE_ECC) && defined(HAVE_X963_KDF) && \
    !defined(NO_SHA256) && defined(WOLFSSL_AES_256)
    static const char input[] = "Test input for AES key wrapping";
    PKCS7 * pkcs7 = NULL;
    byte * eccCert = NULL;
    byte * eccPrivKey = NULL;
    word32 eccCertSz = 0;
    word32 eccPrivKeySz = 0;
    byte output[ONEK_BUF];
    byte decoded[sizeof(input)/sizeof(char)];
    int decodedSz = 0;
#ifdef ECC_TIMING_RESISTANT
    WC_RNG rng;
#endif

#ifdef ECC_TIMING_RESISTANT
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_InitRng(&rng), 0);
#endif

/* Load test certs */
#ifdef USE_CERT_BUFFERS_256
    ExpectNotNull(eccCert = (byte*)XMALLOC(TWOK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    /* Init buffer. */
    eccCertSz = (word32)sizeof_cliecc_cert_der_256;
    if (eccCert != NULL) {
        XMEMCPY(eccCert, cliecc_cert_der_256, eccCertSz);
    }
    ExpectNotNull(eccPrivKey = (byte*)XMALLOC(TWOK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    eccPrivKeySz = (word32)sizeof_ecc_clikey_der_256;
    if (eccPrivKey != NULL) {
        XMEMCPY(eccPrivKey, ecc_clikey_der_256, eccPrivKeySz);
    }
#else /* File system. */
    ExpectTrue((certFile = XFOPEN(eccClientCert, "rb")) != XBADFILE);
    eccCertSz = (word32)FOURK_BUF;
    ExpectNotNull(eccCert = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectTrue((eccCertSz = (word32)XFREAD(eccCert, 1, eccCertSz,
        certFile)) > 0);
    if (certFile != XBADFILE) {
        XFCLOSE(certFile);
    }
    ExpectTrue((keyFile = XFOPEN(eccClientKey, "rb")) != XBADFILE);
    eccPrivKeySz = (word32)FOURK_BUF;
    ExpectNotNull(eccPrivKey = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectTrue((eccPrivKeySz = (word32)XFREAD(eccPrivKey, 1, eccPrivKeySz,
        keyFile)) > 0);
    if (keyFile != XBADFILE) {
        XFCLOSE(keyFile);
    }
#endif /* USE_CERT_BUFFERS_256 */

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, eccCert, eccCertSz), 0);
    if (pkcs7 != NULL) {
        pkcs7->content = (byte*)input;
        pkcs7->contentSz = sizeof(input);
        pkcs7->contentOID = DATA;
        pkcs7->encryptOID = AES256CBCb;
        pkcs7->keyWrapOID = AES256_WRAP;
        pkcs7->keyAgreeOID = dhSinglePass_stdDH_sha256kdf_scheme;
        pkcs7->privateKey = eccPrivKey;
        pkcs7->privateKeySz = eccPrivKeySz;
        pkcs7->singleCert = eccCert;
        pkcs7->singleCertSz = (word32)eccCertSz;
#ifdef ECC_TIMING_RESISTANT
        pkcs7->rng = &rng;
#endif
    }

    /* Test custom AES key wrap/unwrap callback */
    ExpectIntEQ(wc_PKCS7_SetAESKeyWrapUnwrapCb(pkcs7, testAESKeyWrapUnwrapCb), 0);

    ExpectIntGE(wc_PKCS7_EncodeEnvelopedData(pkcs7, output,
        (word32)sizeof(output)), 0);

    decodedSz = wc_PKCS7_DecodeEnvelopedData(pkcs7, output,
        (word32)sizeof(output), decoded, (word32)sizeof(decoded));
    ExpectIntGE(decodedSz, 0);
    /* Verify the size of each buffer. */
    ExpectIntEQ((word32)sizeof(input)/sizeof(char), decodedSz);

    ExpectIntEQ(wasAESKeyWrapCbCalled, 1);
    ExpectIntEQ(wasAESKeyUnwrapCbCalled, 1);

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    XFREE(eccCert, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(eccPrivKey, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef ECC_TIMING_RESISTANT
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_PKCS7_GetEnvelopedDataKariRid().
 */
int test_wc_PKCS7_GetEnvelopedDataKariRid(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7)
#if defined(HAVE_ECC) && defined(HAVE_X963_KDF) && (!defined(NO_AES) || \
        !defined(NO_SHA) || !defined(NO_SHA256) || defined(WOLFSSL_SHA512))
    /* The kari-keyid-cms.msg generated by openssl has a 68 byte RID structure.
     * Reserve a bit more than that in case it might grow. */
    byte rid[256];
    byte cms[1024];
    XFILE cmsFile = XBADFILE;
    int ret;
    word32 ridSz = sizeof(rid);
    XFILE skiHexFile = XBADFILE;
    byte skiHex[256];
    word32 cmsSz = 0;
    word32 skiHexSz = 0;
    size_t i = 0;
    const word32 ridKeyIdentifierOffset = 4;

    ExpectTrue((cmsFile = XFOPEN("./certs/test/kari-keyid-cms.msg", "rb"))
            != XBADFILE);
    ExpectTrue((cmsSz = (word32)XFREAD(cms, 1, sizeof(cms), cmsFile)) > 0);
    if (cmsFile != XBADFILE)
        XFCLOSE(cmsFile);

    ExpectTrue((skiHexFile = XFOPEN("./certs/test/client-ecc-cert-ski.hex",
                    "rb")) != XBADFILE);
    ExpectTrue((skiHexSz = (word32)XFREAD(skiHex, 1, sizeof(skiHex),
                    skiHexFile)) > 0);
    if (skiHexFile != XBADFILE)
        XFCLOSE(skiHexFile);

    if (EXPECT_SUCCESS()) {
        ret = wc_PKCS7_GetEnvelopedDataKariRid(cms, cmsSz, rid, &ridSz);
    }
    ExpectIntEQ(ret, 0);
    ExpectIntLT(ridSz, sizeof(rid));
    ExpectIntGT(ridSz, ridKeyIdentifierOffset);
    /* The Subject Key Identifier hex file should have 2 hex characters for each
     * byte of the key identifier in the returned recipient ID (rid), plus a
     * terminating new line character. */
    ExpectIntGE(skiHexSz, ((ridSz - ridKeyIdentifierOffset) * 2) + 1);
    if (EXPECT_SUCCESS()) {
        for (i = 0; i < (ridSz - ridKeyIdentifierOffset); i++)
        {
            size_t j;
            byte ridKeyIdByte = rid[ridKeyIdentifierOffset + i];
            byte skiByte = 0;
            for (j = 0; j <= 1; j++)
            {
                byte hexChar = skiHex[i * 2 + j];
                skiByte = skiByte << 4;
                if ('0' <= hexChar && hexChar <= '9')
                    skiByte |= (hexChar - '0');
                else if ('A' <= hexChar && hexChar <= 'F')
                    skiByte |= (hexChar - 'A' + 10);
                else
                    ExpectTrue(0);
            }
            ExpectIntEQ(ridKeyIdByte, skiByte);
        }
    }
#endif
#endif /* HAVE_PKCS7 */
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_GetEnvelopedDataKariRid() */


/*
 * Testing wc_PKCS7_EncodeEncryptedData()
 */
int test_wc_PKCS7_EncodeEncryptedData(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && !defined(NO_PKCS7_ENCRYPTED_DATA)
    PKCS7*      pkcs7 = NULL;
    byte*       tmpBytePtr = NULL;
    byte        encrypted[TWOK_BUF];
    byte        decoded[TWOK_BUF];
    word32      tmpWrd32 = 0;
    int         tmpInt = 0;
    int         decodedSz = 0;
    int         encryptedSz = 0;
    int         testSz = 0;
    int         i = 0;
    const byte data[] = { /* Hello World */
        0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f,
        0x72,0x6c,0x64
    };
    #ifndef NO_DES3
        byte desKey[] = {
            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
        };
        byte des3Key[] = {
            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
            0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
            0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
        };
    #endif
    #if !defined(NO_AES) && defined(HAVE_AES_CBC)
        #ifdef WOLFSSL_AES_128
        byte aes128Key[] = {
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
        };
        #endif
        #ifdef WOLFSSL_AES_192
        byte aes192Key[] = {
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
        };
        #endif
        #ifdef WOLFSSL_AES_256
        byte aes256Key[] = {
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
        };
        #endif
    #endif /* !NO_AES && HAVE_AES_CBC */
    const pkcs7EncryptedVector testVectors[] =
    {
    #ifndef NO_DES3
        {data, (word32)sizeof(data), DATA, DES3b, des3Key, sizeof(des3Key)},

        {data, (word32)sizeof(data), DATA, DESb, desKey, sizeof(desKey)},
    #endif /* !NO_DES3 */
    #if !defined(NO_AES) && defined(HAVE_AES_CBC)
        #ifdef WOLFSSL_AES_128
        {data, (word32)sizeof(data), DATA, AES128CBCb, aes128Key,
         sizeof(aes128Key)},
        #endif

        #ifdef WOLFSSL_AES_192
        {data, (word32)sizeof(data), DATA, AES192CBCb, aes192Key,
         sizeof(aes192Key)},
        #endif

        #ifdef WOLFSSL_AES_256
        {data, (word32)sizeof(data), DATA, AES256CBCb, aes256Key,
         sizeof(aes256Key)},
        #endif

    #endif /* !NO_AES && HAVE_AES_CBC */
    };

    testSz = sizeof(testVectors) / sizeof(pkcs7EncryptedVector);

    for (i = 0; i < testSz; i++) {
        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, testDevId), 0);
        if (pkcs7 != NULL) {
            pkcs7->content              = (byte*)testVectors[i].content;
            pkcs7->contentSz            = testVectors[i].contentSz;
            pkcs7->contentOID           = testVectors[i].contentOID;
            pkcs7->encryptOID           = testVectors[i].encryptOID;
            pkcs7->encryptionKey        = testVectors[i].encryptionKey;
            pkcs7->encryptionKeySz      = testVectors[i].encryptionKeySz;
            pkcs7->heap                 = HEAP_HINT;
        }

        /* encode encryptedData */
        ExpectIntGT(encryptedSz = wc_PKCS7_EncodeEncryptedData(pkcs7, encrypted,
            sizeof(encrypted)), 0);

        /* Decode encryptedData */
        ExpectIntGT(decodedSz = wc_PKCS7_DecodeEncryptedData(pkcs7, encrypted,
            (word32)encryptedSz, decoded, sizeof(decoded)), 0);

        ExpectIntEQ(XMEMCMP(decoded, data, decodedSz), 0);
        /* Keep values for last itr. */
        if (i < testSz - 1) {
            wc_PKCS7_Free(pkcs7);
            pkcs7 = NULL;
        }
    }
    if (pkcs7 == NULL || testSz == 0) {
        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, testDevId), 0);
    }

    ExpectIntEQ(wc_PKCS7_EncodeEncryptedData(NULL, encrypted,
        sizeof(encrypted)),WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeEncryptedData(pkcs7, NULL,
        sizeof(encrypted)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_EncodeEncryptedData(pkcs7, encrypted,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Testing the struct. */
    if (pkcs7 != NULL) {
        tmpBytePtr = pkcs7->content;
        pkcs7->content = NULL;
    }
    ExpectIntEQ(wc_PKCS7_EncodeEncryptedData(pkcs7, encrypted,
        sizeof(encrypted)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    if (pkcs7 != NULL) {
        pkcs7->content = tmpBytePtr;
        tmpWrd32 = pkcs7->contentSz;
        pkcs7->contentSz = 0;
    }
    ExpectIntEQ(wc_PKCS7_EncodeEncryptedData(pkcs7, encrypted,
        sizeof(encrypted)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    if (pkcs7 != NULL) {
        pkcs7->contentSz = tmpWrd32;
        tmpInt = pkcs7->encryptOID;
        pkcs7->encryptOID = 0;
    }
    ExpectIntEQ(wc_PKCS7_EncodeEncryptedData(pkcs7, encrypted,
        sizeof(encrypted)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    if (pkcs7 != NULL) {
        pkcs7->encryptOID = tmpInt;
        tmpBytePtr = pkcs7->encryptionKey;
        pkcs7->encryptionKey = NULL;
    }
    ExpectIntEQ(wc_PKCS7_EncodeEncryptedData(pkcs7, encrypted,
        sizeof(encrypted)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    if (pkcs7 != NULL) {
        pkcs7->encryptionKey = tmpBytePtr;
        tmpWrd32 = pkcs7->encryptionKeySz;
        pkcs7->encryptionKeySz = 0;
    }
    ExpectIntEQ(wc_PKCS7_EncodeEncryptedData(pkcs7, encrypted,
        sizeof(encrypted)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    if (pkcs7 != NULL) {
        pkcs7->encryptionKeySz = tmpWrd32;
    }

    ExpectIntEQ(wc_PKCS7_DecodeEncryptedData(NULL, encrypted, (word32)encryptedSz,
        decoded, sizeof(decoded)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_DecodeEncryptedData(pkcs7, NULL, (word32)encryptedSz,
        decoded, sizeof(decoded)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_DecodeEncryptedData(pkcs7, encrypted, 0,
        decoded, sizeof(decoded)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_DecodeEncryptedData(pkcs7, encrypted, (word32)encryptedSz,
        NULL, sizeof(decoded)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_DecodeEncryptedData(pkcs7, encrypted, (word32)encryptedSz,
        decoded, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Test struct fields */

    if (pkcs7 != NULL) {
        tmpBytePtr = pkcs7->encryptionKey;
        pkcs7->encryptionKey = NULL;
    }
    ExpectIntEQ(wc_PKCS7_DecodeEncryptedData(pkcs7, encrypted, (word32)encryptedSz,
        decoded, sizeof(decoded)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    if (pkcs7 != NULL) {
        pkcs7->encryptionKey = tmpBytePtr;
        pkcs7->encryptionKeySz = 0;
    }
    ExpectIntEQ(wc_PKCS7_DecodeEncryptedData(pkcs7, encrypted, (word32)encryptedSz,
        decoded, sizeof(decoded)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_EncodeEncryptedData() */


#if defined(HAVE_PKCS7) && defined(USE_CERT_BUFFERS_2048) && !defined(NO_DES3) && !defined(NO_RSA) && !defined(NO_SHA)
static void build_test_EncryptedKeyPackage(byte * out, word32 * out_size, byte * in_data, word32 in_size, size_t in_content_type, size_t test_vector)
{
    /* EncryptedKeyPackage ContentType TLV DER */
    static const byte ekp_oid_tlv[] = {0x06U, 10U,
        0X60U, 0X86U, 0X48U, 0X01U, 0X65U, 0X02U, 0X01U, 0X02U, 0X4EU, 0X02U};
    if (in_content_type == ENCRYPTED_DATA) {
        /* EncryptedData subtype */
        size_t ekp_content_der_size = 2U + in_size;
        size_t ekp_content_info_size = sizeof(ekp_oid_tlv) + ekp_content_der_size;
        /* EncryptedKeyPackage ContentType */
        out[0] = 0x30U;
        out[1] = ekp_content_info_size & 0x7FU;
        /* EncryptedKeyPackage ContentInfo */
        XMEMCPY(&out[2], ekp_oid_tlv, sizeof(ekp_oid_tlv));
        /* EncryptedKeyPackage content [0] */
        out[14] = 0xA0U;
        out[15] = in_size & 0x7FU;
        XMEMCPY(&out[16], in_data, in_size);
        *out_size = 16U + in_size;
        switch (test_vector)
        {
        case 1: out[0] = 0x20U; break;
        case 2: out[2] = 0x01U; break;
        case 3: out[7] = 0x42U; break;
        case 4: out[14] = 0xA2U; break;
        }
    }
    else if (in_content_type == ENVELOPED_DATA) {
        /* EnvelopedData subtype */
        size_t ekp_choice_der_size = 4U + in_size;
        size_t ekp_content_der_size = 4U + ekp_choice_der_size;
        size_t ekp_content_info_size = sizeof(ekp_oid_tlv) + ekp_content_der_size;
        /* EncryptedKeyPackage ContentType */
        out[0] = 0x30U;
        out[1] = 0x82U;
        out[2] = ekp_content_info_size >> 8U;
        out[3] = ekp_content_info_size & 0xFFU;
        /* EncryptedKeyPackage ContentInfo */
        XMEMCPY(&out[4], ekp_oid_tlv, sizeof(ekp_oid_tlv));
        /* EncryptedKeyPackage content [0] */
        out[16] = 0xA0U;
        out[17] = 0x82U;
        out[18] = ekp_choice_der_size >> 8U;
        out[19] = ekp_choice_der_size & 0xFFU;
        /* EncryptedKeyPackage CHOICE [0] EnvelopedData */
        out[20] = 0xA0U;
        out[21] = 0x82U;
        out[22] = in_size >> 8U;
        out[23] = in_size & 0xFFU;
        XMEMCPY(&out[24], in_data, in_size);
        *out_size = 24U + in_size;
        switch (test_vector)
        {
        case 1: out[0] = 0x20U; break;
        case 2: out[4] = 0x01U; break;
        case 3: out[9] = 0x42U; break;
        case 4: out[16] = 0xA2U; break;
        }
    }
}
#endif /* HAVE_PKCS7 && USE_CERT_BUFFERS_2048 && !NO_DES3 && !NO_RSA && !NO_SHA */

/*
 * Test wc_PKCS7_DecodeEncryptedKeyPackage().
 */
int test_wc_PKCS7_DecodeEncryptedKeyPackage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && defined(USE_CERT_BUFFERS_2048) && !defined(NO_DES3) && !defined(NO_RSA) && !defined(NO_SHA)
    static const struct {
        const char * msg_file_name;
        word32 msg_content_type;
    } test_messages[] = {
        {"./certs/test/ktri-keyid-cms.msg", ENVELOPED_DATA},
        {"./certs/test/encrypteddata.msg", ENCRYPTED_DATA},
    };
    static const int test_vectors[] = {
        0,
        WC_NO_ERR_TRACE(ASN_PARSE_E),
        WC_NO_ERR_TRACE(ASN_PARSE_E),
        WC_NO_ERR_TRACE(PKCS7_OID_E),
        WC_NO_ERR_TRACE(ASN_PARSE_E),
    };
    static const byte key[] = {
        0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU,
        0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
    };
    size_t test_msg = 0U;
    size_t test_vector = 0U;

    for (test_msg = 0U; test_msg < (sizeof(test_messages)/sizeof(test_messages[0])); test_msg++)
    {
        for (test_vector = 0U; test_vector < (sizeof(test_vectors)/sizeof(test_vectors[0])); test_vector++)
        {
            byte * ekp_cms_der = NULL;
            word32 ekp_cms_der_size = 0U;
            byte * inner_cms_der = NULL;
            word32 inner_cms_der_size = (word32)FOURK_BUF;
            XFILE inner_cms_file = XBADFILE;
            PKCS7 * pkcs7 = NULL;
            byte out[15] = {0};
            int result = 0;

            ExpectNotNull(ekp_cms_der = (byte *)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER));
            /* Check for possible previous test failure. */
            if (ekp_cms_der == NULL) {
                break;
            }

            ExpectNotNull(inner_cms_der = (byte *)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER));
            ExpectTrue((inner_cms_file = XFOPEN(test_messages[test_msg].msg_file_name, "rb")) != XBADFILE);
            ExpectTrue((inner_cms_der_size = (word32)XFREAD(inner_cms_der, 1, inner_cms_der_size, inner_cms_file)) > 0);
            if (inner_cms_file != XBADFILE) {
                XFCLOSE(inner_cms_file);
            }
            if (test_messages[test_msg].msg_content_type == ENVELOPED_DATA) {
                /* Verify that the build_test_EncryptedKeyPackage can format as expected. */
                ExpectIntGT(inner_cms_der_size, 127);
            }
            if (test_messages[test_msg].msg_content_type == ENCRYPTED_DATA) {
                /* Verify that the build_test_EncryptedKeyPackage can format as expected. */
                ExpectIntLT(inner_cms_der_size, 124);
            }
            build_test_EncryptedKeyPackage(ekp_cms_der, &ekp_cms_der_size, inner_cms_der, inner_cms_der_size, test_messages[test_msg].msg_content_type, test_vector);
            XFREE(inner_cms_der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

            ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
            ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte *)client_cert_der_2048, sizeof_client_cert_der_2048), 0);
            if (pkcs7 != NULL) {
                if (test_messages[test_msg].msg_content_type == ENVELOPED_DATA) {
                    /* To test EnvelopedData, set private key. */
                    pkcs7->privateKey = (byte *)client_key_der_2048;
                    pkcs7->privateKeySz = sizeof_client_key_der_2048;
                }
                if (test_messages[test_msg].msg_content_type == ENCRYPTED_DATA) {
                    /* To test EncryptedData, set symmetric encryption key. */
                    pkcs7->encryptionKey = (byte *)key;
                    pkcs7->encryptionKeySz = sizeof(key);
                }
            }
            ExpectIntEQ(wc_PKCS7_DecodeEncryptedKeyPackage(pkcs7, NULL, ekp_cms_der_size, out, sizeof(out)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            result = wc_PKCS7_DecodeEncryptedKeyPackage(pkcs7, ekp_cms_der, ekp_cms_der_size, out, sizeof(out));
            if (result == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
                result = wc_PKCS7_DecodeEncryptedKeyPackage(pkcs7, ekp_cms_der, ekp_cms_der_size, out, sizeof(out));
            }
            if (test_vectors[test_vector] == 0U) {
                if (test_messages[test_msg].msg_content_type == ENVELOPED_DATA) {
                    ExpectIntGT(result, 0);
                    ExpectIntEQ(XMEMCMP(out, "test", 4), 0);
                }
                if (test_messages[test_msg].msg_content_type == ENCRYPTED_DATA) {
#ifndef NO_PKCS7_ENCRYPTED_DATA
                    ExpectIntGT(result, 0);
                    ExpectIntEQ(XMEMCMP(out, "testencrypt", 11), 0);
#else
                    ExpectIntEQ(result, WC_NO_ERR_TRACE(ASN_PARSE_E));
#endif
                }
            }
            else {
                ExpectIntEQ(result, test_vectors[test_vector]);
            }
            XFREE(ekp_cms_der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            wc_PKCS7_Free(pkcs7);
        }
    }
#endif /* HAVE_PKCS7 && USE_CERT_BUFFERS_2048 && !NO_DES3 && !NO_RSA && !NO_SHA */
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_DecodeEncryptedKeyPackage() */


/*
 * Test wc_PKCS7_DecodeSymmetricKeyPackage().
 */
int test_wc_PKCS7_DecodeSymmetricKeyPackage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7)
    const byte * item;
    word32 itemSz;
    int ret;

    {
        const byte one_key[] = {
            0x30, 0x08,             /* SymmetricKeyPackage SEQUENCE header  */
              0x02, 0x01, 0x01,     /* version v1 */
              0x30, 0x03,           /* sKeys SEQUENCE OF */
                0x02, 0x01, 0x01,   /* INTEGER standin for OneSymmetricKey */
        };
        /* NULL input data pointer */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                NULL, sizeof(one_key), 0, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* NULL output item pointer */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                one_key, sizeof(one_key), 0, NULL, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* NULL output size pointer */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                one_key, sizeof(one_key), 0, &item, NULL);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Valid key index 0 extraction */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                one_key, sizeof(one_key), 0, &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &one_key[7]);
        ExpectIntEQ(itemSz, 3);

        /* Key index 1 out of range */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                one_key, sizeof(one_key), 1, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_INDEX_E));

        /* Attribute index 0 out of range */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageAttribute(
                one_key, sizeof(one_key), 0, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_INDEX_E));

        /* Attribute index 1 out of range */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageAttribute(
                one_key, sizeof(one_key), 1, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_INDEX_E));
    }

    /* Invalid SKP SEQUENCE header. */
    {
        const byte bad_seq_header[] = {
            0x02, 0x01, 0x42, /* Invalid SymmetricKeyPackage SEQUENCE header */
        };
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                bad_seq_header, sizeof(bad_seq_header), 0, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    /* Missing version object */
    {
        const byte missing_version[] = {
            0x30, 0x05, /* SymmetricKeyPackage SEQUENCE header */
              0x30, 0x03, /* sKeys SEQUENCE OF */
                0x02, 0x01, 0x01, /* INTEGER standin for OneSymmetricKey */
        };
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                missing_version, sizeof(missing_version), 0, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    /* Invalid version number */
    {
        const byte bad_version[] = {
            0x30, 0x08, /* SymmetricKeyPackage SEQUENCE header */
              0x02, 0x01, 0x00, /* version 0 (invalid) */
              0x30, 0x03, /* sKeys SEQUENCE OF */
                0x02, 0x01, 0x01, /* INTEGER standin for OneSymmetricKey */
        };
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                bad_version, sizeof(bad_version), 0, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    {
        const byte key3_attr2[] = {
            0x30, 0x18, /* SymmetricKeyPackage SEQUENCE header */
              0x02, 0x01, 0x01, /* version v1 */
              0xA0, 0x08, /* sKeyPkgAttrs EXPLICIT [0] header */
                0x30, 0x06, /* sKeyPkgAttrs SEQUENCE OF header */
                  0x02, 0x01, 0x40, /* INTEGER standin for Attribute 0 */
                  0x02, 0x01, 0x41, /* INTEGER standin for Attribute 1 */
              0x30, 0x09, /* sKeys SEQUENCE OF header */
                0x02, 0x01, 0x0A, /* INTEGER standin for OneSymmetricKey 0 */
                0x02, 0x01, 0x0B, /* INTEGER standin for OneSymmetricKey 1 */
                0x02, 0x01, 0x0C, /* INTEGER standin for OneSymmetricKey 2 */
        };

        /* Valid attribute index 0 extraction */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageAttribute(
                key3_attr2, sizeof(key3_attr2), 0, &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &key3_attr2[9]);
        ExpectIntEQ(itemSz, 3);

        /* Valid attribute index 1 extraction */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageAttribute(
                key3_attr2, sizeof(key3_attr2), 1, &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &key3_attr2[12]);
        ExpectIntEQ(itemSz, 3);

        /* Attribute index 2 out of range */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageAttribute(
                key3_attr2, sizeof(key3_attr2), 2, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_INDEX_E));

        /* Valid key index 0 extraction */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                key3_attr2, sizeof(key3_attr2), 0, &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &key3_attr2[17]);
        ExpectIntEQ(itemSz, 3);

        /* Valid key index 1 extraction */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                key3_attr2, sizeof(key3_attr2), 1, &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &key3_attr2[20]);
        ExpectIntEQ(itemSz, 3);

        /* Valid key index 2 extraction */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                key3_attr2, sizeof(key3_attr2), 2, &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &key3_attr2[23]);
        ExpectIntEQ(itemSz, 3);

        /* Key index 3 out of range */
        ret = wc_PKCS7_DecodeSymmetricKeyPackageKey(
                key3_attr2, sizeof(key3_attr2), 3, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_INDEX_E));
    }
#endif
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_DecodeSymmetricKeyPackage() */


/*
 * Test wc_PKCS7_DecodeOneSymmetricKey().
 */
int test_wc_PKCS7_DecodeOneSymmetricKey(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7)
    const byte * item;
    word32 itemSz;
    int ret;

    {
        const byte key1_attr2[] = {
            0x30, 0x0E, /* OneSymmetricKey SEQUENCE header */
              0x30, 0x06, /* sKeyAttrs SEQUENCE OF header */
                0x02, 0x01, 0x0A, /* INTEGER standin for Attribute 0 */
                0x02, 0x01, 0x0B, /* INTEGER standin for Attribute 1 */
              0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD /* sKey OCTET STRING */
        };

        /* NULL input data pointer */
        ret = wc_PKCS7_DecodeOneSymmetricKeyAttribute(
                NULL, sizeof(key1_attr2), 0, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* NULL output pointer */
        ret = wc_PKCS7_DecodeOneSymmetricKeyAttribute(
                key1_attr2, sizeof(key1_attr2), 0, NULL, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* NULL output size pointer */
        ret = wc_PKCS7_DecodeOneSymmetricKeyAttribute(
                key1_attr2, sizeof(key1_attr2), 0, &item, NULL);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Valid attribute 0 access */
        ret = wc_PKCS7_DecodeOneSymmetricKeyAttribute(
                key1_attr2, sizeof(key1_attr2), 0, &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &key1_attr2[4]);
        ExpectIntEQ(itemSz, 3);

        /* Valid attribute 1 access */
        ret = wc_PKCS7_DecodeOneSymmetricKeyAttribute(
                key1_attr2, sizeof(key1_attr2), 1, &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &key1_attr2[7]);
        ExpectIntEQ(itemSz, 3);

        /* Attribute index 2 out of range */
        ret = wc_PKCS7_DecodeOneSymmetricKeyAttribute(
                key1_attr2, sizeof(key1_attr2), 2, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_INDEX_E));

        /* Valid key access */
        ret = wc_PKCS7_DecodeOneSymmetricKeyKey(
                key1_attr2, sizeof(key1_attr2), &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &key1_attr2[12]);
        ExpectIntEQ(itemSz, 4);
    }

    {
        const byte no_attrs[] = {
            0x30, 0x06, /* OneSymmetricKey SEQUENCE header */
              0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD /* sKey OCTET STRING */
        };

        /* Attribute index 0 out of range */
        ret = wc_PKCS7_DecodeOneSymmetricKeyAttribute(
                no_attrs, sizeof(no_attrs), 0, &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_INDEX_E));

        /* Valid key access */
        ret = wc_PKCS7_DecodeOneSymmetricKeyKey(
                no_attrs, sizeof(no_attrs), &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &no_attrs[4]);
        ExpectIntEQ(itemSz, 4);
    }

    {
        const byte key0_attr2[] = {
            0x30, 0x08, /* OneSymmetricKey SEQUENCE header */
              0x30, 0x06, /* sKeyAttrs SEQUENCE OF header */
                0x02, 0x01, 0x0A, /* INTEGER standin for Attribute 0 */
                0x02, 0x01, 0x0B, /* INTEGER standin for Attribute 1 */
        };

        /* Valid attribute 0 access */
        ret = wc_PKCS7_DecodeOneSymmetricKeyAttribute(
                key0_attr2, sizeof(key0_attr2), 0, &item, &itemSz);
        ExpectIntEQ(ret, 0);
        ExpectPtrEq(item, &key0_attr2[4]);
        ExpectIntEQ(itemSz, 3);

        /* Invalid key access */
        ret = wc_PKCS7_DecodeOneSymmetricKeyKey(
                key0_attr2, sizeof(key0_attr2), &item, &itemSz);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

#endif
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_DecodeOneSymmetricKey() */


/*
 * Testing wc_PKCS7_Degenerate()
 */
int test_wc_PKCS7_Degenerate(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM)
    PKCS7* pkcs7 = NULL;
    char   fName[] = "./certs/test-degenerate.p7b";
    XFILE  f = XBADFILE;
    byte   der[4096];
    word32 derSz = 0;
#ifndef NO_PKCS7_STREAM
    word32 z;
    int ret;
#endif /* !NO_PKCS7_STREAM */
    ExpectTrue((f = XFOPEN(fName, "rb")) != XBADFILE);
    ExpectTrue((derSz = (word32)XFREAD(der, 1, sizeof(der), f)) > 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    /* test degenerate success */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
#ifndef NO_RSA
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, der, derSz), 0);

    #ifndef NO_PKCS7_STREAM
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

    /* test for streaming */
    ret = -1;
    for (z = 0; z < derSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, der + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
    #endif /* !NO_PKCS7_STREAM */
#else
    ExpectIntNE(wc_PKCS7_VerifySignedData(pkcs7, der, derSz), 0);
#endif /* NO_RSA */
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    /* test with turning off degenerate cases */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    wc_PKCS7_AllowDegenerate(pkcs7, 0); /* override allowing degenerate case */
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, der, derSz),
        WC_NO_ERR_TRACE(PKCS7_NO_SIGNER_E));

    #ifndef NO_PKCS7_STREAM
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    wc_PKCS7_AllowDegenerate(pkcs7, 0); /* override allowing degenerate case */

    /* test for streaming */
    ret = -1;
    for (z = 0; z < derSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, der + z, 1);
        if (ret == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)){
            continue;
        }
        else
            break;
    }
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(PKCS7_NO_SIGNER_E));
    #endif /* !NO_PKCS7_STREAM */

    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_Degenerate() */

#if defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && \
    defined(ASN_BER_TO_DER) && !defined(NO_DES3) && !defined(NO_SHA)
static byte berContent[] = {
    0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x07, 0x03, 0xA0, 0x80, 0x30,
    0x80, 0x02, 0x01, 0x00, 0x31, 0x82, 0x01, 0x48,
    0x30, 0x82, 0x01, 0x44, 0x02, 0x01, 0x00, 0x30,
    0x81, 0xAC, 0x30, 0x81, 0x9E, 0x31, 0x0B, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03,
    0x55, 0x04, 0x08, 0x0C, 0x07, 0x4D, 0x6F, 0x6E,
    0x74, 0x61, 0x6E, 0x61, 0x31, 0x10, 0x30, 0x0E,
    0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42,
    0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x15,
    0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C,
    0x0C, 0x77, 0x6F, 0x6C, 0x66, 0x53, 0x53, 0x4C,
    0x5F, 0x31, 0x30, 0x32, 0x34, 0x31, 0x19, 0x30,
    0x17, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x10,
    0x50, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x6D,
    0x69, 0x6E, 0x67, 0x2D, 0x31, 0x30, 0x32, 0x34,
    0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77,
    0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63,
    0x6F, 0x6D, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
    0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40,
    0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E,
    0x63, 0x6F, 0x6D, 0x02, 0x09, 0x00, 0xBB, 0xD3,
    0x10, 0x03, 0xE6, 0x9D, 0x28, 0x03, 0x30, 0x0D,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
    0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x81, 0x80,
    0x2F, 0xF9, 0x77, 0x4F, 0x04, 0x5C, 0x16, 0x62,
    0xF0, 0x77, 0x8D, 0x95, 0x4C, 0xB1, 0x44, 0x9A,
    0x8C, 0x3C, 0x8C, 0xE4, 0xD1, 0xC1, 0x14, 0x72,
    0xD0, 0x4A, 0x1A, 0x94, 0x27, 0x0F, 0xAA, 0xE8,
    0xD0, 0xA2, 0xE7, 0xED, 0x4C, 0x7F, 0x0F, 0xC7,
    0x1B, 0xFB, 0x81, 0x0E, 0x76, 0x8F, 0xDD, 0x32,
    0x11, 0x68, 0xA0, 0x13, 0xD2, 0x8D, 0x95, 0xEF,
    0x80, 0x53, 0x81, 0x0E, 0x1F, 0xC8, 0xD6, 0x76,
    0x5C, 0x31, 0xD3, 0x77, 0x33, 0x29, 0xA6, 0x1A,
    0xD3, 0xC6, 0x14, 0x36, 0xCA, 0x8E, 0x7D, 0x72,
    0xA0, 0x29, 0x4C, 0xC7, 0x3A, 0xAF, 0xFE, 0xF7,
    0xFC, 0xD7, 0xE2, 0x8F, 0x6A, 0x20, 0x46, 0x09,
    0x40, 0x22, 0x2D, 0x79, 0x38, 0x11, 0xB1, 0x4A,
    0xE3, 0x48, 0xE8, 0x10, 0x37, 0xA0, 0x22, 0xF7,
    0xB4, 0x79, 0xD1, 0xA9, 0x3D, 0xC2, 0xAB, 0x37,
    0xAE, 0x82, 0x68, 0x1A, 0x16, 0xEF, 0x33, 0x0C,
    0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x14, 0x06,
    0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03,
    0x07, 0x04, 0x08, 0xAD, 0xD0, 0x38, 0x9B, 0x16,
    0x4B, 0x7F, 0x99, 0xA0, 0x80, 0x04, 0x82, 0x03,
    0xE8, 0x6D, 0x48, 0xFB, 0x8A, 0xBD, 0xED, 0x6C,
    0xCD, 0xC6, 0x48, 0xFD, 0xB7, 0xB0, 0x7C, 0x86,
    0x2C, 0x8D, 0xF0, 0x23, 0x12, 0xD8, 0xA3, 0x2A,
    0x21, 0x6F, 0x8B, 0x75, 0xBB, 0x47, 0x7F, 0xC9,
    0xBA, 0xBA, 0xFF, 0x91, 0x09, 0x01, 0x7A, 0x5C,
    0x96, 0x02, 0xB8, 0x8E, 0xF8, 0x67, 0x7E, 0x8F,
    0xF9, 0x51, 0x0E, 0xFF, 0x8E, 0xE2, 0x61, 0xC0,
    0xDF, 0xFA, 0xE2, 0x4C, 0x50, 0x90, 0xAE, 0xA1,
    0x15, 0x38, 0x3D, 0xBE, 0x88, 0xD7, 0x57, 0xC0,
    0x11, 0x44, 0xA2, 0x61, 0x05, 0x49, 0x6A, 0x94,
    0x04, 0x10, 0xD9, 0xC2, 0x2D, 0x15, 0x20, 0x0D,
    0xBD, 0xA2, 0xEF, 0xE4, 0x68, 0xFA, 0x39, 0x75,
    0x7E, 0xD8, 0x64, 0x44, 0xCB, 0xE0, 0x00, 0x6D,
    0x57, 0x4E, 0x8A, 0x17, 0xA9, 0x83, 0x6C, 0x7F,
    0xFE, 0x01, 0xEE, 0xDE, 0x99, 0x3A, 0xB2, 0xFF,
    0xD3, 0x72, 0x78, 0xBA, 0xF1, 0x23, 0x54, 0x48,
    0x02, 0xD8, 0x38, 0xA9, 0x54, 0xE5, 0x4A, 0x81,
    0xB9, 0xC0, 0x67, 0xB2, 0x7D, 0x3C, 0x6F, 0xCE,
    0xA4, 0xDD, 0x34, 0x5F, 0x60, 0xB1, 0xA3, 0x7A,
    0xE4, 0x43, 0xF2, 0x89, 0x64, 0x35, 0x09, 0x32,
    0x51, 0xFB, 0x5C, 0x67, 0x0C, 0x3B, 0xFC, 0x36,
    0x6B, 0x37, 0x43, 0x6C, 0x03, 0xCD, 0x44, 0xC7,
    0x2B, 0x62, 0xD6, 0xD1, 0xF4, 0x07, 0x7B, 0x19,
    0x91, 0xF0, 0xD7, 0xF5, 0x54, 0xBC, 0x0F, 0x42,
    0x6B, 0x69, 0xF7, 0xA3, 0xC8, 0xEE, 0xB9, 0x7A,
    0x9E, 0x3D, 0xDF, 0x53, 0x47, 0xF7, 0x50, 0x67,
    0x00, 0xCF, 0x2B, 0x3B, 0xE9, 0x85, 0xEE, 0xBD,
    0x4C, 0x64, 0x66, 0x0B, 0x77, 0x80, 0x9D, 0xEF,
    0x11, 0x32, 0x77, 0xA8, 0xA4, 0x5F, 0xEE, 0x2D,
    0xE0, 0x43, 0x87, 0x76, 0x87, 0x53, 0x4E, 0xD7,
    0x1A, 0x04, 0x7B, 0xE1, 0xD1, 0xE1, 0xF5, 0x87,
    0x51, 0x13, 0xE0, 0xC2, 0xAA, 0xA3, 0x4B, 0xAA,
    0x9E, 0xB4, 0xA6, 0x1D, 0x4E, 0x28, 0x57, 0x0B,
    0x80, 0x90, 0x81, 0x4E, 0x04, 0xF5, 0x30, 0x8D,
    0x51, 0xCE, 0x57, 0x2F, 0x88, 0xC5, 0x70, 0xC4,
    0x06, 0x8F, 0xDD, 0x37, 0xC1, 0x34, 0x1E, 0x0E,
    0x15, 0x32, 0x23, 0x92, 0xAB, 0x40, 0xEA, 0xF7,
    0x43, 0xE2, 0x1D, 0xE2, 0x4B, 0xC9, 0x91, 0xF4,
    0x63, 0x21, 0x34, 0xDB, 0xE9, 0x86, 0x83, 0x1A,
    0xD2, 0x52, 0xEF, 0x7A, 0xA2, 0xEE, 0xA4, 0x11,
    0x56, 0xD3, 0x6C, 0xF5, 0x6D, 0xE4, 0xA5, 0x2D,
    0x99, 0x02, 0x10, 0xDF, 0x29, 0xC5, 0xE3, 0x0B,
    0xC4, 0xA1, 0xEE, 0x5F, 0x4A, 0x10, 0xEE, 0x85,
    0x73, 0x2A, 0x92, 0x15, 0x2C, 0xC8, 0xF4, 0x8C,
    0xD7, 0x3D, 0xBC, 0xAD, 0x18, 0xE0, 0x59, 0xD3,
    0xEE, 0x75, 0x90, 0x1C, 0xCC, 0x76, 0xC6, 0x64,
    0x17, 0xD2, 0xD0, 0x91, 0xA6, 0xD0, 0xC1, 0x4A,
    0xAA, 0x58, 0x22, 0xEC, 0x45, 0x98, 0xF2, 0xCC,
    0x4C, 0xE4, 0xBF, 0xED, 0xF6, 0x44, 0x72, 0x36,
    0x65, 0x3F, 0xE3, 0xB5, 0x8B, 0x3E, 0x54, 0x9C,
    0x82, 0x86, 0x5E, 0xB0, 0xF2, 0x12, 0xE5, 0x69,
    0xFA, 0x46, 0xA2, 0x54, 0xFC, 0xF5, 0x4B, 0xE0,
    0x24, 0x3B, 0x99, 0x04, 0x1A, 0x7A, 0xF7, 0xD1,
    0xFF, 0x68, 0x97, 0xB2, 0x85, 0x82, 0x95, 0x27,
    0x2B, 0xF4, 0xE7, 0x1A, 0x74, 0x19, 0xEC, 0x8C,
    0x4E, 0xA7, 0x0F, 0xAD, 0x4F, 0x5A, 0x02, 0x80,
    0xC1, 0x6A, 0x9E, 0x54, 0xE4, 0x8E, 0xA3, 0x41,
    0x3F, 0x6F, 0x9C, 0x82, 0x9F, 0x83, 0xB0, 0x44,
    0x01, 0x5F, 0x10, 0x9D, 0xD3, 0xB6, 0x33, 0x5B,
    0xAF, 0xAC, 0x6B, 0x57, 0x2A, 0x01, 0xED, 0x0E,
    0x17, 0xB9, 0x80, 0x76, 0x12, 0x1C, 0x51, 0x56,
    0xDD, 0x6D, 0x94, 0xAB, 0xD2, 0xE5, 0x15, 0x2D,
    0x3C, 0xC5, 0xE8, 0x62, 0x05, 0x8B, 0x40, 0xB1,
    0xC2, 0x83, 0xCA, 0xAC, 0x4B, 0x8B, 0x39, 0xF7,
    0xA0, 0x08, 0x43, 0x5C, 0xF7, 0xE8, 0xED, 0x40,
    0x72, 0x73, 0xE3, 0x6B, 0x18, 0x67, 0xA0, 0xB6,
    0x0F, 0xED, 0x8F, 0x9A, 0xE4, 0x27, 0x62, 0x23,
    0xAA, 0x6D, 0x6C, 0x31, 0xC9, 0x9D, 0x6B, 0xE0,
    0xBF, 0x9D, 0x7D, 0x2E, 0x76, 0x71, 0x06, 0x39,
    0xAC, 0x96, 0x1C, 0xAF, 0x30, 0xF2, 0x62, 0x9C,
    0x84, 0x3F, 0x43, 0x5E, 0x19, 0xA8, 0xE5, 0x3C,
    0x9D, 0x43, 0x3C, 0x43, 0x41, 0xE8, 0x82, 0xE7,
    0x5B, 0xF3, 0xE2, 0x15, 0xE3, 0x52, 0x20, 0xFD,
    0x0D, 0xB2, 0x4D, 0x48, 0xAD, 0x53, 0x7E, 0x0C,
    0xF0, 0xB9, 0xBE, 0xC9, 0x58, 0x4B, 0xC8, 0xA8,
    0xA3, 0x36, 0xF1, 0x2C, 0xD2, 0xE1, 0xC8, 0xC4,
    0x3C, 0x48, 0x70, 0xC2, 0x6D, 0x6C, 0x3D, 0x99,
    0xAC, 0x43, 0x19, 0x69, 0xCA, 0x67, 0x1A, 0xC9,
    0xE1, 0x47, 0xFA, 0x0A, 0xE6, 0x5B, 0x6F, 0x61,
    0xD0, 0x03, 0xE4, 0x03, 0x4B, 0xFD, 0xE2, 0xA5,
    0x8D, 0x83, 0x01, 0x7E, 0xC0, 0x7B, 0x2E, 0x0B,
    0x29, 0xDD, 0xD6, 0xDC, 0x71, 0x46, 0xBD, 0x9A,
    0x40, 0x46, 0x1E, 0x0A, 0xB1, 0x00, 0xE7, 0x71,
    0x29, 0x77, 0xFC, 0x9A, 0x76, 0x8A, 0x5F, 0x66,
    0x9B, 0x63, 0x91, 0x12, 0x78, 0xBF, 0x67, 0xAD,
    0xA1, 0x72, 0x9E, 0xC5, 0x3E, 0xE5, 0xCB, 0xAF,
    0xD6, 0x5A, 0x0D, 0xB6, 0x9B, 0xA3, 0x78, 0xE8,
    0xB0, 0x8F, 0x69, 0xED, 0xC1, 0x73, 0xD5, 0xE5,
    0x1C, 0x18, 0xA0, 0x58, 0x4C, 0x49, 0xBD, 0x91,
    0xCE, 0x15, 0x0D, 0xAA, 0x5A, 0x07, 0xEA, 0x1C,
    0xA7, 0x4B, 0x11, 0x31, 0x80, 0xAF, 0xA1, 0x0A,
    0xED, 0x6C, 0x70, 0xE4, 0xDB, 0x75, 0x86, 0xAE,
    0xBF, 0x4A, 0x05, 0x72, 0xDE, 0x84, 0x8C, 0x7B,
    0x59, 0x81, 0x58, 0xE0, 0xC0, 0x15, 0xB5, 0xF3,
    0xD5, 0x73, 0x78, 0x83, 0x53, 0xDA, 0x92, 0xC1,
    0xE6, 0x71, 0x74, 0xC7, 0x7E, 0xAA, 0x36, 0x06,
    0xF0, 0xDF, 0xBA, 0xFB, 0xEF, 0x54, 0xE8, 0x11,
    0xB2, 0x33, 0xA3, 0x0B, 0x9E, 0x0C, 0x59, 0x75,
    0x13, 0xFA, 0x7F, 0x88, 0xB9, 0x86, 0xBD, 0x1A,
    0xDB, 0x52, 0x12, 0xFB, 0x6D, 0x1A, 0xCB, 0x49,
    0x94, 0x94, 0xC4, 0xA9, 0x99, 0xC0, 0xA4, 0xB6,
    0x60, 0x36, 0x09, 0x94, 0x2A, 0xD5, 0xC4, 0x26,
    0xF4, 0xA3, 0x6A, 0x0E, 0x57, 0x8B, 0x7C, 0xA4,
    0x1D, 0x75, 0xE8, 0x2A, 0xF3, 0xC4, 0x3C, 0x7D,
    0x45, 0x6D, 0xD8, 0x24, 0xD1, 0x3B, 0xF7, 0xCF,
    0xE4, 0x45, 0x2A, 0x55, 0xE5, 0xA9, 0x1F, 0x1C,
    0x8F, 0x55, 0x8D, 0xC1, 0xF7, 0x74, 0xCC, 0x26,
    0xC7, 0xBA, 0x2E, 0x5C, 0xC1, 0x71, 0x0A, 0xAA,
    0xD9, 0x6D, 0x76, 0xA7, 0xF9, 0xD1, 0x18, 0xCB,
    0x5A, 0x52, 0x98, 0xA8, 0x0D, 0x3F, 0x06, 0xFC,
    0x49, 0x11, 0x21, 0x5F, 0x86, 0x19, 0x33, 0x81,
    0xB5, 0x7A, 0xDA, 0xA1, 0x47, 0xBF, 0x7C, 0xD7,
    0x05, 0x96, 0xC7, 0xF5, 0xC1, 0x61, 0xE5, 0x18,
    0xA5, 0x38, 0x68, 0xED, 0xB4, 0x17, 0x62, 0x0D,
    0x01, 0x5E, 0xC3, 0x04, 0xA6, 0xBA, 0xB1, 0x01,
    0x60, 0x5C, 0xC1, 0x3A, 0x34, 0x97, 0xD6, 0xDB,
    0x67, 0x73, 0x4D, 0x33, 0x96, 0x01, 0x67, 0x44,
    0xEA, 0x47, 0x5E, 0x44, 0xB5, 0xE5, 0xD1, 0x6C,
    0x20, 0xA9, 0x6D, 0x4D, 0xBC, 0x02, 0xF0, 0x70,
    0xE4, 0xDD, 0xE9, 0xD5, 0x5C, 0x28, 0x29, 0x0B,
    0xB4, 0x60, 0x2A, 0xF1, 0xF7, 0x1A, 0xF0, 0x36,
    0xAE, 0x51, 0x3A, 0xAE, 0x6E, 0x48, 0x7D, 0xC7,
    0x5C, 0xF3, 0xDC, 0xF6, 0xED, 0x27, 0x4E, 0x8E,
    0x48, 0x18, 0x3E, 0x08, 0xF1, 0xD8, 0x3D, 0x0D,
    0xE7, 0x2F, 0x65, 0x8A, 0x6F, 0xE2, 0x1E, 0x06,
    0xC1, 0x04, 0x58, 0x7B, 0x4A, 0x75, 0x60, 0x92,
    0x13, 0xC6, 0x40, 0x2D, 0x3A, 0x8A, 0xD1, 0x03,
    0x05, 0x1F, 0x28, 0x66, 0xC2, 0x57, 0x2A, 0x4C,
    0xE1, 0xA3, 0xCB, 0xA1, 0x95, 0x30, 0x10, 0xED,
    0xDF, 0xAE, 0x70, 0x49, 0x4E, 0xF6, 0xB4, 0x5A,
    0xB6, 0x22, 0x56, 0x37, 0x05, 0xE7, 0x3E, 0xB2,
    0xE3, 0x96, 0x62, 0xEC, 0x09, 0x53, 0xC0, 0x50,
    0x3D, 0xA7, 0xBC, 0x9B, 0x39, 0x02, 0x26, 0x16,
    0xB5, 0x34, 0x17, 0xD4, 0xCA, 0xFE, 0x1D, 0xE4,
    0x5A, 0xDA, 0x4C, 0xC2, 0xCA, 0x8E, 0x79, 0xBF,
    0xD8, 0x4C, 0xBB, 0xFA, 0x30, 0x7B, 0xA9, 0x3E,
    0x52, 0x19, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};
#endif /* HAVE_PKCS7 && !NO_FILESYSTEM && ASN_BER_TO_DER &&
        * !NO_DES3 && !NO_SHA
        */

/*
 * Testing wc_PKCS7_BER()
 */
int test_wc_PKCS7_BER(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && \
    !defined(NO_SHA) && defined(ASN_BER_TO_DER)
    PKCS7* pkcs7 = NULL;
    char   fName[] = "./certs/test-ber-exp02-05-2022.p7b";
    XFILE  f = XBADFILE;
    byte   der[4096];
#ifndef NO_DES3
    byte   decoded[2048];
#endif
    word32 derSz = 0;
#if !defined(NO_PKCS7_STREAM) && !defined(NO_RSA)
    word32 z;
    int ret;
#endif /* !NO_PKCS7_STREAM && !NO_RSA */

    ExpectTrue((f = XFOPEN(fName, "rb")) != XBADFILE);
    ExpectTrue((derSz = (word32)XFREAD(der, 1, sizeof(der), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
#ifndef NO_RSA
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, der, derSz), 0);

    #ifndef NO_PKCS7_STREAM
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);

    /* test for streaming */
    ret = -1;
    for (z = 0; z < derSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, der + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
    #endif /* !NO_PKCS7_STREAM */
#else
    ExpectIntNE(wc_PKCS7_VerifySignedData(pkcs7, der, derSz), 0);
#endif
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifndef NO_DES3
    /* decode BER content */
    ExpectTrue((f = XFOPEN("./certs/1024/client-cert.der", "rb")) != XBADFILE);
    ExpectTrue((derSz = (word32)XFREAD(der, 1, sizeof(der), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
#ifndef NO_RSA
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, der, derSz), 0);
#else
    ExpectIntNE(wc_PKCS7_InitWithCert(pkcs7, der, derSz), 0);
#endif

    ExpectTrue((f = XFOPEN("./certs/1024/client-key.der", "rb")) != XBADFILE);
    ExpectTrue((derSz = (word32)XFREAD(der, 1, sizeof(der), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }
    if (pkcs7 != NULL) {
        pkcs7->privateKey   = der;
        pkcs7->privateKeySz = derSz;
    }
#ifndef NO_RSA
#ifdef WOLFSSL_SP_MATH
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, berContent,
        sizeof(berContent), decoded, sizeof(decoded)), WC_NO_ERR_TRACE(WC_KEY_SIZE_E));
#else
    ExpectIntGT(wc_PKCS7_DecodeEnvelopedData(pkcs7, berContent,
        sizeof(berContent), decoded, sizeof(decoded)), 0);
#endif
#else
    ExpectIntEQ(wc_PKCS7_DecodeEnvelopedData(pkcs7, berContent,
        sizeof(berContent), decoded, sizeof(decoded)), WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
    wc_PKCS7_Free(pkcs7);
#endif /* !NO_DES3 */
#endif
    return EXPECT_RESULT();
} /* END test_wc_PKCS7_BER() */

int test_wc_PKCS7_signed_enveloped(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && !defined(NO_RSA) && !defined(NO_AES) && \
    defined(WOLFSSL_AES_256) && !defined(NO_FILESYSTEM)
    XFILE  f = XBADFILE;
    PKCS7* pkcs7 = NULL;
#ifdef HAVE_AES_CBC
    PKCS7* inner = NULL;
#endif
    WC_RNG rng;
    unsigned char key[FOURK_BUF/2];
    unsigned char cert[FOURK_BUF/2];
    unsigned char env[FOURK_BUF];
    int envSz  = FOURK_BUF;
    int keySz = 0;
    int certSz = 0;
    unsigned char sig[FOURK_BUF * 2];
    int sigSz = FOURK_BUF * 2;
#ifdef HAVE_AES_CBC
    unsigned char decoded[FOURK_BUF];
    int decodedSz = FOURK_BUF;
#endif
#ifndef NO_PKCS7_STREAM
    int z;
    int ret;
#endif /* !NO_PKCS7_STREAM */

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    /* load cert */
    ExpectTrue((f = XFOPEN(cliCertDerFile, "rb")) != XBADFILE);
    ExpectIntGT((certSz = (int)XFREAD(cert, 1, sizeof(cert), f)), 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* load key */
    ExpectTrue((f = XFOPEN(cliKeyFile, "rb")) != XBADFILE);
    ExpectIntGT((keySz = (int)XFREAD(key, 1, sizeof(key), f)), 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }
    ExpectIntGT(keySz = wolfSSL_KeyPemToDer(key, keySz, key, keySz, NULL), 0);

    /* sign cert for envelope */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, (word32)certSz), 0);
    if (pkcs7 != NULL) {
        pkcs7->content    = cert;
        pkcs7->contentSz  = (word32)certSz;
        pkcs7->contentOID = DATA;
        pkcs7->privateKey   = key;
        pkcs7->privateKeySz = (word32)keySz;
        pkcs7->encryptOID   = RSAk;
        pkcs7->hashOID      = SHA256h;
        pkcs7->rng          = &rng;
    }
    ExpectIntGT((sigSz = wc_PKCS7_EncodeSignedData(pkcs7, sig, (word32)sigSz)), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    DoExpectIntEQ(wc_FreeRng(&rng), 0);

#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256)
    /* create envelope */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, (word32)certSz), 0);
    if (pkcs7 != NULL) {
        pkcs7->content   = sig;
        pkcs7->contentSz = (word32)sigSz;
        pkcs7->contentOID = DATA;
        pkcs7->encryptOID = AES256CBCb;
        pkcs7->privateKey   = key;
        pkcs7->privateKeySz = (word32)keySz;
    }
    ExpectIntGT((envSz = wc_PKCS7_EncodeEnvelopedData(pkcs7, env, (word32)envSz)), 0);
    ExpectIntLT(wc_PKCS7_EncodeEnvelopedData(pkcs7, env, 2), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
#endif

    /* create bad signed enveloped data */
    sigSz = FOURK_BUF * 2;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, (word32)certSz), 0);
    if (pkcs7 != NULL) {
        pkcs7->content    = env;
        pkcs7->contentSz  = (word32)envSz;
        pkcs7->contentOID = DATA;
        pkcs7->privateKey   = key;
        pkcs7->privateKeySz = (word32)keySz;
        pkcs7->encryptOID   = RSAk;
        pkcs7->hashOID      = SHA256h;
        pkcs7->rng = &rng;
    }

    /* Set no certs in bundle for this test. */
    if (pkcs7 != NULL) {
        ExpectIntEQ(wc_PKCS7_SetNoCerts(pkcs7, 1), 0);
        ExpectIntEQ(wc_PKCS7_SetNoCerts(NULL, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_PKCS7_GetNoCerts(pkcs7), 1);
    }
    ExpectIntGT((sigSz = wc_PKCS7_EncodeSignedData(pkcs7, sig, (word32)sigSz)), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    /* check verify fails */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, sig, (word32)sigSz),
            WC_NO_ERR_TRACE(PKCS7_SIGNEEDS_CHECK));

    /* try verifying the signature manually */
    {
        RsaKey rKey;
        word32 idx = 0;
        byte digest[MAX_SEQ_SZ + MAX_ALGO_SZ + MAX_OCTET_STR_SZ +
            WC_MAX_DIGEST_SIZE];
        int  digestSz = 0;

        ExpectIntEQ(wc_InitRsaKey(&rKey, HEAP_HINT), 0);
        ExpectIntEQ(wc_RsaPrivateKeyDecode(key, &idx, &rKey, (word32)keySz), 0);
        ExpectIntGT(digestSz = wc_RsaSSL_Verify(pkcs7->signature,
            pkcs7->signatureSz, digest, sizeof(digest), &rKey), 0);
        ExpectIntEQ(digestSz, pkcs7->pkcs7DigestSz);
        ExpectIntEQ(XMEMCMP(digest, pkcs7->pkcs7Digest, digestSz), 0);
        ExpectIntEQ(wc_FreeRsaKey(&rKey), 0);
        /* verify was success */
    }

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    /* initializing the PKCS7 struct with the signing certificate should pass */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, (word32)certSz), 0);
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, sig, (word32)sigSz), 0);

#ifndef NO_PKCS7_STREAM
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, (word32)certSz), 0);

    /* test for streaming */
    ret = -1;
    for (z = 0; z < sigSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, sig + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
#endif /* !NO_PKCS7_STREAM */

    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    /* create valid degenerate bundle */
    sigSz = FOURK_BUF * 2;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    if (pkcs7 != NULL) {
        pkcs7->content    = env;
        pkcs7->contentSz  = (word32)envSz;
        pkcs7->contentOID = DATA;
        pkcs7->privateKey   = key;
        pkcs7->privateKeySz = (word32)keySz;
        pkcs7->encryptOID   = RSAk;
        pkcs7->hashOID      = SHA256h;
        pkcs7->rng = &rng;
    }
    ExpectIntEQ(wc_PKCS7_SetSignerIdentifierType(pkcs7, DEGENERATE_SID), 0);
    ExpectIntGT((sigSz = wc_PKCS7_EncodeSignedData(pkcs7, sig, (word32)sigSz)), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    wc_FreeRng(&rng);

    /* check verify */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, sig, (word32)sigSz), 0);
    ExpectNotNull(pkcs7->content);

#ifndef NO_PKCS7_STREAM
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    /* create valid degenerate bundle */
    sigSz = FOURK_BUF * 2;
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    if (pkcs7 != NULL) {
        pkcs7->content    = env;
        pkcs7->contentSz  = (word32)envSz;
        pkcs7->contentOID = DATA;
        pkcs7->privateKey   = key;
        pkcs7->privateKeySz = (word32)keySz;
        pkcs7->encryptOID   = RSAk;
        pkcs7->hashOID      = SHA256h;
        pkcs7->rng = &rng;
    }
    ExpectIntEQ(wc_PKCS7_SetSignerIdentifierType(pkcs7, DEGENERATE_SID), 0);
    ExpectIntGT((sigSz = wc_PKCS7_EncodeSignedData(pkcs7, sig, (word32)sigSz)), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
    wc_FreeRng(&rng);

    /* check verify */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, HEAP_HINT, testDevId), 0);
    /* test for streaming */
    ret = -1;
    for (z = 0; z < sigSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, sig + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
#endif /* !NO_PKCS7_STREAM */

#ifdef HAVE_AES_CBC
    /* check decode */
    ExpectNotNull(inner = wc_PKCS7_New(NULL, 0));
    ExpectIntEQ(wc_PKCS7_InitWithCert(inner, cert, (word32)certSz), 0);
    if (inner != NULL) {
        inner->privateKey   = key;
        inner->privateKeySz = (word32)keySz;
    }
    ExpectIntGT((decodedSz = wc_PKCS7_DecodeEnvelopedData(inner, pkcs7->content,
                   pkcs7->contentSz, decoded, (word32)decodedSz)), 0);
    wc_PKCS7_Free(inner);
    inner = NULL;
#endif
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifdef HAVE_AES_CBC
    /* check cert set */
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    ExpectIntEQ(wc_PKCS7_VerifySignedData(pkcs7, decoded, (word32)decodedSz), 0);
    ExpectNotNull(pkcs7->singleCert);
    ExpectIntNE(pkcs7->singleCertSz, 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

#ifndef NO_PKCS7_STREAM
    ExpectNotNull(pkcs7 = wc_PKCS7_New(NULL, 0));
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, NULL, 0), 0);
    /* test for streaming */
    ret = -1;
    for (z = 0; z < decodedSz && ret != 0; z++) {
        ret = wc_PKCS7_VerifySignedData(pkcs7, decoded + z, 1);
        if (ret < 0){
            ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
        }
    }
    ExpectIntEQ(ret, 0);
    ExpectNotNull(pkcs7->singleCert);
    ExpectIntNE(pkcs7->singleCertSz, 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;
#endif /* !NO_PKCS7_STREAM */
#endif

    {
        /* arbitrary custom SKID */
        const byte customSKID[] = {
            0x40, 0x25, 0x77, 0x56
        };

        ExpectIntEQ(wc_InitRng(&rng), 0);
        sigSz = FOURK_BUF * 2;
        ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
        if (pkcs7 != NULL) {
            ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, cert, (word32)certSz), 0);
            pkcs7->content    = cert;
            pkcs7->contentSz  = (word32)certSz;
            pkcs7->contentOID = DATA;
            pkcs7->privateKey   = key;
            pkcs7->privateKeySz = (word32)keySz;
            pkcs7->encryptOID   = RSAk;
            pkcs7->hashOID      = SHA256h;
            pkcs7->rng          = &rng;
            ExpectIntEQ(wc_PKCS7_SetSignerIdentifierType(pkcs7, CMS_SKID), 0);
            ExpectIntEQ(wc_PKCS7_SetCustomSKID(pkcs7, customSKID,
                        sizeof(customSKID)), 0);
            ExpectIntGT((sigSz = wc_PKCS7_EncodeSignedData(pkcs7, sig,
                (word32)sigSz)), 0);
        }
        wc_PKCS7_Free(pkcs7);
        pkcs7 = NULL;
        wc_FreeRng(&rng);
    }
#endif /* HAVE_PKCS7 && !NO_RSA && !NO_AES */
    return EXPECT_RESULT();
}

int test_wc_PKCS7_NoDefaultSignedAttribs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) \
    && !defined(NO_AES)
    PKCS7* pkcs7 = NULL;
    void*  heap = NULL;

    ExpectNotNull(pkcs7 = wc_PKCS7_New(heap, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, heap, testDevId), 0);

    ExpectIntEQ(wc_PKCS7_NoDefaultSignedAttribs(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_NoDefaultSignedAttribs(pkcs7), 0);

    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS7_SetOriEncryptCtx(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) \
    && !defined(NO_AES)
    PKCS7*       pkcs7 = NULL;
    void*        heap = NULL;
    WOLFSSL_CTX* ctx = NULL;

    ExpectNotNull(pkcs7 = wc_PKCS7_New(heap, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, heap, testDevId), 0);

    ExpectIntEQ(wc_PKCS7_SetOriEncryptCtx(NULL, ctx), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_SetOriEncryptCtx(pkcs7, ctx), 0);

    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS7_SetOriDecryptCtx(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) \
    && !defined(NO_AES)
    PKCS7*       pkcs7 = NULL;
    void*        heap = NULL;
    WOLFSSL_CTX* ctx = NULL;

    ExpectNotNull(pkcs7 = wc_PKCS7_New(heap, testDevId));
    ExpectIntEQ(wc_PKCS7_Init(pkcs7, heap, testDevId), 0);

    ExpectIntEQ(wc_PKCS7_SetOriDecryptCtx(NULL, ctx), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_PKCS7_SetOriDecryptCtx(pkcs7, ctx), 0);

    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
}

int test_wc_PKCS7_DecodeCompressedData(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) \
    && !defined(NO_AES) && defined(HAVE_LIBZ)
    PKCS7* pkcs7 = NULL;
    void*  heap = NULL;
    byte   out[4096];
    byte*  decompressed = NULL;
    int    outSz;
    int    decompressedSz;
    const char* cert = "./certs/client-cert.pem";
    byte*  cert_buf = NULL;
    size_t cert_sz = 0;

    ExpectIntEQ(load_file(cert, &cert_buf, &cert_sz), 0);
    ExpectNotNull((decompressed = (byte*)XMALLOC(cert_sz, heap,
        DYNAMIC_TYPE_TMP_BUFFER)));
    decompressedSz = (int)cert_sz;
    ExpectNotNull((pkcs7 = wc_PKCS7_New(heap, testDevId)));

    if (pkcs7 != NULL) {
        pkcs7->content    = (byte*)cert_buf;
        pkcs7->contentSz  = (word32)cert_sz;
        pkcs7->contentOID = DATA;
    }

    ExpectIntGT((outSz = wc_PKCS7_EncodeCompressedData(pkcs7, out,
        sizeof(out))), 0);
    wc_PKCS7_Free(pkcs7);
    pkcs7 = NULL;

    /* compressed key should be smaller than when started */
    ExpectIntLT(outSz, cert_sz);

    /* test decompression */
    ExpectNotNull((pkcs7 = wc_PKCS7_New(heap, testDevId)));
    ExpectIntEQ(pkcs7->contentOID, 0);

    /* fail case with out buffer too small */
    ExpectIntLT(wc_PKCS7_DecodeCompressedData(pkcs7, out, outSz,
        decompressed, outSz), 0);

    /* success case */
    ExpectIntEQ(wc_PKCS7_DecodeCompressedData(pkcs7, out, outSz,
        decompressed, decompressedSz), cert_sz);
    ExpectIntEQ(pkcs7->contentOID, DATA);
    ExpectIntEQ(XMEMCMP(decompressed, cert_buf, cert_sz), 0);
    XFREE(decompressed, heap, DYNAMIC_TYPE_TMP_BUFFER);
    decompressed = NULL;

    /* test decompression function with different 'max' inputs */
    outSz = sizeof(out);
    ExpectIntGT((outSz = wc_Compress(out, outSz, cert_buf, (word32)cert_sz, 0)),
        0);
    ExpectIntLT(wc_DeCompressDynamic(&decompressed, 1, DYNAMIC_TYPE_TMP_BUFFER,
        out, outSz, 0, heap), 0);
    ExpectNull(decompressed);
    ExpectIntGT(wc_DeCompressDynamic(&decompressed, -1, DYNAMIC_TYPE_TMP_BUFFER,
        out, outSz, 0, heap), 0);
    ExpectNotNull(decompressed);
    ExpectIntEQ(XMEMCMP(decompressed, cert_buf, cert_sz), 0);
    XFREE(decompressed, heap, DYNAMIC_TYPE_TMP_BUFFER);
    decompressed = NULL;

    ExpectIntGT(wc_DeCompressDynamic(&decompressed, DYNAMIC_TYPE_TMP_BUFFER, 5,
        out, outSz, 0, heap), 0);
    ExpectNotNull(decompressed);
    ExpectIntEQ(XMEMCMP(decompressed, cert_buf, cert_sz), 0);
    XFREE(decompressed, heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (cert_buf != NULL)
        free(cert_buf);
    wc_PKCS7_Free(pkcs7);
#endif
    return EXPECT_RESULT();
}


