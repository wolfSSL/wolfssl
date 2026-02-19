/* test_ossl_x509_ext.c
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

#include <wolfssl/ssl.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/internal.h>
#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/pem.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_ossl_x509_ext.h>


int test_wolfSSL_X509_get_extension_flags(void)
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

int test_wolfSSL_X509_get_ext(void)
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

int test_wolfSSL_X509_get_ext_by_NID(void)
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

int test_wolfSSL_X509_get_ext_subj_alt_name(void)
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

int test_wolfSSL_X509_set_ext(void)
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

int test_wolfSSL_X509_add_ext(void)
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

int test_wolfSSL_X509_get_ext_count(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA)
    int ret = 0;
    WOLFSSL_X509* x509 = NULL;
    const char ocspRootCaFile[] = "./certs/ocsp/root-ca-cert.pem";
    XFILE f = XBADFILE;

    /* NULL parameter check */
    ExpectIntEQ(X509_get_ext_count(NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectNotNull(x509 = wolfSSL_X509_new());
    ExpectIntEQ(X509_get_ext_count(x509), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    wolfSSL_X509_free(x509);
    x509 = NULL;

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(svrCertFile,
        SSL_FILETYPE_PEM));
    ExpectIntEQ(X509_get_ext_count(x509), 5);
    wolfSSL_X509_free(x509);

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(ocspRootCaFile,
        SSL_FILETYPE_PEM));
    ExpectIntEQ(X509_get_ext_count(x509), 5);
    wolfSSL_X509_free(x509);

    ExpectTrue((f = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE)
        XFCLOSE(f);

    /* wolfSSL_X509_get_ext_count() valid input */
    ExpectIntEQ((ret = wolfSSL_X509_get_ext_count(x509)), 5);

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

/* Tests X509v3_get_ext_count, X509v3_get_ext_by_NID, and X509v3_get_ext
 * working with a stack retrieved from wolfSSL_X509_get0_extensions().
 */
int test_wolfSSL_X509_stack_extensions(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA)
    WOLFSSL_X509* x509 = NULL;
    const WOLFSSL_STACK* ext_stack = NULL;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    int idx = -1;
    int count = 0;
    XFILE f = XBADFILE;

    /* Load a certificate */
    ExpectTrue((f = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE)
        XFCLOSE(f);

    /* Get the stack of extensions */
    ExpectNotNull(ext_stack = wolfSSL_X509_get0_extensions(x509));

    /* Test X509v3_get_ext_count */
    ExpectIntGT((count = X509v3_get_ext_count(ext_stack)), 0);

    /* Test X509v3_get_ext_by_NID - find Basic Constraints extension */
    ExpectIntGE((idx = X509v3_get_ext_by_NID(ext_stack, NID_basic_constraints,
                -1)), 0);

    /* Test X509v3_get_ext - get extension by index */
    ExpectNotNull(ext = X509v3_get_ext(ext_stack, idx));

    /* Verify that the extension is the correct one */
    ExpectIntEQ(wolfSSL_OBJ_obj2nid(wolfSSL_X509_EXTENSION_get_object(ext)),
               NID_basic_constraints);

    /* Test negative cases */
    ExpectIntEQ(X509v3_get_ext_by_NID(NULL, NID_basic_constraints, -1),
               WOLFSSL_FATAL_ERROR);
    ExpectNull(X509v3_get_ext(NULL, 0));
    ExpectNull(X509v3_get_ext(ext_stack, -1));
    ExpectNull(X509v3_get_ext(ext_stack, count));

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_EXTENSION_new(void)
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

int test_wolfSSL_X509_EXTENSION_dup(void)
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

int test_wolfSSL_X509_EXTENSION_get_object(void)
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
    ExpectIntEQ(o->nid, SUBJ_KEY_OID);
    ExpectNotNull(dup = wolfSSL_X509_EXTENSION_dup(ext));
    wolfSSL_X509_EXTENSION_free(dup);

    /* wolfSSL_X509_EXTENSION_get_object() NULL argument */
    ExpectNull(o = wolfSSL_X509_EXTENSION_get_object(NULL));

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_EXTENSION_get_data(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_ALL) && !defined(NO_RSA)
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_STRING* str = NULL;
    XFILE file = XBADFILE;
#ifndef WOLFSSL_OLD_EXTDATA_FMT
    const byte ext_data[] = {
        0x04, 0x14, 0xB3, 0x11, 0x32, 0xC9, 0x92, 0x98,
        0x84, 0xE2, 0xC9, 0xF8, 0xD0, 0x3B, 0x6E, 0x03,
        0x42, 0xCA, 0x1F, 0x0E, 0x8E, 0x3C,
    };
#endif

    ExpectTrue((file = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(file, NULL, NULL, NULL));
    if (file != XBADFILE)
        XFCLOSE(file);
    ExpectNotNull(ext = wolfSSL_X509_get_ext(x509, 0));

    ExpectNull(str = wolfSSL_X509_EXTENSION_get_data(NULL));
    ExpectNotNull(str = wolfSSL_X509_EXTENSION_get_data(ext));

#ifndef WOLFSSL_OLD_EXTDATA_FMT
    ExpectIntEQ(str->length, sizeof (ext_data));
    ExpectBufEQ(str->data, ext_data, sizeof (ext_data));
#endif

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_EXTENSION_get_critical(void)
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

    ExpectIntEQ(crit = wolfSSL_X509_EXTENSION_get_critical(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(crit = wolfSSL_X509_EXTENSION_get_critical(ext), 0);

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_EXTENSION_create_by_OBJ(void)
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

int test_wolfSSL_X509V3_set_ctx(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ) && \
    defined(HAVE_CRL)
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

int test_wolfSSL_X509V3_EXT_get(void)
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
        if (EXPECT_SUCCESS()) {
            if (method->ext_nid == NID_subject_key_identifier) {
                ExpectNotNull(method->i2s);
            }
        }
    }

    /* wolfSSL_X509V3_EXT_get() NULL argument test */
    ExpectNull(method = wolfSSL_X509V3_EXT_get(NULL));

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509V3_EXT_nconf(void)
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

int test_wolfSSL_X509V3_EXT_bc(void)
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

int test_wolfSSL_X509V3_EXT_san(void)
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

int test_wolfSSL_X509V3_EXT_aia(void)
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
    ExpectNotNull(aia = (WOLFSSL_AUTHORITY_INFO_ACCESS *)
        wolfSSL_X509V3_EXT_d2i(ext));
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
    ExpectNotNull(aia = (WOLFSSL_AUTHORITY_INFO_ACCESS *)
        wolfSSL_X509V3_EXT_d2i(ext));
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

int test_wolfSSL_X509V3_EXT(void)
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

int test_wolfSSL_X509V3_EXT_print(void)
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

/*
 * Test retrieving Name Constraints extension via X509_get_ext_d2i.
 * Tests basic retrieval of permitted and excluded subtrees, stack operations
 * (num, value), GENERAL_NAME type and data extraction, free functions.
 */
int test_wolfSSL_X509_get_ext_d2i_name_constraints(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && !defined(IGNORE_NAME_CONSTRAINTS)
    XFILE f = XBADFILE;
    X509* x509 = NULL;
    NAME_CONSTRAINTS* nc = NULL;
    GENERAL_SUBTREE* subtree = NULL;
    GENERAL_NAME* gn = NULL;
    int numPermitted = 0;
    int numExcluded = 0;
    int critical = -1;

    /* Test NULL input handling */
    ExpectNull(X509_get_ext_d2i(NULL, NID_name_constraints, NULL, NULL));

    /* Test certificate without name constraints
     * server-cert.pem does not have name constraints extension */
    ExpectTrue((f = XFOPEN("./certs/server-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Should return NULL for certificate without name constraints */
    nc = (NAME_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_name_constraints,
                                             &critical, NULL);
    ExpectNull(nc);
    X509_free(x509);
    x509 = NULL;

    /* Test certificate with permitted email name constraint.
     * cert-ext-nc.pem has nameConstraints with permitted email */
    ExpectTrue((f = XFOPEN("./certs/test/cert-ext-nc.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    critical = -1;
    nc = (NAME_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_name_constraints,
                                             &critical, NULL);
    ExpectNotNull(nc);

    /* Verify critical flag is set (cert marks it critical) */
    ExpectIntEQ(critical, 1);

    /* Check permitted subtrees */
    if (nc != NULL) {
        ExpectNotNull(nc->permittedSubtrees);
        if (nc->permittedSubtrees != NULL) {
            numPermitted = sk_GENERAL_SUBTREE_num(nc->permittedSubtrees);
            ExpectIntGT(numPermitted, 0);

            /* Get first permitted subtree */
            subtree = sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, 0);
            ExpectNotNull(subtree);
            if (subtree != NULL) {
                ExpectNotNull(subtree->base);
                if (subtree->base != NULL) {
                    /* Check GENERAL_NAME type is GEN_EMAIL */
                    gn = subtree->base;
                    ExpectIntEQ(gn->type, GEN_EMAIL);

                    /* Verify email constraint value */
                    ExpectNotNull(gn->d.ia5);
                    if (gn->d.ia5 != NULL) {
                        ExpectNotNull(gn->d.ia5->data);
                        ExpectIntGT(gn->d.ia5->length, 0);
                    }
                }
            }
        }

        /* Check excluded subtrees, should be NULL or empty */
        if (nc->excludedSubtrees != NULL) {
            numExcluded = sk_GENERAL_SUBTREE_num(nc->excludedSubtrees);
            ExpectIntEQ(numExcluded, 0);
        }

        /* Test out of bounds access */
        if (nc->permittedSubtrees != NULL) {
            ExpectNull(sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, 100));
        }
    }

    /* Test NULL stack handling, wolfSSL returns 0 */
    ExpectIntEQ(sk_GENERAL_SUBTREE_num(NULL), 0);
    ExpectNull(sk_GENERAL_SUBTREE_value(NULL, 0));

    NAME_CONSTRAINTS_free(nc);
    nc = NULL;
    X509_free(x509);
    x509 = NULL;

    /* Test free functions with NULL */
    NAME_CONSTRAINTS_free(NULL);
    wolfSSL_GENERAL_SUBTREE_free(NULL);

#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_CERTS && !NO_RSA &&
        * !IGNORE_NAME_CONSTRAINTS */
    return EXPECT_RESULT();
}

/*
 * Test sk_GENERAL_SUBTREE_num and sk_GENERAL_SUBTREE_value functions.
 */
int test_wolfSSL_sk_GENERAL_SUBTREE(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && !defined(IGNORE_NAME_CONSTRAINTS)
    XFILE f = XBADFILE;
    X509* x509 = NULL;
    NAME_CONSTRAINTS* nc = NULL;
    GENERAL_SUBTREE* subtree = NULL;
    int num = 0;
    int i;

    /* Load certificate with name constraints (cert-ext-nc.pem has 1 email) */
    ExpectTrue((f = XFOPEN("./certs/test/cert-ext-nc.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    nc = (NAME_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_name_constraints,
                                             NULL, NULL);
    ExpectNotNull(nc);

    if (nc != NULL) {
        ExpectNotNull(nc->permittedSubtrees);
        if (nc->permittedSubtrees != NULL) {
            /* Test sk_GENERAL_SUBTREE_num */
            num = sk_GENERAL_SUBTREE_num(nc->permittedSubtrees);
            ExpectIntGT(num, 0);

            /* Test sk_GENERAL_SUBTREE_value with valid indices */
            for (i = 0; i < num && i < 10; i++) {
                subtree = sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, i);
                ExpectNotNull(subtree);
                if (subtree != NULL) {
                    ExpectNotNull(subtree->base);
                }
            }

            /* Test sk_GENERAL_SUBTREE_value at boundaries */
            ExpectNotNull(sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, 0));
            if (num > 0) {
                ExpectNotNull(sk_GENERAL_SUBTREE_value(nc->permittedSubtrees,
                                                       num - 1));
            }

            /* Test invalid indices (out of bounds) */
            ExpectNull(sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, num));
            ExpectNull(sk_GENERAL_SUBTREE_value(nc->permittedSubtrees,
                                                num + 1));
            ExpectNull(sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, 10000));
        }
    }

    /* Test NULL stack - wolfSSL returns 0 */
    ExpectIntEQ(sk_GENERAL_SUBTREE_num(NULL), 0);
    ExpectNull(sk_GENERAL_SUBTREE_value(NULL, 0));

    NAME_CONSTRAINTS_free(nc);
    X509_free(x509);

#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_CERTS && !NO_RSA &&
        * !IGNORE_NAME_CONSTRAINTS */
    return EXPECT_RESULT();
}

/*
 * Test GENERAL_NAME types in Name Constraints.
 * Verify that different GENERAL_NAME types (DNS, EMAIL, DIRNAME) are properly
 * extracted from name constraints.
 */
int test_wolfSSL_NAME_CONSTRAINTS_types(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && !defined(IGNORE_NAME_CONSTRAINTS)
    XFILE f = XBADFILE;
    X509* x509 = NULL;
    NAME_CONSTRAINTS* nc = NULL;
    GENERAL_SUBTREE* subtree = NULL;
    GENERAL_NAME* gn = NULL;

    /* Test EMAIL type constraint from cert-ext-nc.pem */
    ExpectTrue((f = XFOPEN("./certs/test/cert-ext-nc.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    nc = (NAME_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_name_constraints,
                                             NULL, NULL);
    ExpectNotNull(nc);
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(nc->permittedSubtrees);
    }
    if (EXPECT_SUCCESS()) {
        subtree = sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, 0);
        ExpectNotNull(subtree);
    }
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(subtree->base);
    }
    if (EXPECT_SUCCESS()) {
        gn = subtree->base;
        ExpectIntEQ(gn->type, GEN_EMAIL);
        ExpectNotNull(gn->d.ia5);
    }
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(gn->d.ia5->data);
        ExpectIntGT(gn->d.ia5->length, 0);
    }
    if (EXPECT_SUCCESS()) {
        /* Constraint should contain "wolfssl.com" */
        ExpectNotNull(XSTRSTR((const char*)gn->d.ia5->data, "wolfssl.com"));
    }

    NAME_CONSTRAINTS_free(nc);
    X509_free(x509);

#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_CERTS && !NO_RSA &&
        * !IGNORE_NAME_CONSTRAINTS */
    return EXPECT_RESULT();
}

/*
 * Test URI type in Name Constraints. Verifies that GEN_URI type name
 * constraints are properly extracted and stored as IA5STRING.
 */
int test_wolfSSL_NAME_CONSTRAINTS_uri(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && !defined(IGNORE_NAME_CONSTRAINTS)
    XFILE f = XBADFILE;
    X509* x509 = NULL;
    NAME_CONSTRAINTS* nc = NULL;
    GENERAL_SUBTREE* subtree = NULL;
    GENERAL_NAME* gn = NULL;
    int i;
    int numSubtrees;
    int foundUri = 0;

    /* Test URI type constraint from cert-ext-nc-combined.pem
     * This cert has both URI and DNS constraints */
    ExpectTrue((f = XFOPEN("./certs/test/cert-ext-nc-combined.pem", "rb"))
                    != XBADFILE);
    ExpectNotNull(x509 = PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    nc = (NAME_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_name_constraints,
                                             NULL, NULL);
    ExpectNotNull(nc);
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(nc->permittedSubtrees);
    }
    /* Find the URI constraint by iterating through subtrees
     * (wolfSSL may store them in a different order than in the cert) */
    if (EXPECT_SUCCESS()) {
        numSubtrees = sk_GENERAL_SUBTREE_num(nc->permittedSubtrees);
        for (i = 0; i < numSubtrees; i++) {
            subtree = sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, i);
            if (subtree != NULL && subtree->base != NULL &&
                subtree->base->type == GEN_URI) {
                gn = subtree->base;
                foundUri = 1;
                break;
            }
        }
        ExpectIntEQ(foundUri, 1);
    }
    if (EXPECT_SUCCESS() && foundUri) {
        ExpectNotNull(gn->d.ia5);
    }
    if (EXPECT_SUCCESS() && foundUri) {
        ExpectNotNull(gn->d.ia5->data);
        ExpectIntGT(gn->d.ia5->length, 0);
    }
    if (EXPECT_SUCCESS() && foundUri) {
        /* Constraint should contain "wolfssl.com" */
        ExpectNotNull(XSTRSTR((const char*)gn->d.ia5->data, "wolfssl.com"));
    }

    /* Test URI constraint matching with NAME_CONSTRAINTS_check_name
     * Constraint is ".wolfssl.com" (leading dot), matches subdomains only */
    if (EXPECT_SUCCESS()) {
        /* Full URIs with subdomain hosts - should match */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://www.wolfssl.com/path", 28), 1);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "http://sub.wolfssl.com", 22), 1);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://a.b.c.wolfssl.com:8080/path?q=1", 39), 1);

        /* Exact domain, should not match .wolfssl.com per RFC 5280 */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://wolfssl.com/", 20), 0);

        /* Different domains, should not match */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://www.example.com/", 24), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://fakewolfssl.com/", 24), 0);

        /* URI with userinfo, should extract host correctly */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://user@www.wolfssl.com/", 29), 1);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://user:pass@www.wolfssl.com/path", 38), 1);

        /* IPv6 literal URIs, host extracted without brackets.
         * These don't match .wolfssl.com constraint (different host type) */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://[::1]:8080/path", 23), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://[2001:db8::1]/", 22), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://[fe80::1%25eth0]:443/", 29), 0);

        /* IPv6 with userinfo */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://user@[::1]:8080/", 24), 0);

        /* Malformed IPv6 (missing closing bracket), should fail */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "https://[::1/path", 17), 0);

        /* Invalid URIs, should fail */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "not-a-uri", 9), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_URI,
            "://no-scheme", 12), 0);
    }

    NAME_CONSTRAINTS_free(nc);
    X509_free(x509);

#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_CERTS && !NO_RSA &&
        * !IGNORE_NAME_CONSTRAINTS */
    return EXPECT_RESULT();
}

/*
 * Test IP address type in Name Constraints.
 * Verifies that GEN_IPADD type name constraints are properly extracted
 * and contain the raw IP bytes in OCTET_STRING format.
 * Format: [IP bytes][subnet mask bytes] (8 bytes for IPv4, 32 for IPv6)
 */
int test_wolfSSL_NAME_CONSTRAINTS_ipaddr(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && !defined(IGNORE_NAME_CONSTRAINTS)
    XFILE f = XBADFILE;
    X509* x509 = NULL;
    NAME_CONSTRAINTS* nc = NULL;
    GENERAL_SUBTREE* subtree = NULL;
    GENERAL_NAME* gn = NULL;
    int numPermitted = 0;
    int critical = -1;

    /* Test IP address type constraint from cert-ext-ncip.pem
     * This cert has permitted IP: 192.168.1.0/255.255.255.0 */
    if ((f = XFOPEN("./certs/test/cert-ext-ncip.pem", "rb")) == XBADFILE) {
        return TEST_SKIPPED;
    }
    x509 = PEM_read_X509(f, NULL, NULL, NULL);
    XFCLOSE(f);
    f = XBADFILE;

    if (x509 == NULL) {
        /* Certificate may fail to load due to constraints, skip */
        return TEST_SKIPPED;
    }

    critical = -1;
    nc = (NAME_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_name_constraints,
                                             &critical, NULL);
    ExpectNotNull(nc);

    /* Verify critical flag is set */
    ExpectIntEQ(critical, 1);

    if (EXPECT_SUCCESS()) {
        ExpectNotNull(nc->permittedSubtrees);
    }
    if (EXPECT_SUCCESS()) {
        numPermitted = sk_GENERAL_SUBTREE_num(nc->permittedSubtrees);
        ExpectIntEQ(numPermitted, 1);
        subtree = sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, 0);
        ExpectNotNull(subtree);
    }
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(subtree->base);
    }
    if (EXPECT_SUCCESS()) {
        gn = subtree->base;
        /* Verify GENERAL_NAME type is GEN_IPADD */
        ExpectIntEQ(gn->type, GEN_IPADD);
        /* Verify IP data is stored in d.ip as OCTET_STRING */
        ExpectNotNull(gn->d.ip);
    }
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(gn->d.ip->data);
        /* IPv4 constraint: 4 bytes IP + 4 bytes mask = 8 */
        ExpectIntEQ(gn->d.ip->length, 8);
    }
    if (EXPECT_SUCCESS()) {
        /* Verify the IP address bytes (192.168.1.0) */
        ExpectIntEQ((unsigned char)gn->d.ip->data[0], 192);
        ExpectIntEQ((unsigned char)gn->d.ip->data[1], 168);
        ExpectIntEQ((unsigned char)gn->d.ip->data[2], 1);
        ExpectIntEQ((unsigned char)gn->d.ip->data[3], 0);
        /* Verify the subnet mask bytes (255.255.255.0) */
        ExpectIntEQ((unsigned char)gn->d.ip->data[4], 255);
        ExpectIntEQ((unsigned char)gn->d.ip->data[5], 255);
        ExpectIntEQ((unsigned char)gn->d.ip->data[6], 255);
        ExpectIntEQ((unsigned char)gn->d.ip->data[7], 0);
    }
    if (EXPECT_SUCCESS() && nc->excludedSubtrees != NULL) {
        /* Excluded subtrees should be empty */
        ExpectIntEQ(sk_GENERAL_SUBTREE_num(nc->excludedSubtrees), 0);
    }

    NAME_CONSTRAINTS_free(nc);
    X509_free(x509);

#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_CERTS && !NO_RSA &&
        * !IGNORE_NAME_CONSTRAINTS */
    return EXPECT_RESULT();
}

/*
 * Test wolfSSL_NAME_CONSTRAINTS_check_name() function, checking individual
 * names against name constraints.
 */
int test_wolfSSL_NAME_CONSTRAINTS_check_name(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && !defined(IGNORE_NAME_CONSTRAINTS)
    XFILE f = XBADFILE;
    X509* x509 = NULL;
    NAME_CONSTRAINTS* nc = NULL;

    /* Test email constraint checking with cert-ext-nc.pem
     * This cert has permitted email for .wolfssl.com (subdomains only) */
    ExpectTrue((f = XFOPEN("./certs/test/cert-ext-nc.pem", "rb")) != XBADFILE);
    ExpectNotNull(x509 = PEM_read_X509(f, NULL, NULL, NULL));
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    nc = (NAME_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_name_constraints,
                                             NULL, NULL);
    ExpectNotNull(nc);

    if (EXPECT_SUCCESS()) {
        /* Constraint is ".wolfssl.com" (leading dot). Per RFC 5280, this
         * matches emails where domain ends with  ".wolfssl.com" (subdomains
         * only), not the exact domain. */

        /* Subdomain emails, should match .wolfssl.com */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "test@sub.wolfssl.com", 20), 1);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "user@mail.wolfssl.com", 21), 1);
        /* Deeper subdomain, should also match */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "admin@a.b.c.wolfssl.com", 23), 1);

        /* Exact domain, should not match .wolfssl.com per RFC */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "user@wolfssl.com", 16), 0);

        /* Different domains, should not match */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "user@other.com", 14), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "user@notwolfssl.com", 19), 0);
        /* Suffix that doesn't have dot boundary */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "user@fakewolfssl.com", 20), 0);

        /* Test DNS names, no DNS constraint, so all should pass */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "www.example.com", 15), 1);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "any.domain.org", 14), 1);

        /* Test NULL/invalid arguments */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(NULL, GEN_EMAIL,
            "user@wolfssl.com", 16), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            NULL, 16), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "user@wolfssl.com", 0), 0);
        /* Invalid email format (no @) */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "invalid-email", 13), 0);
        /* @ at start */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "@wolfssl.com", 12), 0);
        /* @ at end */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "user@", 5), 0);
    }

    NAME_CONSTRAINTS_free(nc);
    X509_free(x509);
    x509 = NULL;
    nc = NULL;

    /* Test IP address constraint checking with cert-ext-ncip.pem
     * This cert has permitted IP 192.168.1.0/255.255.255.0 */
    if ((f = XFOPEN("./certs/test/cert-ext-ncip.pem", "rb")) == XBADFILE) {
        return TEST_SKIPPED;
    }
    x509 = PEM_read_X509(f, NULL, NULL, NULL);
    XFCLOSE(f);
    f = XBADFILE;

    if (x509 == NULL) {
        return TEST_SKIPPED;
    }

    nc = (NAME_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_name_constraints,
                                             NULL, NULL);
    ExpectNotNull(nc);

    if (EXPECT_SUCCESS()) {
        /* Test permitted IPs, within 192.168.1.0/24 subnet */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_IPADD,
            "192.168.1.1", 11), 1);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_IPADD,
            "192.168.1.50", 12), 1);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_IPADD,
            "192.168.1.254", 13), 1);

        /* Test non-permitted IPs, outside 192.168.1.0/24 subnet */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_IPADD,
            "192.168.2.1", 11), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_IPADD,
            "10.0.0.1", 8), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_IPADD,
            "8.8.8.8", 7), 0);

        /* Test invalid IP format */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_IPADD,
            "invalid", 7), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_IPADD,
            "256.1.1.1", 9), 0);
    }

    NAME_CONSTRAINTS_free(nc);
    X509_free(x509);

#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_CERTS && !NO_RSA &&
        * !IGNORE_NAME_CONSTRAINTS */
    return EXPECT_RESULT();
}

/*
 * Test DNS type name constraint checking with leading dot (subdomain matching).
 * Uses cert-ext-nc-combined.pem which has permitted;DNS:.wolfssl.com
 */
int test_wolfSSL_NAME_CONSTRAINTS_dns(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && !defined(IGNORE_NAME_CONSTRAINTS)
    XFILE f = XBADFILE;
    X509* x509 = NULL;
    NAME_CONSTRAINTS* nc = NULL;

    /* Test DNS constraint checking with cert-ext-nc-combined.pem
     * This cert has permitted DNS for .wolfssl.com (subdomains only) */
    f = XFOPEN("./certs/test/cert-ext-nc-combined.pem", "rb");
    if (f == XBADFILE) {
        return TEST_SKIPPED;
    }
    x509 = PEM_read_X509(f, NULL, NULL, NULL);
    XFCLOSE(f);
    f = XBADFILE;

    if (x509 == NULL) {
        return TEST_SKIPPED;
    }

    nc = (NAME_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_name_constraints,
                                             NULL, NULL);
    ExpectNotNull(nc);

    if (EXPECT_SUCCESS()) {
        /* Constraint is ".wolfssl.com" (leading dot). Per RFC 5280, this
         * matches DNS names that end with ".wolfssl.com" (subdomains only). */

        /* Subdomain DNS names, should match */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "www.wolfssl.com", 15), 1);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "mail.wolfssl.com", 16), 1);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "a.b.c.wolfssl.com", 17), 1);

        /* Exact domain, should not match .wolfssl.com per RFC */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "wolfssl.com", 11), 0);

        /* Different domains, should not match */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "www.example.com", 15), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "fakewolfssl.com", 15), 0);
    }

    NAME_CONSTRAINTS_free(nc);
    X509_free(x509);

#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_CERTS && !NO_RSA &&
        * !IGNORE_NAME_CONSTRAINTS */
    return EXPECT_RESULT();
}

/*
 * Test excluded name constraints.
 * Uses cert-ext-ncmulti.pem which has:
 *   permitted;DNS:.example.com, permitted;email:.example.com
 *   excluded;DNS:.blocked.example.com, excluded;email:.blocked.example.com
 */
int test_wolfSSL_NAME_CONSTRAINTS_excluded(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && !defined(IGNORE_NAME_CONSTRAINTS)
    XFILE f = XBADFILE;
    X509* x509 = NULL;
    NAME_CONSTRAINTS* nc = NULL;

    /* Test excluded constraint checking with cert-ext-ncmulti.pem
     * This cert permits .example.com but excludes .blocked.example.com */
    if ((f = XFOPEN("./certs/test/cert-ext-ncmulti.pem", "rb")) == XBADFILE) {
        return TEST_SKIPPED;
    }
    x509 = PEM_read_X509(f, NULL, NULL, NULL);
    XFCLOSE(f);
    f = XBADFILE;

    if (x509 == NULL) {
        return TEST_SKIPPED;
    }

    nc = (NAME_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_name_constraints,
                                             NULL, NULL);
    ExpectNotNull(nc);

    if (EXPECT_SUCCESS()) {
        /* Verify both permitted and excluded subtrees are populated */
        ExpectNotNull(nc->permittedSubtrees);
        ExpectNotNull(nc->excludedSubtrees);
        ExpectIntGT(sk_GENERAL_SUBTREE_num(nc->excludedSubtrees), 0);
    }

    if (EXPECT_SUCCESS()) {
        /* Permitted .example.com subdomains should be allowed */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "www.example.com", 15), 1);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "mail.example.com", 16), 1);

        /* Excluded .blocked.example.com, subdomains should be blocked */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "www.blocked.example.com", 23), 0);
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "sub.blocked.example.com", 23), 0);

        /* blocked.example.com is permitted because
         * .blocked.example.com (with leading dot) only matches subdomains
         * per RFC 5280, and it still matches the permitted .example.com
         * constraint */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "blocked.example.com", 19), 1);

        /* Domains outside permitted .example.com should not be allowed */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_DNS,
            "www.wolfssl.com", 15), 0);

        /* Permitted email .example.com subdomains should be allowed */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "user@www.example.com", 20), 1);

        /* Excluded email .blocked.example.com, should be blocked */
        ExpectIntEQ(wolfSSL_NAME_CONSTRAINTS_check_name(nc, GEN_EMAIL,
            "user@www.blocked.example.com", 28), 0);
    }

    NAME_CONSTRAINTS_free(nc);
    X509_free(x509);

#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_CERTS && !NO_RSA &&
        * !IGNORE_NAME_CONSTRAINTS */
    return EXPECT_RESULT();
}

