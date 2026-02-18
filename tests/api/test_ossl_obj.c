/* test_ossl_obj.c
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

#include <wolfssl/openssl/objects.h>
#include <wolfssl/openssl/pkcs12.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_obj.h>

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
int test_OBJ_NAME_do_all(void)
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

int test_wolfSSL_OBJ(void)
{
/* Password "wolfSSL test" is only 12 (96-bit) too short for testing in FIPS
 * mode
 */
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_SHA256) && !defined(NO_ASN) && \
    !defined(HAVE_FIPS) && !defined(NO_SHA) && defined(WOLFSSL_CERT_EXT) && \
    defined(WOLFSSL_CERT_GEN) && !defined(NO_BIO) && \
    !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
    ASN1_OBJECT *obj = NULL;
    ASN1_OBJECT *obj2 = NULL;
    char buf[50];

    XFILE fp = XBADFILE;
    X509 *x509 = NULL;
    X509_NAME *x509Name = NULL;
    X509_NAME_ENTRY *x509NameEntry = NULL;
    ASN1_OBJECT *asn1Name = NULL;
    int numNames = 0;
    BIO *bio = NULL;
    int nid;
    int i, j;
    const char *f[] = {
    #ifndef NO_RSA
        "./certs/ca-cert.der",
    #endif
    #ifdef HAVE_ECC
        "./certs/ca-ecc-cert.der",
        "./certs/ca-ecc384-cert.der",
    #endif
        NULL};
    ASN1_OBJECT *field_name_obj = NULL;
    int lastpos = -1;
    int tmp = -1;
    ASN1_STRING *asn1 = NULL;
    unsigned char *buf_dyn = NULL;

    ExpectIntEQ(OBJ_obj2txt(buf, (int)sizeof(buf), obj, 1),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectNotNull(obj = OBJ_nid2obj(NID_any_policy));
    ExpectIntEQ(OBJ_obj2nid(obj), NID_any_policy);
    ExpectIntEQ(OBJ_obj2txt(buf, (int)sizeof(buf), obj, 1), 11);
    ExpectIntGT(OBJ_obj2txt(buf, (int)sizeof(buf), obj, 0), 0);
    ASN1_OBJECT_free(obj);
    obj = NULL;

    ExpectNotNull(obj = OBJ_nid2obj(NID_sha256));
    ExpectIntEQ(OBJ_obj2nid(obj), NID_sha256);
    ExpectIntEQ(OBJ_obj2txt(buf, (int)sizeof(buf), obj, 1), 22);
#ifdef WOLFSSL_CERT_EXT
    ExpectIntEQ(OBJ_txt2nid(buf), NID_sha256);
#endif
    ExpectIntGT(OBJ_obj2txt(buf, (int)sizeof(buf), obj, 0), 0);
    ExpectNotNull(obj2 = OBJ_dup(obj));
    ExpectIntEQ(OBJ_cmp(obj, obj2), 0);
    ASN1_OBJECT_free(obj);
    obj = NULL;
    ASN1_OBJECT_free(obj2);
    obj2 = NULL;

    for (i = 0; f[i] != NULL; i++)
    {
        ExpectTrue((fp = XFOPEN(f[i], "rb")) != XBADFILE);
        ExpectNotNull(x509 = d2i_X509_fp(fp, NULL));
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }
        ExpectNotNull(x509Name = X509_get_issuer_name(x509));
        ExpectIntNE((numNames = X509_NAME_entry_count(x509Name)), 0);

        /* Get the Common Name by using OBJ_txt2obj */
        ExpectNotNull(field_name_obj = OBJ_txt2obj("CN", 0));
        ExpectIntEQ(X509_NAME_get_index_by_OBJ(NULL, NULL, 99),
            WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(X509_NAME_get_index_by_OBJ(x509Name, NULL, 99),
            WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(X509_NAME_get_index_by_OBJ(NULL, field_name_obj, 99),
            WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(X509_NAME_get_index_by_OBJ(x509Name, field_name_obj, 99),
            WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(X509_NAME_get_index_by_OBJ(x509Name, NULL, 0),
            WOLFSSL_FATAL_ERROR);
        do
        {
            lastpos = tmp;
            tmp = X509_NAME_get_index_by_OBJ(x509Name, field_name_obj, lastpos);
        } while (tmp > -1);
        ExpectIntNE(lastpos, -1);
        ASN1_OBJECT_free(field_name_obj);
        field_name_obj = NULL;
        ExpectNotNull(x509NameEntry = X509_NAME_get_entry(x509Name, lastpos));
        ExpectNotNull(asn1 = X509_NAME_ENTRY_get_data(x509NameEntry));
        ExpectIntGE(ASN1_STRING_to_UTF8(&buf_dyn, asn1), 0);
        /*
         * All Common Names should be www.wolfssl.com
         * This makes testing easier as we can test for the expected value.
         */
        ExpectStrEQ((char*)buf_dyn, "www.wolfssl.com");
        OPENSSL_free(buf_dyn);
        buf_dyn = NULL;
        bio = BIO_new(BIO_s_mem());
        ExpectTrue(bio != NULL);
        for (j = 0; j < numNames; j++)
        {
            ExpectNotNull(x509NameEntry = X509_NAME_get_entry(x509Name, j));
            ExpectNotNull(asn1Name = X509_NAME_ENTRY_get_object(x509NameEntry));
            ExpectTrue((nid = OBJ_obj2nid(asn1Name)) > 0);
        }
        BIO_free(bio);
        bio = NULL;
        X509_free(x509);
        x509 = NULL;

    }

#ifdef HAVE_PKCS12
    {
        PKCS12 *p12 = NULL;
        int boolRet;
        EVP_PKEY *pkey = NULL;
        const char *p12_f[] = {
            /* bundle uses AES-CBC 256 and PKCS7 key uses DES3 */
        #if !defined(NO_DES3) && defined(WOLFSSL_AES_256) && !defined(NO_RSA)
            "./certs/test-servercert.p12",
        #endif
            NULL
        };

        for (i = 0; p12_f[i] != NULL; i++)
        {
            ExpectTrue((fp = XFOPEN(p12_f[i], "rb")) != XBADFILE);
            ExpectNotNull(p12 = d2i_PKCS12_fp(fp, NULL));
            if (fp != XBADFILE) {
                XFCLOSE(fp);
                fp = XBADFILE;
            }
            ExpectTrue((boolRet = PKCS12_parse(p12, "wolfSSL test",
                                               &pkey, &x509, NULL)) > 0);
            wc_PKCS12_free(p12);
            p12 = NULL;
            EVP_PKEY_free(pkey);
            x509Name = X509_get_issuer_name(x509);
            ExpectNotNull(x509Name);
            ExpectIntNE((numNames = X509_NAME_entry_count(x509Name)), 0);
            ExpectTrue((bio = BIO_new(BIO_s_mem())) != NULL);
            for (j = 0; j < numNames; j++)
            {
                ExpectNotNull(x509NameEntry = X509_NAME_get_entry(x509Name, j));
                ExpectNotNull(asn1Name =
                        X509_NAME_ENTRY_get_object(x509NameEntry));
                ExpectTrue((nid = OBJ_obj2nid(asn1Name)) > 0);
            }
            BIO_free(bio);
            bio = NULL;
            X509_free(x509);
            x509 = NULL;
        }
    }
#endif /* HAVE_PKCS12 */
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_OBJ_cmp(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_SHA256)
    ASN1_OBJECT *obj = NULL;
    ASN1_OBJECT *obj2 = NULL;

    ExpectNotNull(obj = OBJ_nid2obj(NID_any_policy));
    ExpectNotNull(obj2 = OBJ_nid2obj(NID_sha256));

    ExpectIntEQ(OBJ_cmp(NULL, NULL), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(OBJ_cmp(obj, NULL), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(OBJ_cmp(NULL, obj2), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(OBJ_cmp(obj, obj2), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(OBJ_cmp(obj, obj), 0);
    ExpectIntEQ(OBJ_cmp(obj2, obj2), 0);

    ASN1_OBJECT_free(obj);
    ASN1_OBJECT_free(obj2);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_OBJ_txt2nid(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(WOLFSSL_APACHE_HTTPD)
    int i;
    static const struct {
        const char* sn;
        const char* ln;
        const char* oid;
        int nid;
    } testVals[] = {
#ifdef WOLFSSL_APACHE_HTTPD
        { "tlsfeature", "TLS Feature", "1.3.6.1.5.5.7.1.24", NID_tlsfeature },
        { "id-on-dnsSRV", "SRVName", "1.3.6.1.5.5.7.8.7",
                                                             NID_id_on_dnsSRV },
        { "msUPN", "Microsoft User Principal Name",
                                         "1.3.6.1.4.1.311.20.2.3", NID_ms_upn },
#endif
        { NULL, NULL, NULL, NID_undef }
    };

    /* Invalid cases */
    ExpectIntEQ(OBJ_txt2nid(NULL), NID_undef);
    ExpectIntEQ(OBJ_txt2nid("Bad name"), NID_undef);

    /* Valid cases */
    for (i = 0; testVals[i].sn != NULL; i++) {
        ExpectIntEQ(OBJ_txt2nid(testVals[i].sn), testVals[i].nid);
        ExpectIntEQ(OBJ_txt2nid(testVals[i].ln), testVals[i].nid);
        ExpectIntEQ(OBJ_txt2nid(testVals[i].oid), testVals[i].nid);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_OBJ_txt2obj(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_APACHE_HTTPD) || (defined(OPENSSL_EXTRA) && \
        defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_CERT_GEN))
    int i;
    char buf[50];
    ASN1_OBJECT* obj = NULL;
    static const struct {
        const char* oidStr;
        const char* sn;
        const char* ln;
    } objs_list[] = {
    #if defined(WOLFSSL_APACHE_HTTPD)
        { "1.3.6.1.5.5.7.1.24", "tlsfeature", "TLS Feature" },
        { "1.3.6.1.5.5.7.8.7", "id-on-dnsSRV", "SRVName" },
    #endif
        { "2.5.29.19", "basicConstraints", "X509v3 Basic Constraints"},
        { NULL, NULL, NULL }
    };
    static const struct {
        const char* numeric;
        const char* name;
    } objs_named[] = {
        /* In dictionary but not in normal list. */
        { "1.3.6.1.5.5.7.3.8", "Time Stamping" },
        /* Made up OID. */
        { "1.3.5.7",           "1.3.5.7" },
        { NULL, NULL }
    };

    ExpectNull(obj = OBJ_txt2obj("Bad name", 0));
    ASN1_OBJECT_free(obj);
    obj = NULL;
    ExpectNull(obj = OBJ_txt2obj(NULL, 0));
    ASN1_OBJECT_free(obj);
    obj = NULL;

    for (i = 0; objs_list[i].oidStr != NULL; i++) {
        /* Test numerical value of oid (oidStr) */
        ExpectNotNull(obj = OBJ_txt2obj(objs_list[i].oidStr, 1));
        /* Convert object back to text to confirm oid is correct */
        wolfSSL_OBJ_obj2txt(buf, (int)sizeof(buf), obj, 1);
        ExpectIntEQ(XSTRNCMP(buf, objs_list[i].oidStr, (int)XSTRLEN(buf)), 0);
        ASN1_OBJECT_free(obj);
        obj = NULL;
       XMEMSET(buf, 0, sizeof(buf));

        /* Test short name (sn) */
        ExpectNull(obj = OBJ_txt2obj(objs_list[i].sn, 1));
        ExpectNotNull(obj = OBJ_txt2obj(objs_list[i].sn, 0));
        /* Convert object back to text to confirm oid is correct */
        wolfSSL_OBJ_obj2txt(buf, (int)sizeof(buf), obj, 1);
        ExpectIntEQ(XSTRNCMP(buf, objs_list[i].oidStr, (int)XSTRLEN(buf)), 0);
        ASN1_OBJECT_free(obj);
        obj = NULL;
        XMEMSET(buf, 0, sizeof(buf));

        /* Test long name (ln) - should fail when no_name = 1 */
        ExpectNull(obj = OBJ_txt2obj(objs_list[i].ln, 1));
        ExpectNotNull(obj = OBJ_txt2obj(objs_list[i].ln, 0));
        /* Convert object back to text to confirm oid is correct */
        wolfSSL_OBJ_obj2txt(buf, (int)sizeof(buf), obj, 1);
        ExpectIntEQ(XSTRNCMP(buf, objs_list[i].oidStr, (int)XSTRLEN(buf)), 0);
        ASN1_OBJECT_free(obj);
        obj = NULL;
        XMEMSET(buf, 0, sizeof(buf));
    }

    for (i = 0; objs_named[i].numeric != NULL; i++) {
        ExpectNotNull(obj = OBJ_txt2obj(objs_named[i].numeric, 1));
        wolfSSL_OBJ_obj2txt(buf, (int)sizeof(buf), obj, 0);
        ExpectIntEQ(XSTRNCMP(buf, objs_named[i].name, (int)XSTRLEN(buf)), 0);
        wolfSSL_OBJ_obj2txt(buf, (int)sizeof(buf), obj, 1);
        ExpectIntEQ(XSTRNCMP(buf, objs_named[i].numeric, (int)XSTRLEN(buf)), 0);
        ASN1_OBJECT_free(obj);
        obj = NULL;
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_OBJ_ln(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
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
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_OBJ_sn(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
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
#endif
    return EXPECT_RESULT();
}

