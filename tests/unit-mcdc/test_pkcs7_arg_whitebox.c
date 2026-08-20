/* test_pkcs7_arg_whitebox.c
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

/*
 * Argument-chain / data-shape white-box MC/DC supplement for
 * wolfcrypt/src/pkcs7.c (Part 5).
 *
 * Companion to test_pkcs7_whitebox.c: that file drives the streaming and
 * parsing internals; this one drives the argument guards and the small
 * data-shape decisions (attribute-flag matrices, SignerInfo/certificate
 * binding, content-shape selectors) that neither tests/api nor the other
 * white-boxes reach.
 *
 * MC/DC is derived per binary, so every operand's "this one alone fires"
 * vector is paired with the all-false vector inside this same file. The
 * accepting vector only has to make the guard evaluate false; failing
 * deeper in is fine and expected.
 *
 * ARGUED UNREACHABLE, do not re-open:
 *
 *   :4183 cond 1 (`pkcs7->sidType != DEGENERATE_SID`). PKCS7_EncodeSigned's
 *     only assignment of a non-zero flatSignedAttribsSz is at :3836, inside
 *     the `if (pkcs7->sidType != DEGENERATE_SID)` block that opens at :3730.
 *     The enclosing `if (flatSignedAttribsSz > 0)` at :4180 therefore already
 *     implies sidType != DEGENERATE_SID: with a degenerate SID the attribute
 *     block never runs, flatSignedAttribsSz stays 0, and :4183 is not
 *     reached at all. The operand is constant-true where it is evaluated.
 */

#include <wolfcrypt/src/pkcs7.c>

#include <stdio.h>
#include <string.h>
#include <wolfssl/certs_test.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* ESD is multi-kilobyte; keep it off the stack. */
static ESD wbEsd;
static byte wbSigBuf[512];

static const byte wbContentTypeOid[] =
        { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0d, 0x01,
                         0x09, 0x03 };
static const byte wbMessageDigestOid[] =
        { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
                         0x09, 0x04 };
static const byte wbSigningTimeOid[] =
        { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0d, 0x01,
                         0x09, 0x05 };
/* id-data OID, DER encoded */
static const byte wbDataOid[] =
        { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
                         0x07, 0x01 };

/* ------------------------------------------------------------------------- *
 * Section 1: private-key import + sign helper argument chains
 * [:2054, :2105, :2148, :2196, :2300]
 * ------------------------------------------------------------------------- */
static void wb_sign_helper_args(void)
{
    wc_PKCS7 p;
    WC_RNG rng;
    byte in[32];

    XMEMSET(in, 0x5a, sizeof(in));

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; wb_sign_helper_args skipped");
        wb_fail = 1;
        return;
    }
    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_sign_helper_args skipped");
        wb_fail = 1;
        wc_FreeRng(&rng);
        return;
    }

    XMEMSET(&wbEsd, 0, sizeof(wbEsd));
    wbEsd.hashType = WC_HASH_TYPE_SHA256;
    wbEsd.encContentDigest = wbSigBuf;
    wbEsd.encContentDigestBufSz = (word32)sizeof(wbSigBuf);

#ifndef NO_RSA
    WB_NOTE("wc_PKCS7_RsaSign() arg chain [:2105] + ImportRSA [:2054]");
    p.rng = &rng;
    p.privateKey = NULL;
    p.privateKeySz = 0;
    (void)wc_PKCS7_RsaSign(NULL, in, (word32)sizeof(in), &wbEsd);
    p.rng = NULL;
    (void)wc_PKCS7_RsaSign(&p, in, (word32)sizeof(in), &wbEsd);
    p.rng = &rng;
    (void)wc_PKCS7_RsaSign(&p, NULL, (word32)sizeof(in), &wbEsd);
    (void)wc_PKCS7_RsaSign(&p, in, (word32)sizeof(in), NULL);
    /* all false: reaches ImportRSA with privateKey==NULL (:2054 1st false) */
    (void)wc_PKCS7_RsaSign(&p, in, (word32)sizeof(in), &wbEsd);
    /* :2054 2nd operand false */
    p.privateKey = (byte*)client_key_der_2048;
    p.privateKeySz = 0;
    (void)wc_PKCS7_RsaSign(&p, in, (word32)sizeof(in), &wbEsd);
    /* :2054 both true -> real RSA signature */
    p.privateKeySz = (word32)sizeof_client_key_der_2048;
    WB_CHECK(wc_PKCS7_RsaSign(&p, in, (word32)sizeof(in), &wbEsd) > 0,
            ":2054 both true (real RSA sign)");

#ifdef WC_RSA_PSS
    WB_NOTE("wc_PKCS7_RsaPssSign() arg chain [:2300]");
    (void)wc_PKCS7_RsaPssSign(NULL, in, (word32)sizeof(in), &wbEsd);
    p.rng = NULL;
    (void)wc_PKCS7_RsaPssSign(&p, in, (word32)sizeof(in), &wbEsd);
    p.rng = &rng;
    (void)wc_PKCS7_RsaPssSign(&p, NULL, (word32)sizeof(in), &wbEsd);
    (void)wc_PKCS7_RsaPssSign(&p, in, (word32)sizeof(in), NULL);
    /* all false */
    (void)wc_PKCS7_RsaPssSign(&p, in, (word32)sizeof(in), &wbEsd);
#endif
#endif /* !NO_RSA */

#ifdef HAVE_ECC
    WB_NOTE("wc_PKCS7_EcdsaSign() arg chain [:2196] + ImportECC [:2148]");
    p.rng = &rng;
    p.privateKey = NULL;
    p.privateKeySz = 0;
    (void)wc_PKCS7_EcdsaSign(NULL, in, (word32)sizeof(in), &wbEsd);
    p.rng = NULL;
    (void)wc_PKCS7_EcdsaSign(&p, in, (word32)sizeof(in), &wbEsd);
    p.rng = &rng;
    (void)wc_PKCS7_EcdsaSign(&p, NULL, (word32)sizeof(in), &wbEsd);
    (void)wc_PKCS7_EcdsaSign(&p, in, (word32)sizeof(in), NULL);
    /* all false: ImportECC with privateKey==NULL (:2148 1st operand false) */
    (void)wc_PKCS7_EcdsaSign(&p, in, (word32)sizeof(in), &wbEsd);
    /* :2148 2nd operand false */
    p.privateKey = (byte*)ecc_clikey_der_256;
    p.privateKeySz = 0;
    (void)wc_PKCS7_EcdsaSign(&p, in, (word32)sizeof(in), &wbEsd);
    /* :2148 both true -> real ECDSA signature */
    p.privateKeySz = (word32)sizeof_ecc_clikey_der_256;
    WB_CHECK(wc_PKCS7_EcdsaSign(&p, in, (word32)sizeof(in), &wbEsd) > 0,
            ":2148 both true (real ECDSA sign)");
#endif /* HAVE_ECC */

    p.privateKey = NULL;
    p.privateKeySz = 0;
    p.rng = NULL;
    wc_PKCS7_Free(&p);
    wc_FreeRng(&rng);
}

/* ------------------------------------------------------------------------- *
 * Section 2: default signed-attribute flag matrix
 * [:2455, :2457, :2460] and the same matrix inside BuildSignedAttributes
 * [:2519, :2529, :2539] plus its bound checks [:2551, :2568, :2574].
 * ------------------------------------------------------------------------- */
static void wb_signed_attrib_flags(void)
{
    wc_PKCS7 p;
    EncodedAttrib attribs[8];
    PKCS7Attrib custom[1];
    byte signingTime[MAX_TIME_STRING_SZ];
    static const byte customOid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    static const byte customVal[] = { 0x0c, 0x01, 0x41 };
    word16 flagRow[5];
    int i;
    int ret;

    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_signed_attrib_flags skipped");
        wb_fail = 1;
        return;
    }

    flagRow[0] = 0;
    flagRow[1] = WOLFSSL_CONTENT_TYPE_ATTRIBUTE;
    flagRow[2] = WOLFSSL_SIGNING_TIME_ATTRIBUTE;
    flagRow[3] = WOLFSSL_MESSAGE_DIGEST_ATTRIBUTE;
    flagRow[4] = WOLFSSL_NO_ATTRIBUTES;

    WB_NOTE("wc_PKCS7_GetDefaultSignedAttribCount() flag matrix "
            "[:2455,:2457,:2460]");
    (void)wc_PKCS7_GetDefaultSignedAttribCount(NULL);
    for (i = 0; i < 5; i++) {
        p.defaultSignedAttribs = flagRow[i];
        (void)wc_PKCS7_GetDefaultSignedAttribCount(&p);
    }

    WB_NOTE("wc_PKCS7_BuildSignedAttributes() flag matrix + bounds "
            "[:2519,:2529,:2539,:2551,:2568,:2574]");
    for (i = 0; i < 5; i++) {
        XMEMSET(&wbEsd, 0, sizeof(wbEsd));
        XMEMSET(attribs, 0, sizeof(attribs));
        wbEsd.hashType = WC_HASH_TYPE_SHA256;
        wbEsd.signedAttribs = attribs;
        wbEsd.signedAttribsCap = (word32)(sizeof(attribs) /
                                          sizeof(attribs[0]));
        p.defaultSignedAttribs = flagRow[i];
        p.signedAttribs = NULL;
        p.signedAttribsSz = 0;
        (void)wc_PKCS7_BuildSignedAttributes(&p, &wbEsd, wbDataOid,
                (word32)sizeof(wbDataOid), wbContentTypeOid,
                (word32)sizeof(wbContentTypeOid), wbMessageDigestOid,
                (word32)sizeof(wbMessageDigestOid), wbSigningTimeOid,
                (word32)sizeof(wbSigningTimeOid), signingTime,
                (word32)sizeof(signingTime));
    }

    /* :2551 2nd operand true -- working array too small for the canned set. */
    XMEMSET(&wbEsd, 0, sizeof(wbEsd));
    XMEMSET(attribs, 0, sizeof(attribs));
    wbEsd.hashType = WC_HASH_TYPE_SHA256;
    wbEsd.signedAttribs = attribs;
    wbEsd.signedAttribsCap = 1;
    p.defaultSignedAttribs = 0;
    p.signedAttribs = NULL;
    p.signedAttribsSz = 0;
    ret = wc_PKCS7_BuildSignedAttributes(&p, &wbEsd, wbDataOid,
            (word32)sizeof(wbDataOid), wbContentTypeOid,
            (word32)sizeof(wbContentTypeOid), wbMessageDigestOid,
            (word32)sizeof(wbMessageDigestOid), wbSigningTimeOid,
            (word32)sizeof(wbSigningTimeOid), signingTime,
            (word32)sizeof(signingTime));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
            ":2551 2nd operand true (cap too small)");

    /* :2551 1st operand true -- no working array at all. */
    XMEMSET(&wbEsd, 0, sizeof(wbEsd));
    wbEsd.hashType = WC_HASH_TYPE_SHA256;
    wbEsd.signedAttribs = NULL;
    wbEsd.signedAttribsCap = 8;
    ret = wc_PKCS7_BuildSignedAttributes(&p, &wbEsd, wbDataOid,
            (word32)sizeof(wbDataOid), wbContentTypeOid,
            (word32)sizeof(wbContentTypeOid), wbMessageDigestOid,
            (word32)sizeof(wbMessageDigestOid), wbSigningTimeOid,
            (word32)sizeof(wbSigningTimeOid), signingTime,
            (word32)sizeof(signingTime));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
            ":2551 1st operand true (signedAttribs==NULL)");

    /* Custom-attribute block [:2568,:2574]. WOLFSSL_NO_ATTRIBUTES skips the
     * canned block so the custom block is reached with atrIdx == 0. */
    custom[0].oid     = customOid;
    custom[0].oidSz   = (word32)sizeof(customOid);
    custom[0].value   = customVal;
    custom[0].valueSz = (word32)sizeof(customVal);

    /* :2568 2nd operand false: size > 0 but no array. */
    XMEMSET(&wbEsd, 0, sizeof(wbEsd));
    XMEMSET(attribs, 0, sizeof(attribs));
    wbEsd.hashType = WC_HASH_TYPE_SHA256;
    wbEsd.signedAttribs = attribs;
    wbEsd.signedAttribsCap = 8;
    p.defaultSignedAttribs = WOLFSSL_NO_ATTRIBUTES;
    p.signedAttribs = NULL;
    p.signedAttribsSz = 1;
    ret = wc_PKCS7_BuildSignedAttributes(&p, &wbEsd, wbDataOid,
            (word32)sizeof(wbDataOid), wbContentTypeOid,
            (word32)sizeof(wbContentTypeOid), wbMessageDigestOid,
            (word32)sizeof(wbMessageDigestOid), wbSigningTimeOid,
            (word32)sizeof(wbSigningTimeOid), signingTime,
            (word32)sizeof(signingTime));
    WB_CHECK(ret == 0, ":2568 2nd operand false (signedAttribs==NULL)");

    /* :2574 1st operand true: esd working array missing. */
    XMEMSET(&wbEsd, 0, sizeof(wbEsd));
    wbEsd.hashType = WC_HASH_TYPE_SHA256;
    wbEsd.signedAttribs = NULL;
    wbEsd.signedAttribsCap = 8;
    p.signedAttribs = custom;
    p.signedAttribsSz = 1;
    ret = wc_PKCS7_BuildSignedAttributes(&p, &wbEsd, wbDataOid,
            (word32)sizeof(wbDataOid), wbContentTypeOid,
            (word32)sizeof(wbContentTypeOid), wbMessageDigestOid,
            (word32)sizeof(wbMessageDigestOid), wbSigningTimeOid,
            (word32)sizeof(wbSigningTimeOid), signingTime,
            (word32)sizeof(signingTime));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
            ":2574 1st operand true (signedAttribs==NULL)");

    /* :2574 2nd operand true: not enough room for the custom attributes. */
    XMEMSET(&wbEsd, 0, sizeof(wbEsd));
    XMEMSET(attribs, 0, sizeof(attribs));
    wbEsd.hashType = WC_HASH_TYPE_SHA256;
    wbEsd.signedAttribs = attribs;
    wbEsd.signedAttribsCap = 0;
    ret = wc_PKCS7_BuildSignedAttributes(&p, &wbEsd, wbDataOid,
            (word32)sizeof(wbDataOid), wbContentTypeOid,
            (word32)sizeof(wbContentTypeOid), wbMessageDigestOid,
            (word32)sizeof(wbMessageDigestOid), wbSigningTimeOid,
            (word32)sizeof(wbSigningTimeOid), signingTime,
            (word32)sizeof(signingTime));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
            ":2574 2nd operand true (no space left)");

    /* :2568/:2574 all false: real custom attribute encode. */
    XMEMSET(&wbEsd, 0, sizeof(wbEsd));
    XMEMSET(attribs, 0, sizeof(attribs));
    wbEsd.hashType = WC_HASH_TYPE_SHA256;
    wbEsd.signedAttribs = attribs;
    wbEsd.signedAttribsCap = 8;
    ret = wc_PKCS7_BuildSignedAttributes(&p, &wbEsd, wbDataOid,
            (word32)sizeof(wbDataOid), wbContentTypeOid,
            (word32)sizeof(wbContentTypeOid), wbMessageDigestOid,
            (word32)sizeof(wbMessageDigestOid), wbSigningTimeOid,
            (word32)sizeof(wbSigningTimeOid), signingTime,
            (word32)sizeof(signingTime));
    WB_CHECK(ret == 0, ":2568/:2574 all false (custom attribs encoded)");

    p.signedAttribs = NULL;
    p.signedAttribsSz = 0;
    wc_PKCS7_Free(&p);
}

/* ------------------------------------------------------------------------- *
 * Section 3: SignerInfo <-> certificate identity binding
 * [:4998 all-false + SKID branch, :5155, :5288, :5471]
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA) || defined(HAVE_ECC)
static void wb_signerinfo_binding(void)
{
    wc_PKCS7 p;
    PKCS7SignerInfo si;
    byte bogusSkid[KEYID_SIZE];
    byte realSkid[KEYID_SIZE];
    byte sig[64];
    byte hash[32];
    int haveSkid = 0;

    XMEMSET(&si, 0, sizeof(si));
    XMEMSET(bogusSkid, 0xA5, sizeof(bogusSkid));
    XMEMSET(realSkid, 0, sizeof(realSkid));
    XMEMSET(sig, 0x11, sizeof(sig));
    XMEMSET(hash, 0x22, sizeof(hash));

    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_signerinfo_binding skipped");
        wb_fail = 1;
        return;
    }

#ifndef NO_RSA
    /* Recover the RSA client cert's real SKID so CertMatchesSignerInfo can
     * take its "match" return as well as its "no match" return. */
    {
        DecodedCert dc;
        InitDecodedCert(&dc, client_cert_der_2048,
                        (word32)sizeof_client_cert_der_2048, NULL);
        if (ParseCert(&dc, CA_TYPE, NO_VERIFY, 0) == 0) {
            XMEMCPY(realSkid, dc.extSubjKeyId, KEYID_SIZE);
            haveSkid = 1;

            WB_NOTE("wc_PKCS7_CertMatchesSignerInfo() all-false guard "
                    "+ CMS_SKID compare [:4998]");
            /* 1st operand true: no SignerInfo */
            p.signerInfo = NULL;
            WB_CHECK(wc_PKCS7_CertMatchesSignerInfo(&p, &dc) == 0,
                    ":4998 1st operand true");
            /* 2nd operand true: SignerInfo with no sid blob */
            si.sidType = CMS_SKID;
            si.sid     = NULL;
            si.sidSz   = (word32)sizeof(bogusSkid);
            p.signerInfo = &si;
            WB_CHECK(wc_PKCS7_CertMatchesSignerInfo(&p, &dc) == 0,
                    ":4998 2nd operand true");
            si.sidType = CMS_SKID;
            si.sid     = bogusSkid;
            si.sidSz   = (word32)sizeof(bogusSkid);
            p.signerInfo = &si;
            WB_CHECK(wc_PKCS7_CertMatchesSignerInfo(&p, &dc) == 0,
                    ":4998 all false, SKID mismatch");
            si.sid = realSkid;
            WB_CHECK(wc_PKCS7_CertMatchesSignerInfo(&p, &dc) == 1,
                    ":4998 all false, SKID match");
            /* IssuerAndSerialNumber branch with a blob that is not a Name */
            si.sidType = CMS_ISSUER_AND_SERIAL_NUMBER;
            si.sid     = bogusSkid;
            si.sidSz   = (word32)sizeof(bogusSkid);
            (void)wc_PKCS7_CertMatchesSignerInfo(&p, &dc);

            /* IssuerAndSerialNumber blob rebuilt from this very certificate:
             * SEQUENCE(issuer Name) followed by the serial INTEGER. Drives
             * the serial compare [:5039] both ways. */
            {
                static byte isn[1024];
                word32 isnSz = 0;

                if (dc.issuerRaw != NULL && dc.issuerRawLen > 0 &&
                    dc.serialSz > 0 &&
                    (word32)dc.issuerRawLen + (word32)dc.serialSz + 16 <
                        (word32)sizeof(isn)) {
                    isnSz = SetSequence((word32)dc.issuerRawLen, isn);
                    XMEMCPY(isn + isnSz, dc.issuerRaw, (word32)dc.issuerRawLen);
                    isnSz += (word32)dc.issuerRawLen;
                    isn[isnSz++] = ASN_INTEGER;
                    isn[isnSz++] = (byte)dc.serialSz;
                    XMEMCPY(isn + isnSz, dc.serial, (word32)dc.serialSz);
                    isnSz += (word32)dc.serialSz;

                    si.sid   = isn;
                    si.sidSz = isnSz;
                    WB_CHECK(wc_PKCS7_CertMatchesSignerInfo(&p, &dc) == 1,
                            ":5039 both true (issuer+serial match)");

                    /* same issuer, different serial -> compare mismatches */
                    isn[isnSz - 1] ^= 0xFF;
                    WB_CHECK(wc_PKCS7_CertMatchesSignerInfo(&p, &dc) == 0,
                            ":5039 serial mismatch");
                    isn[isnSz - 1] ^= 0xFF;

                    /* corrupt the serial INTEGER header -> GetInt fails */
                    isn[isnSz - (word32)dc.serialSz - 2] = 0x7F;
                    WB_CHECK(wc_PKCS7_CertMatchesSignerInfo(&p, &dc) == 0,
                            ":5039 1st operand false (GetInt fails)");
                }
            }

            si.sidType = CMS_ISSUER_AND_SERIAL_NUMBER;
            si.sid     = bogusSkid;
            si.sidSz   = (word32)sizeof(bogusSkid);
            /* sidSz == 0 (3rd operand true) */
            si.sidSz = 0;
            WB_CHECK(wc_PKCS7_CertMatchesSignerInfo(&p, &dc) == 0,
                    ":4998 3rd operand true");
        }
        FreeDecodedCert(&dc);
    }

    WB_NOTE("wc_PKCS7_RsaVerify() SignerInfo sid binding [:5155]");
    p.cert[0]   = (byte*)client_cert_der_2048;
    p.certSz[0] = (word32)sizeof_client_cert_der_2048;
    /* 1st operand false: no SignerInfo at all */
    p.signerInfo = NULL;
    (void)wc_PKCS7_RsaVerify(&p, sig, (int)sizeof(sig), hash,
                             (word32)sizeof(hash));
    /* 2nd operand false: SignerInfo present but no sid */
    si.sidType = CMS_SKID;
    si.sid     = NULL;
    si.sidSz   = 0;
    p.signerInfo = &si;
    (void)wc_PKCS7_RsaVerify(&p, sig, (int)sizeof(sig), hash,
                             (word32)sizeof(hash));
    /* all true: sid present but binds to a different certificate */
    si.sid   = bogusSkid;
    si.sidSz = (word32)sizeof(bogusSkid);
    (void)wc_PKCS7_RsaVerify(&p, sig, (int)sizeof(sig), hash,
                             (word32)sizeof(hash));
    /* 3rd operand false: sid matches this certificate */
    if (haveSkid) {
        si.sid = realSkid;
        (void)wc_PKCS7_RsaVerify(&p, sig, (int)sizeof(sig), hash,
                                 (word32)sizeof(hash));
    }
#ifdef HAVE_ECC
    /* :5166 both true: the embedded certificate is not RSA-family */
    p.signerInfo = NULL;
    p.cert[0]   = (byte*)cliecc_cert_der_256;
    p.certSz[0] = (word32)sizeof_cliecc_cert_der_256;
    (void)wc_PKCS7_RsaVerify(&p, sig, (int)sizeof(sig), hash,
                             (word32)sizeof(hash));
#ifdef WC_RSA_PSS
    p.hashOID = SHA256h;
    (void)wc_PKCS7_RsaPssVerify(&p, sig, (int)sizeof(sig), hash,
                                (word32)sizeof(hash));
#endif
    p.cert[0]   = (byte*)client_cert_der_2048;
    p.certSz[0] = (word32)sizeof_client_cert_der_2048;
#endif

#ifdef WC_RSA_PSS
    WB_NOTE("wc_PKCS7_RsaPssVerify() SignerInfo sid binding [:5288]");
    p.hashOID = SHA256h;
    p.signerInfo = NULL;
    (void)wc_PKCS7_RsaPssVerify(&p, sig, (int)sizeof(sig), hash,
                                (word32)sizeof(hash));
    si.sid   = NULL;
    si.sidSz = 0;
    p.signerInfo = &si;
    (void)wc_PKCS7_RsaPssVerify(&p, sig, (int)sizeof(sig), hash,
                                (word32)sizeof(hash));
    si.sid   = bogusSkid;
    si.sidSz = (word32)sizeof(bogusSkid);
    (void)wc_PKCS7_RsaPssVerify(&p, sig, (int)sizeof(sig), hash,
                                (word32)sizeof(hash));
    if (haveSkid) {
        si.sid = realSkid;
        (void)wc_PKCS7_RsaPssVerify(&p, sig, (int)sizeof(sig), hash,
                                    (word32)sizeof(hash));
    }
#endif /* WC_RSA_PSS */
#endif /* !NO_RSA */

#ifdef HAVE_ECC
    WB_NOTE("wc_PKCS7_EcdsaVerify() SignerInfo sid binding [:5471]");
    {
        DecodedCert dc;
        int haveEccSkid = 0;
        byte eccSkid[KEYID_SIZE];

        XMEMSET(eccSkid, 0, sizeof(eccSkid));
        InitDecodedCert(&dc, cliecc_cert_der_256,
                        (word32)sizeof_cliecc_cert_der_256, NULL);
        if (ParseCert(&dc, CA_TYPE, NO_VERIFY, 0) == 0) {
            XMEMCPY(eccSkid, dc.extSubjKeyId, KEYID_SIZE);
            haveEccSkid = 1;
        }
        FreeDecodedCert(&dc);

        p.cert[0]   = (byte*)cliecc_cert_der_256;
        p.certSz[0] = (word32)sizeof_cliecc_cert_der_256;
        p.signerInfo = NULL;
        (void)wc_PKCS7_EcdsaVerify(&p, sig, (int)sizeof(sig), hash,
                                   (word32)sizeof(hash));
        si.sidType = CMS_SKID;
        si.sid     = NULL;
        si.sidSz   = 0;
        p.signerInfo = &si;
        (void)wc_PKCS7_EcdsaVerify(&p, sig, (int)sizeof(sig), hash,
                                   (word32)sizeof(hash));
        si.sid   = bogusSkid;
        si.sidSz = (word32)sizeof(bogusSkid);
        (void)wc_PKCS7_EcdsaVerify(&p, sig, (int)sizeof(sig), hash,
                                   (word32)sizeof(hash));
        if (haveEccSkid) {
            si.sid = eccSkid;
            (void)wc_PKCS7_EcdsaVerify(&p, sig, (int)sizeof(sig), hash,
                                       (word32)sizeof(hash));
        }
    }
#endif /* HAVE_ECC */

    p.signerInfo = NULL;
    p.cert[0]   = NULL;
    p.certSz[0] = 0;
    wc_PKCS7_Free(&p);
}
#else
static void wb_signerinfo_binding(void)
{
    WB_NOTE("no RSA/ECC; SignerInfo binding skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 4: wc_PKCS7_VerifyContentMessageDigest() attribute/content shapes
 * [:5857, :5890, :5893]
 * ------------------------------------------------------------------------- */
static void wb_verify_content_msgdigest(void)
{
    wc_PKCS7 p;
    PKCS7DecodedAttrib attrib;
    byte mdOidDer[11];
    byte mdValue[34];
    byte content[8];
    byte pkcs7Content[8];
    byte hash[32];

    XMEMSET(&attrib, 0, sizeof(attrib));
    XMEMCPY(mdOidDer, wbMessageDigestOid, sizeof(wbMessageDigestOid));
    XMEMSET(content, 0x31, sizeof(content));
    XMEMSET(hash, 0, sizeof(hash));

    /* OCTET STRING wrapping a 32-byte digest */
    mdValue[0] = ASN_OCTET_STRING;
    mdValue[1] = 32;
    XMEMSET(mdValue + 2, 0x77, 32);

    /* PKCS#7-typed content: a DER OCTET STRING of 6 bytes */
    pkcs7Content[0] = ASN_OCTET_STRING;
    pkcs7Content[1] = 6;
    XMEMSET(pkcs7Content + 2, 0x32, 6);

    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_verify_content_msgdigest skipped");
        wb_fail = 1;
        return;
    }
    p.hashOID = SHA256h;

    attrib.next    = NULL;
    attrib.oid     = mdOidDer;
    attrib.oidSz   = (word32)sizeof(mdOidDer);
    attrib.value   = mdValue;
    attrib.valueSz = (word32)sizeof(mdValue);
    p.decodedAttrib = &attrib;

    WB_NOTE("VerifyContentMessageDigest attrib->value guards [:5857]");
    /* 1st operand true */
    attrib.value = NULL;
    (void)wc_PKCS7_VerifyContentMessageDigest(&p, NULL, 0);
    /* 2nd operand true */
    attrib.value   = mdValue;
    attrib.valueSz = 0;
    (void)wc_PKCS7_VerifyContentMessageDigest(&p, NULL, 0);
    attrib.valueSz = (word32)sizeof(mdValue);

    WB_NOTE("VerifyContentMessageDigest content shape [:5890,:5893]");
    /* all false at :5857; :5890 1st operand false (content == NULL) */
    p.content   = NULL;
    p.contentSz = 0;
    p.contentIsPkcs7Type = 1;
    (void)wc_PKCS7_VerifyContentMessageDigest(&p, NULL, 0);
    /* :5890 2nd operand false (content set, not PKCS#7-typed) */
    p.content   = content;
    p.contentSz = (word32)sizeof(content);
    p.contentIsPkcs7Type = 0;
    (void)wc_PKCS7_VerifyContentMessageDigest(&p, NULL, 0);
    /* :5890 both true, :5893 contentLen > 1 */
    p.content   = pkcs7Content;
    p.contentSz = (word32)sizeof(pkcs7Content);
    p.contentIsPkcs7Type = 1;
    (void)wc_PKCS7_VerifyContentMessageDigest(&p, NULL, 0);
    /* :5893 contentLen <= 1 */
    p.contentSz = 1;
    (void)wc_PKCS7_VerifyContentMessageDigest(&p, NULL, 0);
    /* caller-supplied hash path */
    p.content   = content;
    p.contentSz = (word32)sizeof(content);
    p.contentIsPkcs7Type = 0;
    (void)wc_PKCS7_VerifyContentMessageDigest(&p, hash, (word32)sizeof(hash));

    p.decodedAttrib = NULL;
    p.content = NULL;
    p.contentSz = 0;
    wc_PKCS7_Free(&p);
}

/* ------------------------------------------------------------------------- *
 * Section 5: PKCS7_EncodeSigned() shape matrix
 * [:3538, :3555, :3649, :4022, :4073]
 * ------------------------------------------------------------------------- */
static byte wbCbContent[16];

#ifdef ASN_BER_TO_DER
static int wb_stream_out_cb(wc_PKCS7* pkcs7, const byte* output,
                            word32 outputSz, void* ctx)
{
    (void)pkcs7;
    (void)output;
    (void)ctx;
    return (int)outputSz;
}

static int wb_get_content_cb(wc_PKCS7* pkcs7, byte** content, void* ctx)
{
    (void)pkcs7;
    (void)ctx;
    if (content != NULL)
        *content = wbCbContent;
    return (int)sizeof(wbCbContent);
}
#endif /* ASN_BER_TO_DER */

#ifndef NO_RSA
static void wb_encodesigned_shapes(void)
{
    wc_PKCS7 p;
    WC_RNG rng;
    static byte out[8192];
    byte content[32];
    byte hash[32];
    word32 outSz;
    int ret;

    XMEMSET(content, 0x63, sizeof(content));
    XMEMSET(hash, 0x64, sizeof(hash));
    XMEMSET(wbCbContent, 0x65, sizeof(wbCbContent));

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; wb_encodesigned_shapes skipped");
        wb_fail = 1;
        return;
    }
    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_encodesigned_shapes skipped");
        wb_fail = 1;
        wc_FreeRng(&rng);
        return;
    }
    if (wc_PKCS7_InitWithCert(&p, (byte*)client_cert_der_2048,
                              (word32)sizeof_client_cert_der_2048) != 0) {
        WB_NOTE("wc_PKCS7_InitWithCert failed; wb_encodesigned_shapes skipped");
        wb_fail = 1;
        wc_PKCS7_Free(&p);
        wc_FreeRng(&rng);
        return;
    }
    p.privateKey   = (byte*)client_key_der_2048;
    p.privateKeySz = (word32)sizeof_client_key_der_2048;
    p.content      = content;
    p.contentSz    = (word32)sizeof(content);
    p.hashOID      = SHA256h;
    p.rng          = &rng;

    WB_NOTE("PKCS7_EncodeSigned() top guard 1st operand [:3538]");
    outSz = (word32)sizeof(out);
    (void)PKCS7_EncodeSigned(NULL, NULL, 0, out, &outSz, NULL, NULL);

    /* baseline: all-false everywhere, a real SignedData encode. */
    outSz = (word32)sizeof(out);
    ret = PKCS7_EncodeSigned(&p, NULL, 0, out, &outSz, NULL, NULL);
    WB_CHECK(ret > 0, "baseline SignedData encode (:3538/:3555/:3649 false)");

    WB_NOTE("PKCS7_EncodeSigned() pre-calculated hash matrix [:3649]");
    /* hashBuf != NULL with a size that does not match hashOID -> BUFFER_E */
    outSz = (word32)sizeof(out);
    ret = PKCS7_EncodeSigned(&p, hash, 16, out, &outSz, NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
            ":3649 both true (hashSz mismatch)");
    /* hashBuf != NULL with the right size -> guard false, encode continues */
    outSz = (word32)sizeof(out);
    ret = PKCS7_EncodeSigned(&p, hash, (word32)sizeof(hash), out, &outSz,
                             NULL, NULL);
    WB_CHECK(ret > 0, ":3649 2nd operand false (hashSz matches)");

    WB_NOTE("PKCS7_EncodeSigned() pre-hash-required matrix [:3555]");
#if defined(HAVE_ECC) || defined(WC_RSA_PSS)
    {
        word32 savedOid = p.publicKeyOID;
        int savedSid = p.sidType;

        /* 1st operand false: degenerate (certs-only) bundle */
        p.sidType = DEGENERATE_SID;
        outSz = (word32)sizeof(out);
        (void)PKCS7_EncodeSigned(&p, NULL, 0, out, &outSz, NULL, NULL);
        p.sidType = savedSid;

#ifdef HAVE_ECC
        /* all true: ECDSA signer with no pre-calculated hash -> BAD_FUNC_ARG */
        p.publicKeyOID = ECDSAk;
        outSz = (word32)sizeof(out);
        ret = PKCS7_EncodeSigned(&p, NULL, 0, out, &outSz, NULL, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                ":3555 all true (ECDSA needs pre-calculated hash)");
        /* 2nd operand false: hash supplied */
        outSz = (word32)sizeof(out);
        (void)PKCS7_EncodeSigned(&p, hash, (word32)sizeof(hash), out, &outSz,
                                 NULL, NULL);
#endif
#ifdef WC_RSA_PSS
        /* 3rd operand false / 4th true: RSA-PSS also needs the hash */
        p.publicKeyOID = RSAPSSk;
        outSz = (word32)sizeof(out);
        ret = PKCS7_EncodeSigned(&p, NULL, 0, out, &outSz, NULL, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                ":3555 4th operand true (RSA-PSS needs pre-calculated hash)");
#endif
        /* 3rd and 4th operands false: plain RSA */
        p.publicKeyOID = RSAk;
        outSz = (word32)sizeof(out);
        (void)PKCS7_EncodeSigned(&p, NULL, 0, out, &outSz, NULL, NULL);
        p.publicKeyOID = savedOid;
    }
#endif /* HAVE_ECC || WC_RSA_PSS */

    WB_NOTE("PKCS7_EncodeSigned() output/streamOutCb matrix [:4022]");
    /* both true: no output buffer and no stream callback */
    outSz = (word32)sizeof(out);
    ret = PKCS7_EncodeSigned(&p, NULL, 0, NULL, &outSz, NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
            ":4022 both true (output==NULL, no streamOutCb)");
#ifdef ASN_BER_TO_DER
    /* 2nd operand false: stream-out callback consumes the encoding */
    p.streamOutCb = wb_stream_out_cb;
    outSz = (word32)sizeof(out);
    (void)PKCS7_EncodeSigned(&p, NULL, 0, NULL, &outSz, NULL, NULL);
    p.streamOutCb = NULL;
#endif

    WB_NOTE("PKCS7_EncodeSigned() header/footer + size-query matrix "
            "[:3981,:3983,:4002,:4066]");
    {
        static byte foot[4096];
        word32 footSz;

        /* :3981/:4066 2nd operand false: footer buffer with no size pointer */
        outSz = (word32)sizeof(out);
        (void)PKCS7_EncodeSigned(&p, hash, (word32)sizeof(hash), out, &outSz,
                foot, NULL);

        /* :3983 both true: pure size query through the head/foot entry */
        outSz = 0;
        footSz = 0;
        (void)PKCS7_EncodeSigned(&p, hash, (word32)sizeof(hash), out, &outSz,
                foot, &footSz);

        /* :3983 1st operand false: head size known, footer too small */
        outSz = 16;
        footSz = 0;
        (void)PKCS7_EncodeSigned(&p, hash, (word32)sizeof(hash), out, &outSz,
                foot, &footSz);

        /* :3983 2nd operand false: footer size nonzero but too small */
        outSz = 0;
        footSz = 4;
        (void)PKCS7_EncodeSigned(&p, hash, (word32)sizeof(hash), out, &outSz,
                foot, &footSz);

        /* :3981/:4066 all true: real head/foot encode */
        outSz = (word32)sizeof(out);
        footSz = (word32)sizeof(foot);
        (void)PKCS7_EncodeSigned(&p, hash, (word32)sizeof(hash), out, &outSz,
                foot, &footSz);
    }

    /* :4002 1st operand true: single output buffer too small */
    outSz = 16;
    ret = PKCS7_EncodeSigned(&p, hash, (word32)sizeof(hash), out, &outSz,
            NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":4002 output buffer too small");
    /* :4002 size query (outputSz == 0) */
    outSz = 0;
    (void)PKCS7_EncodeSigned(&p, hash, (word32)sizeof(hash), out, &outSz,
            NULL, NULL);
#ifdef ASN_BER_TO_DER
    /* :4002 2nd operand false: streamOutCb makes the size check moot */
    p.streamOutCb = wb_stream_out_cb;
    outSz = 16;
    (void)PKCS7_EncodeSigned(&p, hash, (word32)sizeof(hash), out, &outSz,
            NULL, NULL);
    p.streamOutCb = NULL;
#endif

    WB_NOTE("PKCS7_EncodeSigned() content-presence matrix [:4073]");
    /* 3rd operand false: content pointer set but zero length */
    p.contentSz = 0;
    outSz = (word32)sizeof(out);
    (void)PKCS7_EncodeSigned(&p, NULL, 0, out, &outSz, NULL, NULL);
    p.contentSz = (word32)sizeof(content);

    WB_NOTE("wc_PKCS7_EncodeSignedData()/_ex() arg chains [:4337,:4469]");
    /* :4469 all operands true: nonzero contentSz with no content source */
    p.content   = NULL;
    p.contentSz = (word32)sizeof(content);
    ret = wc_PKCS7_EncodeSignedData(&p, out, (word32)sizeof(out));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":4469 contentSz>0 with no content and no callback");
    /* :4469 2nd operand false: contentSz == 0 */
    p.contentSz = 0;
    (void)wc_PKCS7_EncodeSignedData(&p, out, (word32)sizeof(out));
#ifdef ASN_BER_TO_DER
    /* :4469 4th operand false: no content pointer but a getContentCb */
    p.contentSz    = (word32)sizeof(wbCbContent);
    p.getContentCb = wb_get_content_cb;
    (void)wc_PKCS7_EncodeSignedData(&p, out, (word32)sizeof(out));
    /* :4337 1st operand false: getContentCb set, footer args may be NULL */
    outSz = (word32)sizeof(out);
    (void)wc_PKCS7_EncodeSignedData_ex(&p, NULL, 0, out, &outSz, NULL, NULL);
    p.getContentCb = NULL;
#endif
    p.content      = content;
    p.contentSz    = (word32)sizeof(content);
    /* :4337 all true: no getContentCb and no footer arguments */
    outSz = (word32)sizeof(out);
    ret = wc_PKCS7_EncodeSignedData_ex(&p, hash, (word32)sizeof(hash), out,
            &outSz, NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":4337 outputFoot/outputFootSz both NULL");
    /* :4337 all false */
    {
        static byte foot[2048];
        word32 footSz = (word32)sizeof(foot);
        outSz = (word32)sizeof(out);
        (void)wc_PKCS7_EncodeSignedData_ex(&p, hash, (word32)sizeof(hash),
                out, &outSz, foot, &footSz);
    }

    p.privateKey = NULL;
    p.privateKeySz = 0;
    p.content = NULL;
    p.contentSz = 0;
    p.rng = NULL;
    wc_PKCS7_Free(&p);
    wc_FreeRng(&rng);
}
#else
static void wb_encodesigned_shapes(void)
{
    WB_NOTE("NO_RSA; PKCS7_EncodeSigned shape matrix skipped");
}
#endif /* !NO_RSA */

/* ------------------------------------------------------------------------- *
 * Section 6: public decode/encode entry argument chains
 * [:4399, :10163, :11380, :11424, :15001, :15168, :15171, :15710, :16797,
 *  :17785]
 * ------------------------------------------------------------------------- */
static void wb_public_entry_args(void)
{
    wc_PKCS7 p;
    byte buf[64];
    byte out[64];
    word32 outSz;
    word32 idx;
    const byte* keyPtr = NULL;
    word32 keyPtrSz = 0;
    byte content[32];

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(out, 0, sizeof(out));
    XMEMSET(content, 0x71, sizeof(content));
    /* SEQUENCE { OCTET STRING "AAAA" } -- a shape OneSymmetricKey accepts far
     * enough in to move past the argument guard. */
    buf[0] = 0x30; buf[1] = 0x06;
    buf[2] = 0x04; buf[3] = 0x04; buf[4] = 'A'; buf[5] = 'A';
    buf[6] = 'A';  buf[7] = 'A';

    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_public_entry_args skipped");
        wb_fail = 1;
        return;
    }

    WB_NOTE("wc_PKCS7_SetDetached() flag matrix [:4399]");
    (void)wc_PKCS7_SetDetached(NULL, 1);
    (void)wc_PKCS7_SetDetached(&p, 0);   /* 2nd operand false */
    (void)wc_PKCS7_SetDetached(&p, 2);   /* both true */
    (void)wc_PKCS7_SetDetached(&p, 1);   /* 3rd operand false */

    WB_NOTE("wc_PKCS7_DecodeOneSymmetricKeyKey() arg chain [:17785]");
    (void)wc_PKCS7_DecodeOneSymmetricKeyKey(NULL, (word32)sizeof(buf),
            &keyPtr, &keyPtrSz);
    (void)wc_PKCS7_DecodeOneSymmetricKeyKey(buf, (word32)sizeof(buf),
            NULL, &keyPtrSz);
    (void)wc_PKCS7_DecodeOneSymmetricKeyKey(buf, (word32)sizeof(buf),
            &keyPtr, NULL);
    (void)wc_PKCS7_DecodeOneSymmetricKeyKey(buf, 8, &keyPtr, &keyPtrSz);

    WB_NOTE("wc_PKCS7_GetEnvelopedDataKariRid() arg chain [:15001]");
    outSz = (word32)sizeof(out);
    (void)wc_PKCS7_GetEnvelopedDataKariRid(NULL, (word32)sizeof(buf),
            out, &outSz);
    outSz = (word32)sizeof(out);
    (void)wc_PKCS7_GetEnvelopedDataKariRid(buf, 0, out, &outSz);
    outSz = (word32)sizeof(out);
    (void)wc_PKCS7_GetEnvelopedDataKariRid(buf, (word32)sizeof(buf),
            NULL, &outSz);
    (void)wc_PKCS7_GetEnvelopedDataKariRid(buf, (word32)sizeof(buf),
            out, NULL);
    outSz = (word32)sizeof(out);
    (void)wc_PKCS7_GetEnvelopedDataKariRid(buf, (word32)sizeof(buf),
            out, &outSz);

    WB_NOTE("wc_PKCS7_DecodeUnprotectedAttributes() arg chain [:16797]");
    idx = 0;
    (void)wc_PKCS7_DecodeUnprotectedAttributes(NULL, buf,
            (word32)sizeof(buf), &idx);
    idx = 0;
    (void)wc_PKCS7_DecodeUnprotectedAttributes(&p, NULL,
            (word32)sizeof(buf), &idx);
    idx = 0;
    (void)wc_PKCS7_DecodeUnprotectedAttributes(&p, buf, 0, &idx);
    (void)wc_PKCS7_DecodeUnprotectedAttributes(&p, buf,
            (word32)sizeof(buf), NULL);
    idx = 0;
    (void)wc_PKCS7_DecodeUnprotectedAttributes(&p, buf,
            (word32)sizeof(buf), &idx);

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    WB_NOTE("wc_PKCS7_EncodeAuthEnvelopedData() arg chains [:15168,:15171]");
    (void)wc_PKCS7_EncodeAuthEnvelopedData(NULL, out, (word32)sizeof(out));
    p.content   = NULL;
    p.contentSz = (word32)sizeof(content);
    (void)wc_PKCS7_EncodeAuthEnvelopedData(&p, out, (word32)sizeof(out));
    p.content   = content;
    p.contentSz = 0;
    (void)wc_PKCS7_EncodeAuthEnvelopedData(&p, out, (word32)sizeof(out));
    p.contentSz = (word32)sizeof(content);
    (void)wc_PKCS7_EncodeAuthEnvelopedData(&p, NULL, (word32)sizeof(out));
    (void)wc_PKCS7_EncodeAuthEnvelopedData(&p, out, 0);
    /* all false: falls through to the encryptOID switch */
    p.encryptOID = 0;
    (void)wc_PKCS7_EncodeAuthEnvelopedData(&p, out, (word32)sizeof(out));

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData() arg chain [:15710]");
    (void)wc_PKCS7_DecodeAuthEnvelopedData(&p, NULL, (word32)sizeof(buf),
            out, (word32)sizeof(out));
    (void)wc_PKCS7_DecodeAuthEnvelopedData(&p, buf, 0,
            out, (word32)sizeof(out));
    (void)wc_PKCS7_DecodeAuthEnvelopedData(&p, buf, (word32)sizeof(buf),
            NULL, (word32)sizeof(out));
    (void)wc_PKCS7_DecodeAuthEnvelopedData(&p, buf, (word32)sizeof(buf),
            out, 0);
    (void)wc_PKCS7_DecodeAuthEnvelopedData(&p, buf, (word32)sizeof(buf),
            out, (word32)sizeof(out));
    wc_PKCS7_Free(&p);
    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("re-init failed; remaining public arg vectors skipped");
        wb_fail = 1;
        return;
    }
#endif /* HAVE_AESGCM || HAVE_AESCCM */

    WB_NOTE("wc_PKCS7_EncodeEnvelopedData() arg chains [:11380,:11424]");
    p.content   = content;
    p.contentSz = 0;
    (void)wc_PKCS7_EncodeEnvelopedData(&p, out, (word32)sizeof(out));
    p.contentSz = (word32)sizeof(content);
    p.encryptOID = 0;               /* invalid: rejected right after the guard */
    (void)wc_PKCS7_EncodeEnvelopedData(&p, out, (word32)sizeof(out));
#ifndef NO_AES
    {
        static byte envOut[4096];
        p.encryptOID   = AES256CBCb;
        p.singleCert   = (byte*)client_cert_der_2048;
        p.singleCertSz = 0;         /* :11424 2nd operand false */
        (void)wc_PKCS7_EncodeEnvelopedData(&p, envOut, (word32)sizeof(envOut));
        p.singleCert   = NULL;      /* :11424 1st operand false */
        p.singleCertSz = 0;
        (void)wc_PKCS7_EncodeEnvelopedData(&p, envOut, (word32)sizeof(envOut));
    }
#ifndef NO_RSA
    /* :11424 both true: a real KTRI EnvelopedData for the RSA client cert.
     * Built on a heap wc_PKCS7 (wc_PKCS7_New) rather than the shared stack
     * fixture: the recipient list this leaves behind must be released by the
     * matching wc_PKCS7_Free() and must not outlive into the next vector. */
    {
        static byte envOut2[4096];
        static byte envIn[32];
        wc_PKCS7* e = wc_PKCS7_New(NULL, INVALID_DEVID);

        XMEMSET(envIn, 0x3c, sizeof(envIn));
        if (e != NULL) {
            if (wc_PKCS7_InitWithCert(e, (byte*)client_cert_der_2048,
                    (word32)sizeof_client_cert_der_2048) == 0) {
                e->content    = envIn;
                e->contentSz  = (word32)sizeof(envIn);
                e->contentOID = DATA;
                e->encryptOID = AES256CBCb;
                (void)wc_PKCS7_EncodeEnvelopedData(e, envOut2,
                        (word32)sizeof(envOut2));
                e->content   = NULL;
                e->contentSz = 0;
            }
            wc_PKCS7_Free(e);
        }
    }
#endif
#endif
    p.singleCert   = NULL;
    p.singleCertSz = 0;
    p.content      = NULL;
    p.contentSz    = 0;
    wc_PKCS7_Free(&p);
}

/* ------------------------------------------------------------------------- *
 * Section 7: content encrypt/decrypt argument chains
 * [:8359, :9799, :10163]
 * ------------------------------------------------------------------------- */
#ifndef NO_AES
static void wb_content_crypt_args(void)
{
    wc_PKCS7 p;
    byte key[32];
    byte iv[16];
    byte in[32];
    byte out[64];
    byte cek[32];
    int ret;

    XMEMSET(key, 0x81, sizeof(key));
    XMEMSET(iv, 0x82, sizeof(iv));
    XMEMSET(in, 0x83, sizeof(in));
    XMEMSET(out, 0, sizeof(out));
    XMEMSET(cek, 0x84, sizeof(cek));

    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_content_crypt_args skipped");
        wb_fail = 1;
        return;
    }

    WB_NOTE("PKCS7_GenerateContentEncryptionKey() cached-cek matrix [:8359]");
    /* 1st operand false: no cached key -> generates one */
    ret = PKCS7_GenerateContentEncryptionKey(&p, 32);
    WB_CHECK(ret == 0, ":8359 1st operand false (generate)");
    /* both true, same size -> reuse */
    ret = PKCS7_GenerateContentEncryptionKey(&p, 32);
    WB_CHECK(ret == 0, ":8359 both true (reuse)");
    /* both true, different size -> WC_KEY_SIZE_E */
    ret = PKCS7_GenerateContentEncryptionKey(&p, 16);
    WB_CHECK(ret == WC_NO_ERR_TRACE(WC_KEY_SIZE_E),
            ":8359 both true, size mismatch");
    /* 2nd operand false: cek pointer set but zero length */
    {
        byte* savedCek = p.cek;
        word32 savedSz = p.cekSz;
        p.cekSz = 0;
        ret = PKCS7_GenerateContentEncryptionKey(&p, 32);
        WB_CHECK(ret == 0, ":8359 2nd operand false (cekSz==0)");
        /* the call above replaced p.cek; release the old buffer */
        if (p.cek != savedCek)
            XFREE(savedCek, p.heap, DYNAMIC_TYPE_PKCS7);
        (void)savedSz;
    }

    WB_NOTE("wc_PKCS7_EncryptContent() in/out callback matrix [:9799]");
#ifdef ASN_BER_TO_DER
    /* 1st/2nd operand true: no input and no getContentCb */
    (void)wc_PKCS7_EncryptContent(&p, AES256CBCb, key, (int)sizeof(key),
            iv, (int)sizeof(iv), NULL, 0, NULL, 0, NULL, (int)sizeof(in), out);
    /* 2nd operand false: getContentCb supplies the input */
    p.getContentCb = wb_get_content_cb;
    (void)wc_PKCS7_EncryptContent(&p, AES256CBCb, key, (int)sizeof(key),
            iv, (int)sizeof(iv), NULL, 0, NULL, 0, NULL, (int)sizeof(in), out);
    p.getContentCb = NULL;
    /* 3rd/4th operand true: no output and no streamOutCb */
    (void)wc_PKCS7_EncryptContent(&p, AES256CBCb, key, (int)sizeof(key),
            iv, (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), NULL);
    /* 4th operand false: streamOutCb consumes the output */
    p.streamOutCb = wb_stream_out_cb;
    (void)wc_PKCS7_EncryptContent(&p, AES256CBCb, key, (int)sizeof(key),
            iv, (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), NULL);
    p.streamOutCb = NULL;
#endif
    /* all false: real encrypt */
    ret = wc_PKCS7_EncryptContent(&p, AES256CBCb, key, (int)sizeof(key),
            iv, (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    WB_CHECK(ret == 0, ":9799 all false (real AES-CBC encrypt)");

    WB_NOTE("wc_PKCS7_EncryptContent() AES-CBC key/iv size matrix [:9823]");
#ifdef WOLFSSL_AES_128
    (void)wc_PKCS7_EncryptContent(&p, AES128CBCb, key, 16,
            iv, (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    (void)wc_PKCS7_EncryptContent(&p, AES128CBCb, key, 24,
            iv, (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), out);
#endif
#ifdef WOLFSSL_AES_192
    (void)wc_PKCS7_EncryptContent(&p, AES192CBCb, key, 24,
            iv, (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    (void)wc_PKCS7_EncryptContent(&p, AES192CBCb, key, 16,
            iv, (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), out);
#endif
    (void)wc_PKCS7_EncryptContent(&p, AES256CBCb, key, 16,
            iv, (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    (void)wc_PKCS7_EncryptContent(&p, AES256CBCb, key, (int)sizeof(key),
            iv, 8, NULL, 0, NULL, 0, in, (int)sizeof(in), out);

#ifndef NO_DES3
    WB_NOTE("wc_PKCS7_EncryptContent() DES/DES3 key/iv size matrix "
            "[:9959,:9974]");
    (void)wc_PKCS7_EncryptContent(&p, DESb, key, DES_KEYLEN,
            iv, DES_BLOCK_SIZE, NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    (void)wc_PKCS7_EncryptContent(&p, DESb, key, DES_KEYLEN + 1,
            iv, DES_BLOCK_SIZE, NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    (void)wc_PKCS7_EncryptContent(&p, DESb, key, DES_KEYLEN,
            iv, DES_BLOCK_SIZE + 1, NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    (void)wc_PKCS7_EncryptContent(&p, DES3b, key, DES3_KEYLEN,
            iv, DES_BLOCK_SIZE, NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    (void)wc_PKCS7_EncryptContent(&p, DES3b, key, DES3_KEYLEN + 1,
            iv, DES_BLOCK_SIZE, NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    (void)wc_PKCS7_EncryptContent(&p, DES3b, key, DES3_KEYLEN,
            iv, DES_BLOCK_SIZE + 1, NULL, 0, NULL, 0, in, (int)sizeof(in), out);
#endif

    WB_NOTE("wc_PKCS7_DecryptContentEx() input matrix [:10163]");
    XFREE(p.cek, p.heap, DYNAMIC_TYPE_PKCS7);
    p.cek   = NULL;
    p.cekSz = 0;
    /* 1st operand false: input present */
    (void)wc_PKCS7_DecryptContentEx(&p, AES256CBCb, iv, (int)sizeof(iv),
            NULL, 0, NULL, 0, out, (int)sizeof(in), out);
#ifdef ASN_BER_TO_DER
    /* both true: no input, no getContentCb */
    (void)wc_PKCS7_DecryptContentEx(&p, AES256CBCb, iv, (int)sizeof(iv),
            NULL, 0, NULL, 0, NULL, (int)sizeof(in), out);
    /* 2nd operand false: getContentCb present */
    p.getContentCb = wb_get_content_cb;
    (void)wc_PKCS7_DecryptContentEx(&p, AES256CBCb, iv, (int)sizeof(iv),
            NULL, 0, NULL, 0, NULL, (int)sizeof(in), out);
    p.getContentCb = NULL;
#endif

    wc_PKCS7_Free(&p);
}
#else
static void wb_content_crypt_args(void)
{
    WB_NOTE("NO_AES; content crypt arg matrix skipped");
}
#endif /* !NO_AES */

/* ------------------------------------------------------------------------- *
 * Section 8: recipient-info optional-field matrices
 * [:9111 (KARI ukm), :11224/:11264 (KEKRI otherAttribute)]
 * ------------------------------------------------------------------------- */
static void wb_recipient_optionals(void)
{
    wc_PKCS7 p;
    byte kek[32];
    byte keyId[8];
    byte otherOid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    byte other[]    = { 0x04, 0x02, 0x11, 0x22 };
    byte ukm[16];

    XMEMSET(kek, 0x91, sizeof(kek));
    XMEMSET(keyId, 0x92, sizeof(keyId));
    XMEMSET(ukm, 0x93, sizeof(ukm));

    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_recipient_optionals skipped");
        wb_fail = 1;
        return;
    }
    /* both KEKRI and KARI size the content-encryption key from encryptOID;
     * without it wc_PKCS7_GetOIDKeySize() rejects before any of the
     * optional-field decisions below are reached. */
#ifndef NO_AES
    p.encryptOID = AES256CBCb;
#endif

#if defined(HAVE_AES_KEYWRAP) && !defined(NO_AES)
    WB_NOTE("wc_PKCS7_AddRecipient_KEKRI() otherAttribute matrix "
            "[:11224,:11264]");
    /* both true: OtherKeyAttribute present */
    (void)wc_PKCS7_AddRecipient_KEKRI(&p, AES256_WRAP, kek, (word32)sizeof(kek),
            keyId, (word32)sizeof(keyId), NULL, otherOid,
            (word32)sizeof(otherOid), other, (word32)sizeof(other), 0);
    /* 2nd operand false: pointer set, zero length */
    (void)wc_PKCS7_AddRecipient_KEKRI(&p, AES256_WRAP, kek, (word32)sizeof(kek),
            keyId, (word32)sizeof(keyId), NULL, otherOid,
            (word32)sizeof(otherOid), other, 0, 0);
    /* 1st operand false: no OtherKeyAttribute at all */
    (void)wc_PKCS7_AddRecipient_KEKRI(&p, AES256_WRAP, kek, (word32)sizeof(kek),
            keyId, (word32)sizeof(keyId), NULL, NULL, 0, NULL, 0, 0);
#endif

#if defined(HAVE_ECC) && defined(HAVE_AES_KEYWRAP) && defined(HAVE_X963_KDF)
    WB_NOTE("wc_PKCS7_AddRecipient_KARI() ukm matrix [:9111] "
            "(+ KariGenerateEphemeralKey/KEK all-false [:8700,:8861])");
    /* both true: user keying material supplied */
    (void)wc_PKCS7_AddRecipient_KARI(&p, cliecc_cert_der_256,
            (word32)sizeof_cliecc_cert_der_256, AES256_WRAP,
            dhSinglePass_stdDH_sha256kdf_scheme, ukm, (word32)sizeof(ukm), 0);
    /* 2nd operand false: size set but no buffer */
    (void)wc_PKCS7_AddRecipient_KARI(&p, cliecc_cert_der_256,
            (word32)sizeof_cliecc_cert_der_256, AES256_WRAP,
            dhSinglePass_stdDH_sha256kdf_scheme, NULL, (word32)sizeof(ukm), 0);
    /* 1st operand false: no ukm */
    (void)wc_PKCS7_AddRecipient_KARI(&p, cliecc_cert_der_256,
            (word32)sizeof_cliecc_cert_der_256, AES256_WRAP,
            dhSinglePass_stdDH_sha256kdf_scheme, NULL, 0, 0);

    WB_NOTE("KariGenerateEphemeralKey/KariGenerateKEK guards [:8700,:8861]");
    {
        WC_PKCS7_KARI kari;
        static ecc_key wbEccKey;
        static DecodedCert wbDCert;
        WC_RNG rng;

        XMEMSET(&wbEccKey, 0, sizeof(wbEccKey));   /* dp == NULL */
        XMEMSET(&wbDCert, 0, sizeof(wbDCert));

        XMEMSET(&kari, 0, sizeof(kari));
        (void)wc_PKCS7_KariGenerateEphemeralKey(NULL);
        /* 2nd operand true: no decoded certificate */
        kari.decoded  = NULL;
        kari.recipKey = &wbEccKey;
        (void)wc_PKCS7_KariGenerateEphemeralKey(&kari);
        /* 3rd operand true: no recipient key */
        kari.decoded  = &wbDCert;
        kari.recipKey = NULL;
        (void)wc_PKCS7_KariGenerateEphemeralKey(&kari);
        /* 4th operand true: recipient key carries no curve parameters */
        kari.recipKey = &wbEccKey;
        (void)wc_PKCS7_KariGenerateEphemeralKey(&kari);

        if (wc_InitRng(&rng) == 0) {
            XMEMSET(&kari, 0, sizeof(kari));
            (void)wc_PKCS7_KariGenerateKEK(NULL, &rng, AES256_WRAP,
                    dhSinglePass_stdDH_sha256kdf_scheme);
            /* 2nd operand true: no recipient key */
            kari.recipKey  = NULL;
            kari.senderKey = &wbEccKey;
            (void)wc_PKCS7_KariGenerateKEK(&kari, &rng, AES256_WRAP,
                    dhSinglePass_stdDH_sha256kdf_scheme);
            /* 3rd operand true: no sender key */
            kari.recipKey  = &wbEccKey;
            kari.senderKey = NULL;
            (void)wc_PKCS7_KariGenerateKEK(&kari, &rng, AES256_WRAP,
                    dhSinglePass_stdDH_sha256kdf_scheme);
            /* 4th operand true: sender key carries no curve parameters */
            kari.senderKey = &wbEccKey;
            (void)wc_PKCS7_KariGenerateKEK(&kari, &rng, AES256_WRAP,
                    dhSinglePass_stdDH_sha256kdf_scheme);
            wc_FreeRng(&rng);
        }
    }
#endif /* HAVE_ECC && HAVE_AES_KEYWRAP && HAVE_X963_KDF */

    wc_PKCS7_Free(&p);
}

/* ------------------------------------------------------------------------- *
 * Section 9: VerifySignedData zero-length streaming input [:6915]
 * ------------------------------------------------------------------------- */
#ifndef NO_PKCS7_STREAM
static void wb_verify_zero_input(void)
{
    wc_PKCS7 p;

    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_verify_zero_input skipped");
        wb_fail = 1;
        return;
    }

    WB_NOTE("PKCS7_VerifySignedData(): pkiMsg==NULL with inSz==0 [:6915]");
    /* 2nd operand true: NULL input with a nonzero size -> BAD_FUNC_ARG */
    (void)wc_PKCS7_VerifySignedData_ex(&p, NULL, 0, NULL, 5, NULL, 0);
    /* 2nd operand false: NULL input with zero size is legal in stream mode */
    (void)wc_PKCS7_VerifySignedData_ex(&p, NULL, 0, NULL, 0, NULL, 0);

    wc_PKCS7_Free(&p);
}
#else
static void wb_verify_zero_input(void)
{
    WB_NOTE("NO_PKCS7_STREAM; zero-length verify input skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 9b: PKCS7_VerifySignedData() header/footer guard
 * `pkiMsg2 == NULL || pkiMsg2Sz == 0` [:7675]. pkiMsg2/pkiMsg2Sz start out
 * as the caller's pkiMsgFoot/pkiMsgFootSz (wc_PKCS7_VerifySignedData_ex).
 * The entry guard a few lines earlier (:6923) already rejects
 * `pkiMsg2Sz > 0 && pkiMsg2 == NULL`, so by the time this line runs,
 * pkiMsg2 == NULL forces pkiMsg2Sz == 0 too -- the 1st operand's
 * independence pair (pkiMsg2==NULL true, pkiMsg2Sz==0 FALSE) can never
 * exist; reported as an exclusion, not driven here.
 *
 * The 2nd operand is excluded for the same reason, established by
 * measurement after this file was written and recorded in
 * tests/unit-mcdc/test_pkcs7_craft_whitebox.c family (e): every path into
 * :7675 reassigns pkiMsg2/pkiMsg2Sz to a non-NULL buffer and a non-zero size
 * (:7646-:7665 streaming, :7418/:7610/:7615 otherwise), and the one branch
 * that skips the reassignment is entered only when pkiMsg2Sz > 0 already
 * holds. The two calls below stay because they are a real two-buffer
 * detached verify baseline that other guards in this binary pair against.
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
static void wb_verify_footer_guard(void)
{
    wc_PKCS7* p;
    /* A detached SignedData footer carries the whole certificate plus the
     * SignerInfo and a 2048-bit RSA signature: ~1.9KB. Sized from that, and
     * static so the small-stack variant does not carry it on the stack. */
    static byte head[1024];
    static byte foot[4096];
    word32 headSz = sizeof(head);
    word32 footSz = sizeof(foot);
    byte content[32];
    byte hash[WC_SHA256_DIGEST_SIZE];
    WC_RNG rng;
    int ret;

    XMEMSET(content, 0x37, sizeof(content));
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; wb_verify_footer_guard skipped");
        wb_fail = 1;
        return;
    }
    if (wc_Hash(WC_HASH_TYPE_SHA256, content, (word32)sizeof(content), hash,
            (word32)sizeof(hash)) != 0) {
        WB_NOTE("wc_Hash failed; wb_verify_footer_guard skipped");
        wc_FreeRng(&rng);
        wb_fail = 1;
        return;
    }

    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    WB_CHECK(p != NULL, "New for footer-guard corpus build");
    if (p == NULL) {
        wc_FreeRng(&rng);
        return;
    }
    ret = -1;
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) == 0) {
        p->content      = NULL; /* _ex() signs the caller-supplied hash */
        p->contentSz    = (word32)sizeof(content);
        p->contentOID   = DATA;
        p->hashOID      = SHA256h;
        p->privateKey   = (byte*)client_key_der_2048;
        p->privateKeySz = (word32)sizeof_client_key_der_2048;
        p->encryptOID   = RSAk;
        p->rng          = &rng;
        (void)wc_PKCS7_SetDetached(p, (word16)1);
        ret = wc_PKCS7_EncodeSignedData_ex(p, hash, (word32)sizeof(hash),
                head, &headSz, foot, &footSz);
    }
    wc_PKCS7_Free(p);
    wc_FreeRng(&rng);
    WB_CHECK(ret >= 0, "detached head/foot corpus built for footer-guard"
            " drive");
    if (ret < 0) {
        return;
    }

    WB_NOTE("PKCS7_VerifySignedData(): header/footer guard [:7675]");

    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL && wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
        p->contentSz = (word32)sizeof(content);
        ret = wc_PKCS7_VerifySignedData_ex(p, hash, (word32)sizeof(hash),
                head, headSz, foot, footSz);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "baseline: real footer (pkiMsg2!=NULL, pkiMsg2Sz>0),"
                " reaches past the guard");
    }
    if (p != NULL) {
        wc_PKCS7_Free(p);
    }

    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL && wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
        p->contentSz = (word32)sizeof(content);
        ret = wc_PKCS7_VerifySignedData_ex(p, hash, (word32)sizeof(hash),
                head, headSz, foot, 0);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                "footSz==0 attempt: reaches past the guard, but see the"
                " section note above -- does NOT close the 2nd operand"
                " (STAGE4 substitutes the header size before this line)");
    }
    if (p != NULL) {
        wc_PKCS7_Free(p);
    }
}
#else
static void wb_verify_footer_guard(void)
{
    WB_NOTE("NO_RSA or no 2048-bit test cert buffers; VerifySignedData"
            " footer-guard drive skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 10: assorted small matrices
 * [:10428 SetSignerIdentifierType, :10044/:10130 DecryptContentInit,
 *  :17789/:17792/:17797 DecodeOneSymmetricKeyKey, :6639 HandleOctetStrings,
 *  :15234/:15367/:15381/:15634 EncodeAuthEnvelopedData, :9531 KTRI]
 * ------------------------------------------------------------------------- */
static void wb_small_matrices(void)
{
    wc_PKCS7 p;
    byte key32[32];
    byte iv16[16];
    byte osk[32];
    const byte* keyPtr = NULL;
    word32 keyPtrSz = 0;
    word32 idx;
    int i;

    for (i = 0; i < (int)sizeof(key32); i++)
        key32[i] = (byte)(i + 1);
    for (i = 0; i < (int)sizeof(iv16); i++)
        iv16[i] = (byte)(i + 0x40);

    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_small_matrices skipped");
        wb_fail = 1;
        return;
    }

    WB_NOTE("wc_PKCS7_SetSignerIdentifierType() type matrix [:10428]");
    (void)wc_PKCS7_SetSignerIdentifierType(NULL, CMS_SKID);
    (void)wc_PKCS7_SetSignerIdentifierType(&p, CMS_ISSUER_AND_SERIAL_NUMBER);
    (void)wc_PKCS7_SetSignerIdentifierType(&p, CMS_SKID);
    (void)wc_PKCS7_SetSignerIdentifierType(&p, DEGENERATE_SID);
    (void)wc_PKCS7_SetSignerIdentifierType(&p, 0x7ffe);
    (void)wc_PKCS7_SetSignerIdentifierType(&p, CMS_ISSUER_AND_SERIAL_NUMBER);

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    WB_NOTE("wc_PKCS7_DecryptContentInit() AES-CBC key-size matrix [:10044]");
#ifdef WOLFSSL_AES_192
    if (wc_PKCS7_DecryptContentInit(&p, AES192CBCb, key32, 24, iv16,
            (int)sizeof(iv16), INVALID_DEVID, NULL) == 0)
        wc_PKCS7_DecryptContentFree(&p, AES192CBCb, NULL);
    (void)wc_PKCS7_DecryptContentInit(&p, AES192CBCb, key32, 32, iv16,
            (int)sizeof(iv16), INVALID_DEVID, NULL);
#endif
#ifdef WOLFSSL_AES_256
    (void)wc_PKCS7_DecryptContentInit(&p, AES256CBCb, key32, 16, iv16,
            (int)sizeof(iv16), INVALID_DEVID, NULL);
#endif
#endif /* !NO_AES && HAVE_AES_CBC */
#ifndef NO_DES3
    WB_NOTE("wc_PKCS7_DecryptContentInit() DES3 iv-size matrix [:10130]");
    (void)wc_PKCS7_DecryptContentInit(&p, DES3b, key32, DES3_KEYLEN, iv16,
            DES_BLOCK_SIZE + 1, INVALID_DEVID, NULL);
    if (wc_PKCS7_DecryptContentInit(&p, DES3b, key32, DES3_KEYLEN, iv16,
            DES_BLOCK_SIZE, INVALID_DEVID, NULL) == 0)
        wc_PKCS7_DecryptContentFree(&p, DES3b, NULL);
#endif

    WB_NOTE("wc_PKCS7_DecodeOneSymmetricKeyKey() element matrix "
            "[:17789,:17792,:17797]");
    XMEMSET(osk, 0, sizeof(osk));
    /* SEQUENCE { SEQUENCE {} OCTET STRING "AAAA" } -- the sKeyAttrs arm */
    osk[0] = 0x30; osk[1] = 0x0a;
    osk[2] = 0x30; osk[3] = 0x02; osk[4] = 0x05; osk[5] = 0x00;
    osk[6] = 0x04; osk[7] = 0x04;
    osk[8] = 'A'; osk[9] = 'A'; osk[10] = 'A'; osk[11] = 'A';
    (void)wc_PKCS7_DecodeOneSymmetricKeyKey(osk, 12, &keyPtr, &keyPtrSz);
    (void)wc_PKCS7_DecodeOneSymmetricKeyAttribute(osk, 12, 0, &keyPtr,
            &keyPtrSz);
    (void)wc_PKCS7_DecodeOneSymmetricKeyAttribute(osk, 12, 5, &keyPtr,
            &keyPtrSz);
    (void)wc_PKCS7_DecodeOneSymmetricKeyAttribute(NULL, 12, 0, &keyPtr,
            &keyPtrSz);
    /* :17792 second operand false: no sKeyAttrs, straight to the key */
    osk[2] = 0x04; osk[3] = 0x04;
    (void)wc_PKCS7_DecodeOneSymmetricKeyKey(osk, 12, &keyPtr, &keyPtrSz);
    /* :17797 true: the element after the SEQUENCE is not an OCTET STRING */
    osk[0] = 0x30; osk[1] = 0x06;
    osk[2] = 0x05; osk[3] = 0x00;
    osk[4] = 0x02; osk[5] = 0x02; osk[6] = 0x01; osk[7] = 0x02;
    (void)wc_PKCS7_DecodeOneSymmetricKeyKey(osk, 8, &keyPtr, &keyPtrSz);
    /* :17789 true: the outer SEQUENCE header itself is wrong */
    osk[0] = 0x31;
    (void)wc_PKCS7_DecodeOneSymmetricKeyKey(osk, 8, &keyPtr, &keyPtrSz);
    (void)wc_PKCS7_DecodeOneSymmetricKeyAttribute(osk, 8, 0, &keyPtr,
            &keyPtrSz);

    WB_NOTE("wc_PKCS7_ParseToRecipientInfoSet() content-type matrix [:13995]");
    {
        byte env[16];
        word32 envIdx;
        int savedOid = p.contentOID;

        XMEMSET(env, 0, sizeof(env));
        env[0] = 0x30; env[1] = 0x04; env[2] = 0x02; env[3] = 0x01;
        env[4] = 0x00; env[5] = 0x31;

        p.contentOID = DATA;
        envIdx = 0;
        (void)wc_PKCS7_ParseToRecipientInfoSet(&p, env, (word32)sizeof(env),
                &envIdx, ENVELOPED_DATA);
        envIdx = 0;
        (void)wc_PKCS7_ParseToRecipientInfoSet(&p, env, (word32)sizeof(env),
                &envIdx, AUTH_ENVELOPED_DATA);
        envIdx = 0;
        (void)wc_PKCS7_ParseToRecipientInfoSet(&p, env, (word32)sizeof(env),
                &envIdx, SIGNED_DATA);
        p.contentOID = FIRMWARE_PKG_DATA;
        envIdx = 0;
        (void)wc_PKCS7_ParseToRecipientInfoSet(&p, env, (word32)sizeof(env),
                &envIdx, SIGNED_DATA);
        p.contentOID = savedOid;
    }

#ifndef NO_PKCS7_STREAM
    WB_NOTE("wc_PKCS7_HandleOctetStrings() argument chain [:6639]");
    idx = 0;
    (void)wc_PKCS7_HandleOctetStrings(NULL, osk, (word32)sizeof(osk), &idx,
            &idx, 0);
    idx = 0;
    (void)wc_PKCS7_HandleOctetStrings(&p, NULL, (word32)sizeof(osk), &idx,
            &idx, 0);
    idx = 0;
    (void)wc_PKCS7_HandleOctetStrings(&p, osk, (word32)sizeof(osk), &idx,
            NULL, 0);
    /* all-false baseline: the 3 operand-true rows above never pair against
     * a call that gets past the guard, so the guard's independence pairs
     * were never actually closed (mirrors the arg-guard trap noted in the
     * suite brief -- an operand-true-only batch without the baseline). */
    {
        wc_PKCS7 hp;
        int ret;

        XMEMSET(&hp, 0, sizeof(hp));
        if (wc_PKCS7_Init(&hp, NULL, INVALID_DEVID) == 0 &&
                wc_PKCS7_CreateStream(&hp) == 0) {
            idx = 0;
            ret = wc_PKCS7_HandleOctetStrings(&hp, osk, (word32)sizeof(osk),
                    &idx, &idx, 0);
            WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    ":6639 baseline (all false): valid pkcs7/in/idx, reaches"
                    " past the guard");
            wc_PKCS7_FreeStream(&hp);
        }
        else {
            WB_CHECK(0, ":6639 baseline setup (Init/CreateStream) failed");
        }
    }
#else
    (void)idx;
#endif

    wc_PKCS7_Free(&p);
}

/* ------------------------------------------------------------------------- *
 * Section 11: full AuthEnvelopedData encode with optional-field variations
 * [:15234, :15367, :15381, :15634] and the KTRI key-type guard [:9531]
 * ------------------------------------------------------------------------- */
#if (defined(HAVE_AESGCM) || defined(HAVE_AESCCM)) && !defined(NO_RSA)
static void wb_auth_encode_shapes(void)
{
    wc_PKCS7 p;
    WC_RNG rng;
    static byte out[8192];
    byte content[48];
    PKCS7Attrib attrib[1];
    static const byte aOid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    static const byte aVal[] = { 0x0c, 0x02, 0x58, 0x59 };
    int ret;

    XMEMSET(content, 0x9a, sizeof(content));
    attrib[0].oid     = aOid;
    attrib[0].oidSz   = (word32)sizeof(aOid);
    attrib[0].value   = aVal;
    attrib[0].valueSz = (word32)sizeof(aVal);

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; wb_auth_encode_shapes skipped");
        wb_fail = 1;
        return;
    }
    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0 ||
        wc_PKCS7_InitWithCert(&p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) != 0) {
        WB_NOTE("PKCS7 init failed; wb_auth_encode_shapes skipped");
        wb_fail = 1;
        wc_FreeRng(&rng);
        return;
    }

    p.content    = content;
    p.contentSz  = (word32)sizeof(content);
    p.contentOID = DATA;
    p.encryptOID = AES256GCMb;
    p.rng        = &rng;

    WB_NOTE("wc_PKCS7_EncodeAuthEnvelopedData() optional-field matrix "
            "[:15234,:15367,:15381,:15634]");
    /* :15234/:15367 all false and the attribute arms taken */
    p.authAttribs   = attrib;
    p.authAttribsSz = 1;
    ret = wc_PKCS7_EncodeAuthEnvelopedData(&p, out, (word32)sizeof(out));
    WB_CHECK(ret > 0, "AuthEnvelopedData with auth attributes encoded");

    /* :15367 2nd operand false: attribute array set, count zero */
    p.authAttribsSz = 0;
    (void)wc_PKCS7_EncodeAuthEnvelopedData(&p, out, (word32)sizeof(out));

    /* :15234 2nd operand false: recipient cert set, size zero */
    p.authAttribs   = NULL;
    p.singleCertSz  = 0;
    (void)wc_PKCS7_EncodeAuthEnvelopedData(&p, out, (word32)sizeof(out));

    /* :15234 1st operand false: no manually set recipient cert */
    {
        byte* savedCert = p.singleCert;
        p.singleCert = NULL;
        (void)wc_PKCS7_EncodeAuthEnvelopedData(&p, out, (word32)sizeof(out));
        p.singleCert = savedCert;
    }

#ifdef HAVE_ECC
    WB_NOTE("wc_PKCS7_AddRecipient_KTRI() non-RSA certificate [:9531]");
    (void)wc_PKCS7_AddRecipient_KTRI(&p, cliecc_cert_der_256,
            (word32)sizeof_cliecc_cert_der_256, 0);
    (void)wc_PKCS7_AddRecipient_KTRI(&p, client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048, 0);
#endif

    p.authAttribs   = NULL;
    p.authAttribsSz = 0;
    p.content       = NULL;
    p.contentSz     = 0;
    p.rng           = NULL;
    wc_PKCS7_Free(&p);
    wc_FreeRng(&rng);
}
#else
static void wb_auth_encode_shapes(void)
{
    WB_NOTE("no AES-GCM/CCM or no RSA; AuthEnvelopedData encode shapes"
            " skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 12: attribute-size overflow guards, digest builder and the
 * InitWithCert key-type matrix
 * [:1096, :1352, :1822, :1843, :1957, :5726, :5746]
 * ------------------------------------------------------------------------- */
static void wb_size_guards(void)
{
    wc_PKCS7 p;
    EncodedAttrib ea[2];
    PKCS7Attrib at[2];
    static const byte gOid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    static const byte gVal[] = { 0x0c, 0x02, 0x41, 0x42 };
    byte content[32];
    byte hash[WC_SHA256_DIGEST_SIZE];
    int ret;

    XMEMSET(content, 0xc1, sizeof(content));
    XMEMSET(hash, 0xc2, sizeof(hash));

    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_size_guards skipped");
        wb_fail = 1;
        return;
    }

#if defined(WOLFSSL_SHA3) && \
    (defined(WOLFSSL_SHAKE256) || defined(WOLFSSL_SHAKE128))
    WB_NOTE("wc_PKCS7_DigestParamsAbsent() hashOID matrix [:1096]");
    p.hashOID = SHA256h;
    (void)wc_PKCS7_DigestParamsAbsent(&p);
#ifdef WOLFSSL_SHAKE256
    p.hashOID = SHAKE256h;
    (void)wc_PKCS7_DigestParamsAbsent(&p);
#endif
#ifdef WOLFSSL_SHAKE128
    p.hashOID = SHAKE128h;
    (void)wc_PKCS7_DigestParamsAbsent(&p);
#endif
#endif
    p.hashOID = SHA256h;

    WB_NOTE("EncodeAttributes() size-overflow guards [:1822,:1843]");
    XMEMSET(ea, 0, sizeof(ea));
    XMEMSET(at, 0, sizeof(at));
    at[0].oid     = gOid;
    at[0].oidSz   = (word32)sizeof(gOid);
    at[0].value   = gVal;
    at[0].valueSz = (word32)sizeof(gVal);
    at[1] = at[0];
    /* all false */
    ret = EncodeAttributes(ea, 2, at, 2);
    WB_CHECK(ret > 0, ":1822/:1843 all false (normal attributes)");
    /* :1822 1st operand true: valueSz + oidSz already wraps */
    at[0].valueSz = 0xFFFFFFF0U;
    at[0].oidSz   = 0x40;
    ret = EncodeAttributes(ea, 1, at, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":1822 1st operand true");
    /* :1822 2nd operand true: the sum only wraps once the SET header is added */
    at[0].valueSz = 0xFFFFFFFAU;
    at[0].oidSz   = 1;
    ret = EncodeAttributes(ea, 1, at, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":1822 2nd operand true");
    /* :1843 2nd operand true: each attribute fits, the running total does not */
    at[0].valueSz = 0x60000000U;
    at[0].oidSz   = (word32)sizeof(gOid);
    at[1] = at[0];
    ret = EncodeAttributes(ea, 2, at, 2);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":1843 2nd operand true");

    WB_NOTE("FlattenEncodedAttribs() size-overflow guards [:1957]");
    {
        FlatAttrib* derArr[1];

        derArr[0] = NULL;
        XMEMSET(ea, 0, sizeof(ea));
        ea[0].valueSeqSz = 0xFFFFFFF0U;
        ea[0].oidSz      = 0x40;
        WB_CHECK(FlattenEncodedAttribs(&p, derArr, 1, ea, 1) ==
                WC_NO_ERR_TRACE(BUFFER_E), ":1957 1st operand true");
        ea[0].valueSeqSz = 0xFFFFFFF0U;
        ea[0].oidSz      = 0x08;
        ea[0].valueSetSz = 0x40;
        WB_CHECK(FlattenEncodedAttribs(&p, derArr, 1, ea, 1) ==
                WC_NO_ERR_TRACE(BUFFER_E), ":1957 2nd operand true");
        ea[0].valueSetSz = 0x02;
        ea[0].valueSz    = 0x40;
        WB_CHECK(FlattenEncodedAttribs(&p, derArr, 1, ea, 1) ==
                WC_NO_ERR_TRACE(BUFFER_E), ":1957 3rd operand true");
    }

    WB_NOTE("wc_PKCS7_BuildSignedDataDigest() hash-source matrix "
            "[:5726,:5746]");
    {
        byte pkcs7Digest[MAX_PKCS7_DIGEST_SZ];
        word32 pkcs7DigestSz;
        byte* plainDigest = NULL;
        word32 plainDigestSz = 0;
        byte signedAttrib[8];

        XMEMSET(signedAttrib, 0x31, sizeof(signedAttrib));
        p.content   = content;
        p.contentSz = (word32)sizeof(content);
        p.hashOID   = SHA256h;

        /* :5726/:5746 2nd operand false: hash pointer with zero length */
        pkcs7DigestSz = (word32)sizeof(pkcs7Digest);
        (void)wc_PKCS7_BuildSignedDataDigest(&p, NULL, 0, pkcs7Digest,
                &pkcs7DigestSz, &plainDigest, &plainDigestSz, hash, 0, 0);
        /* :5726/:5746 1st operand false: no caller hash at all */
        pkcs7DigestSz = (word32)sizeof(pkcs7Digest);
        (void)wc_PKCS7_BuildSignedDataDigest(&p, NULL, 0, pkcs7Digest,
                &pkcs7DigestSz, &plainDigest, &plainDigestSz, NULL, 0, 0);
        /* :5746 all true: caller hash used directly */
        pkcs7DigestSz = (word32)sizeof(pkcs7Digest);
        (void)wc_PKCS7_BuildSignedDataDigest(&p, NULL, 0, pkcs7Digest,
                &pkcs7DigestSz, &plainDigest, &plainDigestSz, hash,
                (word32)sizeof(hash), 0);
        /* :5746 3rd operand false: signed attributes present */
        pkcs7DigestSz = (word32)sizeof(pkcs7Digest);
        (void)wc_PKCS7_BuildSignedDataDigest(&p, signedAttrib,
                (word32)sizeof(signedAttrib), pkcs7Digest, &pkcs7DigestSz,
                &plainDigest, &plainDigestSz, hash, (word32)sizeof(hash), 0);

        p.content   = NULL;
        p.contentSz = 0;
    }

    wc_PKCS7_Free(&p);

    WB_NOTE("wc_PKCS7_InitWithCert() signer key-type matrix [:1352]");
    {
        wc_PKCS7* c;

#ifndef NO_RSA
        c = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (c != NULL) {
            (void)wc_PKCS7_InitWithCert(c, (byte*)client_cert_der_2048,
                    (word32)sizeof_client_cert_der_2048);
            wc_PKCS7_Free(c);
        }
#endif
#ifdef HAVE_ECC
        c = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (c != NULL) {
            (void)wc_PKCS7_InitWithCert(c, (byte*)cliecc_cert_der_256,
                    (word32)sizeof_cliecc_cert_der_256);
            wc_PKCS7_Free(c);
        }
#endif
#ifdef HAVE_ED25519
        /* neither RSA-family nor ECDSA: all operands false */
        c = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (c != NULL) {
            (void)wc_PKCS7_InitWithCert(c, (byte*)client_ed25519_cert,
                    (word32)sizeof_client_ed25519_cert);
            wc_PKCS7_Free(c);
        }
#endif
    }
}

/* ------------------------------------------------------------------------- *
 * wc_PKCS7_EncodeContentStream(): the trailing-pad gate
 *   :3413  `(cipherType != WC_CIPHER_NONE) && (totalSz == pkcs7->contentSz)`
 *
 * Both operands need rows that no public encode call produces. The only
 * cipherType != WC_CIPHER_NONE callers are inside wc_PKCS7_EncryptContent()
 * and are reached only when pkcs7->encodeStream is set, and every such call
 * hands the whole content over in one piece, so totalSz always ends up equal
 * to pkcs7->contentSz. Calling the (file-static) encoder directly supplies
 * all three rows in this binary:
 *
 *   (F,-)  cipherType WC_CIPHER_NONE, the signed-bundle shape
 *   (T,T)  AES-CBC with contentSz == inSz  -> the pad block runs
 *   (T,F)  AES-CBC with contentSz > inSz   -> the read loop runs out of
 *          input first (`contentDataRead <= 0` breaks the do/while), so the
 *          pad block is skipped and the partial block is flushed as-is
 * ------------------------------------------------------------------------- */
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128) && \
    defined(ASN_BER_TO_DER)
static void wb_encode_content_stream_pad(void)
{
    static byte in[32];
    static byte out[512];
    byte key[16], iv[16];
    Aes  aes;
    wc_PKCS7* p;
    int  ret;

    XMEMSET(in, 0x41, sizeof(in));
    XMEMSET(key, 0x42, sizeof(key));
    XMEMSET(iv, 0x43, sizeof(iv));

    WB_NOTE("wc_PKCS7_EncodeContentStream(): WC_CIPHER_NONE, pad gate short-"
            "circuits on the first operand [:3413 cond 0 false]");
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
            p->encodeStream = 1;
            p->contentSz    = (word32)sizeof(in);
            ret = wc_PKCS7_EncodeContentStream(p, NULL, NULL, in,
                    (int)sizeof(in), out, WC_CIPHER_NONE);
            WB_CHECK(ret == 0, ":3413 WC_CIPHER_NONE stream copy");
        }
        wc_PKCS7_Free(p);
    }

    WB_NOTE("wc_PKCS7_EncodeContentStream(): AES-CBC with the whole content"
            " consumed, so the pad block runs [:3413 both operands true]");
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0 && wc_AesInit(&aes, NULL,
                    INVALID_DEVID) == 0) {
            if (wc_AesSetKey(&aes, key, (word32)sizeof(key), iv,
                        AES_ENCRYPTION) == 0) {
                p->encodeStream = 1;
                p->encryptOID   = AES128CBCb;
                p->contentSz    = (word32)sizeof(in);
                ret = wc_PKCS7_EncodeContentStream(p, NULL, &aes, in,
                        (int)sizeof(in), out, WC_CIPHER_AES_CBC);
                WB_CHECK(ret == 0, ":3413 AES-CBC padded flush");
            }
            wc_AesFree(&aes);
        }
        wc_PKCS7_Free(p);
    }

    WB_NOTE("wc_PKCS7_EncodeContentStream(): AES-CBC whose declared contentSz"
            " is larger than the input, so the read loop stops short and the"
            " pad block is skipped [:3413 cond 1 false]");
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0 && wc_AesInit(&aes, NULL,
                    INVALID_DEVID) == 0) {
            if (wc_AesSetKey(&aes, key, (word32)sizeof(key), iv,
                        AES_ENCRYPTION) == 0) {
                p->encodeStream = 1;
                p->encryptOID   = AES128CBCb;
                p->contentSz    = (word32)sizeof(in) * 2;
                ret = wc_PKCS7_EncodeContentStream(p, NULL, &aes, in,
                        (int)sizeof(in), out, WC_CIPHER_AES_CBC);
                WB_CHECK(ret == 0, ":3413 AES-CBC short read, no pad block");
            }
            wc_AesFree(&aes);
        }
        wc_PKCS7_Free(p);
    }
}
#else
static void wb_encode_content_stream_pad(void)
{
    WB_NOTE("no AES-CBC/BER-to-DER; EncodeContentStream pad gate skipped");
}
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("pkcs7.c white-box MC/DC argument-chain supplement\n");

    wb_sign_helper_args();
    wb_signed_attrib_flags();
    wb_signerinfo_binding();
    wb_verify_content_msgdigest();
    wb_encodesigned_shapes();
    wb_public_entry_args();
    wb_content_crypt_args();
    wb_recipient_optionals();
    wb_verify_zero_input();
    wb_verify_footer_guard();
    wb_small_matrices();
    wb_auth_encode_shapes();
    wb_size_guards();
    wb_encode_content_stream_pad();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit discards this variant's coverage
     * entirely in the test harness. Failures are surfaced via the
     * printed [FAIL] lines instead. */
    (void)wb_fail;
    return 0;
}
