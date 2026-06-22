/* test_lms_xmss.c
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
#include <wolfssl/wolfcrypt/asn.h>
#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#endif
#include <tests/api/api.h>
#include <tests/utils.h>
#include <tests/api/test_lms_xmss.h>

/*----------------------------------------------------------------------------*/
/* LMS tests                                                                  */
/*----------------------------------------------------------------------------*/

#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)

#include <wolfssl/wolfcrypt/wc_lms.h>

#define LMS_TEST_PRIV_KEY_FILE "/tmp/wolfssl_test_lms.key"

static int test_lms_write_key(const byte* priv, word32 privSz, void* context)
{
    FILE* f = fopen((const char*)context, "wb");
    int ret = WC_LMS_RC_SAVED_TO_NV_MEMORY;
    if (f == NULL)
        return -1;
    if (fwrite(priv, 1, privSz, f) != privSz)
        ret = -1;
    fclose(f);
    return ret;
}

static int test_lms_read_key(byte* priv, word32 privSz, void* context)
{
    FILE* f = fopen((const char*)context, "rb");
    if (f == NULL)
        return -1;
    if (fread(priv, 1, privSz, f) == 0) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return WC_LMS_RC_READ_TO_MEMORY;
}

/* Helper: init an LMS key with callbacks and L1-H10-W8 params */
static int test_lms_init_key(LmsKey* key, WC_RNG* rng)
{
    int ret;

    ret = wc_LmsKey_Init(key, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

#if !defined(WOLFSSL_LMS_MAX_HEIGHT) || (WOLFSSL_LMS_MAX_HEIGHT >= 10)
    ret = wc_LmsKey_SetParameters(key, 1, 10, 8);
#else
    ret = wc_LmsKey_SetParameters(key, 1, 5, 8);
#endif
    if (ret != 0) return ret;

    ret = wc_LmsKey_SetWriteCb(key, test_lms_write_key);
    if (ret != 0) return ret;

    ret = wc_LmsKey_SetReadCb(key, test_lms_read_key);
    if (ret != 0) return ret;

    ret = wc_LmsKey_SetContext(key, (void*)LMS_TEST_PRIV_KEY_FILE);
    if (ret != 0) return ret;

    (void)rng;
    return 0;
}

#endif /* WOLFSSL_HAVE_LMS && !WOLFSSL_LMS_VERIFY_ONLY */

/*
 * Test basic LMS sign/verify with multiple signings.
 * Uses L1-H10-W8 (1024 total signatures, 32-entry leaf cache).
 */
int test_wc_LmsKey_sign_verify(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
    LmsKey  key;
    WC_RNG  rng;
    byte    msg[] = "test message for LMS signing";
    byte    sig[2048];
    word32  sigSz;
    int     i;
    int     numSigs = 5;

    XMEMSET(&key, 0, sizeof(key));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    remove(LMS_TEST_PRIV_KEY_FILE);
    ExpectIntEQ(test_lms_init_key(&key, &rng), 0);
    ExpectIntEQ(wc_LmsKey_MakeKey(&key, &rng), 0);

    for (i = 0; i < numSigs; i++) {
        sigSz = sizeof(sig);
        ExpectIntEQ(wc_LmsKey_Sign(&key, sig, &sigSz, msg, sizeof(msg)), 0);
        ExpectIntEQ(wc_LmsKey_Verify(&key, sig, sigSz, msg, sizeof(msg)), 0);
    }

    wc_LmsKey_Free(&key);
    wc_FreeRng(&rng);
    remove(LMS_TEST_PRIV_KEY_FILE);
#endif
    return EXPECT_RESULT();
}

/*
 * Test LMS key reload after advancing past the leaf cache window.
 *
 * Reproduces a heap-buffer-overflow bug in wc_lms_treehash_init() where the
 * leaf cache write uses (i * hash_len) instead of ((i - leaf->idx) * hash_len).
 * When q > max_cb (default 32), wc_LmsKey_Reload calls wc_hss_init_auth_path
 * which calls wc_lms_treehash_init with q > 0, causing writes past the end of
 * the leaf cache buffer.
 *
 * Reproduction steps:
 *   1. Generate L1-H10-W8 key (cacheBits=5, max_cb=32)
 *   2. Sign 33 times to advance q past the cache window
 *   3. Free the key and reload from persisted state
 *   4. Sign and verify after reload
 *
 * Without the fix: heap-buffer-overflow at wc_lms_impl.c:1965
 * With the fix:    all operations succeed, signatures verify
 */
int test_wc_LmsKey_reload_cache(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY) && \
    (!defined(WOLFSSL_LMS_MAX_HEIGHT) || (WOLFSSL_LMS_MAX_HEIGHT >= 10))
    LmsKey  key;
    LmsKey  vkey;
    WC_RNG  rng;
    byte    msg[] = "test message for LMS signing";
    byte    sig[2048];
    word32  sigSz;
    byte    pub[64];
    word32  pubSz = sizeof(pub);
    int     i;
    /* Sign 33 times to advance q past the 32-entry cache window. */
    int     preSigs = 33;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&vkey, 0, sizeof(vkey));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Phase 1: Generate key and sign past cache window */
    remove(LMS_TEST_PRIV_KEY_FILE);
    ExpectIntEQ(test_lms_init_key(&key, &rng), 0);
    ExpectIntEQ(wc_LmsKey_MakeKey(&key, &rng), 0);

    for (i = 0; i < preSigs; i++) {
        sigSz = sizeof(sig);
        ExpectIntEQ(wc_LmsKey_Sign(&key, sig, &sigSz, msg, sizeof(msg)), 0);
    }

    /* Save public key for verification after reload */
    ExpectIntEQ(wc_LmsKey_ExportPubRaw(&key, pub, &pubSz), 0);

    wc_LmsKey_Free(&key);

    /* Phase 2: Reload key. Triggers wc_lms_treehash_init with q=33 */
    ExpectIntEQ(test_lms_init_key(&key, &rng), 0);
    ExpectIntEQ(wc_LmsKey_Reload(&key), 0);

    /* Phase 3: Sign after reload and verify with separate verify-only key */
    sigSz = sizeof(sig);
    ExpectIntEQ(wc_LmsKey_Sign(&key, sig, &sigSz, msg, sizeof(msg)), 0);

    ExpectIntEQ(wc_LmsKey_Init(&vkey, NULL, INVALID_DEVID), 0);
#if !defined(WOLFSSL_LMS_MAX_HEIGHT) || (WOLFSSL_LMS_MAX_HEIGHT >= 10)
    ExpectIntEQ(wc_LmsKey_SetParameters(&vkey, 1, 10, 8), 0);
#else
    ExpectIntEQ(wc_LmsKey_SetParameters(&vkey, 1, 5, 8), 0);
#endif
    ExpectIntEQ(wc_LmsKey_ImportPubRaw(&vkey, pub, pubSz), 0);
    ExpectIntEQ(wc_LmsKey_Verify(&vkey, sig, sigSz, msg, sizeof(msg)), 0);

    wc_LmsKey_Free(&vkey);
    wc_LmsKey_Free(&key);
    wc_FreeRng(&rng);
    remove(LMS_TEST_PRIV_KEY_FILE);
#endif
    return EXPECT_RESULT();
}

/*----------------------------------------------------------------------------*/
/* RFC 9802 (HSS/LMS and XMSS/XMSS^MT in X.509) tests                         */
/*----------------------------------------------------------------------------*/

/* For every committed self-signed test certificate confirm:
 *   - wc_ParseCert succeeds on the RFC 9802 AlgorithmIdentifier encoding
 *     (OID-only SEQUENCE, no NULL parameters)
 *   - keyOID and signatureOID are set to the expected values
 *   - loading as a trust anchor and verifying the same bytes through
 *     wolfSSL_CertManagerVerifyBuffer exercises the ConfirmSignature
 *     path and succeeds on a valid cert
 *   - flipping a byte in the signature AND flipping a byte in the
 *     TBSCertificate both cause verification to fail.
 *
 * Test vectors are in certs/lms/ and certs/xmss/, generated with Bouncy
 * Castle 1.81. BC's default XMSS / XMSS^MT X.509 encoding uses pre-
 * standard ISARA OIDs and wraps the raw RFC 8391 pub key in an OCTET
 * STRING, so the fixtures were produced with a small generator that
 * overrides the AlgorithmIdentifier and SPKI to match RFC 9802. */
/* Only the LMS interop-anchor verification still loads a committed fixture
 * (bc_lms_native_bc_root.der); everything else is generated in-process. Gate
 * these file helpers on exactly that call site to avoid an unused-function
 * warning in XMSS-only or truncated-hash builds. */
#if defined(WOLFSSL_HAVE_LMS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_CERTS) && !defined(WOLFSSL_NO_LMS_SHA256_256)
/* Sanity bound on a test fixture cert. 1 MiB is well above any realistic
 * RFC 9802 cert and catches a wild XFTELL. Typed as
 * long to match XFTELL's return so the size comparison below isn't
 * a mixed long-vs-int compare. */
#define RFC9802_TEST_MAX_CERT_SIZE ((long)(1L << 20))

/* Load a whole file into a freshly-allocated buffer. Caller frees. */
static int rfc9802_load_file(const char* path, byte** out, int* outLen)
{
    EXPECT_DECLS;
    XFILE  f = XBADFILE;
    long   sz = 0;
    size_t got = 0;
    byte*  buf = NULL;

    *out = NULL;
    *outLen = 0;
    ExpectTrue((f = XFOPEN(path, "rb")) != XBADFILE);
    if (f == XBADFILE)
        return TEST_FAIL;
    if (XFSEEK(f, 0, XSEEK_END) == 0)
        sz = XFTELL(f);
    (void)XFSEEK(f, 0, XSEEK_SET);
    ExpectIntGT(sz, 0);
    ExpectIntLT(sz, RFC9802_TEST_MAX_CERT_SIZE);
    /* Hard-fail before XMALLOC if XFSEEK / XFTELL produced an unusable
     * size: ExpectInt* records the failure but doesn't short-circuit,
     * so without this guard a -1 from XFTELL would cast to a multi-GiB
     * (size_t) allocation, and a 0 would request a zero-byte malloc. */
    if (sz <= 0 || sz >= RFC9802_TEST_MAX_CERT_SIZE) {
        XFCLOSE(f);
        return TEST_FAIL;
    }
    ExpectNotNull(buf = (byte*)XMALLOC((size_t)sz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (buf != NULL) {
        got = XFREAD(buf, 1, (size_t)sz, f);
        ExpectIntEQ(got, (size_t)sz);
        /* On a short read the caller would otherwise proceed with a
         * partially-initialized buffer and produce cascading parse
         * failures driven by the uninitialized tail. Free here so the
         * caller's `if (buf == NULL) return TEST_FAIL;` short-circuits
         * cleanly with a single recorded failure. */
        if (got != (size_t)sz) {
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            buf = NULL;
            sz = 0;
        }
    }
    XFCLOSE(f);
    *out = buf;
    *outLen = (int)sz;
    return EXPECT_RESULT();
}

static WC_MAYBE_UNUSED int rfc9802_verify_one_cert(const char* path,
    word32 expectedKeyOID, word32 expectedSigOID)
{
    EXPECT_DECLS;
    byte*                 buf = NULL;
    byte*                 tampered = NULL;
    int                   bytes = 0;
    DecodedCert           cert;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    word32                certBegin = 0;
    word32                sigIndex = 0;

    ExpectIntEQ(rfc9802_load_file(path, &buf, &bytes), TEST_SUCCESS);
    if (buf == NULL)
        return TEST_FAIL;

    /* Parse + check OIDs, capture certBegin and sigIndex for later tamper. */
    wc_InitDecodedCert(&cert, buf, (word32)bytes, NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL), 0);
    ExpectIntEQ((int)cert.keyOID, (int)expectedKeyOID);
    ExpectIntEQ((int)cert.signatureOID, (int)expectedSigOID);
    certBegin = cert.certBegin;
    sigIndex  = cert.sigIndex;
    wc_FreeDecodedCert(&cert);

    /* Full verify against a self-installed trust anchor. */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, buf, (long)bytes,
        WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, buf, (long)bytes,
        WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }

    ExpectNotNull(tampered = (byte*)XMALLOC((size_t)bytes, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));

    /* Negative 1: flip a byte inside the signatureValue BIT STRING.
     * Everything after sigIndex is the signatureAlgorithm + the BIT
     * STRING payload, so flipping the last byte is always inside the
     * signature content. */
    if (tampered != NULL) {
        XMEMCPY(tampered, buf, (size_t)bytes);
        tampered[bytes - 1] ^= 0x01;
        ExpectNotNull(cm = wolfSSL_CertManagerNew());
        ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, buf, (long)bytes,
            WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, tampered,
            (long)bytes, WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        if (cm != NULL) {
            wolfSSL_CertManagerFree(cm);
            cm = NULL;
        }
    }

    /* Negative 2: flip a byte at the midpoint of the TBSCertificate. The
     * TBS is the first element of the outer Certificate SEQUENCE and
     * its bytes lie between (certBegin + outerSeqHeader) and sigIndex.
     * Picking the midpoint ensures we're inside TBS regardless of the
     * fixture's DN / extensions layout. */
    if (tampered != NULL && sigIndex > certBegin + 8U) {
        word32 midTbs = certBegin + 8 + ((sigIndex - (certBegin + 8)) / 2);
        XMEMCPY(tampered, buf, (size_t)bytes);
        tampered[midTbs] ^= 0x01;
        ExpectNotNull(cm = wolfSSL_CertManagerNew());
        ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, buf, (long)bytes,
            WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, tampered,
            (long)bytes, WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        if (cm != NULL) {
            wolfSSL_CertManagerFree(cm);
            cm = NULL;
        }
    }

    /* The fixtures MUST carry a KeyUsage extension with at least one of
     * digitalSignature / nonRepudiation / keyCertSign / cRLSign set per
     * RFC 9802 sec 3. Re-parse and assert that wolfSSL recorded a non-
     * empty set of KeyUsage bits from one of those values. */
    wc_InitDecodedCert(&cert, buf, (word32)bytes, NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL), 0);
    ExpectIntEQ(cert.extKeyUsageSet, 1);
    ExpectIntNE(cert.extKeyUsage & (KEYUSE_DIGITAL_SIG | KEYUSE_CONTENT_COMMIT |
        KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN), 0);
    wc_FreeDecodedCert(&cert);

    XFREE(tampered, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}
#endif

/* Direct wolfCrypt-level negative tests for the parameter-derivation
 * helpers used by the RFC 9802 parse path. These exercise failure modes
 * (unknown algorithm bytes, truncated inputs, mismatches) that a real
 * cert body wouldn't easily reach. */
#if defined(WOLFSSL_HAVE_LMS)
static int rfc9802_lms_import_negative(void)
{
    EXPECT_DECLS;
    LmsKey key;
    /* 60-byte buffer matches HSS_PUBLIC_KEY_LEN(32), just like a valid
     * SHA-256/M32/H5 key; the algorithm-type bytes are junk so param
     * derivation must fail cleanly. */
    byte   junk[60];

    XMEMSET(junk, 0, sizeof(junk));
    /* levels=1, lmsType=0xFFFFFFFF, lmOtsType=0xFFFFFFFF. */
    junk[3] = 1;
    XMEMSET(junk + 4, 0xFF, 4);
    XMEMSET(junk + 8, 0xFF, 4);

    /* Unknown algorithm types must be rejected. */
    ExpectIntEQ(wc_LmsKey_Init(&key, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_LmsKey_ImportPubRaw(&key, junk, sizeof(junk)),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    wc_LmsKey_Free(&key);

    /* Too-short buffer: only L + lmsType, no lmOtsType. */
    ExpectIntEQ(wc_LmsKey_Init(&key, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_LmsKey_ImportPubRaw(&key, junk, 8),
        WC_NO_ERR_TRACE(BUFFER_E));
    wc_LmsKey_Free(&key);

#if !defined(WOLFSSL_NO_LMS_SHA256_256)
    /* The two cases below pin specific SHA-256/M32 parameter codes
     * (L1_H5_W8, L1_H5_W4, L1_H10_W2). Skip them in builds where the
     * SHA-256/M32 family is disabled -- the family-agnostic checks
     * above (junk algorithm types, too-short buffer, GetSigLen on
     * unconfigured key) still cover the universal invariants. */

    /* Pre-set params that disagree with the raw key's algorithm bytes:
     * configure H=5/W=8 but feed buffer that claims H=10 / W=2. */
    XMEMSET(junk, 0, sizeof(junk));
    junk[3] = 1;       /* levels=1     */
    junk[7] = 6;       /* lmsType = LMS_SHA256_M32_H10 = 6 */
    junk[11] = 2;      /* lmOtsType = LMOTS_SHA256_N32_W2 = 2 */
    ExpectIntEQ(wc_LmsKey_Init(&key, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_LmsKey_SetParameters(&key, 1, 5, 8), 0);
    ExpectIntEQ(wc_LmsKey_ImportPubRaw(&key, junk, sizeof(junk)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_LmsKey_Free(&key);
#endif /* !WOLFSSL_NO_LMS_SHA256_256 */

    /* GetSigLen on a key with no params set must not NULL-deref the
     * params pointer; it must return BAD_FUNC_ARG instead. */
    {
        word32 sigLen = 0;
        ExpectIntEQ(wc_LmsKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_LmsKey_GetSigLen(&key, &sigLen),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_LmsKey_Free(&key);
    }

#if !defined(WOLFSSL_NO_LMS_SHA256_256)
    /* Partial-write invariant: a length mismatch after a successful
     * auto-derive must leave key->params NULL. Build a buffer whose
     * leading u32str(L) || lmsType || lmOtsType identifies a known
     * parameter set, but truncate to one byte less than the real pub
     * key length so the post-derive length check fails. */
    {
        byte truncated[59];   /* HSS_PUBLIC_KEY_LEN(32) is 60 */
        XMEMSET(truncated, 0, sizeof(truncated));
        truncated[3] = 1;     /* L = 1 */
        truncated[7] = 5;     /* lmsType = LMS_SHA256_M32_H5 */
        truncated[11] = 4;    /* lmOtsType = LMOTS_SHA256_N32_W4 */
        ExpectIntEQ(wc_LmsKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectNull(key.params);
        ExpectIntEQ(wc_LmsKey_ImportPubRaw(&key, truncated,
            sizeof(truncated)), WC_NO_ERR_TRACE(BUFFER_E));
        ExpectNull(key.params);
        wc_LmsKey_Free(&key);
    }
#endif /* !WOLFSSL_NO_LMS_SHA256_256 */

    return EXPECT_RESULT();
}
#endif

#if defined(WOLFSSL_HAVE_XMSS)
static int rfc9802_xmss_import_negative(void)
{
    EXPECT_DECLS;
    XmssKey key;
    byte    junk[8];

    XMEMSET(junk, 0, sizeof(junk));

    /* Too-short buffer. */
    ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, junk, 2, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    wc_XmssKey_Free(&key);

    /* Unknown OID (all-zero) for both XMSS and XMSS^MT. */
    ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, junk, sizeof(junk), 0),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    wc_XmssKey_Free(&key);
    ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, junk, sizeof(junk), 1),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    wc_XmssKey_Free(&key);

    /* NULL key / input. */
    ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(NULL, junk, sizeof(junk), 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, NULL, 8, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_XmssKey_Free(&key);

    /* GetSigLen on a key with no params set must not NULL-deref the
     * params pointer; it must return BAD_FUNC_ARG instead. */
    {
        word32 sigLen = 0;
        ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_XmssKey_GetSigLen(&key, &sigLen),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_XmssKey_Free(&key);
    }

#if !defined(WOLFSSL_XMSS_MIN_HEIGHT) || (WOLFSSL_XMSS_MIN_HEIGHT <= 10)
    /* Once params have been configured (state != INITED), the OID
     * prefix in the raw key MUST match key->oid and is_xmssmt MUST
     * match key->is_xmssmt. Set XMSS-SHA2_10_256 and feed a valid-
     * sized buffer whose 4-byte OID prefix is bogus -> BAD_FUNC_ARG. */
    {
        byte mismatch[XMSS_SHA256_PUBLEN];
        ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256"), 0);
        XMEMSET(mismatch, 0, sizeof(mismatch));
        mismatch[3] = 0x77; /* nonsense OID */
        ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, mismatch,
            sizeof(mismatch), 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* Same buffer with the correct OID, but is_xmssmt hint
         * contradicts the configured family -> BAD_FUNC_ARG. */
        mismatch[3] = 0x01; /* WC_XMSS_OID_SHA2_10_256 */
        ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, mismatch,
            sizeof(mismatch), 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_XmssKey_Free(&key);
    }

    /* Partial-write invariant: a length mismatch after a successful
     * auto-derive must leave the key in its INITED state, with
     * key->params NULL. */
    {
        byte truncated[XMSS_SHA256_PUBLEN - 1];
        XMEMSET(truncated, 0, sizeof(truncated));
        truncated[3] = 0x01;
        ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectNull(key.params);
        ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, truncated,
            sizeof(truncated), 0), WC_NO_ERR_TRACE(BUFFER_E));
        ExpectNull(key.params);
        wc_XmssKey_Free(&key);
    }

    /* is_xmssmt disambiguation: XMSS oid=1 and XMSS^MT oid=1 share
     * the wire-numeric value but resolve to different parameter sets.
     * Importing the same 68-byte buffer with hint=0 vs hint=1 must
     * land in different tables and produce distinct is_xmssmt. */
    {
        byte buf[XMSS_SHA256_PUBLEN];
        XMEMSET(buf, 0, sizeof(buf));
        buf[3] = 0x01;

        ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, buf, sizeof(buf), 0), 0);
        ExpectIntEQ((int)key.is_xmssmt, 0);
        wc_XmssKey_Free(&key);

    #if WOLFSSL_XMSS_MAX_HEIGHT >= 20
        ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, buf, sizeof(buf), 1), 0);
        ExpectIntEQ((int)key.is_xmssmt, 1);
        wc_XmssKey_Free(&key);
    #endif
    }

    /* Lenient state: re-importing the same pub key into a VERIFYONLY
     * key (params set, no private material) succeeds. The second
     * call exercises the lenient-state branch. */
    {
        byte buf[XMSS_SHA256_PUBLEN];
        XMEMSET(buf, 0, sizeof(buf));
        buf[3] = 0x01;

        ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, buf, sizeof(buf), 0), 0);
        ExpectIntEQ((int)key.state, (int)WC_XMSS_STATE_VERIFYONLY);
        ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, buf, sizeof(buf), 0), 0);
        ExpectIntEQ((int)key.state, (int)WC_XMSS_STATE_VERIFYONLY);
        wc_XmssKey_Free(&key);
    }

    /* Strict signature-length check: wc_XmssKey_Verify rejects any
     * sigLen != key->params->sig_len. This guards every consumer
     * (RFC 9802 X.509, PKCS#7, CMS, ...) against a longer wrapper that
     * happens to start with a valid signature. Construct a key in
     * VERIFYONLY state, then verify with sig_len + 1 and sig_len - 1
     * byte buffers; both must fail with BUFFER_E before any crypto
     * runs. The buffer contents are irrelevant since the length check
     * fires first. */
    {
        byte    pub[XMSS_SHA256_PUBLEN];
        byte*   sigBuf = NULL;
        word32  sigLen = 0;
        const byte msg[1] = { 0 };

        XMEMSET(pub, 0, sizeof(pub));
        pub[3] = 0x01;
        ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, pub, sizeof(pub), 0), 0);
        ExpectIntEQ((int)key.state, (int)WC_XMSS_STATE_VERIFYONLY);
        ExpectIntEQ(wc_XmssKey_GetSigLen(&key, &sigLen), 0);
        ExpectIntGT(sigLen, 0);
        ExpectNotNull(sigBuf = (byte*)XMALLOC((size_t)sigLen + 1, NULL,
            DYNAMIC_TYPE_TMP_BUFFER));
        if (sigBuf != NULL) {
            XMEMSET(sigBuf, 0, (size_t)sigLen + 1);
            ExpectIntEQ(wc_XmssKey_Verify(&key, sigBuf, sigLen + 1,
                msg, (int)sizeof(msg)), WC_NO_ERR_TRACE(BUFFER_E));
            ExpectIntEQ(wc_XmssKey_Verify(&key, sigBuf, sigLen - 1,
                msg, (int)sizeof(msg)), WC_NO_ERR_TRACE(BUFFER_E));
            XFREE(sigBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        wc_XmssKey_Free(&key);
    }

    /* BAD_STATE_E branch: WC_XMSS_STATE_OK must be rejected. Reaching
     * OK normally requires a successful private-key Reload / sign,
     * which is unavailable in WOLFSSL_XMSS_VERIFY_ONLY builds. Force
     * the state directly to exercise the rejection without coupling
     * this helper to the signing test fixture; sk stays NULL so Free
     * is still safe. */
    {
        byte pub[XMSS_SHA256_PUBLEN];

        XMEMSET(pub, 0, sizeof(pub));
        pub[3] = 0x01;
        ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256"), 0);
        key.state = WC_XMSS_STATE_OK;
        ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, pub, sizeof(pub), 0),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_XmssKey_Free(&key);
    }
#endif

    return EXPECT_RESULT();
}
#endif

/* Collect the byte offset of the final sub-identifier of every
 * 1.3.6.1.5.5.7.6.<lastByte> OID in a DER cert (XMSS ends 0x22, XMSS^MT ends
 * 0x23). RFC 9802 reuses the same OID for the SubjectPublicKeyInfo algorithm,
 * the TBS signatureAlgorithm and the outer signatureAlgorithm, so a conformant
 * XMSS/XMSS^MT cert contains exactly three, in TBS-signature / SPKI-key /
 * outer-signature order. Returns the number of occurrences found. */
#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_HAVE_XMSS) && \
    !defined(WOLFSSL_XMSS_VERIFY_ONLY) && defined(WOLFSSL_CERT_GEN) && \
    !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
static int rfc9802_collect_hbs_oid_offsets(const byte* der, word32 derSz,
    byte lastByte, word32* offsets, int maxOff)
{
    /* OID body for 1.3.6.1.5.5.7.6: 2B 06 01 05 05 07 06, then <lastByte>. */
    static const byte pfx[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06 };
    int    n = 0;
    word32 i;

    for (i = 0; (word32)(i + sizeof(pfx)) < derSz; i++) {
        if (XMEMCMP(der + i, pfx, sizeof(pfx)) == 0 &&
                der[i + sizeof(pfx)] == lastByte) {
            if (n < maxOff)
                offsets[n] = i + (word32)sizeof(pfx);
            n++;
        }
    }
    return n;
}
#endif

int test_rfc9802_lms_x509_verify(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_LMS)
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(WOLFSSL_NO_LMS_SHA256_256)
    /* Cross-implementation interop gate. bc_lms_native_bc_root.der is
     * generated through Bouncy Castle's stock JcaContentSignerBuilder("LMS")
     * + JcaX509v3CertificateBuilder with no overrides; BC's native LMS X.509
     * path is RFC 9802-compliant for HSS/LMS, so wolfSSL must accept it
     * end-to-end. This is the one fixture from an independent implementation
     * that we keep; wolfSSL's own generation is exercised by
     * test_rfc9802_lms_x509_gen instead of committed wolfSSL fixtures. */
    ExpectIntEQ(rfc9802_verify_one_cert("./certs/lms/bc_lms_native_bc_root.der",
        HSS_LMSk, CTC_HSS_LMS), TEST_SUCCESS);
#endif /* !NO_FILESYSTEM && !NO_CERTS && !WOLFSSL_NO_LMS_SHA256_256 */
    /* Pure wolfCrypt-level negative tests don't need filesystem or cert
     * support, so they run for any LMS-enabled build. */
    ExpectIntEQ(rfc9802_lms_import_negative(), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

int test_rfc9802_xmss_x509_verify(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_XMSS)
    /* No independent (RFC 9802-aligned) third-party XMSS X.509 implementation
     * exists to interop against - OpenSSL has no XMSS cert signing and Bouncy
     * Castle's XMSS encoding is not yet aligned with the final RFC - so there
     * is no committed interop fixture here. wolfSSL's own XMSS/XMSS^MT cert
     * generation, chain signing and the X.509-level signatureAlgorithm/SPKI
     * mismatch rejection are exercised in test_rfc9802_xmss_x509_gen.
     *
     * Pure wolfCrypt-level negative tests run for any XMSS-enabled build. */
    ExpectIntEQ(rfc9802_xmss_import_negative(), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* RFC 9802 certificate/CSR GENERATION tests.
 *
 * These exercise the cert-gen path (wc_MakeCert_ex / wc_SignCert_ex and
 * wc_MakeCertReq_ex) with a freshly generated LMS or XMSS key, then feed
 * the result back through the existing verification path to prove the
 * generated SubjectPublicKeyInfo, signatureAlgorithm and signature are
 * RFC 9802-compliant and self-consistent. */
/* RFC 9802 cert/CSR generation is only wired into the ASN.1 template
 * implementation (the original/non-template path has no LMS/XMSS support),
 * so all of these tests require WOLFSSL_ASN_TEMPLATE. */
#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_CERT_GEN) && \
    !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    ((defined(WOLFSSL_HAVE_LMS)  && !defined(WOLFSSL_LMS_VERIFY_ONLY)) || \
     (defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY)))
/* Populate a minimal self-consistent subject/issuer name. */
static void rfc9802_gen_set_names(Cert* cert)
{
    XSTRNCPY(cert->subject.country,    "US",                  CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.state,      "OR",                  CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.locality,   "Portland",            CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.org,        "wolfSSL",             CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.unit,       "Testing",             CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.commonName, "RFC9802 Gen Root CA", CTC_NAME_SIZE);
}

/* Verify a self-signed DER cert by loading it as its own CA. */
static int rfc9802_gen_verify_selfsigned(const byte* der, int derSz)
{
    EXPECT_DECLS;
    WOLFSSL_CERT_MANAGER* cm = NULL;

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, der, (long)derSz,
        WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, (long)derSz,
        WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    if (cm != NULL)
        wolfSSL_CertManagerFree(cm);
    return EXPECT_RESULT();
}

#ifdef WOLFSSL_CERT_REQ
/* Parse a generated CSR and confirm its proof-of-possession signature. */
static int rfc9802_gen_verify_csr(const byte* der, int derSz)
{
    EXPECT_DECLS;
    DecodedCert dc;

    wc_InitDecodedCert(&dc, der, (word32)derSz, NULL);
    ExpectIntEQ(wc_ParseCert(&dc, CERTREQ_TYPE, VERIFY, NULL), 0);
    wc_FreeDecodedCert(&dc);
    return EXPECT_RESULT();
}
#endif /* WOLFSSL_CERT_REQ */

/* Generate a self-signed root CA (and, when CSRs are enabled, a PKCS#10
 * request) for an already-made key, then feed each back through the
 * verification path. keyType is the wc_MakeCert_ex/wc_SignCert_ex selector
 * (LMS_TYPE / XMSS_TYPE / XMSSMT_TYPE) and sigType the matching CTC_ OID.
 * key is void* to mirror the public wc_MakeCert_ex API; callers must pass a
 * key object whose type matches keyType. */
static int rfc9802_gen_roundtrip(void* key, int keyType, int sigType,
    WC_RNG* rng, word32 derCap)
{
    EXPECT_DECLS;
    byte* der = NULL;
    int   derSz = 0;

    ExpectNotNull(der = (byte*)XMALLOC(derCap, NULL, DYNAMIC_TYPE_TMP_BUFFER));

    /* Self-signed root CA: generate -> sign -> verify round trip. */
    if (EXPECT_SUCCESS() && der != NULL) {
        Cert cert;
        ExpectIntEQ(wc_InitCert(&cert), 0);
        rfc9802_gen_set_names(&cert);
        cert.sigType    = sigType;
        cert.isCA       = 1;
        cert.selfSigned = 1;
        cert.daysValid  = 365;
        ExpectIntGT(wc_MakeCert_ex(&cert, der, derCap, keyType, key, rng), 0);
        ExpectIntGT(derSz = wc_SignCert_ex(cert.bodySz, cert.sigType, der,
            derCap, keyType, key, rng), 0);
        ExpectIntEQ(rfc9802_gen_verify_selfsigned(der, derSz), TEST_SUCCESS);
    }

#ifdef WOLFSSL_CERT_REQ
    /* PKCS#10 CSR: generate -> self-sign proof-of-possession -> parse. */
    if (EXPECT_SUCCESS() && der != NULL) {
        Cert cert;
        ExpectIntEQ(wc_InitCert(&cert), 0);
        rfc9802_gen_set_names(&cert);
        cert.sigType = sigType;
        ExpectIntGT(wc_MakeCertReq_ex(&cert, der, derCap, keyType, key), 0);
        ExpectIntGT(derSz = wc_SignCert_ex(cert.bodySz, cert.sigType, der,
            derCap, keyType, key, rng), 0);
        ExpectIntEQ(rfc9802_gen_verify_csr(der, derSz), TEST_SUCCESS);
    }
#endif /* WOLFSSL_CERT_REQ */

    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}

/* wc_ecc_make_key is available with HAVE_ECC; HAVE_ECC_KEY_EXPORT is needed
 * for the leaf SPKI and !WC_NO_RNG for key generation. */
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && !defined(WC_NO_RNG)
/* Subject name for the generated leaf (distinct from the CA subject). */
static void rfc9802_gen_set_leaf_names(Cert* cert)
{
    XSTRNCPY(cert->subject.country,    "US",                CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.state,      "OR",                CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.locality,   "Portland",          CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.org,        "wolfSSL",           CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.unit,       "Testing",           CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.commonName, "RFC9802 Gen Leaf",  CTC_NAME_SIZE);
}

/* Generate a self-signed LMS/XMSS CA, then an ECC leaf issued and signed by
 * that CA, and confirm the leaf chains to the CA (and fails without it). This
 * is the real RFC 9802 use case - a hash-based CA signing another cert - that
 * self-signed roots and CSRs don't cover. caKey is the already-made CA key;
 * caKeyType/caSigType select its algorithm. */
static int rfc9802_gen_chain(void* caKey, int caKeyType, int caSigType,
    WC_RNG* rng, word32 derCap)
{
    EXPECT_DECLS;
    ecc_key leafKey;
    int     leafKeyInit = 0;
    byte*   caDer   = NULL;
    byte*   leafDer = NULL;
    int     caSz   = 0;
    int     leafSz = 0;
    WOLFSSL_CERT_MANAGER* cm = NULL;

    ExpectNotNull(caDer = (byte*)XMALLOC(derCap, NULL, DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(leafDer = (byte*)XMALLOC(derCap, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(wc_ecc_init(&leafKey), 0);
    leafKeyInit = 1;
    ExpectIntEQ(wc_ecc_make_key(rng, 32, &leafKey), 0);

    /* Self-signed CA root. */
    if (EXPECT_SUCCESS() && caDer != NULL) {
        Cert ca;
        ExpectIntEQ(wc_InitCert(&ca), 0);
        rfc9802_gen_set_names(&ca);
        ca.sigType    = caSigType;
        ca.isCA       = 1;
        ca.selfSigned = 1;
        ca.daysValid  = 365;
        ExpectIntGT(wc_MakeCert_ex(&ca, caDer, derCap, caKeyType, caKey, rng),
            0);
        ExpectIntGT(caSz = wc_SignCert_ex(ca.bodySz, caSigType, caDer, derCap,
            caKeyType, caKey, rng), 0);
    }

    /* ECC leaf, issued by the CA's subject and signed with the CA key. */
    if (EXPECT_SUCCESS() && leafDer != NULL && caSz > 0) {
        Cert leaf;
        ExpectIntEQ(wc_InitCert(&leaf), 0);
        rfc9802_gen_set_leaf_names(&leaf);
        leaf.sigType   = caSigType;
        leaf.daysValid = 365;
        ExpectIntEQ(wc_SetIssuerBuffer(&leaf, caDer, caSz), 0);
        ExpectIntGT(wc_MakeCert_ex(&leaf, leafDer, derCap, ECC_TYPE, &leafKey,
            rng), 0);
        ExpectIntGT(leafSz = wc_SignCert_ex(leaf.bodySz, caSigType, leafDer,
            derCap, caKeyType, caKey, rng), 0);
    }

    /* Leaf verifies only when the CA is the trust anchor. */
    if (EXPECT_SUCCESS() && leafSz > 0) {
        ExpectNotNull(cm = wolfSSL_CertManagerNew());
        ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, caDer, (long)caSz,
            WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, leafDer, (long)leafSz,
            WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        if (cm != NULL) {
            wolfSSL_CertManagerFree(cm);
            cm = NULL;
        }
        ExpectNotNull(cm = wolfSSL_CertManagerNew());
        ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, leafDer, (long)leafSz,
            WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        if (cm != NULL) {
            wolfSSL_CertManagerFree(cm);
            cm = NULL;
        }
    }

    /* Negative: corrupt the leaf's signature (last byte of the DER, in the
     * signatureValue) and confirm verification fails even with the CA loaded.
     * This proves the CA's hash-based signature is cryptographically checked,
     * not accepted on issuer-name chaining alone. */
    if (EXPECT_SUCCESS() && leafSz > 0) {
        byte saved = leafDer[leafSz - 1];
        leafDer[leafSz - 1] ^= 0xFF;
        ExpectNotNull(cm = wolfSSL_CertManagerNew());
        ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, caDer, (long)caSz,
            WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, leafDer, (long)leafSz,
            WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        if (cm != NULL) {
            wolfSSL_CertManagerFree(cm);
            cm = NULL;
        }
        leafDer[leafSz - 1] = saved;
    }

    if (leafKeyInit)
        wc_ecc_free(&leafKey);
    XFREE(leafDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(caDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}
#endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT */
#endif /* gen test support */

#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_HAVE_LMS) && \
    !defined(WOLFSSL_LMS_VERIFY_ONLY) && \
    defined(WOLFSSL_CERT_GEN) && !defined(NO_FILESYSTEM) && \
    !defined(NO_CERTS) && !defined(WOLFSSL_NO_LMS_SHA256_256)
/* Init an LMS key with the shared persistence callbacks and given params. */
static int rfc9802_gen_lms_init(LmsKey* key, int levels, int height, int win)
{
    int ret = wc_LmsKey_Init(key, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_LmsKey_SetParameters(key, levels, height, win);
    if (ret == 0)
        ret = wc_LmsKey_SetWriteCb(key, test_lms_write_key);
    if (ret == 0)
        ret = wc_LmsKey_SetReadCb(key, test_lms_read_key);
    if (ret == 0)
        ret = wc_LmsKey_SetContext(key, (void*)LMS_TEST_PRIV_KEY_FILE);
    return ret;
}
#endif

int test_rfc9802_lms_x509_gen(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_HAVE_LMS) && \
    !defined(WOLFSSL_LMS_VERIFY_ONLY) && \
    defined(WOLFSSL_CERT_GEN) && !defined(NO_FILESYSTEM) && \
    !defined(NO_CERTS) && !defined(WOLFSSL_NO_LMS_SHA256_256)
    LmsKey  key;
    WC_RNG  rng;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Single-level LMS (L1-H5-W8). */
    remove(LMS_TEST_PRIV_KEY_FILE);
    ExpectIntEQ(rfc9802_gen_lms_init(&key, 1, 5, 8), 0);
    ExpectIntEQ(wc_LmsKey_MakeKey(&key, &rng), 0);
    ExpectIntEQ(rfc9802_gen_roundtrip(&key, LMS_TYPE, CTC_HSS_LMS, &rng, 8192),
        TEST_SUCCESS);

    /* Negative: signing an LMS key with a non-LMS signature OID must be
     * rejected rather than emit a cert whose signatureAlgorithm contradicts
     * its public key. The check fires before any signature is produced, so
     * the key's one-time signatures are not consumed. */
    if (EXPECT_SUCCESS()) {
        Cert  cert;
        byte* tmp = NULL;
        ExpectNotNull(tmp = (byte*)XMALLOC(8192, NULL, DYNAMIC_TYPE_TMP_BUFFER));
        ExpectIntEQ(wc_InitCert(&cert), 0);
        rfc9802_gen_set_names(&cert);
        cert.sigType    = CTC_HSS_LMS;
        cert.isCA       = 1;
        cert.selfSigned = 1;
        cert.daysValid  = 365;
        if (tmp != NULL) {
            ExpectIntGT(wc_MakeCert_ex(&cert, tmp, 8192, LMS_TYPE, &key,
                &rng), 0);
            ExpectIntEQ(wc_SignCert_ex(cert.bodySz, CTC_XMSS, tmp, 8192,
                LMS_TYPE, &key, &rng), WC_NO_ERR_TRACE(ALGO_ID_E));
        }
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && !defined(WC_NO_RNG)
    /* Real CA use case: the LMS CA signs an ECC leaf; the leaf must chain to
     * the CA. Reuses the L1 key (plenty of one-time signatures remain). */
    ExpectIntEQ(rfc9802_gen_chain(&key, LMS_TYPE, CTC_HSS_LMS, &rng, 8192),
        TEST_SUCCESS);
#endif

    wc_LmsKey_Free(&key);
    remove(LMS_TEST_PRIV_KEY_FILE);

#if !defined(WOLFSSL_LMS_MAX_LEVELS) || (WOLFSSL_LMS_MAX_LEVELS >= 2)
    /* Multi-level HSS (L2-H5-W8): the signature embeds a lower-level LMS
     * public key + signature, exercising the larger, multi-level encoding. */
    remove(LMS_TEST_PRIV_KEY_FILE);
    ExpectIntEQ(rfc9802_gen_lms_init(&key, 2, 5, 8), 0);
    ExpectIntEQ(wc_LmsKey_MakeKey(&key, &rng), 0);
    ExpectIntEQ(rfc9802_gen_roundtrip(&key, LMS_TYPE, CTC_HSS_LMS, &rng, 8192),
        TEST_SUCCESS);
    wc_LmsKey_Free(&key);
    remove(LMS_TEST_PRIV_KEY_FILE);
#endif

#if !defined(WOLFSSL_LMS_MAX_LEVELS) || (WOLFSSL_LMS_MAX_LEVELS >= 3)
    /* Three-level HSS with Winternitz 4 (L3-H5-W4): exercises the deepest
     * multi-level encoding and a different Winternitz parameter than the
     * W8 cases above. */
    remove(LMS_TEST_PRIV_KEY_FILE);
    ExpectIntEQ(rfc9802_gen_lms_init(&key, 3, 5, 4), 0);
    ExpectIntEQ(wc_LmsKey_MakeKey(&key, &rng), 0);
    ExpectIntEQ(rfc9802_gen_roundtrip(&key, LMS_TYPE, CTC_HSS_LMS, &rng, 8192),
        TEST_SUCCESS);
    wc_LmsKey_Free(&key);
    remove(LMS_TEST_PRIV_KEY_FILE);
#endif

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_HAVE_XMSS) && \
    !defined(WOLFSSL_XMSS_VERIFY_ONLY) && \
    defined(WOLFSSL_CERT_GEN) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
#define XMSS_GEN_TEST_PRIV_KEY_FILE "/tmp/wolfssl_test_xmss_gen.key"
static enum wc_XmssRc xmss_gen_write_key(const byte* priv, word32 privSz,
    void* context)
{
    XFILE f = XFOPEN((const char*)context, "wb");
    enum wc_XmssRc ret = WC_XMSS_RC_SAVED_TO_NV_MEMORY;
    if (f == XBADFILE)
        return WC_XMSS_RC_WRITE_FAIL;
    if (XFWRITE(priv, 1, privSz, f) != privSz)
        ret = WC_XMSS_RC_WRITE_FAIL;
    XFCLOSE(f);
    return ret;
}
static enum wc_XmssRc xmss_gen_read_key(byte* priv, word32 privSz,
    void* context)
{
    XFILE f = XFOPEN((const char*)context, "rb");
    enum wc_XmssRc ret = WC_XMSS_RC_READ_TO_MEMORY;
    if (f == XBADFILE)
        return WC_XMSS_RC_READ_FAIL;
    if (XFREAD(priv, 1, privSz, f) != privSz)
        ret = WC_XMSS_RC_READ_FAIL;
    XFCLOSE(f);
    return ret;
}

/* Init an XMSS/XMSS^MT key with the shared persistence callbacks. */
static int rfc9802_gen_xmss_init(XmssKey* key, const char* paramStr)
{
    int ret = wc_XmssKey_Init(key, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_XmssKey_SetParamStr(key, paramStr);
    if (ret == 0)
        ret = wc_XmssKey_SetWriteCb(key, xmss_gen_write_key);
    if (ret == 0)
        ret = wc_XmssKey_SetReadCb(key, xmss_gen_read_key);
    if (ret == 0)
        ret = wc_XmssKey_SetContext(key, (void*)XMSS_GEN_TEST_PRIV_KEY_FILE);
    return ret;
}

/* X.509-level negative tests on a wolfSSL-generated XMSS/XMSS^MT cert, run
 * against the already-made key (no extra keygen). oidLast is the cert's true
 * final OID byte (XMSS 0x22, XMSS^MT 0x23) and oidSwap the other family's:
 *
 *  (a) flip only the outer signatureAlgorithm OID -> it no longer equals the
 *      TBS signatureAlgorithm, which the generic X.509 algId-consistency check
 *      rejects (ASN_SIG_OID_E at parse);
 *  (b) flip both signatureAlgorithm copies (TBS + outer) but leave the SPKI
 *      key OID -> outer == TBS (that check passes), yet the signature
 *      algorithm now disagrees with the public-key algorithm, which RFC 9802
 *      requires verification to reject (SigOidMatchesKeyOid, before the - now
 *      also invalid - signature is even checked).
 *
 * Either way verification must fail. */
static int rfc9802_gen_xmss_oid_tamper(void* key, int keyType, int sigType,
    WC_RNG* rng, byte oidLast, byte oidSwap)
{
    EXPECT_DECLS;
    byte*  der = NULL;
    int    derSz = 0;
    word32 off[8];
    int    n = 0;
    WOLFSSL_CERT_MANAGER* cm = NULL;

    ExpectNotNull(der = (byte*)XMALLOC(16384, NULL, DYNAMIC_TYPE_TMP_BUFFER));

    if (EXPECT_SUCCESS() && der != NULL) {
        Cert cert;
        ExpectIntEQ(wc_InitCert(&cert), 0);
        rfc9802_gen_set_names(&cert);
        cert.sigType    = sigType;
        cert.isCA       = 1;
        cert.selfSigned = 1;
        cert.daysValid  = 365;
        ExpectIntGT(wc_MakeCert_ex(&cert, der, 16384, keyType, key, rng), 0);
        ExpectIntGT(derSz = wc_SignCert_ex(cert.bodySz, sigType, der, 16384,
            keyType, key, rng), 0);
    }

    if (EXPECT_SUCCESS() && derSz > 0) {
        n = rfc9802_collect_hbs_oid_offsets(der, (word32)derSz, oidLast, off, 8);
        /* TBS-signature, SPKI-key, outer-signature - in that order. */
        ExpectIntEQ(n, 3);
    }

    /* (a) Outer signatureAlgorithm != TBS signatureAlgorithm. */
    if (EXPECT_SUCCESS() && n == 3) {
        der[off[2]] = oidSwap;
        ExpectNotNull(cm = wolfSSL_CertManagerNew());
        (void)wolfSSL_CertManagerLoadCABuffer(cm, der, (long)derSz,
            WOLFSSL_FILETYPE_ASN1);
        ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, der, (long)derSz,
            WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        if (cm != NULL) {
            wolfSSL_CertManagerFree(cm);
            cm = NULL;
        }
        der[off[2]] = oidLast; /* restore */
    }

    /* (b) signatureAlgorithm (both copies) disagrees with the SPKI key OID. */
    if (EXPECT_SUCCESS() && n == 3) {
        der[off[0]] = oidSwap;
        der[off[2]] = oidSwap;
        ExpectNotNull(cm = wolfSSL_CertManagerNew());
        (void)wolfSSL_CertManagerLoadCABuffer(cm, der, (long)derSz,
            WOLFSSL_FILETYPE_ASN1);
        ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, der, (long)derSz,
            WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        if (cm != NULL) {
            wolfSSL_CertManagerFree(cm);
            cm = NULL;
        }
    }

    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}
#endif /* XMSS gen support */

int test_rfc9802_xmss_x509_gen(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_HAVE_XMSS) && \
    !defined(WOLFSSL_XMSS_VERIFY_ONLY) && \
    defined(WOLFSSL_CERT_GEN) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    XmssKey key;
    WC_RNG  rng;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Single-tree XMSS. */
    remove(XMSS_GEN_TEST_PRIV_KEY_FILE);
    ExpectIntEQ(rfc9802_gen_xmss_init(&key, "XMSS-SHA2_10_256"), 0);
    ExpectIntEQ(wc_XmssKey_MakeKey(&key, &rng), 0);
    ExpectIntEQ((int)key.is_xmssmt, 0);
    ExpectIntEQ(rfc9802_gen_roundtrip(&key, XMSS_TYPE, CTC_XMSS, &rng, 16384),
        TEST_SUCCESS);

    /* Negative: the XMSSMT_TYPE selector must not be accepted for a
     * single-tree XMSS key, and signing a single-tree key as XMSS^MT must be
     * rejected. Both checks fire before signing, so no signature is used. */
    if (EXPECT_SUCCESS()) {
        Cert  cert;
        byte* tmp = NULL;
        ExpectNotNull(tmp = (byte*)XMALLOC(16384, NULL,
            DYNAMIC_TYPE_TMP_BUFFER));
        ExpectIntEQ(wc_InitCert(&cert), 0);
        rfc9802_gen_set_names(&cert);
        cert.sigType    = CTC_XMSS;
        cert.isCA       = 1;
        cert.selfSigned = 1;
        cert.daysValid  = 365;
        /* Wrong selector for the key's tree variant. */
        if (tmp != NULL) {
            ExpectIntEQ(wc_MakeCert_ex(&cert, tmp, 16384, XMSSMT_TYPE, &key,
                &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            /* Correct selector, but signed with the XMSS^MT OID. */
            ExpectIntGT(wc_MakeCert_ex(&cert, tmp, 16384, XMSS_TYPE, &key,
                &rng), 0);
            ExpectIntEQ(wc_SignCert_ex(cert.bodySz, CTC_XMSSMT, tmp, 16384,
                XMSS_TYPE, &key, &rng), WC_NO_ERR_TRACE(ALGO_ID_E));
        }
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && !defined(WC_NO_RNG)
    /* Real CA use case: the XMSS CA signs an ECC leaf; the leaf must chain. */
    ExpectIntEQ(rfc9802_gen_chain(&key, XMSS_TYPE, CTC_XMSS, &rng, 16384),
        TEST_SUCCESS);
#endif
    /* X.509-level signatureAlgorithm/SPKI OID consistency, reusing this key. */
    ExpectIntEQ(rfc9802_gen_xmss_oid_tamper(&key, XMSS_TYPE, CTC_XMSS, &rng,
        /* XMSS */ 0x22, /* swap */ 0x23), TEST_SUCCESS);

    wc_XmssKey_Free(&key);
    remove(XMSS_GEN_TEST_PRIV_KEY_FILE);

    /* Multi-tree XMSS^MT: exercises the XMSSMT_TYPE selector, the
     * XMSSMTk public-key OID branch and the CTC_XMSSMT signature OID. */
    remove(XMSS_GEN_TEST_PRIV_KEY_FILE);
    ExpectIntEQ(rfc9802_gen_xmss_init(&key, "XMSSMT-SHA2_20/2_256"), 0);
    ExpectIntEQ(wc_XmssKey_MakeKey(&key, &rng), 0);
    ExpectIntEQ((int)key.is_xmssmt, 1);
    ExpectIntEQ(rfc9802_gen_roundtrip(&key, XMSSMT_TYPE, CTC_XMSSMT, &rng,
        16384), TEST_SUCCESS);
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && !defined(WC_NO_RNG)
    ExpectIntEQ(rfc9802_gen_chain(&key, XMSSMT_TYPE, CTC_XMSSMT, &rng, 16384),
        TEST_SUCCESS);
#endif
    ExpectIntEQ(rfc9802_gen_xmss_oid_tamper(&key, XMSSMT_TYPE, CTC_XMSSMT, &rng,
        /* XMSS^MT */ 0x23, /* swap */ 0x22), TEST_SUCCESS);
    wc_XmssKey_Free(&key);
    remove(XMSS_GEN_TEST_PRIV_KEY_FILE);

    /* A second XMSS^MT parameter set (different embedded param-set OID and a
     * larger signature) to keep the encoder/auto-derive decoder exercised
     * across sizes now that the committed multi-size fixtures are gone. */
    remove(XMSS_GEN_TEST_PRIV_KEY_FILE);
    ExpectIntEQ(rfc9802_gen_xmss_init(&key, "XMSSMT-SHA2_20/4_256"), 0);
    ExpectIntEQ(wc_XmssKey_MakeKey(&key, &rng), 0);
    ExpectIntEQ((int)key.is_xmssmt, 1);
    ExpectIntEQ(rfc9802_gen_roundtrip(&key, XMSSMT_TYPE, CTC_XMSSMT, &rng,
        16384), TEST_SUCCESS);
    wc_XmssKey_Free(&key);
    remove(XMSS_GEN_TEST_PRIV_KEY_FILE);

    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}
