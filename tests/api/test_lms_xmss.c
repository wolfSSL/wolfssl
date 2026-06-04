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
#if (defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
/* Sanity bound on a test fixture cert. The largest BC-generated
 * fixture we ship (XMSS^MT 40/8) is ~19 KiB; 1 MiB is well above
 * any realistic RFC 9802 cert and catches a wild XFTELL. Typed as
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

static int rfc9802_verify_one_cert(const char* path, word32 expectedKeyOID,
    word32 expectedSigOID)
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

        ExpectIntEQ(wc_XmssKey_Init(&key, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_XmssKey_ImportPubRaw_ex(&key, buf, sizeof(buf), 1), 0);
        ExpectIntEQ((int)key.is_xmssmt, 1);
        wc_XmssKey_Free(&key);
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

    return EXPECT_RESULT();
}
#endif

/* Walk the AlgorithmIdentifier SEQUENCE that begins at sigIndex and
 * locate the byte offset of the last byte of its OID content. Handles
 * both short-form (length < 128) and long-form DER length encodings,
 * so a future fixture-regenerator that emits longer OIDs / SEQUENCEs
 * still drives this test rather than tripping the loud-fail branch.
 *
 * Returns 0 on success with *oidLastByte set; returns -1 on any DER
 * shape mismatch. */
#if defined(WOLFSSL_HAVE_XMSS) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
static int rfc9802_find_sig_alg_oid_last_byte(const byte* buf, word32 bufLen,
    word32 sigIndex, word32* oidLastByte)
{
    word32 idx = sigIndex;
    word32 oidContentLen = 0;

    /* AlgorithmIdentifier ::= SEQUENCE { algorithm OID, ... } */
    if (idx >= bufLen || buf[idx] != 0x30)
        return -1;
    idx++;
    /* Skip SEQUENCE length (short or long form). */
    if (idx >= bufLen)
        return -1;
    if (buf[idx] < 0x80) {
        idx++;
    }
    else {
        word32 nbytes = (word32)(buf[idx] & 0x7F);
        if (nbytes == 0 || nbytes > 4 || idx + 1 + nbytes > bufLen)
            return -1;
        idx += 1 + nbytes;
    }
    /* algorithm OID tag. */
    if (idx >= bufLen || buf[idx] != 0x06)
        return -1;
    idx++;
    /* OID length (short or long form). */
    if (idx >= bufLen)
        return -1;
    if (buf[idx] < 0x80) {
        oidContentLen = buf[idx];
        idx++;
    }
    else {
        word32 nbytes = (word32)(buf[idx] & 0x7F);
        word32 i;
        if (nbytes == 0 || nbytes > 4 || idx + 1 + nbytes > bufLen)
            return -1;
        for (i = 0; i < nbytes; i++)
            oidContentLen = (oidContentLen << 8) | buf[idx + 1 + i];
        idx += 1 + nbytes;
    }
    if (oidContentLen == 0 || idx + oidContentLen > bufLen)
        return -1;
    *oidLastByte = idx + oidContentLen - 1;
    return 0;
}

/* Helper: load fixture, locate last byte of outer signatureAlgorithm
 * OID, patch it from `expected` to `swap`, and assert that verifying
 * the patched cert against itself as a trust anchor fails. */
static int rfc9802_assert_oid_patch_breaks_verify(const char* path,
    byte expectedLastByte, byte patchedLastByte)
{
    EXPECT_DECLS;
    byte*                 buf = NULL;
    int                   bytes = 0;
    DecodedCert           cert;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    word32                sigIndex = 0;
    word32                lastOidByte = 0;

    ExpectIntEQ(rfc9802_load_file(path, &buf, &bytes), TEST_SUCCESS);
    if (buf == NULL)
        return TEST_FAIL;

    wc_InitDecodedCert(&cert, buf, (word32)bytes, NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL), 0);
    sigIndex = cert.sigIndex;
    wc_FreeDecodedCert(&cert);

    ExpectIntEQ(rfc9802_find_sig_alg_oid_last_byte(buf, (word32)bytes,
        sigIndex, &lastOidByte), 0);
    /* Sanity-check the fixture matches the family the caller asserted,
     * so a future regenerator swapping fixtures fails loudly here
     * rather than silently testing the wrong direction. */
    ExpectIntEQ((int)buf[lastOidByte], (int)expectedLastByte);

    if (lastOidByte < (word32)bytes &&
            buf[lastOidByte] == expectedLastByte) {
        buf[lastOidByte] = patchedLastByte;
        ExpectNotNull(cm = wolfSSL_CertManagerNew());
        /* After the patch the cert's outer signatureAlgorithm and SPKI
         * disagree. Verification must fail somewhere (at parse, at
         * load, or at ConfirmSignature). The load is best-effort -
         * some shape changes get caught there, others only at verify. */
        (void)wolfSSL_CertManagerLoadCABuffer(cm, buf, (long)bytes,
            WOLFSSL_FILETYPE_ASN1);
        ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, buf,
            (long)bytes, WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
        if (cm != NULL) {
            wolfSSL_CertManagerFree(cm);
            cm = NULL;
        }
    }

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}

/* X.509-level negative: swap the outer signatureAlgorithm OID byte so
 * the cert declares XMSS where the SPKI is XMSS^MT, and vice versa.
 * SigOidMatchesKeyOid must reject both directions before any crypto. */
static int rfc9802_xmss_sig_oid_mismatch(void)
{
    EXPECT_DECLS;
    /* XMSS sigOID ends 0x22; XMSS^MT sigOID ends 0x23. Patch each
     * direction so the asymmetric-key path is exercised both ways -
     * a regression that only stripped the check from one branch of
     * SigOidMatchesKeyOid would otherwise be missed. */
    ExpectIntEQ(rfc9802_assert_oid_patch_breaks_verify(
        "./certs/xmss/bc_xmss_sha2_10_256_root.der",
        /* expected XMSS */ 0x22, /* patched to XMSS^MT */ 0x23),
        TEST_SUCCESS);
    ExpectIntEQ(rfc9802_assert_oid_patch_breaks_verify(
        "./certs/xmss/bc_xmssmt_sha2_20_2_256_root.der",
        /* expected XMSS^MT */ 0x23, /* patched to XMSS */ 0x22),
        TEST_SUCCESS);
    return EXPECT_RESULT();
}
#endif

/* Exercise a real CA -> leaf certificate chain, not just self-signed.
 * Loads the CA as a trust anchor and verifies the leaf against it. */
#if defined(WOLFSSL_HAVE_LMS) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
static int rfc9802_lms_chain_verify(void)
{
    EXPECT_DECLS;
    byte*                 caBuf   = NULL;
    byte*                 leafBuf = NULL;
    int                   caLen   = 0;
    int                   leafLen = 0;
    WOLFSSL_CERT_MANAGER* cm      = NULL;

    ExpectIntEQ(rfc9802_load_file("./certs/lms/bc_lms_chain_ca.der",
        &caBuf, &caLen), TEST_SUCCESS);
    ExpectIntEQ(rfc9802_load_file("./certs/lms/bc_lms_chain_leaf.der",
        &leafBuf, &leafLen), TEST_SUCCESS);

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    /* Only the CA is a trust anchor; the leaf is verified against it. */
    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, caBuf, (long)caLen,
        WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, leafBuf, (long)leafLen,
        WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);

    /* Without loading the CA the leaf must NOT verify. */
    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, leafBuf, (long)leafLen,
        WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }

    XFREE(leafBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(caBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}
#endif

/* Mirror of rfc9802_lms_chain_verify but for an XMSS CA -> leaf pair. */
#if defined(WOLFSSL_HAVE_XMSS) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
static int rfc9802_xmss_chain_verify(void)
{
    EXPECT_DECLS;
    byte*                 caBuf   = NULL;
    byte*                 leafBuf = NULL;
    int                   caLen   = 0;
    int                   leafLen = 0;
    WOLFSSL_CERT_MANAGER* cm      = NULL;

    ExpectIntEQ(rfc9802_load_file("./certs/xmss/bc_xmss_chain_ca.der",
        &caBuf, &caLen), TEST_SUCCESS);
    ExpectIntEQ(rfc9802_load_file("./certs/xmss/bc_xmss_chain_leaf.der",
        &leafBuf, &leafLen), TEST_SUCCESS);

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, caBuf, (long)caLen,
        WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, leafBuf, (long)leafLen,
        WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);

    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, leafBuf, (long)leafLen,
        WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }

    XFREE(leafBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(caBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}
#endif

int test_rfc9802_lms_x509_verify(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_LMS)
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(WOLFSSL_NO_LMS_SHA256_256)
    /* Mixed single-level LMS and multi-level HSS fixtures. The HSS
     * public key carries only the top-level LMS/LM-OTS types, so
     * wc_LmsKey_ImportPubRaw's auto-derive path searches the map
     * by (levels, lmsType, lmOtsType). The bc_lms_native_bc_root
     * fixture is generated through Bouncy Castle's stock
     * JcaContentSignerBuilder("LMS") + JcaX509v3CertificateBuilder
     * with no overrides; including it here is the cross-impl interop
     * gate (BC's native LMS X.509 path is RFC 9802-compliant for HSS/
     * LMS, so wolfSSL must accept it end-to-end).
     *
     * All fixtures use the SHA-256/M32 family, so the whole block
     * is gated on that family being compiled in. Truncated SHA-256/192
     * or SHAKE-only builds skip this block. */
    static const char* const lmsFiles[] = {
        "./certs/lms/bc_lms_sha256_h5_w4_root.der",
#if !defined(WOLFSSL_LMS_MAX_HEIGHT) || (WOLFSSL_LMS_MAX_HEIGHT >= 10)
        "./certs/lms/bc_lms_sha256_h10_w8_root.der",
#endif
#if !defined(WOLFSSL_LMS_MAX_LEVELS) || (WOLFSSL_LMS_MAX_LEVELS >= 2)
        "./certs/lms/bc_hss_L2_H5_W8_root.der",
#endif
#if !defined(WOLFSSL_LMS_MAX_LEVELS) || (WOLFSSL_LMS_MAX_LEVELS >= 3)
        "./certs/lms/bc_hss_L3_H5_W4_root.der",
#endif
        "./certs/lms/bc_lms_native_bc_root.der",
    };
    size_t i;
    for (i = 0; i < sizeof(lmsFiles) / sizeof(lmsFiles[0]); i++) {
        ExpectIntEQ(rfc9802_verify_one_cert(lmsFiles[i],
            HSS_LMSk, CTC_HSS_LMS), TEST_SUCCESS);
    }
    ExpectIntEQ(rfc9802_lms_chain_verify(), TEST_SUCCESS);
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
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    static const char* const xmssFiles[] = {
        "./certs/xmss/bc_xmss_sha2_10_256_root.der",
        "./certs/xmss/bc_xmss_sha2_16_256_root.der",
    };
    static const char* const xmssmtFiles[] = {
        "./certs/xmss/bc_xmssmt_sha2_20_2_256_root.der",
        "./certs/xmss/bc_xmssmt_sha2_20_4_256_root.der",
        "./certs/xmss/bc_xmssmt_sha2_40_8_256_root.der",
    };
    size_t i;
    for (i = 0; i < sizeof(xmssFiles) / sizeof(xmssFiles[0]); i++) {
        ExpectIntEQ(rfc9802_verify_one_cert(xmssFiles[i],
            XMSSk, CTC_XMSS), TEST_SUCCESS);
    }
    for (i = 0; i < sizeof(xmssmtFiles) / sizeof(xmssmtFiles[0]); i++) {
        ExpectIntEQ(rfc9802_verify_one_cert(xmssmtFiles[i],
            XMSSMTk, CTC_XMSSMT), TEST_SUCCESS);
    }
    ExpectIntEQ(rfc9802_xmss_sig_oid_mismatch(), TEST_SUCCESS);
    ExpectIntEQ(rfc9802_xmss_chain_verify(), TEST_SUCCESS);
#endif /* !NO_FILESYSTEM && !NO_CERTS */
    /* Pure wolfCrypt-level negative tests don't need filesystem or cert
     * support, so they run for any XMSS-enabled build. */
    ExpectIntEQ(rfc9802_xmss_import_negative(), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}
