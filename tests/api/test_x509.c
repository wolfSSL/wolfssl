/* test_x509.c
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

#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_x509.h>
#include <tests/utils.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/x509v3.h>

#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/asn.h>

#if defined(OPENSSL_ALL) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
#define HAVE_TEST_X509_RFC2818_VERIFICATION_CALLBACK
/* callback taken and simplified from
 * include/boost/asio/ssl/impl/rfc2818_verification.ipp
 * version: boost-1.84.0 */
static int rfc2818_verification_callback(int preverify,
        WOLFSSL_X509_STORE_CTX* store)
{
    EXPECT_DECLS;
    int depth;
    X509* cert;
    GENERAL_NAMES* gens;
    byte address_bytes[] = { 127, 0, 0, 1 };
    X509_NAME* name;
    int i;
    ASN1_STRING* common_name = 0;
    int matches = 0;

    /* Don't bother looking at certificates that have
     * failed pre-verification. */
    if (!preverify)
        return 0;

    /* We're only interested in checking the certificate at
     * the end of the chain. */
    depth = X509_STORE_CTX_get_error_depth(store);
    if (depth > 0)
        return 1;

    /* Try converting the host name to an address. If it is an address then we
     * need to look for an IP address in the certificate rather than a
     * host name. */

    cert = X509_STORE_CTX_get_current_cert(store);

    /* Go through the alternate names in the certificate looking for matching
     * DNS or IP address entries. */
    gens = (GENERAL_NAMES*)X509_get_ext_d2i(
            cert, NID_subject_alt_name, NULL, NULL);
    for (i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
        GENERAL_NAME* gen = sk_GENERAL_NAME_value(gens, i);
        if (gen->type == GEN_DNS) {
            ASN1_IA5STRING* domain = gen->d.dNSName;
            if (domain->type == V_ASN1_IA5STRING && domain->data &&
                    domain->length &&
                    XSTRCMP(domain->data, "example.com") == 0)
                matches++;
        }
        else if (gen->type == GEN_IPADD)
        {
            ASN1_OCTET_STRING* ip_address = gen->d.iPAddress;
            if (ip_address->type == V_ASN1_OCTET_STRING && ip_address->data &&
                    ip_address->length == sizeof(address_bytes) &&
                    XMEMCMP(address_bytes, ip_address->data, 4) == 0)
                matches++;
        }
    }
    GENERAL_NAMES_free(gens);

    /* No match in the alternate names, so try the common names. We should only
     * use the "most specific" common name, which is the last one in
     * the list. */
    name = X509_get_subject_name(cert);
    i = -1;
    while ((i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0)
    {
        X509_NAME_ENTRY* name_entry = X509_NAME_get_entry(name, i);
        common_name = X509_NAME_ENTRY_get_data(name_entry);
    }
    if (common_name && common_name->data && common_name->length)
    {
        if (XSTRCMP(common_name->data, "www.wolfssl.com") == 0)
            matches++;
    }

    ExpectIntEQ(matches, 3);
    return matches == 3;
}
#endif

int test_x509_rfc2818_verification_callback(void)
{
    EXPECT_DECLS;
#ifdef HAVE_TEST_X509_RFC2818_VERIFICATION_CALLBACK
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLS_client_method, wolfTLS_server_method), 0);

    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
            WOLFSSL_FILETYPE_PEM), 1);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
            WOLFSSL_FILETYPE_PEM), 1);

    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliCertFile, NULL), 1);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER,
            rfc2818_verification_callback);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

/* Basic unit coverage for GetCAByAKID.
 *
 * These tests construct a minimal WOLFSSL_CERT_MANAGER and Signer objects in
 * memory and then call GetCAByAKID directly, verifying that:
 *  - a NULL or incomplete input returns NULL,
 *  - a matching issuer/serial pair returns the expected Signer, and
 *  - a non-matching pair returns NULL.
 *
 * These tests are intended to check the behaviour of the lookup logic itself;
 * they do not exercise certificate parsing or real CA loading.
 */
int test_x509_GetCAByAKID(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_AKID_NAME
    WOLFSSL_CERT_MANAGER cm;
    Signer signerA;
    Signer signerB;
    Signer* found;
    byte issuerBuf[]  = { 0x01, 0x02, 0x03, 0x04 };
    byte serialBuf[]  = { 0x0a, 0x0b, 0x0c, 0x0d };
    byte wrongSerial[] = { 0x07, 0x07, 0x07, 0x07 };
    byte issuerHash[SIGNER_DIGEST_SIZE];
    byte serialHash[SIGNER_DIGEST_SIZE];
    word32 row;

    XMEMSET(&cm, 0, sizeof(cm));
    XMEMSET(&signerA, 0, sizeof(signerA));
    XMEMSET(&signerB, 0, sizeof(signerB));
    XMEMSET(issuerHash, 0, sizeof(issuerHash));
    XMEMSET(serialHash, 0, sizeof(serialHash));

    /* Initialize CA mutex so GetCAByAKID can lock/unlock it. */
    ExpectIntEQ(wc_InitMutex(&cm.caLock), 0);

    /* Place both signers into the same CA table bucket. */
    row = 0;
    cm.caTable[row] = &signerA;
    signerA.next = &signerB;
    signerB.next = NULL;

    /* Pre-compute the expected name and serial hashes using the same helper
     * that GetCAByAKID uses internally. */
    ExpectIntEQ(CalcHashId(issuerBuf, sizeof(issuerBuf), issuerHash), 0);
    ExpectIntEQ(CalcHashId(serialBuf, sizeof(serialBuf), serialHash), 0);

    /* Configure signerA as the matching signer. */
    XMEMCPY(signerA.issuerNameHash, issuerHash, SIGNER_DIGEST_SIZE);
    XMEMCPY(signerA.serialHash,     serialHash, SIGNER_DIGEST_SIZE);

    /* Configure signerB with different hashes so it should not match. */
    XMEMSET(signerB.issuerNameHash, 0x11, SIGNER_DIGEST_SIZE);
    XMEMSET(signerB.serialHash,     0x22, SIGNER_DIGEST_SIZE);

    /* 1) NULL manager should yield NULL. */
    found = GetCAByAKID(NULL, issuerBuf, (word32)sizeof(issuerBuf),
                        serialBuf, (word32)sizeof(serialBuf));
    ExpectNull(found);

    /* 2) NULL issuer should yield NULL. */
    found = GetCAByAKID(&cm, NULL, (word32)sizeof(issuerBuf),
                        serialBuf, (word32)sizeof(serialBuf));
    ExpectNull(found);

    /* 3) NULL serial should yield NULL. */
    found = GetCAByAKID(&cm, issuerBuf, (word32)sizeof(issuerBuf),
                        NULL, (word32)sizeof(serialBuf));
    ExpectNull(found);

    /* 4) Zero-length issuer/serial should yield NULL. */
    found = GetCAByAKID(&cm, issuerBuf, 0, serialBuf, (word32)sizeof(serialBuf));
    ExpectNull(found);
    found = GetCAByAKID(&cm, issuerBuf, (word32)sizeof(issuerBuf),
                        serialBuf, 0);
    ExpectNull(found);

    /* 5) Non-matching serial should yield NULL. */
    found = GetCAByAKID(&cm, issuerBuf, (word32)sizeof(issuerBuf),
                        wrongSerial, (word32)sizeof(wrongSerial));
    ExpectNull(found);

    /* 6) Matching issuer/serial should return signerA. */
    found = GetCAByAKID(&cm, issuerBuf, (word32)sizeof(issuerBuf),
                        serialBuf, (word32)sizeof(serialBuf));
    ExpectPtrEq(found, &signerA);

    wc_FreeMutex(&cm.caLock);

#endif /* WOLFSSL_AKID_NAME */
    return EXPECT_RESULT();
}

/* Regression test: wolfSSL_X509_verify_cert() must honour the hostname set via
 * X509_VERIFY_PARAM_set1_host().  Before the fix the hostname was stored in
 * ctx->param->hostName but never consulted, so any chain-valid certificate
 * would pass regardless of hostname mismatch (RFC 6125 sec. 6.4.1 violation).
 *
 * Uses existing PEM fixtures:
 *   svrCertFile  - CN=www.wolfssl.com, SAN DNS=example.com, SAN IP=127.0.0.1
 *   caCertFile   - CA that signed svrCertFile
 */
int test_x509_verify_cert_hostname_check(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_X509_STORE*        store = NULL;
    WOLFSSL_X509_STORE_CTX*    ctx   = NULL;
    WOLFSSL_X509*              ca    = NULL;
    WOLFSSL_X509*              leaf  = NULL;
    WOLFSSL_X509_VERIFY_PARAM* param = NULL;

    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectNotNull(ca    = wolfSSL_X509_load_certificate_file(caCertFile,
                                                         SSL_FILETYPE_PEM));
    ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, ca), WOLFSSL_SUCCESS);

    ExpectNotNull(leaf = wolfSSL_X509_load_certificate_file(svrCertFile,
                                                        SSL_FILETYPE_PEM));

    /* Case 1: no hostname constraint - must succeed. */
    ExpectNotNull(ctx = wolfSSL_X509_STORE_CTX_new());
    ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, leaf, NULL),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_verify_cert(ctx), WOLFSSL_SUCCESS);
    wolfSSL_X509_STORE_CTX_free(ctx);
    ctx = NULL;

    /* Case 2: hostname matches a SAN DNS entry - must succeed. */
    ExpectNotNull(ctx = wolfSSL_X509_STORE_CTX_new());
    ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, leaf, NULL),
                WOLFSSL_SUCCESS);
    param = wolfSSL_X509_STORE_CTX_get0_param(ctx);
    ExpectNotNull(param);
    ExpectIntEQ(wolfSSL_X509_VERIFY_PARAM_set1_host(param, "example.com",
                XSTRLEN("example.com")), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_verify_cert(ctx), WOLFSSL_SUCCESS);
    wolfSSL_X509_STORE_CTX_free(ctx);
    ctx = NULL;

    /* Case 3: hostname does not match - must FAIL with the right error code. */
    ExpectNotNull(ctx = wolfSSL_X509_STORE_CTX_new());
    ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, leaf, NULL),
                WOLFSSL_SUCCESS);
    param = wolfSSL_X509_STORE_CTX_get0_param(ctx);
    ExpectNotNull(param);
    ExpectIntEQ(wolfSSL_X509_VERIFY_PARAM_set1_host(param, "wrong.com",
                XSTRLEN("wrong.com")), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_X509_verify_cert(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_STORE_CTX_get_error(ctx),
                X509_V_ERR_HOSTNAME_MISMATCH);
    ExpectIntEQ(wolfSSL_X509_STORE_CTX_get_error_depth(ctx), 0);
    wolfSSL_X509_STORE_CTX_free(ctx);
    ctx = NULL;

#ifdef WOLFSSL_IP_ALT_NAME
    /* Case 4: IP matches a SAN IP entry - must succeed. */
    ExpectNotNull(ctx = wolfSSL_X509_STORE_CTX_new());
    ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, leaf, NULL),
                WOLFSSL_SUCCESS);
    param = wolfSSL_X509_STORE_CTX_get0_param(ctx);
    ExpectNotNull(param);
    ExpectIntEQ(wolfSSL_X509_VERIFY_PARAM_set1_ip_asc(param, "127.0.0.1"),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_verify_cert(ctx), WOLFSSL_SUCCESS);
    wolfSSL_X509_STORE_CTX_free(ctx);
    ctx = NULL;

    /* Case 5: IP does not match - must FAIL with the right error code. */
    ExpectNotNull(ctx = wolfSSL_X509_STORE_CTX_new());
    ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, leaf, NULL),
                WOLFSSL_SUCCESS);
    param = wolfSSL_X509_STORE_CTX_get0_param(ctx);
    ExpectNotNull(param);
    ExpectIntEQ(wolfSSL_X509_VERIFY_PARAM_set1_ip_asc(param, "192.168.1.1"),
                WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_X509_verify_cert(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_STORE_CTX_get_error(ctx),
                X509_V_ERR_IP_ADDRESS_MISMATCH);
    ExpectIntEQ(wolfSSL_X509_STORE_CTX_get_error_depth(ctx), 0);
    wolfSSL_X509_STORE_CTX_free(ctx);
    ctx = NULL;
#endif /* WOLFSSL_IP_ALT_NAME */

    wolfSSL_X509_free(leaf);
    wolfSSL_X509_free(ca);
    wolfSSL_X509_STORE_free(store);
#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_RSA */
    return EXPECT_RESULT();
}

int test_x509_set_serialNumber(void)
{
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    EXPECT_DECLS;
    WOLFSSL_X509*         x509 = NULL;
    WOLFSSL_ASN1_INTEGER* s    = NULL;
#if defined(OPENSSL_EXTRA_X509_SMALL)
    WOLFSSL_ASN1_INTEGER  asnInt;
#endif

    ExpectNotNull(x509 = wolfSSL_X509_new());
#if defined(OPENSSL_EXTRA_X509_SMALL)
    XMEMSET(&asnInt, 0, sizeof(asnInt));
    asnInt.data = asnInt.intData;
    asnInt.isDynamic = 0;
    asnInt.dataMax = (unsigned int)sizeof(asnInt.intData);
    s = &asnInt;
#else
    ExpectNotNull(s = wolfSSL_ASN1_INTEGER_new());
#endif

    /* --- invalid inputs that must be rejected --- */

    /* NULL x509 */
    ExpectIntEQ(X509_set_serialNumber(NULL, s), WOLFSSL_FAILURE);
    /* NULL s */
    ExpectIntEQ(X509_set_serialNumber(x509, NULL), WOLFSSL_FAILURE);

    if (s != NULL) {
        /* length == 0: too short */
        s->length  = 0;
        s->data[0] = ASN_INTEGER;
        s->data[1] = 0;
        ExpectIntEQ(wolfSSL_X509_set_serialNumber(x509, s),
                    WOLFSSL_FAILURE);

        /* length == 1: still too short */
        s->length  = 1;
        s->data[0] = ASN_INTEGER;
        s->data[1] = 0;
        ExpectIntEQ(wolfSSL_X509_set_serialNumber(x509, s),
                    WOLFSSL_FAILURE);

        /* length == 2: still rejected - the guard requires length >= 3 */
        s->length  = 2;
        s->data[0] = ASN_INTEGER;
        s->data[1] = 0;
        ExpectIntEQ(wolfSSL_X509_set_serialNumber(x509, s),
                    WOLFSSL_FAILURE);

        /* wrong type byte */
        s->length  = 4;
        s->data[0] = 0x00; /* not ASN_INTEGER */
        s->data[1] = 2;    /* length field */
        s->data[2] = 0x01;
        s->data[3] = 0x02;
        ExpectIntEQ(wolfSSL_X509_set_serialNumber(x509, s),
                    WOLFSSL_FAILURE);

        /* mismatched length byte (data[1] != s->length - 2) */
        s->length  = 4;
        s->data[0] = ASN_INTEGER;
        s->data[1] = 99; /* claims 99 bytes but s->length - 2 == 2 */
        s->data[2] = 0x01;
        s->data[3] = 0x02;
        ExpectIntEQ(wolfSSL_X509_set_serialNumber(x509, s),
                    WOLFSSL_FAILURE);

        /* --- valid two-byte serial number --- */
        s->length  = 4;
        s->data[0] = ASN_INTEGER;
        s->data[1] = 2;
        s->data[2] = 0x01;
        s->data[3] = 0x02;
        ExpectIntEQ(wolfSSL_X509_set_serialNumber(x509, s),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(x509->serialSz, 2);
        /* NUL terminator must be placed right after the copied data */
        ExpectIntEQ(x509->serial[x509->serialSz], 0);
        ExpectIntEQ(x509->serial[0], 0x01);
        ExpectIntEQ(x509->serial[1], 0x02);
    }

#if !defined(OPENSSL_EXTRA_X509_SMALL)
    wolfSSL_ASN1_INTEGER_free(s);
#endif
    wolfSSL_X509_free(x509);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
}

/*
 * Test: CopyDateToASN1_TIME clamps attacker-controlled time field length.
 *
 * Attack chain:
 *   1. Attacker crafts a DER certificate with notBefore UTCTime length byte
 *      set to 0x1F (31) instead of 0x0D (13). The first 13 bytes are a valid
 *      "YYMMDDHHMMSSZ" string (passes ExtractDate 'Z'-at-position-12 check),
 *      followed by 18 sentinel bytes (0xDE). Parent SEQUENCE lengths are
 *      adjusted so the DER is structurally valid.
 *   2. The malicious cert is presented as the server cert in a TLS handshake
 *      (via memio -- no sockets needed).
 *   3. The client parses the cert. CopyDateToASN1_TIME() in internal.c must
 *      clamp the length to CTC_DATE_SIZE - 2 (30) so that downstream code
 *      in wolfSSL_X509_notBefore() can safely prepend type+length at offset
 *      0-1 of the 32-byte notBeforeData without overflowing.
 *
 * The test verifies that notBefore.length <= CTC_DATE_SIZE - 2 (30),
 * regardless of the attacker's wire value (31).
 */

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && \
    !defined(NO_RSA) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)

/* Verify callback that accepts all certificates regardless of errors. */
static int accept_all_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)preverify;
    (void)store;
    return 1;
}

/*
 * Craft a malicious DER certificate by inflating the notBefore UTCTime length.
 *
 * Scans for the Validity SEQUENCE (pattern: 0x30 XX 0x17 0x0D), inflates the
 * notBefore length by 'inflate' bytes, inserts sentinel bytes (0xDE), and
 * adjusts all parent SEQUENCE lengths.
 *
 * out:      caller-supplied buffer, must be at least origSz + inflate bytes.
 * outSz:   set to the new cert size on success.
 * Returns 0 on success, -1 on failure.
 */
static int craft_malicious_time_cert(const byte* orig, int origSz,
    byte* out, int* outSz, int inflate)
{
    int i;
    int validityOff = -1;
    int notBeforeLenOff;  /* offset of the notBefore length byte */
    int notBeforeDataEnd; /* offset just past the 13-byte time data */
    word16 seqLen;

    /* Scan for Validity SEQUENCE: 0x30 XX 0x17 0x0D */
    for (i = 0; i < origSz - 3; i++) {
        if (orig[i] == 0x30 && orig[i + 2] == 0x17 && orig[i + 3] == 0x0D) {
            validityOff = i;
            break;
        }
    }
    if (validityOff < 0) {
        return -1;
    }

    notBeforeLenOff = validityOff + 3; /* the 0x0D byte */
    notBeforeDataEnd = notBeforeLenOff + 1 + 13; /* tag(1) was at +2, data starts at +4 */

    /* Build the new buffer:
     *   [0 .. notBeforeLenOff-1]  unchanged prefix
     *   [notBeforeLenOff]         inflated length byte
     *   [notBeforeLenOff+1 .. notBeforeDataEnd-1]  original 13 time bytes
     *   <insert 'inflate' sentinel bytes here>
     *   [notBeforeDataEnd .. origSz-1]  remainder of cert
     */

    /* Copy prefix including the length byte position */
    XMEMCPY(out, orig, notBeforeDataEnd);

    /* Patch the notBefore UTCTime length byte */
    out[notBeforeLenOff] = (byte)(0x0D + inflate);

    /* Insert sentinel bytes */
    XMEMSET(out + notBeforeDataEnd, 0xDE, inflate);

    /* Copy the rest of the cert (notAfter field onward) */
    XMEMCPY(out + notBeforeDataEnd + inflate,
             orig + notBeforeDataEnd,
             origSz - notBeforeDataEnd);

    /* Fix Validity SEQUENCE length (single-byte encoding at validityOff+1) */
    out[validityOff + 1] = (byte)(orig[validityOff + 1] + inflate);

    /* Fix TBSCertificate SEQUENCE length (2-byte big-endian at offset 6-7,
     * format: 30 82 XX XX) */
    seqLen = ((word16)orig[6] << 8) | orig[7];
    seqLen += (word16)inflate;
    out[6] = (byte)(seqLen >> 8);
    out[7] = (byte)(seqLen & 0xFF);

    /* Fix Certificate SEQUENCE length (2-byte big-endian at offset 2-3,
     * format: 30 82 XX XX) */
    seqLen = ((word16)orig[2] << 8) | orig[3];
    seqLen += (word16)inflate;
    out[2] = (byte)(seqLen >> 8);
    out[3] = (byte)(seqLen & 0xFF);

    *outSz = origSz + inflate;
    return 0;
}

#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */

int test_x509_time_field_overread_via_tls(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && \
    !defined(NO_RSA) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    WOLFSSL_X509* peer = NULL;
    WOLFSSL_ASN1_TIME* notBefore = NULL;
    /*
     * Inflate notBefore length by 18 bytes: 13 + 18 = 31.
     * CopyDecodedToX509() sets notBefore.length = min(31, MAX_DATE_SZ) = 31
     * because it trusts the raw ASN.1 length byte from the wire.
     * A valid UTCTime is only 13 bytes.
     */
    const int INFLATE = 18;
    byte malicious_der[sizeof_server_cert_der_2048 + 18];
    int malicious_der_sz = 0;

    /* --- Step 1: Craft malicious certificate --- */
    ExpectIntEQ(craft_malicious_time_cert(
        server_cert_der_2048, (int)sizeof_server_cert_der_2048,
        malicious_der, &malicious_der_sz, INFLATE), 0);
    ExpectIntEQ(malicious_der_sz,
                (int)sizeof_server_cert_der_2048 + INFLATE);

    /* --- Step 2: Set up TLS via memio --- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup_ex(&test_ctx, &ctx_c, &ctx_s,
        &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
        (byte*)ca_cert_der_2048, (int)sizeof_ca_cert_der_2048,
        malicious_der, malicious_der_sz,
        (byte*)server_key_der_2048, (int)sizeof_server_key_der_2048), 0);

    /* Client verify callback accepts all errors (signature is broken
     * because we modified the TBSCertificate without re-signing).
     * Must be set on ssl_c (not ctx_c) because the SSL object was already
     * created from ctx_c inside test_memio_setup_ex(). */
    if (ssl_c != NULL) {
        wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_PEER,
                           accept_all_verify_cb);
    }

    /* --- Step 3: Perform TLS handshake --- */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* --- Step 4: Verify CopyDecodedToX509 does not trust wire length --- */
#ifdef KEEP_PEER_CERT
    ExpectNotNull(peer = wolfSSL_get_peer_certificate(ssl_c));

    /*
     * X509_get_notBefore returns &x509->notBefore directly (no copy).
     * CopyDecodedToX509() set notBefore.length = min(wireLength, 32) = 31
     * because it trusts the raw ASN.1 length byte from the attacker's cert.
     *
     * The data buffer is CTC_DATE_SIZE (32) bytes, and the notBeforeData
     * encoding prepends type+length at offset 0-1, leaving 30 bytes for
     * content. So the maximum safe length is CTC_DATE_SIZE - 2 = 30.
     *
     * This assertion FAILS on the buggy code (length > 30) and will PASS
     * once CopyDateToASN1_TIME clamps to the buffer capacity.
     */
    if (peer != NULL) {
        notBefore = wolfSSL_X509_get_notBefore(peer);
    }
    ExpectNotNull(notBefore);
    ExpectIntLE(notBefore->length, CTC_DATE_SIZE - 2); /* max: 30 */

    wolfSSL_X509_free(peer);
#endif /* KEEP_PEER_CERT */

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif /* compile guards */
    return EXPECT_RESULT();
}
