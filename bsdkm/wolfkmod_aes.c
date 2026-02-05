#if !defined(WC_SKIP_INCLUDED_C_FILES) && defined(BSDKM_CRYPTO_REGISTER)
#include <wolfssl/wolfcrypt/aes.h>

/*
 * the cryptodev framework always calls a callback, even when CRYPTOCAP_F_SYNC.
 */
static int
wolfkdriv_test_crp_callback(struct cryptop * crp)
{
    (void)crp;
    return (0);
}

/* Test aes-cbc with a buffer larger than aes block size.
 * Verify direct wolfcrypt API and opencrypto framework return
 * same result. */
static int wolfkdriv_test_aes_cbc_big(device_t dev, int crid)
{
    crypto_session_t session = NULL;
    struct crypto_session_params csp;
    struct cryptop * crp = NULL;
    Aes *            aes_encrypt = NULL;
    int    error = 0;
    byte msg[] = {
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    byte work1[WC_AES_BLOCK_SIZE * 3]; /* wolfcrypt buffer */
    byte work2[WC_AES_BLOCK_SIZE * 3]; /* opencrypto buffer */
    /* padded to 16-bytes */
    const byte key[] = "0123456789abcdef   ";
    /* padded to 16-bytes */
    const byte iv[]  = "1234567890abcdef   ";

    memset(&csp, 0, sizeof(csp));
    memcpy(work1, msg, sizeof(msg)); /* wolfcrypt work buffer */
    memcpy(work2, msg, sizeof(msg)); /* opencrypto work buffer */

    /* wolfcrypt encrypt */
    aes_encrypt = (Aes *)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_AES);
    if (aes_encrypt == NULL) {
        error = ENOMEM;
        device_printf(dev, "error: malloc failed\n");
        goto test_aes_cbc_big_out;
    }

    error = wc_AesInit(aes_encrypt, NULL, INVALID_DEVID);
    if (error) {
        device_printf(dev, "error: newsession_cipher: aes init: %d\n", error);
        goto test_aes_cbc_big_out;
    }

    error = wc_AesSetKey(aes_encrypt, key, 16, iv, AES_ENCRYPTION);
    if (error) {
        device_printf(dev, "error: wc_AesSetKey: %d\n", error);
        goto test_aes_cbc_big_out;
    }

    error = wc_AesCbcEncrypt(aes_encrypt, work1, work1, sizeof(work1));
    if (error) {
        device_printf(dev, "error: wc_AesCbcEncrypt: %d\n", error);
        goto test_aes_cbc_big_out;
    }

    /* opencrypto encrypt */
    csp.csp_mode = CSP_MODE_CIPHER;
    csp.csp_cipher_alg = CRYPTO_AES_CBC;
    csp.csp_ivlen = WC_AES_BLOCK_SIZE;
    csp.csp_cipher_key = key;
    csp.csp_cipher_klen = WC_AES_BLOCK_SIZE;
    error = crypto_newsession(&session, &csp, crid);
    if (error || session == NULL) {
        goto test_aes_cbc_big_out;
    }

    crp = crypto_getreq(session, M_WAITOK);
    if (crp == NULL) {
        device_printf(dev, "error: test_aes: crypto_getreq failed\n");
        goto test_aes_cbc_big_out;
    }

    crp->crp_callback = wolfkdriv_test_crp_callback;
    crp->crp_op = CRYPTO_OP_ENCRYPT;
    crp->crp_flags = CRYPTO_F_IV_SEPARATE;

    memcpy(crp->crp_iv, iv, WC_AES_BLOCK_SIZE);

    crypto_use_buf(crp, work2, sizeof(work2));
    crp->crp_payload_start = 0;
    crp->crp_payload_length = sizeof(work2);

    error = crypto_dispatch(crp);
    if (error) {
        goto test_aes_cbc_big_out;
    }

    error = XMEMCMP(work1, work2, sizeof(work2));
    if (error) {
        device_printf(dev, "error: test_aes: enc vectors diff: %d\n", error);
        goto test_aes_cbc_big_out;
    }

    /* opencrypto decrypt */
    crp->crp_op = CRYPTO_OP_DECRYPT;

    error = crypto_dispatch(crp);
    if (error) {
        goto test_aes_cbc_big_out;
    }

    error = XMEMCMP(work2, msg, sizeof(msg));
    if (error) {
        device_printf(dev, "error: test_aes: dec vectors diff: %d\n", error);
        goto test_aes_cbc_big_out;
    }

test_aes_cbc_big_out:
    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: test_aes_cbc_big: error=%d, session=%p, crp=%p\n",
                  error, (void *)session, (void*)crp);
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    if (crp != NULL) {
        crypto_freereq(crp);
        crp = NULL;
    }

    if (session != NULL) {
        crypto_freesession(session);
        session = NULL;
    }

    if (aes_encrypt != NULL) {
        wc_AesFree(aes_encrypt);
        XFREE(aes_encrypt, NULL, DYNAMIC_TYPE_AES);
        aes_encrypt = NULL;
    }

    return (error);
}

/* Test aes-gcm encrypt and decrypt a small buffer with opencrypto
 * framework and wolfcrypt.
 */
static int wolfkdriv_test_aes_gcm(device_t dev, int crid)
{
    crypto_session_t session = NULL;
    struct crypto_session_params csp;
    struct cryptop * crp = NULL;
    Aes *            enc = NULL;
    int              error = 0;

    WOLFSSL_SMALL_STACK_STATIC const byte p[] =
    {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
    };

    WOLFSSL_SMALL_STACK_STATIC const byte c1[] =
    {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62
    };

    WOLFSSL_SMALL_STACK_STATIC byte a[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    WOLFSSL_SMALL_STACK_STATIC const byte k1[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    WOLFSSL_SMALL_STACK_STATIC const byte iv1[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };

    WOLFSSL_SMALL_STACK_STATIC const byte t1[] =
    {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
    };

    byte resultT[sizeof(t1) + WC_AES_BLOCK_SIZE];
    byte resultC[sizeof(p) + WC_AES_BLOCK_SIZE];
    byte resultC2[sizeof(p) + WC_AES_BLOCK_SIZE];

    XMEMSET(resultT, 0, sizeof(resultT));
    XMEMSET(resultC, 0, sizeof(resultC));

    XMEMSET(resultC2, 0, sizeof(resultC));
    XMEMCPY(resultC2, p, sizeof(p));

    /* wolfcrypt encrypt */
    enc = (Aes *)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_AES);
    if (enc == NULL) {
        error = ENOMEM;
        device_printf(dev, "error: malloc failed\n");
        goto test_aes_gcm_out;
    }

    error = wc_AesGcmEncryptInit(enc, k1, sizeof(k1), iv1, sizeof(iv1));
    if (error) { goto test_aes_gcm_out; }

    error = wc_AesGcmEncryptUpdate(enc, resultC, p, sizeof(p), a, sizeof(a));
    if (error) { goto test_aes_gcm_out; }

    error = wc_AesGcmEncryptFinal(enc, resultT, sizeof(t1));
    if (error) { goto test_aes_gcm_out; }

    error = XMEMCMP(resultC, c1, sizeof(c1));
    if (error) { goto test_aes_gcm_out; }

    error = XMEMCMP(resultT, t1, sizeof(t1));
    if (error) { goto test_aes_gcm_out; }

    /*
     * opencrypto encrypt
     * */

    /* set crypto session params */
    memset(&csp, 0, sizeof(csp));
    csp.csp_flags |= CSP_F_SEPARATE_AAD;
    csp.csp_mode = CSP_MODE_AEAD;
    csp.csp_cipher_alg = CRYPTO_AES_NIST_GCM_16;
    csp.csp_ivlen = sizeof(iv1);
    csp.csp_cipher_key = k1;
    csp.csp_cipher_klen = sizeof(k1);

    /* get crypto session handle */
    error = crypto_newsession(&session, &csp, crid);
    if (error || session == NULL) {
        device_printf(dev, "error: test_aes: crypto_newsession: %d, %p\n",
                      error, (void *)session);
        goto test_aes_gcm_out;
    }

    /* get a crypto op handle */
    crp = crypto_getreq(session, M_WAITOK);
    if (crp == NULL) {
        device_printf(dev, "error: test_aes: crypto_getreq failed\n");
        goto test_aes_gcm_out;
    }

    /* configure it */
    crp->crp_callback = wolfkdriv_test_crp_callback;
    crp->crp_op = (CRYPTO_OP_ENCRYPT | CRYPTO_OP_COMPUTE_DIGEST);
    crp->crp_flags = CRYPTO_F_IV_SEPARATE;

    memcpy(crp->crp_iv, iv1, sizeof(iv1));

    crypto_use_buf(crp, resultC2, sizeof(resultC2));
    crp->crp_payload_start = 0;
    crp->crp_payload_length = sizeof(p);

    crp->crp_aad = a;
    crp->crp_aad_start = 0;
    crp->crp_aad_length = sizeof(a);
    crp->crp_digest_start = crp->crp_payload_start + sizeof(p);

    error = crypto_dispatch(crp);
    if (error) {
        goto test_aes_gcm_out;
    }

    error = XMEMCMP(resultC2, c1, sizeof(c1));
    if (error) { goto test_aes_gcm_out; }

    error = XMEMCMP(resultC2 + sizeof(p), t1, sizeof(t1));
    if (error) { goto test_aes_gcm_out; }

    /* opencrypto decrypt */
    crp->crp_op = (CRYPTO_OP_DECRYPT | CRYPTO_OP_VERIFY_DIGEST);

    error = crypto_dispatch(crp);
    if (error) {
        goto test_aes_gcm_out;
    }

    error = XMEMCMP(resultC2, p, sizeof(p));
    if (error) { goto test_aes_gcm_out; }

test_aes_gcm_out:
    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: test_aes_gcm: error=%d, session=%p, crp=%p\n",
                  error, (void *)session, (void*)crp);
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    if (crp != NULL) {
        crypto_freereq(crp);
        crp = NULL;
    }

    if (session != NULL) {
        crypto_freesession(session);
        session = NULL;
    }

    if (enc != NULL) {
        wc_AesFree(enc);
        XFREE(enc, NULL, DYNAMIC_TYPE_AES);
        enc = NULL;
    }

    return (error);
}


static int wolfkdriv_test_aes(device_t dev, int crid)
{
    int error = 0;

    if (error == 0) {
        error = wolfkdriv_test_aes_cbc_big(dev, crid);
    }

    if (error == 0) {
        error = wolfkdriv_test_aes_gcm(dev, crid);
    }

    return (error);
}
#endif /* !WC_SKIP_INCLUDED_C_FILES && BSDKM_CRYPTO_REGISTER */
