/* caliptra_test.c — test harness for the wolfSSL Caliptra port
 *
 * Exercises the port via the standard wolfSSL API with WOLF_CALIPTRA_DEVID.
 *
 * Two transport backends are supported:
 *
 *   Software simulator (caliptra_sim.c) — default, no external dependencies:
 *     gcc $CFLAGS -DBUILDING_WOLFSSL \
 *         caliptra_sim.c caliptra_test.c \
 *         wolfcrypt/src/port/caliptra/caliptra_port.o \
 *         src/.libs/libwolfssl.a -lpthread -lm \
 *         -o caliptra_test_bin
 *
 *   hw-model emulator (caliptra_hwmodel.c) — requires the Caliptra hw-model
 *   C binding.  Build using the Makefile in this directory:
 *     make -C wolfcrypt/src/port/caliptra/sim/ run
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/port/caliptra/caliptra_port.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <string.h>

/* hw-model backend: include init/cleanup declarations when requested */
#ifdef CALIPTRA_HWMODEL
#include "caliptra_hwmodel.h"
#endif

/* Use INVALID_DEVID when we want software fallback (no CryptoCb device) */
#ifndef WC_NO_DEVID
#define WC_NO_DEVID INVALID_DEVID
#endif

/* =========================================================================
 * Test infrastructure
 * ========================================================================= */

static int tests_run = 0;
static int tests_pass = 0;

#define TEST(name, cond) do { \
    tests_run++; \
    if (cond) { \
        printf("PASS: %s\n", name); \
        tests_pass++; \
    } else { \
        printf("FAIL: %s (line %d)\n", name, __LINE__); \
    } \
} while (0)

/* Compare byte arrays; return 1 if equal */
static int bytes_eq(const byte* a, const byte* b, int len)
{
    int i, diff = 0;
    for (i = 0; i < len; i++) diff |= (int)(a[i] ^ b[i]);
    return diff == 0;
}

/* =========================================================================
 * Test 1: RNG generates non-zero bytes
 * ========================================================================= */

static void test_rng(void)
{
    WC_RNG rng;
    byte buf1[32];
    byte buf2[32];
    int ret;
    int any_nonzero = 0;
    int i;

    memset(buf1, 0, sizeof(buf1));
    memset(buf2, 0, sizeof(buf2));

    ret = wc_InitRng_ex(&rng, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0)
        ret = wc_RNG_GenerateBlock(&rng, buf1, sizeof(buf1));
    if (ret == 0)
        ret = wc_RNG_GenerateBlock(&rng, buf2, sizeof(buf2));
    wc_FreeRng(&rng);

    for (i = 0; i < 32; i++) {
        if (buf1[i]) any_nonzero = 1;
    }

    /* Two successive 32-byte generations from the same RNG must differ.
     * Catches a stuck-at-constant DRBG (e.g. a transport that returns
     * a cached buffer instead of running the firmware DRBG) which a
     * single nonzero-bytes check would not detect. */
    TEST("RNG generates nonzero and non-repeating",
         ret == 0 && any_nonzero && !bytes_eq(buf1, buf2, 32));
}

/* =========================================================================
 * Test 2: SHA-256 empty message known-answer
 * ========================================================================= */

static void test_sha256_empty(void)
{
    static const byte sha256_empty[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    wc_Sha256 sha;
    byte digest[32];
    int ret;

    ret = wc_InitSha256_ex(&sha, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0)
        ret = wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);

    TEST("SHA-256 empty KAT", ret == 0 && bytes_eq(digest, sha256_empty, 32));
}

/* =========================================================================
 * Test 3: SHA-256 "abc" known-answer
 * ========================================================================= */

static void test_sha256_abc(void)
{
    static const byte sha256_abc[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    wc_Sha256 sha;
    byte digest[32];
    int ret;

    ret = wc_InitSha256_ex(&sha, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0)
        ret = wc_Sha256Update(&sha, (const byte*)"abc", 3);
    if (ret == 0)
        ret = wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);

    TEST("SHA-256 abc KAT", ret == 0 && bytes_eq(digest, sha256_abc, 32));
}

/* =========================================================================
 * Test 4: SHA-384 empty message known-answer
 * ========================================================================= */

static void test_sha384_empty(void)
{
    static const byte sha384_empty[] = {
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
        0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
        0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
        0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
        0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
        0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
    };

    wc_Sha384 sha;
    byte digest[48];
    int ret;

    ret = wc_InitSha384_ex(&sha, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0)
        ret = wc_Sha384Final(&sha, digest);
    wc_Sha384Free(&sha);

    TEST("SHA-384 empty KAT", ret == 0 && bytes_eq(digest, sha384_empty, 48));
}

/* =========================================================================
 * Test 5: SHA-256 multi-update matches single-call software
 * ========================================================================= */

static void test_sha256_multiupdate(void)
{
    wc_Sha256 sha1, sha2;
    byte d1[32], d2[32];
    int ret1, ret2;

    /* Via Caliptra device with two updates */
    ret1 = wc_InitSha256_ex(&sha1, NULL, WOLF_CALIPTRA_DEVID);
    if (ret1 == 0)
        ret1 = wc_Sha256Update(&sha1, (const byte*)"Hello, ", 7);
    if (ret1 == 0)
        ret1 = wc_Sha256Update(&sha1, (const byte*)"Caliptra!", 9);
    if (ret1 == 0)
        ret1 = wc_Sha256Final(&sha1, d1);
    wc_Sha256Free(&sha1);

    /* Software reference: single update */
    ret2 = wc_InitSha256_ex(&sha2, NULL, WC_NO_DEVID);
    if (ret2 == 0)
        ret2 = wc_Sha256Update(&sha2, (const byte*)"Hello, Caliptra!", 16);
    if (ret2 == 0)
        ret2 = wc_Sha256Final(&sha2, d2);
    wc_Sha256Free(&sha2);

    TEST("SHA-256 multi-update matches software",
         ret1 == 0 && ret2 == 0 && bytes_eq(d1, d2, 32));
}

/* =========================================================================
 * Test 6: AES-GCM encrypt then decrypt (roundtrip)
 * ========================================================================= */

static void test_aesgcm_roundtrip(void)
{
    /* TEST-ONLY: NIST AES-256 test vector key from FIPS 197 / SP 800-38D.
     * Not for production use; reused across this file's AES-GCM tests for
     * traceability against published vectors. */
    static const byte aes_key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    static const byte plaintext[] = "Hello, Caliptra! This is a test.";
    static const byte aad[]       = "additional data";

    CaliptraCmk enc_cmk;
    byte ciphertext[48];
    byte decrypted[48];
    byte enc_tag[16];
    byte iv_out[12];
    Aes enc_aes, dec_aes;
    byte dummy_iv[12];  /* placeholder: wolfSSL requires ivSz>0; Caliptra ignores it */
    int ret;

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(decrypted,  0, sizeof(decrypted));
    memset(enc_tag,    0, sizeof(enc_tag));
    memset(iv_out,     0, sizeof(iv_out));
    memset(dummy_iv,   0, sizeof(dummy_iv));

    /* Import the AES key */
    ret = wc_caliptra_import_key(aes_key, 32, CMB_KEY_USAGE_AES /* 2 */, &enc_cmk);
    if (ret != 0) {
        TEST("AES-GCM encrypt/decrypt roundtrip", 0);
        return;
    }

    /* Encrypt: Caliptra generates the IV */
    ret = wc_AesInit(&enc_aes, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0) {
        enc_aes.devCtx = &enc_cmk;
        ret = wc_AesGcmEncrypt(&enc_aes,
                               ciphertext, plaintext, 32,
                               dummy_iv, 12,
                               enc_tag, 16,
                               aad, 15);
        if (ret == 0) {
            ret = wc_caliptra_aesgcm_get_iv(&enc_aes, iv_out, sizeof(iv_out));
        }
        wc_AesFree(&enc_aes);
    }

    if (ret != 0) {
        wc_caliptra_delete_key(&enc_cmk);
        TEST("AES-GCM encrypt/decrypt roundtrip", 0);
        return;
    }

    /* Decrypt using the Caliptra-generated IV */
    ret = wc_AesInit(&dec_aes, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0) {
        dec_aes.devCtx = &enc_cmk;   /* same key handle */
        ret = wc_AesGcmDecrypt(&dec_aes,
                               decrypted, ciphertext, 32,
                               iv_out, 12,
                               enc_tag, 16,
                               aad, 15);
        wc_AesFree(&dec_aes);
    }

    wc_caliptra_delete_key(&enc_cmk);

    TEST("AES-GCM encrypt/decrypt roundtrip",
         ret == 0 && bytes_eq(decrypted, plaintext, 32));
}

/* =========================================================================
 * Test 7: ECDSA sign and verify
 * ========================================================================= */

static void test_ecdsa_sign_verify(void)
{
    WC_RNG      rng;
    ecc_key     raw_key;             /* software key for material generation */
    ecc_key     sign_key, ver_key;   /* Caliptra-routed sign and verify keys */
    CaliptraCmk sign_cmk, verify_cmk;
    byte        sig_der[160];
    word32      sig_len = sizeof(sig_der);
    byte        hash[48];
    byte        priv_bytes[48];
    word32      priv_len = sizeof(priv_bytes);
    byte        pub_x[48], pub_y[48];
    word32      pub_xlen = sizeof(pub_x), pub_ylen = sizeof(pub_y);
    byte        pub_key[96];         /* Qx || Qy for Caliptra verify import */
    int         verify_res = 0;
    int         saved_devId;
    int         ret;

    memset(hash,       0xAB, sizeof(hash));
    memset(sig_der,    0,    sizeof(sig_der));
    memset(priv_bytes, 0,    sizeof(priv_bytes));
    memset(pub_x,      0,    sizeof(pub_x));
    memset(pub_y,      0,    sizeof(pub_y));
    memset(pub_key,    0,    sizeof(pub_key));
    memset(&sign_cmk,   0,   sizeof(sign_cmk));
    memset(&verify_cmk, 0,   sizeof(verify_cmk));

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST("Caliptra ECDSA sign+verify", 0);
        return;
    }

    /* Generate a P-384 keypair in software to obtain priv/pub material. */
    wc_ecc_init_ex(&raw_key, NULL, INVALID_DEVID);
    ret = wc_ecc_make_key_ex(&rng, 48, &raw_key, ECC_SECP384R1);
    if (ret == 0)
        ret = wc_ecc_export_private_only(&raw_key, priv_bytes, &priv_len);
    if (ret == 0)
        ret = wc_ecc_export_public_raw(&raw_key,
                                       pub_x, &pub_xlen,
                                       pub_y, &pub_ylen);
    wc_ecc_free(&raw_key);
    if (ret != 0) {
        wc_ForceZero(priv_bytes, sizeof(priv_bytes));
        wc_FreeRng(&rng);
        TEST("Caliptra ECDSA sign+verify", 0);
        return;
    }

    /* Import priv as ECDSA sign CMK (sim treats <=48 bytes as private scalar). */
    ret = wc_caliptra_import_key(priv_bytes, priv_len,
                                 CMB_KEY_USAGE_ECDSA, &sign_cmk);
    if (ret != 0) {
        wc_ForceZero(priv_bytes, sizeof(priv_bytes));
        wc_FreeRng(&rng);
        TEST("Caliptra ECDSA sign+verify", 0);
        return;
    }

    /* Import Qx||Qy (96 bytes) as ECDSA verify CMK. */
    memcpy(pub_key,      pub_x, 48);
    memcpy(pub_key + 48, pub_y, 48);
    ret = wc_caliptra_import_key(pub_key, sizeof(pub_key),
                                 CMB_KEY_USAGE_ECDSA, &verify_cmk);
    if (ret != 0) {
        wc_caliptra_delete_key(&sign_cmk);
        wc_ForceZero(priv_bytes, sizeof(priv_bytes));
        wc_FreeRng(&rng);
        TEST("Caliptra ECDSA sign+verify", 0);
        return;
    }

    /* Sign via Caliptra.  Use wc_ecc_init_ex + wc_ecc_import_unsigned with
     * devId temporarily INVALID_DEVID so the import does not route through
     * CryptoCb (which has no callback for "import an unsigned key").  After
     * import, restore devId and set devCtx so wc_ecc_sign_hash dispatches
     * through caliptra_ecdsa_sign().  This is the same idiom as
     * wolfcrypt/test/test.c caliptra_test() Test 6. */
    wc_ecc_init_ex(&sign_key, NULL, WOLF_CALIPTRA_DEVID);
    saved_devId    = sign_key.devId;
    sign_key.devId = INVALID_DEVID;
    ret = wc_ecc_import_unsigned(&sign_key, pub_x, pub_y,
                                 priv_bytes, ECC_SECP384R1);
    sign_key.devId = saved_devId;
    if (ret == 0) {
        sign_key.devCtx = &sign_cmk;
        ret = wc_ecc_sign_hash(hash, sizeof(hash),
                               sig_der, &sig_len, &rng, &sign_key);
    }
    wc_ecc_free(&sign_key);

    if (ret != 0) {
        wc_caliptra_delete_key(&sign_cmk);
        wc_caliptra_delete_key(&verify_cmk);
        wc_ForceZero(priv_bytes, sizeof(priv_bytes));
        wc_FreeRng(&rng);
        TEST("Caliptra ECDSA sign+verify", 0);
        return;
    }

    /* Verify via Caliptra.  Same import-with-temporary-devId pattern; verify
     * does not need the private scalar. */
    wc_ecc_init_ex(&ver_key, NULL, WOLF_CALIPTRA_DEVID);
    saved_devId   = ver_key.devId;
    ver_key.devId = INVALID_DEVID;
    ret = wc_ecc_import_unsigned(&ver_key, pub_x, pub_y, NULL, ECC_SECP384R1);
    ver_key.devId = saved_devId;
    if (ret == 0) {
        ver_key.devCtx = &verify_cmk;
        ret = wc_ecc_verify_hash(sig_der, sig_len, hash, sizeof(hash),
                                 &verify_res, &ver_key);
    }
    wc_ecc_free(&ver_key);

    wc_caliptra_delete_key(&sign_cmk);
    wc_caliptra_delete_key(&verify_cmk);
    wc_ForceZero(priv_bytes, sizeof(priv_bytes));
    wc_FreeRng(&rng);

    TEST("Caliptra ECDSA sign+verify", ret == 0 && verify_res == 1);
}

/* =========================================================================
 * Test 8: HMAC-SHA-384 matches software reference
 *
 * The Caliptra HMAC mailbox command is single-shot: all message data must
 * be present in one mailbox call.  wolfSSL's CryptoCb HMAC callback is
 * invoked once per wc_HmacUpdate() and once at wc_HmacFinal(), so the
 * streaming Hmac API cannot be plumbed through to Caliptra.  caliptra_port.c
 * returns WC_HW_E (not CRYPTOCB_UNAVAILABLE) when hmac->devCtx is set, which
 * prevents wolfSSL from falling through to software HMAC over an unauthorized
 * key.  See the compile-time assertion in caliptra_port.c that enforces
 * WC_HW_E != CRYPTOCB_UNAVAILABLE for this reason.
 *
 * The supported path is wc_caliptra_hmac() — a single-shot wrapper around
 * the CM_HMAC mailbox command.  This test exercises wc_caliptra_hmac and
 * cross-validates against a wolfSSL software HMAC computed with
 * INVALID_DEVID (bypasses CryptoCb).  Same idiom as wolfcrypt/test/test.c
 * caliptra_test() Test 5.
 * ========================================================================= */

static void test_hmac_sha384(void)
{
    /* Caliptra firmware requires HMAC keys to be exactly 48 or 64 bytes
     * (SHA-384 or SHA-512 block size); 32-byte keys are rejected. */
    static const byte hmac_key[48] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    static const byte msg[] = "data";
    static const word32 msg_len = 4;

    CaliptraCmk hmac_cmk;
    byte   caliptra_mac[48];
    word32 caliptra_mac_len = sizeof(caliptra_mac);
    byte   sw_mac[48];
    Hmac   sw_hmac;
    int    ret;

    memset(&hmac_cmk,    0, sizeof(hmac_cmk));
    memset(caliptra_mac, 0, sizeof(caliptra_mac));
    memset(sw_mac,       0, sizeof(sw_mac));

    /* Import the HMAC key into the Caliptra sim */
    ret = wc_caliptra_import_key(hmac_key, 48, CMB_KEY_USAGE_HMAC, &hmac_cmk);
    if (ret != 0) {
        TEST("HMAC-SHA-384 matches software", 0);
        return;
    }

    /* Caliptra HMAC via the supported single-shot wrapper */
    ret = wc_caliptra_hmac(&hmac_cmk, WC_SHA384, msg, msg_len,
                           caliptra_mac, &caliptra_mac_len);
    wc_caliptra_delete_key(&hmac_cmk);
    if (ret != 0 || caliptra_mac_len != 48) {
        TEST("HMAC-SHA-384 matches software", 0);
        return;
    }

    /* Software reference using INVALID_DEVID to bypass CryptoCb */
    ret = wc_HmacInit(&sw_hmac, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_HmacSetKey(&sw_hmac, WC_SHA384, hmac_key, 48);
        if (ret == 0)
            ret = wc_HmacUpdate(&sw_hmac, msg, msg_len);
        if (ret == 0)
            ret = wc_HmacFinal(&sw_hmac, sw_mac);
        wc_HmacFree(&sw_hmac);
    }

    TEST("HMAC-SHA-384 matches software",
         ret == 0 && bytes_eq(caliptra_mac, sw_mac, 48));
}

/* =========================================================================
 * Test 9: AES-GCM authentication failure (tampered tag)
 * ========================================================================= */

static void test_aesgcm_auth_failure(void)
{
    /* TEST-ONLY: same NIST AES-256 test vector key as test_aesgcm_roundtrip.
     * Hoisting to file scope was rejected as more change than necessary;
     * the duplication is intentional so each test function reads as
     * self-contained when reviewed in isolation. */
    static const byte aes_key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    static const byte plaintext[] = "Hello, Caliptra! This is a test.";

    CaliptraCmk cmk;
    byte ciphertext[48];
    byte discarded[48];
    byte auth_tag[16];
    byte bad_tag[16];
    byte iv[12];
    byte dummy_iv[12];  /* placeholder: wolfSSL requires ivSz>0; Caliptra ignores it */
    Aes  aes;
    int  ret;

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(discarded,  0, sizeof(discarded));
    memset(auth_tag,   0, sizeof(auth_tag));
    memset(iv,         0, sizeof(iv));
    memset(dummy_iv,   0, sizeof(dummy_iv));

    ret = wc_caliptra_import_key(aes_key, 32, CMB_KEY_USAGE_AES, &cmk);
    if (ret != 0) {
        TEST("AES-GCM tampered tag returns AES_GCM_AUTH_E", 0);
        return;
    }

    /* Encrypt to obtain valid ciphertext, tag, and Caliptra-generated IV */
    ret = wc_AesInit(&aes, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0) {
        aes.devCtx = &cmk;
        ret = wc_AesGcmEncrypt(&aes,
                               ciphertext, plaintext, 32,
                               dummy_iv, 12,
                               auth_tag, 16,
                               NULL, 0);
        if (ret == 0)
            ret = wc_caliptra_aesgcm_get_iv(&aes, iv, sizeof(iv));
        wc_AesFree(&aes);
    }

    if (ret != 0) {
        wc_caliptra_delete_key(&cmk);
        TEST("AES-GCM tampered tag returns AES_GCM_AUTH_E", 0);
        return;
    }

    /* Tamper the authentication tag: flip the first byte */
    memcpy(bad_tag, auth_tag, 16);
    bad_tag[0] ^= 0xFF;

    /* Decrypt with the tampered tag — must return AES_GCM_AUTH_E, not 0 */
    ret = wc_AesInit(&aes, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0) {
        aes.devCtx = &cmk;
        ret = wc_AesGcmDecrypt(&aes,
                               discarded, ciphertext, 32,
                               iv, 12,
                               bad_tag, 16,
                               NULL, 0);
        wc_AesFree(&aes);
    }

    wc_caliptra_delete_key(&cmk);

    TEST("AES-GCM tampered tag returns AES_GCM_AUTH_E", ret == AES_GCM_AUTH_E);
}

/* =========================================================================
 * main
 * ========================================================================= */

int main(void)
{
    int ret;

    wolfSSL_Init();

#ifdef CALIPTRA_HWMODEL
    /* Boot the hw-model emulator before registering the CryptoCb device.
     * ROM_PATH and FW_PATH are supplied via -D flags in the Makefile. */
#ifndef CALIPTRA_ROM_PATH
#error "CALIPTRA_ROM_PATH must be defined when building with CALIPTRA_HWMODEL"
#endif
#ifndef CALIPTRA_FW_PATH
#error "CALIPTRA_FW_PATH must be defined when building with CALIPTRA_HWMODEL"
#endif
    ret = caliptra_hwmodel_init(CALIPTRA_ROM_PATH, CALIPTRA_FW_PATH);
    if (ret != 0) {
        printf("FATAL: caliptra_hwmodel_init failed: %d\n", ret);
        wolfSSL_Cleanup();
        return 1;
    }
#endif /* CALIPTRA_HWMODEL */

    ret = wc_CryptoCb_RegisterDevice(WOLF_CALIPTRA_DEVID, wc_caliptra_cb, NULL);
    if (ret != 0) {
        printf("FATAL: CryptoCb_RegisterDevice failed: %d\n", ret);
#ifdef CALIPTRA_HWMODEL
        caliptra_hwmodel_cleanup();
#endif
        wolfSSL_Cleanup();
        return 1;
    }

    test_rng();
    test_sha256_empty();
    test_sha256_abc();
    test_sha384_empty();
    test_sha256_multiupdate();
    test_aesgcm_roundtrip();
    test_ecdsa_sign_verify();
    test_hmac_sha384();
    test_aesgcm_auth_failure();

    printf("\n%d/%d tests passed\n", tests_pass, tests_run);

    wc_CryptoCb_UnRegisterDevice(WOLF_CALIPTRA_DEVID);
    wolfSSL_Cleanup();

#ifdef CALIPTRA_HWMODEL
    caliptra_hwmodel_cleanup();
#endif

    return (tests_pass == tests_run) ? 0 : 1;
}
