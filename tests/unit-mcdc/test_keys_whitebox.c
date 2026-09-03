/* test_keys_whitebox.c -- MC/DC white-box driver for src/keys.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* src/keys.c has no test file, no --group of its own, and no caller outside
 * internal.c and tls13.c. Everything in it runs during a handshake, from
 * values a handshake has already negotiated -- which is exactly why its
 * remaining conditions have no independence pair from outside.
 *
 * The negotiated cipher suite is one value per connection. The protocol
 * version is one value per connection. `enc` and `dec` are non-NULL on every
 * call the library makes. So `cipherSuite0 != ECC_BYTE && ...`, the SSLv3
 * and DTLS version tests, and the `enc && enc->chacha == NULL` allocation
 * guards are each evaluated once, one way, per binary.
 *
 * Called directly they are cheap: GetCipherSpec and SetKeys take plain
 * structs, not a WOLFSSL, and SetCipherSpecs and SetKeysSide need only the
 * fields they read. The fixture is a zeroed WOLFSSL with a ctx, as for the
 * internal.c drivers.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - Bail paths print, so "covered nothing" differs from "nothing to say".
 */

#include <wolfssl/options.h>

#include <src/keys.c>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS)

static int g_checks;
#define WB_NOTE(what) do { g_checks++; (void)(what); } while (0)

/* ------------------------------------------------------------ GetCipherSpec

 * `cipherSuite0 != ECC_BYTE && cipherSuite0 != ECDHE_PSK_BYTE && ...` decides
 * which suite table is consulted. A connection negotiates one suite, so each
 * operand is fixed for the life of the binary; here the first byte is swept
 * over every table selector plus one that matches none.
 *
 * `specs->sig_algo == anonymous_sa_algo && opts != NULL` is the anonymous
 * carve-out that marks the peer pre-authenticated. Both operands need a pair,
 * and every in-tree caller passes a non-NULL opts. */
static void wb_cipher_spec(void)
{
    static const byte suite0[] = {
        ECC_BYTE, ECDHE_PSK_BYTE, CHACHA_BYTE, TLS13_BYTE, 0x00, 0xFE
    };
    static const byte suite[] = {
        TLS_RSA_WITH_AES_128_CBC_SHA & 0xFF,
        TLS_DH_anon_WITH_AES_128_CBC_SHA & 0xFF,
        TLS_PSK_WITH_AES_128_CBC_SHA & 0xFF,
        0xFF
    };
    const word16 sides[2] = { WOLFSSL_CLIENT_END, WOLFSSL_SERVER_END };
    CipherSpecs specs;
    Options opts;
    size_t a, b;
    int s;

    for (s = 0; s < 2; s++) {
        for (a = 0; a < sizeof(suite0) / sizeof(suite0[0]); a++) {
            for (b = 0; b < sizeof(suite) / sizeof(suite[0]); b++) {
                XMEMSET(&specs, 0, sizeof(specs));
                XMEMSET(&opts, 0, sizeof(opts));
                WB_NOTE(GetCipherSpec(sides[s], suite0[a], suite[b],
                                      &specs, &opts));
                /* the same suite with no Options: the second operand of the
                 * anonymous carve-out, which no in-tree caller can take */
                XMEMSET(&specs, 0, sizeof(specs));
                WB_NOTE(GetCipherSpec(sides[s], suite0[a], suite[b],
                                      &specs, NULL));
            }
        }
    }

    /* An anonymous suite specifically, so the first operand of that decision
     * is true with opts both present and absent. */
    XMEMSET(&specs, 0, sizeof(specs));
    XMEMSET(&opts, 0, sizeof(opts));
    WB_NOTE(GetCipherSpec(WOLFSSL_CLIENT_END, 0x00,
                          TLS_DH_anon_WITH_AES_128_CBC_SHA & 0xFF,
                          &specs, &opts));
    XMEMSET(&specs, 0, sizeof(specs));
    WB_NOTE(GetCipherSpec(WOLFSSL_CLIENT_END, 0x00,
                          TLS_DH_anon_WITH_AES_128_CBC_SHA & 0xFF,
                          &specs, NULL));
}

/* ---------------------------------------------------------- SetCipherSpecs

 * `ssl->version.major == SSLv3_MAJOR && ssl->version.minor >= TLSv1_MINOR`
 * and `ssl->options.dtls && ssl->version.major == DTLS_MAJOR`. Each is two
 * operands over a version and a flag that are fixed once a connection exists,
 * so the sweep sets them directly. */
static void wb_set_cipher_specs(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    static const struct { byte major; byte minor; const char* what; } vers[] = {
        { SSLv3_MAJOR, SSLv3_MINOR,   "SSLv3" },
        { SSLv3_MAJOR, TLSv1_MINOR,   "TLS 1.0" },
        { SSLv3_MAJOR, TLSv1_1_MINOR, "TLS 1.1" },
        { SSLv3_MAJOR, TLSv1_2_MINOR, "TLS 1.2" },
        { SSLv3_MAJOR, TLSv1_3_MINOR, "TLS 1.3" },
        { DTLS_MAJOR,  DTLSv1_2_MINOR,"DTLS 1.2" },
        { DTLS_MAJOR,  DTLS_MINOR,    "DTLS 1.3" },
        { 0xFE,        0x00,          "neither family" },
    };
    static const byte suite0[] = { ECC_BYTE, CHACHA_BYTE, TLS13_BYTE, 0x00 };
    size_t v, a;
    int dtls;

    for (v = 0; v < sizeof(vers) / sizeof(vers[0]); v++) {
        for (dtls = 0; dtls < 2; dtls++) {
            for (a = 0; a < sizeof(suite0) / sizeof(suite0[0]); a++) {
                XMEMSET(ssl, 0, sizeof(*ssl));
                ssl->ctx = ctx;
                ssl->version.major = vers[v].major;
                ssl->version.minor = vers[v].minor;
                ssl->options.side = WOLFSSL_CLIENT_END;
                ssl->options.cipherSuite0 = suite0[a];
                ssl->options.cipherSuite =
                    TLS_RSA_WITH_AES_128_CBC_SHA & 0xFF;
#ifdef WOLFSSL_DTLS
                ssl->options.dtls = (byte)dtls;
#endif
                WB_NOTE(SetCipherSpecs(ssl));
            }
        }
    }
}

/* ----------------------------------------------------------------- SetKeys

 * `if (enc && enc->chacha == NULL)` and its decrypt twin allocate the cipher
 * state lazily. Every caller inside the library passes both, and passes them
 * freshly zeroed, so the NULL operand and the already-allocated operand are
 * each half a pair. Calling it with one side or neither completes both.
 *
 * SetKeys takes a Ciphers, a Keys and a CipherSpecs -- no WOLFSSL and no
 * ownership -- so stack objects are correct here. The allocation it performs
 * is freed by hand below. */
static void wb_set_keys(void)
{
    Ciphers enc;
    Ciphers dec;
    Keys keys;
    CipherSpecs specs;
    int side;
    size_t i;

    static const struct { int haveEnc; int haveDec; const char* what; } rows[] = {
        { 1, 1, "both sides, as the library calls it" },
        { 1, 0, "encrypt only" },
        { 0, 1, "decrypt only" },
        { 0, 0, "neither" },
    };

    for (side = 0; side < 2; side++) {
        for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            int s = side ? WOLFSSL_SERVER_END : WOLFSSL_CLIENT_END;

            XMEMSET(&enc, 0, sizeof(enc));
            XMEMSET(&dec, 0, sizeof(dec));
            XMEMSET(&keys, 0, sizeof(keys));
            XMEMSET(&specs, 0, sizeof(specs));

            /* a ChaCha20-Poly1305 suite, so the chacha allocation guards are
             * the decisions actually taken */
            specs.bulk_cipher_algorithm = wolfssl_chacha;
            specs.key_size = CHACHA20_256_KEY_SIZE;
            specs.iv_size = CHACHA20_IV_SIZE;
            specs.hash_size = WC_SHA256_DIGEST_SIZE;

            WB_NOTE(SetKeys(rows[i].haveEnc ? &enc : NULL,
                            rows[i].haveDec ? &dec : NULL,
                            &keys, &specs, s, NULL, INVALID_DEVID, NULL, 0));

            /* and again on the same objects, so the second call finds the
             * state already allocated -- the other half of each pair */
            WB_NOTE(SetKeys(rows[i].haveEnc ? &enc : NULL,
                            rows[i].haveDec ? &dec : NULL,
                            &keys, &specs, s, NULL, INVALID_DEVID, NULL, 0));

#ifdef HAVE_CHACHA
            XFREE(enc.chacha, NULL, DYNAMIC_TYPE_CIPHER);
            XFREE(dec.chacha, NULL, DYNAMIC_TYPE_CIPHER);
            enc.chacha = NULL;
            dec.chacha = NULL;
#endif
        }
    }
}

/* ------------------------------------------------------------- SetAuthKeys

 * `if (authentication && authentication->poly1305 == NULL)`, twice: once to
 * decide whether to allocate and once to check the allocation. Both operands
 * of both, from a NULL argument and from a struct called twice. */
static void wb_set_auth_keys(void)
{
#ifdef HAVE_ONE_TIME_AUTH
    OneTimeAuth auth;
    Keys keys;
    CipherSpecs specs;

    XMEMSET(&keys, 0, sizeof(keys));
    XMEMSET(&specs, 0, sizeof(specs));

    WB_NOTE(SetAuthKeys(NULL, &keys, &specs, NULL, INVALID_DEVID));

    XMEMSET(&auth, 0, sizeof(auth));
    WB_NOTE(SetAuthKeys(&auth, &keys, &specs, NULL, INVALID_DEVID));
    /* second call: poly1305 is no longer NULL */
    WB_NOTE(SetAuthKeys(&auth, &keys, &specs, NULL, INVALID_DEVID));

#ifdef HAVE_POLY1305
    XFREE(auth.poly1305, NULL, DYNAMIC_TYPE_CIPHER);
    auth.poly1305 = NULL;
#endif
#endif
}

/* -------------------------------------------------------------- SetKeysSide

 * `ret == 0 && ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version)` and
 * `ret == 0 && ssl->options.dtls && !ssl->options.tls1_3`. The dtls operand
 * and the version operand are both fixed per connection; sweeping the four
 * combinations against both sides pairs each of them. */
static void wb_set_keys_side(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    static const enum encrypt_side sides[3] = {
        ENCRYPT_SIDE_ONLY, DECRYPT_SIDE_ONLY, ENCRYPT_AND_DECRYPT_SIDE
    };
    static const struct { byte major; byte minor; const char* what; } vers[] = {
        { SSLv3_MAJOR, TLSv1_2_MINOR,  "TLS 1.2" },
        { SSLv3_MAJOR, TLSv1_3_MINOR,  "TLS 1.3" },
        { DTLS_MAJOR,  DTLSv1_2_MINOR, "DTLS 1.2" },
        { DTLS_MAJOR,  DTLS_MINOR,     "DTLS 1.3" },
    };
    size_t v, s;
    int dtls;

    for (v = 0; v < sizeof(vers) / sizeof(vers[0]); v++) {
        for (dtls = 0; dtls < 2; dtls++) {
            for (s = 0; s < sizeof(sides) / sizeof(sides[0]); s++) {
                XMEMSET(ssl, 0, sizeof(*ssl));
                ssl->ctx = ctx;
                ssl->version.major = vers[v].major;
                ssl->version.minor = vers[v].minor;
                ssl->options.side = WOLFSSL_CLIENT_END;
                ssl->options.tls1_3 =
                    (vers[v].minor == TLSv1_3_MINOR ||
                     vers[v].minor == DTLS_MINOR) ? 1 : 0;
#ifdef WOLFSSL_DTLS
                ssl->options.dtls = (byte)dtls;
#endif
                ssl->specs.bulk_cipher_algorithm = wolfssl_aes_gcm;
                ssl->specs.key_size = AES_128_KEY_SIZE;
                ssl->specs.iv_size = AESGCM_IMP_IV_SZ;
                ssl->specs.hash_size = WC_SHA256_DIGEST_SIZE;

                WB_NOTE(SetKeysSide(ssl, sides[s]));

                /* free whatever the call allocated on this throwaway ssl */
                FreeCiphers(ssl);
            }
        }
    }
}

/* ---------------------------------------------------------------- main */

int main(void)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("keys white-box: wolfSSL_Init failed\n");
        goto done;
    }
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        printf("keys white-box: CTX_new failed\n");
        goto done;
    }
    ssl = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    if (ssl == NULL) {
        printf("keys white-box: out of memory\n");
        goto done;
    }

    wb_cipher_spec();
    wb_set_cipher_specs(ssl, ctx);
    wb_set_keys();
    wb_set_auth_keys();
    wb_set_keys_side(ssl, ctx);

    printf("keys white-box: %d vectors driven\n", g_checks);

done:
    XFREE(ssl, NULL, DYNAMIC_TYPE_SSL);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("keys white-box: skipped (TLS not built)\n");
    return 0;
}

#endif
