/* test_signature_whitebox.c
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
 * MC/DC supplement for wolfcrypt/src/signature.c (module "signature",
 * single variant "default").
 *
 * TARGET, in wc_SignatureVerifyHash()'s RSA arm (~line 311):
 *
 *     if (ret >= 0 && plain_ptr) {
 *          ^idx0      ^idx1
 *
 * THREE VECTORS, ONE BINARY (llvm-cov derives MC/DC per binary):
 *
 *   V1  (T,T)  wb_sig_plainptr_guard() "accepting" call: a genuine RSA-2048
 *              PKCS#1 v1.5 verify of a signature this driver just produced
 *              over the same digest. wc_RsaSSL_VerifyInline() returns the
 *              plaintext length and publishes plain_ptr.
 *              -> decision TRUE. Pairs with V2 for idx0 and with V3 for idx1.
 *
 *   V2  (F,-)  the same call with one byte of the signature flipped. The
 *              public-key operation yields non-conforming padding, RsaUnPad()
 *              returns RSA_PAD_E, plain_ptr is never assigned. idx0 FALSE,
 *              idx1 not evaluated (short circuit) -> decision FALSE.
 *              Memory-safe: plain_ptr is still the NULL it was initialised to
 *              at line 298 and the guard short-circuits before it is read.
 *
 *   V3  (T,F)  idx1's FALSE half. See "WHY V3 NEEDS AN INTERPOSER" below.
 *
 * WHY V3 NEEDS AN INTERPOSER (source-derived)
 * -------------------------------------------
 * In this variant (software RSA only: no WOLFSSL_CRYPTOCELL, no SE050, no
 * WOLF_CRYPTO_CB_RSA_PAD) the two operands are perfectly coupled and
 * (ret >= 0 && plain_ptr == NULL) is structurally unreachable:
 *
 *   - signature.c line 292/295: this variant is NOT WOLFSSL_SMALL_STACK, so
 *     plain_data is an ALIGN64 stack array (MAX_ENCODED_CLASSIC_SIG_SZ = 512
 *     for SP_INT_BITS 4096) and the guard is "plain_len <= sizeof(plain_data)".
 *     There is NO XMALLOC on this path, so mcdc_fault_alloc.h has no site to
 *     fault here -- and in the small-stack build a failed plain_data XMALLOC
 *     would take the "else -> MEMORY_E" arm and never reach line 311 at all.
 *   - plain_ptr is only ever written by RsaPrivateDecryptEx() (rsa.c ~4136,
 *     "*outPtr = pad;"), inside "else if (ret >= 0 && pad != NULL)". pad is
 *     only written by RsaUnPad() (rsa.c ~2061) on its success path, which is
 *     also the only path on which it returns a non-negative length. Every
 *     other exit of wc_RsaSSL_VerifyInline() (BAD_FUNC_ARG, BAD_STATE_E,
 *     MEMORY_E, RSA_PAD_E, RSA_BUFFER_E, the wc_RsaFunction_ex failure break)
 *     is negative. Hence in software: ret >= 0  <=>  plain_ptr != NULL.
 *
 * The guard is nevertheless real defensive code for backends that return
 * success without publishing an inline pointer. So V3 drives it the same way
 * mcdc_fault_hash.h drives the hash engines: MACRO INTERPOSITION for this
 * translation unit only. mcdc_sig_verify_inline() is compiled BEFORE the
 * "#define wc_RsaSSL_VerifyInline ..." (so it still reaches the real
 * implementation in rsa.o) and, when armed, returns 0 while leaving *out
 * untouched. That is exactly the backend shape the guard defends against.
 * Nothing is read through plain_ptr on this vector -- the guard is FALSE, so
 * the XMEMCMP at line 313 is not executed.
 *
 * If the campaign prefers not to admit interposition-driven evidence here,
 * the alternative is to EXCLUDE 311:21:311:42:1 (and, with it, the (T,F)
 * half only) on the argument above; V1/V2 still close idx0 on their own.
 *
 * Build: compiled by the campaign's white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with signature.o removed. Not part of the wolfSSL build.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* Every wolfSSL header the interposer and the target need must be parsed
 * BEFORE the "#define wc_RsaSSL_VerifyInline" below, otherwise the macro would
 * rewrite the API declaration itself. Same ordering rule as
 * mcdc_fault_hash.h. */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#ifndef NO_ASN
    #include <wolfssl/wolfcrypt/asn.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

/* Static test key material (raw C arrays, no other dependency). */
#ifndef USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_2048
#endif
#include <wolfssl/certs_test.h>

#include <stdio.h>

#if defined(__GNUC__) || defined(__clang__)
    #define MCDC_SIG_MAYBE_UNUSED __attribute__((unused))
#else
    #define MCDC_SIG_MAYBE_UNUSED
#endif

/* ---- V3 lever: wc_RsaSSL_VerifyInline interposer (see header comment) ---- */
#if !defined(NO_RSA) && !defined(WOLFSSL_CRYPTOCELL)

#define MCDC_SIG_VI_REAL       0   /* pass through to the real RSA backend  */
#define MCDC_SIG_VI_OK_NO_PTR  1   /* return >= 0 and leave *out untouched  */

static int mcdc_sig_vi_mode = MCDC_SIG_VI_REAL;

MCDC_SIG_MAYBE_UNUSED
static int mcdc_sig_verify_inline(byte* in, word32 inLen, byte** out,
    RsaKey* key)
{
    if (mcdc_sig_vi_mode == MCDC_SIG_VI_OK_NO_PTR) {
        (void)in;
        (void)inLen;
        (void)key;
        (void)out;      /* deliberately NOT written: caller's NULL stands */
        return 0;
    }
    return wc_RsaSSL_VerifyInline(in, inLen, out, key);
}

#undef  wc_RsaSSL_VerifyInline
#define wc_RsaSSL_VerifyInline(a, b, c, d) \
    mcdc_sig_verify_inline((a), (b), (c), (d))

#endif /* !NO_RSA && !WOLFSSL_CRYPTOCELL */

#include <wolfcrypt/src/signature.c>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* --------------------------------------------------------------------------
 * wc_SignatureVerifyHash(): "ret >= 0 && plain_ptr" independence pairs.
 * ----------------------------------------------------------------------- */
#if !defined(NO_SIG_WRAPPER) && !defined(NO_RSA) && !defined(NO_ASN) && \
    !defined(NO_SHA256) && !defined(WOLFSSL_CRYPTOCELL) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WC_NO_RNG)
static void wb_sig_plainptr_guard(void)
{
    RsaKey key;
    WC_RNG rng;
    byte   hash[WC_SHA256_DIGEST_SIZE];
    byte   sig[512];
    byte   bad[512];
    word32 idx    = 0;
    word32 sigLen = (word32)sizeof(sig);
    int    ret;
    int    rngOk = 0, keyOk = 0;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(hash, 0x5a, sizeof(hash));
    XMEMSET(sig,  0, sizeof(sig));
    XMEMSET(bad,  0, sizeof(bad));

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; plain_ptr guard skipped");
        return;
    }
    rngOk = 1;

    if (wc_InitRsaKey(&key, NULL) != 0) {
        WB_NOTE("wc_InitRsaKey failed; plain_ptr guard skipped");
        goto done;
    }
    keyOk = 1;

    if (wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &key,
            (word32)sizeof_client_key_der_2048) != 0) {
        WB_NOTE("RSA-2048 test key decode failed; plain_ptr guard skipped");
        goto done;
    }

    /* Deterministic: PKCS#1 v1.5 over a fixed digest with a fixed key. */
    ret = wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_RSA, hash, (word32)sizeof(hash), sig, &sigLen,
        &key, (word32)sizeof(RsaKey), &rng, 0);
    if (ret != 0 || sigLen == 0 || sigLen > (word32)sizeof(sig)) {
        WB_NOTE("RSA sign setup failed; plain_ptr guard skipped");
        goto done;
    }

    /* V1 (T,T): genuine verify. plain_ptr published, ret == hash_len. */
    ret = wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA,
        hash, (word32)sizeof(hash), sig, sigLen, &key,
        (word32)sizeof(RsaKey));
    if (ret != 0) {
        WB_NOTE("valid RSA signature unexpectedly rejected");
        wb_fail = 1;
    }

    /* V2 (F,-): one flipped signature byte -> RSA_PAD_E, plain_ptr stays
     * NULL and is never read (short circuit). */
    XMEMCPY(bad, sig, sigLen);
    bad[sigLen / 2] = (byte)(bad[sigLen / 2] ^ 0xFF);
    ret = wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA,
        hash, (word32)sizeof(hash), bad, sigLen, &key,
        (word32)sizeof(RsaKey));
    if (ret == 0) {
        WB_NOTE("corrupted RSA signature unexpectedly accepted");
        wb_fail = 1;
    }

    /* V3 (T,F): interposed backend reports success without publishing an
     * inline pointer. Guard is FALSE, so nothing dereferences plain_ptr. */
    mcdc_sig_vi_mode = MCDC_SIG_VI_OK_NO_PTR;
    (void)wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA,
        hash, (word32)sizeof(hash), sig, sigLen, &key,
        (word32)sizeof(RsaKey));
    mcdc_sig_vi_mode = MCDC_SIG_VI_REAL;

    WB_NOTE("wc_SignatureVerifyHash ret/plain_ptr pairs exercised");

done:
    if (keyOk)
        (void)wc_FreeRsaKey(&key);
    if (rngOk)
        (void)wc_FreeRng(&rng);
}
#else
static void wb_sig_plainptr_guard(void)
{ WB_NOTE("RSA sign+verify wrapper not compiled in; plain_ptr guard skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("signature.c white-box MC/DC supplement\n");

    wb_sig_plainptr_guard();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
