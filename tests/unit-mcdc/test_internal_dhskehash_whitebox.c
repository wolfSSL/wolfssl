/* test_internal_dhskehash_whitebox.c -- MC/DC white-box driver for the
 * file-static ServerKeyExchange hashing and DH-parameter guards in
 * src/internal.c
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

/* WHY A WHITE-BOX.
 *
 *   HashSkeData     -- `if (ret == 0 && !SigAlgoCachesMsgs(sigAlgo))`,
 *                      appearing twice. A real handshake only ever runs this
 *                      with one fixed signature algorithm per connection, so
 *                      the caching/non-caching split of SigAlgoCachesMsgs()
 *                      never varies within a single call site's history the
 *                      way a from-scratch driver can force it to.
 *   GetDhPublicKey  -- the four-operand FFDHE-parameter-match guard. A real
 *                      handshake against a conforming DH server always uses
 *                      genuine, matching FFDHE parameters, so the decision is
 *                      always false there; the four ways it can be forced
 *                      true (unknown group, wrong g length, wrong g bytes,
 *                      wrong p bytes) never occur against a real peer.
 *
 * MC/DC's independence pair has to be demonstrated inside ONE binary's own
 * execution trace: llvm-cov computes the covered bit per condition from a
 * single profile, and the campaign's union is a logical OR of those
 * already-computed bits across binaries, not a merge of raw traces. So every
 * pair below -- including the "everything valid" partner -- is produced by
 * THIS driver; none of it is borrowed from the real handshake corpus.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - Each target carries the SAME preprocessor guard that encloses it in
 *     internal.c.
 */

#include <wolfssl/options.h>

#include <src/internal.c>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)

static int g_calls;

typedef struct WbFix {
    WOLFSSL*     ssl;
    WOLFSSL_CTX* ctx;
} WbFix;

static void wb_reset(WbFix* f)
{
    XMEMSET(f->ssl, 0, sizeof(*f->ssl));
    XMEMSET(f->ctx, 0, sizeof(*f->ctx));
    f->ssl->ctx = f->ctx;
    f->ssl->heap = NULL;
    f->ssl->devId = INVALID_DEVID;
    f->ssl->version.major = SSLv3_MAJOR;
    f->ssl->version.minor = TLSv1_2_MINOR;
}

/* Free whatever HashSkeData / GetDhPublicKey may have left allocated on the
 * fixture, so the next vector starts clean. Safe to call unconditionally --
 * XFREE(NULL, ...) is a no-op. */
static void wb_free_buffers(WbFix* f)
{
    XFREE(f->ssl->buffers.sig.buffer, f->ssl->heap, DYNAMIC_TYPE_SIGNATURE);
    f->ssl->buffers.sig.buffer = NULL;
    XFREE(f->ssl->buffers.digest.buffer, f->ssl->heap, DYNAMIC_TYPE_DIGEST);
    f->ssl->buffers.digest.buffer = NULL;
    XFREE(f->ssl->buffers.serverDH_P.buffer, f->ssl->heap,
          DYNAMIC_TYPE_PUBLIC_KEY);
    f->ssl->buffers.serverDH_P.buffer = NULL;
    XFREE(f->ssl->buffers.serverDH_G.buffer, f->ssl->heap,
          DYNAMIC_TYPE_PUBLIC_KEY);
    f->ssl->buffers.serverDH_G.buffer = NULL;
    XFREE(f->ssl->buffers.serverDH_Pub.buffer, f->ssl->heap,
          DYNAMIC_TYPE_PUBLIC_KEY);
    f->ssl->buffers.serverDH_Pub.buffer = NULL;
}

/* ----------------------------------------------------------- HashSkeData
 *
 * Two identical two-operand guards over the same `ret`/`sigAlgo`, evaluated
 * back to back with nothing in between that can change either. One sweep of
 * three calls pairs all four target conditions at once:
 *   - an early failure (unsupported hash type) drives `ret == 0` false at
 *     both sites, sharing one vector;
 *   - a non-caching signature algorithm (rsa_sa_algo) with a valid hash type
 *     drives both sites fully true -- the decision's other shared vector;
 *   - a caching signature algorithm (ed25519_sa_algo, when built) with the
 *     same valid hash type drives `!SigAlgoCachesMsgs()` false at both sites
 *     while `ret == 0` stays true, pairing the second operand. */
#if (!defined(NO_WOLFSSL_CLIENT) && (!defined(NO_DH) || defined(HAVE_ECC) || \
      defined(HAVE_CURVE25519) || defined(HAVE_CURVE448))) || \
    (!defined(NO_WOLFSSL_SERVER) && (defined(HAVE_ECC) || \
      ((defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)) && \
       (defined(HAVE_ED25519) || defined(HAVE_ED448) || !defined(NO_RSA)))) || \
     (!defined(NO_DH) && (!defined(NO_RSA) || defined(HAVE_ANON))))
static void wb_hash_ske_data(WbFix* f)
{
    static const byte data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte              clientRandom[RAN_LEN];
    byte              serverRandom[RAN_LEN];
    Arrays            arrays;

    XMEMSET(clientRandom, 0xAA, sizeof(clientRandom));
    XMEMSET(serverRandom, 0xBB, sizeof(serverRandom));
    XMEMSET(&arrays, 0, sizeof(arrays));
    XMEMCPY(arrays.clientRandom, clientRandom, RAN_LEN);
    XMEMCPY(arrays.serverRandom, serverRandom, RAN_LEN);

    /* shared false-operand-0 vector: an invalid hash type makes
     * wc_HashGetDigestSize() fail, so ret != 0 before either guard. */
    wb_reset(f);
    f->ssl->arrays = &arrays;
    (void)HashSkeData(f->ssl, (enum wc_HashType)9999, data,
                      (word32)sizeof(data), rsa_sa_algo);
    g_calls++;
    wb_free_buffers(f);

    /* the shared true vector: ret stays 0 through both guards, and
     * rsa_sa_algo does not cache messages -- SigAlgoCachesMsgs() is false. */
    wb_reset(f);
    f->ssl->arrays = &arrays;
    (void)HashSkeData(f->ssl, WC_HASH_TYPE_SHA256, data,
                      (word32)sizeof(data), rsa_sa_algo);
    g_calls++;
    wb_free_buffers(f);

#ifdef HAVE_ED25519
    /* operand 1's false pair: ret stays 0, but ed25519_sa_algo DOES cache
     * messages -- SigAlgoCachesMsgs() is true, so !SigAlgoCachesMsgs() is
     * false and the decision is false with operand 0 held true. */
    wb_reset(f);
    f->ssl->arrays = &arrays;
    (void)HashSkeData(f->ssl, WC_HASH_TYPE_SHA256, data,
                      (word32)sizeof(data), ed25519_sa_algo);
    g_calls++;
    wb_free_buffers(f);
#endif

    f->ssl->arrays = NULL;
}
#endif

/* --------------------------------------------------------- GetDhPublicKey
 *
 * The four-operand FFDHE match guard. All four vectors and the shared false
 * (accepting) partner are built from the SAME real ffdhe2048 parameter table
 * the library ships (wc_Dh_ffdhe2048_Get()), so "matches" and "does not
 * match" are both well-defined without needing a live peer. */
#ifndef NO_DH
#ifdef HAVE_FFDHE
#ifdef HAVE_FFDHE_2048
#ifdef HAVE_PUBLIC_FFDHE
/* Build a ServerKeyExchange DH-params wire fragment: 2-byte-length-prefixed
 * P, G, Pub. Returns the total length written to buf (which must be large
 * enough -- callers size it generously). */
static word32 wb_build_dh_wire(byte* buf, const byte* p, word16 pLen,
                               const byte* g, word16 gLen,
                               const byte* pub, word16 pubLen)
{
    word32 idx = 0;

    c16toa(pLen, buf + idx); idx += OPAQUE16_LEN;
    XMEMCPY(buf + idx, p, pLen); idx += pLen;
    c16toa(gLen, buf + idx); idx += OPAQUE16_LEN;
    XMEMCPY(buf + idx, g, gLen); idx += gLen;
    c16toa(pubLen, buf + idx); idx += OPAQUE16_LEN;
    XMEMCPY(buf + idx, pub, pubLen); idx += pubLen;

    return idx;
}

static void wb_get_dh_public_key_one(WbFix* f, const byte* p, word16 pLen,
                                     const byte* g, word16 gLen)
{
    byte      wire[600];
    byte      pub[8];
    DskeArgs  args;
    word32    wireLen;

    XMEMSET(pub, 0x01, sizeof(pub));
    wireLen = wb_build_dh_wire(wire, p, pLen, g, gLen, pub,
                               (word16)sizeof(pub));

    wb_reset(f);
    f->ssl->options.minDhKeySz = 0;
    f->ssl->options.maxDhKeySz = 4096;

    XMEMSET(&args, 0, sizeof(args));
    args.idx = 0;
    args.begin = 0;

    (void)GetDhPublicKey(f->ssl, wire, wireLen, &args);
    g_calls++;
    wb_free_buffers(f);
}

static void wb_get_dh_public_key(WbFix* f)
{
    const DhParams* real = wc_Dh_ffdhe2048_Get();
    byte            badP[256];
    byte            badG[1];
    byte            shortP[100];

    if (real == NULL || real->p_len != 256 || real->g_len != 1)
        return;   /* table shape changed; nothing safe to build against */

    XMEMCPY(badP, real->p, sizeof(badP));
    badP[0] ^= 0xFF;                 /* content differs, same length */
    badG[0] = (byte)(real->g[0] ^ 0xFF);
    XMEMSET(shortP, 0x03, sizeof(shortP));

    /* operand 0 true: P length matches no known FFDHE group -> params stays
     * NULL. G is irrelevant (any 1 byte). */
    wb_get_dh_public_key_one(f, shortP, (word16)sizeof(shortP),
                             real->g, (word16)real->g_len);

    /* operand 1 true: P length selects ffdhe2048 (so params != NULL), but G
     * is a different LENGTH than params->g_len -- short-circuits before
     * comparing G or P content. */
    wb_get_dh_public_key_one(f, real->p, (word16)real->p_len,
                             badG, (word16)0);

    /* operand 2 true: P length matches, G length matches, G content does
     * not -- short-circuits before comparing P content. */
    wb_get_dh_public_key_one(f, real->p, (word16)real->p_len,
                             badG, (word16)real->g_len);

    /* operand 3 true: P length matches, G matches exactly, P content does
     * not. */
    wb_get_dh_public_key_one(f, badP, (word16)real->p_len,
                             real->g, (word16)real->g_len);

    /* the shared false partner: everything matches the real table exactly */
    wb_get_dh_public_key_one(f, real->p, (word16)real->p_len,
                             real->g, (word16)real->g_len);
}
#endif /* HAVE_PUBLIC_FFDHE */
#endif /* HAVE_FFDHE_2048 */
#endif /* HAVE_FFDHE */
#endif /* !NO_DH */

/* ---------------------------------------------------------------------- main */

int main(void)
{
    WbFix f;

    XMEMSET(&f, 0, sizeof(f));

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal dh/ske-hash white-box: wolfSSL_Init failed\n");
        return 0;
    }

    f.ssl = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    f.ctx = (WOLFSSL_CTX*)XMALLOC(sizeof(WOLFSSL_CTX), NULL, DYNAMIC_TYPE_CTX);
    if (f.ssl == NULL || f.ctx == NULL) {
        printf("internal dh/ske-hash white-box: out of memory\n");
        goto done;
    }

#if (!defined(NO_WOLFSSL_CLIENT) && (!defined(NO_DH) || defined(HAVE_ECC) || \
      defined(HAVE_CURVE25519) || defined(HAVE_CURVE448))) || \
    (!defined(NO_WOLFSSL_SERVER) && (defined(HAVE_ECC) || \
      ((defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)) && \
       (defined(HAVE_ED25519) || defined(HAVE_ED448) || !defined(NO_RSA)))) || \
     (!defined(NO_DH) && (!defined(NO_RSA) || defined(HAVE_ANON))))
    wb_hash_ske_data(&f);
#endif
#if !defined(NO_DH) && defined(HAVE_FFDHE) && defined(HAVE_FFDHE_2048) && \
    defined(HAVE_PUBLIC_FFDHE)
    wb_get_dh_public_key(&f);
#endif

    printf("internal dh/ske-hash white-box: %d static-guard calls\n", g_calls);

done:
    XFREE(f.ctx, NULL, DYNAMIC_TYPE_CTX);
    XFREE(f.ssl, NULL, DYNAMIC_TYPE_SSL);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("internal dh/ske-hash white-box: skipped (TLS 1.2 not built)\n");
    return 0;
}

#endif
