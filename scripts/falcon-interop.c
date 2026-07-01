/* falcon-interop.c
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

/* Phase-5 Falcon interop harness.
 *
 * Cross-checks the native wolfCrypt Falcon implementation (wc_falcon_*,
 * <wolfssl/wolfcrypt/falcon.h>) against liboqs (open-quantum-safe), called
 * DIRECTLY through its OQS_SIG_* API. (The legacy wc_falcon_* wrapper now maps
 * to the native code, so it is NOT used here as the "liboqs side".)
 *
 * Both encode Falcon identically (public key header 0x09/0x0A + 14-bit packed
 * h; signature header 0x39/0x3A + 40-byte nonce + compressed s2), so keys and
 * signatures are cross-usable. The interop matrix, run for both levels:
 *
 *   (1) liboqs keygen+sign  -> native verify
 *   (2) liboqs keygen+sign  -> liboqs verify   (baseline)
 *   (3) native keygen+sign  -> native verify
 *   (4) native keygen+sign  -> liboqs verify
 *
 * Build wolfSSL with native Falcon (no liboqs needed by the library itself):
 *   ./configure --enable-falcon && make
 * Then compile + run against the built lib + liboqs:
 *   gcc -I. -I<oqs>/include scripts/falcon-interop.c \
 *       src/.libs/libwolfssl.a <oqs>/lib/liboqs.a -lm -lcrypto -lpthread \
 *       -o falcon-interop && ./falcon-interop
 *
 * Exit status is 0 only if every cell passes.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/random.h>

#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(HAVE_FALCON)
    #error "This harness requires wolfSSL built with --enable-falcon"
#endif

static const char* kMsg = "wolfSSL Falcon native<->liboqs interop message";

typedef struct {
    byte        level;          /* FALCON_LEVEL1 / FALCON_LEVEL5 */
    const char* oqsAlg;
} falcon_params;

static int oqs_verify(OQS_SIG* o, const byte* pub, const byte* sig,
        size_t sigLen) {
    return OQS_SIG_verify(o, (const uint8_t*)kMsg, strlen(kMsg), sig, sigLen,
            pub) == OQS_SUCCESS ? 0 : -1;
}

static int native_verify(byte level, const byte* pub, word32 pubLen,
        const byte* sig, word32 sigLen) {
    falcon_key k;
    int res = 0, ret;
    if (wc_falcon_init(&k) != 0) return -1;
    ret = wc_falcon_set_level(&k, level);
    if (ret == 0) ret = wc_falcon_import_public(pub, pubLen, &k);
    if (ret == 0) ret = wc_falcon_verify_msg(sig, sigLen, (const byte*)kMsg,
            (word32)strlen(kMsg), &res, &k);
    wc_falcon_free(&k);
    return (ret == 0 && res == 1) ? 0 : -1;
}

static int run_level(const falcon_params* p, WC_RNG* rng) {
    OQS_SIG* o = OQS_SIG_new(p->oqsAlg);
    int rc = 0;
    byte *oqsPub = NULL, *oqsSec = NULL, *oqsSig = NULL;
    size_t oqsSigLen = 0;
    word32 pubLen = (p->level == FALCON_LEVEL1) ?
        FALCON_LEVEL1_PUB_KEY_SIZE : FALCON_LEVEL5_PUB_KEY_SIZE;

    if (o == NULL) { printf("  L%d: OQS_SIG_new failed\n", p->level); return -1; }
    oqsPub = malloc(o->length_public_key);
    oqsSec = malloc(o->length_secret_key);
    oqsSig = malloc(o->length_signature);
    if (!oqsPub || !oqsSec || !oqsSig) { rc = -1; goto done; }

    /* liboqs keygen + sign (shared by cells 1 and 2). */
    if (OQS_SIG_keypair(o, oqsPub, oqsSec) != OQS_SUCCESS) { rc=-1; goto done; }
    if (OQS_SIG_sign(o, oqsSig, &oqsSigLen, (const uint8_t*)kMsg, strlen(kMsg),
            oqsSec) != OQS_SUCCESS) { rc=-1; goto done; }

    /* (1) liboqs sign -> native verify */
    if (native_verify(p->level, oqsPub, pubLen, oqsSig, (word32)oqsSigLen) != 0) {
        printf("  L%d cell(1) liboqs->native  FAIL\n", p->level); rc=-1;
    } else printf("  L%d cell(1) liboqs->native  PASS\n", p->level);

    /* (2) liboqs sign -> liboqs verify */
    if (oqs_verify(o, oqsPub, oqsSig, oqsSigLen) != 0) {
        printf("  L%d cell(2) liboqs->liboqs  FAIL\n", p->level); rc=-1;
    } else printf("  L%d cell(2) liboqs->liboqs  PASS\n", p->level);

#ifdef WC_FALCON_HAVE_NATIVE_SIGN
    {
        falcon_key nk;
        byte natPub[FALCON_MAX_PUB_KEY_SIZE];
        byte natSig[FALCON_MAX_SIG_SIZE];
        word32 natPubLen = sizeof(natPub), natSigLen = sizeof(natSig);
        int ret, res = 0;

        ret = wc_falcon_init(&nk);
        if (ret == 0) ret = wc_falcon_set_level(&nk, p->level);
        if (ret == 0) ret = wc_falcon_make_key(&nk, rng);
        if (ret == 0) ret = wc_falcon_export_public(&nk, natPub, &natPubLen);
        if (ret == 0) ret = wc_falcon_sign_msg((const byte*)kMsg,
                (word32)strlen(kMsg), natSig, &natSigLen, &nk, rng);

        /* (3) native sign -> native verify */
        res = 0;
        if (ret == 0) ret = wc_falcon_verify_msg(natSig, natSigLen,
                (const byte*)kMsg, (word32)strlen(kMsg), &res, &nk);
        if (ret != 0 || res != 1) {
            printf("  L%d cell(3) native->native  FAIL\n", p->level); rc=-1;
        } else printf("  L%d cell(3) native->native  PASS\n", p->level);

        /* (4) native sign -> liboqs verify */
        if (ret == 0 && oqs_verify(o, natPub, natSig, natSigLen) == 0) {
            printf("  L%d cell(4) native->liboqs  PASS\n", p->level);
        } else {
            printf("  L%d cell(4) native->liboqs  FAIL\n", p->level); rc=-1;
        }
        wc_falcon_free(&nk);
    }
#else
    printf("  L%d cell(3) native->native  SKIP (native sign unavailable)\n", p->level);
    printf("  L%d cell(4) native->liboqs  SKIP (native sign unavailable)\n", p->level);
#endif

done:
    free(oqsPub); free(oqsSec); free(oqsSig);
    OQS_SIG_free(o);
    return rc;
}

int main(void) {
    WC_RNG rng;
    int f = 0;
    falcon_params l1 = { FALCON_LEVEL1, OQS_SIG_alg_falcon_512 };
    falcon_params l5 = { FALCON_LEVEL5, OQS_SIG_alg_falcon_1024 };

    printf("Falcon native<->liboqs interop matrix\n");
    if (wc_InitRng(&rng) != 0) { printf("rng init failed\n"); return 1; }
    f |= run_level(&l1, &rng);
    f |= run_level(&l5, &rng);
    wc_FreeRng(&rng);
    printf("%s\n", f == 0 ? "ALL PASS" : "FAIL");
    return f != 0;
}
