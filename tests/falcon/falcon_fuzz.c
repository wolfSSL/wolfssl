/* falcon_fuzz.c
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

/* Falcon keygen/sign/verify round-trip fuzzer.
 *
 * Targets a specific, intermittently reproducing failure reported against the
 * native Falcon implementation: a freshly generated key produces a signature
 * that then fails to verify against its own public key. Because the fault is
 * probabilistic (it depends on the Gaussian sampler / signing-restart path and
 * on the particular key), a single make_key/sign/verify pass rarely trips it;
 * this driver hammers the loop across many keys and many messages per key so a
 * "fairly regular" fault surfaces quickly.
 *
 * On the first mismatch the driver dumps a self-contained repro artifact
 * (public key, raw private key, message, and the signature that did not
 * verify) so the failure can be replayed deterministically -- verification is a
 * pure function of (public key, message, signature), so the dumped triple
 * reproduces the fault without needing to reconstruct the RNG stream.
 *
 * Usage:
 *   falcon_fuzz [--level 1|5|both] [--iters N] [--msgs M] [--seed S]
 *               [--stop-on-fail] [--dump-dir DIR] [--quiet]
 *   falcon_fuzz --replay FILE
 *
 * Exit status is non-zero if any verify mismatch (or unexpected API error) was
 * observed, so it drops straight into CI / a nightly loop.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#if !defined(HAVE_FALCON)
int main(void)
{
    fprintf(stderr,
        "falcon_fuzz: wolfSSL was built without Falcon support.\n"
        "Reconfigure with --enable-experimental --enable-falcon.\n");
    return 77; /* automake "skip" convention */
}
#elif !defined(WC_FALCON_HAVE_NATIVE_SIGN)
int main(void)
{
    fprintf(stderr,
        "falcon_fuzz: this build is verify-only (no native signing), so the\n"
        "keygen/sign/verify round trip cannot be exercised. Rebuild without\n"
        "WOLFSSL_FALCON_VERIFY_ONLY / WOLF_CRYPTO_CB_ONLY_FALCON.\n");
    return 77; /* automake "skip" convention */
}
#else

/* Largest message we sign; deliberately spans several hash-to-point blocks. */
#define FUZZ_MAX_MSG_LEN 512

/* Extra headroom added to the signature buffer beyond any level's maximum, so
 * the signer must enforce the level budget itself instead of being clamped by
 * our buffer. Must be > 0 to exercise the over-length path on every level. */
#define FALCON_SLACK 64

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void print_hex(FILE* f, const char* tag, const byte* buf, word32 len)
{
    word32 i;
    fprintf(f, "%s=", tag);
    for (i = 0; i < len; i++)
        fprintf(f, "%02x", buf[i]);
    fprintf(f, "\n");
}

/* Dump the failing artifact so it can be replayed with --replay. Returns 0 on
 * success. */
static int dump_repro(const char* dir, int level, unsigned long iter,
        const byte* pub, word32 pubLen,
        const byte* prv, word32 prvLen,
        const byte* msg, word32 msgLen,
        const byte* sig, word32 sigLen)
{
    char path[512];
    FILE* f;

    snprintf(path, sizeof(path), "%s/falcon_fail_L%d_%lu.repro",
             dir ? dir : ".", level, iter);
    f = fopen(path, "w");
    if (f == NULL) {
        fprintf(stderr, "  (could not open repro file %s)\n", path);
        return -1;
    }

    fprintf(f, "# Falcon keygen/sign/verify failure artifact.\n");
    fprintf(f, "# Replay with:  falcon_fuzz --replay %s\n", path);
    fprintf(f, "level=%d\n", level);
    print_hex(f, "pub", pub, pubLen);
    print_hex(f, "prv", prv, prvLen);
    print_hex(f, "msg", msg, msgLen);
    print_hex(f, "sig", sig, sigLen);
    fclose(f);

    fprintf(stderr, "  repro written to %s\n", path);
    return 0;
}

/* One keygen/sign/verify episode. Returns 0 on success, 1 on a detected
 * failure (already reported + dumped), <0 on an unexpected API error that
 * prevents the test from running. */
static int run_episode(WC_RNG* rng, int level, unsigned long iter,
        int msgsPerKey, const char* dumpDir, int quiet)
{
    falcon_key key;
    byte  pub[FALCON_MAX_PUB_KEY_SIZE];
    byte  prv[FALCON_MAX_KEY_SIZE];
    byte  msg[FUZZ_MAX_MSG_LEN];
    /* Deliberately over-sized: FALCON_SLACK bytes larger than any level's
     * signature. We hand this whole length to wc_falcon_sign_msg so the signer
     * is forced to bound the encoding by the *level's* fixed maximum rather
     * than coincidentally by our buffer size -- this is what exposes an
     * over-length (buffer-bounded) signature bug on BOTH levels, not just when
     * the buffer happens to exceed the level max. */
    byte  sig[FALCON_MAX_SIG_SIZE + FALCON_SLACK];
    word32 sigMax = (word32)((level == FALCON_LEVEL5) ? FALCON_LEVEL5_SIG_SIZE
                                                      : FALCON_LEVEL1_SIG_SIZE);
    word32 pubLen, prvLen, msgLen, sigLen;
    int ret;
    int m;
    int failures = 0;

    ret = wc_falcon_init(&key);
    if (ret != 0) {
        fprintf(stderr, "wc_falcon_init failed: %d\n", ret);
        return -1;
    }
    ret = wc_falcon_set_level(&key, (byte)level);
    if (ret != 0) {
        fprintf(stderr, "wc_falcon_set_level(%d) failed: %d\n", level, ret);
        wc_falcon_free(&key);
        return -1;
    }

    ret = wc_falcon_make_key(&key, rng);
    if (ret != 0) {
        fprintf(stderr, "[L%d iter %lu] wc_falcon_make_key failed: %d\n",
                level, iter, ret);
        wc_falcon_free(&key);
        return -1;
    }

    /* A key that cannot self-check is itself a keygen bug worth catching. */
    ret = wc_falcon_check_key(&key);
    if (ret != 0) {
        fprintf(stderr, "[L%d iter %lu] wc_falcon_check_key failed: %d\n",
                level, iter, ret);
        failures++;
    }

    /* Export the key material up front so any failing message can be dumped
     * against the exact key that produced it. */
    pubLen = sizeof(pub);
    ret = wc_falcon_export_public(&key, pub, &pubLen);
    if (ret != 0) {
        fprintf(stderr, "[L%d iter %lu] export_public failed: %d\n",
                level, iter, ret);
        wc_falcon_free(&key);
        return -1;
    }
    prvLen = sizeof(prv);
    ret = wc_falcon_export_private_only(&key, prv, &prvLen);
    if (ret != 0) {
        fprintf(stderr, "[L%d iter %lu] export_private_only failed: %d\n",
                level, iter, ret);
        wc_falcon_free(&key);
        return -1;
    }

    for (m = 0; m < msgsPerKey; m++) {
        int res = 0;

        /* Vary the message length, including the zero-length edge case, so we
         * cover different hash-to-point block counts. */
        if (m == 0) {
            msgLen = 0;
        }
        else {
            msgLen = (word32)(rand() % FUZZ_MAX_MSG_LEN) + 1;
        }
        if (msgLen > 0)
            (void)wc_RNG_GenerateBlock(rng, msg, msgLen);

        sigLen = sizeof(sig);
        ret = wc_falcon_sign_msg(msg, msgLen, sig, &sigLen, &key, rng);
        if (ret != 0) {
            fprintf(stderr,
                "[L%d iter %lu msg %d] wc_falcon_sign_msg failed: %d "
                "(msgLen=%u)\n", level, iter, m, ret, msgLen);
            failures++;
            /* Nothing to verify without a signature; capture the key anyway. */
            dump_repro(dumpDir, level, iter, pub, pubLen, prv, prvLen,
                       msg, msgLen, sig, 0);
            continue;
        }

        /* An emitted signature longer than the level's fixed maximum is itself
         * the bug (a buffer-bounded rather than budget-bounded encoding): it is
         * out of spec and no verifier will accept it. Catch it directly, even
         * before verify, since it is the precise fault we are hunting. */
        if (sigLen > sigMax) {
            fprintf(stderr,
                "[L%d iter %lu msg %d] OVER-LENGTH SIGNATURE: sigLen=%u > "
                "level max %u (msgLen=%u)\n",
                level, iter, m, sigLen, sigMax, msgLen);
            dump_repro(dumpDir, level, iter, pub, pubLen, prv, prvLen,
                       msg, msgLen, sig, sigLen);
            failures++;
            continue;
        }

        res = 0;
        ret = wc_falcon_verify_msg(sig, sigLen, msg, msgLen, &res, &key);
        if (ret != 0 || res != 1) {
            /* THE bug we are hunting: signed by a fresh key, will not verify. */
            fprintf(stderr,
                "[L%d iter %lu msg %d] SIGN/VERIFY MISMATCH: verify ret=%d "
                "res=%d (msgLen=%u sigLen=%u)\n",
                level, iter, m, ret, res, msgLen, sigLen);
            dump_repro(dumpDir, level, iter, pub, pubLen, prv, prvLen,
                       msg, msgLen, sig, sigLen);
            failures++;
            continue;
        }

        /* Sanity guard against a verifier that trivially accepts everything:
         * a single flipped signature bit must NOT verify. */
        if (sigLen > 0) {
            byte saved = sig[sigLen / 2];
            sig[sigLen / 2] ^= 0x01;
            res = 1;
            ret = wc_falcon_verify_msg(sig, sigLen, msg, msgLen, &res, &key);
            if (ret == 0 && res == 1) {
                fprintf(stderr,
                    "[L%d iter %lu msg %d] tampered signature verified as "
                    "valid -- verifier is not rejecting corruption\n",
                    level, iter, m);
                failures++;
            }
            sig[sigLen / 2] = saved;
        }
    }

    wc_falcon_free(&key);

    if (!quiet && failures == 0 && (iter % 500 == 0)) {
        fprintf(stdout, "[L%d] %lu keys ok\n", level, iter);
        fflush(stdout);
    }

    return failures ? 1 : 0;
}

static int fuzz_level(WC_RNG* rng, int level, unsigned long iters,
        int msgsPerKey, const char* dumpDir, int stopOnFail, int quiet,
        unsigned long* keysDone, unsigned long* failsSeen)
{
    unsigned long i;
    int hardError = 0;

    for (i = 1; !g_stop && (iters == 0 || i <= iters); i++) {
        int r = run_episode(rng, level, i, msgsPerKey, dumpDir, quiet);
        (*keysDone)++;
        if (r < 0) {
            hardError = 1;
            break;
        }
        if (r > 0) {
            (*failsSeen)++;
            if (stopOnFail) {
                g_stop = 1;
                break;
            }
        }
    }
    return hardError;
}

/* ---------------------------- replay support ---------------------------- */

static long read_hex_field(const char* line, const char* tag, byte* out,
        long outMax)
{
    size_t taglen = strlen(tag);
    const char* p;
    long n = 0;

    if (strncmp(line, tag, taglen) != 0 || line[taglen] != '=')
        return -1;
    p = line + taglen + 1;

    while (p[0] && p[0] != '\n' && p[0] != '\r') {
        unsigned v;
        if (p[1] == '\0' || p[1] == '\n' || p[1] == '\r')
            break;
        if (sscanf(p, "%2x", &v) != 1)
            break;
        if (n >= outMax)
            return -2;
        out[n++] = (byte)v;
        p += 2;
    }
    return n;
}

static int replay(const char* file)
{
    FILE* f = fopen(file, "r");
    char line[4096];
    int level = 0;
    byte pub[FALCON_MAX_PUB_KEY_SIZE];
    byte msg[FUZZ_MAX_MSG_LEN * 4];
    byte sig[FALCON_MAX_SIG_SIZE];
    long pubLen = -1, msgLen = -1, sigLen = -1;
    falcon_key key;
    int ret, res = 0;

    if (f == NULL) {
        fprintf(stderr, "cannot open repro file %s\n", file);
        return 2;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] == '#')
            continue;
        if (strncmp(line, "level=", 6) == 0) {
            level = atoi(line + 6);
        }
        else if (strncmp(line, "pub=", 4) == 0) {
            pubLen = read_hex_field(line, "pub", pub, (long)sizeof(pub));
        }
        else if (strncmp(line, "msg=", 4) == 0) {
            msgLen = read_hex_field(line, "msg", msg, (long)sizeof(msg));
        }
        else if (strncmp(line, "sig=", 4) == 0) {
            sigLen = read_hex_field(line, "sig", sig, (long)sizeof(sig));
        }
        /* prv= is captured for investigation but not needed to replay verify */
    }
    fclose(f);

    if (level == 0 || pubLen <= 0 || msgLen < 0 || sigLen <= 0) {
        fprintf(stderr, "malformed repro file (level=%d pubLen=%ld msgLen=%ld "
                "sigLen=%ld)\n", level, pubLen, msgLen, sigLen);
        return 2;
    }

    ret = wc_falcon_init(&key);
    if (ret == 0)
        ret = wc_falcon_set_level(&key, (byte)level);
    if (ret == 0)
        ret = wc_falcon_import_public(pub, (word32)pubLen, &key);
    if (ret != 0) {
        fprintf(stderr, "replay: importing public key failed: %d\n", ret);
        wc_falcon_free(&key);
        return 2;
    }

    ret = wc_falcon_verify_msg(sig, (word32)sigLen, msg, (word32)msgLen,
                               &res, &key);
    wc_falcon_free(&key);

    printf("replay %s: level=%d msgLen=%ld sigLen=%ld -> verify ret=%d res=%d\n",
           file, level, msgLen, sigLen, ret, res);
    if (ret == 0 && res == 1) {
        printf("  VERIFIES OK (bug not reproduced with this artifact)\n");
        return 0;
    }
    printf("  DOES NOT VERIFY (bug reproduced)\n");
    return 1;
}

/* ------------------------------- driver -------------------------------- */

static void usage(const char* argv0)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --level 1|5|both   security level(s) to fuzz (default: both)\n"
        "  --iters N          keygen iterations per level, 0 = forever "
        "(default: 5000)\n"
        "  --msgs M           messages signed per key (default: 8)\n"
        "  --seed S           seed the C RNG used for message lengths\n"
        "  --stop-on-fail     stop at the first detected failure\n"
        "  --dump-dir DIR     directory for repro artifacts (default: .)\n"
        "  --quiet            suppress periodic progress output\n"
        "  --replay FILE      re-verify a dumped repro artifact and exit\n",
        argv0);
}

int main(int argc, char** argv)
{
    WC_RNG rng;
    int ret;
    int doL1 = 1, doL5 = 1;
    unsigned long iters = 5000;
    int msgsPerKey = 8;
    int stopOnFail = 0;
    int quiet = 0;
    unsigned int seed = 0;
    int haveSeed = 0;
    const char* dumpDir = ".";
    const char* replayFile = NULL;
    unsigned long keysDone = 0, failsSeen = 0;
    int i;
    int hardError = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--level") == 0 && i + 1 < argc) {
            const char* v = argv[++i];
            if (strcmp(v, "1") == 0) { doL1 = 1; doL5 = 0; }
            else if (strcmp(v, "5") == 0) { doL1 = 0; doL5 = 1; }
            else if (strcmp(v, "both") == 0) { doL1 = 1; doL5 = 1; }
            else { usage(argv[0]); return 2; }
        }
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            iters = strtoul(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "--msgs") == 0 && i + 1 < argc) {
            msgsPerKey = atoi(argv[++i]);
            if (msgsPerKey < 1) msgsPerKey = 1;
        }
        else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            seed = (unsigned int)strtoul(argv[++i], NULL, 10);
            haveSeed = 1;
        }
        else if (strcmp(argv[i], "--stop-on-fail") == 0) {
            stopOnFail = 1;
        }
        else if (strcmp(argv[i], "--dump-dir") == 0 && i + 1 < argc) {
            dumpDir = argv[++i];
        }
        else if (strcmp(argv[i], "--quiet") == 0) {
            quiet = 1;
        }
        else if (strcmp(argv[i], "--replay") == 0 && i + 1 < argc) {
            replayFile = argv[++i];
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
        else {
            fprintf(stderr, "unknown / incomplete option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (replayFile != NULL)
        return replay(replayFile);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* The C library RNG only chooses message lengths; key/signature entropy all
     * comes from the wolfCrypt WC_RNG below. Seeding it just makes the length
     * schedule repeatable across runs. */
    if (!haveSeed)
        seed = (unsigned int)time(NULL);
    srand(seed);

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "wc_InitRng failed: %d\n", ret);
        return 2;
    }

    printf("falcon_fuzz: levels=%s%s iters=%lu msgs/key=%d seed=%u\n",
           doL1 ? "1" : "", doL5 ? (doL1 ? ",5" : "5") : "",
           iters, msgsPerKey, seed);
    fflush(stdout);

    if (doL1 && !g_stop)
        hardError |= fuzz_level(&rng, FALCON_LEVEL1, iters, msgsPerKey,
                                dumpDir, stopOnFail, quiet,
                                &keysDone, &failsSeen);
    if (doL5 && !g_stop)
        hardError |= fuzz_level(&rng, FALCON_LEVEL5, iters, msgsPerKey,
                                dumpDir, stopOnFail, quiet,
                                &keysDone, &failsSeen);

    wc_FreeRng(&rng);

    printf("\nfalcon_fuzz: %lu keys exercised, %lu failure(s) detected%s\n",
           keysDone, failsSeen, g_stop ? " (interrupted)" : "");

    if (hardError)
        return 2;
    return failsSeen ? 1 : 0;
}

#endif /* HAVE_FALCON && WC_FALCON_HAVE_NATIVE_SIGN */
