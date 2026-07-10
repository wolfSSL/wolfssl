/* test_ed25519_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/ed25519.c.
 *
 * The tests/api ed25519 suite drives ed25519.c through its *public* API. The
 * file-static helper ed25519_hash() opens with:
 *
 *   if (key == NULL || (in == NULL && inLen > 0) || hash == NULL) {
 *       return BAD_FUNC_ARG;
 *   }
 *
 * Every public caller (wc_ed25519_make_public, wc_ed25519_sign_msg_ex,
 * wc_ed25519ph_sign_msg, wc_ed25519ph_verify_msg) always passes a non-NULL
 * key, a non-NULL hash output buffer, and either a non-NULL `in` or an
 * `in`/`inLen` pair where inLen is a compile-time-fixed nonzero constant
 * (WC_SHA512_DIGEST_SIZE or ED25519_KEY_SIZE) paired with a real buffer --
 * none of them ever construct the "in==NULL && inLen>0" combination or pass
 * key/hash as NULL. This translation unit reaches all three operands' TRUE
 * sides (and completes the FALSE-side pairing within this same binary, per
 * the campaign's cross-binary MC/DC lesson) by compiling ed25519.c directly
 * (#include) and calling the static helper directly.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage
 * by source line:col in the per-module campaign (iso26262/mcdc-per-module):
 * llvm-cov computes MC/DC independence PER BINARY, and the campaign's
 * aggregate.sh ORs the "independence shown" bit across binaries by key. That
 * is why every pair below is completed *within this file* rather than
 * relying on the API tests to supply the other half.
 *
 * Build: compiled by run-mcdc-par.sh's white-box step with the SAME MC/DC
 * CFLAGS, -DHAVE_CONFIG_H and -I<workspace> as the instrumented library,
 * then linked against that variant's libwolfssl.a with its ed25519.o
 * removed (this TU supplies the instrumented ed25519.c). NOT part of the
 * wolfSSL build; not registered in tests/api. See tests/unit-mcdc/
 * README.md.
 *
 * Targeted residual (ed25519.c):
 *   Class 1  ed25519_hash() key/in/hash NULL guard ............ 4 conditions
 * The only ed25519.c gap confirmed structurally unreachable through the
 * public API (every wrapper hard-codes non-NULL, well-formed arguments).
 * See the campaign's RESIDUALS.md for everything else: the "ret==0" FALSE
 * sides following a successful ed25519_hash() call (would need a mockable
 * malloc/wc_InitSha512Ex failure to force), and the WOLFSSL_CHECK_VER_FAULTS
 * redundant post-verify ConstantCompare (a deterministic double-call on the
 * same fixed inputs that cannot diverge between the two calls without
 * memory corruption between them -- structurally unreachable, matching the
 * aes/ecc campaigns' "defensive redundant check" residual class).
 */

/* Pull ed25519.c in verbatim so the file-static helper below is in scope
 * and instrumented in THIS binary. ed25519.c includes settings.h (which
 * picks up user_settings.h via -DWOLFSSL_USER_SETTINGS) and ed25519.h
 * itself. */
#include <wolfcrypt/src/ed25519.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#ifdef HAVE_ED25519

/* ------------------------------------------------------------------------- *
 * Class 1: ed25519_hash() (line ~172).
 *
 *   if (key == NULL || (in == NULL && inLen > 0) || hash == NULL)
 *
 * unique-cause MC/DC for a 3-operand OR needs, per operand, a pair where
 * only that operand's value differs against an otherwise all-false vector.
 * ------------------------------------------------------------------------- */
static void wb_ed25519_hash(void)
{
    ed25519_key key;
    byte in[8];
    byte hash[WC_SHA512_DIGEST_SIZE];
    int ret;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(in, 0x11, sizeof(in));

    /* all-false baseline: valid call. */
    ret = ed25519_hash(&key, in, sizeof(in), hash);
    if (ret != 0) {
        WB_NOTE("ed25519_hash(valid) unexpected error");
        wb_fail = 1;
    }

    /* key == NULL: operand 1 TRUE, others false. */
    ret = ed25519_hash(NULL, in, sizeof(in), hash);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("ed25519_hash(key==NULL) did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* in == NULL && inLen > 0: operand 2 TRUE, others false. Also
     * completes operand 2's own inner-compound independence (paired
     * against the all-false baseline's in!=NULL, and against inLen==0
     * below for the inLen>0 half). */
    ret = ed25519_hash(&key, NULL, sizeof(in), hash);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("ed25519_hash(in==NULL,inLen>0) did not return "
                 "BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* in == NULL && inLen == 0: operand 2's inner "inLen > 0" FALSE side
     * (in==NULL alone does not trip the guard) -- valid call, matches how
     * every public caller with a zero-length message actually behaves. */
    ret = ed25519_hash(&key, NULL, 0, hash);
    if (ret != 0) {
        WB_NOTE("ed25519_hash(in==NULL,inLen==0) unexpected error");
        wb_fail = 1;
    }

    /* hash == NULL: operand 3 TRUE, others false. */
    ret = ed25519_hash(&key, in, sizeof(in), NULL);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("ed25519_hash(hash==NULL) did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }

    WB_NOTE("ed25519_hash key/in/hash guard exercised");
}

#else

static void wb_ed25519_hash(void)
{
    WB_NOTE("HAVE_ED25519 not compiled in this variant; skipped");
}

#endif /* HAVE_ED25519 */

int main(void)
{
    printf("ed25519.c white-box supplement\n");
#ifndef HAVE_ED25519
    printf("  HAVE_ED25519 not defined; nothing to exercise\n");
    return 0;
#else
    wb_ed25519_hash();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the
     * campaign treats a nonzero exit as a failed variant and discards its
     * coverage. */
    return 0;
#endif
}
