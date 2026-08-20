/* test_tls13_whitebox.c
 *
 * White-box MC/DC supplement for src/tls13.c.
 *
 * This is the FIRST white-box driver in the campaign that targets a src/ file
 * rather than wolfcrypt/src/*.c. The build contract is identical (see
 * tests/unit-mcdc/README.md): this TU #includes the target .c verbatim, is
 * compiled with the exact flags the instrumented library used for it, and is
 * linked against that variant's libwolfssl.a with the target's own object
 * removed, so this TU supplies the single (instrumented) definition.
 *
 * WHY A WHITE-BOX IS NEEDED HERE, given that src/ has almost no mutable file
 * scope variables and all state hangs off WOLFSSL / WOLFSSL_CTX:
 * tls13.c has ~80 `static` functions. What this TU buys is not access to
 * hidden state but the ability to call those helpers with ARGUMENT
 * COMBINATIONS NO PUBLIC CALLER PRODUCES -- the defensive guards that every
 * in-library caller has already excluded before the callee runs. Those guards
 * are real conditions in the coverage map and are unreachable from tests/api
 * without editing library source.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage by
 * source line:col by the campaign's aggregate.sh, which ORs the "independence
 * shown" bit across binaries. llvm-cov derives independence PER BINARY, so
 * every MC/DC pair below is completed WITHIN THIS FILE; nothing here leans on
 * the API tests to supply the other half of a pair.
 *
 * main() always returns 0: the campaign treats a nonzero exit as a failed
 * white-box and discards its coverage, so setup problems are printed as skips.
 */

/* Pull tls13.c in verbatim so its file-static helpers are in scope and
 * instrumented in THIS binary. tls13.c includes settings.h, which picks up
 * user_settings.h via -DWOLFSSL_USER_SETTINGS. */
#include <src/tls13.c>

#include <stdio.h>

#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* The guard stack that encloses DecodeTls13SigAlg() in tls13.c:
 *   #if !defined(NO_TLS) && defined(WOLFSSL_TLS13)
 *   #ifndef WOLFCRYPT_ONLY
 *   #ifndef NO_CERTS
 *   #if !defined(NO_RSA) || defined(HAVE_ECC) || ...
 * Reproduced verbatim so this file still compiles (as a no-op) on any build
 * axis that does not compile the helper. */
#if !defined(NO_TLS) && defined(WOLFSSL_TLS13) && !defined(WOLFCRYPT_ONLY) && \
    !defined(NO_CERTS) && \
    (!defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519) || \
     defined(HAVE_ED448) || defined(HAVE_FALCON) || \
     defined(WOLFSSL_HAVE_MLDSA) || defined(WOLFSSL_HAVE_SLHDSA))
    #define WB_HAVE_DECODE_SIGALG
#endif

/* ------------------------------------------------------------------------- *
 * DecodeTls13SigAlg(): the two RSA-PSS minor-byte RANGE checks.
 *
 *   if (input[1] >= RSA_PSS_RSAE_SHA256_MINOR &&
 *           input[1] <= RSA_PSS_RSAE_SHA512_MINOR)          [0x04 .. 0x06]
 *   else if (input[1] >= RSA_PSS_PSS_SHA256_MINOR &&
 *           input[1] <= RSA_PSS_PSS_SHA512_MINOR)           [0x09 .. 0x0B]
 *
 * DecodeTls13SigAlg is file-static and every in-library caller feeds it a
 * signature algorithm that already passed the peer's advertised sig_algs
 * negotiation, so the "major byte is 0x08 but the minor byte sits just outside
 * a PSS range" combinations -- exactly the (T,F) halves of these two pairs --
 * never arrive from a handshake. Called directly here with all three vectors
 * per decision:
 *   {0x08,0x05}  -> (T,T) decision true
 *   {0x08,0x03}  -> (F,-) decision false (short-circuits)   pair for operand 0
 *   {0x08,0x07}  -> (T,F) decision false                    pair for operand 1
 * and the same shape one range up for the PSS-PSS check, which is only
 * reached when the RSAE check is false.
 *
 * Pure function of a 2-byte buffer and two out-bytes: no WOLFSSL object, no
 * allocation, no entropy.
 * ------------------------------------------------------------------------- */
#ifdef WB_HAVE_DECODE_SIGALG
static void wb_decode_tls13_sigalg(void)
{
    static const byte vec[6][2] = {
        { NEW_SA_MAJOR, 0x05 },  /* RSAE range: T,T */
        { NEW_SA_MAJOR, 0x03 },  /* RSAE range: F,- ; PSS range: F,- */
        { NEW_SA_MAJOR, 0x07 },  /* RSAE range: T,F */
        { NEW_SA_MAJOR, 0x0A },  /* RSAE F,- then PSS range: T,T */
        { NEW_SA_MAJOR, 0x0C },  /* RSAE F,- then PSS range: T,F */
        { NEW_SA_MAJOR, 0x09 }   /* PSS range lower edge: T,T */
    };
    byte input[2];
    byte hashAlgo;
    byte hsType;
    size_t i;

    for (i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {
        input[0] = vec[i][0];
        input[1] = vec[i][1];
        hashAlgo = 0;
        hsType   = 0;
        (void)DecodeTls13SigAlg(input, &hashAlgo, &hsType);
    }

    WB_NOTE("DecodeTls13SigAlg: both PSS minor-byte range decisions driven "
            "with both halves of each independence pair");
}
#else
static void wb_decode_tls13_sigalg(void)
{ WB_NOTE("DecodeTls13SigAlg not compiled in this variant; skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("tls13.c white-box MC/DC supplement\n");

    wb_decode_tls13_sigalg();

    printf("done\n");
    /* Always 0: a nonzero exit is scored as a failed white-box and its
     * coverage is discarded. */
    return 0;
}
