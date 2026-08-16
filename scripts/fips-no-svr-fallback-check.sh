#!/usr/bin/env bash
# =============================================================================
# fips-no-svr-fallback-check.sh -- fail a certified FIPS build that decides
# WHICH IMPLEMENTATION to run from whether vector registers were available.
#
# The construct this hunts:
#
#     if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
#         ..._avx2(...);            /* accelerated */
#     }
#     else {
#         ..._c(...);               /* a DIFFERENT implementation */
#     }
#
# and its De Morgan twin, which selects the other implementation by falling
# INTO the then-arm instead of out of it (wolfcrypt/src/sha256.c):
#
#     if ((sha_method == SHA256_C) ||
#         (SAVE_VECTOR_REGISTERS2() != 0))
#     {
#         return Transform_Sha256_C_from_raw(S, D);   /* a DIFFERENT impl */
#     }
#
# Both connectives are hunted.  An earlier revision keyed on && alone and
# reported PASS over the four || sites in sha256.c and sha512.c.
#
# SAVE_VECTOR_REGISTERS2() returning non-zero (WC_ACCEL_INHIBIT_E in kernel
# softirq/atomic context) short-circuits the connective, so control silently
# lands on another implementation of the same algorithm.  That is run-time
# implementation selection: FIPS 140-3 IG 10.3.A GeneralNote1 requires each
# implementation in the module to be self-tested separately, and no CAST
# covers the one a vector-register failure happens to select.  The correct
# shape is save-or-fail-closed:
#
#     if ((ret = SAVE_VECTOR_REGISTERS2()) != 0)
#         return ret;
#
# WHY IT PREPROCESSES INSTEAD OF GREPPING THE SOURCE
# --------------------------------------------------
# The same text is legitimate inside a block that a certified build does not
# compile -- e.g. aes.c's copies live under
# "WC_C_DYNAMIC_FALLBACK && WC_ALLOW_RUNTIME_IMPL_SELECT", and settings.h
# leaves WC_ALLOW_RUNTIME_IMPL_SELECT undefined for every validation-targeted
# build.  A source-level grep cannot tell those apart and would either cry
# wolf or need an allowlist -- and an allowlist is exactly where a real one
# would be parked.  So this runs the C preprocessor with -fdirectives-only,
# which evaluates #if/#ifdef and drops dead branches while leaving macro
# invocations unexpanded.  Whatever still says SAVE_VECTOR_REGISTERS2 in a
# condition after that is live in THIS build's boundary.
#
# Usage:  scripts/fips-no-svr-fallback-check.sh [configured-tree-dir]
# Exit:   0 clean, 1 a live site found, 2 cannot run (unconfigured tree)
# =============================================================================
set -uo pipefail
TREE="${1:-.}"
cd "$TREE" || exit 2

[ -f Makefile ] || { echo "SKIP: $TREE is not configured (no Makefile)."; exit 2; }

# Preprocess with the compiler the tree is CONFIGURED for, not the host one.
# On a cross-configured tree the host gcc does not define __aarch64__ (or does
# define __x86_64__), so it resolves the wrong arm of every arch #ifdef and the
# answer is about a target that was never built.  Checked: host gcc reports 0
# __aarch64__ on an aarch64 tree.
GATE_CC=$(sed -n 's/^CC = //p' Makefile | head -1)
GATE_CC=${GATE_CC:-gcc}

# EVERY variable the compile rule puts -D macros in, in the order the rule uses
# them:  $(..._CPPFLAGS) $(CPPFLAGS) $(..._CFLAGS) $(CFLAGS), where the
# per-target vars are "-DBUILDING_WOLFSSL $(AM_...)".  Order is kept because a
# later -D or -U must override an earlier one exactly as it does in the build.
#
# Reading AM_CFLAGS alone was a false negative with the same consequence as a
# missed regex.  configure folds EXTRA_CFLAGS into AM_CFLAGS but leaves a user's
# CFLAGS and CPPFLAGS where they were, and real invocations put -D there --
# kh-reinstall-for-optest.sh passes -DHAVE_FORCE_FIPS_FAILURE and
# -DDEBUG_FIPS_VERBOSE that way.  With WC_C_DYNAMIC_FALLBACK supplied through
# CFLAGS this script printed "PASS ... 111/111 sources examined" over four live
# || sites in sha256.c and sha512.c.  Confident coverage numbers, wrong answer.
mk_var() { sed -n "s/^$1 = //p" Makefile | head -1; }
CFLAGS_LINE="$(mk_var AM_CPPFLAGS) $(mk_var CPPFLAGS) $(mk_var AM_CFLAGS) $(mk_var CFLAGS)"

# Drop make-only constructs the shell must not see.
CFLAGS_LINE=$(echo "$CFLAGS_LINE" | sed 's/\$([^)]*)//g')

# -Werror must not come along now that CFLAGS does.  wolfcrypt/src carries
# #warning directives that fire in ordinary configurations (misc.c, asn_tsp.c,
# evp_pk.c), and under -Werror each one fails this script's preprocess, which it
# would then report as INCONCLUSIVE over the whole tree.  A warning flag cannot
# change which branches survive -fdirectives-only, so dropping it removes no
# evidence.  Only -Werror* is dropped; -I, -D and -U are all kept.
CFLAGS_LINE=$(echo "$CFLAGS_LINE" | sed 's/-Werror[^[:space:]]*//g')

# Only meaningful for a validation-targeted build; a non-FIPS build carries the
# legacy run-time selection deliberately and legitimately.  Tested against the
# composed flags rather than AM_CFLAGS alone, so a build that gets HAVE_FIPS
# through CPPFLAGS is gated instead of skipped.
case " $CFLAGS_LINE " in
    *-DHAVE_FIPS*) ;;
    *)
        if ! grep -q 'define HAVE_FIPS' wolfssl/options.h 2>/dev/null; then
            echo "SKIP: not a FIPS build; run-time selection is legitimate here."
            exit 0
        fi
        ;;
esac

# The in-boundary sources that carry acceleration dispatch.
SRCS=$(ls wolfcrypt/src/*.c 2>/dev/null)

# SHAPE 1 -- one line.  SAVE_VECTOR_REGISTERS2() combined with something else,
# rather than having its result assigned and tested on its own.  Either
# connective: "&& (SVR2() == 0)" and "|| (SVR2() != 0)" are the same selection.
PATTERN='(&&|[|][|])[[:space:]]*\(*[[:space:]]*SAVE_VECTOR_REGISTERS2\(\)[[:space:]]*[=!]=|SAVE_VECTOR_REGISTERS2\(\)[[:space:]]*[=!]=[[:space:]]*0[[:space:]]*\)[[:space:]]*(&&|[|][|])'

# SHAPES 2 and 3 -- what SHAPE 1 alone cannot see.  Both were demonstrated to
# slip past a grep for SHAPE 1, and shape 2 was hiding a live site in
# ge_operations.c (an Ed25519 verify path) that this gate reported as PASS:
#
#   SHAPE 2, the condition wraps.  Identical meaning to shape 1, but the
#   connective ends the previous line, so a single-line regex never sees the
#   two together.  This is the shape the four sha256.c/sha512.c || sites take:
#
#       if (IS_INTEL_AVX512(f) && IS_INTEL_AVX512_IFMA(f) &&
#               IS_INTEL_AVX512_VL(f) &&
#               (SAVE_VECTOR_REGISTERS2() == 0)) {   /* accelerated */
#       ...
#       return ..._c(...);                           /* a DIFFERENT impl */
#
#   SHAPE 3, the error is swallowed.  The result is bound and tested properly,
#   then the failure arm sets the status back to 0 -- which is only ever done
#   so control can continue into another implementation:
#
#       ret = SAVE_VECTOR_REGISTERS2();
#       if (ret != 0) {
#           sha3_block = BlockSha3;   /* a DIFFERENT impl */
#           ret = 0;                  /* <-- the tell */
#       }
#
# Both are additions.  Nothing shape 1 used to catch stops being caught.
#
#   SHAPE 4, the status is bound, tested, and then LOST.  This one shipped in
#   wolfcrypt/src/sp_x86_64.c and this gate reported PASS over it, which is why
#   it is here.  The save result is assigned to a variable and immediately
#   converted into a lane flag -- correctly -- and then the variable is
#   overwritten by an unrelated status before anything acts on the failure:
#
#       err = SAVE_VECTOR_REGISTERS2();
#       if (err == 0)
#           saved_vector_registers = 1;
#       ...
#       err = sp_2048_mod_32_cond(r, a, m);   /* <-- the save result is gone */
#       if (err == MP_OKAY) {
#           if (saved_vector_registers) { ..._avx2(...); }
#           else                        { ..._c(...);    }   /* <-- runs */
#       }
#
#   Shapes 1-3 cannot see it: nothing is fused, nothing wraps, and the status
#   is not reset to 0 -- it is replaced by a different call's return value.
#
#   Testing for the clobber itself needs dataflow.  The STRUCTURE is decidable
#   without it, and forbidding the structure is the stronger rule anyway: a
#   variable carrying the save result -- or a flag derived from it -- must
#   never be the condition of an if/else that chooses between implementations.
#   When it is, the else arm is reachable from a save failure unless some
#   unrelated guard happens to sit in the right place, and "happens to" is not
#   a property a module can be certified on.
#
#   The correct shape splits the two facts into two variables:
#
#       if (IS_INTEL_AVX2(cpuid_flags))     /* CPU capability -- the lane   */
#           use_avx2_lane = 1;
#       err = SAVE_VECTOR_REGISTERS2();     /* availability -- the status   */
#       if (err == 0)
#           saved_vector_registers = 1;     /* ONLY "must restore"          */
#       ...
#       if (use_avx2_lane) { if (err == MP_OKAY) ..._avx2(...); }
#       else               { ..._c(...); }  /* only on a non-AVX2 part      */
#
#   sp_ecc_make_key_256() in sp_x86_64.c is the in-tree reference.  Note that
#   saved_vector_registers still appears there -- guarding
#   RESTORE_VECTOR_REGISTERS(), with no else arm -- and is correctly not
#   reported: the rule is about lane SELECTION, not about the flag existing.
SHAPE4='
{ line[NR] = $0 }
END {
    # A variable that receives the save result, and any flag set to 1 under an
    # immediately following test of it.  The lookahead is deliberately tight:
    # a file-wide "if (err == 0)" search would match every unrelated use of a
    # status variable that happens to be named err somewhere else.
    for (n = 1; n <= NR; n++) {
        if (! match(line[n], /[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*SAVE_VECTOR_REGISTERS2\(\)/))
            continue
        s = substr(line[n], RSTART, RLENGTH)
        sub(/[ \t]*=.*/, "", s)
        sub(/^.*[^A-Za-z0-9_]/, "", s)
        savevar[s] = 1
        for (m = n + 1; m <= n + 3 && m <= NR; m++) {
            if (! match(line[m], /if[ \t]*\([ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*==[ \t]*0[ \t]*\)/))
                continue
            t = substr(line[m], RSTART, RLENGTH)
            sub(/^if[ \t]*\([ \t]*/, "", t)
            sub(/[ \t]*==.*/, "", t)
            if (t != s)
                continue
            for (k = m; k <= m + 2 && k <= NR; k++) {
                if (match(line[k], /[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*1[ \t]*;/)) {
                    u = substr(line[k], RSTART, RLENGTH)
                    sub(/[ \t]*=.*/, "", u)
                    sub(/^.*[^A-Za-z0-9_]/, "", u)
                    savevar[u] = 1
                    break
                }
            }
            break
        }
    }
    # Any of those used as an if-condition that has an else arm.  Walk the
    # then-arm to its end -- brace-matched when it is a block, to the first
    # statement end when it is not -- so the else found is this ifs own.
    for (n = 1; n <= NR; n++) {
        if (! match(line[n], /if[ \t]*\([ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\)/))
            continue
        v = substr(line[n], RSTART, RLENGTH)
        sub(/^if[ \t]*\([ \t]*/, "", v)
        sub(/[ \t]*\).*/, "", v)
        if (! (v in savevar))
            continue
        rest = line[n]
        sub(/.*if[ \t]*\([^)]*\)/, "", rest)
        d = gsub(/{/, "{", rest) - gsub(/}/, "}", rest)
        m = n
        if (d > 0) {
            while (m < NR && d != 0) {
                m++
                d += gsub(/{/, "{", line[m]) - gsub(/}/, "}", line[m])
            }
        }
        else {
            while (m < NR && line[m] !~ /;[ \t]*$/)
                m++
        }
        for (k = m; k <= m + 1 && k <= NR; k++) {
            if (line[k] ~ /(^|[^A-Za-z0-9_])else([^A-Za-z0-9_]|$)/) {
                printf "%d:%s   [lane chosen by save-derived %s; other implementation at %d:%s]\n", n, line[n], v, k, line[k]
                break
            }
        }
    }
}'

SHAPES23='
{ line[NR] = $0 }
/(&&|[|][|])[[:space:]]*$/                         { pend = NR }
/SAVE_VECTOR_REGISTERS2\(\)[[:space:]]*[=!]=/ {
    if (pend && NR - pend <= 3) printf "%d:%s\n", NR, $0
}
match($0, /[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*SAVE_VECTOR_REGISTERS2\(\)/) {
    s = substr($0, RSTART, RLENGTH); sub(/[[:space:]]*=.*/, "", s)
    sub(/^.*[^A-Za-z0-9_]/, "", s); var[NR] = s
}
END {
    for (n in var) {
        v = var[n]
        for (i = n + 1; i <= n + 8 && i <= NR; i++) {
            if (line[i] ~ ("(^|[^A-Za-z0-9_])" v "[[:space:]]*=[[:space:]]*0[[:space:]]*;"))
                printf "%d:%s   [status cleared at %d:%s]\n", n, line[n], i, line[i]
        }
    }
}'

found=0
examined=0
carriers=0
ppfail=0
ppfail_first=""
ppfail_msg=""
for f in $SRCS; do
    # Check the preprocessor's exit status.  Discarding it turns "this file
    # could not be read" into an empty $pp, which matches nothing and is
    # indistinguishable from "this file is clean" -- a whole sweep of failures
    # then prints PASS.  A file that was never examined must never read as
    # clean, so failures are counted and reported as INCONCLUSIVE below.
    # ($GATE_CC's status is taken directly, not through a pipe: the greps
    # downstream legitimately return 1 when they match nothing, so `set -e`
    # cannot do this job here.)
    if ! pp=$($GATE_CC -E -fdirectives-only -I. -Iwolfssl $CFLAGS_LINE "$f" 2>&1); then
        ppfail=$((ppfail + 1))
        if [ -z "$ppfail_first" ]; then
            ppfail_first=$f
            ppfail_msg=$(printf '%s\n' "$pp" | grep -m1 'error:')
        fi
        continue
    fi
    examined=$((examined + 1))
    # Does this translation unit contain the construct at all, after the
    # preprocessor has dropped the arms this build does not compile?  Files
    # examined is coverage of FILES; this is coverage of CODE, and only the
    # second one says the gate could have found anything.  A tree configured
    # without SP assembly discards every dispatch site in sp_x86_64.c before
    # this script sees it, and the run then reports a clean sweep of 111
    # sources while the defect sits in the repository.  That is not
    # hypothetical -- it is how the fallback in sp_RsaPublic_*, calc_s_* and
    # sp_ecc_mulmod_base_add_* survived to 13 Aug 2026.
    #
    # Pattern-matched in the shell, NOT piped into `grep -q`.  With
    # `set -o pipefail`, grep -q exits on its first match, the writer takes
    # SIGPIPE, and the pipeline reports 141 -- so a LARGE preprocessed file
    # reads as "no match" while a small one reads as a match.  That is a race,
    # and it silently under-counted exactly the big files this check exists to
    # confirm are in scope.  Caught by listing the carriers and noticing
    # sp_x86_64.c was not among them.
    # INVOCATIONS, not mentions.  -fdirectives-only leaves the #define lines
    # from memory.h/types.h in every translation unit, so a plain search for the
    # name matches 108 of 111 sources and says nothing at all.  Count only
    # SAVE_VECTOR_REGISTERS2() appearing outside a directive line.
    #
    # awk, not `grep -q`: awk reads to EOF.  A short-circuiting reader exits on
    # its first match, the writer takes SIGPIPE, and `set -o pipefail` turns
    # that into a non-zero pipeline -- so the LARGE files read as no-match while
    # small ones matched.  A race, and it hid sp_x86_64.c, which is the one file
    # this check exists to confirm is in scope.
    nsites=$(printf '%s\n' "$pp" | awk \
        '/SAVE_VECTOR_REGISTERS2\(\)/ && $0 !~ /^[ \t]*#/ { c++ } END { print c+0 }')
    if [ "$nsites" -gt 0 ]; then
        carriers=$((carriers + 1))
    fi
    out=$(printf '%s\n' "$pp" | grep -nE "$PATTERN")
    out2=$(printf '%s\n' "$pp" | awk "$SHAPES23")
    out4=$(printf '%s\n' "$pp" | awk "$SHAPE4")
    out=$(printf '%s\n%s\n%s' "$out" "$out2" "$out4" | grep -v '^$')
    if [ -n "$out" ]; then
        n=$(echo "$out" | wc -l)
        echo "  $f: $n live site(s)"
        echo "$out" | head -3 | sed 's/^/      /'
        found=$((found + n))
    fi
done

echo
if [ "$found" -ne 0 ]; then
    cat <<'MSG'
FAIL: a certified FIPS build selects its implementation from whether vector
registers were available.

SPLIT THE CONDITION.  CPU capability chooses the lane; saving the vector
registers is a separate decision, and its failure ends the call:

    if (IS_INTEL_AVX2(cpuid_flags)) {       /* stepping -- retained */
        err = SAVE_VECTOR_REGISTERS2();     /* fallback -- deleted  */
        if (err == 0) {
            ...accelerated...
            RESTORE_VECTOR_REGISTERS();
        }
    }
    else {
        ...C...                             /* only on a part without AVX2 */
    }

Fusing them -- "&& (SAVE_VECTOR_REGISTERS2() == 0)", or its twin
"|| (SAVE_VECTOR_REGISTERS2() != 0)" -- makes a save failure select the C lane
and report success, which is the mechanism being removed.
Where the else is not otherwise guarded, write "else if (err == MP_OKAY)" so a
failed save reaches NEITHER lane.  wc_mldsa.c and wc_mlkem_poly.c already carry
MLDSA_SVR_OR_RETURN() / MLKEM_SVR_OR_RETURN() for this; use them there.

Do NOT answer this by pinning the algorithm to one implementation.  The
per-algorithm pin (--with-fips-<alg>-impl) was REMOVED on 12 August 2026: v7
ships what v5.2.1, v5.2.4 and v6.0.0 shipped, where several lanes are compiled
and CPUID picks one.  Stepping is not the defect; the fallback is.

Do not add an exception here -- an allowlist in this script is precisely where a
real one would be hidden.  See linuxkm/SVR-FALLBACK-ANALYSIS.md 3.0.
MSG
    exit 1
fi

# Coverage is part of the verdict.  Report it before claiming a pass, so a run
# that examined almost nothing cannot be mistaken for a clean sweep.
total=$(printf '%s\n' $SRCS | grep -c .)
if [ "$ppfail" -ne 0 ]; then
    cat <<MSG
INCONCLUSIVE: $ppfail of $total source(s) could not be preprocessed, so they
were never examined.  This is not a pass.

  first failure: $ppfail_first
  $ppfail_msg

A tree configured with --enable-linuxkm cannot be preprocessed by this gate:
AM_CFLAGS then pulls in kernel headers (linux/kconfig.h and friends) that are
not on the host include path.  Run it against a userspace-configured tree,
which is what the CI job does.  The hazard this gate looks for is a kernel
softirq/atomic-context hazard, so the gate being blind on the kernel tree is
exactly the case worth being loud about.
MSG
    exit 2
fi
# A gate that could not have seen the construct did not clear the tree of it.
if [ "$carriers" -eq 0 ]; then
    cat <<MSG
INCONCLUSIVE: $examined of $total sources were examined and NONE of them
compiles a single SAVE_VECTOR_REGISTERS2() call site, so this run could not have
found the construct it hunts.  This is not a pass.

The usual cause is a configuration that compiles no accelerated dispatch --
e.g. no --enable-sp-asm, so wolfcrypt/src/sp_x86_64.c is discarded whole.  Run
this against the PAA line as well:

    ./configure --enable-fips=v7 --enable-aesni-with-avx --enable-sp-asm

A software-only build is a legitimate thing to check, but on its own it is
evidence about a build with nothing to select between, not about the module.
MSG
    exit 2
fi

# =============================================================================
# THE LKCAPI SHIM LAYER, WHICH THE SCAN ABOVE CANNOT REACH
# -----------------------------------------------------------------------------
# SRCS is wolfcrypt/src/*.c.  linuxkm/*.c is not in it and cannot be added: the
# glue includes kernel headers, so this gate cannot preprocess it (see the
# INCONCLUSIVE message above), and on a userspace-configured tree those files
# are not compiled at all.
#
# That blind spot hid a second run-time fallback.  WC_LINUXKM_C_FALLBACK_IN_SHIMS
# keeps a separately-keyed C AES context beside the accelerated one and selects
# it in km_AesGet() (linuxkm/lkcapi_aes_glue.c) when the vector registers are
# unavailable:
#
#     else if (! CAN_SAVE_VECTOR_REGISTERS()) {
#         ret = ctx->aes_decrypt_C;      /* a DIFFERENT implementation */
#     }
#
# Same defect as WC_C_DYNAMIC_FALLBACK, one layer up.  It is held out of
# certified builds by the #error in linuxkm/lkcapi_glue.c, and by the auto-define
# below it requiring WC_ALLOW_RUNTIME_IMPL_SELECT, which no validation-targeted
# build defines.
#
# What is checked here is that BOTH halves of that guard are still present.  This
# is a source-text assertion, not a preprocessed one, and that is the right tool
# for the job: the thing being checked IS a source-level guard.  It proves the
# guard exists, not that a build honours it -- the #error itself does that, and a
# build defining the macro fails to compile.
# =============================================================================
SHIM_GUARD_FILE="linuxkm/lkcapi_glue.c"
shim_guard_fail=0
if [ ! -f "$SHIM_GUARD_FILE" ]; then
    echo "INCONCLUSIVE: $SHIM_GUARD_FILE not found; the shim-fallback guard was not checked."
    exit 2
fi
# Half 1: a certified build must #error on the macro.
if ! grep -q '#error .*WC_LINUXKM_C_FALLBACK_IN_SHIMS' "$SHIM_GUARD_FILE"; then
    echo "FAIL: $SHIM_GUARD_FILE no longer #errors on WC_LINUXKM_C_FALLBACK_IN_SHIMS."
    shim_guard_fail=1
fi
# Half 2: the auto-define must still require WC_ALLOW_RUNTIME_IMPL_SELECT, which
# is what keeps it from firing on a certified configuration by itself.
if ! grep -A6 '^#elif defined(LKCAPI_HAVE_ARCH_ACCEL)' "$SHIM_GUARD_FILE" \
        | grep -q 'defined(WC_ALLOW_RUNTIME_IMPL_SELECT)'; then
    echo "FAIL: the WC_LINUXKM_C_FALLBACK_IN_SHIMS auto-define in $SHIM_GUARD_FILE" \
         "no longer requires WC_ALLOW_RUNTIME_IMPL_SELECT."
    shim_guard_fail=1
fi
if [ "$shim_guard_fail" -ne 0 ]; then
    cat <<'MSG'

WC_LINUXKM_C_FALLBACK_IN_SHIMS selects a second AES implementation at run time
from vector-register availability.  It is permitted only in non-FIPS and
uncertified development builds.  See linuxkm/SVR-FALLBACK-ANALYSIS.md 3.0.
MSG
    exit 1
fi

echo "PASS: no vector-register-conditional implementation selection" \
     "($examined/$total sources examined; $carriers carry compiled" \
     "SAVE_VECTOR_REGISTERS2() call sites; LKCAPI shim-fallback guard intact)."
exit 0
