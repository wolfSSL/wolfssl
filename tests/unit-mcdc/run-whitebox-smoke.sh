#!/bin/bash
#
# run-whitebox-smoke.sh [build-dir]
#
# The tests/unit-mcdc/*_whitebox.c translation units each #include one library
# source file and exercise its file-static functions directly -- code the public
# API cannot reach. They are not part of tests/unit.test, so nothing in the
# normal test run builds or executes them, and a change to a library source can
# break one without any test failing.
#
# This runs the subset that builds against a plain --enable-all configuration:
#   * take the compile line the build already used for the included source,
#   * remove that source's object from libwolfssl.a,
#   * compile the white-box TU in its place and link it against the remainder,
#   * run it and require exit 0.
#
# A TU that does not build here needs configuration this one does not provide;
# that is expected and is reported as "skip". To keep a real breakage from
# hiding among those skips, smoke-expected.txt lists the TUs known to build and
# pass under this configuration -- if one of those stops working the script
# fails. Regenerate that list with --update when a TU is added or a build option
# changes, and say so in the commit.
#
# THE LIST IS COMPILER-SPECIFIC. Six TUs build under clang but not gcc, so a
# list generated with one compiler reports false regressions under the other.
# It is generated with gcc, which is what the workflow uses; set CC to match
# before regenerating.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SRC=$(cd "$HERE/../.." && pwd)
BUILD=${1:-$SRC}
EXPECTED="$HERE/smoke-expected.txt"
UPDATE=0
[ "${1:-}" = "--update" ] && { UPDATE=1; BUILD=${2:-$SRC}; }

LIB="$BUILD/src/.libs/libwolfssl.a"
[ -f "$LIB" ] || { echo "no static library at $LIB"; echo "configure with --enable-static"; exit 2; }
CC_=${CC:-cc}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

pass=(); skip=(); fail=(); unsupported=()
for tu in "$HERE"/*_whitebox.c; do
    name=$(basename "$tu" .c)
    inc=$(grep -oE '#include *[<"](wolfcrypt/src|src)/[a-z0-9_]+\.c' "$tu" | head -1 | sed 's/.*[<"]//')
    if [ -z "$inc" ]; then skip+=("$name(no included source)"); continue; fi
    base=$(basename "$inc" .c)
    cp "$LIB" "$work/t.a"
    mem=$(ar t "$work/t.a" | grep -E "_la-${base}\.o$" | head -1)
    [ -n "$mem" ] && ar d "$work/t.a" "$mem" 2>/dev/null
    if ! ( cd "$BUILD" && $CC_ -O0 -g -I"$BUILD" -I"$SRC" -I"$SRC/tests" \
             -DWOLFSSL_TEST_STATIC_BUILD -DHAVE_CONFIG_H \
             -o "$work/$name.bin" "$tu" "$work/t.a" -lm -lpthread ) \
             >"$work/$name.log" 2>&1; then
        skip+=("$name"); continue
    fi
    if ( cd "$BUILD" && "$work/$name.bin" ) >>"$work/$name.log" 2>&1; then
        pass+=("$name")
    elif [ -f "$EXPECTED" ] && grep -qx "$name" "$EXPECTED"; then
        # It passed here before, so this is a regression, not a configuration
        # limit.
        echo "FAIL $name"; tail -5 "$work/$name.log" | sed 's/^/    /'
        fail+=("$name")
    else
        # Builds against this configuration but does not run clean under it.
        # Thesewhite-boxes target a narrower build; not a finding here.
        unsupported+=("$name")
    fi
done

if [ "$UPDATE" = 1 ]; then
    printf '%s\n' "${pass[@]}" | sort > "$EXPECTED"
    echo "wrote $(wc -l < "$EXPECTED") entries to ${EXPECTED#$SRC/}"
    exit 0
fi

echo "white-box smoke: ${#pass[@]} passed, ${#skip[@]} not built here, ${#unsupported[@]} built but need a narrower build, ${#fail[@]} failed"
[ ${#unsupported[@]} -eq 0 ] || printf '  needs a narrower build: %s\n' "${unsupported[*]}"
rc=0
[ ${#fail[@]} -eq 0 ] || rc=1
if [ -f "$EXPECTED" ]; then
    printf '%s\n' "${pass[@]}" | sort > "$work/got.txt"
    missing=$(comm -23 "$EXPECTED" "$work/got.txt")
    if [ -n "$missing" ]; then
        echo "REGRESSION: these built and passed before and do not now:"
        echo "$missing" | sed 's/^/    /'
        rc=1
    fi
    extra=$(comm -13 "$EXPECTED" "$work/got.txt")
    [ -n "$extra" ] && { echo "note: newly passing, run --update to record:";
                         echo "$extra" | sed 's/^/    /'; }
fi
exit $rc
