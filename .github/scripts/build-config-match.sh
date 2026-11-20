#!/bin/bash
# Checks that an application including every public wolfSSL header computes
# the same build configuration fingerprint as the library itself.
#
# The library's fingerprint is computed in build_check.h, which includes
# only some headers. If a header that build_check.h does not (always)
# include derives a fingerprinted macro, an application that includes it
# sees a different fingerprint and wc_CheckBuildConfig() reports a false
# mismatch. This builds and installs the library with the given configure
# arguments, then builds an application that includes options.h, every
# installed header and finally build_check.h, and runs it against the
# installed library. If the configuration builds tests/unit.test, its
# build configuration tests are run as well (examples, and so unit.test,
# are not built in wolfCrypt-only configurations).
#
# Usage: build-config-match.sh WORK_DIR [CONFIGURE_ARGS...]
# Run from the top of a checkout that has been through ./autogen.sh.

set -euo pipefail

work=${1:?usage: $0 WORK_DIR [CONFIGURE_ARGS...]}
shift
mkdir -p "$work"
work=$(cd "$work" && pwd)
prefix=$work/install
jobs=$(nproc 2>/dev/null || echo 4)

./configure --prefix="$prefix" --enable-shared --disable-static "$@"
make -j"$jobs"
make install

if [ -x tests/unit.test ]; then
    ./tests/unit.test --api -test_wc_BuildConfig -test_wc_BuildConfigNames
fi

inc=$prefix/include
app=$work/app.c
{
    echo '#include <wolfssl/options.h>'
    echo '#include <wolfssl/wolfcrypt/settings.h>'
    # Skipped: port headers, which only compile on their platforms, and the
    # math backends, which conflict with each other (wolfmath.h includes
    # the configured one).
    (cd "$inc" && find wolfssl -name '*.h' | LC_ALL=C sort) | \
        grep -v -E '^wolfssl/(options|wolfcrypt/build_check(_list)?)\.h$' | \
        grep -v -E '^wolfssl/wolfcrypt/port/' | \
        grep -v -E '^wolfssl/wolfcrypt/(integer|tfm|sp_int)\.h$' | \
        while read -r h; do
            echo "#include <$h>"
        done
    echo '#include <wolfssl/wolfcrypt/build_check.h>'
    cat <<'EOF'
#include <stdio.h>
#ifndef HAVE_WC_INTROSPECTION
    #error "HAVE_WC_INTROSPECTION is not defined in options.h"
#endif
int main(void)
{
    char desc[2048];
    word32 mismatch = 0;
    int ret = wc_CheckBuildConfigEx(&mismatch, desc, (word32)sizeof(desc));
    if (ret != 0) {
        printf("build config mismatch (%d, 0x%x): %s\n", ret,
               (unsigned)mismatch, desc);
        return 1;
    }
    printf("build config matches\n");
    return 0;
}
EOF
} > "$app"

${CC:-cc} -I"$inc" -o "$work/app" "$app" -L"$prefix/lib" -lwolfssl
LD_LIBRARY_PATH=$prefix/lib "$work/app"
