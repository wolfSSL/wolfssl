#!/bin/bash
#
# run-test.sh -- reproduce the kernel-side test setup for these patches.
#
#   ./run-test.sh                 # 5.15.170, 6.16.12, 7.1.9
#   ./run-test.sh 6.16.12         # just one
#   ./run-test.sh --list
#
# For each version: check the toolchain, fetch the tarball, apply the patch the
# coverage table in README.md says serves it, build the kernel far enough to get
# Module.symvers, confirm the hook symbol is EXPORTED, then build the wolfSSL
# module against it and confirm the RBGC symbols are in the .ko.
#
# Work lands in ./work/ beside this script; set WORK= to move it.  Each kernel
# tree is roughly 2G, and anything running "git clean -xdff" over this checkout
# will delete the default location mid-build.
#
# Env: WORK, WOLFSSL_SRC, FIPS_FLAVOR (e.g. FIPS_FLAVOR=v7).
set -u -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HERE/work}"
WOLFSSL_SRC="${WOLFSSL_SRC:-$(cd "$HERE/../.." && pwd)}"

# version : gcc : patch base : kernel.org path
KNOWN="
5.15.170:gcc-10:5.17-ubuntu-jammy-tegra:v5.x
6.16.12:gcc:6.16:v6.x
7.1.9:gcc:7.0:v7.x
"

say()   { printf '%s\n' "$*"; }
head_() { printf '\n=== %s\n' "$*"; }
die()   { printf 'run-test: %s\n' "$*" >&2; exit 1; }

if [ "${1:-}" = "--list" ]; then
    printf '%-10s %-8s %s\n' version gcc base
    echo "$KNOWN" | while IFS=: read -r v g b u; do
        [ -n "${v:-}" ] && printf '%-10s %-8s %s\n' "$v" "$g" "$b"
    done
    exit 0
fi

WANT=("$@"); [ ${#WANT[@]} -eq 0 ] && WANT=(5.15.170 6.16.12 7.1.9)

missing=""
for t in curl tar make patch nm bc flex bison; do
    command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
for v in "${WANT[@]}"; do
    line=$(echo "$KNOWN" | grep "^$v:") || die "unknown version $v (try --list)"
    g=$(echo "$line" | cut -d: -f2)
    command -v "$g" >/dev/null 2>&1 || missing="$missing $g"
done
[ -f "$WOLFSSL_SRC/configure.ac" ] || die "no wolfSSL source at $WOLFSSL_SRC (set WOLFSSL_SRC)"
[ -x "$HERE/patch-kernel.sh" ]     || die "patch-kernel.sh missing beside this script"

if [ -n "$missing" ]; then
    say "run-test: missing:$missing"
    say ""
    say "  sudo apt install build-essential curl bc flex bison libelf-dev libssl-dev"
    say ""
    say "Older trees need an older compiler; 5.15 is built here with gcc-10:"
    say "  sudo apt install gcc-10"
    exit 1
fi

mkdir -p "$WORK/tarballs" "$WORK/shim"
rc_all=0

for v in "${WANT[@]}"; do
    line=$(echo "$KNOWN" | grep "^$v:")
    GCC=$(echo  "$line" | cut -d: -f2)
    BASE=$(echo "$line" | cut -d: -f3)
    URLD=$(echo "$line" | cut -d: -f4)
    DIR="$WORK/linux-$v"
    TB="$WORK/tarballs/linux-$v.tar.xz"
    LOG="$WORK/linux-$v.log"

    head_ "$v  (gcc $GCC, base $BASE)"

    # tools/objtool resolves its own compiler, so CC= and HOSTCC= do not reach
    # it.  A PATH shim is what actually pins the version.
    ln -sf "$(command -v "$GCC")" "$WORK/shim/gcc"
    ln -sf "$(command -v "$GCC")" "$WORK/shim/cc"
    export PATH="$WORK/shim:$PATH"

    if [ ! -s "$TB" ]; then
        say "  downloading"
        curl -fL --retry 3 --no-progress-meter -o "$TB.part" \
            "https://cdn.kernel.org/pub/linux/kernel/$URLD/linux-$v.tar.xz" \
            || { say "  FAIL download"; rm -f "$TB.part"; rc_all=1; continue; }
        mv "$TB.part" "$TB"
    fi
    [ -d "$DIR" ] || { say "  extracting"
        tar -C "$WORK" -xf "$TB" || { say "  FAIL extract"; rc_all=1; continue; }; }

    # The base is forced.  patch-kernel.sh takes the first coverage row for a
    # series, which for 5.15.170 is the 5.15 base, whose hunks fail at --fuzz=0;
    # README.md's sublevel table puts that version on the tegra base.
    if grep -qs wolfssl_linuxkm_register_random_bytes_handlers "$DIR/include/linux/random.h"; then
        say "  already patched"
    else
        say "  applying $BASE"
        "$HERE/patch-kernel.sh" "$DIR" "$BASE" >"$LOG" 2>&1 \
            || { say "  FAIL patch -- see $LOG"; rc_all=1; continue; }
    fi

    # A full build, not modules_prepare: modules_prepare leaves no
    # Module.symvers, and without that modpost calls the hook symbol undefined,
    # which looks exactly like the patch not having worked.
    if [ ! -f "$DIR/Module.symvers" ]; then
        say "  building kernel with $GCC (several minutes)"
        { make -C "$DIR" -j"$(nproc)" defconfig
          make -C "$DIR" -j"$(nproc)"
        } >>"$LOG" 2>&1 || { say "  FAIL kernel build -- see $LOG"; rc_all=1; continue; }
    fi
    grep -qs wolfssl_linuxkm_register_random_bytes_handlers "$DIR/Module.symvers" \
        || { say "  FAIL hook not exported in Module.symvers"; rc_all=1; continue; }
    say "  kernel ok, hook exported"

    # CONFIG_X86_KERNEL_IBT (defconfig, 6.2+) makes Kbuild run objtool over the
    # linked libwolfssl.o, which OBJECT_FILES_NON_STANDARD does not cover, and
    # it rejects the return thunks Kbuild inlines on purpose.
    OBJTOOL_OFF=
    if grep -qs "^CONFIG_X86_KERNEL_IBT=y" "$DIR/.config"; then
        OBJTOOL_OFF=KBUILD_EXTRA_FLAGS=FORCE_GLOBAL_OBJTOOL_OFF=1
        say "  IBT on -- adding FORCE_GLOBAL_OBJTOOL_OFF=1"
    fi

    say "  building wolfSSL module"
    MLOG="$WORK/linux-$v.module.log"
    ( cd "$WOLFSSL_SRC" \
      && ./configure --enable-linuxkm --enable-linuxkm-pie --disable-sp-asm \
            --enable-linuxkm-rbgc "--with-linux-source=$DIR" \
            ${FIPS_FLAVOR:+--enable-fips=$FIPS_FLAVOR} \
      && env KERNEL_EXTRA_CFLAGS_REMOVE=-pg FORCE_NO_MODULE_SIG=1 $OBJTOOL_OFF \
            make -j"$(nproc)" ) >"$MLOG" 2>&1 \
        || { say "  FAIL module build -- see $MLOG"; rc_all=1; continue; }

    # The RBGC sources are gated, so a build that compiled none of them still
    # links clean.  Count the symbols rather than trusting the exit status.
    n=$(nm "$WOLFSSL_SRC/linuxkm/libwolfssl.ko" 2>/dev/null | grep -c ' [tT] wc_grb_')
    [ "${n:-0}" -ge 1 ] \
        || { say "  FAIL module built with 0 wc_grb_ symbols"; rc_all=1; continue; }
    say "  PASS  $n wc_grb_ symbols"
done

exit $rc_all
