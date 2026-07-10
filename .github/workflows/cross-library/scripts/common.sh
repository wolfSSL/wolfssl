#!/usr/bin/env bash
#
# Shared helpers for the wolfSSL cross-library compile checks.
#
# Each cross-library script builds a downstream wolfSSL product against a
# locally-built, already-installed wolfSSL and confirms it COMPILES. There is
# no runtime testing here (no `make check`): the goal is only to catch changes
# in wolfSSL that would stop a product from compiling.
#
# Product-script interface (see wolfssh.sh etc.):
#   <product>.sh [-t <ref>] <wolfssl_install_dir> <repo> [product_configure...]
#     -t <ref>   build that git ref (tag or branch)
#     (no -t)    build HEAD of the repo's default branch (master or main,
#                auto-detected, no guessing)

set -euo pipefail

# resolve_repo_url <repo>
# Accept either "owner/repo" shorthand or a full git URL / scp-style remote and
# echo a clonable URL.
resolve_repo_url() {
    local repo="$1"
    case "$repo" in
        *://*|git@*) printf '%s\n' "$repo" ;;
        *)           printf 'https://github.com/%s.git\n' "$repo" ;;
    esac
}

# default_branch <url>
# Echo the remote's default branch (e.g. master or main). Falls back to master.
default_branch() {
    local url="$1" br
    br="$(git ls-remote --symref "$url" HEAD 2>/dev/null \
            | sed -n 's@^ref:[[:space:]]*refs/heads/\([^[:space:]]*\)[[:space:]]*HEAD$@\1@p')"
    printf '%s\n' "${br:-master}"
}

# latest_tag <url>
# Echo the highest version tag on the remote, or nothing if it has no tags.
# Uses git's version sort (--sort=-v:refname), which is robust to a repo mixing
# tag styles (e.g. wolfTPM has both "v4.0.0" and a legacy "v.1.8" that GNU
# `sort -V` mis-orders to the top). sed picks line 1 without cutting git's pipe,
# so `set -o pipefail` stays happy.
latest_tag() {
    local url="$1"
    git ls-remote --tags --refs --sort='-v:refname' "$url" \
        | sed -n '1s@.*refs/tags/@@p'
}

# Globals populated by _prepare, consumed by the build functions below.
CL_INSTALL=""
CL_REPO=""
CL_SRC=""
CL_REF=""
CL_CONFIGURE=()

# _prepare [-t <ref>] <wolfssl_install_dir> <repo> [configure...]
# Parse args, resolve the ref (tag via -t, else default branch), shallow-clone
# the product, and leave CWD inside the cloned tree.
_prepare() {
    local tag="" opt OPTIND=1
    while getopts ":t:" opt; do
        case "$opt" in
            t) tag="$OPTARG" ;;
            *) echo "usage: $0 [-t <ref>] <wolfssl_install_dir> <repo> [configure...]" >&2
               exit 2 ;;
        esac
    done
    shift $((OPTIND - 1))

    CL_INSTALL="$1"; shift
    CL_REPO="$1";    shift
    CL_CONFIGURE=("$@")

    local url
    url="$(resolve_repo_url "$CL_REPO")"
    CL_SRC="$(basename "$CL_REPO" .git)"

    if [ -n "$tag" ]; then
        CL_REF="$tag"
    else
        CL_REF="$(default_branch "$url")"
    fi

    echo "==> Building ${CL_REPO} @ ${CL_REF} against wolfSSL in ${CL_INSTALL}"
    set -x
    git clone --depth 1 --branch "$CL_REF" "$url" "$CL_SRC"
    cd "$CL_SRC"
    set +x
}

# cross_build_autotools [-t <ref>] <wolfssl_install_dir> <repo> [configure...]
# Standard autotools product: configure --with-wolfssl and compile (no check).
cross_build_autotools() {
    _prepare "$@"
    set -x
    if [ -x ./autogen.sh ]; then
        ./autogen.sh
    fi
    # Point the compiler/linker at the installed wolfSSL. --with-wolfssl alone
    # is not enough for every product: some configure link-tests need -L to
    # find -lwolfssl, and some example/app compiles need -I to find headers
    # (e.g. wolfssl/options.h). rpath lets the built binaries run without
    # LD_LIBRARY_PATH, and PKG_CONFIG_PATH covers products that probe pkg-config.
    export PKG_CONFIG_PATH="${CL_INSTALL}/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    ./configure --with-wolfssl="$CL_INSTALL" "${CL_CONFIGURE[@]}" \
        CPPFLAGS="-I${CL_INSTALL}/include" \
        LDFLAGS="-L${CL_INSTALL}/lib -Wl,-rpath,${CL_INSTALL}/lib"
    make "-j$(nproc)"
    set +x
}
