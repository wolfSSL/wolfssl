#
# ci-probe-common.sh
# Shared helpers for CI probes. Source, don't execute:
#   . "$(dirname "$0")/ci-probe-common.sh"
#

# $1=option name being parsed (used only for the error message)
need_arg() {
    { [ $# -ge 2 ] && [ -n "$2" ]; } || {
        echo "$(basename "$0" .sh): $1 needs an argument" >&2
        exit 2
    }
}

# Sets SRCDIR from caller's $0 if --srcdir not provided.
# $1 = caller's $0
infer_srcdir() {
    if [ -z "$SRCDIR" ]; then
        case $1 in */*) ;; *) set -- "./$1" ;; esac
        SRCDIR=$(cd "$(dirname "$1")/../.." 2>/dev/null && pwd) || SRCDIR=.
    fi
}

# Reports captured compile/preprocess exit code and exits on failure.
# Exit 77 (SKIP) if SOFT_COMPILE_FAIL=1, else exit 2 (::error::).
# $1 = exit code, $2 = failure description, $3 = script name.
report_compile_rc() {
    [ "$1" -eq 0 ] && return 0
    if [ "$SOFT_COMPILE_FAIL" = "1" ]; then
        echo "$3: SKIP - $2"
        sed 's/^/  /' "$TMP/err" | head -10
        exit 77
    fi
    echo "::error::$3: $2"
    sed 's/^/  /' "$TMP/err" | head -10
    exit 2
}
