#!/usr/bin/env bash
#
# check-source-text.sh
#
# Source-hygiene checker for wolfSSL.
# Public subset of the internal wolfssl-multi-test.sh check-source-text scenario.
#
# Subtests (lettered to match the internal multi-test):
#   A. trailing whitespace
#   B. no ending newline
#   C. 8-bit / non-ASCII bytes
#   D. weird control chars, hard tabs, CRs (excluding Makefile-like, .S, .asm)
#   E. C++ '//' comments in C-like files (excluding // NOLINT and // cppcheck)
#   F. flush-left function calls (debug residue) in C-like files
#   G. invalid UTF-8 (requires iconv)
#   H. macros that take args but have an empty definition
#
# Not ported (require pcre2grep against built artifacts or are
# wolfSSL-internal conventions covered elsewhere):
#   I. unescaped error code operands (WC_NO_ERR_TRACE)
#   J. unannotated native heap access
#   K. unknown macros (requires built config.h + .wolfssl_known_macro_extras)
#   L. codespell - run as its own workflow (.github/workflows/codespell.yml)
#
# Usage:
#   .github/scripts/check-source-text.sh           # scan all tracked files
#   .github/scripts/check-source-text.sh <files...> # scan a specific list
#
# Exits 0 if clean, 1 if any check fails.
# When run under GitHub Actions, emits ::error file=...,line=... annotations.

set -u
shopt -s extglob

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT" || exit 2

FAIL=0
GHA="${GITHUB_ACTIONS:-}"

emit() {
    # emit <check> <file> <line> <message>
    local check="$1" file="$2" line="$3" msg="$4"
    if [ -n "$GHA" ]; then
        printf '::error file=%s,line=%s,title=%s::%s\n' "$file" "$line" "$check" "$msg"
    else
        printf '%s:%s: [%s] %s\n' "$file" "$line" "$check" "$msg"
    fi
    FAIL=1
}

# ---- File classification ----------------------------------------------------

is_excluded() {
    case "$1" in
        IDE/*|mcapi/*|mplabx/*|mqx/*|RTOS/*|tirtos/*|zephyr/*|bsdkm/*) return 0 ;;
        debian/*|rpm/*|Docker/*|build-aux/*|autom4te.cache/*) return 0 ;;
        cyassl/*|doc/*) return 0 ;;
        aclocal.m4|config.in|Makefile.in) return 0 ;;
        certs/*|*.der|*.pem|*.crl|*.p12|*.pfx|*.jks) return 0 ;;
        *.gz|*.zip|*.tar|*.bz2|*.xz|*.7z) return 0 ;;
        *.png|*.jpg|*.jpeg|*.gif|*.ico|*.pdf) return 0 ;;
        *.vcproj|*.vcxproj|*.vcxproj.user|*.sln|*.sdf) return 0 ;;
        *.gen.h|*.generated.*) return 0 ;;
        ChangeLog.md) return 0 ;;
        wolfcrypt/src/fp_*.i|wolfcrypt/src/sp_dsp32.c) return 0 ;;
    esac
    return 1
}

# Mirrors multi-test scrubbable_extensions.
is_scrubbable() {
    case "$1" in
        *.c|*.h|*.s|*.S|*.i) return 0 ;;
        *.cc|*.cpp|*.cxx|*.hpp|*.hxx|*.cu) return 0 ;;
        *.asm) return 0 ;;
        *.in|*.ac|*.am|*.m4|*.mk) return 0 ;;
        *.yml|*.sh|*.css|*.js|*.dox|*.tex|*.html|*.md) return 0 ;;
        CMakeLists.txt) return 0 ;;
        scripts/*.test) return 0 ;;
    esac
    return 1
}

# Mirrors multi-test c_like_extensions: *.[chi] + *.cu
is_c_like() {
    case "$1" in
        *.c|*.h|*.i|*.cu) return 0 ;;
    esac
    return 1
}

is_makelike() {
    case "$1" in
        Makefile|Makefile.*|*.am|*.mk) return 0 ;;
    esac
    return 1
}

# ---- Build file list --------------------------------------------------------

if [ "$#" -gt 0 ]; then
    INPUT_FILES=("$@")
else
    mapfile -t INPUT_FILES < <(git ls-files)
fi

SCRUB=()
C_LIKE=()
for f in "${INPUT_FILES[@]}"; do
    [ -f "$f" ] || continue
    is_excluded "$f" && continue
    if is_scrubbable "$f"; then SCRUB+=("$f"); fi
    if is_c_like  "$f"; then C_LIKE+=("$f"); fi
done

have_scrub()  { [ "${#SCRUB[@]}"  -gt 0 ]; }
have_c_like() { [ "${#C_LIKE[@]}" -gt 0 ]; }

# Stream grep output (file:line:rest) and convert to annotated emit() calls.
emit_hits() {
    local check="$1" msg="$2" f row line
    while IFS= read -r row; do
        f="${row%%:*}"
        row="${row#*:}"
        line="${row%%:*}"
        emit "$check" "$f" "$line" "$msg"
    done
}

# ---- Subtests ---------------------------------------------------------------

# A. trailing whitespace
check_trailing_whitespace() {
    have_scrub || return 0
    emit_hits "trailing-whitespace" "trailing whitespace" \
        < <(LC_ALL=C grep -E -n -e $'[ \t]+$' -- "${SCRUB[@]}" 2>/dev/null || true)
}

# B. no ending newline
check_no_ending_newline() {
    have_scrub || return 0
    local f
    for f in "${SCRUB[@]}"; do
        [ -s "$f" ] || continue
        if [ -n "$(tail -c 1 -- "$f")" ]; then
            emit "no-ending-newline" "$f" 1 "missing newline at end of file"
        fi
    done
}

# Per-subtest exclusions mirror the internal multi-test's path filters.

excl_8bit() {
    case "$1" in
        *.md|README*|AUTHORS|*.txt) return 0 ;;
        examples/client/client.c) return 0 ;;
        examples/server/server.c) return 0 ;;
        wolfcrypt/benchmark/benchmark.c) return 0 ;;
        wolfssl/test.h) return 0 ;;
    esac
    return 1
}

excl_control_chars() {
    is_makelike "$1" && return 0
    case "$1" in
        *.S|*.asm) return 0 ;;
        wolfcrypt/src/port/arm/*) return 0 ;;
        wolfcrypt/src/asm.c|wolfcrypt/src/sp_*.c) return 0 ;;
        linuxkm/libwolfssl.mod.c) return 0 ;;
        debian/rules.in) return 0 ;;
        m4/*) return 0 ;;
        */include.am) return 0 ;;
    esac
    return 1
}

excl_cpp_comments() {
    case "$1" in
        wolfcrypt/src/port/arm/*) return 0 ;;
        mcapi/*) return 0 ;;
        */user_settings*.h|user_settings*.h) return 0 ;;
        resource.h) return 0 ;;
        wolfcrypt/src/asm.c|wolfcrypt/src/sp_*.c) return 0 ;;
    esac
    return 1
}

excl_utf8() {
    case "$1" in
        wolfssl.prime) return 0 ;;
        wolfcrypt/src/port/arm/*) return 0 ;;
    esac
    return 1
}

# H is scoped narrowly in multi-test: only wolfssl/, wolfcrypt/src/, src/
# C-like files, and excludes sp_*.c (allows sp_int.c).
in_empty_macro_scope() {
    case "$1" in
        wolfssl/*|wolfcrypt/src/*|src/*) ;;
        *) return 1 ;;
    esac
    case "$1" in
        wolfcrypt/src/sp_int.c) return 0 ;;
        wolfcrypt/src/sp_*.c) return 1 ;;
    esac
    return 0
}

# C. 8-bit / non-ASCII bytes.
check_8bit() {
    local files=() f
    for f in "${SCRUB[@]}"; do
        excl_8bit "$f" && continue
        files+=("$f")
    done
    [ "${#files[@]}" -gt 0 ] || return 0
    emit_hits "non-ascii" "non-ASCII (8-bit) byte" \
        < <(LC_ALL=C grep -E -n -e $'[^\001-\177]' -- "${files[@]}" 2>/dev/null || true)
}

# D. weird control chars / hard tabs / CRs.
check_control_chars() {
    local files=() f
    for f in "${SCRUB[@]}"; do
        excl_control_chars "$f" && continue
        files+=("$f")
    done
    [ "${#files[@]}" -gt 0 ] || return 0
    # \001-\011: SOH..HT (includes \t); \013-\037: VT..US (includes \r); \177: DEL
    # \012 (LF) excluded so newline-terminated lines pass through.
    emit_hits "control-char" "weird control char / hard tab / CR" \
        < <(LC_ALL=C grep -E -n -e $'[\001-\011\013-\037\177]' -- "${files[@]}" 2>/dev/null || true)
}

# E. C++-style // comments in C-like files.
# Allows "// NOLINT" and "// cppcheck" suppressions (no /**/ alternatives).
# Needs GNU grep -P for the negative lookahead.
check_cpp_comments() {
    local files=() f
    for f in "${C_LIKE[@]}"; do
        excl_cpp_comments "$f" && continue
        files+=("$f")
    done
    [ "${#files[@]}" -gt 0 ] || return 0
    emit_hits "cpp-comment" "C++-style // comment" \
        < <(LC_ALL=C grep -P -n \
            -e '(^|[^:"*+a-zA-Z0-9])//(?!([*]| ?NOLINT| ?cppcheck)).*$' \
            -- "${files[@]}" 2>/dev/null || true)
}

# F. flush-left function calls (typically debugging residue).
check_flush_left_calls() {
    have_c_like || return 0
    emit_hits "flush-left-call" "flush-left function call (debug residue?)" \
        < <(LC_ALL=C grep -P -n \
            -e '^(?!(?:wc_)?static_assert[0-9]* *\(|module_init *\(|module_exit *\(|[A-Z][A-Z0-9_]* *\()[a-zA-Z_]+[a-zA-Z0-9_]* *\(.*\);' \
            -- "${C_LIKE[@]}" 2>/dev/null || true)
}

# G. invalid UTF-8 (requires iconv).
check_utf8() {
    if ! command -v iconv >/dev/null 2>&1; then
        echo "check-source-text: [skipping invalid-utf8 - iconv not available]" >&2
        return 0
    fi
    have_scrub || return 0
    local f
    for f in "${SCRUB[@]}"; do
        excl_utf8 "$f" && continue
        if ! LC_ALL=en_US.UTF-8 iconv -f UTF-8 -o /dev/null -- "$f" 2>/dev/null; then
            emit "invalid-utf8" "$f" 1 "file is not valid UTF-8"
        fi
    done
}

# H. macros that take args but have an empty definition.
# Scoped to wolfssl/, wolfcrypt/src/, src/ - excludes sp_*.c except sp_int.c.
check_empty_macros() {
    local files=() f
    for f in "${C_LIKE[@]}"; do
        in_empty_macro_scope "$f" || continue
        files+=("$f")
    done
    [ "${#files[@]}" -gt 0 ] || return 0
    emit_hits "empty-macro" "macro takes args but has empty body" \
        < <(LC_ALL=C grep -E -n \
            -e '#define +[A-Za-z0-9_]+\( *[A-Za-z0-9_]+ *(, *[A-Za-z0-9_]+)* *\) *$' \
            -- "${files[@]}" 2>/dev/null || true)
}

# ---- Run --------------------------------------------------------------------

check_trailing_whitespace
check_no_ending_newline
check_8bit
check_control_chars
check_cpp_comments
check_flush_left_calls
check_utf8
check_empty_macros

if [ "$FAIL" -ne 0 ]; then
    echo "::error::check-source-text found violations" >&2
    exit 1
fi
echo "check-source-text: clean"
