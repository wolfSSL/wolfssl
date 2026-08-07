#!/usr/bin/env bash
#
# set-user-setting.sh
#
# Set WC_CFG_* switches in a copy of a user_settings.h template, for CI configs
# that build the same template in more than one profile.
#
# Usage:
#   set-user-setting.sh <user_settings.h> NAME=VALUE [NAME=VALUE ...]
#
# Why this exists rather than a sed in the JSON: a `sed -i` matching the whole
# line, interior alignment included, silently does nothing if the template is
# ever re-aligned, and the config then quietly tests the default profile
# instead of the one it names. This matches on the switch name alone and fails
# if a switch is missing, so a rename or a typo is a build failure rather than
# a test that stopped testing anything.

set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <user_settings.h> NAME=VALUE [NAME=VALUE ...]" >&2
    exit 2
fi

file=$1
shift

[ -f "$file" ] || { echo "$0: no such file: $file" >&2; exit 1; }

for pair in "$@"; do
    case $pair in
        *=*) ;;
        *) echo "$0: expected NAME=VALUE, got '$pair'" >&2; exit 2 ;;
    esac
    name=${pair%%=*}
    value=${pair#*=}

    # The switch must exist, and exactly once, or the caller's intent is
    # already wrong.
    count=$(grep -c "^#define ${name}[[:space:]]" "$file" || true)
    if [ "$count" != "1" ]; then
        echo "$0: '${name}' appears ${count} time(s) in ${file}, expected 1" >&2
        exit 1
    fi

    # Rewrite just the value field, keeping the column the template aligns to
    # and any trailing comment on the line.
    awk -v n="$name" -v v="$value" '
        $0 ~ "^#define " n "[[:space:]]" {
            # prefix = "#define NAME" plus the alignment whitespace
            match($0, "^#define[ \t]+" n "[ \t]+")
            prefix = substr($0, 1, RLENGTH)
            rest = substr($0, RLENGTH + 1)
            # drop the old value token, keep whatever follows it
            sub("^[^ \t]+", "", rest)
            print prefix v rest
            next
        }
        { print }
    ' "$file" > "$file.tmp"
    mv "$file.tmp" "$file"

    # Confirm it took.
    if ! grep -q "^#define ${name}[[:space:]]\+${value}\([[:space:]]\|$\)" \
            "$file"; then
        echo "$0: failed to set ${name} to ${value} in ${file}" >&2
        exit 1
    fi
done
