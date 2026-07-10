#!/usr/bin/env bash
#
# Decide whether an intentional wolfSSL break of a downstream product has been
# DECLARED in a commit message, so the cross-library job can tell an accountable
# break from an accidental one.
#
# ONLY a break of a product's latest RELEASE TAG can be declared, i.e. a
# released, immutable version that wolfSSL is intentionally dropping
# compatibility with. The declaring commit names that exact tag:
#
#     breaks-<product>=<tag>      e.g.  breaks-wolfssh=v1.5.0-stable
#
# There is deliberately no shorthand (no latest/head/*), and there is NO way to
# declare a break of a product's master/HEAD: if wolfSSL master breaks a
# product's master, the PR must be reworked or the product's master fixed, and
# it is never waived. (The engine only consults this script for the latest-tag leg.)
#
# The scan window is "the release tag BEFORE the last one .. HEAD", i.e. the
# last TWO wolfSSL release cycles. Two (not one) so that when wolfSSL cuts a new
# release, a break declared in the prior cycle keeps being recognized for one
# more cycle, giving the downstream product time to ship a fixed release before
# PRs go red again for the known issue. Matching is case-insensitive.
#
# Exit 0 (prints the declaring commits) if the (product, ref) break is declared;
# exit 1 otherwise. Requires full history + tags in the checkout
# (actions/checkout fetch-depth: 0, fetch-tags: true).
#
# Usage: check-break.sh <product> <ref>

set -uo pipefail

product="$1"
ref="$2"

lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
ref_lc="$(lc "$ref")"

# Fail LOUD, never fail open. This is a gate: if git cannot read the repository
# (e.g. a container-job "dubious ownership" refusal, or a shallow/absent
# checkout), every git call below returns nothing and the scan would silently
# report "no break declared", turning an environment failure into a wrong
# compatibility verdict. Refuse to run rather than answer from a broken repo.
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "check-break: ERROR: cannot read git history at '$(pwd)':" >&2
    git rev-parse --is-inside-work-tree 1>&2 || true   # re-run to surface git's own message
    echo "check-break: not a usable git checkout (dubious ownership in a container job, or missing history/tags)." >&2
    exit 2
fi

# Window: the release tag BEFORE the last one .. HEAD (last two release cycles,
# for the one-release grace period described above). We pick release tags by
# version order, not commit ancestry: wolfSSL carries many non-release tags
# (e.g. *-CHKIN, wolfEntropy*) that `git describe` would otherwise land on.
# RELEASE_GLOB matches wolfSSL's release tags (vX.Y.Z-stable).
RELEASE_GLOB='v*-stable'
rel="$(git tag --merged HEAD --sort=-v:refname --list "$RELEASE_GLOB" 2>/dev/null)"
# Line 2 = the release before the newest (our scan base). Fall back to the
# newest (line 1) if only one exists, or full history if there are no release
# tags (e.g. an unexpectedly shallow clone).
base="$(printf '%s\n' "$rel" | sed -n '2p')"
[ -n "$base" ] || base="$(printf '%s\n' "$rel" | sed -n '1p')"
range="HEAD"
[ -n "$base" ] && range="${base}..HEAD"

# Diagnostics (to stderr, so they always show in the CI log). This is what makes
# a "no break is declared" failure debuggable: it prints the scan window and the
# actual commit messages/tokens check-break.sh is looking at. git stderr is NOT
# suppressed here (unlike the scan below) so a real git failure, e.g. "dubious
# ownership" of the workspace in a container job, surfaces instead of silently
# looking like "no token found".
{
    echo "check-break: product='${product}' ref='${ref}'"
    echo "check-break: release tags merged into HEAD (newest first):"
    printf '%s\n' "$rel" | sed 's/^/    /'
    echo "check-break: scan base='${base:-<root>}' range='${range}'"
    echo "check-break: commit messages in range (hash subject):"
    git log "$range" --no-merges --format='    %h %s' 2>&1 | sed -n '1,300p'
    echo "check-break: breaks-${product}= tokens found in range:"
    git log "$range" --no-merges --format='%B' 2>&1 \
        | grep -ioaE "breaks-${product}=[^[:space:]]+" | sed 's/^/    /' \
        || echo "    (none)"
} >&2

declared=0
while IFS= read -r val; do
    [ -z "$val" ] && continue
    v="$(lc "$val")"
    # A break target may ONLY be an exact release tag. Branch names and
    # wildcards (head, master, main, latest, all, *) are never valid break
    # targets and are ignored outright, so master/HEAD breaks are not waivable.
    case "$v" in
        head|master|main|latest|all|*'*'*) continue ;;
    esac
    [ "$v" = "$ref_lc" ] && declared=1
done < <(git log "$range" --no-merges --format='%B' 2>/dev/null \
            | grep -ioaE "breaks-${product}=[^[:space:]]+" \
            | sed 's/^[^=]*=//')

if [ "$declared" -eq 1 ]; then
    echo "Declared break: '${product}' at '${ref}' is covered by a breaks-${product}= token (since ${base:-<root>}):"
    git log "$range" --no-merges -i --grep="breaks-${product}=" \
        --format='  %h %s (%an)' 2>/dev/null || true
    exit 0
fi
exit 1
