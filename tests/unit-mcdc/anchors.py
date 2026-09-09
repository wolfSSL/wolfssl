#!/usr/bin/env python3
#
# anchors.py - keep the ":<line>" source anchors in tests/unit-mcdc/*.c honest.
#
# The white-box TUs quote lines of the source they #include (":22253" means
# wolfcrypt/src/asn.c:22253) in section headers, prose and WB_NOTE/WB_CHECK
# strings, so a reader can jump from a coverage row to the decision it
# completes. Those numbers are written by hand and every edit to the target
# source silently invalidates them -- asn.c drifted ~1000 lines under this
# suite before anyone noticed.
#
# This pins each anchor to the *text* of the line it points at, in a manifest
# beside the TU (anchors/<tu>.json). After that the numbers are checkable:
#
#   anchors.py check                 # CI / pre-commit: report drift, exit 1
#   anchors.py update                # rewrite the numbers, refresh the manifest
#   anchors.py pin <tu> <line> ...   # (re-)pin anchors whose line was edited
#   anchors.py bootstrap <tu>        # pin every anchor a TU currently uses,
#                                    # trusting today's numbers -- only do this
#                                    # for a TU whose anchors you have checked
#
# A TU with no manifest is skipped, so files can be pinned as they are
# verified rather than all at once. Unpinned anchors are listed by "check"
# under "unpinned" and never fail the run. Note that a number means one
# source line wherever it appears, so "update" rewrites every occurrence of
# it in the TU: while a file is only half pinned, a stale unpinned anchor
# that happens to share a number with a pinned one is carried along with it.
# Bootstrapping a TU once its anchors are known good avoids that.
#
# An anchor is just a source line, not necessarily a decision: sections point
# at loop headers, helper calls and plain statements too. Resolution is by
# line text, with the enclosing function as a tie-breaker, so it survives
# insertions and deletions anywhere else in the file.

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
MANIFEST_DIR = os.path.join(HERE, "anchors")

# ":12345", not the "26" of a UTCTime literal like "260611214429Z" and not
# the "22253" inside a longer number.
ANCHOR_RE = re.compile(r"(?<!\d):(\d{3,6})(?!\d)")
INCLUDE_RE = re.compile(r'#include *[<"]((?:wolfcrypt/src|src)/[a-z0-9_]+\.c)')


def norm(text):
    """Whitespace-insensitive form used to compare source lines."""
    return re.sub(r"\s+", " ", text).strip()


def read_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read().split("\n")


def target_source(tu_path):
    """The source file a white-box TU #includes, or None."""
    for line in read_lines(tu_path):
        match = INCLUDE_RE.search(line)
        if match:
            return match.group(1)
    return None


def anchors_in(tu_path, nsrc):
    """Every anchor a TU uses, as {line: occurrence count}."""
    found = {}
    for line in read_lines(tu_path):
        for match in ANCHOR_RE.finditer(line):
            value = int(match.group(1))
            if 1 <= value <= nsrc:
                found[value] = found.get(value, 0) + 1
    return found


def function_ranges(src_lines):
    """Rough {name: (first, last)} for top-level definitions, 1-based.

    Only used to disambiguate a line text that occurs more than once, so a
    missed function costs a warning, never a wrong answer.
    """
    ranges = {}
    header = re.compile(r"^[A-Za-z_][\w \t\*]*?([A-Za-z_]\w*)\s*\(")
    i = 0
    while i < len(src_lines):
        match = header.match(src_lines[i])
        if match:
            # A prototype ends in ';' before any '{' -- and wolfSSL wraps
            # long ones over several lines, so looking at this line alone
            # would take the two-line prototype for a definition and run the
            # brace match into whatever follows.
            k = i
            body = None
            while k < len(src_lines) and k < i + 12:
                brace = src_lines[k].find("{")
                semi = src_lines[k].find(";")
                if brace >= 0 and (semi < 0 or brace < semi):
                    body = k
                    break
                if semi >= 0:
                    break
                k += 1
            if body is not None:
                depth = 0
                j = body
                while j < len(src_lines) and j < body + 4000:
                    depth += src_lines[j].count("{") - src_lines[j].count("}")
                    if depth <= 0:
                        break
                    j += 1
                ranges.setdefault(match.group(1), (i + 1, j + 1))
                i = j
        i += 1
    return ranges


def manifest_path(tu_path):
    return os.path.join(MANIFEST_DIR,
                        os.path.basename(tu_path)[:-2] + ".json")


def load_manifest(tu_path):
    path = manifest_path(tu_path)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_manifest(tu_path, data):
    os.makedirs(MANIFEST_DIR, exist_ok=True)
    data["anchors"] = dict(sorted(data["anchors"].items(),
                                  key=lambda kv: int(kv[0])))
    with open(manifest_path(tu_path), "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=False)
        handle.write("\n")


def prev_text(src_lines, line_no):
    """The nearest non-blank line above, to tell identical lines apart."""
    i = line_no - 2
    while i >= 0 and not src_lines[i].strip():
        i -= 1
    return norm(src_lines[i]) if i >= 0 else ""


def resolve(pin, src_lines, ranges, recorded_line):
    """Where the pinned text lives now: (line, note) or (None, why)."""
    want = pin["text"]
    hits = [i + 1 for i, line in enumerate(src_lines) if norm(line) == want]
    if not hits:
        return None, "line text no longer present (edited?)"
    if len(hits) == 1:
        return hits[0], ""
    if pin.get("prev"):
        exact = [h for h in hits if prev_text(src_lines, h) == pin["prev"]]
        if len(exact) == 1:
            return exact[0], ""
        if exact:
            hits = exact
    span = ranges.get(pin.get("fn"))
    if span:
        inside = [h for h in hits if span[0] <= h <= span[1]]
        if len(inside) == 1:
            return inside[0], ""
        if inside:
            hits = inside
    nearest = min(hits, key=lambda h: abs(h - recorded_line))
    return nearest, "%d candidates, took the nearest" % len(hits)


def enclosing_fn(line_no, ranges):
    best = None
    for name, (lo, hi) in ranges.items():
        if lo <= line_no <= hi and (best is None or
                                    (hi - lo) < (best[1] - best[0])):
            best, best_name = (lo, hi), name
    return best_name if best else None


def tu_list(args):
    if args:
        return [a if os.path.isabs(a) else os.path.join(ROOT, a) for a in args]
    return sorted(os.path.join(HERE, f) for f in os.listdir(HERE)
                  if f.endswith(".c"))


def cmd_check(args, fix=False):
    rc = 0
    for tu in tu_list(args):
        data = load_manifest(tu)
        if data is None:
            continue
        src_path = os.path.join(ROOT, data["source"])
        src_lines = read_lines(src_path)
        ranges = function_ranges(src_lines)
        used = anchors_in(tu, len(src_lines))
        moved, broken = {}, []
        for key, pin in data["anchors"].items():
            old = int(key)
            new, note = resolve(pin, src_lines, ranges, old)
            if new is None:
                broken.append((old, pin, note))
                continue
            if new != old:
                moved[old] = (new, note)
        unpinned = sorted(a for a in used
                          if str(a) not in data["anchors"])
        name = os.path.relpath(tu, ROOT)
        if moved or broken:
            rc = 1
            print("%s (%s)" % (name, data["source"]))
            for old in sorted(moved):
                new, note = moved[old]
                print("  :%d -> :%d  (%d use%s)%s" %
                      (old, new, used.get(old, 0),
                       "" if used.get(old, 0) == 1 else "s",
                       "  " + note if note else ""))
            for old, pin, note in broken:
                print("  :%d  STALE - %s" % (old, note))
                print("      was: %s" % pin["text"][:72])
        if fix and moved:
            apply_moves(tu, data, moved, src_lines, ranges)
            print("  updated %s" % name)
        if unpinned:
            print("%s: %d unpinned anchor%s (%s%s)" %
                  (name, len(unpinned), "" if len(unpinned) == 1 else "s",
                   ", ".join(":%d" % a for a in unpinned[:8]),
                   ", ..." if len(unpinned) > 8 else ""))
    return rc


def apply_moves(tu, data, moved, src_lines, ranges):
    text = "\n".join(read_lines(tu))
    text = ANCHOR_RE.sub(
        lambda m: ":%d" % moved.get(int(m.group(1)), (int(m.group(1)),))[0]
        if int(m.group(1)) in moved else m.group(0), text)
    with open(tu, "w", encoding="utf-8") as handle:
        handle.write(text)
    rebuilt = {}
    for key, pin in data["anchors"].items():
        line_no = moved.get(int(key), (int(key),))[0]
        pin["fn"] = enclosing_fn(line_no, ranges) or pin.get("fn")
        pin["prev"] = prev_text(src_lines, line_no)
        rebuilt[str(line_no)] = pin
    data["anchors"] = rebuilt
    save_manifest(tu, data)


def cmd_bootstrap(args):
    if not args:
        print("bootstrap needs at least one TU", file=sys.stderr)
        return 2
    for tu in tu_list(args):
        src_rel = target_source(tu)
        if src_rel is None:
            print("%s: no included source, skipped" %
                  os.path.relpath(tu, ROOT))
            continue
        src_lines = read_lines(os.path.join(ROOT, src_rel))
        ranges = function_ranges(src_lines)
        data = load_manifest(tu) or {"source": src_rel, "anchors": {}}
        added = 0
        for line_no in sorted(anchors_in(tu, len(src_lines))):
            if str(line_no) in data["anchors"]:
                continue
            data["anchors"][str(line_no)] = {
                "fn": enclosing_fn(line_no, ranges),
                "text": norm(src_lines[line_no - 1]),
                "prev": prev_text(src_lines, line_no),
            }
            added += 1
        save_manifest(tu, data)
        print("%s: pinned %d anchor%s (%d total)" %
              (os.path.relpath(tu, ROOT), added, "" if added == 1 else "s",
               len(data["anchors"])))
    return 0


def cmd_pin(args):
    if len(args) < 2:
        print("pin needs a TU and one or more line numbers", file=sys.stderr)
        return 2
    tu = args[0] if os.path.isabs(args[0]) else os.path.join(ROOT, args[0])
    src_rel = target_source(tu)
    src_lines = read_lines(os.path.join(ROOT, src_rel))
    ranges = function_ranges(src_lines)
    data = load_manifest(tu) or {"source": src_rel, "anchors": {}}
    for raw in args[1:]:
        line_no = int(raw.lstrip(":"))
        data["anchors"][str(line_no)] = {
            "fn": enclosing_fn(line_no, ranges),
            "text": norm(src_lines[line_no - 1]),
            "prev": prev_text(src_lines, line_no),
        }
        print(":%d -> %s" % (line_no, norm(src_lines[line_no - 1])[:70]))
    save_manifest(tu, data)
    return 0


USAGE = """usage: anchors.py <command> [tu...]

  check              report anchors whose target line moved (exit 1 if any)
  update             same, but rewrite the TUs and manifests in place
  bootstrap <tu>     pin every anchor a TU uses against today's source
  pin <tu> <line>... (re-)pin single anchors, e.g. after editing that line

With no TU argument, check/update cover every TU that has a manifest."""


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(USAGE)
        return 0
    cmd, rest = argv[1], argv[2:]
    if cmd == "check":
        return cmd_check(rest, fix=False)
    if cmd == "update":
        return cmd_check(rest, fix=True)
    if cmd == "bootstrap":
        return cmd_bootstrap(rest)
    if cmd == "pin":
        return cmd_pin(rest)
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
