#!/usr/bin/env python3
"""wolfssl-compliance-tooling SBOM driver - the product-neutral SBOM engine.

This is the generalized form of wolfBoot's tools/scripts/wolfboot-sbom.sh. It is
product-neutral: the name, version, root, generator, and license are all
arguments. Nothing product-specific is hard-coded. Any product front end
(autotools, CMake, plain Make, IAR, or a compilation database) produces the
inputs and hands them to this driver.

The driver covers every product tier:

  * Library (tier R/L/S): hash the built library with --lib.
  * Source-embedded (tier E, e.g. wolfBoot): hash a source set with --srcs-file.
  * As-built / FIPS / kernel module: --lib with --no-artifact-hash on the
    as-built artifact. Never substitute a source list for a certified artifact.
  * Linker / binding: record a declared dependency with --dep-wolfssl and
    friends (feature-detected against the generator).

Config (choose one):
  --cflags "..."     Raw CFLAGS. -D tokens are expanded through the host
                     compiler and scrubbed of absolute paths. Pair with
                     --settings-h so the capture also sees the header those
                     -D tokens are interpreted by; without it the dump is the
                     -D list alone and every derived macro is missing.
  --options-h PATH   A pre-expanded flat #define header, used verbatim (scrubbed).
  --user-settings P  A user_settings.h. Passed to the generator, which captures it.
  --source-only      No build-config macros (e.g. a Kconfig-driven build).

The macro capture runs the HOST compiler (never the cross compiler), so the SBOM
is byte-reproducible across toolchains: gcc, clang, IAR, armcl, ccrx, and xc32
all converge to the same document for the same config.

Reproducibility: captured macros are scrubbed of absolute host paths before they
reach gen-sbom (for example -DPICO_SDK_PATH=/home/you/pico-sdk from arch.mk). Use
--no-scrub to disable (debug only).
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_ABS_PATH_POSIX = re.compile(r'^/[^ ]+')
_ABS_PATH_WINDOWS_DRIVE = re.compile(r'^[A-Za-z]:[\\/]')
_ABS_PATH_WINDOWS_UNC = re.compile(r'^\\\\')
_DEFINE = re.compile(r'^#define\s+(\S+)\s*(.*)$')


def is_absolute_path_token(token):
    """Return True when a macro token looks like an absolute host path."""
    return bool(
        _ABS_PATH_POSIX.match(token) or
        _ABS_PATH_WINDOWS_DRIVE.match(token) or
        _ABS_PATH_WINDOWS_UNC.match(token)
    )


def scrub_defines(text):
    """Redact absolute-path tokens from a flat #define header text.

    A macro value that is (or contains) an absolute path would otherwise make
    the SBOM machine-specific and leak the local file system. The macro name is
    kept, so the configuration record stays complete.
    """
    out = []
    for line in text.splitlines():
        m = _DEFINE.match(line)
        if not m:
            out.append(line)
            continue
        name, val = m.group(1), m.group(2)
        if val == "":
            out.append(line)
            continue
        toks = []
        for t in val.split(" "):
            core = t.replace('"', '')
            toks.append("<redacted-path>" if is_absolute_path_token(core) else t)
        out.append("#define " + name + " " + " ".join(toks))
    return "\n".join(out) + "\n"


def read_version(version_file, version_macro):
    """Read a version string from a header, e.g. LIBWOLFBOOT_VERSION_STRING."""
    # An empty macro would make re.escape('') a zero-width prefix, so the pattern
    # degrades to the first quoted string in the header (a copyright year, an
    # unrelated define) -- return "" rather than a silently wrong version.
    if not version_macro:
        return ""
    if not version_file or not os.path.isfile(version_file):
        return ""
    pat = re.compile(re.escape(version_macro) + r'\s*"([^"]*)"')
    with open(version_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pat.search(line)
            if m:
                return m.group(1)
    return ""


def find_gen_sbom(explicit):
    """Locate gen-sbom: explicit arg, a sibling vendored copy, then WOLFSSL_DIR."""
    if explicit:
        return explicit
    sibling = os.path.join(SCRIPT_DIR, "gen-sbom")
    if os.path.isfile(sibling):
        return sibling
    wolfssl_dir = os.environ.get("WOLFSSL_DIR")
    if wolfssl_dir:
        cand = os.path.join(wolfssl_dir, "scripts", "gen-sbom")
        if os.path.isfile(cand):
            return cand
    return sibling  # report the sibling path in the error message


def gen_sbom_supports(python, gen_sbom, flag):
    """Return True if the generator advertises a flag in its --help."""
    try:
        res = subprocess.run([python, gen_sbom, "--help"],
                             capture_output=True, text=True, check=False)
    except OSError:
        return False
    return flag in (res.stdout + res.stderr)


def split_cflags(cflags):
    """Split a CFLAGS string on whitespace.

    Deliberately a plain split rather than shlex: --cflags arrives from a Make
    recipe, so the shell has already removed one layer of quoting. Re-lexing it
    as shell words would strip a second layer, and shlex's POSIX escape
    handling would eat the backslashes out of Windows paths --
    -DPICO_SDK_PATH=C:\\Users\\ci\\sdk becomes C:Userscisdk, which is both
    wrong and no longer matched by the absolute-path scrub, so a mangled host
    path would leak into the SBOM.
    """
    return cflags.split()


def capture_macros(hostcc, cflags, settings_h="", include_dirs=()):
    """Expand a build configuration through the host compiler's -dM -E.

    The capture must see BOTH inputs that determine the configuration:

      * the ``-D`` tokens from CFLAGS, which select features
        (``-DWOLFBOOT_SIGN_ECC256``), and
      * the settings header those tokens are interpreted by, reached via
        ``-include``.

    Feeding only one of them yields a confident, well-formed, wrong document.
    With no ``-include``, the compiler reads an empty translation unit and the
    dump is just the ``-D`` list plus compiler built-ins, so every macro the
    settings header derives is missing. With no ``-D`` tokens, every ``#if``
    in that header is evaluated against an empty configuration and the dump
    describes a product nobody built -- wolfBoot's user_settings.h gates
    HAVE_ECC on WOLFBOOT_SIGN_ECC256, so a capture missing the latter silently
    reports a secure bootloader with no signature algorithm.

    ``-I`` and ``-isystem`` from CFLAGS are forwarded so the ``-include``
    header can resolve the product headers it pulls in (user_settings.h,
    target.h). Every other flag is dropped: they describe code generation,
    not configuration, and cross-toolchain flags would break the host cc.
    """
    toks = split_cflags(cflags)
    defs, incs = [], []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.startswith("-D"):
            defs.append(t)
        elif t in ("-I", "-isystem", "-include") and i + 1 < len(toks):
            # Separated form: keep -I/-isystem, but never a second -include
            # (the settings header below is the only one we want).
            if t != "-include":
                incs += [t, toks[i + 1]]
            i += 1
        elif t.startswith("-I"):
            incs.append(t)
        i += 1

    for d in include_dirs:
        incs += ["-I", d]

    cmd = [hostcc, "-dM", "-E", "-DWOLFSSL_USER_SETTINGS", *incs, *defs]
    if settings_h:
        cmd += ["-include", settings_h]
    cmd += ["-x", "c", os.devnull]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except OSError:
        sys.exit(f"ERROR: '{hostcc} -dM -E' failed; install a host C compiler "
                 f"or set --hostcc.")
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or "").strip()
        hint = ""
        if settings_h:
            hint = (f"\n       The capture includes '{settings_h}'. Check that "
                    f"--include-dir covers the headers it pulls in.")
        sys.exit(f"ERROR: '{hostcc} -dM -E' failed while capturing the build "
                 f"configuration.{hint}\n{detail}")
    return res.stdout


def load_srcs(srcs_file, skip_missing):
    """Read the source list; optionally drop paths that do not exist."""
    kept, dropped = [], 0
    with open(srcs_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if skip_missing and not os.path.isfile(s):
                print(f"WARNING: skipping missing source: {s}", file=sys.stderr)
                dropped += 1
                continue
            kept.append(s)
    if not kept:
        sys.exit("ERROR: no source files remain for the SBOM.")
    if dropped:
        print(f"  (--skip-missing dropped {dropped} file(s))", file=sys.stderr)
    return kept


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    # Composition (at least one of --lib / --srcs-file; --source-only needs srcs).
    ap.add_argument("--lib", default="",
                    help="Path to the built library to hash (tier R/L/S).")
    ap.add_argument("--srcs-file", default="",
                    help="File listing compiled-in sources (tier E).")
    ap.add_argument("--no-artifact-hash", action="store_true",
                    help="Do not recompute the artifact hash. For as-built FIPS "
                         "or kernel modules.")

    # Config (choose one).
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--cflags", default="",
                     help="Build CFLAGS; -D tokens expanded through the host cc.")
    ap.add_argument("--settings-h", default="",
                    help="Settings header -include'd during the --cflags "
                         "capture, so macros the header derives from the -D "
                         "set are recorded. Required for any product whose "
                         "configuration lives in a user_settings.h.")
    ap.add_argument("--include-dir", action="append", default=[],
                    metavar="DIR",
                    help="Extra -I path for the --cflags capture (repeatable). "
                         "-I/-isystem already present in CFLAGS are forwarded "
                         "automatically.")
    grp.add_argument("--options-h", default="",
                     help="A pre-expanded flat #define header, used verbatim.")
    grp.add_argument("--user-settings", default="",
                     help="A user_settings.h; passed to the generator.")
    grp.add_argument("--source-only", action="store_true",
                     help="Source-inventory SBOM with no build-config macros.")

    # Identity.
    ap.add_argument("--name", required=True, help="Package name in the SBOM.")
    ap.add_argument("--version", default="")
    ap.add_argument("--version-file", default="")
    ap.add_argument("--version-macro", default="")
    ap.add_argument("--supplier", default="wolfSSL Inc.")
    ap.add_argument("--component-type", default="",
                    help="CycloneDX component.type, mirrored to SPDX "
                         "primaryPackagePurpose. Use firmware for a "
                         "bootloader. Passed through only if the generator "
                         "supports it.")
    ap.add_argument("--license-file", default="")
    ap.add_argument("--license-override", default="")
    ap.add_argument("--license-text", default="")
    ap.add_argument("--document-namespace", default="",
                    help="SPDX documentNamespace override.")

    # Dependencies (feature-detected against the generator).
    ap.add_argument("--dep-wolfssl", default="")
    ap.add_argument("--dep-wolfcrypt", default="")
    ap.add_argument("--dep-openssl", default="")
    ap.add_argument("--dep-libz", default="",
                    help="yes|no. Record zlib. Pass the product's real "
                         "build option; gen-sbom defaults to no.")
    ap.add_argument("--dep-version", action="append", default=[],
                    help="Dependency version, e.g. wolfssl=5.9.2 (repeatable).")
    ap.add_argument("--crypto-only", default="",
                    help="auto|yes|no. Whether only the wolfCrypt subset of "
                         "the wolfSSL release is compiled in. The generator "
                         "defaults to auto, reading WOLFCRYPT_ONLY out of the "
                         "captured configuration; state it explicitly when "
                         "the front end captures no macros (--source-only).")

    # Outputs and environment.
    ap.add_argument("--cdx-out", default="")
    ap.add_argument("--spdx-out", default="")
    ap.add_argument("--gen-sbom", default="")
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--hostcc", default=os.environ.get("HOSTCC", "cc"))
    ap.add_argument("--root", default="")
    ap.add_argument("--skip-missing", action="store_true")
    ap.add_argument("--no-scrub", action="store_true")
    args = ap.parse_args()

    root = os.path.abspath(args.root) if args.root else os.getcwd()
    license_file = args.license_file or os.path.join(root, "LICENSE")

    version = args.version or read_version(args.version_file, args.version_macro)
    if not version:
        sys.exit("ERROR: could not determine version; pass --version or "
                 "--version-file with --version-macro.")

    if not args.lib and not args.srcs_file:
        sys.exit("ERROR: pass at least one of --lib or --srcs-file.")
    if args.source_only and not args.srcs_file:
        sys.exit("ERROR: --source-only needs --srcs-file.")
    if args.srcs_file and not os.path.isfile(args.srcs_file):
        sys.exit(f"ERROR: --srcs-file '{args.srcs_file}' does not exist.")
    if args.lib and not os.path.isfile(args.lib):
        sys.exit(f"ERROR: --lib '{args.lib}' does not exist.")

    gen_sbom = find_gen_sbom(args.gen_sbom)
    if not os.path.isfile(gen_sbom):
        sys.exit(f"ERROR: gen-sbom not found at '{gen_sbom}'. Pass --gen-sbom "
                 f"/path/to/wolfssl/scripts/gen-sbom or set WOLFSSL_DIR.")

    cdx_out = args.cdx_out or f"{args.name}-{version}.cdx.json"
    spdx_out = args.spdx_out or f"{args.name}-{version}.spdx.json"

    tmp_files = []
    try:
        cmd = [args.python, gen_sbom,
               "--name", args.name,
               "--version", version,
               "--supplier", args.supplier,
               "--license-file", license_file,
               "--cdx-out", cdx_out,
               "--spdx-out", spdx_out]

        # Composition.
        if args.srcs_file:
            srcs = load_srcs(args.srcs_file, args.skip_missing)
            fd, srcs_path = tempfile.mkstemp(prefix="wolfssl-compliance-tooling-srcs-", suffix=".txt")
            os.close(fd)
            tmp_files.append(srcs_path)
            with open(srcs_path, "w", encoding="utf-8") as f:
                f.write("\n".join(srcs) + "\n")
            cmd += ["--srcs-file", srcs_path]
            src_count = len(srcs)
        else:
            src_count = 0
        if args.lib:
            cmd += ["--lib", args.lib]
        if args.no_artifact_hash:
            cmd += ["--no-artifact-hash"]

        # Config.
        if args.settings_h and not args.cflags:
            # --settings-h only feeds the --cflags capture. Ignoring it in
            # silence is how a product ends up believing it recorded a
            # configuration it never captured.
            print("WARNING: --settings-h is only used with --cflags; "
                  "ignoring it here.", file=sys.stderr)
        if args.user_settings:
            if not os.path.isfile(args.user_settings):
                sys.exit(f"ERROR: --user-settings '{args.user_settings}' "
                         f"does not exist.")
            cmd += ["--user-settings", args.user_settings]
        else:
            if args.source_only:
                defines_text = ""
            elif args.options_h:
                if not os.path.isfile(args.options_h):
                    sys.exit(f"ERROR: --options-h '{args.options_h}' does not exist.")
                with open(args.options_h, encoding="utf-8", errors="replace") as f:
                    defines_text = f.read()
            elif args.cflags:
                if args.settings_h and not os.path.isfile(args.settings_h):
                    sys.exit(f"ERROR: --settings-h '{args.settings_h}' "
                             f"does not exist.")
                defines_text = capture_macros(
                    args.hostcc, args.cflags,
                    settings_h=args.settings_h,
                    include_dirs=args.include_dir)
            else:
                sys.exit("ERROR: pass one of --cflags, --options-h, "
                         "--user-settings, or --source-only.")
            if not args.no_scrub and not args.source_only:
                defines_text = scrub_defines(defines_text)
            fd, defines_path = tempfile.mkstemp(prefix="wolfssl-compliance-tooling-defs-", suffix=".h")
            os.close(fd)
            tmp_files.append(defines_path)
            with open(defines_path, "w", encoding="utf-8") as f:
                f.write(defines_text)
            cmd += ["--options-h", defines_path]

        # License overrides.
        if args.license_override:
            cmd += ["--license-override", args.license_override]
        if args.license_text:
            cmd += ["--license-text", args.license_text]
        if args.document_namespace and gen_sbom_supports(
                args.python, gen_sbom, "--document-namespace"):
            cmd += ["--document-namespace", args.document_namespace]

        if args.component_type and gen_sbom_supports(
                args.python, gen_sbom, "--component-type"):
            cmd += ["--component-type", args.component_type]

        # Dependencies, only if the generator supports them.
        if args.dep_wolfssl and gen_sbom_supports(args.python, gen_sbom, "--dep-wolfssl"):
            cmd += ["--dep-wolfssl", args.dep_wolfssl]
        if args.dep_wolfcrypt and gen_sbom_supports(
                args.python, gen_sbom, "--dep-wolfcrypt"):
            cmd += ["--dep-wolfcrypt", args.dep_wolfcrypt]
        if args.dep_openssl and gen_sbom_supports(args.python, gen_sbom, "--dep-openssl"):
            cmd += ["--dep-openssl", args.dep_openssl]
        if args.dep_libz and gen_sbom_supports(args.python, gen_sbom, "--dep-libz"):
            cmd += ["--dep-libz", args.dep_libz]
        if args.dep_version and gen_sbom_supports(args.python, gen_sbom, "--dep-version"):
            for dv in args.dep_version:
                cmd += ["--dep-version", dv]
        if args.crypto_only and gen_sbom_supports(
                args.python, gen_sbom, "--crypto-only"):
            cmd += ["--crypto-only", args.crypto_only]

        print(f"SBOM: name={args.name} version={version}")
        if args.lib:
            print(f"  library: {args.lib}"
                  + (" (as-built, no re-hash)" if args.no_artifact_hash else ""))
        if src_count:
            print(f"  sources: {src_count} file(s)")
        print(f"  outputs: {cdx_out}  {spdx_out}")

        rc = subprocess.call(cmd)
    finally:
        for f in tmp_files:
            try:
                os.remove(f)
            except OSError:
                pass

    if rc == 0:
        print(f"SBOM written: {cdx_out}  {spdx_out}")
    sys.exit(rc)


if __name__ == "__main__":
    main()
