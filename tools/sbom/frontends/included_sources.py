"""Find the source files a compile command compiles in through #include,
such as wolfSSL's src/ssl_api_*.c, which are not compile_commands.json
entries of their own."""

import os
import re
import shlex
import subprocess

# Options whose next token is their argument, kept for the -M run.
_KEEP_PAIRS = ('-D', '-U', '-I', '-iquote', '-isystem', '-isystem-after',
               '-idirafter', '-imacros', '-include', '-isysroot', '-iprefix',
               '-iwithprefix', '-iwithprefixbefore', '-iwithsysroot',
               '-iframework', '-iframeworkwithsysroot', '-F', '-target',
               '-arch', '--sysroot', '-x', '-specs', '--specs',
               '--gcc-toolchain', '-gcc-toolchain', '-meabi', '-include-pch')
# Options whose next token is their argument, dropped with it.
_DROP_PAIRS = ('-o', '-MF', '-MT', '-MQ', '-MJ', '-Xclang', '-Xpreprocessor',
               '-Xassembler', '-Xlinker', '-mllvm', '--param', '--output',
               '-framework', '-undefined', '-force_load', '-filelist',
               '-multiply_defined', '-mthread-model', '-arch_only', '-mmlir',
               '-module-dependency-dir', '-multiply_defined_unused',
               '-target-arch-variant')
_KEEP_EXACT = ('-ansi', '-undef', '-pthread', '-nostdinc', '-nostdinc++',
               '-nobuiltininc')
# Joined forms of the pairs, and flags that set target or language macros.
_KEEP = tuple(o for o in _KEEP_PAIRS if o != '-arch') + (
    '--sysroot=', '--target=', '-std=', '--std=', '-stdlib=', '-specs=',
    '--specs=', '--gcc-toolchain=', '-m', '-O')
# -f flags that change predefined macros; any other -f may write a file.
_F_KEEP = ('signed-char', 'unsigned-char', 'short-wchar', 'short-enums',
           'freestanding', 'hosted', 'builtin', 'pic', 'PIC', 'pie', 'PIE',
           'stack-protector', 'sanitize=', 'openmp', 'openacc', 'exceptions',
           'cxx-exceptions', 'rtti', 'ms-extensions', 'ms-compatibility',
           'declspec', 'blocks', 'gnu89-inline', 'asm', 'wrapv', 'trapv',
           'char8_t', 'gnu-keywords', 'coroutines', 'fast-math', 'math-errno',
           'finite-math-only', 'inline', 'cf-protection', 'input-charset=',
           'exec-charset=', 'dollars-in-identifiers', 'threadsafe-statics',
           'sized-deallocation', 'aligned-new', 'unwind-tables',
           'leading-underscore', 'single-precision-constant', 'abi-version=')
# Preprocessor options worth forwarding from -Xclang and -Xpreprocessor.
_WRAPPED_PAIRS = ('-D', '-U', '-I', '-include', '-imacros', '-include-pch',
                  '-isystem', '-iquote', '-idirafter')
_LAUNCHERS = ('ccache', 'sccache', 'distcc', 'icecc')
# GNU as takes -M as --mri.
_ASSEMBLER = re.compile(r'(^|-)as(\.exe)?$')


class ScanError(Exception):
    pass


def _wp_option(t):
    """A -Wp, option without its -M and -o parts, or None if none is left."""
    parts, kept = t.split(',')[1:], []
    while parts:
        p = parts.pop(0)
        if p in ('-MD', '-MMD', '-MF', '-MT', '-MQ', '-o', '--output') \
                and parts:
            parts.pop(0)
        elif not p.startswith(('-M', '-o', '--output')):
            kept.append(p)
    return '-Wp,' + ','.join(kept) if kept else None


def _keep_flag(t):
    """t if it is a single-token flag the -M run needs, else None."""
    if t.startswith('-Wp,'):
        return _wp_option(t)
    if t.startswith('-f'):
        name = t[5:] if t.startswith('-fno-') else t[2:]
        return t if name.startswith(_F_KEEP) else None
    if t in _KEEP_EXACT or (t.startswith(_KEEP) and t not in _DROP_PAIRS):
        return t
    return None


def _expand_response_files(tokens, directory, depth=0):
    out = []
    for t in tokens:
        if not t.startswith('@') or t == '@':
            out.append(t)
            continue
        path = os.path.join(directory or '', t[1:])
        if depth > 8:
            raise ScanError(f"response files nested too deep at {path}")
        try:
            with open(path, errors='surrogateescape') as f:
                inner = shlex.split(f.read())
        except (OSError, ValueError) as e:
            raise ScanError(f"cannot read response file {path}: {e}")
        out += _expand_response_files(inner, directory, depth + 1)
    return out


def _compiler_index(tokens):
    i = 0
    while (i < len(tokens) - 1 and os.path.splitext(
            os.path.basename(tokens[i]))[0] in _LAUNCHERS):
        i += 1
    return i


def _arches(tokens):
    return list(dict.fromkeys(tokens[j + 1] for j in range(len(tokens) - 1)
                              if tokens[j] == '-arch'))


def dependency_command(tokens, source, arch=None):
    """The preprocessor flags of a compile command for one -arch (the
    first by default), as a -M run on source."""
    i = _compiler_index(tokens)
    rest = tokens[i + 1:]
    arch = arch or next(iter(_arches(rest)), None)
    # -M goes first so a misparsed option swallows the source and fails.
    cmd, i = [tokens[i], '-M'], 0
    while i < len(rest):
        t = rest[i]
        pair = i + 1 < len(rest)
        if t in ('-Xclang', '-Xpreprocessor') and pair:
            inner = rest[i + 1]
            if (inner in _WRAPPED_PAIRS and i + 3 < len(rest)
                    and rest[i + 2] == t):
                cmd += rest[i:i + 4]
                i += 4
                continue
            if inner.startswith(('-D', '-U', '-I')):
                cmd += [t, inner]
            i += 2
        elif t == f'-Xarch_{arch}' and pair:
            kept = _keep_flag(rest[i + 1])
            cmd += [kept] if kept else []
            i += 2
        elif (t in _DROP_PAIRS or t.startswith('-Xarch_')) and pair:
            i += 2
        elif t in _KEEP_PAIRS and pair:
            if t != '-arch' or rest[i + 1] == arch:
                cmd += [t, rest[i + 1]]
            i += 2
        else:
            kept = _keep_flag(t)
            cmd += [kept] if kept else []
            i += 1
    return cmd + [source]


def parse_make_deps(text):
    """Return the prerequisites of the make rules printed by -M."""
    text = text.replace('\\\r\n', ' ').replace('\\\n', ' ')
    deps = []
    for rule in text.splitlines():
        prereqs = re.split(r':(?:\s|$)', rule, maxsplit=1)
        if len(prereqs) < 2:
            continue
        deps += [d.replace('\\ ', ' ').replace('\\#', '#').replace('$$', '$')
                 for d in re.split(r'(?<!\\)\s+', prereqs[1].strip()) if d]
    return deps


def included_sources(tokens, directory, source, root, exts):
    """Return the files under root with an extension in exts that the
    command for source reads, other than source itself."""
    if _ASSEMBLER.search(os.path.basename(tokens[_compiler_index(tokens)])):
        return []
    tokens = _expand_response_files(tokens, directory)
    found = []
    for arch in _arches(tokens) or [None]:
        cmd = dependency_command(tokens, source, arch)
        for path in _scan(cmd, directory, source, root, exts):
            if path not in found:
                found.append(path)
    return found


def _scan(cmd, directory, source, root, exts):
    try:
        r = subprocess.run(cmd, cwd=directory or None, capture_output=True,
                           text=True, errors='surrogateescape')
    except OSError as e:
        raise ScanError(f"cannot run '{cmd[0]}': {e}")
    if r.returncode:
        raise ScanError(f"'{cmd[0]} -M' failed for {source}:\n"
                        f"{r.stderr.strip()}")
    root, own = os.path.realpath(root), os.path.realpath(source)
    found, listed = [], False
    for dep in parse_make_deps(r.stdout):
        raw = os.path.join(directory or '', dep)
        real, path = os.path.realpath(raw), os.path.normpath(raw)
        if os.path.realpath(path) != real:
            path = real
        try:
            inside = os.path.commonpath([real, root]) == root
        except ValueError:
            inside = False
        listed = listed or real == own
        if inside and real != own and path.lower().endswith(exts):
            found.append(path)
    if not listed:
        raise ScanError(f"'{cmd[0]} -M' printed no dependencies for {source}")
    return found
