#!/usr/bin/env python3
# Keeps wolfssl/wolfcrypt/build_check_list.h in step with the public headers.
#
# wc_CheckBuildConfig() compares an application's fingerprint of the build
# configuration with the loaded library's: feature-macro bits and the sizes
# of public structs, both listed in build_check_list.h. The list is
# maintained by hand, so the risk is a new macro that changes a public
# struct's layout without anyone adding it there. A mismatch on that macro
# would then pass the check and corrupt memory at run time, which is exactly
# what the check exists to prevent.
#
# Rule enforced for every struct or union defined in the public headers
# (wolfssl/*.h, wolfssl/wolfcrypt/*.h, wolfssl/openssl/*.h; internal.h and
# port/ excluded) that has #if-guarded members, i.e. whose layout depends on
# the configuration. It must be one of:
#   * sized: a size slot (WC_BCS) in build_check_list.h records it;
#   * covered: embedded by value, directly or transitively, in a sized
#     struct, so that struct's size changes with it;
#   * fingerprinted: every macro guarding its members is a feature bit
#     (WC_BCF) in build_check_list.h;
#   * allowlisted in UNCHECKED below, with the reason it does not matter
#     to applications.
#
# Size is not enough for a member that can fit into existing padding: on
# LP64 an int before an 8-byte-aligned member, or at the end of a struct,
# can appear or vanish without changing sizeof() while moving every member
# after it. So in every struct that is not allowlisted, sized or covered
# included, a conditional block whose members are all bitfields or single
# members of a type narrower than 8 bytes (SMALL_TYPES, plus typedefs and
# enums of those) must have every guarding macro fingerprinted. A block
# with a pointer, array, 64-bit or struct member always changes the size.
#
# Also checked:
#   * every header that defines or undefines a fingerprinted macro is
#     reachable through build_check.h's includes, so the library and an
#     application see the same value whatever else they include; or the
#     macro is in DERIVED below, meaning its list entry repeats the header's
#     derivation;
#   * every macro named in build_check_list.h appears somewhere in the
#     source tree's headers or build system (catches typos and renames);
#   * every size-slot type is defined in a public header;
#   * every allowlist entry still names a struct that exists.
#
# Findings are emitted as GitHub workflow commands (::error) so they surface
# as annotations, and as plain text so the log reads locally.
#
# Usage: check-build-config-list.py [--root DIR] [--verbose]

import argparse
import pathlib
import re
import sys

LIST = 'wolfssl/wolfcrypt/build_check_list.h'

# Structs with configuration-dependent layouts that applications do not
# allocate or access, so they need no fingerprint. Keep reasons short;
# "internal" means only reached through pointers the library hands out, or
# only used inside the library.
UNCHECKED = {
    # Debug, test and tracking scaffolding.
    'func_args': 'test.h harness, built with the library flags',
    'tcp_ready': 'test.h harness, built with the library flags',
    'memHint': 'memory tracking debug build only',
    'memoryStats': 'memory tracking debug build only',
    'stack_size_debug_context': 'stack size debug build only',
    'wc_rng_debug_stats_snapshot': 'RNG debug statistics',
    'w64wrapper': 'internal 64-bit arithmetic helper',
    # Platform plumbing, filled and read only inside the library.
    'ReadDirCtx': 'internal directory iterator',
    'gnrc_wolfssl_ctx': 'RIOT-OS I/O glue, internal',
    'socket_connector': 'RIOT-OS I/O glue, internal',
    'OS_Seed': 'embedded in WC_RNG, internal',
    'WOLF_EVENT': 'async event, internal',
    'WC_ASYNC_DEV': 'async device, internal',
    'WC_ASYNC_SW': 'async software device, internal',
    'wc_rng_bank_inst': 'RNG bank instance, internal',
    'WOLFSSL_HEAP': 'static memory heap, used through API only',
    'WOLFSSL_HEAP_HINT': 'static memory heap hint, used through API only',
    # Library-internal state reached through opaque handles.
    'SessionRow': 'session cache, internal',
    'SignatureCtx': 'certificate signature verify state, internal',
    'CertStatus': 'OCSP response parsing, internal',
    'Signer': 'CA table entry, internal',
    'DecodedCRL': 'CRL parsing, internal',
    'wc_LmsParamsMap': 'constant parameter table, internal',
    'LmsParams': 'constant parameter table, reached by const pointer',
    'LmsState': 'LMS signing work state, internal',
    'XmssState': 'XMSS signing work state, internal',
    'sp_int_minimal': 'SP math temporary, internal',
    'WOLFSSL_CRYPTO_EX_DATA': 'ex_data storage, accessed through API only',
    'WOLFSSL_X509_STORE': 'opaque, created by wolfSSL_X509_STORE_new()',
    'WOLFSSL_BIO_ADDR': 'BIO address union, accessed through API only',
}

# Size-slot types that are scalars or arrays rather than structs.
SCALAR_SLOTS = {'void*', 'long', 'size_t', 'mp_digit', 'wc_BuildDigitBits'}

# Fingerprinted macros that a header build_check.h does not always include
# defines or undefines itself. The list entry makes the bit independent of
# whether the header was included: it repeats the header's derivation (or,
# for ssl.h's NO_TLS changes, reads a marker the header leaves), or records
# the bit only in configurations where build_check.h includes the header.
DERIVED = {
    ('wolfssl/internal.h', 'WOLFSSL_TICKET_HAVE_ID'):
        'defined with WOLFSSL_EARLY_DATA and HAVE_SESSION_TICKET',
    ('wolfssl/wolfcrypt/sp.h', 'WOLFSSL_HAVE_SP_ECC'):
        'undefined without HAVE_ECC',
    ('wolfssl/wolfcrypt/sp_int.h', 'WOLFSSL_SP_INT_NEGATIVE'):
        'defined with OPENSSL_EXTRA and ASN; sp_int.h is SP math only',
    ('wolfssl/wolfcrypt/aes.h', 'WOLFSSL_ARM32_AES_HW_FLAGS'):
        'defined for 32-bit ARM assembly, outside the NO_AES guard',
    ('wolfssl/wolfcrypt/dilithium.h', 'WOLFSSL_MLDSA_DYNAMIC_KEYS'):
        'legacy WOLFSSL_DILITHIUM_DYNAMIC_KEYS alias',
    ('wolfssl/wolfcrypt/dilithium.h', 'WOLFSSL_MLDSA_ASSIGN_KEY'):
        'legacy WOLFSSL_DILITHIUM_ASSIGN_KEY alias',
    ('wolfssl/ssl.h', 'WOLFSSL_NO_TLS12'):
        'set under NO_TLS; ssl.h marks it with WOLFSSL_NO_TLS12_SET_BY_SSL_H',
    ('wolfssl/ssl.h', 'WOLFSSL_TLS13'):
        'unset under NO_TLS; ssl.h marks it with WOLFSSL_TLS13_UNSET_BY_SSL_H',
    ('wolfssl/ssl.h', 'WOLFSSL_DTLS_MTU'):
        'defined with OPENSSL_ALL and WOLFSSL_DTLS',
    ('wolfssl/wolfio.h', 'WOLFSSL_NO_SOCK'):
        'defined on ESP8266; the bit is only recorded outside WOLFCRYPT_ONLY',
    ('wolfssl/wolfio.h', 'WOLFSSL_USER_IO'):
        'defined on ESP8266; the bit is only recorded outside WOLFCRYPT_ONLY',
}

# Identifiers in #if expressions that are not configuration macros: the
# defined operator, compiler and platform predefines, include guards and
# *_TYPE_DEFINED guards (but not HAVE_*_H, which are configuration),
# export macros, version tests, and the numeric
# math-size values (their effect on layout is caught by the mp_int and key
# size slots). Keep this narrow: an identifier excluded here is never
# checked, so a real feature flag that matched (ALT_ECC_SIZE, for one, would
# match a "*_SIZE" pattern) could slip through.
NOT_CONFIG = re.compile(
    r'^(defined|__\w+|_MSC_VER|_WIN32|_WIN64|WIN32|_M_X64|_M_IX86|'
    r'WOLF_C89|WOLF_C99|HAVE_ANONYMOUS_INLINE_AGGREGATES|'
    r'\w+_TYPE_DEFINED|(?!HAVE_)\w+_H_?|WOLFSSL_API|WOLFSSL_LOCAL|'
    r'FIPS_VERSION\w*|HAVE_FIPS_VERSION\w*|SELF_TEST_VERSION\w*|'
    r'LIBWOLFSSL_VERSION_HEX|SP_WORD_SIZE|SP_INT_BITS|SP_INT_DIGITS|'
    r'FP_MAX_BITS|[A-Z]{1,2})$')


def error(msg, path=None):
    loc = 'file=%s::' % path if path else '::'
    print('::error %s%s' % (loc, msg))


def public_headers(root):
    out = []
    for sub in ('wolfssl', 'wolfssl/wolfcrypt', 'wolfssl/openssl'):
        for p in sorted((root / sub).glob('*.h')):
            if p.name in ('internal.h', 'options.h', 'build_check_list.h'):
                continue
            out.append(p)
    return out


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'),
                  text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def find_structs(path):
    """Yield (names, body, guard_lines) for each struct/union definition.

    names holds the tag and any typedef name. body is the full text between
    the braces (nested definitions included). guard_lines are the
    preprocessor conditionals inside the body.
    """
    # Splice continued lines first, so that a condition continued onto the
    # next line is parsed whole.
    text = strip_comments(re.sub(r'\\\n', '', path.read_text(errors='replace')))
    head = re.compile(r'(typedef\s+)?\b(struct|union)\s+(\w*)\s*\{')
    pos = 0
    while True:
        m = head.search(text, pos)
        if not m:
            return
        depth = 0
        i = m.end() - 1
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = text[m.end():i]
        names = set()
        if m.group(3):
            names.add(m.group(3))
        if m.group(1):
            tm = re.match(r'\s*(\w+)', text[i + 1:])
            if tm:
                names.add(tm.group(1))
        guards = [l for l in body.split('\n')
                  if re.match(r'\s*#\s*(if|ifdef|ifndef|elif)\b', l)]
        yield names, body, guards
        # Continue inside the body too, so nested named structs are seen.
        pos = m.end()


def guard_macros(lines):
    macs = set()
    for l in lines:
        expr = re.sub(r'^\s*#\s*\w+', '', l)
        for ident in re.findall(r'\b[A-Za-z_]\w*\b', expr):
            if ident.upper() != ident or NOT_CONFIG.match(ident):
                continue
            macs.add(ident)
    return macs


# Types narrower than 8 bytes on every supported platform. A member of one
# of these can fit into the padding before an 8-byte-aligned member or at
# the end of the struct, leaving sizeof() unchanged while moving the members
# that follow. Extended at run time with typedefs and enums of these found
# in the public headers (see small_typedefs()).
SMALL_TYPES = {
    'byte', 'char', 'word8', 'word16', 'word32', 'sword8', 'sword16',
    'sword32', 'short', 'int', 'bool', 'enum', 'int8_t', 'uint8_t',
    'int16_t', 'uint16_t', 'int32_t', 'uint32_t', 'WC_BITFIELD',
    'WC_ATOMIC_UINT_ARG', 'WC_ATOMIC_INT_ARG', 'wolfSSL_Atomic_Int',
    'wolfSSL_Atomic_Uint', 'pid_t',
}


def small_typedefs(root):
    """Names typedef'd in the public headers to a small type or an enum."""
    out = set()
    for p in public_headers(root):
        text = strip_comments(re.sub(r'\\\n', '', p.read_text(errors='replace')))
        for name in re.findall(r'typedef\s+enum\b[^;{]*\{[^}]*\}\s*(\w+)\s*;',
                               text):
            out.add(name)
        for name in re.findall(r'typedef\s+enum\s+\w+\s+(\w+)\s*;', text):
            out.add(name)
        for base, name in re.findall(
                r'typedef\s+(?:(?:const|volatile|unsigned|signed)\s+)*'
                r'(\w+)\s+(\w+)\s*;', text):
            out.add((base, name))
    small = set(SMALL_TYPES) | {n for n in out if isinstance(n, str)}
    pairs = [n for n in out if not isinstance(n, str)]
    grew = True
    while grew:
        grew = False
        for base, name in pairs:
            if base in small and name not in small:
                small.add(name)
                grew = True
    return small


def member_is_small(s, small):
    """True if the member declaration s can fit into padding: a bitfield,
    or a single (not array, not pointer) member of a small type."""
    if re.search(r':\s*\d+\s*;$', s):
        return True
    if '*' in s or '[' in s or '(' in s or s.startswith('}'):
        return False
    words = re.findall(r'\w+', s)
    for w in words:
        if w in ('const', 'volatile', 'unsigned', 'signed', 'struct',
                 'union') or re.match(r'ALIGN\d+$', w):
            continue
        return w in small
    return False


SMALL = None


def subword_macros(body):
    """Macros guarding a conditional block whose members are all small.

    Each #if/#elif/#else branch is a block of its own and is charged to the
    macros of its #if chain. A nested block's members are members of the
    enclosing block too, so an outer condition is only charged when
    everything under it is small.
    """
    out = set()
    stack = []

    def close(b):
        if b['sub'] and not b['big']:
            out.update(b['macs'])
        b['chain_sub'] |= b['sub']
        b['chain_big'] |= b['big']

    def member(kind):
        if stack:
            stack[-1][kind] = True

    for line in body.split('\n'):
        s = line.strip()
        if re.match(r'#\s*(if|ifdef|ifndef)\b', s):
            stack.append({'macs': guard_macros([s]), 'sub': False,
                          'big': False, 'chain_sub': False,
                          'chain_big': False})
        elif re.match(r'#\s*(elif|else)\b', s) and stack:
            b = stack[-1]
            close(b)
            b.update(macs=b['macs'] | guard_macros([s]), sub=False,
                     big=False)
        elif re.match(r'#\s*endif\b', s) and stack:
            b = stack.pop()
            close(b)
            if b['chain_sub']:
                member('sub')
            if b['chain_big']:
                member('big')
        elif s.endswith(';') and not s.startswith('#'):
            member('sub' if member_is_small(s, SMALL) else 'big')
    return out


def reachable_headers(root, start):
    """Headers that start always includes, directly or transitively.

    An #include counts only when no configuration macro guards it (include
    guards and the other NOT_CONFIG names do not count): a header that
    build_check.h reaches only in some configurations, such as sp_int.h,
    which wolfmath.h includes for SP math only, is not seen by the library
    in the others, while an application may include it directly.
    """
    seen = set()
    work = [start]
    inc = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')
    while work:
        rel = work.pop()
        if rel in seen:
            continue
        p = root / rel
        if not p.is_file():
            continue
        seen.add(rel)
        text = strip_comments(re.sub(r'\\\n', '', p.read_text(errors='replace')))
        stack = []
        for line in text.split('\n'):
            s = line.strip()
            if re.match(r'#\s*(if|ifdef|ifndef)\b', s):
                # build_check.h's own body is under HAVE_WC_INTROSPECTION;
                # without it there is nothing to compare.
                stack.append(bool(guard_macros([s]) -
                                  {'HAVE_WC_INTROSPECTION'}))
            elif re.match(r'#\s*elif\b', s) and stack:
                stack[-1] = True
            elif re.match(r'#\s*else\b', s) and stack:
                # The #else of a plain include guard is never taken; any
                # other #else is a configuration branch.
                stack[-1] = True
            elif re.match(r'#\s*endif\b', s) and stack:
                stack.pop()
            else:
                m = inc.match(s)
                # settings.h is the platform switchboard every wolfSSL
                # header starts with; the port settings headers it pulls in
                # are not included on their own, so its conditions are the
                # same on both sides.
                if not m or (any(stack) and
                             not rel.endswith('wolfcrypt/settings.h')):
                    continue
                name = m.group(1)
                for cand in (name,
                             str(pathlib.PurePosixPath(rel).parent / name)):
                    if cand.startswith('wolfssl/') and \
                            (root / cand).is_file():
                        work.append(cand)
                        break
    return seen


def norm_cond(line):
    """A preprocessor condition line as a comparable expression."""
    s = line.strip()
    m = re.match(r'#\s*ifdef\s+(\w+)', s)
    if m:
        return 'defined(%s)' % m.group(1)
    m = re.match(r'#\s*ifndef\s+(\w+)', s)
    if m:
        return '!defined(%s)' % m.group(1)
    s = re.sub(r'^#\s*if\s*', '', s)
    s = re.sub(r'defined\s+(\w+)', r'defined(\1)', s)
    s = re.sub(r'\s+', '', s)
    while s.startswith('(') and s.endswith(')') and \
            s.count('(') == s.count(')'):
        s = s[1:-1]
    return s


def include_conds(path):
    """{included header: [conditions]} for path's direct includes."""
    text = strip_comments(re.sub(r'\\\n', '', path.read_text(errors='replace')))
    stack = []
    out = {}
    for line in text.split('\n'):
        s = line.strip()
        if re.match(r'#\s*(if|ifdef|ifndef)\b', s):
            stack.append(s)
        elif re.match(r'#\s*(elif|else)\b', s) and stack:
            stack[-1] = None
        elif re.match(r'#\s*endif\b', s) and stack:
            stack.pop()
        else:
            m = re.match(r'#\s*include\s*<(wolfssl/[^>]+)>', s)
            if m:
                out[m.group(1)] = [x for x in stack]
    return out


def define_conds(path, mac):
    """For each #define/#undef of mac in path, the enclosing conditions."""
    text = strip_comments(re.sub(r'\\\n', '', path.read_text(errors='replace')))
    stack = []
    out = []
    for line in text.split('\n'):
        s = line.strip()
        if re.match(r'#\s*(if|ifdef|ifndef)\b', s):
            stack.append(s)
        elif re.match(r'#\s*(elif|else)\b', s) and stack:
            stack[-1] = None
        elif re.match(r'#\s*endif\b', s) and stack:
            stack.pop()
        elif re.match(r'#\s*(define|undef)\s+%s\b' % mac, s):
            out.append([norm_cond(x) for x in stack if x is not None])
    return out


def guarded_like_include(root, rel, mac, inc):
    """True if every change of mac in header rel is under the same
    condition that build_check.h includes rel under, so it happens exactly
    when build_check.h sees it."""
    if rel not in inc:
        return False
    need = inc[rel]
    if not need or any(c is None for c in need):
        return False
    # Drop build_check.h's include guard and HAVE_WC_INTROSPECTION wrapper.
    need = [norm_cond(c) for c in need
            if guard_macros([c]) - {'HAVE_WC_INTROSPECTION'}]
    sites = define_conds(root / rel, mac)
    return bool(need) and bool(sites) and \
        all(all(c in site for c in need) for site in sites)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()
    root = pathlib.Path(args.root)
    errors = 0
    global SMALL
    SMALL = small_typedefs(root)

    listing = (root / LIST).read_text()
    features = set(re.findall(r'WC_BCF(?:_NO)?\(\s*\d+\s*,\s*\d+\s*,\s*(\w+)\s*\)',
                              listing))
    sized = set()
    for t in re.findall(r'WC_BCS(?:_NO|_UNKNOWN)?\(\s*\d+\s*,\s*([^)]+?)\s*\)',
                        listing):
        sized.add(t.replace('struct ', '').strip())

    # Collect every struct, keyed by each of its names. A name can have
    # several definitions (mp_int has one per math backend), so each name
    # maps to all of them.
    structs = []
    by_name = {}
    for p in public_headers(root):
        for names, body, guards in find_structs(p):
            if not names:
                continue
            rec = {'names': names, 'body': body, 'guards': guards,
                   'path': p.relative_to(root)}
            structs.append(rec)
            for n in names:
                by_name.setdefault(n, []).append(rec)
    # typedef [struct|union] Tag Name; outside of definitions, including
    # plain aliases such as "typedef sp_int mp_int;".
    for p in public_headers(root):
        text = strip_comments(p.read_text(errors='replace'))
        for tag, name in re.findall(
                r'typedef\s+(?:(?:struct|union)\s+)?(\w+)\s+(\w+)\s*;', text):
            for rec in by_name.get(tag, []):
                rec['names'].add(name)
                if rec not in by_name.setdefault(name, []):
                    by_name[name].append(rec)

    # Coverage: sized structs, plus anything embedded by value in one.
    covered = set()
    work = [rec for n in sized for rec in by_name.get(n, [])]
    missing_sized = sorted(n for n in sized if n not in by_name and
                           n not in SCALAR_SLOTS)
    while work:
        rec = work.pop()
        if id(rec) in covered:
            continue
        covered.add(id(rec))
        # "Type name;" or "Type name[..];" or "struct Tag name;" - not
        # pointers.
        for t in re.findall(
                r'(?:^|[;{}\n])\s*(?:const\s+)?(?:(?:struct|union)\s+)?'
                r'(\w+)\s+(?:ALIGN\d+\s+)?\w+\s*(?:\[[^\]]*\]\s*)*;',
                rec['body']):
            for sub in by_name.get(t, []):
                if id(sub) not in covered:
                    work.append(sub)

    for name in sorted(UNCHECKED):
        if name not in by_name:
            error('build-config check: allowlisted struct %s no longer '
                  'exists; remove it from UNCHECKED in %s' %
                  (name, pathlib.Path(__file__).name))
            errors += 1

    checked = 0
    for rec in structs:
        if not rec['guards']:
            continue
        if rec['names'] & set(UNCHECKED):
            continue
        unlisted = sorted(subword_macros(rec['body']) - features)
        if unlisted:
            name = '/'.join(sorted(rec['names']))
            error('build-config check: public struct %s has members guarded '
                  'by %s that are only bitfields or members narrower than 8 '
                  'bytes, which can fit into padding without changing its '
                  'size but move later members. Add feature '
                  'bits (WC_BCF) for %s to %s.' %
                  (name, ', '.join(unlisted),
                   'it' if len(unlisted) == 1 else 'them', LIST), rec['path'])
            errors += 1
        if id(rec) in covered:
            continue
        checked += 1
        unlisted = sorted(guard_macros(rec['guards']) - features)
        if unlisted:
            name = '/'.join(sorted(rec['names']))
            error('build-config check: public struct %s has members guarded '
                  'by %s, which %s not fingerprinted. Add a size slot (WC_BCS) '
                  'or feature bits (WC_BCF) to %s, or allowlist the struct in '
                  'UNCHECKED in %s with the reason applications do not '
                  'depend on its layout.' %
                  (name, ', '.join(unlisted),
                   'is' if len(unlisted) == 1 else 'are', LIST,
                   pathlib.Path(__file__).name), rec['path'])
            errors += 1

    # A header that changes a fingerprinted macro must be seen by both sides.
    reach = reachable_headers(root, 'wolfssl/wolfcrypt/build_check.h')
    inc = include_conds(root / 'wolfssl/wolfcrypt/build_check.h')
    found = set()
    for p in sorted(root.glob('wolfssl/**/*.h')):
        rel = p.relative_to(root).as_posix()
        if rel in reach or rel == 'wolfssl/options.h' or \
                p.name == 'build_check_list.h':
            continue
        text = strip_comments(re.sub(r'\\\n', '', p.read_text(errors='replace')))
        for mac in re.findall(r'^\s*#\s*(?:define|undef)\s+(\w+)', text, re.M):
            if mac not in features:
                continue
            found.add((rel, mac))
            if (rel, mac) not in DERIVED and \
                    not guarded_like_include(root, rel, mac, inc):
                error('build-config check: %s defines or undefines %s, which '
                      'is fingerprinted, but build_check.h does not always '
                      'include it, so the bit can depend on what the '
                      'application included. Include the header from '
                      'build_check.h unconditionally, guard the change with '
                      'the condition build_check.h includes the header '
                      'under, or make the list entry independent of the '
                      'header and add it to DERIVED in %s.' %
                      (rel, mac, pathlib.Path(__file__).name), rel)
                errors += 1
    for rel, mac in sorted(set(DERIVED) - found):
        error('build-config check: DERIVED entry %s %s is stale; remove it '
              'from %s' % (rel, mac, pathlib.Path(__file__).name))
        errors += 1

    # Every fingerprinted macro should exist somewhere in the tree.
    corpus = []
    for pat in ('wolfssl/**/*.h', 'configure.ac', 'CMakeLists.txt',
                'cmake/*.in', 'cmake/*.cmake'):
        for p in root.glob(pat):
            if p.name != 'build_check_list.h' and p.is_file():
                corpus.append(p.read_text(errors='replace'))
    corpus = '\n'.join(corpus)
    for mac in sorted(features):
        if not re.search(r'\b%s\b' % re.escape(mac), corpus):
            error('build-config check: %s is listed in %s but appears in no '
                  'header or build file (typo or renamed macro?)' %
                  (mac, LIST), LIST)
            errors += 1
    for t in missing_sized:
        error('build-config check: size slot type %s is not defined in any '
              'public header' % t, LIST)
        errors += 1

    if args.verbose or errors:
        print('build-config check: %d feature macros, %d sized types, '
              '%d structs covered by size, %d checked by macro, %d '
              'allowlisted' % (len(features), len(sized), len(covered),
                               checked, len(UNCHECKED)))
    if errors:
        print('build-config check: %d error(s)' % errors)
        return 1
    print('build-config check: OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
