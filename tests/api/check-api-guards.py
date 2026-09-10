#!/usr/bin/env python3
#
# check-api-guards.py [--all] [base-ref]
#
# Every entry in tests/api is compiled into the one unit.test binary, in every
# configuration CI builds. A test that calls an API the build did not compile
# is not a test failure -- it is a link error that takes the whole binary down,
# and it is invisible to anything that only reads headers, because wolfSSL
# declares plenty of API unconditionally and implements it under a narrower
# condition. That combination has broken CI here four separate times: a guard
# that names what the test NEEDS rather than what the build PROVIDES.
#
# This checks the other direction. For each API below it walks every call site's
# enclosing #if chain and requires the macros the IMPLEMENTATION requires. Run
# it over the test sources; it exits non-zero if a call site is not covered.
#
# Adding an entry: find where the function is defined (not declared) and copy
# the conditions around it. "requires_off" are macros that must be excluded,
# "requires_on" macros that must be present.
#
# It is deliberately a whitelist rather than a parse of ssl.h: the mapping from
# symbol to implementation guard cannot be derived from the declaration, which
# is the entire problem it exists to catch.
#
# By default it only looks at call sites on lines this branch added or changed
# against the base ref (origin/master), which is what makes it usable as a
# pre-push check. Running it over everything reports plenty of long-standing
# call sites that are fine in practice, because the configurations that would
# break them are not built -- auditing those is a different job. --all does
# that anyway.
import re
import sys
import glob

# symbol -> (must be excluded, must be defined), from the definition site
API = {
    # src/ssl.c, under !NO_WOLFSSL_CLIENT && !NO_TLS
    'wolfSSLv23_client_method':      (['NO_TLS', 'NO_WOLFSSL_CLIENT'], []),
    'wolfSSLv23_server_method':      (['NO_TLS', 'NO_WOLFSSL_SERVER'], []),
    # src/tls.c, additionally under WOLFSSL_DTLS && !WOLFSSL_NO_TLS12:
    # DTLS 1.2 is built out of the TLS 1.2 code
    'wolfDTLSv1_2_client_method':    (['NO_WOLFSSL_CLIENT', 'WOLFSSL_NO_TLS12'],
                                      ['WOLFSSL_DTLS']),
    'wolfDTLSv1_2_server_method':    (['NO_WOLFSSL_SERVER', 'WOLFSSL_NO_TLS12'],
                                      ['WOLFSSL_DTLS']),
    # src/ssl_api_ext.c: each sits under !NO_TLS as well as its own feature
    'wolfSSL_UseSNI':                (['NO_TLS'], ['HAVE_SNI']),
    'wolfSSL_CTX_UseSNI':            (['NO_TLS'], ['HAVE_SNI']),
    'wolfSSL_SNI_GetRequest':        (['NO_TLS', 'NO_WOLFSSL_SERVER'], ['HAVE_SNI']),
    'wolfSSL_SNI_GetFromBuffer':     (['NO_TLS', 'NO_WOLFSSL_SERVER'], ['HAVE_SNI']),
    'wolfSSL_UseSupportedCurve':     (['NO_TLS'], ['HAVE_SUPPORTED_CURVES']),
    'wolfSSL_CTX_UseSupportedCurve': (['NO_TLS'], ['HAVE_SUPPORTED_CURVES']),
    # src/ssl.c, compiled only when some key-agreement group exists to name.
    # ANY_GROUP below stands for that disjunction.
    'wolfSSL_get_curve_name':        ([], ['ANY_GROUP']),
    # wolfcrypt/src/memory.c, under USE_WOLFSSL_MEMORY -- which --enable-leantls
    # removes by way of WOLFSSL_LEANPSK
    'wolfSSL_SetAllocators':         ([], ['USE_WOLFSSL_MEMORY']),
    'wolfSSL_GetAllocators':         ([], ['USE_WOLFSSL_MEMORY']),
    # src/ssl_certman.c: declared unconditionally in ssl.h, implemented only
    # inside #ifndef NO_FILESYSTEM. (LoadCA also reads PEM only, but that is a
    # fixture question, not a link one, so it is not encoded here.)
    'wolfSSL_CertManagerLoadCA':     (['NO_FILESYSTEM'], []),
    'wolfSSL_CertManagerVerify':     (['NO_FILESYSTEM'], []),
    'wolfSSL_CertManagerLoadCRL':    (['NO_FILESYSTEM'], []),
    'wolfSSL_CertManagerLoadCRLFile': (['NO_FILESYSTEM'], []),
}


def strip_comments(text):
    """Blank out comments and string literals, keeping every newline so line
    numbers still line up. Without this the scan matches the API names in the
    explanatory comments these tests are full of."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(''.join(ch if ch == '\n' else ' ' for ch in text[i:j]))
            i = j
        elif c == '/' and i + 1 < n and text[i + 1] == '/':
            j = text.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
        elif c in '"\'':
            q, j = c, i + 1
            while j < n and text[j] != q:
                j += 2 if text[j] == '\\' else 1
            j = min(j + 1, n)
            out.append(''.join(ch if ch == '\n' else ' ' for ch in text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def guard_chain(lines, upto):
    """The #if directives open at line `upto`, joined, continuations included."""
    stack = []
    for i, line in enumerate(lines[:upto], 1):
        s = line.strip()
        if re.match(r'#\s*if', s):
            text, j = [], i - 1
            while True:
                text.append(lines[j].strip())
                if not lines[j].rstrip().endswith('\\'):
                    break
                j += 1
            stack.append(' '.join(text))
        elif re.match(r'#\s*endif', s):
            if stack:
                stack.pop()
        elif re.match(r'#\s*el(se|if)', s):
            if stack:
                stack[-1] = s
    return ' '.join(stack)


# Macros that are only ever defined in a build that has TLS, so a block already
# guarded by one of them cannot also need !defined(NO_TLS) spelled out.
IMPLIES_TLS = (
    'WOLFSSL_TLS13', 'WOLFSSL_DTLS', 'WOLFSSL_DTLS13', 'HAVE_SNI', 'HAVE_ALPN',
    'HAVE_SESSION_TICKET', 'HAVE_SECURE_RENEGOTIATION', 'HAVE_MAX_FRAGMENT',
    'HAVE_SUPPORTED_CURVES', 'HAVE_EXTENDED_MASTER', 'HAVE_TRUSTED_CA',
    'HAVE_ENCRYPT_THEN_MAC', 'HAVE_SERVER_RENEGOTIATION_INFO',
    'HAVE_CERTIFICATE_STATUS_REQUEST', 'HAVE_TLS_EXTENSIONS', 'HAVE_ECH',
)


def require_ref(base):
    """Refuse to run against a ref git cannot resolve.

    A shallow checkout has no base branch, and then every diff comes back
    empty and the check passes without looking at anything -- which is worse
    than not running it, because it reports success. Fail loudly instead.
    """
    import subprocess
    r = subprocess.run(['git', 'rev-parse', '--verify', '--quiet', base + '^{commit}'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(
            f"check-api-guards: cannot resolve '{base}'.\n"
            f"  The diff scope needs it. In CI, check out with fetch-depth: 0;\n"
            f"  locally, fetch the base branch, or pass --all to scan every\n"
            f"  call site instead.\n")
        sys.exit(2)


def changed_lines(path, base):
    """Line numbers this branch added or changed in path."""
    import subprocess
    out = subprocess.run(['git', 'diff', '-U0', f'{base}...HEAD', '--', path],
                         capture_output=True, text=True).stdout
    hit = set()
    for m in re.finditer(r'^@@ -\S+ \+(\d+)(?:,(\d+))? @@', out, re.M):
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) else 1
        hit.update(range(start, start + count))
    return hit


def check(path, only=None):
    lines = strip_comments(open(path, errors='replace').read()).split('\n')
    bad = []
    for i, line in enumerate(lines, 1):
        if only is not None and i not in only:
            continue
        for sym, (off, on) in API.items():
            if not re.search(r'\b' + re.escape(sym) + r'\s*\(', line):
                continue
            chain = guard_chain(lines, i)
            miss_off = [m for m in off
                        if f'!defined({m})' not in chain and f'ifndef {m}' not in chain]
            miss_on = [m for m in on
                       if f'defined({m})' not in chain and f'ifdef {m}' not in chain]
            # ANY_GROUP is satisfied by any one of the group macros
            if 'ANY_GROUP' in miss_on:
                if any(f'defined({g})' in chain or f'ifdef {g}' in chain
                       or f'!defined({g})' in chain
                       for g in ('HAVE_ECC', 'HAVE_CURVE25519', 'HAVE_CURVE448',
                                 'NO_DH', 'WOLFSSL_HAVE_MLKEM')):
                    miss_on = [m for m in miss_on if m != 'ANY_GROUP']
            # WOLFSSL_DTLS implies TLS is compiled in, so a DTLS-guarded block
            # never needs !NO_TLS spelled out as well.
            if any(f'defined({m})' in chain or f'ifdef {m}' in chain
                   for m in IMPLIES_TLS):
                miss_off = [m for m in miss_off if m != 'NO_TLS']
            if miss_off or miss_on:
                bad.append((i, sym, miss_off, miss_on))
    return bad


def main():
    args = [a for a in sys.argv[1:]]
    scan_all = '--all' in args
    if scan_all:
        args.remove('--all')
    base = args[0] if args else 'origin/master'
    if not scan_all:
        require_ref(base)
    paths = sorted(glob.glob('tests/api/test_*.c'))
    total = 0
    for path in paths:
        only = None if scan_all else changed_lines(path, base)
        if only is not None and not only:
            continue
        for line, sym, off, on in check(path, only):
            need = []
            if off:
                need.append('!defined(' + '), !defined('.join(off) + ')')
            if on:
                need.append('defined(' + '), defined('.join(on) + ')')
            print(f'{path}:{line}: {sym} needs {" and ".join(need)}')
            total += 1
    scope = 'every call site' if scan_all else f'call sites changed since {base}'
    if total:
        print(f'\n{total} call site(s) reachable in a build that does not '
              f'implement the API ({scope})')
        return 1
    print(f'api guards: {scope} covered')
    return 0


if __name__ == '__main__':
    sys.exit(main())
