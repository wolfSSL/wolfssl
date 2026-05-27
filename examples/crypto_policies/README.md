# wolfSSL crypto-policy files

This directory ships two kinds of policy files, both consumed by
`wolfSSL_crypto_policy_enable(path)` (or
`wolfSSL_crypto_policy_enable_buffer(buf)`):

| File | Format | Code path |
|---|---|---|
| `<policy>/wolfssl.txt` | Legacy single-line `@SECLEVEL=N:...` cipher string | `crypto_policy_parse()` in `src/ssl.c` |
| `<policy>/wolfssl-allowlist.txt` | Granular sectioned allowlist | `wolfSSL_crypto_policy_parse_granular()` in `src/crypto_policy_granular.c` |

`wolfSSL_crypto_policy_enable()` sniffs the file header (first non-blank
non-comment line) and dispatches to the matching parser. The two
formats coexist; existing deployments that point at a legacy file keep
working unchanged.

## Why two formats?

The legacy `@SECLEVEL=N:EECDH:kRSA:...` format was rejected by the
Fedora crypto-policies maintainers as
[insufficient](https://gitlab.com/redhat-crypto/fedora-crypto-policies/-/issues/60)
because it inherits the OpenSSL cipher-string DSL: opaque family
aliases, a coarse `@SECLEVEL` integer that bundles unrelated decisions
together, and no granular control over signature schemes, named
groups, or per-version protocol enablement.

The allowlist format mirrors the GnuTLS back-end that crypto-policies
already endorses as granular: explicit primitive names, one directive
per primitive, grouped by category. The vocabulary is owned by
crypto-policies; the wolfSSL-side mapping tables live in
`src/crypto_policy_granular.c`.

## Allowlist file format

```ini
# Header — mandatory.
version = 1
override-mode = allowlist

[protocols]
enabled-version = TLS1.2     # one directive per enabled value
enabled-version = TLS1.3
enabled-version = DTLS1.2

[ciphers]
enabled-cipher = AES-256-GCM
enabled-cipher = AES-128-GCM
enabled-cipher = CHACHA20-POLY1305

[key-exchange]
enabled-kx = ECDHE
enabled-kx = DHE-RSA

[macs]
enabled-mac = AEAD
enabled-mac = HMAC-SHA2-256
enabled-mac = HMAC-SHA2-384

[hashes]
enabled-hash = SHA2-256
enabled-hash = SHA2-384
enabled-hash = SHA2-512

[groups]
enabled-group = X25519
enabled-group = SECP256R1
enabled-group = SECP384R1

[signatures]
enabled-sig = ECDSA-SHA2-256
enabled-sig = ECDSA-SHA2-384
enabled-sig = RSA-SHA2-256

[constraints]
min-rsa-bits  = 2048
min-dh-bits   = 2048
min-dsa-bits  = 2048
security-level = 2
```

Rules:

* `version = 1` is the only format this build understands. A higher
  version is rejected outright (`WOLFSSL_BAD_FILE`) rather than parsed
  under wrong semantics.
* `override-mode = allowlist` is mandatory.
* Section headers (`[protocols]`, …) are cosmetic; only `key = value`
  lines drive parsing.
* `#` introduces a line comment.
* Unknown tokens (for instance, post-quantum primitives a given
  wolfSSL build does not implement) are tolerated silently. The
  intersection of "policy-enabled" ∩ "build-supported" is what gets
  applied to every `WOLFSSL_CTX`.
* Per-category limit: 64 tokens, 48 bytes each.
* File size limit: 1 MiB.

## What the apply step drives

For every `WOLFSSL_CTX` created after the policy is enabled, the
applier calls (in order):

1. `wolfSSL_CTX_SetMinVersion` from the lowest `enabled-version`.
2. `wolfSSL_CTX_set_cipher_list` from the cross-product
   `cipher × kx × mac × version` against the build's known TLS suites.
3. `wolfSSL_CTX_UseSupportedCurve` for each mapped `enabled-group`.
4. `wolfSSL_CTX_set1_sigalgs_list` from the mapped `enabled-sig` set.
5. `wolfSSL_CTX_SetMinRsaKey_Sz` / `SetMinDhKey_Sz` /
   `SetMinEccKey_Sz` from `min-rsa-bits` / `min-dh-bits`
   (ECC floor derived from RSA-equivalent strength).

Steps 1, 3 and 4 are best-effort: if a build lacks the primitive (no
TLS 1.0 support, no `rsa_pss_*`), the applier logs and continues
rather than tearing down the CTX — the remaining steps still enforce
the policy.

## The five fixtures shipped here

`legacy/`, `default/`, `future/`, `fips/`, `bsi/` are unmodified
outputs of the Fedora crypto-policies generator. They are checked into
this tree so the wolfSSL unit tests can exercise the parser end-to-end
against the same files a Fedora install would produce. Regenerate
with:

```sh
python3 build-crypto-policies.py --flat --policy DEFAULT policies out
cp out/DEFAULT-wolfssl.txt \
   examples/crypto_policies/default/wolfssl-allowlist.txt
```

## Related upstream issues

* wolfSSL [#9802](https://github.com/wolfSSL/wolfssl/issues/9802) — full
  Fedora crypto-policies support tracking issue.
* fedora-crypto-policies
  [work item #60](https://gitlab.com/redhat-crypto/fedora-crypto-policies/-/issues/60)
  — file format coordination.
* The OpenSSL [`opensslcnf.config`](https://gitlab.com/redhat-crypto/fedora-crypto-policies/-/blob/main/python/policygenerators/openssl.py)
  and GnuTLS
  [`gnutls.config`](https://gitlab.com/redhat-crypto/fedora-crypto-policies/-/blob/main/python/policygenerators/gnutls.py)
  generators are the precedents this allowlist format follows.
