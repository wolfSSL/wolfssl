# Create/Update Signed CA

This document describes how to create/update the "Signed CA" data used by the RA6M4
example program (FSPSM/SCE-backed TLS demo): a wolfSSL example CA certificate, signed
with an RSA-PSS signature over its own DER bytes, then converted to a C byte array for
`#include` into the demo sources.

## Quick start

`example_keys/generate_SignedCA.sh` automates the whole process (sign, verify, convert to
C). A Windows wrapper, `example_keys/generate_SignedCA.bat`, is also provided so it can be
run directly from `cmd.exe`/PowerShell without opening a shell manually.

Requires:

- `openssl` on `PATH`
- `perl` on `PATH` (for `<wolfssl>/scripts/dertoc.pl`)
- On Windows: [Git for Windows](https://git-scm.com/download/win) (its bundled
  `bash.exe`/`openssl`/`perl` are what `generate_SignedCA.bat` uses; set `GIT_BASH` to
  override the default install path if it's somewhere other than
  `C:\Program Files\Git\bin\bash.exe`)

Run from inside `example_keys/` (both scripts write output next to themselves, and the
`wolfssl`-dir argument is a fixed relative path from there):

```
cd example_keys

# Windows
generate_SignedCA.bat RSA     # signs .../wolfssl/certs/ca-cert.der
generate_SignedCA.bat ECC     # signs .../wolfssl/certs/ca-ecc-cert.der

# Linux/macOS/Git Bash
./generate_SignedCA.sh rsa_private.pem rsa_public.pem \
    ../../../../../../../wolfssl/certs/ca-cert.der ../../../../../../../wolfssl
./generate_SignedCA.sh rsa_private.pem rsa_public.pem \
    ../../../../../../../wolfssl/certs/ca-ecc-cert.der ../../../../../../../wolfssl
```

Each run produces, next to the input file's basename:

- `<name>.der.sign` -- the raw RSA-PSS signature bytes
- `<name>.der.c` -- the signature converted to a C byte array (see below)

**The generated C array is named `XXXXXXX`** -- `dertoc.pl` (see below) always names it
from its second argument, and the script always passes the placeholder `XXXXXXX`. Rename
`XXXXXXX`/`sizeof_XXXXXXX` in the output `.c` file to a real symbol (e.g.
`ca_cert_der_sign`, matching what `wc_sce_inform_cert_sign()` expects in
`test/src/test_main.c`) before using it.

## What the script does (manual equivalent)

If you need to customize a step, this is what `generate_SignedCA.sh`/`.bat` runs under
the hood.

### 1. Generate an RSA key pair (one-time; already done for `rsa_private.pem`/`rsa_public.pem`)

```
$ openssl genrsa 2048 2> /dev/null > rsa_private.pem
$ openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem 2> /dev/null
```

### 2. Sign the CA certificate with RSA-PSS

```
$ openssl dgst -sha256 -sign rsa_private.pem \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
    -out <signed-CA>.sign <CA-file-to-sign>

# e.g., signing wolfSSL's example CA cert:
$ openssl dgst -sha256 -sign rsa_private.pem \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
    -out ca-cert.der.sign /path/to/wolfssl/certs/ca-cert.der
```

The script also verifies the signature both ways (`-prverify` with the private key,
`-verify` with the public key) immediately after signing, as a sanity check.

### 3. Convert the signature to a C source file

```
$ /path/to/wolfssl/scripts/dertoc.pl ./ca-cert.der.sign XXXXXXX ca-cert.der.c
```

`dertoc.pl <input-file> <c-array-name> <output.c>` emits:

```c
static const unsigned char <c-array-name>[] = { /* ...hex bytes... */ };
static const int sizeof_<c-array-name> = sizeof(<c-array-name>);
```

## Appendix

### example_keys/ contents

```
example_keys/
+-- rsa_private.pem          2048-bit RSA private key, used to sign CA certs
+-- rsa_public.pem           matching public key, used to verify the signature
+-- generate_SignedCA.sh     sign + verify + convert to C, in one step (Linux/macOS/Git Bash)
+-- generate_SignedCA.bat    Windows cmd.exe/PowerShell wrapper (calls the .sh via Git Bash)
+-- ca-cert.der.sign         pre-generated: RSA-PSS signature over certs/ca-cert.der
+-- ca-cert.der.c            pre-generated: the above, as a C byte array
+-- ca-ecc-cert.der.sign     pre-generated: RSA-PSS signature over certs/ca-ecc-cert.der
+-- ca-ecc-cert.der.c        pre-generated: the above, as a C byte array
```
