# Falcon keygen/sign/verify fuzzer

`falcon_fuzz` hunts for a specific, intermittently reproducing fault in the
native Falcon implementation: **a freshly generated key produces a signature
that then fails to verify against its own public key.**

Because the fault is probabilistic — it depends on the Gaussian sampler and the
signing-restart path, and on the particular key — a single
`make_key`/`sign`/`verify` pass rarely trips it. This driver hammers the loop
across many keys and many messages per key (varying message length, including
the zero-length edge case) so a "fairly regular" fault surfaces quickly.

## What it checks per key

1. `wc_falcon_make_key` succeeds and `wc_falcon_check_key` passes.
2. Each of `--msgs` random messages signs, and the signature **verifies**
   against the key's own public key (`res == 1`). This is the primary target.
3. A single-bit-flipped signature is **rejected** — guards against a verifier
   that trivially accepts everything (which would otherwise mask the real bug).

## Reproducing a failure

Verification is a pure function of `(public key, message, signature)`, so on the
first mismatch the driver writes a self-contained `*.repro` artifact (public
key, raw private key, message, and the non-verifying signature). Replay it
deterministically — no need to reconstruct the RNG stream:

```
./falcon_fuzz --replay falcon_fail_L1_1234.repro
```

Replay exits 1 (and prints "DOES NOT VERIFY") when the artifact reproduces the
fault, 0 when it verifies cleanly.

## Building and running

Requires the parent tree configured/built with Falcon:

```
./configure --enable-experimental --enable-falcon && make
```

Then:

```
sh tests/falcon/run.sh [iters] [msgs]     # build + run, CI-friendly exit codes
# or
cd tests/falcon && make && ./falcon_fuzz --help
```

### Options

```
--level 1|5|both   security level(s) to fuzz (default: both)
--iters N          keygen iterations per level, 0 = forever (default: 5000)
--msgs M           messages signed per key (default: 8)
--seed S           seed the C RNG that chooses message lengths (repeatable schedule)
--stop-on-fail     stop at the first detected failure
--dump-dir DIR     directory for *.repro artifacts (default: .)
--quiet            suppress periodic progress output
--replay FILE      re-verify a dumped repro artifact and exit
```

### Exit codes

- `0` — no failures detected
- `1` — a signature did not verify (a `*.repro` artifact was written)
- `2` — build/setup error
- `77` — Falcon (or native signing) not compiled in — treated as "skip"
